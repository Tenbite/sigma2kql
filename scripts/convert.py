#!/usr/bin/env python3
"""
sigma2kql - convert SigmaHQ rules into one validated .kql file per rule.

Incremental by default: only rules changed in SigmaHQ since the last processed
commit are converted. A full rebuild happens automatically on the first run, when
config.yml / a custom pipeline / tool versions change, or with --full.

Usage:
    python scripts/convert.py [--config config.yml] [--full] [--no-validate]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata as md
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

ROOT = Path(__file__).resolve().parent.parent

TARGETS = {
    # target: (pipeline module, pipeline function, tables module, tables variable)
    "microsoft_xdr": ("sigma.pipelines.microsoftxdr", "microsoft_xdr_pipeline",
                      "sigma.pipelines.microsoftxdr.tables", "MICROSOFT_XDR_TABLES"),
    "sentinel_asim": ("sigma.pipelines.sentinelasim", "sentinel_asim_pipeline",
                      "sigma.pipelines.sentinelasim.tables", "SENTINEL_ASIM_TABLES"),
    "azure_monitor": ("sigma.pipelines.azuremonitor", "azure_monitor_pipeline",
                      "sigma.pipelines.azuremonitor.tables", "AZURE_MONITOR_TABLES"),
}

# Normalize the schema types used by the backend's table files to Kusto scalar types.
KUSTO_TYPES = {
    "string": "string", "int": "int", "integer": "int", "long": "long", "real": "real",
    "double": "real", "bool": "bool", "boolean": "bool", "datetime": "datetime",
    "date/time": "datetime", "dynamic": "dynamic", "guid": "guid", "timespan": "timespan",
    # .NET names used by the Defender portal schema export
    "int16": "int", "int32": "int", "int64": "long", "byte": "int", "sbyte": "int",
    "single": "real", "decimal": "decimal", "object": "dynamic",
}

DRL = "Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License"


# --------------------------------------------------------------------------- helpers

def log(msg: str) -> None:
    print(msg, flush=True)


def git(sigma_dir: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(sigma_dir), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")


def enum_name(value) -> str | None:
    return value.name.lower() if value is not None else None


def tool_versions() -> dict:
    versions = {
        "pySigma": md.version("pySigma"),
        "pySigma-backend-kusto": md.version("pySigma-backend-kusto"),
    }
    pkg = ROOT / "node_modules/@kusto/language-service-next/package.json"
    versions["kusto-language"] = load_json(pkg, {}).get("version", "not installed")
    return versions


def fingerprint(cfg_text: str, cfg: dict, versions: dict, schema: dict) -> str:
    h = hashlib.sha256()
    h.update(Path(__file__).read_bytes())  # editing this script triggers a rebuild
    h.update(cfg_text.encode())
    h.update(json.dumps(schema, sort_keys=True).encode())  # a schema change triggers a rebuild
    for p in cfg.get("custom_pipelines") or []:
        path = ROOT / p
        h.update(path.read_bytes() if path.exists() else b"missing")
    h.update(json.dumps(versions, sort_keys=True).encode())
    return h.hexdigest()


# --------------------------------------------------------------------------- pipeline / schema

def build_backend(cfg: dict) -> KustoBackend:
    mod_name, fn_name, _, _ = TARGETS[cfg["target"]]
    pipelines = [getattr(importlib.import_module(mod_name), fn_name)()]
    for p in cfg.get("custom_pipelines") or []:
        path = ROOT / p
        if path.exists():
            pipelines.append(ProcessingPipeline.from_yaml(path.read_text()))
    pipelines.sort(key=lambda p: p.priority)
    combined = pipelines[0]
    for p in pipelines[1:]:
        combined = combined + p
    return KustoBackend(processing_pipeline=combined)


def bundled_schema(target: str) -> dict:
    """The table schema shipped inside pySigma-backend-kusto (can lag behind Microsoft)."""
    _, _, tables_mod, tables_var = TARGETS[target]
    mod = importlib.import_module(tables_mod)
    tables = getattr(mod, tables_var)
    common = {}
    if target == "sentinel_asim":  # ASIM tables also expose the common ASIM fields
        common = getattr(mod, "SENTINEL_ASIM_COMMON_FIELDS", {}).get("COMMON", {})
    schema = {}
    for table, cols in tables.items():
        merged = {**common, **cols}
        schema[table] = {name: KUSTO_TYPES.get(str(info.get("data_type", "")).lower(), "string")
                         for name, info in merged.items()}
    return schema


def parse_portal_schema(data) -> dict:
    """Normalize a Defender portal schema export: [{Name, Schema: [{Name, Type}, ...]}, ...]."""
    tables = data.get("Tables", data.get("tables", [])) if isinstance(data, dict) else data
    out = {}
    for t in tables:
        name, cols = t.get("Name"), t.get("Schema") or []
        if not name or not cols:
            continue
        out[name] = {c["Name"]: KUSTO_TYPES.get(str(c.get("Type", "")).lower(), "string")
                     for c in cols if c.get("Name")}
    return out


def live_schema(cfg: dict) -> tuple[dict, str]:
    """Download the current schema (see `live_schema` in config.yml). Falls back to the cached
    copy from the last successful download. Returns ({} , reason) when neither is usable."""
    opts = cfg.get("live_schema") or {}
    if cfg["target"] != "microsoft_xdr" or not opts.get("url"):
        return {}, "not configured"
    cache = ROOT / opts.get("cache", "state/xdr_schema.json")
    required = opts.get("required_tables", ["DeviceProcessEvents"])
    try:
        import urllib.request
        req = urllib.request.Request(opts["url"], headers={"User-Agent": "sigma2kql"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            schema = parse_portal_schema(json.loads(resp.read().decode("utf-8-sig")))
        missing = [t for t in required if t not in schema]
        if missing:
            raise ValueError(f"download is missing required tables: {', '.join(missing)}")
        write_json(cache, schema)
        return schema, f"downloaded from {opts['url']} ({len(schema)} tables)"
    except Exception as exc:  # noqa: BLE001
        cached = load_json(cache, {})
        if cached:
            return cached, f"cached copy ({len(cached)} tables) - download failed: {exc}"
        return {}, f"unavailable - download failed: {exc}"


def schema_drift(bundled: dict, live: dict) -> list[str]:
    """Markdown lines comparing the backend's bundled schema with the live one."""
    lines = []
    for table in sorted(set(bundled) & set(live)):
        gone = sorted(set(bundled[table]) - set(live[table]))
        new = sorted(set(live[table]) - set(bundled[table]))
        retyped = sorted(c for c in set(bundled[table]) & set(live[table])
                         if bundled[table][c] != live[table][c])
        if not (gone or new or retyped):
            continue
        lines += [f"## {table}", ""]
        if gone:
            lines.append(f"- **Not in the live schema** (queries using these fail validation): {', '.join(gone)}")
        if retyped:
            lines.append("- **Type changed:** " + ", ".join(
                f"{c} ({bundled[table][c]} → {live[table][c]})" for c in retyped))
        if new:
            lines.append(f"- New columns the backend doesn't know about: {', '.join(new)}")
        lines.append("")
    only_bundled = sorted(set(bundled) - set(live))
    if only_bundled:
        lines += ["## Tables only in the bundled schema", "",
                  "Kept for validation because the live export doesn't list them: "
                  + ", ".join(only_bundled), ""]
    return lines


def validate(queries: list[dict], schema: Path) -> dict:
    """Run the Node validator over [{id, query}] and return {id: {errors, warnings}}."""
    if not queries:
        return {}
    script = ROOT / "validator/validate.js"
    proc = subprocess.run(["node", str(script), str(schema)], input=json.dumps(queries),
                          capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        sys.exit(f"Validator failed. Did you run `npm ci`?\n{proc.stderr}")
    return {r["id"]: r for r in json.loads(proc.stdout)}


# --------------------------------------------------------------------------- rule handling

def short_error(exc: Exception) -> str:
    msg = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
    msg = msg.split(". Please use valid fields")[0]
    return f"{type(exc).__name__}: {msg}"[:300]


def error_group(reason: str, logsource: str = "") -> str:
    """Bucket failure reasons so the summary shows what to fix first."""
    m = re.search(r"field name encountered: ([\w\-]+)", reason)
    if m:
        return f"Unmapped field `{m.group(1)}`"
    if re.search(r"Unable to determine table name", reason):
        return f"No table for log source `{logsource or '?'}`"
    m = re.search(r"Unsupported field name|Invalid SigmaDetectionItem field", reason)
    if m:
        return "Unsupported field"
    return re.sub(r"[`'\"].*?[`'\"]", "…", reason)[:120]


def attack_tags(rule: SigmaRule) -> tuple[list[str], list[str]]:
    attack, other = [], []
    for t in rule.tags:
        if t.namespace == "attack":
            name = t.name.upper() if re.fullmatch(r"[tgs]\d+(\.\d+)?", t.name) else t.name
            attack.append(name)
        else:
            other.append(f"{t.namespace}.{t.name}")
    return attack, other


def comment_block(label: str, text: str) -> list[str]:
    text = " ".join(str(text).split())
    lines = textwrap.wrap(text, 96) or [""]
    return [f"// {label}: {lines[0]}"] + [f"//   {line}" for line in lines[1:]]


def logsource_str(rule: SigmaRule) -> str:
    ls = rule.logsource
    return "/".join(x for x in (ls.product, ls.category, ls.service) if x) or "none"


# --------------------------------------------------------------------------- wildcard fix
#
# The Kusto backend sometimes leaves a Sigma wildcard (*) inside a string comparison, e.g.
#   RegistryKey endswith "\\Schedule\\TaskCache\\Tree*"
# KQL treats that * as a literal asterisk, so the comparison silently never matches.
# We rewrite each such comparison to an equivalent case-insensitive regex.

_CMP = re.compile(r'(?P<field>\b\w+) (?P<op>contains|endswith|startswith|has|=~|==) '
                  r'"(?P<val>(?:[^"\\]|\\.)*)"')
_RE_META = set(r".^$|?+()[]{}\\")


def _kql_unescape(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def _regex_literal(s: str) -> str:
    return "".join("\\" + ch if ch in _RE_META else ch for ch in s)


def rewrite_wildcards(query: str) -> tuple[str, int]:
    count = 0

    def fix(m: re.Match) -> str:
        nonlocal count
        raw = _kql_unescape(m.group("val"))
        if "*" not in raw:
            return m.group(0)
        count += 1
        body = ".*".join(_regex_literal(part) for part in raw.split("*"))
        op = m.group("op")
        anchored = {"startswith": f"^{body}", "endswith": f"{body}$",
                    "=~": f"^{body}$", "==": f"^{body}$"}.get(op, body)
        flags = "" if op == "==" else "(?i)"
        pattern = (flags + anchored).replace('"', '""')
        return f'{m.group("field")} matches regex @"{pattern}"'

    return _CMP.sub(fix, query), count


def header(rule: SigmaRule, rel: str, sha: str, cfg: dict, versions: dict, validation: str,
           rewrites: int = 0) -> str:
    attack, other = attack_tags(rule)
    lines = [f"// Title: {rule.title}",
             f"// Sigma ID: {rule.id}",
             f"// Status: {enum_name(rule.status)} | Level: {enum_name(rule.level)}",
             f"// Author: {rule.author or 'unknown'}",
             f"// Date: {rule.date or '-'} | Modified: {rule.modified or '-'}"]
    if attack:
        lines.append(f"// ATT&CK: {', '.join(attack)}")
    if other:
        lines.append(f"// Tags: {', '.join(other)}")
    if rule.description:
        lines += comment_block("Description", rule.description)
    if rule.falsepositives:
        lines.append("// False positives:")
        lines += [f"//   - {' '.join(str(fp).split())}" for fp in rule.falsepositives]
    if rule.references:
        lines.append("// References:")
        lines += [f"//   - {ref}" for ref in rule.references]
    lines += [f"// Sigma rule: https://github.com/SigmaHQ/sigma/blob/{sha}/{rel}",
              f"// License: {DRL}",
              f"// Converted by sigma2kql (target: {cfg['target']}, pySigma {versions['pySigma']}, "
              f"pySigma-backend-kusto {versions['pySigma-backend-kusto']})",
              f"// Validation: {validation}",
              "// Machine-generated and not tested against real telemetry. Verify before use as a detection."]
    if rewrites:
        lines.append(f"// Note: {rewrites} wildcard comparison(s) rewritten to 'matches regex' "
                     "(KQL treats * in contains/endswith/== as a literal character)")
    return "\n".join(lines)


def process_file(rel: str, sigma_dir: Path, backend: KustoBackend, cfg: dict) -> dict:
    """Parse, filter and convert one rule file. Returns a DB entry (without validation)."""
    path = sigma_dir / rel
    entry = {"result": "failed", "reason": "", "rules": []}
    try:
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        entry["reason"] = short_error(exc)
        return entry

    rules = [r for r in collection.rules if isinstance(r, SigmaRule)]
    if rules:
        entry["logsource"] = logsource_str(rules[0])
    if not rules:
        return {**entry, "result": "skipped", "reason": "correlation-only file (not supported)"}

    statuses, levels = cfg.get("statuses"), cfg.get("levels")
    wanted = [r for r in rules
              if (not statuses or enum_name(r.status) in statuses)
              and (not levels or enum_name(r.level) in levels)]
    if not wanted:
        r = rules[0]
        return {**entry, "result": "skipped",
                "reason": f"filtered (status={enum_name(r.status)}, level={enum_name(r.level)})"}

    for rule in wanted:
        info = {"id": str(rule.id), "title": rule.title, "level": enum_name(rule.level),
                "status": enum_name(rule.status), "attack": attack_tags(rule)[0]}
        try:
            info["queries"] = [q for q in backend.convert_rule(rule) if q.strip()]
            if not info["queries"]:
                raise ValueError("Empty query: nothing in the detection maps to the target")
            info["rewrites"] = 0
            if cfg.get("rewrite_wildcards", True):
                fixed = [rewrite_wildcards(q) for q in info["queries"]]
                info["queries"] = [q for q, _ in fixed]
                info["rewrites"] = sum(n for _, n in fixed)
        except Exception as exc:  # noqa: BLE001
            entry["reason"] = short_error(exc)
            entry["title"] = rule.title
            return entry
        info["rule"] = rule
        entry["rules"].append(info)

    entry["result"] = "converted"
    return entry


# --------------------------------------------------------------------------- reports

def write_reports(db: dict, cfg: dict, state: dict, versions: dict) -> dict:
    out_dir, rep_dir = ROOT / cfg["output_dir"], ROOT / cfg["reports_dir"]
    rep_dir.mkdir(parents=True, exist_ok=True)
    counts = Counter(e["result"] for e in db.values())

    # kql/INDEX.md
    by_folder = defaultdict(list)
    for rel, e in sorted(db.items()):
        if e["result"] == "converted":
            by_folder[rel.split("/")[0]].append((rel, e))
    idx = [f"# Sigma rules in KQL ({cfg['target']})", "",
           f"{counts['converted']} rules converted from SigmaHQ commit "
           f"[`{state['sigma_sha'][:10]}`](https://github.com/SigmaHQ/sigma/commit/{state['sigma_sha']}). "
           f"Last run: {state['last_run']}.", "",
           f"Rules are licensed under the {DRL}. Each file keeps the original author and Sigma ID.", "",
           "> [!WARNING]",
           "> These queries are machine-generated and have not been tested against real telemetry. "
           "Validation confirms they are valid KQL, not that they detect what the Sigma rule describes. "
           "Run them as hunts and tune them before using any as a detection.", ""]
    for folder, items in sorted(by_folder.items()):
        idx += [f"## {folder} ({len(items)})", "", "| Rule | Level | ATT&CK | Table |", "|---|---|---|---|"]
        for rel, e in items:
            kql_rel = e["kql"].split("/", 1)[1]
            title = e["title"].replace("|", "\\|")
            idx.append(f"| [{title}]({kql_rel}) | {e['level']} | {', '.join(e['attack'])} | {e['table']} |")
        idx.append("")
    (out_dir / "INDEX.md").write_text("\n".join(idx) + "\n")

    # reports/failed.md
    failed = {r: e for r, e in db.items() if e["result"] == "failed"}
    groups = Counter(error_group(e["reason"], e.get("logsource", "")) for e in failed.values())
    lines = ["# Conversion failures", "",
             "Fix the most common ones first by adding a field mapping to `pipelines/custom.yml`.", "",
             "| Reason | Rules |", "|---|---|"]
    lines += [f"| {g} | {n} |" for g, n in groups.most_common()]
    lines += ["", "## By rule", ""]
    lines += [f"- `{r}` — {e['reason']}" for r, e in sorted(failed.items())]
    (rep_dir / "failed.md").write_text("\n".join(lines) + "\n")

    # reports/validation_failed.md
    invalid = {r: e for r, e in db.items() if e["result"] == "invalid"}
    lines = ["# Queries that failed KQL validation", "",
             "These converted, but Microsoft's Kusto parser rejected them against the target schema, "
             "so they were not written to the KQL folder.", ""]
    for r, e in sorted(invalid.items()):
        lines += [f"## {e.get('title', r)}", "", f"`{r}`", ""]
        lines += [f"- {err}" for err in e.get("errors", [])]
        lines += ["", "```kql", *e.get("queries", []), "```", ""]
    (rep_dir / "validation_failed.md").write_text("\n".join(lines) + "\n")

    # reports/wildcard_rewrites.md
    rewritten = {r: e for r, e in db.items() if e.get("wildcard_rewrites")}
    lines = ["# Wildcard rewrites", "",
             "The backend left a Sigma `*` wildcard inside a `contains`/`endswith`/`==` comparison in these "
             "rules. KQL treats that as a literal asterisk, so the comparison would never match. Each one was "
             "rewritten to an equivalent case-insensitive `matches regex` and then validated.", "",
             "| Rule | Level | Rewrites | KQL |", "|---|---|---|---|"]
    for r, e in sorted(rewritten.items()):
        title = e["title"].replace("|", "\\|")
        lines.append(f"| {title} | {e['level']} | {e['wildcard_rewrites']} | [{Path(e['kql']).name}](../{e['kql']}) |")
    (rep_dir / "wildcard_rewrites.md").write_text("\n".join(lines) + "\n")

    # reports/summary.md
    skipped = Counter(e["reason"].split(" (")[0] for e in db.values() if e["result"] == "skipped")
    summary = ["# sigma2kql run summary", "",
               f"- Target: `{cfg['target']}`",
               f"- SigmaHQ commit: `{state['sigma_sha']}`",
               f"- Last run: {state['last_run']} ({state['last_mode']})",
               f"- Tools: " + ", ".join(f"{k} {v}" for k, v in versions.items()),
               f"- Validation schema: {state.get('schema_source', 'bundled')} (see schema_drift.md)", "",
               "| Result | Rules |", "|---|---|",
               f"| Converted and valid | {counts['converted']} |",
               f"| Failed validation | {counts['invalid']} |",
               f"| Failed conversion | {counts['failed']} |",
               f"| Skipped | {counts['skipped']} |", "",
               f"Converted rules with wildcard comparisons rewritten to regex: {len(rewritten)} "
               "(see wildcard_rewrites.md)", "",
               "Skipped breakdown: " + ", ".join(f"{k}: {v}" for k, v in skipped.most_common()), "",
               "Top conversion failures:", ""]
    summary += [f"- {g}: {n}" for g, n in groups.most_common(10)]
    text = "\n".join(summary) + "\n"
    (rep_dir / "summary.md").write_text(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(text)
    return counts


# --------------------------------------------------------------------------- health check
#
# A run can succeed and still be degraded. These checks write any problems to
# HEALTH_FILE (not committed); the workflow's last step fails the run if it exists,
# which triggers GitHub's failure email. Thresholds live under `health:` in config.yml.

HEALTH_FILE = ROOT / "health_problems.txt"


def check_health(cfg: dict, prev: dict, counts: dict, schema_source: str) -> int:
    """Compare this run with the previous one. Returns the updated schema-failure streak."""
    opts = {"max_converted_drop_pct": 10, "max_new_invalid": 25, "schema_fail_runs": 3,
            **(cfg.get("health") or {})}
    problems = []
    prev_counts = prev.get("counts") or {}

    live_configured = cfg["target"] == "microsoft_xdr" and (cfg.get("live_schema") or {}).get("url")
    schema_ok = not live_configured or schema_source.startswith("downloaded")
    streak = 0 if schema_ok else prev.get("schema_fail_streak", 0) + 1
    if streak >= opts["schema_fail_runs"]:
        problems.append(f"Live schema download has failed {streak} runs in a row: {schema_source}")

    before, now = prev_counts.get("converted", 0), counts.get("converted", 0)
    if before and now < before * (1 - opts["max_converted_drop_pct"] / 100):
        problems.append(f"Converted rules dropped from {before} to {now} "
                        f"(more than {opts['max_converted_drop_pct']}%). See reports/summary.md.")

    inv_before, inv_now = prev_counts.get("invalid", 0), counts.get("invalid", 0)
    if prev_counts and inv_now - inv_before > opts["max_new_invalid"]:
        problems.append(f"Queries failing validation jumped from {inv_before} to {inv_now}. "
                        "See reports/validation_failed.md and reports/schema_drift.md.")

    HEALTH_FILE.unlink(missing_ok=True)
    if problems:
        HEALTH_FILE.write_text("\n".join(f"- {p}" for p in problems) + "\n")
        log("HEALTH CHECK PROBLEMS:\n" + HEALTH_FILE.read_text())
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
                fh.write("\n## Health check problems\n\n" + HEALTH_FILE.read_text())
    else:
        log("Health check: OK")
    return streak


# --------------------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.yml")
    ap.add_argument("--full", action="store_true", help="rebuild everything")
    ap.add_argument("--no-validate", action="store_true", help="skip KQL validation")
    args = ap.parse_args()

    cfg_path = ROOT / args.config
    cfg_text = cfg_path.read_text()
    cfg = yaml.safe_load(cfg_text)
    if cfg["target"] not in TARGETS:
        sys.exit(f"Unknown target {cfg['target']!r}; choose one of {', '.join(TARGETS)}")
    do_validate = cfg.get("validate", True) and not args.no_validate

    sigma_dir = ROOT / cfg["sigma_dir"]
    out_dir, rep_dir = ROOT / cfg["output_dir"], ROOT / cfg["reports_dir"]
    state_path = ROOT / cfg["state_file"]
    db_path = rep_dir / "rules.json"

    versions = tool_versions()

    # ---- schema used for validation: live Defender schema where available, bundled otherwise
    bundled = bundled_schema(cfg["target"])
    live, schema_source = live_schema(cfg)
    schema = {**bundled, **live}
    log(f"Live schema: {schema_source}")
    rep_dir.mkdir(parents=True, exist_ok=True)
    drift = ["# Schema drift", "",
             f"Live schema: {schema_source}", "",
             "Compares the schema bundled with pySigma-backend-kusto against the live Defender schema. "
             "Validation uses the live schema for every table it lists.", ""]
    drift += schema_drift(bundled, live) if live else ["No live schema in use."]
    (rep_dir / "schema_drift.md").write_text("\n".join(drift) + "\n")

    fp = fingerprint(cfg_text, cfg, versions, schema)
    state = load_json(state_path, {})
    head = git(sigma_dir, "rev-parse", "HEAD")
    rule_dirs = cfg["rule_dirs"]

    # ---- decide what to process
    full = args.full or state.get("fingerprint") != fp or not state.get("sigma_sha")
    changed, removed = [], []
    if not full:
        if state["sigma_sha"] == head:
            log(f"Nothing to do: already at SigmaHQ {head[:10]} with the same config.")
            state["schema_fail_streak"] = check_health(cfg, state, state.get("counts", {}), schema_source)
            write_json(state_path, state)
            return
        try:
            diff = git(sigma_dir, "diff", "--name-status", "--no-renames",
                       state["sigma_sha"], head, "--", *rule_dirs)
        except subprocess.CalledProcessError:
            log("Previous commit not found in SigmaHQ history; doing a full rebuild.")
            full = True
        else:
            for line in diff.splitlines():
                status, rel = line.split("\t", 1)
                if not rel.endswith(".yml"):
                    continue
                (removed if status == "D" else changed).append(rel)

    if full:
        log("Full rebuild.")
        shutil.rmtree(out_dir, ignore_errors=True)
        db = {}
        changed = sorted(str(p.relative_to(sigma_dir)) for d in rule_dirs
                         for p in (sigma_dir / d).rglob("*.yml"))
    else:
        db = load_json(db_path, {})
        log(f"Incremental: {state['sigma_sha'][:10]}..{head[:10]} — "
            f"{len(changed)} changed, {len(removed)} deleted.")
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- remove outputs for deleted and to-be-reprocessed rules
    for rel in removed + changed:
        old = db.pop(rel, None)
        if old and old.get("kql"):
            (ROOT / old["kql"]).unlink(missing_ok=True)

    # ---- convert
    backend = build_backend(cfg)
    results = {}
    for i, rel in enumerate(changed, 1):
        results[rel] = process_file(rel, sigma_dir, backend, cfg)
        if i % 500 == 0:
            log(f"  converted {i}/{len(changed)}")

    # ---- validate
    verdicts = {}
    if do_validate:
        schema_path = ROOT / "state" / f"schema_{cfg['target']}.json"
        write_json(schema_path, schema)
        batch = [{"id": f"{rel}#{n}#{q}", "query": query}
                 for rel, e in results.items() if e["result"] == "converted"
                 for n, info in enumerate(e["rules"]) for q, query in enumerate(info["queries"])]
        log(f"Validating {len(batch)} queries with Kusto.Language {versions['kusto-language']}...")
        verdicts = validate(batch, schema_path)

    # ---- write .kql files and update DB
    for rel, e in results.items():
        if e["result"] != "converted":
            db[rel] = {"result": e["result"], "reason": e["reason"], "title": e.get("title", ""),
                       "logsource": e.get("logsource", "")}
            continue
        all_errors = [err for n, info in enumerate(e["rules"]) for q, _ in enumerate(info["queries"])
                      for err in verdicts.get(f"{rel}#{n}#{q}", {}).get("errors", [])]
        too_deep = [x for x in all_errors if "syntax depth exceeds" in x]
        errors = [x for x in all_errors if x not in too_deep]
        if not do_validate:
            validation = "not run"
        elif too_deep:
            validation = "syntax only - query too deeply nested for full semantic analysis"
        else:
            validation = (f"passed (Kusto.Language {versions['kusto-language']}, "
                          f"{'live Defender' if live else 'bundled ' + cfg['target']} schema)")
        first = e["rules"][0]
        queries = [q for info in e["rules"] for q in info["queries"]]
        base = {"title": first["title"], "id": first["id"], "level": first["level"],
                "status": first["status"], "attack": first["attack"]}
        if errors:
            db[rel] = {**base, "result": "invalid", "errors": errors, "queries": queries}
            continue
        blocks = [header(info["rule"], rel, head, cfg, versions, validation, info.get("rewrites", 0))
                  + "\n\n" + "\n\n".join(info["queries"])
                  for info in e["rules"]]
        rewrites = sum(info.get("rewrites", 0) for info in e["rules"])
        kql_rel = f"{cfg['output_dir']}/{Path(rel).with_suffix('.kql')}"
        kql_path = ROOT / kql_rel
        kql_path.parent.mkdir(parents=True, exist_ok=True)
        kql_path.write_text("\n\n// ----------\n\n".join(blocks) + "\n", encoding="utf-8")
        table = queries[0].split("\n", 1)[0].split("|")[0].strip() if queries else ""
        db[rel] = {**base, "result": "converted", "kql": kql_rel, "table": table,
                   "validation": "partial" if too_deep else ("passed" if do_validate else "not run"),
                   "wildcard_rewrites": rewrites}

    # ---- clean up empty folders left by deletions
    for d in sorted((p for p in out_dir.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        if not any(d.iterdir()):
            d.rmdir()

    prev_state = state
    state = {"sigma_sha": head, "fingerprint": fp, "versions": versions,
             "last_run": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
             "last_mode": "full" if full else "incremental", "target": cfg["target"],
             "schema_source": schema_source}
    write_json(db_path, db)
    counts = write_reports(db, cfg, state, versions)
    state["counts"] = dict(counts)
    state["schema_fail_streak"] = check_health(cfg, prev_state, counts, schema_source)
    write_json(state_path, state)
    log(f"Done. converted={counts['converted']} invalid={counts['invalid']} "
        f"failed={counts['failed']} skipped={counts['skipped']}")


if __name__ == "__main__":
    main()
