#!/usr/bin/env python3
"""
Static JSON API for sigma2kql, served by GitHub Pages next to the search page.

Writes, under docs/api/v1/:
  index.json    manifest: run metadata, counts, endpoint URLs
  rules.json    every converted rule (published + pending) with metadata and KQL
  schema.json   JSON Schema describing rules.json
and docs/api/index.html, a human-readable page documenting the API.

Called by build_site.py, so the workflow needs no extra step.

Versioning: v1 field names and meanings are stable. New fields may be added; nothing is
renamed or removed without a new version path (/api/v2/).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

API_VERSION = "v1"
SCHEMA_VERSION = "1.0.0"
LICENSE_RULES = "Detection Rule License (DRL) 1.1 - https://github.com/SigmaHQ/Detection-Rule-License"
DISCLAIMER = ("Machine-generated from SigmaHQ rules and not tested against real telemetry. "
              "Provided as is, with no warranty. Run as hunts and tune before using as detections.")


def site_urls(cfg: dict) -> tuple[str, str]:
    """(site_url, repo_url). Forks get their own URLs from GITHUB_REPOSITORY in Actions."""
    repo = os.environ.get("GITHUB_REPOSITORY") or cfg.get("github_repository") or "Tenbite/sigma2kql"
    owner, name = repo.split("/", 1)
    site = cfg.get("site_url") or f"https://{owner.lower()}.github.io/{name}/"
    return site.rstrip("/") + "/", f"https://github.com/{repo}"


def _split_attack(attack: list[str]) -> tuple[list[str], list[str]]:
    techniques = [a for a in attack if re.fullmatch(r"T\d+(\.\d+)?", a)]
    tactics = [a for a in attack if not re.fullmatch(r"[TGS]\d+(\.\d+)?", a)]
    return tactics, techniques


def to_record(meta: dict, queries: list[str], *, rel: str, kql_path: str, stage: str,
              platform: str, source: str, repo_url: str) -> dict:
    """One API record from a parsed .kql header (see build_site.parse_block)."""
    status_line = meta.get("Status", "")
    level = (re.search(r"Level:\s*(\w+)", status_line) or [None, ""])[1]
    date_line = meta.get("Date", "")
    created = date_line.split("|")[0].strip()
    modified = (re.search(r"Modified:\s*(\d{4}-\d{2}-\d{2})", date_line) or [None, ""])[1]
    attack = [a.strip() for a in meta.get("ATT&CK", "").split(",") if a.strip()]
    tactics, techniques = _split_attack(attack)
    validation = meta.get("Validation", "")
    sigma_url = meta.get("Sigma rule", "")
    sigma_id = meta.get("Sigma ID", "")
    tables = [q.split("\n", 1)[0].split("|")[0].strip() for q in queries if q]

    pending = None
    if stage == "Pending":
        m = re.match(r"#(\d+)\s*(.*)", meta.get("Pull request", ""))
        pending = {
            "pr_number": int(m.group(1)) if m else None,
            "pr_title": m.group(2).strip() if m else meta.get("Pull request", ""),
            "pr_url": meta.get("Pull request URL", ""),
            "pr_author": meta.get("Pull request author", ""),
            "change": meta.get("Change", ""),
        }

    as_list = lambda v: v if isinstance(v, list) else []
    return {
        "uid": f"pr-{pending['pr_number']}/{sigma_id}" if pending else sigma_id,
        "sigma_id": sigma_id,
        "title": meta.get("Title", ""),
        "stage": stage.lower(),
        "status": status_line.split("|")[0].strip(),
        "level": level,
        "author": meta.get("Author", ""),
        "date": created if created != "-" else "",
        "modified": modified,
        "description": meta.get("Description", ""),
        "false_positives": as_list(meta.get("False positives")),
        "references": as_list(meta.get("References")),
        "tags": [t.strip() for t in meta.get("Tags", "").split(",") if t.strip()],
        "attack": {"tactics": tactics, "techniques": techniques},
        "platform": platform,
        "source": source,
        "sigma": {"path": (re.search(r"/blob/[0-9a-f]+/(.+)$", sigma_url) or [None, rel.replace(".kql", ".yml")])[1], "url": sigma_url},
        "kql": {
            "table": tables[0] if tables else "",
            "tables": sorted(set(tables)),
            "queries": queries,
            "file": kql_path,
            "file_url": f"{repo_url}/blob/main/{kql_path}",
            "raw_url": f"{repo_url.replace('https://github.com/', 'https://raw.githubusercontent.com/')}/main/{kql_path}",
        },
        "validation": {
            "status": "passed" if validation.startswith("passed") else ("syntax_only" if validation.startswith("syntax only") else "unknown"),
            "detail": validation,
        },
        "notes": [meta["Note"]] if meta.get("Note") else [],
        "pending": pending,
        "license": LICENSE_RULES,
    }


def _manifest(records: list[dict], cfg: dict, root: Path, site: str, repo_url: str, size: int) -> dict:
    try:
        state = json.loads((root / cfg.get("state_file", "state/state.json")).read_text())
    except (OSError, ValueError):
        state = {}
    base = f"{site}api/{API_VERSION}/"
    pending = [r for r in records if r["stage"] == "pending"]
    return {
        "name": "sigma2kql API",
        "description": "SigmaHQ detection rules converted to Microsoft Defender XDR Advanced Hunting KQL, with metadata.",
        "api_version": API_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "update_schedule": "nightly, run starts 06:17 UTC",
        "target": state.get("target", cfg.get("target", "")),
        "sigmahq_commit": state.get("sigma_sha", ""),
        "tools": state.get("versions", {}),
        "validation_schema": state.get("schema_source", ""),
        "counts": {
            "total": len(records),
            "published": len(records) - len(pending),
            "pending": len(pending),
            "pending_pull_requests": len({r["pending"]["pr_number"] for r in pending}),
        },
        "endpoints": {
            "manifest": f"{base}index.json",
            "rules": f"{base}rules.json",
            "schema": f"{base}schema.json",
            "docs": f"{site}api/",
        },
        "rules_bytes": size,
        "homepage": site,
        "repository": repo_url,
        "license": {"rules": LICENSE_RULES, "code": f"MIT - {repo_url}/blob/main/LICENSE"},
        "disclaimer": DISCLAIMER,
    }


def write(records: list[dict], cfg: dict, root: Path) -> None:
    site, repo_url = site_urls(cfg)
    out = root / "docs" / "api" / API_VERSION
    out.mkdir(parents=True, exist_ok=True)
    # Stable order and one rule per line, so nightly git diffs stay small.
    records = sorted(records, key=lambda r: (r["stage"] != "published", r["sigma"]["path"], r["uid"]))
    body = ",\n".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) for r in records)
    meta_stub = {"api_version": API_VERSION, "schema_version": SCHEMA_VERSION}
    rules_text = '{"meta":' + json.dumps(meta_stub) + ',"rules":[\n' + body + "\n]}\n"
    manifest = _manifest(records, cfg, root, site, repo_url, len(rules_text.encode()))
    meta = {k: manifest[k] for k in ("api_version", "schema_version", "generated_at", "sigmahq_commit",
                                     "target", "tools", "counts", "endpoints", "license", "disclaimer")}
    rules_text = '{"meta":' + json.dumps(meta, ensure_ascii=False) + ',"rules":[\n' + body + "\n]}\n"
    (out / "rules.json").write_text(rules_text, encoding="utf-8")
    (out / "index.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "schema.json").write_text(json.dumps(SCHEMA, indent=2) + "\n", encoding="utf-8")
    page = DOCS.replace("__SITE__", site).replace("__REPO__", repo_url).replace("__BASE__", f"{site}api/{API_VERSION}/")
    page = page.replace("__TOTAL__", f"{manifest['counts']['total']:,}").replace("__PUBLISHED__", f"{manifest['counts']['published']:,}")
    page = page.replace("__PENDING__", f"{manifest['counts']['pending']:,}").replace("__MB__", f"{len(rules_text.encode()) / 1e6:.1f}")
    (root / "docs" / "api" / "index.html").write_text(page, encoding="utf-8")
    print(f"API: wrote {len(records)} rules to docs/api/{API_VERSION}/rules.json ({len(rules_text.encode()) / 1e6:.1f} MB)")


_str = {"type": "string"}
_strs = {"type": "array", "items": {"type": "string"}}
SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://tenbite.github.io/sigma2kql/api/v1/schema.json",
    "title": "sigma2kql rules (API v1)",
    "type": "object",
    "required": ["meta", "rules"],
    "properties": {
        "meta": {"type": "object", "description": "Run metadata; same fields as index.json."},
        "rules": {"type": "array", "items": {
            "type": "object",
            "required": ["uid", "sigma_id", "title", "stage", "level", "kql", "validation", "license"],
            "properties": {
                "uid": {**_str, "description": "Unique key. The Sigma ID for published rules; 'pr-<number>/<Sigma ID>' for pending rules."},
                "sigma_id": {**_str, "description": "Sigma rule ID (UUID). A rule can appear as published and as pending (an update in an open pull request)."},
                "title": _str,
                "stage": {"enum": ["published", "pending"], "description": "pending = from an open, unmerged SigmaHQ pull request."},
                "status": {**_str, "description": "Sigma status: stable, test, experimental."},
                "level": {**_str, "description": "Sigma level: medium, high, critical."},
                "author": _str,
                "date": {**_str, "description": "Rule creation date (YYYY-MM-DD)."},
                "modified": {**_str, "description": "Last modified date (YYYY-MM-DD), or empty."},
                "description": _str,
                "false_positives": _strs,
                "references": _strs,
                "tags": {**_strs, "description": "Non-ATT&CK Sigma tags, e.g. detection.threat-hunting."},
                "attack": {"type": "object", "properties": {"tactics": _strs, "techniques": _strs}},
                "platform": {**_str, "description": "Windows, Linux, macOS or Other."},
                "source": {**_str, "description": "SigmaHQ folder: Core, Emerging threats, Threat hunting."},
                "sigma": {"type": "object", "properties": {"path": _str, "url": {**_str, "description": "Exact Sigma rule version converted."}}},
                "kql": {"type": "object", "properties": {
                    "table": {**_str, "description": "Main Defender XDR table, e.g. DeviceProcessEvents."},
                    "tables": _strs,
                    "queries": {**_strs, "description": "One query per Sigma rule in the file (usually one)."},
                    "file": {**_str, "description": "Path of the .kql file in the repository."},
                    "file_url": _str, "raw_url": _str}},
                "validation": {"type": "object", "properties": {
                    "status": {"enum": ["passed", "syntax_only", "unknown"]},
                    "detail": _str}},
                "notes": {**_strs, "description": "Conversion notes, e.g. automatic fixes applied."},
                "pending": {"type": ["object", "null"], "properties": {
                    "pr_number": {"type": ["integer", "null"]}, "pr_title": _str, "pr_url": _str,
                    "pr_author": _str, "change": {**_str, "description": "new rule | update to existing rule"}}},
                "license": _str,
            }}},
    },
}


DOCS = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sigma2kql JSON API</title>
<meta name="description" content="Free JSON API with every SigmaHQ rule converted to Microsoft Defender XDR KQL, with metadata. Updated nightly.">
<style>
:root { --bg: #0f1419; --panel: #161c23; --ink: #e6e9ee; --muted: #9aa5b1; --rule: #2a323c; --accent: #5ba8c9; --code: #11171d; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 860px; margin: 0 auto; padding: 32px 16px 64px; }
a { color: var(--accent); }
h1 { font-size: 1.7rem; margin: 0 0 6px; } h2 { font-size: 1.2rem; margin: 32px 0 8px; }
.sub { color: var(--muted); margin: 0 0 12px; }
.warn { padding: 10px 14px; border-left: 3px solid #d4a14a; background: var(--panel); color: var(--muted); font-size: .92rem; }
table { width: 100%; border-collapse: collapse; font-size: .92rem; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--rule); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
code { font: .88em ui-monospace, SFMono-Regular, Consolas, monospace; background: var(--code); padding: 1px 5px; border-radius: 4px; }
pre { background: var(--code); border: 1px solid var(--rule); border-radius: 8px; padding: 12px 14px; overflow-x: auto; font: .85rem/1.5 ui-monospace, SFMono-Regular, Consolas, monospace; }
pre code { background: none; padding: 0; }
.nav { margin: 0 0 20px; font-size: .92rem; }
footer { margin-top: 40px; color: var(--muted); font-size: .85rem; }
</style>
</head>
<body>
<main>
<p class="nav"><a href="__SITE__">&larr; Search the rules</a> · <a href="__REPO__">Source on GitHub</a></p>
<h1>sigma2kql JSON API</h1>
<p class="sub">Every converted rule (__TOTAL__ today: __PUBLISHED__ published, __PENDING__ pending), with its metadata and Defender XDR KQL, as static JSON. Free, no key, rebuilt nightly. Rules were written by the <a href="https://github.com/SigmaHQ/sigma">SigmaHQ</a> community.</p>
<p class="warn">Machine-generated and not tested against real telemetry. Queries pass Microsoft's KQL parser against the live Defender schema, which proves they are valid KQL, not that they detect what the rule describes. Rules are under the <a href="https://github.com/SigmaHQ/Detection-Rule-License">DRL 1.1</a>: keep each rule's author and Sigma ID if you redistribute.</p>

<h2>Endpoints</h2>
<table>
<tr><th>URL</th><th>What it is</th></tr>
<tr><td><a href="__BASE__index.json"><code>/api/v1/index.json</code></a></td><td>Small manifest: when it was built, SigmaHQ commit, tool versions, counts, endpoint URLs. Check this first to see if anything changed.</td></tr>
<tr><td><a href="__BASE__rules.json"><code>/api/v1/rules.json</code></a></td><td>All rules with metadata and KQL (about __MB__ MB, compressed in transit).</td></tr>
<tr><td><a href="__BASE__schema.json"><code>/api/v1/schema.json</code></a></td><td>JSON Schema for <code>rules.json</code>.</td></tr>
</table>
<p>It is a static file, so there's no server-side filtering: download once, then filter locally. Fields are stable within <code>v1</code>; new fields may be added, nothing is renamed or removed without a <code>/v2/</code>.</p>

<h2>Examples</h2>
<p><strong>curl + jq:</strong> high and critical published rules on DeviceProcessEvents</p>
<pre><code>curl -s __BASE__rules.json | jq '.rules[]
  | select(.stage=="published" and (.level=="high" or .level=="critical") and .kql.table=="DeviceProcessEvents")
  | {title, sigma_id, query: .kql.queries[0]}'</code></pre>
<p><strong>PowerShell:</strong> rules for one ATT&amp;CK technique</p>
<pre><code>$api = Invoke-RestMethod __BASE__rules.json
$api.rules | Where-Object { $_.attack.techniques -contains 'T1105' } | Select-Object title, level, sigma_id</code></pre>
<p><strong>Python:</strong> rules changed in the last 30 days</p>
<pre><code>import datetime, requests
data = requests.get("__BASE__rules.json", timeout=60).json()
since = (datetime.date.today() - datetime.timedelta(days=30)).isoformat()
for r in data["rules"]:
    if (r["modified"] or r["date"]) &gt;= since:
        print(r["level"], r["title"], r["kql"]["file_url"])</code></pre>

<h2>Rule fields</h2>
<table>
<tr><th>Field</th><th>Meaning</th></tr>
<tr><td><code>uid</code></td><td>Unique key: the Sigma ID, or <code>pr-&lt;number&gt;/&lt;Sigma ID&gt;</code> for pending rules.</td></tr>
<tr><td><code>sigma_id</code>, <code>title</code>, <code>status</code>, <code>level</code>, <code>author</code>, <code>date</code>, <code>modified</code>, <code>description</code></td><td>From the Sigma rule.</td></tr>
<tr><td><code>false_positives</code>, <code>references</code>, <code>tags</code></td><td>Lists from the Sigma rule.</td></tr>
<tr><td><code>attack.tactics</code>, <code>attack.techniques</code></td><td>MITRE ATT&amp;CK mapping.</td></tr>
<tr><td><code>stage</code></td><td><code>published</code>, or <code>pending</code> for rules from open SigmaHQ pull requests (not reviewed or merged yet).</td></tr>
<tr><td><code>platform</code>, <code>source</code></td><td>Windows / Linux / macOS / Other; SigmaHQ folder (Core, Emerging threats, Threat hunting).</td></tr>
<tr><td><code>sigma.path</code>, <code>sigma.url</code></td><td>The exact Sigma rule version that was converted.</td></tr>
<tr><td><code>kql.table</code>, <code>kql.tables</code>, <code>kql.queries</code></td><td>Defender XDR table(s) and the query text.</td></tr>
<tr><td><code>kql.file</code>, <code>kql.file_url</code>, <code>kql.raw_url</code></td><td>Where the <code>.kql</code> file lives in the repo.</td></tr>
<tr><td><code>validation.status</code></td><td><code>passed</code> (parser + live schema) or <code>syntax_only</code> (too deeply nested for full analysis).</td></tr>
<tr><td><code>notes</code></td><td>Automatic fixes applied during conversion, if any.</td></tr>
<tr><td><code>pending</code></td><td>For pending rules: <code>pr_number</code>, <code>pr_title</code>, <code>pr_url</code>, <code>pr_author</code>, <code>change</code>. Otherwise <code>null</code>.</td></tr>
<tr><td><code>license</code></td><td>The rule's license (DRL 1.1).</td></tr>
</table>

<h2>Good to know</h2>
<ul>
<li>Updated nightly. Pending rules come and go as pull requests open, merge, or close.</li>
<li>Be kind to GitHub Pages: fetch once a day at most, or check <code>index.json</code>'s <code>generated_at</code> first.</li>
<li>Prefer git? The same data is in the repo as one <code>.kql</code> file per rule.</li>
<li>Found a bad rule? <a href="__REPO__/issues/new?template=bad-rule.md">Open an issue</a>.</li>
</ul>
<footer>Rules by the SigmaHQ community and their original authors, under the DRL 1.1. Code MIT. Not affiliated with SigmaHQ or Microsoft.</footer>
</main>
</body>
</html>
"""
