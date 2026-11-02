#!/usr/bin/env python3
"""
Pending rules: convert rules from OPEN SigmaHQ pull requests (not yet reviewed or merged).

Every run rebuilds the pending folder from scratch from the pull requests that are open
right now, so cleanup is automatic:
  - PR merged  -> its pending rules disappear; the rule arrives in kql/ via the normal pipeline
  - PR closed  -> its pending rules disappear
  - PR updated -> its pending rules are reconverted from the latest commit

Rule files are read with git (no API quota). The GitHub API is used only to list open PRs,
authenticated with GITHUB_TOKEN when it is set (it is inside GitHub Actions).

Usage:
    python scripts/pending.py [--config config.yml] [--pr-list prs.json]
    --pr-list: read the open-PR list from a JSON file instead of the API (for testing)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import convert as cv  # noqa: E402  (reuses the main pipeline: backend, fixes, header, validator)

ROOT = cv.ROOT
REPO = "SigmaHQ/sigma"


def log(msg: str) -> None:
    print(msg, flush=True)


def git(sigma_dir: Path, *args: str, check: bool = True) -> str:
    return subprocess.run(["git", "-C", str(sigma_dir), *args], check=check,
                          capture_output=True, text=True).stdout


def clean(text: str, limit: int = 140) -> str:
    """PR titles and names are untrusted: one line, no control characters, bounded length."""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or "")).strip()
    return text[:limit]


# --------------------------------------------------------------------------- open PRs

def open_prs_from_api() -> list[dict]:
    token = os.environ.get("GITHUB_TOKEN", "")
    prs, page = [], 1
    while True:
        url = f"https://api.github.com/repos/{REPO}/pulls?state=open&per_page=100&page={page}"
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                   "User-Agent": "sigma2kql-pending"})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=30) as resp:
            batch = json.loads(resp.read())
        prs += [{"number": p["number"], "title": p["title"], "user": (p.get("user") or {}).get("login", ""),
                 "draft": p.get("draft", False), "url": p["html_url"], "head_sha": p["head"]["sha"],
                 "updated_at": p.get("updated_at", "")} for p in batch]
        if len(batch) < 100:
            return prs
        page += 1


# --------------------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yml")
    ap.add_argument("--pr-list", help="JSON file with the open PR list (testing)")
    args = ap.parse_args()

    cfg_text = (ROOT / args.config).read_text()
    cfg = yaml.safe_load(cfg_text)
    pcfg = {"enabled": True, "output_dir": "kql-pending", "include_drafts": False,
            "statuses": ["stable", "test", "experimental"], "levels": ["medium", "high", "critical"],
            "max_prs": 300, **(cfg.get("pending") or {})}
    if not pcfg["enabled"]:
        log("Pending rules are disabled in config.yml.")
        return

    sigma_dir = ROOT / cfg["sigma_dir"]
    out_dir = ROOT / pcfg["output_dir"]
    rep_dir = ROOT / cfg["reports_dir"]
    rule_dirs = cfg["rule_dirs"]

    prs = json.loads(Path(args.pr_list).read_text()) if args.pr_list else open_prs_from_api()
    skipped_drafts = [p for p in prs if p.get("draft") and not pcfg["include_drafts"]]
    prs = [p for p in prs if pcfg["include_drafts"] or not p.get("draft")]
    prs = sorted(prs, key=lambda p: -p["number"])[: pcfg["max_prs"]]
    log(f"Open pull requests: {len(prs)} (skipped {len(skipped_drafts)} drafts)")

    # one batched fetch for every PR head
    default = git(sigma_dir, "symbolic-ref", "--short", "refs/remotes/origin/HEAD", check=False).strip() or "origin/master"
    refspecs = [f"pull/{p['number']}/head:refs/remotes/pr/{p['number']}" for p in prs]
    for i in range(0, len(refspecs), 50):
        chunk = refspecs[i:i + 50]
        res = subprocess.run(["git", "-C", str(sigma_dir), "fetch", "-q", "--force", "origin", *chunk],
                             check=False, capture_output=True, text=True)
        if res.returncode != 0:   # one bad ref fails the whole batch: retry one by one
            for spec in chunk:
                subprocess.run(["git", "-C", str(sigma_dir), "fetch", "-q", "--force", "origin", spec],
                               check=False, capture_output=True, text=True)

    # pending rules use the pending filters, everything else matches the main pipeline
    run_cfg = {**cfg, "statuses": pcfg["statuses"], "levels": pcfg["levels"]}
    backend = cv.build_backend(cfg)
    versions = cv.tool_versions()

    # validation schema: the live Defender schema cached by the main run, else the bundled one
    schema = cv.bundled_schema(cfg["target"])
    live_cache = ROOT / (cfg.get("live_schema") or {}).get("cache", "state/xdr_schema.json")
    live = cv.load_json(live_cache, {}) if cfg["target"] == "microsoft_xdr" else {}
    schema = {**schema, **live}
    schema_path = ROOT / "state" / "schema_pending.json"
    cv.write_json(schema_path, schema)

    shutil.rmtree(out_dir, ignore_errors=True)   # rebuilt from scratch = automatic cleanup
    out_dir.mkdir(parents=True)
    tmp_root = Path(tempfile.mkdtemp(prefix="sigma-pending-"))

    results = []   # one per rule file
    try:
        for pr in prs:
            n, ref = pr["number"], f"refs/remotes/pr/{pr['number']}"
            if subprocess.run(["git", "-C", str(sigma_dir), "rev-parse", "-q", "--verify", ref],
                              capture_output=True).returncode != 0:
                log(f"  PR #{n}: could not fetch, skipped")
                continue
            base = git(sigma_dir, "merge-base", default, ref, check=False).strip()
            if not base:
                continue
            diff = git(sigma_dir, "diff", "--name-status", "--no-renames", base, ref, "--", *rule_dirs, check=False)
            head_sha = git(sigma_dir, "rev-parse", ref).strip()
            for line in diff.splitlines():
                status, rel = line.split("\t", 1)
                if status not in ("A", "M") or not rel.endswith(".yml"):
                    continue
                content = git(sigma_dir, "show", f"{ref}:{rel}", check=False)
                if not content:
                    continue
                dest = tmp_root / str(n) / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
                entry = cv.process_file(rel, tmp_root / str(n), backend, run_cfg)
                results.append({"pr": pr, "rel": rel, "change": "new rule" if status == "A" else "update to existing rule",
                                "sha": head_sha, "entry": entry})

        # validate every converted query in one pass
        batch = [{"id": f"{i}#{k}#{q}", "query": query}
                 for i, r in enumerate(results) if r["entry"]["result"] == "converted"
                 for k, info in enumerate(r["entry"]["rules"]) for q, query in enumerate(info["queries"])]
        verdicts = cv.validate(batch, schema_path) if cfg.get("validate", True) else {}

        written = 0
        for i, r in enumerate(results):
            e = r["entry"]
            if e["result"] != "converted":
                continue
            errors = [err for k, info in enumerate(e["rules"]) for q, _ in enumerate(info["queries"])
                      for err in verdicts.get(f"{i}#{k}#{q}", {}).get("errors", [])
                      if "syntax depth exceeds" not in err]
            if errors:
                e["result"], e["reason"] = "invalid", errors[0]
                continue
            pr = r["pr"]
            pending_lines = [
                f"// PENDING: from an OPEN SigmaHQ pull request. Not reviewed or merged by SigmaHQ yet.",
                f"// Pull request: #{pr['number']} {clean(pr['title'])}",
                f"// Pull request URL: https://github.com/{REPO}/pull/{pr['number']}",
                f"// Pull request author: {clean(pr.get('user', ''), 60)}",
                f"// Change: {r['change']}",
            ]
            blocks = []
            for info in e["rules"]:
                hdr = cv.header(info["rule"], r["rel"], r["sha"], cfg, versions,
                                "passed (Kusto.Language, Defender schema)" if cfg.get("validate", True) else "not run",
                                info.get("rewrites", 0))
                blocks.append("\n".join(pending_lines) + "\n" + hdr + "\n\n" + "\n\n".join(info["queries"]))
            path = out_dir / f"pr-{pr['number']}" / Path(r["rel"]).with_suffix(".kql")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n\n// ----------\n\n".join(blocks) + "\n", encoding="utf-8")
            r["kql"] = str(path.relative_to(ROOT))
            written += 1
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    # ---- index + report
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = Counter(r["entry"]["result"] for r in results)
    idx = ["# Pending rules from open SigmaHQ pull requests", "",
           "> [!CAUTION]",
           "> These rules come from **open pull requests that SigmaHQ has not reviewed or merged**. "
           "They may change, be rejected, or be wrong. Machine-converted and untested. Use for early hunting only.",
           "", f"Rebuilt {now} from {len(prs)} open pull requests. When a pull request is merged or closed, "
           "its pending rules are removed automatically on the next run.", ""]
    by_pr: dict[int, list] = {}
    for r in results:
        if r.get("kql"):
            by_pr.setdefault(r["pr"]["number"], []).append(r)
    for n in sorted(by_pr, reverse=True):
        pr = by_pr[n][0]["pr"]
        idx += [f"## [#{n}](https://github.com/{REPO}/pull/{n}) {clean(pr['title'])}", "",
                "| Rule | Change | Level |", "|---|---|---|"]
        for r in by_pr[n]:
            info = r["entry"]["rules"][0]
            title = info["title"].replace("|", "\\|")
            idx.append(f"| [{title}]({Path(r['kql']).relative_to(pcfg['output_dir'])}) | {r['change']} | {info['level']} |")
        idx.append("")
    (out_dir / "INDEX.md").write_text("\n".join(idx) + "\n", encoding="utf-8")

    rep = ["# Pending rules run", "", f"- Run: {now}", f"- Open pull requests checked: {len(prs)} (drafts skipped: {len(skipped_drafts)})",
           f"- Pull requests with converted rules: {len(by_pr)}", "",
           "| Result | Rule files |", "|---|---|",
           f"| Converted and valid | {counts['converted']} |", f"| Failed validation | {counts['invalid']} |",
           f"| Failed conversion | {counts['failed']} |", f"| Skipped (filters) | {counts['skipped']} |", "",
           "## Not converted", ""]
    rep += [f"- #{r['pr']['number']} `{r['rel']}`: {r['entry']['reason']}" for r in results
            if r["entry"]["result"] in ("failed", "invalid")]
    rep_dir.mkdir(parents=True, exist_ok=True)
    (rep_dir / "pending.md").write_text("\n".join(rep) + "\n", encoding="utf-8")
    log(f"Pending rules done: {written} rule files from {len(by_pr)} pull requests "
        f"(invalid={counts['invalid']} failed={counts['failed']} skipped={counts['skipped']})")


if __name__ == "__main__":
    main()
