#!/usr/bin/env python3
"""
Build the searchable rule browser for GitHub Pages.

Reads every .kql file the converter wrote and produces:
  docs/rules.json   one record per rule (metadata + query)
  docs/index.html   a single-page browser with search and filters

Usage: python scripts/build_site.py [--config config.yml]
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SOURCES = {"rules": "Core", "rules-emerging-threats": "Emerging threats", "rules-threat-hunting": "Threat hunting"}
LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def platform_of(rel: str) -> str:
    parts = rel.split("/")
    if parts[0] == "rules" and len(parts) > 1 and parts[1] in ("windows", "linux", "macos"):
        return {"windows": "Windows", "linux": "Linux", "macos": "macOS"}[parts[1]]
    name = parts[-1]
    if "_win_" in name or name.startswith("win_"):
        return "Windows"
    if "_lnx_" in name or name.startswith("lnx_"):
        return "Linux"
    if "_macos_" in name or name.startswith("macos_"):
        return "macOS"
    return "Other"


LIST_FIELDS = {"False positives", "References"}   # header fields written as "- item" lines


def parse_block(block: str) -> dict:
    meta, query_lines, current = {}, [], None
    for line in block.splitlines():
        if not line.startswith("//"):
            query_lines.append(line)
            continue
        text = line[2:]
        if text.startswith("   ") and current:  # continuation of the previous field
            item = text.strip()
            value = meta.get(current)
            if isinstance(value, list):        # list fields (false positives, references)
                if item.startswith("- ") or not value:
                    value.append(item[2:] if item.startswith("- ") else item)
                else:
                    value[-1] += " " + item
            else:                              # text fields: a wrapped line may start with "- "
                meta[current] = (str(value or "") + " " + item).strip()
            continue
        m = re.match(r" ([A-Za-z&' ]+):\s?(.*)$", text)
        if not m:
            current = None
            continue
        key, value = m.group(1).strip(), m.group(2).strip()
        current = key
        meta[key] = value if value or key not in LIST_FIELDS else []
    meta["query"] = "\n".join(query_lines).strip()
    return meta


def build(cfg: dict) -> int:
    out_dir = ROOT / "docs"
    out_dir.mkdir(exist_ok=True)
    pending_dir = (cfg.get("pending") or {}).get("output_dir", "kql-pending")
    roots = [(ROOT / cfg["output_dir"], cfg["output_dir"], "Published"), (ROOT / pending_dir, pending_dir, "Pending")]
    records = []
    skipped = []
    for kql_root, out_name, stage, path in ((r, n, st, p) for r, n, st in roots if r.exists() for p in sorted(r.rglob("*.kql"))):
      try:
        full_rel = str(path.relative_to(kql_root))
        rel = full_rel.split("/", 1)[1] if stage == "Pending" else full_rel   # drop the pr-<n>/ prefix
        blocks = path.read_text(encoding="utf-8").split("\n\n// ----------\n\n")
        first = parse_block(blocks[0])
        queries = [parse_block(b)["query"] for b in blocks]
        status_line = first.get("Status", "")
        status = status_line.split("|")[0].strip()
        m = re.search(r"Level:\s*(\w+)", status_line)
        level = m.group(1) if m else ""
        attack = [a.strip() for a in first.get("ATT&CK", "").split(",") if a.strip()]
        records.append({
            "t": first.get("Title", path.stem),
            "id": first.get("Sigma ID", ""),
            "lv": level,
            "st": status,
            "au": first.get("Author", ""),
            "dt": first.get("Date", "").split("|")[0].strip(),
            "ta": [a for a in attack if not re.fullmatch(r"[TGS]\d+(\.\d+)?", a)],
            "te": [a for a in attack if re.fullmatch(r"T\d+(\.\d+)?", a)],
            "tb": queries[0].split("\n", 1)[0].split("|")[0].strip() if queries else "",
            "pf": platform_of(rel),
            "src": SOURCES.get(rel.split("/")[0], rel.split("/")[0]),
            "de": first.get("Description", ""),
            "fp": first.get("False positives", []) if isinstance(first.get("False positives"), list) else [],
            "sg": first.get("Sigma rule", ""),
            "kp": f"{out_name}/{full_rel}",
            "q": "\n\n".join(queries),
            "stg": stage,
            "pr": first.get("Pull request", ""),
            "pru": first.get("Pull request URL", ""),
            "ch": first.get("Change", ""),
        })
      except Exception as exc:  # one odd file must never take the whole page down
        skipped.append(f"{path}: {exc}")
    for line in skipped:
        print(f"WARNING: skipped {line}")
    records.sort(key=lambda r: (LEVEL_ORDER.get(r["lv"], 9), r["t"].lower()))
    (out_dir / "rules.json").write_text(json.dumps(records, separators=(",", ":")), encoding="utf-8")
    built = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    (out_dir / "index.html").write_text(PAGE.replace("__BUILT__", built), encoding="utf-8")
    (out_dir / ".nojekyll").write_text("")
    return len(records)


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sigma to Defender KQL: rule browser</title>
<meta name="description" content="Search and filter SigmaHQ rules converted to Microsoft Defender XDR KQL. Copy any query into Advanced Hunting.">
<style>
:root {
  --bg: #15191e; --panel: #1b2026; --raise: #222830; --ink: #e6e8ea; --muted: #9aa3ad;
  --rule: #2c333b; --accent: #6db3cf; --accent-ink: #0f1a20;
  --crit: #f07178; --high: #f2a65a; --med: #e6c76b; --low: #8fbf7f;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, "Cascadia Code", "JetBrains Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--bg); color: var(--ink); font-family: var(--sans); font-size: 15px; line-height: 1.5; }
a { color: var(--accent); }
a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
header { border-bottom: 1px solid var(--rule); }
.wrap { max-width: 1100px; margin: 0 auto; padding: 0 16px; }
header .wrap { padding-top: 20px; padding-bottom: 16px; }
h1 { font-size: 1.45rem; margin: 0 0 4px; letter-spacing: -0.01em; }
.sub { color: var(--muted); margin: 0; font-size: 0.93rem; }
.warn { margin: 12px 0 0; padding: 8px 12px; border-left: 3px solid var(--high); background: var(--panel); color: var(--muted); font-size: 0.88rem; }
.controls { position: sticky; top: 0; z-index: 5; background: var(--bg); border-bottom: 1px solid var(--rule); }
.controls .wrap { padding-top: 12px; padding-bottom: 12px; display: grid; gap: 10px; }
#q { width: 100%; padding: 10px 12px; font-size: 1rem; background: var(--panel); color: var(--ink); border: 1px solid var(--rule); border-radius: 8px; }
.filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
select { padding: 7px 8px; background: var(--panel); color: var(--ink); border: 1px solid var(--rule); border-radius: 6px; font-size: 0.9rem; max-width: 100%; }
#reset { padding: 7px 10px; background: none; border: 1px solid var(--rule); color: var(--muted); border-radius: 6px; cursor: pointer; font-size: 0.9rem; }
#reset:hover { color: var(--ink); }
#count { color: var(--muted); font-size: 0.9rem; margin-left: auto; }
main .wrap { padding-top: 12px; padding-bottom: 40px; }
details.rule { border: 1px solid var(--rule); border-radius: 8px; background: var(--panel); margin-bottom: 8px; }
details.rule[open] { background: var(--raise); }
summary { list-style: none; cursor: pointer; padding: 10px 12px; display: grid; grid-template-columns: auto 1fr; gap: 4px 10px; align-items: baseline; }
summary::-webkit-details-marker { display: none; }
.lv { font-size: 0.75rem; font-weight: 700; padding: 2px 7px; border-radius: 999px; color: var(--accent-ink); text-transform: capitalize; }
.lv.critical { background: var(--crit); } .lv.high { background: var(--high); } .lv.medium { background: var(--med); } .lv.low { background: var(--low); }
.title { font-weight: 600; }
.meta { grid-column: 2; color: var(--muted); font-size: 0.84rem; display: flex; flex-wrap: wrap; gap: 4px 12px; }
.body { padding: 0 12px 12px; }
.body p { margin: 4px 0 10px; color: var(--ink); }
.body h4 { margin: 12px 0 4px; font-size: 0.82rem; color: var(--muted); font-weight: 600; }
.body ul { margin: 0 0 8px; padding-left: 18px; color: var(--muted); font-size: 0.9rem; }
pre { margin: 0; padding: 12px; background: #0f1317; border: 1px solid var(--rule); border-radius: 6px; overflow-x: auto; font-family: var(--mono); font-size: 0.82rem; line-height: 1.45; white-space: pre-wrap; word-break: break-word; }
.qhead { display: flex; justify-content: space-between; align-items: center; margin: 12px 0 6px; }
.copy { padding: 5px 10px; background: var(--accent); color: var(--accent-ink); border: 0; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.85rem; }
.links { display: flex; gap: 14px; flex-wrap: wrap; font-size: 0.88rem; margin-top: 10px; }
#more { display: block; margin: 16px auto 0; padding: 9px 16px; background: var(--panel); color: var(--ink); border: 1px solid var(--rule); border-radius: 8px; cursor: pointer; }
.pv { display: inline-block; margin-left: 6px; font-size: 0.72rem; font-weight: 700; padding: 1px 7px; border-radius: 999px; border: 1px solid var(--high); color: var(--high); vertical-align: 2px; }
.pvnote { padding: 8px 10px; border-left: 3px solid var(--high); background: var(--bg); color: var(--muted) !important; font-size: 0.9rem; }
.empty { color: var(--muted); padding: 24px 0; text-align: center; }
footer { color: var(--muted); font-size: 0.85rem; border-top: 1px solid var(--rule); }
footer .wrap { padding-top: 14px; padding-bottom: 28px; }
@media (max-width: 600px) { .controls { position: static; } #count { width: 100%; margin-left: 0; } select { flex: 1 1 45%; } }
</style>
</head>
<body>
<header><div class="wrap">
  <h1>Sigma to Defender KQL</h1>
  <p class="sub">SigmaHQ rules converted to Microsoft Defender XDR Advanced Hunting queries, plus pending rules from open SigmaHQ pull requests (labeled). Rebuilt nightly. <a href="https://github.com/Tenbite/sigma2kql">Repo</a></p>
  <p class="warn">Machine-generated and not tested against real telemetry. Provided as is, with no warranty. Run as a hunt and tune before using as a detection. Rules are under the <a href="https://github.com/SigmaHQ/Detection-Rule-License">Detection Rule License 1.1</a>.</p>
</div></header>

<div class="controls"><div class="wrap">
  <input id="q" type="search" placeholder="Search titles, descriptions, techniques, or query text (e.g. lsass, T1059, rundll32)" aria-label="Search rules" autocomplete="off">
  <div class="filters">
    <select id="f-lv" aria-label="Level"><option value="">All levels</option></select>
    <select id="f-pf" aria-label="Platform"><option value="">All platforms</option></select>
    <select id="f-ta" aria-label="ATT&CK tactic"><option value="">All tactics</option></select>
    <select id="f-tb" aria-label="Defender table"><option value="">All tables</option></select>
    <select id="f-src" aria-label="Source folder"><option value="">All sources</option></select>
    <select id="f-stg" aria-label="Stage"><option value="">Published + pending</option></select>
    <button id="reset" type="button">Clear</button>
    <span id="count" aria-live="polite">Loading rules…</span>
  </div>
</div></div>

<main><div class="wrap">
  <div id="list"></div>
  <button id="more" type="button" hidden>Show more</button>
</div></main>

<footer><div class="wrap">
  Built __BUILT__ from <a href="https://github.com/SigmaHQ/sigma">SigmaHQ</a> with pySigma and the Kusto backend. Each rule keeps its original author and Sigma ID.
</div></footer>

<script>
(() => {
  const PAGE = 50;
  let all = [], shown = [], limit = PAGE;
  const $ = id => document.getElementById(id);
  const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const F = { lv: $('f-lv'), pf: $('f-pf'), ta: $('f-ta'), tb: $('f-tb'), src: $('f-src'), stg: $('f-stg') };
  const LV = ['critical', 'high', 'medium', 'low', 'informational'];

  function fill(sel, values) {
    for (const v of values) { const o = document.createElement('option'); o.value = v; o.textContent = v.charAt(0).toUpperCase() + v.slice(1); sel.appendChild(o); }
  }
  function uniq(fn) { const s = new Set(); all.forEach(r => [].concat(fn(r)).forEach(v => v && s.add(v))); return [...s]; }

  function readHash() {
    const p = new URLSearchParams(location.hash.slice(1));
    $('q').value = p.get('q') || '';
    for (const k in F) F[k].value = p.get(k) || '';
  }
  function writeHash() {
    const p = new URLSearchParams();
    if ($('q').value.trim()) p.set('q', $('q').value.trim());
    for (const k in F) if (F[k].value) p.set(k, F[k].value);
    const h = p.toString();
    history.replaceState(null, '', h ? '#' + h : location.pathname);
  }

  function apply() {
    const terms = $('q').value.toLowerCase().split(/\s+/).filter(Boolean);
    shown = all.filter(r =>
      (!F.lv.value || r.lv === F.lv.value) &&
      (!F.pf.value || r.pf === F.pf.value) &&
      (!F.ta.value || r.ta.includes(F.ta.value)) &&
      (!F.tb.value || r.tb === F.tb.value) &&
      (!F.src.value || r.src === F.src.value) &&
      (!F.stg.value || r.stg === F.stg.value) &&
      terms.every(t => r._s.includes(t)));
    limit = PAGE;
    writeHash();
    render();
  }

  function card(r) {
    const fp = r.fp.length ? `<h4>False positives</h4><ul>${r.fp.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : '';
    return `<details class="rule"><summary>
        <span class="lv ${esc(r.lv)}">${esc(r.lv)}</span>
        <span class="title">${esc(r.t)}${r.stg === 'Pending' ? ' <span class="pv">Pending</span>' : ''}</span>
        <span class="meta"><span>${esc(r.tb)}</span><span>${esc(r.pf)}</span>${r.te.length ? `<span>${esc(r.te.join(', '))}</span>` : ''}${r.ta.length ? `<span>${esc(r.ta.join(', '))}</span>` : ''}</span>
      </summary><div class="body">
        ${r.stg === 'Pending' ? `<p class="pvnote">From an <strong>open SigmaHQ pull request</strong> (${esc(r.ch)}). Not reviewed or merged yet, so it may change or be rejected. <a href="${esc(r.pru)}">Pull request ${esc(r.pr.split(' ')[0])}</a></p>` : ''}
        ${r.de ? `<p>${esc(r.de)}</p>` : ''}
        ${fp}
        <div class="qhead"><h4 style="margin:0">KQL</h4><button class="copy" type="button">Copy query</button></div>
        <pre>${esc(r.q)}</pre>
        <div class="links">
          ${r.sg ? `<a href="${esc(r.sg)}">Sigma rule</a>` : ''}
          <a href="https://github.com/Tenbite/sigma2kql/blob/main/${esc(r.kp)}">KQL file</a>
          <span style="color:var(--muted)">by ${esc(r.au || 'unknown')}${r.dt ? ', ' + esc(r.dt) : ''}</span>
        </div>
      </div></details>`;
  }

  function render() {
    const slice = shown.slice(0, limit);
    $('list').innerHTML = slice.length ? slice.map(card).join('') : '<p class="empty">No rules match. Try fewer words or clear a filter.</p>';
    $('count').textContent = `${shown.length.toLocaleString()} of ${all.length.toLocaleString()} rules`;
    $('more').hidden = shown.length <= limit;
    $('more').textContent = `Show ${Math.min(PAGE, shown.length - limit)} more`;
    $('list').querySelectorAll('.copy').forEach((b, i) => b.addEventListener('click', async e => {
      e.preventDefault();
      try { await navigator.clipboard.writeText(slice[i].q); b.textContent = 'Copied'; }
      catch { b.textContent = 'Select and copy'; }
      setTimeout(() => (b.textContent = 'Copy query'), 1500);
    }));
  }

  let timer;
  $('q').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(apply, 150); });
  Object.values(F).forEach(s => s.addEventListener('change', apply));
  $('reset').addEventListener('click', () => { $('q').value = ''; Object.values(F).forEach(s => (s.value = '')); apply(); });
  $('more').addEventListener('click', () => { limit += PAGE; render(); });

  fetch('rules.json').then(r => r.json()).then(data => {
    all = data;
    all.forEach(r => { r._s = [r.t, r.de, r.id, r.tb, r.pf, r.au, r.te.join(' '), r.ta.join(' '), r.pr, r.stg, r.q].join(' ').toLowerCase(); });
    fill(F.lv, LV.filter(l => all.some(r => r.lv === l)));
    fill(F.pf, uniq(r => r.pf).sort());
    fill(F.ta, uniq(r => r.ta).sort());
    fill(F.tb, uniq(r => r.tb).sort());
    fill(F.src, uniq(r => r.src).sort());
    fill(F.stg, ['Published', 'Pending'].filter(v => all.some(r => r.stg === v)));
    readHash();
    apply();
  }).catch(() => { $('count').textContent = 'Could not load rules.json'; });
})();
</script>
</body>
</html>
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yml")
    args = ap.parse_args()
    cfg = yaml.safe_load((ROOT / args.config).read_text())
    n = build(cfg)
    print(f"Built docs/index.html with {n} rules.")


if __name__ == "__main__":
    main()
