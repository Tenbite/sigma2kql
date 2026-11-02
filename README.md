# sigma2kql

Converts the [SigmaHQ](https://github.com/SigmaHQ/sigma) rule repository into **one `.kql` file per rule** for Microsoft Defender XDR and Microsoft Sentinel, and keeps it up to date automatically with GitHub Actions. Everything here is free.

> [!WARNING]
> **These queries are machine-generated and have not been tested against real telemetry.** Every query was checked by Microsoft's Kusto parser, which confirms it is valid KQL that uses real tables and columns. It does **not** confirm the query detects the behavior the original Sigma rule describes, or that it is free of false positives. Some queries may never match, and some may be noisy. Treat them as a starting point for hunting: run them, check the results, and tune them before using any of them as a detection or alert.

## How it works

Each run does the following, in order:

1. **Fetch the rules.** Clones [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and works out which rules changed since the last processed commit. The first run, or any change to the config or tooling, rebuilds everything.
2. **Filter.** Keeps rules from the configured folders with the configured statuses and levels (by default `stable`/`test`, `medium` and above).
3. **Convert.** Translates each rule to KQL with [pySigma](https://github.com/SigmaHQ/pySigma) and [pySigma-backend-kusto](https://github.com/AttackIQ/pySigma-backend-kusto), using the backend's Defender XDR pipeline plus the extra mappings and fixes in `pipelines/custom.yml`. The conversion is deterministic; no AI or LLM writes any query.
4. **Fix known backend issues.** Rewrites comparisons where the backend left a Sigma `*` wildcard inside a string, which KQL would treat as a literal asterisk (see [Known issues corrected](#known-issues-corrected)).
5. **Validate.** Parses every query with Microsoft's own Kusto language parser ([Kusto.Language](https://github.com/microsoft/Kusto-Query-Language), from npm as `@kusto/language-service-next`) against the table schema, using the live Defender schema from [XDRInternals](https://xdrinternals.com) where available. Queries that fail are kept out of `kql/` and listed in `reports/validation_failed.md`.
6. **Write and commit.** Writes one `.kql` file per rule with a comment header, regenerates the index and reports, and commits the changes back to this repo.

## Output

```
kql/
  INDEX.md                         table of every converted rule, with level, ATT&CK and table
  rules/windows/process_creation/
    proc_creation_win_....kql      mirrors the SigmaHQ folder layout
  rules-emerging-threats/...
  rules-threat-hunting/...
reports/
  summary.md                       counts, tool versions, schema used, top failure reasons
  failed.md                        rules that didn't convert, grouped by reason
  validation_failed.md             converted but rejected by the Kusto parser, with the query
  wildcard_rewrites.md             rules where wildcard comparisons were rewritten to regex
  schema_drift.md                  differences between the bundled and live Defender schemas
  rules.json                       per-rule state used for incremental runs
state/
  state.json                       last SigmaHQ commit processed + config fingerprint
  xdr_schema.json                  cached copy of the last live schema download
```

Each `.kql` file starts with a comment header: title, Sigma ID, status, level, author, dates, ATT&CK, description, false positives, references, a link to the exact Sigma rule version it came from, the license, the tool versions used, and which schema it was validated against. The query follows.

## Using a query

Copy everything from the table name down (comment lines are fine to include; KQL ignores them).

- **Defender XDR:** security.microsoft.com → Hunting → Advanced hunting.
- **Microsoft Sentinel:** Logs. The Defender tables are available when the Defender XDR connector streams them.

Run it as a hunt first and check the results before turning it into a detection.

## Setup

1. Create a new GitHub repository and push this folder to it.
2. In the repo: **Settings → Actions → General → Workflow permissions → Read and write permissions**.
3. **Actions → Convert Sigma to KQL → Run workflow.** The first run is a full build (about a minute).

After that it runs daily at 06:17 UTC and commits only what changed. A public repo gets unlimited Actions minutes; a private repo uses a few minutes a day from the free 2,000/month.

## Configuration (`config.yml`)

| Key | What it does |
|---|---|
| `target` | `microsoft_xdr` (Defender XDR / MDE tables, also in Sentinel via the XDR connector), `sentinel_asim`, or `azure_monitor` |
| `rule_dirs` | SigmaHQ folders to convert |
| `statuses`, `levels` | Filters. Remove a key to accept everything. |
| `custom_pipelines` | Your own field mappings and fixes (see below) |
| `validate` | Turn Kusto validation on or off |
| `rewrite_wildcards` | Rewrite literal-`*` comparisons to `matches regex` |
| `live_schema` | Where to download the current Defender schema from |

Changing `config.yml`, a custom pipeline, the script, a tool version, or the live schema triggers a full rebuild automatically.

**More than one target:** copy `config.yml` to e.g. `config.azure_monitor.yml`, change `target`, `output_dir`, `reports_dir` and `state_file`, and run `python scripts/convert.py --config config.azure_monitor.yml` as an extra step in the workflow. `microsoft_xdr` has no `SecurityEvent` table, so many `windows/security` rules only convert with `azure_monitor`.

## Live schema

With `target: microsoft_xdr`, validation uses the current Defender XDR schema published by [XDRInternals](https://xdrinternals.com) (`FullSchema-latest.json`), instead of the schema bundled with pySigma-backend-kusto, which was last updated in September 2024.

- Each successful download is saved to `state/xdr_schema.json` and committed, so schema changes show up in git history and trigger a full rebuild.
- If the download fails or is missing core tables, the last cached copy is used; with no cache, the bundled schema is used. `reports/summary.md` says which one a run used.
- `reports/schema_drift.md` lists columns the backend still maps to that Microsoft no longer has (queries using them fail validation), type changes, and new columns.

The XDRInternals file is a community-maintained export, not an official Microsoft API. Remove the `live_schema` block to validate with the bundled schema only.

## Fixing failures

`reports/failed.md` lists why rules didn't convert, most common first. Two kinds:

- **No table for a log source** (e.g. `windows/ps_script`, `webserver`, `aws/cloudtrail`): the target has no table for that data. Try another target, or accept the gap.
- **Unmapped field**: the table exists but a Sigma field has no equivalent column. If there is a real equivalent, add a mapping to `pipelines/custom.yml` (it has working examples and a template). Some fields have no equivalent at all, e.g. MDE doesn't record a process's `CurrentDirectory`.

## Known issues corrected

These are problems in the backend's output that would produce queries that look valid but never match, or match far too much:

- **Wildcards left inside strings.** The backend sometimes outputs comparisons like `endswith "...\Tree*"`, where KQL treats `*` as a literal character. These are rewritten to `matches regex`. Affected rules are listed in `reports/wildcard_rewrites.md` and marked with a `// Note:` line in their header.
- **Missing `ActionType` filters** on `file_delete` and `registry_delete` rules, which otherwise match creates and modifications too.
- **`file_access` rules**, which are failed on purpose: MDE doesn't record file reads, so they would match writes instead.
- **`GrandParentImage`**, which maps to a column holding only a file name, so `endswith "\rundll32.exe"` never matched.

The last three are fixed in `pipelines/custom.yml`, with a comment on each.

## Limits of validation

Validation proves a query parses, references real tables and columns, and uses operators valid for the column types. It does **not** prove the KQL still detects what the Sigma rule describes. Backend mappings can change meaning (for example, Sigma's numeric `LogonType: 10` vs MDE's text `LogonType` values), and some Sigma log sources have no exact equivalent in Defender. Test any rule you deploy against real or simulated telemetry first.

A few very large queries exceed the parser's nesting limit; they're written with `Validation: syntax only` in the header.

## Running locally

```bash
pip install -r requirements.txt
npm ci
git clone --filter=blob:none https://github.com/SigmaHQ/sigma.git sigma
python scripts/convert.py          # add --full to rebuild, --no-validate to skip validation
```

## Credits and sources

| What | Used for |
|---|---|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | The detection rules, by the SigmaHQ community |
| [pySigma](https://github.com/SigmaHQ/pySigma) | Parsing Sigma rules and running processing pipelines |
| [pySigma-backend-kusto](https://github.com/AttackIQ/pySigma-backend-kusto) (AttackIQ) | Converting rules to KQL, and the bundled table schemas |
| [Kusto.Language](https://github.com/microsoft/Kusto-Query-Language) (Microsoft) | Parsing and validating every query |
| [XDRInternals](https://xdrinternals.com) | The live Defender XDR table schema used for validation |
| [GitHub Actions](https://docs.github.com/actions) | Running the conversion on a schedule |

## License

The generated `.kql` files are derived from SigmaHQ rules and are licensed under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License). Each file keeps the original author and Sigma ID; keep them if you redistribute or build on these queries.

This repository is not affiliated with SigmaHQ, Microsoft, AttackIQ, or XDRInternals.
