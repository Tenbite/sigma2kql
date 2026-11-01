# sigma2kql

Converts the [SigmaHQ](https://github.com/SigmaHQ/sigma) rule repository into **one validated `.kql` file per rule**, and keeps it up to date automatically with GitHub Actions. Everything here is free.

- **Converter:** [pySigma](https://github.com/SigmaHQ/pySigma) + [pySigma-backend-kusto](https://github.com/AttackIQ/pySigma-backend-kusto). Deterministic, no LLM.
- **Validator:** Microsoft's own Kusto parser (`Kusto.Language`, from npm as `@kusto/language-service-next`), checked against the target's table schema. Queries that don't parse, or that use a column or type the table doesn't have, are kept out of `kql/` and listed in `reports/validation_failed.md`.
- **Incremental:** each run only converts rules changed in SigmaHQ since the last processed commit.

## Output

```
kql/
  INDEX.md                         table of every converted rule, with level, ATT&CK and table
  rules/windows/process_creation/
    proc_creation_win_....kql      mirrors the SigmaHQ folder layout
  rules-emerging-threats/...
  rules-threat-hunting/...
reports/
  summary.md                       counts, tool versions, top failure reasons
  failed.md                        rules that didn't convert, grouped by reason
  validation_failed.md             converted but rejected by the Kusto parser, with the query
  rules.json                       per-rule state used for incremental runs
state/state.json                   last SigmaHQ commit processed + config fingerprint
```

Each `.kql` file starts with a comment header: title, Sigma ID, status, level, author, dates, ATT&CK, description, false positives, references, a link to the exact Sigma rule version, the license, tool versions, and validation status. The query follows.

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
| `custom_pipelines` | Your own field mappings (see below) |
| `validate` | Turn Kusto validation on or off |

Changing `config.yml`, a custom pipeline, the script, or a tool version triggers a full rebuild automatically.

**More than one target:** copy `config.yml` to e.g. `config.azure_monitor.yml`, change `target`, `output_dir`, `reports_dir` and `state_file`, and run `python scripts/convert.py --config config.azure_monitor.yml` as an extra step in the workflow. `microsoft_xdr` has no `SecurityEvent` table, so many `windows/security` rules only convert with `azure_monitor`.

## Fixing failures

`reports/failed.md` lists why rules didn't convert, most common first. Two kinds:

- **No table for a log source** (e.g. `windows/ps_script`, `webserver`, `aws/cloudtrail`): the target has no table for that data. Try another target, or accept the gap.
- **Unmapped field**: the table exists but a Sigma field has no equivalent column. If there is a real equivalent, add a mapping to `pipelines/custom.yml` (it has a working example and a template). Some fields have no equivalent at all, e.g. MDE doesn't record a process's `CurrentDirectory`.

## Running locally

```bash
pip install -r requirements.txt
npm ci
git clone --filter=blob:none https://github.com/SigmaHQ/sigma.git sigma
python scripts/convert.py          # add --full to rebuild, --no-validate to skip validation
```

## What validation does and doesn't prove

It proves the query parses, references real tables and columns, and uses operators that are valid for the column types. It does **not** prove the KQL still detects what the Sigma rule describes. Backend mappings can change semantics (for example, Sigma's numeric `LogonType: 10` vs MDE's string `LogonType` values), so test the rules you deploy against real or simulated telemetry first.

A few very large queries exceed the parser's nesting limit; they're written with `Validation: syntax only` in the header.

## License

The generated `.kql` files are derived from SigmaHQ rules and are licensed under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License). Each file keeps the original author and Sigma ID; keep them if you redistribute or build on these queries.
