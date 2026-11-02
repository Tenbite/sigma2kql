<div align="center">

# sigma2kql

**SigmaHQ detection rules, converted to Microsoft Defender XDR KQL. Validated and rebuilt every night.**

[![Nightly conversion](https://github.com/Tenbite/sigma2kql/actions/workflows/convert.yml/badge.svg)](https://github.com/Tenbite/sigma2kql/actions/workflows/convert.yml)
![Rules](https://img.shields.io/badge/rules-1%2C900%2B-1f6f8b)
![Target](https://img.shields.io/badge/target-Defender%20XDR%20Advanced%20Hunting-1f6f8b)
[![Rule license](https://img.shields.io/badge/rules-DRL%201.1-555)](https://github.com/SigmaHQ/Detection-Rule-License)
[![Code license](https://img.shields.io/badge/code-MIT-555)](LICENSE)

### [Search the rules](https://tenbite.github.io/sigma2kql/) · [Rule index](kql/INDEX.md) · [Pending rules](kql-pending/INDEX.md) · [Latest run report](reports/summary.md)

</div>

> [!WARNING]
> **Machine-generated. Not tested against real telemetry.** Every query passes Microsoft's KQL parser against the live Defender schema, which proves it is valid KQL. It does **not** prove the query detects what the Sigma rule describes, or that it is quiet in your environment. Provided as is, with no warranty. Run queries as hunts and tune them before using any as a detection. Not affiliated with SigmaHQ or Microsoft.

## What this is

1. **A ready-to-use KQL library.** About 1,900 SigmaHQ rules as Defender XDR Advanced Hunting queries, one `.kql` file per rule. [Search and filter them](https://tenbite.github.io/sigma2kql/) by level, platform, ATT&CK tactic, technique, or table, and copy any query in one click.
2. **Pending rules.** Rules from **open SigmaHQ pull requests**, converted before they're merged, in [`kql-pending/`](kql-pending/INDEX.md). Clearly labeled on the [search page](https://tenbite.github.io/sigma2kql/#stg=Pending) and filterable. See [Pending rules](#pending-rules).
3. **A reusable pipeline.** A free GitHub Actions workflow you can fork to keep your own copy current, or point at your own Sigma rules.

## How conversions are checked

Converting Sigma to KQL is the easy part. These checks run on every rule, every night, to keep broken queries out of the library:

| Check | What it catches |
|---|---|
| **Microsoft's KQL parser** ([Kusto.Language](https://github.com/microsoft/Kusto-Query-Language)) | Syntax errors, unknown columns, and type mismatches. Failing queries are kept out and listed in [`reports/validation_failed.md`](reports/validation_failed.md). |
| **Live Defender schema** ([XDRInternals](https://xdrinternals.com)) | Columns Microsoft has renamed or removed since the converter's built-in 2024 schema. Changes are tracked in [`reports/schema_drift.md`](reports/schema_drift.md). |
| **Wildcard fix** | The backend sometimes leaves a Sigma `*` inside a string (for example `endswith "...\Tree*"`), which KQL treats literally, so the query never matches. These are rewritten to `matches regex` and listed in [`reports/wildcard_rewrites.md`](reports/wildcard_rewrites.md). |
| **Event type fixes** | Adds the missing `ActionType` filter to file and registry delete rules, so they don't match every create and modify event. |
| **Unsupported rules removed** | File-read rules are dropped, because Defender doesn't log file reads and the queries would match writes instead. |
| **Nightly health check** | Fails the run and emails the maintainer if converted rules drop sharply, validation failures spike, or the schema download keeps failing. |

Rules that can't be converted, mostly because Defender has no table for that data (PowerShell script block logs, Windows Security events, web, proxy, and cloud logs), are listed with the reason in [`reports/failed.md`](reports/failed.md).

## Pending rules

New detections often sit in SigmaHQ pull requests for days or weeks before they're merged. Each night, the pipeline also converts rules from **open, non-draft pull requests** into [`kql-pending/`](kql-pending/INDEX.md), one folder per pull request.

> [!CAUTION]
> Pending rules have **not been reviewed or merged by SigmaHQ**. They may change, be rejected, or be wrong. Use them for early hunting only.

- **Labeled everywhere:** each file's header and the search page mark it as pending, with a link to its pull request and whether it's a new rule or an update to an existing one.
- **Same checks:** pending rules go through the same conversion fixes and KQL validation as published rules.
- **Cleans itself up:** the folder is rebuilt from scratch every night. When a pull request is merged, its pending rules disappear and the rule shows up in `kql/`. When one is closed, its pending rules simply disappear.

Results of each pending run are in [`reports/pending.md`](reports/pending.md). Turn pending rules off with `pending: enabled: false` in `config.yml`.

## Using a query

1. Find a rule on the [search page](https://tenbite.github.io/sigma2kql/) or in the [rule index](kql/INDEX.md).
2. Copy the query into **security.microsoft.com → Hunting → Advanced hunting**.
3. Run it as a hunt, review the results, and tune it before turning it into a detection.

Each `.kql` file starts with a header: title, Sigma ID, author, level, ATT&CK, description, false positives, references, a link to the exact Sigma rule version, and its validation status.

## Run your own copy

1. **Fork** this repo.
2. **Settings → Actions → General → Workflow permissions →** Read and write.
3. Open the **Actions** tab and enable workflows (forks start with them off), then run **Convert Sigma to KQL**.
4. Optional: **Settings → Pages →** deploy from `main` / `docs` for your own search page.

It then updates itself nightly. Public repos get unlimited free Actions minutes.

**Customize:** `config.yml` controls which rule folders, statuses, and levels are converted. `pipelines/custom.yml` holds field mappings and fixes. To use your own Sigma rules, change the clone URL in `.github/workflows/convert.yml` and `rule_dirs` in `config.yml`.

**Get notified:** turn on failure emails under your GitHub **Settings → Notifications → Actions**. For alerts if the workflow stops running entirely, add a free [healthchecks.io](https://healthchecks.io) ping URL as a repo secret named `HEALTHCHECK_URL`.

<details>
<summary><strong>How the pipeline works</strong></summary>

1. **Pull.** Clone SigmaHQ and diff against the last processed commit, so only new or changed rules are converted. Deleted rules are removed.
2. **Filter.** Keep `stable` and `test` rules rated medium and above from the core, emerging threats, and threat hunting folders.
3. **Convert.** [pySigma](https://github.com/SigmaHQ/pySigma) with AttackIQ's [Kusto backend](https://github.com/AttackIQ/pySigma-backend-kusto) and its Defender XDR pipeline, plus the fixes in `pipelines/custom.yml`. Deterministic; no AI writes any query.
4. **Fix and validate.** Apply the wildcard fix, then run every query through the KQL parser.
5. **Publish.** Write the `.kql` files, rebuild the index, reports, and search page, and commit back to the repo.

Any change to `config.yml`, a custom pipeline, the scripts, the tool versions, or the Defender schema triggers a full rebuild.

| Path | Contents |
|---|---|
| `kql/` | One `.kql` file per rule, mirroring SigmaHQ's folders, plus `INDEX.md` |
| `kql-pending/` | Rules from open SigmaHQ pull requests, one folder per pull request, plus `INDEX.md` |
| `docs/` | The search page (GitHub Pages) |
| `reports/` | Run summary, failures, validation rejections, wildcard rewrites, schema drift |
| `scripts/` | `convert.py` (pipeline), `pending.py` (pending rules from pull requests), and `build_site.py` (search page) |
| `validator/` | The KQL validator (Node, Kusto.Language) |
| `pipelines/custom.yml` | Extra field mappings and fixes |
| `state/` | Last processed commit and cached Defender schema |

</details>

## Found a bad rule?

[Open an issue](https://github.com/Tenbite/sigma2kql/issues/new?template=bad-rule.md) with the rule title and what's wrong. Problems with the detection logic itself belong upstream in [SigmaHQ](https://github.com/SigmaHQ/sigma/issues).

## Credits

| Project | Used for |
|---|---|
| [SigmaHQ](https://github.com/SigmaHQ/sigma) and contributors | The detection rules |
| [pySigma](https://github.com/SigmaHQ/pySigma) + [pySigma-backend-kusto](https://github.com/AttackIQ/pySigma-backend-kusto) (AttackIQ) | Conversion |
| [Kusto.Language](https://github.com/microsoft/Kusto-Query-Language) (Microsoft) | Query validation |
| [XDRInternals](https://xdrinternals.com) | Live Defender schema |
| [Claude](https://claude.ai) | Helped build and debug the pipeline |

## License

- **Rules** (`kql/`, `kql-pending/`, `docs/rules.json`) are derived from SigmaHQ and remain under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License). Each file keeps the original author and Sigma ID; keep them if you redistribute.
- **Code** (scripts, workflow, validator, search page) is under the [MIT License](LICENSE).

Not affiliated with SigmaHQ, Microsoft, AttackIQ, XDRInternals, or Anthropic.
