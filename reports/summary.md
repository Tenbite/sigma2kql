# sigma2kql run summary

- Target: `microsoft_xdr`
- SigmaHQ commit: `54967d64e6dda2b4daa81f47f7a8bf1f591b68a0`
- Last run: 2026-11-13 14:39 UTC (incremental)
- Tools: pySigma 1.5.1, pySigma-backend-kusto 1.0.1, kusto-language 12.4.1
- Validation schema: downloaded from https://xdrinternals.com/FullSchema-latest.json (209 tables) (see schema_drift.md)

| Result | Rules |
|---|---|
| Converted and valid | 1910 |
| Failed validation | 14 |
| Failed conversion | 1171 |
| Skipped | 684 |

Converted rules with wildcard comparisons rewritten to regex: 102 (see wildcard_rewrites.md)

Skipped breakdown: filtered: 684

Top conversion failures:

- No table for log source `windows/ps_script`: 150
- No table for log source `webserver`: 78
- No table for log source `windows/security`: 68
- No table for log source `windows/system`: 66
- No table for log source `proxy`: 50
- No table for log source `azure/auditlogs`: 43
- No table for log source `azure/activitylogs`: 33
- No table for log source `aws/cloudtrail`: 29
- No table for log source `windows/ps_module`: 28
- No table for log source `windows/process_access`: 25
