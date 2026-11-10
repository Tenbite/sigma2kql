# sigma2kql run summary

- Target: `microsoft_xdr`
- SigmaHQ commit: `d7c9da10c170a6988d68ebdf2c9f7bd8782b7c55`
- Last run: 2026-11-10 14:57 UTC (incremental)
- Tools: pySigma 1.5.1, pySigma-backend-kusto 1.0.1, kusto-language 12.4.1
- Validation schema: downloaded from https://xdrinternals.com/FullSchema-latest.json (209 tables) (see schema_drift.md)

| Result | Rules |
|---|---|
| Converted and valid | 1910 |
| Failed validation | 14 |
| Failed conversion | 1171 |
| Skipped | 684 |

Converted rules with wildcard comparisons rewritten to regex: 100 (see wildcard_rewrites.md)

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
