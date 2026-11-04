# sigma2kql run summary

- Target: `microsoft_xdr`
- SigmaHQ commit: `c68bb91abb1146b8a6a65caf6819b1836d97f09d`
- Last run: 2026-11-04 14:38 UTC (incremental)
- Tools: pySigma 1.5.1, pySigma-backend-kusto 1.0.1, kusto-language 12.4.1
- Validation schema: downloaded from https://xdrinternals.com/FullSchema-latest.json (209 tables) (see schema_drift.md)

| Result | Rules |
|---|---|
| Converted and valid | 1910 |
| Failed validation | 14 |
| Failed conversion | 1171 |
| Skipped | 682 |

Converted rules with wildcard comparisons rewritten to regex: 100 (see wildcard_rewrites.md)

Skipped breakdown: filtered: 682

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
