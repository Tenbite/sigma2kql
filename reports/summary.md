# sigma2kql run summary

- Target: `microsoft_xdr`
- SigmaHQ commit: `05d1031f537e830b76da53bae2400c5814c89165`
- Last run: 2026-11-01 23:27 UTC (full)
- Tools: pySigma 1.5.1, pySigma-backend-kusto 1.0.1, kusto-language 12.4.1

| Result | Rules |
|---|---|
| Converted and valid | 1916 |
| Failed validation | 15 |
| Failed conversion | 1164 |
| Skipped | 681 |

Skipped breakdown: filtered: 681

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
