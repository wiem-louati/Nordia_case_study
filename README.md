# Nordia incident, 10–12 March 2026: README of evidence

This README lists, for each key finding, the PowerShell command I ran, the line numbers it returns and what those lines show, so that anyone can redo it.

- **Environment:** Windows PowerShell, run in the `cyber\` folder, on copies of the provided files. Nothing is installed; no address or domain from the logs is contacted or resolved.
- **Line numbers:** `file:N` is the line number printed by `Select-String`. Line 1 of `auth.csv` and `accounts.csv` is the header row.
- **Personal data:** customers are called C1 and C2. In the commands, set the variable from `environment.md` (C1) or from step 15's output (C2). Customer e-mails are not reproduced in this file.
- **Labels:** E = established (a line proves it) · P = probable · H = possible.

Contents: `Incident_Report_Nordia_Wiem_Louati.pdf` (incident report) · `README.md` (this file) · `scripts/detect.py` (optional: two detection rules).

## Clarifications received from Hydatis (shared with all finalists)

- **Clocks:** the three systems use one internal time source, with no known clock problem. So the 1–3 s correlations between `access.log` and `dns.log` (steps A12, A13, B5) are reliable.
- **Log shipping:** it may have been interrupted on 11 March, with no further detail. The 12:56–13:29 gap (B4) is consistent with this; its exact cause is not confirmed. The absence of an event is therefore not evidence that it did not happen.
- **Export columns:** they cannot be confirmed. My assumption is that a customer export holds identity and contact details, and an invoice export holds invoice data. The report says how the impact changes if this is wrong.
- **New-address e-mail:** it is sent on any IP never used before by the account. `203.0.113.142` was not seen for C1 elsewhere in the supplied logs (C1's other logins, `auth.csv:66`, `132`, `2049`, all come from 198.51.100.212), and `198.51.100.77` was not seen for C2 elsewhere in them. Three days of logs cannot establish the accounts' full IP history.

## How I narrowed it down

I did not read every line. I started from the only fact given, the complaint, and followed it:

1. C1's sign-in, which gave me the first source IP.
2. Everything that IP did in `auth.csv`, which led to the staff account and the new admin.
3. The web activity of each account in `access.log`, which showed the exports and the webhook.
4. The DNS lookups of `web-01` around the webhook test.

I then ranked login failures by IP to find the second address, and checked the expected activity (scanner, Aegis) against the change calendar.

---

## Part A: the investigation (steps 01–19)

### A01. Working folder
```powershell
Get-ChildItem -Name
```
The folder contains `access.log`, `accounts.csv`, `auth.csv`, `dns.log`, `environment.md`, `README.md`. I read `environment.md` first.

### A02. The sign-in that matches the complaint (E)
```powershell
$customer = '<C1 e-mail from environment.md>'
Select-String -Path .\auth.csv -SimpleMatch $customer
```
- `auth.csv:1029`: `2026-03-11T03:27:23Z, customer, login_success, C1, 203.0.113.142`, Linux Chrome 122.
- The complaint says "around 04:30 Paris time", which is about 03:30 UTC (UTC+1 in March).
- C1's 3 other logins (`auth.csv:66`, `132`, `2049`) use iPhone Safari from 198.51.100.212.

### A03. C1's web activity from that IP (E)
```powershell
$sourceIp = '203.0.113.142'
Select-String -Path .\access.log -SimpleMatch "$sourceIp - $customer ["
```
- `access.log:3530`: `/account` returned 200 at 03:27:25, 2 s after the login.
- `access.log:3538`, `3541`: 2 invoice downloads, HTTP 200.
- `access.log:3545`, `3547`, `3549`: 3 invoice downloads refused with **403**.

The same account, IP, browser and timestamps tie the web session to the login.

### A04. Everything the first IP did in auth.csv (E)
```powershell
$fromIp = Import-Csv .\auth.csv | Where-Object { $_.src_ip -eq $sourceIp }
$fromIp | Group-Object portal,event | Select-Object Count,Name
```
```
729 customer, login_failure
  1 customer, login_success
 11 admin, login_failure
  3 admin, login_success
  1 admin, account_created
```
These are event counts. The `admin` portal is the staff back-office.

### A05. The staff account used (E)
```powershell
$fromIp | Where-Object { $_.portal -eq 'admin' -and $_.event -eq 'login_success' } |
    Format-Table timestamp,username,detail -AutoSize
```
`l.fontaine` at 04:38:21Z, 12:16:56Z and 20:11:28Z on 11 March, each with `mfa=none`.

### A06. Who created the new account (E)
```powershell
$fromIp | Where-Object { $_.event -eq 'account_created' } |
    Format-List timestamp,username,actor,detail
```
At `2026-03-11T05:12:52Z`, actor `l.fontaine` created `svc-backup01` with `role=admin;created_via=admin_ui`. `actor` is who acted; `username` is the new account.

### A07. Role check and evidence lines (E; why it was allowed: open)
```powershell
Select-String -Path .\auth.csv -SimpleMatch '2026-03-11T05:12:52Z'
Select-String -Path .\accounts.csv -SimpleMatch 'l.fontaine,'
```
- `auth.csv:1443`: the account creation.
- `accounts.csv:4`: `l.fontaine, support, no (MFA), 2023-09-14 (last password change), office network`.

`environment.md` says only *admin* can create accounts. `accounts.csv` is a snapshot from 10 March 00:00, so role history and authorisation records are needed to explain why the application allowed this.

### A08. The new admin signs in (E)
```powershell
Select-String -Path .\auth.csv -SimpleMatch ',svc-backup01,'
```
- `auth.csv:1443`: the creation.
- `auth.csv:1995`: `login_success` at 12 March 14:07:33Z from **192.0.2.213**, Windows Firefox 123, `mfa=none`.

### A09. The new admin's web activity (E)
```powershell
Select-String -Path .\access.log -SimpleMatch '192.0.2.213 - svc-backup01 ['
```
- `access.log:7654` (`/admin/`), `7655` (`/admin/settings/webhooks`), `7660` (`/admin/users`).
- `access.log:7668`, `7672`, `7688`: invoice exports for `2026-02`, `2026-01` and `2025-12`, all HTTP 200, 1.19–1.30 MB each.

Row counts and contents are unknown.

### A10. Customer exports by `l.fontaine` from the first IP (E: responses; rows unknown)
```powershell
$exports = Select-String -Path .\access.log -SimpleMatch '203.0.113.142 - l.fontaine [' |
    Where-Object { $_.Line -match '"GET /admin/customers/export\?\S+ HTTP/1\.1" 200 ' }
$exports.Count                                   
$exports | Select-Object -ExpandProperty LineNumber
```
38 HTTP 200 responses, from `access.log:3992` (11 Mar 05:14) to `access.log:6287` (12 Mar 03:10). The count measures responses, not customer rows (see A3 for the page sizes).

### A11. Webhook settings submitted and test requested (E; saved configuration and delivery: unverified)
```powershell
Select-String -Path .\access.log -SimpleMatch '203.0.113.142 - l.fontaine [' |
    Where-Object { $_.Line -match '/admin/settings/webhooks' }
```
- `access.log:3983`: `GET /admin/settings/webhooks` 200, at 05:06:44.
- `access.log:3986`: `POST /admin/settings/webhooks` **302**, at 05:07:21.
- `access.log:3987`: `POST /admin/settings/webhooks/test` 200, at 05:08:03.

### A12. DNS lookup right after the test (E)
```powershell
Select-String -Path .\dns.log -Pattern '^2026-03-11T05:08:\d{2}Z 10\.20\.1\.10 '
```
`dns.log:3542`: at `05:08:06Z`, `web-01` (10.20.1.10) resolves `hooks.nordia-notify.example` to **203.0.113.250**, 3 s after the test. Nordia owns only `nordia.example` and `nordia-static.example`.

### A13. The lookup recurs (E: lookups; H: delivery)
```powershell
$hookDns = Select-String -Path .\dns.log -Pattern '^\S+ 10\.20\.1\.10 hooks\.nordia-notify\.example '
$hookDns.Count                                   # 53
$hookDns | Select-Object -Last 3
```
`dns.log:8923`, `8941`, `8954` follow the 3 invoice exports of step 09 by 2, 1 and 3 seconds. The timing supports an association. Delivery logs or outbound traffic records would be needed to prove that anything was transmitted.

### A14. Rank customer login failures by IP (E)
```powershell
Import-Csv .\auth.csv |
    Where-Object { $_.portal -eq 'customer' -and $_.event -eq 'login_failure' } |
    Group-Object src_ip | Sort-Object Count -Descending | Select-Object -First 5 Count,Name
```
```
729 203.0.113.142
309 198.51.100.77
  6 10.20.9.50
  3 192.0.2.149
  3 203.0.113.199
```

### A15. The accepted login from the second IP: C2 (E)
```powershell
Import-Csv .\auth.csv | Where-Object {
    $_.src_ip -eq '198.51.100.77' -and $_.portal -eq 'customer' -and $_.event -eq 'login_success'
} | Format-Table timestamp,username,src_ip -AutoSize
```
`auth.csv:579`: C2, `2026-03-11T02:24:48Z`, 198.51.100.77. Who controls this IP, and how it relates to the first IP, is unknown. Both use the same Linux Chrome 122 user agent.

### A16. C2's web activity (E)
```powershell
$c2 = '<C2 e-mail from step 15>'
Select-String -Path .\access.log -SimpleMatch "198.51.100.77 - $c2 ["
```
5 HTTP 200 responses from 02:24:50. `access.log:3066` and `3070` are 2 invoice downloads.

### A17. Ruled out: internal scanner
```powershell
Select-String -Path .\auth.csv -Pattern ',10\.20\.9\.50,'
```
`auth.csv:179`–`190`: 6 customer and 6 back-office failures (`admin`, `root`, `test`, `demo`…), at 14:10 on 10 March, with user agent `NordiaVulnScan/3.2`. This matches the planned scan (14:00–14:30) in the change calendar.

### A18–19. Ruled out: Aegis telemetry
```powershell
Select-String -Path .\dns.log -SimpleMatch 'aegis-telemetry.example' |
    ForEach-Object { ($_.Line -split '\s+')[1] } | Group-Object | Select-Object Count,Name
Select-String -Path .\dns.log -SimpleMatch 'aegis-telemetry.example' |
    Group-Object { ($_.Line -split '\s+')[1] } |
    ForEach-Object { $_.Group | Select-Object -First 1 LineNumber,Line }
```
575 queries: 288 from 10.20.5.18 and 287 from 10.20.5.17, the two documented finance pilot PCs. `dns.log:9` and `10` are one sample per PC: random subdomain, TXT, answer `ok`. They look like DNS tunnelling, but they match the documented product.

---

## Part B: additional checks (support for report items not covered above)


### B1. One recorded failure per staff username (E)
```powershell
$fromIp | Where-Object { $_.portal -eq 'admin' -and $_.event -eq 'login_failure' } |
    Format-Table timestamp,username -AutoSize
```
11 different staff accounts, one failure each, from 04:31:31 (`auth.csv:1429`, `r.bouvier`) to 04:37:37 (`auth.csv:1439`, `a.rousseau`). The first recorded successful login for `l.fontaine` from this IP follows at 04:38:21.

### B2. Distinct customer e-mails tried by the two IPs (E)
```powershell
Import-Csv .\auth.csv |
    Where-Object { $_.portal -eq 'customer' -and $_.src_ip -in '203.0.113.142','198.51.100.77' } |
    Select-Object -ExpandProperty username | Sort-Object -Unique | Measure-Object
```
Count = **1,040**. Each e-mail is tried about once, which is consistent with automated login attempts.

### B3. Export page sizes and missing pages (E: sizes and missing numbers; H: pages 14–15 taken, unverified)
```powershell
$pages = $exports | ForEach-Object {
    if ($_.Line -match 'page=(\d+)&size=(\d+)') { [pscustomobject]@{ Line=$_.LineNumber; Page=[int]$Matches[1]; Size=[int]$Matches[2] } } }
$pages | Group-Object Size | Select-Object Count,Name          # 37 x 500, 1 x 50
1..39 | Where-Object { $_ -notin ($pages | Where-Object Size -eq 500).Page }   # 14, 15
```
- The first response is `page=1&size=50` (`access.log:3992`). Then come pages 1–13 (to `access.log:5082`) and 16–39 (from `access.log:5240` to `6287`) of size 500.
- Requested rows: 50 + 37 × 500 = 18,550.

### B4. Gap in access.log (E)
```powershell
Select-String -Path .\access.log -SimpleMatch '/api/v1/health' |
    Where-Object { $_.Line -match '11/Mar/2026:1[23]:' } | ForEach-Object { $_.LineNumber, ($_.Line -split ' ')[3] -join ' ' }
```
- The uptime probe logs every 5 min until `access.log:5170` (12:55:03), then resumes at `access.log:5180` (13:30:01).
- `access.log:5178` (12:56:48) and `5179` (13:29:08) are consecutive lines: nothing was logged for 32 minutes.
- During that gap, the webhook domain is still looked up at `dns.log:5299` (13:00:56) and `5408` (13:25:22). These fall between page 13 (12:17) and page 16 (13:57). Exports of pages 14–15 are therefore possible but unverified.

### B5. Webhook lookups after normal staff exports (E: lookups; H: delivery)
```powershell
Select-String -Path .\access.log -Pattern '^192\.0\.2\.50 - (c\.vidal|o\.lambert) \[12/Mar.*export'
$hookDns | Where-Object { $_.Line -match '^2026-03-12T(08|10):' }
```
| Staff export | DNS lookup |
|---|---|
| `access.log:6555` o.lambert 08:30:49 | `dns.log:7448` 08:30:50 |
| `access.log:6861` c.vidal 10:05:58 | `dns.log:7842` 10:06:00 |
| `access.log:6963` c.vidal 10:31:21 | `dns.log:7959` 10:31:24 |
| `access.log:6964` c.vidal 10:34:22 | `dns.log:7971` 10:34:24 |

### B6. Probing on 10 March (ruled out as a data leak)
```powershell
$probing = Select-String -Path .\access.log -SimpleMatch 'python-requests' |
    Where-Object {
        $_.Line -match '^198\.51\.100\.77 ' -and
        $_.Line -match '\[10/Mar/2026:22:(4[1-9]|5[0-2]):'
    }
$probing | Group-Object { ($_.Line -split '\s+')[8] } | Select-Object Count,Name
$probing | Where-Object { $_.Line -match '"[^"]+" 200 ' } | ForEach-Object { ($_.Line -split '\s+')[6] }
```
136 requests from 198.51.100.77, 10 March 22:41–22:52:
- 116 returned 404, 7 returned 302 (redirect to login), 3 returned 401, 1 returned 403.
- The 9 that returned 200 are `/robots.txt`, `/sitemap.xml`, `/`, `/login`, `/about`, `/about/team`, `/admin/login`, `/api/v1/health`, `/password/forgot`: all public pages.

Note: an unfiltered search for `python-requests` returns 138 lines, with 118 × 404. The 2 extra lines come from a different address, 192.0.2.198 (`access.log:6300`, `6301`, 12 March 04:08): `/actuator/health` and `/actuator/env`, both 404. They are background probing with no successful response, separate from this incident.

### B7. Staff accounts without MFA (E)
```powershell
Import-Csv .\accounts.csv | Where-Object mfa_enabled -eq 'no' | Format-Table username,role,last_password_change
```
`l.fontaine` (support, 2023-09-14), `y.benamar` (support, 2024-02-05), `t.nguyen` (finance, 2024-06-17).
- **Configuration:** `accounts.csv:4`, `7`, `10` (`mfa_enabled = no`).
- **What was used:** every successful back-office login of these accounts records `mfa=none`.

```powershell
Select-String -Path .\auth.csv -Pattern ',admin,login_success,(l\.fontaine|y\.benamar|t\.nguyen),.*mfa=none' |
    ForEach-Object { $_.LineNumber, ($_.Line -split ',')[0,3,5] -join ' ' }
```
| Account | `auth.csv` lines | Note |
|---|---|---|
| `l.fontaine` | 1440, 1618, 1773 | from 203.0.113.142 (attacker activity) |
| `l.fontaine` | 34, 1477, 1828 | from the office (192.0.2.50) |
| `y.benamar` | 31, 1482, 1844 | from the office |
| `t.nguyen` | 45, 1483, 1817 | from the office |

---

---

## Part C: reproducibility checks for figures in the report

### C1. Volume of the customer-export responses (12.1 MB)
```powershell
$bytes = $exports | ForEach-Object {
    if ($_.Line -match '"GET [^"]+" 200 (\d+) ') { [long]$Matches[1] }
}
$totalBytes = ($bytes | Measure-Object -Sum).Sum
[pscustomobject]@{ Responses = $bytes.Count; Bytes = $totalBytes; MB = [math]::Round($totalBytes / 1000000, 2) }
```
Expected: `Responses 38`, `Bytes 12100227`, `MB 12.1`.

This sums the response bytes logged by the web server. It does not establish the number of customer rows returned or of unique customers.

### C2. Successful staff logins without MFA (y.benamar, t.nguyen)
```powershell
Import-Csv .\auth.csv |
    Where-Object {
        $_.portal -eq 'admin' -and
        $_.event -eq 'login_success' -and
        $_.username -in 'y.benamar','t.nguyen'
    } |
    Format-Table timestamp,username,src_ip,detail -AutoSize
Select-String -Path .\auth.csv -Pattern ',admin,login_success,(y\.benamar|t\.nguyen),'
```
Expected: 6 rows, all from 192.0.2.50 with `mfa=none`.
- `y.benamar`: `auth.csv:31` (10 Mar 07:34:01), `1482` (11 Mar 07:45:57), `1844` (12 Mar 08:05:53).
- `t.nguyen`: `auth.csv:45` (10 Mar 08:05:33), `1483` (11 Mar 07:46:19), `1817` (12 Mar 07:27:45).

The pattern without `,admin,login_success,` also returns failures and logouts (15 lines in total).

### C3. Time windows of the automated login attempts
```powershell
$failures = Import-Csv .\auth.csv | Where-Object {
    $_.portal -eq 'customer' -and
    $_.event -eq 'login_failure' -and
    $_.timestamp -like '2026-03-11*' -and
    $_.src_ip -in '198.51.100.77','203.0.113.142'
}
$failures | Group-Object src_ip | ForEach-Object {
    $ordered = $_.Group | Sort-Object timestamp
    [pscustomobject]@{ IP = $_.Name; Failures = $_.Count; FirstUTC = $ordered[0].timestamp; LastUTC = $ordered[-1].timestamp }
}
```
Expected:

| IP | Failures | First (UTC) | Last (UTC) |
|---|---|---|---|
| 198.51.100.77 | 309 | 2026-03-11T01:58:03Z | 2026-03-11T02:40:59Z |
| 203.0.113.142 | 729 | 2026-03-11T02:41:07Z | 2026-03-11T04:22:58Z |

### C4. The log gap and the DNS lookups inside it
```powershell
Get-Content .\access.log | Select-Object -Skip 5177 -First 2
Select-String -Path .\dns.log -Pattern '^2026-03-11T13:(00:56|25:22)Z 10\.20\.1\.10 hooks'
```
Expected:
- `access.log` lines 5178 (12:56:48) and 5179 (13:29:08) are consecutive, with nothing logged between them for 32 minutes.
- `dns.log:5299` (13:00:56) and `dns.log:5408` (13:25:22) show web-01 looking up `hooks.nordia-notify.example`.

The pattern is restricted to `10.20.1.10` because line 5298, at the same second, is an unrelated mail lookup by a workstation.

### C5. Statements based on documentation or Hydatis' clarifications

| Report statement | Source |
|---|---|
| Customer complaint on 12 March at 16:40 UTC, about a sign-in around 04:30 Paris time | `environment.md`, "Why you are called in" |
| About 37 hours between C1's login and the complaint | Calculation: 11 March 03:27:23 to 12 March 16:40 = 37 h 12 min 37 s |
| Shared time source; log shipping possibly interrupted on 11 March | Hydatis' clarification to all finalists |
| Export columns cannot be confirmed | Hydatis' clarification to all finalists |
| The security e-mail is sent on any IP never used before by the account | Hydatis' clarification to all finalists |
| Only the admin role can create accounts; webhooks not believed configured | `environment.md`, "What the application team told us" |
| Scanner window 10 March 14:00–14:30; Aegis pilot on ws-fin-07/08 | `environment.md`, "Change calendar" |

---

## Detection rules (optional extra, `scripts/detect.py`, Python 3 standard library)

```powershell
python .\scripts\detect.py <path to the cyber folder>   
```
| Rule | Threshold | Result on these logs |
|---|---|---|
| R1. Failed logins per source IP | ≥ 20 in 10 minutes | Fires on 198.51.100.77 (01:58) and 203.0.113.142 (02:41); no other IP |
| R2. Customer rows exported per back-office user | > 1,000 in 24 hours | Fires on `l.fontaine` at 05:54:17 on 11 March; `c.vidal` (450 rows over 3 days) does not |

R2 was first tested at 200 rows. That fired on normal support exports, so the threshold was raised.
