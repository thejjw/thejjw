---
name: kimi-usage-query
description: Check Kimi Code membership usage, weekly quota, rolling five-hour limits, concurrency, and Extra Usage balance. Use when asked about Kimi Code plan usage, remaining credits, resets, membership tier, or quota status.
---

# Query Kimi usage

Query Kimi Code membership usage from a private endpoint that corresponds to the quota information shown by the Kimi Code CLI `/usage` command. Treat the endpoint schema as observed behavior rather than a public API contract.

## Kimi Code membership

Read `KIMI_API_KEY` from the environment. On the personal Windows setup, `Load-AiApiKeysFromCS` normally loads it from Windows Credential Manager. Never print the key.

Send `GET https://api.kimi.com/coding/v1/usages` with:

- `Accept: application/json`
- `Authorization: Bearer <KIMI_API_KEY>`

### PowerShell

```powershell
if ([string]::IsNullOrWhiteSpace($env:KIMI_API_KEY)) {
    throw 'KIMI_API_KEY is not set.'
}

$headers = @{
    Accept        = 'application/json'
    Authorization = "Bearer $env:KIMI_API_KEY"
}

$request = @{
    Uri         = 'https://api.kimi.com/coding/v1/usages'
    Headers     = $headers
    Method      = 'Get'
    ErrorAction = 'Stop'
}
Invoke-RestMethod @request
```

### Bash, Git Bash, or WSL

```bash
: "${KIMI_API_KEY:?KIMI_API_KEY is not set}"

curl --fail-with-body --silent --show-error \
  'https://api.kimi.com/coding/v1/usages' \
  -H 'Accept: application/json' \
  -H "Authorization: Bearer $KIMI_API_KEY"
```

Pipe the response to `jq` when available. Report a concise summary rather than dumping identifying account data.

## Observed response schema

Numeric quota values are strings.

- `usage`: weekly `limit`, `used`, `remaining`, and `resetTime`. The quota refreshes every seven days from the subscription date.
- `limits`: rolling rate-window entries. A five-hour entry uses `window.duration: 300` and `window.timeUnit: TIME_UNIT_MINUTE`; its `detail` contains `limit`, `used`, `remaining`, and `resetTime`.
- `user.membership.level`: membership tier.
- `parallel.limit`: concurrent-session cap.
- `totalQuota`: aggregate `limit` and `remaining` when present.
- `boosterWallet`: optional Extra Usage balance. Observed fields include `amount`, `amountLeft`, `monthlyChargeLimit`, and `monthlyUsed`; monetary values may use 1e6 fixed-point representation.
- `authentication.method`: `METHOD_API_KEY` for API-key authentication.
- `subType`: subscription source/type when present.

Convert reset timestamps from UTC to the user's local timezone when presenting results. Do not assume optional fields are present.

## Errors

- `401`: missing, invalid, expired, or revoked API key.
- `402`: membership is unavailable or expired.
- `403` or `429`: quota, membership, concurrency, or service-capacity condition; preserve and summarize the response message.
- `404`: the private endpoint may be unavailable for the account or may have changed.

If the request fails, recommend the supported `/usage` command in Kimi Code CLI or the Kimi Code Console.
