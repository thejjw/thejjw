---
name: kimi-usage-query
description: Check Kimi Code membership usage, weekly quota, rolling five-hour limits, concurrency, and Extra Usage balance. Use when asked about Kimi Code plan usage, remaining credits, resets, membership tier, or quota status.
---

# Query Kimi usage

Query Kimi Code membership usage from the managed-usage endpoint used by the open-source Kimi Code CLI. Treat it as an implementation contract that may drift rather than a versioned public API.

## Kimi Code membership

Read `KIMI_API_KEY` from the environment. On the personal Windows setup, `Load-AiApiKeysFromCS` normally loads it from Windows Credential Manager. Never print the key.

Send `GET https://api.kimi.com/coding/v1/usages` with the default base URL. Honor `KIMI_CODE_BASE_URL` when set, trim trailing slashes, and append `/usages`.

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

## Response handling

Numeric quota values may be strings or numbers. Follow the tolerant parser in Kimi Code's `packages/oauth/src/managed-usage.ts`:

- `usage`: weekly summary. Read `limit`; read `used`, or derive it as `limit - remaining`. Prefer `name`, then `title`, then `Weekly limit`.
- `limits`: rolling entries. Read quota fields from `detail` when present, otherwise from the item. Prefer labels from `name`, `title`, or `scope`; otherwise derive a label from `duration` and `timeUnit`. A five-hour window is commonly `duration: 300` with `TIME_UNIT_MINUTE`.
- Reset fields may be `reset_at`, `resetAt`, `reset_time`, or `resetTime`. Relative seconds may be `reset_in`, `resetIn`, `ttl`, or `window`.
- `user.membership.level`: membership tier.
- `parallel.limit`: concurrent-session cap.
- `totalQuota`: aggregate `limit` and `remaining` when present.
- `boosterWallet`: optional Extra Usage object. Require `balance.type: BOOSTER` and a positive `balance.amount`. Convert `balance.amount` and `balance.amountLeft` from fixed-point cents by dividing by 1,000,000 and rounding to whole cents; preserve a positive sub-cent value as one cent. Read `monthlyChargeLimit.priceInCents`, `monthlyUsed.priceInCents`, `monthlyChargeLimitEnabled`, and their currency fields. Prefer the monthly-limit currency, then monthly-used currency, otherwise `USD`.
- `authentication.method`: `METHOD_API_KEY` for API-key authentication.
- `subType`: subscription source/type when present.

Convert reset timestamps from UTC to the user's local timezone when presenting results. Do not assume optional fields are present.

Upstream parser reference: https://github.com/MoonshotAI/kimi-code/blob/main/packages/oauth/src/managed-usage.ts

## Errors

- `401`: missing, invalid, expired, or revoked API key.
- `402`: membership is unavailable or expired.
- `403` or `429`: quota, membership, concurrency, or service-capacity condition; preserve and summarize the response message.
- `404`: the private endpoint may be unavailable for the account or may have changed.

If the request fails, recommend the supported `/usage` command in Kimi Code CLI or the Kimi Code Console.
