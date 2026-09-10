---
name: deepseek-usage-query
description: Query DeepSeek API balance and estimate remaining token budget from current pricing
metadata:
  audience: developers
  workflow: deepseek-monitoring
---

## What I do

Query the **current balance** from the DeepSeek platform. Returns JSON with balance availability and per-currency balances only; DeepSeek does **not** provide a detailed token-usage ledger from this endpoint.

Use the returned **CNY** and **USD** balances to estimate how much DeepSeek V4.1 Flash or V4 Pro usage remains under the current pricing.

## Configuration

**API Key:**
- **Windows:** Read from the `$env:DEEPSEEK_API_KEY` environment variable. In the personal Windows setup, this is usually loaded from Windows Credential Store by the `Load-AiApiKeysFromCS` function in the PowerShell profile.
- **Linux/Mac:** Read from the `DEEPSEEK_API_KEY` environment variable.

## API Endpoint

**URL:** `https://api.deepseek.com/user/balance`

**Method:** `GET`

**Headers:**
- `Content-Type: application/json`
- `Authorization: Bearer <your-api-key>`

## Calling the API

### Bash / Git Bash / WSL
```bash
curl -s 'https://api.deepseek.com/user/balance' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $DEEPSEEK_API_KEY"
```

### PowerShell
```powershell
$headers = @{
    'Content-Type' = 'application/json'
    'Authorization' = "Bearer $env:DEEPSEEK_API_KEY"
}
Invoke-RestMethod -Uri 'https://api.deepseek.com/user/balance' -Headers $headers
```

> Note: On Windows, `$env:DEEPSEEK_API_KEY` may not expand inside `curl` arguments - use `$DEEPSEEK_API_KEY` with bash-style curl, or use `Invoke-RestMethod` for PowerShell.
> Note: pipe to `jq` if available for formatted output.

## Response

JSON with:
- `is_available`: whether the account has sufficient balance for API calls
- `balance_infos`: array of balance objects, one per currency

Each balance object includes:
- `currency`: `CNY` or `USD`
- `total_balance`: total available balance
- `granted_balance`: not-expired granted balance
- `topped_up_balance`: topped-up balance

## Practical Analysis

Use the balance values to estimate rough token budgets with:

`estimated_tokens = balance / price_per_1M_tokens * 1,000,000`

For current planning, use the matching currency for the estimate (off-peak baseline; peak hours double these rates):

- DeepSeek V4.1 Flash (Off-Peak)
  - 1M input tokens, cache hit: `0.003 USD` or `0.02 CNY`
  - 1M input tokens, cache miss: `0.15 USD` or `1.00 CNY`
  - 1M output tokens: `0.60 USD` or `4.00 CNY`
- DeepSeek V4 Pro
  - Prior to V4.1 Pro launch, all requests to V4 Pro are server-side routed to V4.1 Flash and billed at the V4.1 Flash rates above.

Peak hours (2x rates): Monday to Friday 01:00-04:00 and 06:00-10:00 UTC (09:00-12:00 and 14:00-18:00 Beijing Time). Weekends and all other hours bill at off-peak rates.
> These estimates are approximate. Actual spend depends on cache-hit ratio, prompt size, output length, and model mix. If both USD and CNY balances are returned, compute both separately and report the more conservative remaining budget when needed.

## Note

The document can be updated via https://api-docs.deepseek.com/api/get-user-balance and https://api-docs.deepseek.com/quick_start/pricing for API usage and model/pricing information.
