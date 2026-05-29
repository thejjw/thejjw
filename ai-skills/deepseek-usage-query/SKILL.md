---
name: deepseek-usage-query
description: Query DeepSeek API balance and estimate remaining token budget from current pricing
metadata:
  audience: developers
  workflow: deepseek-monitoring
---

## What I do

Query the **current balance** from the DeepSeek platform. Returns JSON with balance availability and per-currency balances only; DeepSeek does **not** provide a detailed token-usage ledger from this endpoint.

Use the returned **CNY** and **USD** balances to estimate how much DeepSeek V4 Flash or V4 Pro usage remains under the current pricing.

## Configuration

**API Key:** `$env:DEEPSEEK_API_KEY` (Windows) or `DEEPSEEK_API_KEY` (Linux/Mac).

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

For current planning, use the matching currency for the estimate:

- DeepSeek V4 Flash
  - 1M input tokens, cache hit: `0.0028 USD` or `0.02 CNY`
  - 1M input tokens, cache miss: `0.14 USD` or `1 CNY`
  - 1M output tokens: `0.28 USD` or `2 CNY`
- DeepSeek V4 Pro
  - 1M input tokens, cache hit: `0.003625 USD` or `0.025 CNY`
  - 1M input tokens, cache miss: `0.435 USD` or `3 CNY`
  - 1M output tokens: `0.87 USD` or `6 CNY`

> These estimates are approximate. Actual spend depends on cache-hit ratio, prompt size, output length, and model mix. If both USD and CNY balances are returned, compute both separately and report the more conservative remaining budget when needed.

## Note

The document can be updated via https://api-docs.deepseek.com/api/get-user-balance and https://api-docs.deepseek.com/quick_start/pricing for API usage and model/pricing information.