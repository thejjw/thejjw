# aiusage

Collect AI subscription usage that `hermes usage` does not cover (Z.AI, Kimi,
MiniMax, DeepSeek), merge it with the providers Hermes already reports, and
render one plain-text message that can be delivered by `hermes send`.

No LLM is involved at any point: fetching, merging and rendering are ordinary
Python stdlib calls, and delivery is a single `hermes send` invocation.

## Layout

| Path | Purpose |
|---|---|
| `contract.py` | `Window` / `UsageReport` and the JSON shape shared with `hermes usage --json` |
| `http.py` | urllib wrapper: timeout, bounded retries, short failure reasons |
| `keys.py` | credential resolution (flag, env, `~/.hermes/.env`, Hermes credential pool) |
| `render.py` | KST formatting, reset countdowns, message layout |
| `providers/` | one adapter per provider: `parse(doc)` for tests, `fetch(key)` for the network |
| `cli.py` | `fetch`, `render`, `report` subcommands |
| `tests/` | offline unittest suite plus captured response fixtures |

## Commands

```bash
# fetch and render the four local providers (debugging)
PYTHONPATH=hermes python3 -m aiusage report

# emit JSON, one file per provider
PYTHONPATH=hermes python3 -m aiusage fetch --out /tmp/usage

# render a directory of saved documents (network-free)
PYTHONPATH=hermes python3 -m aiusage render /tmp/usage
```

`aiusage.sh` in this directory is a thin wrapper for interactive use.

## Credentials

Resolution order per provider: explicit value, process environment,
`~/.hermes/.env`, then the Hermes credential pool in `~/.hermes/auth.json`.
Variable names: `ZAI_API_KEY`/`GLM_API_KEY`, `KIMI_CODE_PLAN_API_KEY`/
`KIMI_API_KEY`, `MINIMAX_API_KEY`, `DEEPSEEK_API_KEY`.

Keys are never printed or logged. A missing key becomes an `unavailable` line in
the report instead of an error.

## Resets

Every window carries a reset time when the provider reports one, and the
message always states which case applies:

- `resets <time> KST (in <countdown>)` — reported by the API, or derived from a
  known window start plus duration.
- `reset not reported (<window> rolling)` — the API exposes a rolling window but
  no anchor to compute the next reset from. Z.AI's 5-hour token window is the
  known case; inventing a time here would be fabrication.
- `reset n/a` — a window with no reset concept at all.

Prepaid balances (DeepSeek) have no window and say so.

## Tests

```bash
python3 -m unittest discover -s aiusage/tests -t .
```

All parsing and rendering tests run against captured fixtures; no network and no
credentials needed. On Windows, `pip install tzdata` first — there is no system
IANA database for `zoneinfo`.

## Deployment

The daily job lives outside this repository: `/root/.hermes/scripts/ai-usage-report.sh`
builds the report (three `hermes usage` calls plus `fetch --out`) and pipes the
rendered text to `hermes send`. Host cron runs it at `0 23 * * *` UTC, which is
08:00 KST. `/root/.hermes/scripts/verify-ai-usage-report.sh` audits the install,
and the runner accepts `--dry-run` to print the message without sending it.
