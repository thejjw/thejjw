# Test fixtures

Captured responses used by the usage-query tests. Every file is synthetic: no
account identifier, email address, or other personal data is present, so the
fixtures are safe to keep in the repository.

| File | Provenance |
|---|---|
| `codex-wham-usage.json` | The `wham/usage` response body the Codex CLI's own test suite mocks, taken verbatim from `codex-rs/app-server/tests/suite/v2/rate_limits.rs` in `openai/codex`. The `account-123` and `user-123` identifiers are the suite's placeholders. |
| `claude-oauth-usage-flat.json` | The flat `/api/oauth/usage` shape: `five_hour` and `seven_day` objects, the legacy per-model weekly buckets, and a disabled `extra_usage` block. |
| `claude-oauth-usage-limits.json` | The `limits[]` shape, combined with the flat objects because the console returns both at once. It carries a `session`, a `weekly_all`, and a model-scoped `weekly_scoped` entry. |

The two Claude shapes are what Anthropic's endpoint returns in the wild: an
older account sees the flat objects, a newer one sees the `limits` array, and
some responses carry both. The parser prefers the array, so a window is never
reported twice.
