# organ-gmail-inbox-auth

A **pure decision organ** extracted from discovery-engine
`lib/dataflow_core/gmail_inbox/auth.py`. It decides the single next action for
a Gmail OAuth credential pipeline — *connect*, *refresh*, or *use the cached
token* — without ever importing Google's client libraries, hitting the network,
or touching a database.

The I/O (building `Credentials`, calling `creds.refresh()`,
`token_store.save_tokens()`, `build("gmail", "v1", ...)`) stays in the caller.
This organ owns only the decisions the original made *before* any I/O.

## Contract

`decide(state, context) -> {output, rationale, self_metric}`

### Input `state`

```json
{
  "tokens": {
    "access_token": "ya29...",
    "refresh_token": "1//...",
    "expires_at": "2026-06-11T12:55:00Z",
    "email": "ops@example.com"
  },
  "now": "2026-06-11T12:00:00Z",
  "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
  "refresh_skew_seconds": 60
}
```

| field | meaning |
|-------|---------|
| `tokens` | exactly what `TokenStore.get_tokens()` returns. `expires_at` is ISO-8601; a naive value is treated as UTC (matching discovery-engine's naive-UTC store). |
| `now` | the decision clock (ISO-8601). **Null → the organ cannot prove freshness and conservatively refreshes.** Pass a real clock for purity. |
| `scopes` | requested OAuth scopes. Null/empty/non-list → defaults to read-only Gmail. |
| `refresh_skew_seconds` | refresh-ahead window. Null/invalid → 60. |

### Output

```json
{
  "output": {
    "action": "use_cached",
    "connected": true,
    "needs_refresh": false,
    "email": "ops@example.com",
    "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
    "refresh_skew_seconds": 60,
    "seconds_until_expiry": 3300.0,
    "error": null
  },
  "rationale": "Connected; cached access token is fresh ...",
  "self_metric": { "confidence": 1.0, "decision_path": "use_cached" }
}
```

`output.action` is one of:

| action | when | original behaviour |
|--------|------|--------------------|
| `not_connected` | no refresh token in the bundle | `get_credentials` raises `GmailAuthError` (`output.error` carries the message) |
| `refresh` | connected, but no expiry / within skew / expired / unknown clock | `creds.refresh()` then `save_tokens()` |
| `use_cached` | connected and the token is fresh beyond the skew | build the service without refreshing |

`self_metric.confidence`: `1.0` for a well-formed decision; `0.5` when connected
but the clock is unknown (decision still made, conservatively refresh); `0.0` on
an internal error (fail-safe → `refresh`).

## Provenance

Extracted from `lib/dataflow_core/gmail_inbox/auth.py`:

- **missing-refresh-token guard** — `get_credentials` → `GmailAuthError`
- **scope default** — `scopes = scopes or [GMAIL_READONLY_SCOPE]`
- **`_needs_refresh`** — `expires_at <= now + _REFRESH_SKEW_SECONDS`
- **`is_connected` / `connected_email`** projections

Deliberately **not** extracted (impure I/O — stays in the caller):
`Credentials(...)`, `creds.refresh(GoogleRequest())`, `save_tokens(...)`,
`build("gmail", "v1", ...)`.

## Run

```bash
# one sample
ORGAN_INPUT=samples/use_cached_fresh.json python3 organ.py

# from stdin
echo '{"state": {"tokens": {"refresh_token": "r"}, "now": "2026-06-11T12:00:00Z"}}' | python3 organ.py

# conformance + tests
python3 conformance_check.py
python -m pytest -v
```

## Design notes

- **Pure.** No DB / network / Google-client calls. All inputs arrive as JSON.
- **Fail-safe → refresh.** A malformed state never raises; refreshing a still
  valid token is harmless, while using a stale one 401s the whole poll.
- **Naive-UTC clock.** Aware datetimes are converted to UTC then stripped of
  tzinfo so comparisons stay naive-vs-naive, exactly as the original store did.
