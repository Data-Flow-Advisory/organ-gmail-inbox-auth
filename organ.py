#!/usr/bin/env python3
"""
Gmail Inbox Auth Organ — extracted decision logic from discovery-engine.

A pure decider for the Gmail OAuth credential pipeline. Given a token bundle
that the CALLER has already loaded from its TokenStore (a ``GmailAccount`` row,
a secret file, etc.) plus the current clock and requested scopes, the organ
decides the SINGLE next auth action without ever touching Google's client
libraries, the network, or a database:

  1. resolve the OAuth scopes (default → read-only Gmail),
  2. report whether the account is connected (a refresh token is present),
  3. decide whether the cached access token is still fresh or must be refreshed
     (the ``_needs_refresh`` skew-ahead comparison),
  4. surface the connected email for echo-through.

Provenance (discovery-engine ``lib/dataflow_core/gmail_inbox/auth.py``):
  - The I/O — building ``google.oauth2.credentials.Credentials``, calling
    ``creds.refresh(GoogleRequest())``, ``token_store.save_tokens(...)``, and
    ``build("gmail", "v1", ...)`` — stays in the CALLER. Those are the only
    steps that import the Google client libraries; they are NOT part of this
    organ, which is pure by construction.
  - What IS extracted is every decision the original made BEFORE any I/O:
    the missing-refresh-token guard (``get_credentials`` lines 101-103, the
    ``GmailAuthError`` path), the scope default (line 99), the refresh-skew
    freshness test (``_needs_refresh`` lines 71-74), and the
    ``is_connected`` / ``connected_email`` projections (lines 160-165).

Contract:
  INPUT state: {
    "tokens": {                         # what TokenStore.get_tokens() returns
      "access_token": str | null,
      "refresh_token": str | null,
      "expires_at": str | null,         # ISO-8601; naive == UTC (matches
                                        #   discovery-engine's naive-UTC store)
      "email": str | null
    },
    "now": str | null,                  # decision clock (ISO-8601). When null
                                        #   the organ cannot prove freshness and
                                        #   conservatively refreshes.
    "scopes": [str, ...] | null,        # requested OAuth scopes; null → default
    "refresh_skew_seconds": int | null  # refresh-ahead window; null → 60
  }

  OUTPUT: {
    "output": {
      "action": str,        # "not_connected" | "refresh" | "use_cached"
      "connected": bool,    # a refresh token is present
      "needs_refresh": bool,
      "email": str | null,
      "scopes": [str, ...],         # resolved scopes
      "refresh_skew_seconds": int,
      "seconds_until_expiry": float | null,  # null when not computable
      "error": str | null   # GmailAuthError message when action=="not_connected"
    },
    "rationale": "...",
    "self_metric": {
      "confidence": float,        # 1.0 when inputs well-formed, < 1.0 on
                                  #   unknown-clock / error
      "decision_path": str
    }
  }

The organ is pure:
  - Takes all inputs via JSON (the caller pre-loads the token bundle + clock).
  - Makes no DB / network / Google-client calls.
  - Never raises on bad input (fail-safe → refresh, the conservative branch:
    refreshing a still-valid token is harmless; using a stale one 401s).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

# OAuth scopes (verbatim from auth.py).
GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"

TOKEN_URI = "https://oauth2.googleapis.com/token"

# Refresh slightly ahead of expiry so an in-flight poll doesn't 401
# (auth.py ``_REFRESH_SKEW_SECONDS``).
DEFAULT_REFRESH_SKEW_SECONDS = 60


def resolve_scopes(scopes) -> list:
    """Resolve requested scopes, defaulting to read-only Gmail.

    Mirrors ``scopes = scopes or [GMAIL_READONLY_SCOPE]`` in
    ``get_credentials`` — an empty / null / non-list value falls back to the
    read-only default.
    """
    if isinstance(scopes, list) and scopes:
        return [str(s) for s in scopes]
    return [GMAIL_READONLY_SCOPE]


def parse_dt(value):
    """Parse an ISO-8601 datetime to a naive-UTC ``datetime`` (or None).

    The discovery-engine token store keeps naive-UTC datetimes
    (``_utcnow_naive``). Aware inputs are converted to UTC then stripped of
    tzinfo so comparisons stay naive-vs-naive, matching the original.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # Accept a trailing 'Z' (Zulu) which fromisoformat rejects pre-3.11.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def needs_refresh(expires_at, now, skew_seconds: int) -> bool:
    """Decide whether the access token must be refreshed.

    Mirrors auth.py ``_needs_refresh``: no expiry → refresh; otherwise refresh
    when ``expires_at <= now + skew``. Extends it for purity: when ``now`` is
    unknown the organ cannot prove freshness, so it conservatively refreshes.
    """
    exp = parse_dt(expires_at)
    if exp is None:
        return True
    n = parse_dt(now)
    if n is None:
        # Can't prove freshness without a clock — refresh to be safe.
        return True
    return (exp - n).total_seconds() <= skew_seconds


def decide(state: dict, context: dict | None = None) -> dict:
    """Decide the next Gmail auth action for a loaded token bundle.

    Args:
        state: {"tokens": {...}, "now": ISO, "scopes": [...], "refresh_skew_seconds": int}
        context: unused, present for orchestrator compatibility.

    Returns:
        {"output": {...}, "rationale": "...", "self_metric": {...}}
    """
    context = context or {}

    try:
        tokens = state.get("tokens") or {}
        if not isinstance(tokens, dict):
            tokens = {}

        scopes = resolve_scopes(state.get("scopes"))

        raw_skew = state.get("refresh_skew_seconds")
        try:
            skew = int(raw_skew) if raw_skew is not None else DEFAULT_REFRESH_SKEW_SECONDS
        except (TypeError, ValueError):
            skew = DEFAULT_REFRESH_SKEW_SECONDS

        refresh_token = tokens.get("refresh_token")
        email = tokens.get("email")
        expires_at = tokens.get("expires_at")
        now = state.get("now")

        # seconds_until_expiry is informational; null when not computable.
        exp_dt = parse_dt(expires_at)
        now_dt = parse_dt(now)
        if exp_dt is not None and now_dt is not None:
            seconds_until_expiry = (exp_dt - now_dt).total_seconds()
        else:
            seconds_until_expiry = None

        base_output = {
            "connected": bool(refresh_token),
            "email": email,
            "scopes": scopes,
            "refresh_skew_seconds": skew,
            "seconds_until_expiry": seconds_until_expiry,
        }

        # 1. Missing-refresh-token guard (auth.py lines 101-103). Without a
        #    refresh token the original raises GmailAuthError; the organ
        #    surfaces the same condition as a terminal decision.
        if not refresh_token:
            return {
                "output": {
                    **base_output,
                    "action": "not_connected",
                    "needs_refresh": False,
                    "error": "Gmail not connected — no refresh token available.",
                },
                "rationale": (
                    "No refresh token in the token bundle; the account is not "
                    "connected. Caller should raise GmailAuthError / re-run the "
                    "OAuth consent flow."
                ),
                "self_metric": {"confidence": 1.0, "decision_path": "not_connected"},
            }

        must_refresh = needs_refresh(expires_at, now, skew)

        # When connected but the clock is unknown we still decide (conservative
        # refresh) — flag the reduced certainty.
        clock_unknown = exp_dt is not None and now_dt is None
        confidence = 0.5 if clock_unknown else 1.0

        if must_refresh:
            if exp_dt is None:
                why = "no expiry recorded"
            elif now_dt is None:
                why = "decision clock unknown (no 'now'); refreshing conservatively"
            else:
                why = (
                    f"token expires in {seconds_until_expiry:.0f}s, "
                    f"within the {skew}s refresh skew"
                )
            return {
                "output": {
                    **base_output,
                    "action": "refresh",
                    "needs_refresh": True,
                    "error": None,
                },
                "rationale": (
                    f"Connected; access token must be refreshed ({why}). Caller "
                    f"should refresh and persist via save_tokens()."
                ),
                "self_metric": {
                    "confidence": confidence,
                    "decision_path": "refresh",
                },
            }

        # 3. Use cached — token is present and outside the refresh skew.
        return {
            "output": {
                **base_output,
                "action": "use_cached",
                "needs_refresh": False,
                "error": None,
            },
            "rationale": (
                f"Connected; cached access token is fresh "
                f"({seconds_until_expiry:.0f}s left, beyond the {skew}s skew). "
                f"Caller may build the Gmail service without refreshing."
            ),
            "self_metric": {"confidence": 1.0, "decision_path": "use_cached"},
        }

    except Exception as e:
        # Fail-safe → refresh. Refreshing a still-valid token is cheap and
        # harmless; using a stale one 401s the whole poll.
        return {
            "output": {
                "action": "refresh",
                "connected": True,
                "needs_refresh": True,
                "email": None,
                "scopes": [GMAIL_READONLY_SCOPE],
                "refresh_skew_seconds": DEFAULT_REFRESH_SKEW_SECONDS,
                "seconds_until_expiry": None,
                "error": None,
            },
            "rationale": f"Decision logic error (fail-safe → refresh): {e}",
            "self_metric": {"confidence": 0.0, "decision_path": "error_fallback"},
        }


def main() -> int:
    path = os.environ.get("ORGAN_INPUT")
    raw = open(path).read() if path else sys.stdin.read()
    try:
        payload = json.loads(raw)
        state = payload["state"]
    except Exception as e:
        print(json.dumps({"error": f"invalid input: {e}"}), file=sys.stderr)
        return 1
    print(json.dumps(decide(state, payload.get("context")), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
