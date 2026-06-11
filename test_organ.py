#!/usr/bin/env python3
"""Tests for the Gmail Inbox Auth Organ."""

import glob
import json
import os
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone

from organ import (
    DEFAULT_REFRESH_SKEW_SECONDS,
    GMAIL_MODIFY_SCOPE,
    GMAIL_READONLY_SCOPE,
    decide,
    needs_refresh,
    parse_dt,
    resolve_scopes,
)

# Directory containing this test file (== repo root). Used for subprocess cwd
# so the suite is portable across machines and CI checkout paths.
REPO_DIR = os.path.dirname(os.path.abspath(__file__))


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


NOW = datetime(2026, 6, 11, 12, 0, 0)


class TestResolveScopes(unittest.TestCase):
    def test_none_defaults_readonly(self):
        self.assertEqual(resolve_scopes(None), [GMAIL_READONLY_SCOPE])

    def test_empty_list_defaults_readonly(self):
        self.assertEqual(resolve_scopes([]), [GMAIL_READONLY_SCOPE])

    def test_non_list_defaults_readonly(self):
        self.assertEqual(resolve_scopes("nope"), [GMAIL_READONLY_SCOPE])

    def test_explicit_scopes_preserved(self):
        self.assertEqual(
            resolve_scopes([GMAIL_MODIFY_SCOPE]), [GMAIL_MODIFY_SCOPE]
        )

    def test_scopes_coerced_to_str(self):
        self.assertEqual(resolve_scopes([123]), ["123"])


class TestParseDt(unittest.TestCase):
    def test_none(self):
        self.assertIsNone(parse_dt(None))

    def test_empty_string(self):
        self.assertIsNone(parse_dt("   "))

    def test_garbage_string(self):
        self.assertIsNone(parse_dt("not-a-date"))

    def test_naive_iso(self):
        self.assertEqual(parse_dt("2026-06-11T12:00:00"), NOW)

    def test_zulu_suffix_converted_to_naive_utc(self):
        # 'Z' is UTC; result should be the naive-UTC equivalent.
        self.assertEqual(parse_dt("2026-06-11T12:00:00Z"), NOW)

    def test_aware_offset_converted_to_utc(self):
        # 13:00 +01:00 == 12:00 UTC naive.
        self.assertEqual(parse_dt("2026-06-11T13:00:00+01:00"), NOW)

    def test_datetime_passthrough(self):
        self.assertEqual(parse_dt(NOW), NOW)


class TestNeedsRefresh(unittest.TestCase):
    def test_no_expiry_refreshes(self):
        self.assertTrue(needs_refresh(None, _iso(NOW), 60))

    def test_no_clock_refreshes_conservatively(self):
        self.assertTrue(needs_refresh(_iso(NOW + timedelta(hours=1)), None, 60))

    def test_fresh_token_no_refresh(self):
        exp = _iso(NOW + timedelta(hours=1))
        self.assertFalse(needs_refresh(exp, _iso(NOW), 60))

    def test_expired_token_refreshes(self):
        exp = _iso(NOW - timedelta(minutes=5))
        self.assertTrue(needs_refresh(exp, _iso(NOW), 60))

    def test_within_skew_refreshes(self):
        # expires in 30s, skew 60s → must refresh.
        exp = _iso(NOW + timedelta(seconds=30))
        self.assertTrue(needs_refresh(exp, _iso(NOW), 60))

    def test_exactly_at_skew_boundary_refreshes(self):
        # expires in exactly 60s, skew 60s → <= boundary → refresh.
        exp = _iso(NOW + timedelta(seconds=60))
        self.assertTrue(needs_refresh(exp, _iso(NOW), 60))

    def test_just_beyond_skew_no_refresh(self):
        exp = _iso(NOW + timedelta(seconds=61))
        self.assertFalse(needs_refresh(exp, _iso(NOW), 60))


class TestDecideNotConnected(unittest.TestCase):
    def test_no_refresh_token(self):
        out = decide({"tokens": {"access_token": "a", "email": "x@y.com"}})
        self.assertEqual(out["output"]["action"], "not_connected")
        self.assertFalse(out["output"]["connected"])
        self.assertFalse(out["output"]["needs_refresh"])
        self.assertIn("no refresh token", out["output"]["error"].lower())
        self.assertEqual(out["self_metric"]["decision_path"], "not_connected")
        self.assertEqual(out["self_metric"]["confidence"], 1.0)

    def test_empty_tokens(self):
        out = decide({"tokens": {}})
        self.assertEqual(out["output"]["action"], "not_connected")

    def test_missing_tokens_key(self):
        out = decide({})
        self.assertEqual(out["output"]["action"], "not_connected")

    def test_email_echoed_even_when_not_connected(self):
        out = decide({"tokens": {"email": "x@y.com"}})
        self.assertEqual(out["output"]["email"], "x@y.com")


class TestDecideRefresh(unittest.TestCase):
    def test_no_expiry_refreshes(self):
        out = decide(
            {"tokens": {"refresh_token": "r", "access_token": "a"}, "now": _iso(NOW)}
        )
        self.assertEqual(out["output"]["action"], "refresh")
        self.assertTrue(out["output"]["connected"])
        self.assertTrue(out["output"]["needs_refresh"])
        self.assertIsNone(out["output"]["error"])
        self.assertEqual(out["self_metric"]["decision_path"], "refresh")

    def test_expired_refreshes(self):
        out = decide(
            {
                "tokens": {
                    "refresh_token": "r",
                    "expires_at": _iso(NOW - timedelta(minutes=1)),
                },
                "now": _iso(NOW),
            }
        )
        self.assertEqual(out["output"]["action"], "refresh")
        self.assertLess(out["output"]["seconds_until_expiry"], 0)

    def test_unknown_clock_lowers_confidence(self):
        out = decide(
            {"tokens": {"refresh_token": "r", "expires_at": _iso(NOW + timedelta(hours=1))}}
        )
        self.assertEqual(out["output"]["action"], "refresh")
        self.assertEqual(out["self_metric"]["confidence"], 0.5)
        self.assertIsNone(out["output"]["seconds_until_expiry"])


class TestDecideUseCached(unittest.TestCase):
    def test_fresh_token_uses_cache(self):
        out = decide(
            {
                "tokens": {
                    "refresh_token": "r",
                    "access_token": "a",
                    "email": "x@y.com",
                    "expires_at": _iso(NOW + timedelta(hours=1)),
                },
                "now": _iso(NOW),
            }
        )
        self.assertEqual(out["output"]["action"], "use_cached")
        self.assertFalse(out["output"]["needs_refresh"])
        self.assertTrue(out["output"]["connected"])
        self.assertEqual(out["output"]["email"], "x@y.com")
        self.assertEqual(out["self_metric"]["confidence"], 1.0)
        self.assertAlmostEqual(out["output"]["seconds_until_expiry"], 3600, delta=1)


class TestDecideScopesAndSkew(unittest.TestCase):
    def test_default_scope(self):
        out = decide({"tokens": {"refresh_token": "r"}, "now": _iso(NOW)})
        self.assertEqual(out["output"]["scopes"], [GMAIL_READONLY_SCOPE])

    def test_explicit_modify_scope(self):
        out = decide(
            {
                "tokens": {"refresh_token": "r"},
                "scopes": [GMAIL_MODIFY_SCOPE],
                "now": _iso(NOW),
            }
        )
        self.assertEqual(out["output"]["scopes"], [GMAIL_MODIFY_SCOPE])

    def test_default_skew(self):
        out = decide({"tokens": {"refresh_token": "r"}, "now": _iso(NOW)})
        self.assertEqual(
            out["output"]["refresh_skew_seconds"], DEFAULT_REFRESH_SKEW_SECONDS
        )

    def test_custom_skew_widens_refresh_window(self):
        # expires in 5 min; default skew (60s) would NOT refresh, but a
        # 600s skew should.
        exp = _iso(NOW + timedelta(minutes=5))
        cached = decide(
            {"tokens": {"refresh_token": "r", "expires_at": exp}, "now": _iso(NOW)}
        )
        self.assertEqual(cached["output"]["action"], "use_cached")
        refreshed = decide(
            {
                "tokens": {"refresh_token": "r", "expires_at": exp},
                "now": _iso(NOW),
                "refresh_skew_seconds": 600,
            }
        )
        self.assertEqual(refreshed["output"]["action"], "refresh")

    def test_bad_skew_falls_back_to_default(self):
        out = decide(
            {
                "tokens": {"refresh_token": "r"},
                "now": _iso(NOW),
                "refresh_skew_seconds": "nonsense",
            }
        )
        self.assertEqual(
            out["output"]["refresh_skew_seconds"], DEFAULT_REFRESH_SKEW_SECONDS
        )


class TestContractShape(unittest.TestCase):
    def test_all_paths_have_canonical_shape(self):
        cases = [
            {"tokens": {}},  # not_connected
            {"tokens": {"refresh_token": "r"}, "now": _iso(NOW)},  # refresh (no exp)
            {
                "tokens": {"refresh_token": "r", "expires_at": _iso(NOW + timedelta(hours=1))},
                "now": _iso(NOW),
            },  # use_cached
        ]
        for state in cases:
            out = decide(state)
            self.assertEqual(set(out), {"output", "rationale", "self_metric"})
            self.assertIn("action", out["output"])
            self.assertIsInstance(out["self_metric"]["confidence"], (int, float))
            self.assertNotIsInstance(out["self_metric"]["confidence"], bool)
            self.assertIsInstance(out["rationale"], str)

    def test_fail_safe_on_garbage_state(self):
        # state is not a dict-with-tokens; .get on a str raises → fail-safe.
        out = decide("garbage")  # type: ignore[arg-type]
        self.assertEqual(out["output"]["action"], "refresh")
        self.assertEqual(out["self_metric"]["confidence"], 0.0)
        self.assertEqual(out["self_metric"]["decision_path"], "error_fallback")


class TestSamplesViaSubprocess(unittest.TestCase):
    """Drive organ.py as a subprocess over every committed sample."""

    def test_samples_conform(self):
        samples = sorted(glob.glob(os.path.join(REPO_DIR, "samples", "*.json")))
        self.assertTrue(samples, "no samples found")
        for path in samples:
            env = dict(os.environ, ORGAN_INPUT=path)
            proc = subprocess.run(
                [sys.executable, "organ.py"],
                cwd=REPO_DIR,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"{path}: {proc.stderr}")
            data = json.loads(proc.stdout)
            self.assertEqual(set(data), {"output", "rationale", "self_metric"})
            self.assertIn(
                data["output"]["action"],
                {"not_connected", "refresh", "use_cached"},
            )


if __name__ == "__main__":
    unittest.main()
