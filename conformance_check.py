#!/usr/bin/env python3
"""Conformance checker for the gmail-inbox-auth organ.

Runs organ.py on every committed sample and asserts the canonical output
shape: {output, rationale, self_metric} with a numeric self_metric.confidence
and a recognised output.action.

Kept as a standalone committed script (not inline workflow YAML) so it is both
locally runnable and immune to YAML-escaping breakage.

Exit 0 when all samples conform; exit 1 otherwise.
"""

import glob
import json
import os
import subprocess
import sys

REQUIRED_KEYS = {"output", "rationale", "self_metric"}
VALID_ACTIONS = {"not_connected", "refresh", "use_cached"}


def check_sample(path: str) -> list:
    """Return a list of error strings for one sample (empty == conforms)."""
    errors = []
    env = dict(os.environ, ORGAN_INPUT=path)
    proc = subprocess.run(
        [sys.executable, "organ.py"],
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        errors.append(f"organ.py exited {proc.returncode}: {proc.stderr.strip()}")
        return errors

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        errors.append(f"output is not valid JSON: {exc}")
        return errors

    missing = REQUIRED_KEYS - set(data)
    if missing:
        errors.append(f"missing top-level keys: {sorted(missing)}")

    action = data.get("output", {}).get("action")
    if action not in VALID_ACTIONS:
        errors.append(f"output.action {action!r} not in {sorted(VALID_ACTIONS)}")

    metric = data.get("self_metric", {})
    if "confidence" not in metric:
        errors.append("self_metric missing 'confidence'")
    elif not isinstance(metric["confidence"], (int, float)) or isinstance(
        metric["confidence"], bool
    ):
        errors.append(
            f"self_metric.confidence must be numeric, got "
            f"{type(metric.get('confidence')).__name__}"
        )
    return errors


def main() -> int:
    samples = sorted(glob.glob("samples/*.json"))
    if not samples:
        print("ERROR: no samples/*.json found")
        return 1

    summary = os.getenv("GITHUB_STEP_SUMMARY")

    def emit(line: str) -> None:
        print(line)
        if summary:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    emit("# Gmail Inbox Auth Organ — Conformance")
    failed = 0
    for path in samples:
        errors = check_sample(path)
        if errors:
            failed += 1
            emit(f"## ✗ {os.path.basename(path)}")
            for err in errors:
                emit(f"- {err}")
        else:
            emit(f"## ✓ {os.path.basename(path)}")

    emit("")
    if failed:
        emit(f"**{failed}/{len(samples)} samples FAILED conformance**")
        return 1
    emit(f"**All {len(samples)} samples passed conformance**")
    return 0


if __name__ == "__main__":
    sys.exit(main())
