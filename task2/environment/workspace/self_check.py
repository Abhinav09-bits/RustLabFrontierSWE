#!/usr/bin/env python3
"""Public self-check. The scored run uses other names, paths, and clocks."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

BIN = os.environ.get("GATE_PY", "/app/gatekeep.py")


def run(policy: dict, request: dict, when: int) -> subprocess.CompletedProcess:
    scratch = Path(tempfile.mkdtemp(prefix="gate-self-"))
    policy_path = scratch / "policy.json"
    request_path = scratch / "request.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    request_path.write_text(json.dumps(request), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            BIN,
            "decide",
            "--policy",
            str(policy_path),
            "--request",
            str(request_path),
            "--time",
            str(when),
        ],
        capture_output=True,
        text=True,
    )


def main() -> int:
    if not Path(BIN).is_file():
        print("self-check 0/5")
        print(f"missing program: {BIN}", file=sys.stderr)
        return 1

    allow_library = {
        "default": "deny",
        "rules": [
            {
                "id": "public-read",
                "effect": "allow",
                "principal": "casey",
                "action": "read",
                "resource": "/library/*",
            }
        ],
    }
    cases = [
        (
            "library file",
            allow_library,
            {"principal": "casey", "action": "read", "resource": "/library/readme"},
            100,
            0,
            "allow\n",
        ),
        (
            "closed vault",
            allow_library,
            {"principal": "casey", "action": "read", "resource": "/vault/key"},
            100,
            1,
            "deny\n",
        ),
        (
            "deny overrides",
            {
                "default": "deny",
                "rules": [
                    {
                        "id": "public-any",
                        "effect": "allow",
                        "principal": "*",
                        "action": "*",
                        "resource": "*",
                    },
                    {
                        "id": "public-block",
                        "effect": "deny",
                        "principal": "casey",
                        "action": "read",
                        "resource": "/vault",
                    },
                ],
            },
            {"principal": "casey", "action": "read", "resource": "/vault"},
            100,
            1,
            "deny\n",
        ),
        (
            "dotdot",
            allow_library,
            {"principal": "casey", "action": "read", "resource": "/library/../vault/key"},
            100,
            1,
            "deny\n",
        ),
        (
            "encoded slash",
            allow_library,
            {"principal": "casey", "action": "read", "resource": "/library%2F../vault/key"},
            100,
            1,
            "deny\n",
        ),
    ]
    passed = 0
    for name, policy, request, when, code, stdout in cases:
        proc = run(policy, request, when)
        if proc.returncode == code and proc.stdout == stdout:
            passed += 1
        else:
            print(
                f"{name} failed: exit {proc.returncode} stdout {proc.stdout!r}",
                file=sys.stderr,
            )
    print(f"self-check {passed}/{len(cases)}")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
