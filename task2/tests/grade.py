#!/usr/bin/env python3
"""Hidden grader for the authorization gate."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

BIN = os.environ.get("GATE_PY", "/app/gatekeep.py")


def run(policy, request, when, raw_policy=None, raw_request=None) -> subprocess.CompletedProcess:
    scratch = Path(tempfile.mkdtemp(prefix="gate-grade-"))
    if os.environ.get("GATE_AS_USER"):
        os.chmod(scratch, 0o777)
    policy_path = scratch / "policy.json"
    request_path = scratch / "request.json"
    if raw_policy is None:
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
    else:
        policy_path.write_text(raw_policy, encoding="utf-8")
    if raw_request is None:
        request_path.write_text(json.dumps(request), encoding="utf-8")
    else:
        request_path.write_text(raw_request, encoding="utf-8")
    user = os.environ.get("GATE_AS_USER", "")
    cmd = [
        sys.executable,
        BIN,
        "decide",
        "--policy",
        str(policy_path),
        "--request",
        str(request_path),
        "--time",
        str(when),
    ]
    if user:
        cmd = ["runuser", "-u", user, "--", *cmd]
    return subprocess.run(cmd, capture_output=True, text=True)


class Fail(Exception):
    pass


def expect(cond: bool, message: str) -> None:
    if not cond:
        raise Fail(message)


def expect_decision(policy, request, when, code, text, message) -> None:
    proc = run(policy, request, when)
    expect(proc.returncode == code and proc.stdout == text, f"{message}: exit {proc.returncode} stdout {proc.stdout!r} stderr {proc.stderr!r}")


def allow_rule(rule_id, principal, action, resource, **extra):
    rule = {
        "id": rule_id,
        "effect": "allow",
        "principal": principal,
        "action": action,
        "resource": resource,
    }
    rule.update(extra)
    return rule


def deny_rule(rule_id, principal, action, resource, **extra):
    rule = allow_rule(rule_id, principal, action, resource, **extra)
    rule["effect"] = "deny"
    return rule


def test_child_allow_and_sibling_prefix() -> None:
    policy = {
        "default": "deny",
        "rules": [allow_rule("read-records", "mina", "read", "/records/*")],
    }
    expect_decision(
        policy,
        {"principal": "mina", "action": "read", "resource": "/records/2024/q1"},
        1_700_000_000,
        0,
        "allow\n",
        "child path",
    )
    expect_decision(
        policy,
        {"principal": "mina", "action": "read", "resource": "/records"},
        1_700_000_000,
        1,
        "deny\n",
        "exact parent is not a child pattern",
    )
    expect_decision(
        policy,
        {"principal": "mina", "action": "read", "resource": "/records-extra"},
        1_700_000_000,
        1,
        "deny\n",
        "prefix lookalike",
    )


def test_default_allow_and_exact_root() -> None:
    policy = {"default": "allow", "rules": []}
    expect_decision(
        policy,
        {"principal": "ravi", "action": "list", "resource": "/"},
        10,
        0,
        "allow\n",
        "default allow on root",
    )
    starred = {"default": "deny", "rules": [allow_rule("all", "*", "*", "*")]}
    expect_decision(
        starred,
        {"principal": "ravi", "action": "list", "resource": "/"},
        10,
        0,
        "allow\n",
        "star matches root",
    )
    children = {"default": "deny", "rules": [allow_rule("kids", "*", "*", "/*")]}
    expect_decision(
        children,
        {"principal": "ravi", "action": "list", "resource": "/"},
        10,
        1,
        "deny\n",
        "slash-star does not match root",
    )
    expect_decision(
        children,
        {"principal": "ravi", "action": "list", "resource": "/payroll"},
        10,
        0,
        "allow\n",
        "slash-star matches one segment",
    )


def test_deny_overrides_other_action() -> None:
    policy = {
        "default": "deny",
        "rules": [
            allow_rule("wide", "mina", "*", "/finance/*"),
            deny_rule("no-wire", "mina", "wire", "/finance/outbox"),
        ],
    }
    expect_decision(
        policy,
        {"principal": "mina", "action": "wire", "resource": "/finance/outbox"},
        50,
        1,
        "deny\n",
        "specific deny overrides allow",
    )
    expect_decision(
        policy,
        {"principal": "mina", "action": "read", "resource": "/finance/outbox"},
        50,
        0,
        "allow\n",
        "a different action stays allowed",
    )


def test_windows_and_dot_segments() -> None:
    policy = {
        "default": "deny",
        "rules": [allow_rule("pay", "leela", "read", "/payroll/2024")],
    }
    expect_decision(
        policy,
        {"principal": "leela", "action": "read", "resource": "/payroll\\2024"},
        80,
        0,
        "allow\n",
        "backslash is a separator",
    )
    expect_decision(
        policy,
        {"principal": "leela", "action": "read", "resource": "/payroll/./2024/"},
        80,
        0,
        "allow\n",
        "dot and trailing slash collapse",
    )
    expect_decision(
        policy,
        {"principal": "leela", "action": "read", "resource": "/payroll//2024"},
        80,
        0,
        "allow\n",
        "repeated slash collapses",
    )


def test_single_decode_only() -> None:
    policy = {
        "default": "deny",
        "rules": [allow_rule("desk", "leela", "read", "/desk/*")],
    }
    expect_decision(
        policy,
        {"principal": "leela", "action": "read", "resource": "/desk/%2e%2e/payroll"},
        80,
        1,
        "deny\n",
        "encoded dotdot leaves the allowed tree",
    )
    expect_decision(
        policy,
        {"principal": "leela", "action": "read", "resource": "/desk/%252e%252e/notes"},
        80,
        0,
        "allow\n",
        "a second decode must not run",
    )
    expect_decision(
        policy,
        {"principal": "leela", "action": "read", "resource": "/desk%5c..%5cpayroll"},
        80,
        1,
        "deny\n",
        "encoded backslash becomes a separator",
    )


def test_escape_beats_allow_all() -> None:
    policy = {"default": "deny", "rules": [allow_rule("any", "*", "*", "*")]}
    expect_decision(
        policy,
        {"principal": "mina", "action": "read", "resource": "/../payroll"},
        80,
        1,
        "deny\n",
        "an escaped path is denied before rules",
    )
    expect_decision(
        policy,
        {"principal": "mina", "action": "read", "resource": "/desk/../../payroll"},
        80,
        1,
        "deny\n",
        "popping past the root denies",
    )


def test_time_window_is_inclusive() -> None:
    policy = {
        "default": "deny",
        "rules": [allow_rule("shift", "omar", "open", "/lab/*", not_before=1000, not_after=2000)],
    }
    request = {"principal": "omar", "action": "open", "resource": "/lab/hood"}
    expect_decision(policy, request, 1000, 0, "allow\n", "not_before is inclusive")
    expect_decision(policy, request, 2000, 0, "allow\n", "not_after is inclusive")
    expect_decision(policy, request, 999, 1, "deny\n", "before the window")
    expect_decision(policy, request, 2001, 1, "deny\n", "after the window")


def test_case_and_other_principal() -> None:
    policy = {
        "default": "deny",
        "rules": [allow_rule("one", "Mina", "read", "/Records/*")],
    }
    expect_decision(
        policy,
        {"principal": "mina", "action": "read", "resource": "/Records/a"},
        5,
        1,
        "deny\n",
        "principal case",
    )
    expect_decision(
        policy,
        {"principal": "Mina", "action": "read", "resource": "/records/a"},
        5,
        1,
        "deny\n",
        "path case",
    )


def test_malformed_documents() -> None:
    good_request = {"principal": "omar", "action": "open", "resource": "/lab"}
    cases = [
        ({"default": "deny", "rules": [], "extra": 1}, good_request, "extra policy key"),
        (
            {"default": "deny", "rules": [allow_rule("a", "omar", "open", "/"), ]},
            good_request,
            "root is not a pattern",
        ),
        (
            {
                "default": "deny",
                "rules": [
                    allow_rule("same", "omar", "open", "/lab"),
                    allow_rule("same", "omar", "open", "/lab"),
                ],
            },
            good_request,
            "duplicate rule id",
        ),
        (
            {"default": "deny", "rules": [allow_rule("w", "omar", "open", "/lab/*", not_before=5, not_after=4)]},
            good_request,
            "reversed window",
        ),
        (
            {"default": "deny", "rules": [allow_rule("ok", "omar", "open", "/lab")]},
            {"principal": "*", "action": "open", "resource": "/lab"},
            "star principal in a request",
        ),
        (
            {"default": "deny", "rules": [allow_rule("ok", "omar", "open", "/lab")]},
            {"principal": "omar", "action": "open", "resource": "lab"},
            "relative resource",
        ),
        (
            {"default": "deny", "rules": [allow_rule("ok", "omar", "open", "/lab")]},
            {"principal": "omar", "action": "open", "resource": "/lab/%zz"},
            "broken percent escape",
        ),
    ]
    for policy, request, message in cases:
        proc = run(policy, request, 10)
        expect(proc.returncode == 2 and proc.stdout == "", f"{message}: exit {proc.returncode} stdout {proc.stdout!r}")
    proc = run(
        {"default": "deny", "rules": []},
        good_request,
        10,
        raw_policy='{"default":"deny","default":"allow","rules":[]}',
    )
    expect(proc.returncode == 2 and proc.stdout == "", f"duplicate key: exit {proc.returncode} stdout {proc.stdout!r}")


def main() -> int:
    if not Path(BIN).is_file():
        print(f"missing program: {BIN}")
        return 1
    tests = [
        test_child_allow_and_sibling_prefix,
        test_default_allow_and_exact_root,
        test_deny_overrides_other_action,
        test_windows_and_dot_segments,
        test_single_decode_only,
        test_escape_beats_allow_all,
        test_time_window_is_inclusive,
        test_case_and_other_principal,
        test_malformed_documents,
    ]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Fail as exc:
            failed += 1
            print(f"FAIL {test.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
