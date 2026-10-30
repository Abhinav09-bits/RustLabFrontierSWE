#!/usr/bin/env python3
"""Request authorization gate."""

import argparse
import json
import sys
from pathlib import Path

HEX = set("0123456789abcdefABCDEF")
NAME = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~@-")
SEG = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-")
RULE_KEYS = {"id", "effect", "principal", "action", "resource", "not_before", "not_after"}
REQUIRED_RULE_KEYS = {"id", "effect", "principal", "action", "resource"}


def bad(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def finish(decision: str) -> None:
    sys.stdout.write(decision + "\n")
    raise SystemExit(0 if decision == "allow" else 1)


def is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def load_json(path: Path):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        bad(f"cannot read {path}")

    def pairs(items):
        keys = [key for key, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)

    try:
        return json.loads(text, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        bad("invalid json")


def name_ok(value, allow_star: bool) -> bool:
    if not isinstance(value, str) or not value or len(value) > 64:
        return False
    if value == "*":
        return allow_star
    return all(ch in NAME for ch in value)


def pattern_ok(pattern: str) -> bool:
    if pattern in {"*", "/*"}:
        return True
    body = pattern[:-2] if pattern.endswith("/*") else pattern
    if not body.startswith("/") or "//" in body:
        return False
    parts = body.split("/")[1:]
    if not parts:
        return False
    for part in parts:
        if not part or part in {".", ".."} or any(ch not in SEG for ch in part):
            return False
    return True


def percent_decode_once(value: str) -> str:
    out = []
    index = 0
    while index < len(value):
        if value[index] != "%":
            out.append(value[index])
            index += 1
            continue
        chunk = value[index + 1 : index + 3]
        if len(chunk) != 2 or any(ch not in HEX for ch in chunk):
            raise ValueError("bad percent")
        out.append(chr(int(chunk, 16)))
        index += 3
    return "".join(out)


def normalize(resource: str):
    if not isinstance(resource, str) or "\x00" in resource:
        return None, "bad" if not isinstance(resource, str) else "deny"
    if not resource.startswith("/"):
        return None, "bad"
    try:
        decoded = percent_decode_once(resource)
    except ValueError:
        return None, "bad"
    if "\x00" in decoded:
        return None, "deny"
    decoded = decoded.replace("\\", "/")
    stack = []
    for part in decoded.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                return None, "deny"
            stack.pop()
            continue
        stack.append(part)
    if not stack:
        return "/", "ok"
    return "/" + "/".join(stack), "ok"


def resource_matches(pattern: str, path: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("/*"):
        base = pattern[:-2]
        return path.startswith(base + "/") and path != base + "/"
    return pattern == path


def load_policy(path: Path) -> dict:
    data = load_json(path)
    if not isinstance(data, dict) or set(data) != {"default", "rules"}:
        bad("policy shape")
    if data["default"] not in {"allow", "deny"}:
        bad("policy default")
    rules = data["rules"]
    if not isinstance(rules, list):
        bad("policy rules")
    seen = set()
    clean = []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - RULE_KEYS or not REQUIRED_RULE_KEYS <= set(rule):
            bad("rule shape")
        if not name_ok(rule["id"], allow_star=False) or rule["id"] in seen:
            bad("rule id")
        seen.add(rule["id"])
        if rule["effect"] not in {"allow", "deny"}:
            bad("rule effect")
        if not name_ok(rule["principal"], allow_star=True) or not name_ok(rule["action"], allow_star=True):
            bad("rule subject")
        if not isinstance(rule["resource"], str) or not pattern_ok(rule["resource"]):
            bad("rule resource")
        window = {}
        for key in ("not_before", "not_after"):
            if key in rule:
                if not is_int(rule[key]) or rule[key] < 0:
                    bad("rule window")
                window[key] = rule[key]
        if "not_before" in window and "not_after" in window and window["not_before"] > window["not_after"]:
            bad("rule window order")
        clean.append({**rule, **window})
    return {"default": data["default"], "rules": clean}


def load_request(path: Path) -> dict:
    data = load_json(path)
    if not isinstance(data, dict) or set(data) != {"principal", "action", "resource"}:
        bad("request shape")
    if not name_ok(data["principal"], allow_star=False) or not name_ok(data["action"], allow_star=False):
        bad("request subject")
    path_value, status = normalize(data["resource"])
    return {"principal": data["principal"], "action": data["action"], "path": path_value, "status": status}


def rule_matches(rule: dict, request: dict, when: int) -> bool:
    if rule["principal"] not in {"*", request["principal"]}:
        return False
    if rule["action"] not in {"*", request["action"]}:
        return False
    if "not_before" in rule and when < rule["not_before"]:
        return False
    if "not_after" in rule and when > rule["not_after"]:
        return False
    return resource_matches(rule["resource"], request["path"])


def decide(policy: dict, request: dict, when: int) -> None:
    if request["status"] == "deny":
        finish("deny")
    if request["status"] != "ok":
        bad("request resource")
    matched = [rule for rule in policy["rules"] if rule_matches(rule, request, when)]
    if any(rule["effect"] == "deny" for rule in matched):
        finish("deny")
    if any(rule["effect"] == "allow" for rule in matched):
        finish("allow")
    finish(policy["default"])


def main() -> None:
    parser = argparse.ArgumentParser(prog="gatekeep")
    sub = parser.add_subparsers(dest="cmd", required=True)
    decide_cmd = sub.add_parser("decide")
    decide_cmd.add_argument("--policy", required=True)
    decide_cmd.add_argument("--request", required=True)
    decide_cmd.add_argument("--time", required=True, type=int)
    args = parser.parse_args()
    if args.time < 0:
        bad("time")
    policy_path = Path(args.policy)
    request_path = Path(args.request)
    if not policy_path.is_file() or not request_path.is_file():
        bad("missing input")
    decide(load_policy(policy_path), load_request(request_path), args.time)


if __name__ == "__main__":
    main()
