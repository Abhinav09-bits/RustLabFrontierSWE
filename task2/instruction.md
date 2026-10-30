# Request authorization gate

Implement `/app/gatekeep.py`. Python 3.12 is already installed. The program decides whether one request is allowed by a written policy. A scored run uses other principals, other paths, and other clocks than the public self-check. Matching only the sample names in that file scores 0.

Run it as:

```text
python3 /app/gatekeep.py decide --policy POLICY --request REQUEST --time UNIX
```

`UNIX` is an integer number of seconds, zero or greater. Write nothing to stdout except the decision line. Write diagnostics to stderr.

## Results

| Exit | Stdout | When |
| --- | --- | --- |
| 0 | `allow` and a single newline | The request is allowed. |
| 1 | `deny` and a single newline | The request is denied, including a path that escapes the root. |
| 2 | empty | The policy, the request, or the clock is malformed. Do not print `allow` or `deny`. |

## Documents

Both files are UTF-8 JSON objects. A repeated key in one object is malformed. `true`, `false`, and numbers with a fraction are not integers.

The policy object has exactly two keys:

- `default`: `allow` or `deny`
- `rules`: an array, which may be empty

Each rule has exactly these keys, and may also include `not_before` and `not_after`:

- `id`: a name, unique in the file
- `effect`: `allow` or `deny`
- `principal`: a name, or `*`
- `action`: a name, or `*`
- `resource`: a pattern
- `not_before`: optional integer seconds, inclusive
- `not_after`: optional integer seconds, inclusive

A name is 1 to 64 characters from letters, digits, `.`, `_`, `~`, `@`, and `-`. `*` is only legal for a rule principal or a rule action. If both time bounds are present, `not_before` must be less than or equal to `not_after`. A negative bound is malformed.

A resource pattern is one of:

- `*`, which matches every normalized path, including `/`
- an absolute path such as `/records/2024`, with one or more segments
- that path plus a trailing `/*`, such as `/records/*`

Pattern segments use letters, digits, `.`, `_`, `~`, and `-`. They are not empty, `.`, or `..`. Patterns are already canonical: no percent-encoding, no backslash, no repeated slash, and no `*` inside a segment. Anything else in the policy is malformed.

The request object has exactly three keys:

- `principal`: a name, not `*`
- `action`: a name, not `*`
- `resource`: a string

## Normalization

Normalize only the request resource. Do this before any rule is considered.

1. A resource that does not start with `/` is malformed.
2. A raw `NUL` in the resource, or a `NUL` produced by decoding, denies the request.
3. Percent-decode a single pass. `%` must be followed by two hexadecimal digits, `0-9`, `a-f`, or `A-F`. A broken escape is malformed. Do not decode a second time, so `%252e%252e` becomes the characters `%2e%2e`, not `..`.
4. Replace every `\` with `/`. A decoded `%5c` or `%5C` is a backslash and therefore becomes a separator.
5. Split on `/`. Drop empty segments and `.` segments. For `..`, remove the previous segment. If there is no previous segment, the path has escaped the root: print `deny` and exit 1. Do not continue into the rules. A policy that allows `*` still denies an escaped path.
6. The normalized path is `/` when no segments remain, otherwise `/` plus the segments joined by `/`.

A trailing slash, a repeated slash, and a `.` segment disappear during this pass. `%2f` and `%2F` become `/` and then split segments. `/reports/%2e%2e/payroll` normalizes to `/payroll`.

## Matching and decision

A rule matches when every condition holds:

- the principal is `*` or equal to the request principal
- the action is `*` or equal to the request action
- the clock is inside the rule window, when a bound is present; both ends are inclusive
- the resource pattern matches the normalized path

`/records` matches only `/records`. `/records/*` matches `/records/a` and `/records/a/b`, and does not match `/records` or `/records-extra`. `/*` matches every normalized path except `/`. Comparison is case sensitive.

Collect every matching rule. A matching `deny` wins over every matching `allow`. If no deny matches and an allow matches, the decision is allow. If no rule matches, use `default`. Rule order does not matter.

The normalized path `/` has no segments. No exact pattern equals `/`. Only `*` matches it. `/*` does not.

## Self-check

`/app/self_check.py` is already in the workspace. Run:

```text
python3 /app/self_check.py
```

It prints `self-check P/T`. `P` counts the public cases that passed. The process exits 0 only when `P` equals `T`. Those cases cover an allowed child path, a default deny, a deny that overrides an allow, a `..` segment, and a single-decoded `%2f`. As more of the contract works, `P` rises.

The scored run repeats those behaviors with other names and adds windows, backslashes, a single decode that must not run twice, and malformed documents. A program that only recognizes the sample principal `casey` or the sample paths in the self-check can raise `P` and still score 0.
