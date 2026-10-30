#!/usr/bin/env python3
"""Public self-check. The scored run uses other sizes and other payloads."""

import os
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

BIN = os.environ.get("SEGLOG_PY", "/app/seglog.py")
HDR = 32
OVERHEAD = 17


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def meta_bytes(segment_bytes: int) -> bytes:
    head = b"SEGLOG1\x00" + (1).to_bytes(4, "little") + segment_bytes.to_bytes(4, "little")
    return head + crc32(head).to_bytes(4, "little") + (b"\x00" * 12)


def run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, BIN, *args], capture_output=True)


def main() -> int:
    if not Path(BIN).is_file():
        print("self-check 0/5")
        print(f"missing program: {BIN}", file=sys.stderr)
        return 1

    passed = 0
    total = 5
    scratch = Path(tempfile.mkdtemp(prefix="seglog-self-"))

    root = scratch / "layout"
    proc = run(["init", "--dir", str(root), "--segment-bytes", "4096"])
    meta = root / "meta"
    if proc.returncode == 0 and meta.is_file() and meta.read_bytes() == meta_bytes(4096):
        passed += 1
    else:
        print("layout case failed", file=sys.stderr)

    root = scratch / "round"
    payloads = [b"public-sample-one", b"", b"public-sample-two"]
    ok = run(["init", "--dir", str(root), "--segment-bytes", "4096"]).returncode == 0
    for index, payload in enumerate(payloads):
        src = scratch / f"round-{index}"
        src.write_bytes(payload)
        ok = ok and run(["append", "--dir", str(root), "--input", str(src)]).returncode == 0
    out = scratch / "round.bin"
    proc = run(["dump", "--dir", str(root), "--output", str(out)])
    if ok and proc.returncode == 0 and out.read_bytes() == b"".join(payloads):
        passed += 1
    else:
        print("round-trip case failed", file=sys.stderr)

    root = scratch / "roll"
    fill = b"R" * (4096 - HDR - OVERHEAD)
    tail = b"public-rollover"
    ok = run(["init", "--dir", str(root), "--segment-bytes", "4096"]).returncode == 0
    (scratch / "fill").write_bytes(fill)
    (scratch / "tail").write_bytes(tail)
    ok = ok and run(["append", "--dir", str(root), "--input", str(scratch / "fill")]).returncode == 0
    ok = ok and run(["append", "--dir", str(root), "--input", str(scratch / "tail")]).returncode == 0
    ok = ok and (root / "segments" / "000001.seg").is_file()
    out = scratch / "roll.bin"
    proc = run(["dump", "--dir", str(root), "--output", str(out)])
    if ok and proc.returncode == 0 and out.read_bytes() == fill + tail:
        passed += 1
    else:
        print("rollover case failed", file=sys.stderr)

    root = scratch / "torn"
    first, second = b"public-keep", b"public-drop"
    ok = run(["init", "--dir", str(root), "--segment-bytes", "4096"]).returncode == 0
    (scratch / "keep").write_bytes(first)
    (scratch / "drop").write_bytes(second)
    ok = ok and run(["append", "--dir", str(root), "--input", str(scratch / "keep")]).returncode == 0
    ok = ok and run(["append", "--dir", str(root), "--input", str(scratch / "drop")]).returncode == 0
    seg = root / "segments" / "000000.seg"
    if ok:
        seg.write_bytes(seg.read_bytes()[: HDR + 17 + len(first) + 6])
    out = scratch / "torn.bin"
    dumped = run(["dump", "--dir", str(root), "--output", str(out)])
    recovered = run(["recover", "--dir", str(root)])
    checked = run(["check", "--dir", str(root)])
    if (
        ok
        and dumped.returncode == 0
        and out.read_bytes() == first
        and recovered.returncode == 0
        and checked.returncode == 0
    ):
        passed += 1
    else:
        print("torn-tail case failed", file=sys.stderr)

    root = scratch / "big"
    ok = run(["init", "--dir", str(root), "--segment-bytes", "4096"]).returncode == 0
    blob = scratch / "big.bin"
    blob.write_bytes(b"B" * (4096 - HDR - OVERHEAD + 1))
    before = (root / "segments" / "000000.seg").read_bytes() if ok else b""
    proc = run(["append", "--dir", str(root), "--input", str(blob)])
    after = (root / "segments" / "000000.seg").read_bytes() if ok else b""
    if ok and proc.returncode == 3 and before == after:
        passed += 1
    else:
        print("oversize case failed", file=sys.stderr)

    print(f"self-check {passed}/{total}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
