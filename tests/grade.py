#!/usr/bin/env python3
"""Hidden behavioral grader for the segmented log."""

import hashlib
import os
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

BIN = os.environ.get("SEGLOG_PY", "/app/seglog.py")
MAGIC_META = b"SEGLOG1\x00"
MAGIC_SEG = b"SEGMNT1\x00"
MAGIC_REC = b"REC1"
COMMIT = 0xA5
HDR = 32
OVERHEAD = 17


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def meta_bytes(segment_bytes: int) -> bytes:
    head = MAGIC_META + (1).to_bytes(4, "little") + segment_bytes.to_bytes(4, "little")
    return head + crc32(head).to_bytes(4, "little") + (b"\x00" * 12)


def segment_header(index: int, segment_bytes: int) -> bytes:
    head = MAGIC_SEG + index.to_bytes(4, "little") + segment_bytes.to_bytes(4, "little")
    return head + crc32(head).to_bytes(4, "little") + (b"\x00" * 12)


def record_bytes(payload: bytes) -> bytes:
    head = MAGIC_REC + len(payload).to_bytes(4, "little") + crc32(payload).to_bytes(4, "little")
    return head + crc32(head).to_bytes(4, "little") + payload + bytes([COMMIT])


def encode_segment(index: int, segment_bytes: int, payloads: list[bytes]) -> bytes:
    buf = bytearray(segment_header(index, segment_bytes))
    for payload in payloads:
        buf += record_bytes(payload)
    buf += b"\x00" * (segment_bytes - len(buf))
    return bytes(buf)


def run(args: list[str]) -> subprocess.CompletedProcess:
    # Scored runs execute the program as the unprivileged agent so it cannot
    # read root-only files or rewrite the reward.
    user = os.environ.get("SEGLOG_AS_USER", "")
    cmd = [sys.executable, BIN, *args]
    if user:
        cmd = ["runuser", "-u", user, "--", *cmd]
    return subprocess.run(cmd, capture_output=True)


def fresh() -> Path:
    path = Path(tempfile.mkdtemp(prefix="seglog-grade-"))
    # The program under test runs as the unprivileged agent, so it must be
    # able to create logs in this directory.
    if os.environ.get("SEGLOG_AS_USER"):
        os.chmod(path, 0o777)
    return path


def snapshot(root: Path) -> dict[str, str]:
    out = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def write_payload(scratch: Path, name: str, payload: bytes) -> Path:
    path = scratch / name
    path.write_bytes(payload)
    return path


class Fail(Exception):
    pass


def expect(cond: bool, message: str) -> None:
    if not cond:
        raise Fail(message)


def init_log(root: Path, segment_bytes: int = 4096) -> subprocess.CompletedProcess:
    return run(["init", "--dir", str(root), "--segment-bytes", str(segment_bytes)])


def test_init_layout() -> None:
    scratch = fresh()
    root = scratch / "log"
    proc = init_log(root, 4096)
    expect(proc.returncode == 0, f"init failed: {proc.stderr!r}")
    expect((root / "meta").read_bytes() == meta_bytes(4096), "meta bytes mismatch")
    expect(
        (root / "segments" / "000000.seg").read_bytes() == encode_segment(0, 4096, []),
        "empty segment mismatch",
    )
    expect(run(["check", "--dir", str(root)]).returncode == 0, "fresh log did not check clean")


def test_roundtrip_and_exact_records() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    payloads = [b"alpha", b"", b"REC1\x00\xa5", os.urandom(50)]
    for i, payload in enumerate(payloads):
        src = write_payload(scratch, f"p{i}", payload)
        proc = run(["append", "--dir", str(root), "--input", str(src)])
        expect(proc.returncode == 0, f"append {i} failed: {proc.stderr!r}")
    expect(
        (root / "segments" / "000000.seg").read_bytes() == encode_segment(0, 4096, payloads),
        "segment bytes do not match the specified record layout",
    )
    out = scratch / "out.bin"
    proc = run(["dump", "--dir", str(root), "--output", str(out)])
    expect(proc.returncode == 0, f"dump failed: {proc.stderr!r}")
    expect(out.read_bytes() == b"".join(payloads), "dump payload mismatch")


def test_recover_clean_is_noop() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    src = write_payload(scratch, "p", b"stable")
    expect(run(["append", "--dir", str(root), "--input", str(src)]).returncode == 0, "append failed")
    before = snapshot(root)
    expect(run(["recover", "--dir", str(root)]).returncode == 0, "recover failed")
    expect(snapshot(root) == before, "recover changed a clean log")
    expect(run(["check", "--dir", str(root)]).returncode == 0, "check failed after noop recover")


def test_exact_fill_rollover() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root, 4096).returncode == 0, "init failed")
    first = b"A" * (4096 - HDR - OVERHEAD)
    second = b"tail"
    expect(
        run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "a", first))]).returncode == 0,
        "filling append failed",
    )
    expect(
        (root / "segments" / "000000.seg").read_bytes() == encode_segment(0, 4096, [first]),
        "full segment mismatch",
    )
    expect(
        run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "b", second))]).returncode == 0,
        "rollover append failed",
    )
    expect((root / "segments" / "000001.seg").is_file(), "second segment was not created")
    expect(
        (root / "segments" / "000001.seg").read_bytes() == encode_segment(1, 4096, [second]),
        "rolled segment mismatch",
    )
    out = scratch / "out.bin"
    expect(run(["dump", "--dir", str(root), "--output", str(out)]).returncode == 0, "dump failed")
    expect(out.read_bytes() == first + second, "rollover dump mismatch")


def test_truncate_second_record() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    first, second = b"alpha", b"beta-record"
    run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "a", first))])
    run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "b", second))])
    seg = root / "segments" / "000000.seg"
    cut = HDR + len(record_bytes(first)) + 8
    seg.write_bytes(seg.read_bytes()[:cut])
    expect(run(["check", "--dir", str(root)]).returncode == 4, "torn log was not reported")
    before = snapshot(root)
    out = scratch / "out.bin"
    expect(run(["dump", "--dir", str(root), "--output", str(out)]).returncode == 0, "dump of torn log failed")
    expect(out.read_bytes() == first, "dump kept a torn record")
    expect(snapshot(root) == before, "dump modified a torn log")
    expect(run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "c", b"x"))]).returncode == 4, "append should refuse a torn log")
    expect(snapshot(root) == before, "refused append modified the log")
    expect(run(["recover", "--dir", str(root)]).returncode == 0, "recover failed")
    expect(seg.read_bytes() == encode_segment(0, 4096, [first]), "recovered segment mismatch")
    expect(run(["check", "--dir", str(root)]).returncode == 0, "recovered log is not clean")
    expect(run(["recover", "--dir", str(root)]).returncode == 0, "second recover failed")
    expect(seg.read_bytes() == encode_segment(0, 4096, [first]), "second recover changed the segment")
    expect(
        run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "d", b"after"))]).returncode == 0,
        "append after recover failed",
    )
    expect(run(["dump", "--dir", str(root), "--output", str(scratch / "out2.bin")]).returncode == 0, "final dump failed")
    expect((scratch / "out2.bin").read_bytes() == first + b"after", "append after recover lost data")


def test_zero_commit_and_crc_damage() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    first, second = b"one", b"two"
    run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "a", first))])
    run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "b", second))])
    seg = root / "segments" / "000000.seg"
    start = HDR + len(record_bytes(first))
    blob = bytearray(seg.read_bytes())
    blob[start + len(record_bytes(second)) - 1] = 0
    seg.write_bytes(blob)
    out = scratch / "out.bin"
    expect(run(["dump", "--dir", str(root), "--output", str(out)]).returncode == 0, "dump failed")
    expect(out.read_bytes() == first, "uncommitted record was returned")

    scratch2 = fresh()
    root2 = scratch2 / "log"
    expect(init_log(root2).returncode == 0, "init failed")
    run(["append", "--dir", str(root2), "--input", str(write_payload(scratch2, "a", first))])
    run(["append", "--dir", str(root2), "--input", str(write_payload(scratch2, "b", second))])
    seg2 = root2 / "segments" / "000000.seg"
    blob = bytearray(seg2.read_bytes())
    blob[start + 16] ^= 0x01
    seg2.write_bytes(blob)
    expect(run(["dump", "--dir", str(root2), "--output", str(scratch2 / "out.bin")]).returncode == 0, "dump failed")
    expect((scratch2 / "out.bin").read_bytes() == first, "payload with a bad crc was returned")

    blob = bytearray(encode_segment(0, 4096, [first, second]))
    blob[start + 12] ^= 0x01
    seg2.write_bytes(blob)
    expect(run(["dump", "--dir", str(root2), "--output", str(scratch2 / "out2.bin")]).returncode == 0, "dump failed")
    expect((scratch2 / "out2.bin").read_bytes() == first, "record with a bad header crc was returned")


def test_does_not_skip_damaged_record() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    first, second = b"keep-me-out", b"should-not-survive"
    run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "a", first))])
    run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "b", second))])
    seg = root / "segments" / "000000.seg"
    blob = bytearray(seg.read_bytes())
    blob[HDR + 16] ^= 0xFF
    seg.write_bytes(blob)
    out = scratch / "out.bin"
    expect(run(["dump", "--dir", str(root), "--output", str(out)]).returncode == 0, "dump failed")
    expect(out.read_bytes() == b"", "a later valid record was read past a damaged one")
    expect(run(["recover", "--dir", str(root)]).returncode == 0, "recover failed")
    expect(seg.read_bytes() == encode_segment(0, 4096, []), "recover kept records after the damaged prefix")


def test_garbage_tail_and_orphan_segment() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    payload = b"good"
    run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "a", payload))])
    seg = root / "segments" / "000000.seg"
    blob = bytearray(seg.read_bytes())
    blob[HDR + len(record_bytes(payload)) : HDR + len(record_bytes(payload)) + 4] = b"XXXX"
    seg.write_bytes(blob)
    orphan = root / "segments" / "000001.seg"
    orphan.write_bytes(encode_segment(1, 4096, [b"orphan"]))
    out = scratch / "out.bin"
    expect(run(["dump", "--dir", str(root), "--output", str(out)]).returncode == 0, "dump failed")
    expect(out.read_bytes() == payload, "garbage tail or orphan segment leaked into the dump")
    expect(run(["recover", "--dir", str(root)]).returncode == 0, "recover failed")
    expect(not orphan.exists(), "recover left a segment after the torn tail")
    expect(seg.read_bytes() == encode_segment(0, 4096, [payload]), "recovered prefix mismatch")


def test_delete_empty_torn_later_segment() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    payload = b"A" * (4096 - HDR - OVERHEAD)
    expect(
        run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "a", payload))]).returncode == 0,
        "fill failed",
    )
    second = root / "segments" / "000001.seg"
    torn = bytearray(encode_segment(1, 4096, []))
    torn[HDR : HDR + 10] = b"REC1XXXXXX"
    second.write_bytes(torn)
    expect(run(["check", "--dir", str(root)]).returncode == 4, "torn later segment was not repairable")
    expect(run(["recover", "--dir", str(root)]).returncode == 0, "recover failed")
    expect(not second.exists(), "empty torn later segment was kept")
    expect(run(["check", "--dir", str(root)]).returncode == 0, "log not clean after deleting the torn segment")
    out = scratch / "out.bin"
    expect(run(["dump", "--dir", str(root), "--output", str(out)]).returncode == 0, "dump failed")
    expect(out.read_bytes() == payload, "prefix payload was lost")


def test_payload_too_big_is_noop() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    src = write_payload(scratch, "big", b"B" * (4096 - HDR - OVERHEAD + 1))
    before = snapshot(root)
    proc = run(["append", "--dir", str(root), "--input", str(src)])
    expect(proc.returncode == 3, f"oversized payload returned {proc.returncode}")
    expect(snapshot(root) == before, "oversized append modified the log")


def test_fatal_corruption_is_untouched() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    src = write_payload(scratch, "p", b"data")
    expect(run(["append", "--dir", str(root), "--input", str(src)]).returncode == 0, "append failed")
    meta = root / "meta"
    blob = bytearray(meta.read_bytes())
    blob[-1] ^= 0x01
    meta.write_bytes(blob)
    before = snapshot(root)
    for args in (
        ["check", "--dir", str(root)],
        ["dump", "--dir", str(root), "--output", str(scratch / "out.bin")],
        ["recover", "--dir", str(root)],
        ["append", "--dir", str(root), "--input", str(src)],
    ):
        proc = run(args)
        expect(proc.returncode == 2, f"{args[0]} returned {proc.returncode} on a bad meta crc")
        expect(snapshot(root) == before, f"{args[0]} modified a fatally corrupt log")
    expect(not (scratch / "out.bin").exists(), "dump created an output after fatal corruption")

    seg = root / "segments" / "000000.seg"
    # Restore a readable meta, then destroy the segment header.
    meta.write_bytes(meta_bytes(4096))
    seg.write_bytes(b"\x00" * 10)
    before = snapshot(root)
    proc = run(["recover", "--dir", str(root)])
    expect(proc.returncode == 2, f"short header returned {proc.returncode}")
    expect(snapshot(root) == before, "recover modified a segment with a destroyed header")


def test_illegal_layouts() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    (root / "segments" / "000001.seg").write_bytes(encode_segment(1, 4096, [b"x"]))
    before = snapshot(root)
    proc = run(["check", "--dir", str(root)])
    expect(proc.returncode == 2, f"gap-free extra segment returned {proc.returncode}")
    expect(snapshot(root) == before, "check modified an illegal layout")
    expect(run(["recover", "--dir", str(root)]).returncode == 2, "recover rewrote an illegal layout")
    expect(snapshot(root) == before, "recover modified an illegal layout")

    (root / "segments" / "000001.seg").unlink()
    (root / "segments" / "000002.seg").write_bytes(encode_segment(2, 4096, []))
    before = snapshot(root)
    expect(run(["dump", "--dir", str(root), "--output", str(scratch / "nope")]).returncode == 2, "gap was accepted")
    expect(snapshot(root) == before, "dump modified a gapped log")
    expect(not (scratch / "nope").exists(), "dump wrote output for a gapped log")


def test_init_rejects_bad_arguments() -> None:
    scratch = fresh()
    for size in (0, 4095, 3840, 1048832, 4096 + 128):
        root = scratch / f"bad-{size}"
        proc = run(["init", "--dir", str(root), "--segment-bytes", str(size)])
        expect(proc.returncode == 2, f"size {size} returned {proc.returncode}")
        expect(not root.exists(), f"size {size} created a directory")
    root = scratch / "ok"
    expect(init_log(root, 4352).returncode == 0, "4352 should be a legal segment size")
    expect(init_log(root, 4352).returncode == 2, "second init should fail")
    missing_parent = scratch / "missing" / "log"
    proc = run(["init", "--dir", str(missing_parent), "--segment-bytes", "4096"])
    expect(proc.returncode == 2, "init with a missing parent should fail")
    expect(not missing_parent.exists(), "init created a missing parent")


def test_short_zero_tail_is_padded() -> None:
    scratch = fresh()
    root = scratch / "log"
    expect(init_log(root).returncode == 0, "init failed")
    payload = b"pad-me"
    expect(run(["append", "--dir", str(root), "--input", str(write_payload(scratch, "a", payload))]).returncode == 0, "append failed")
    seg = root / "segments" / "000000.seg"
    full = seg.read_bytes()
    seg.write_bytes(full[: HDR + len(record_bytes(payload)) + 20])
    expect(run(["check", "--dir", str(root)]).returncode == 4, "short segment was treated as clean")
    expect(run(["dump", "--dir", str(root), "--output", str(scratch / "out.bin")]).returncode == 0, "dump failed")
    expect((scratch / "out.bin").read_bytes() == payload, "short tail dropped a committed record")
    expect(run(["recover", "--dir", str(root)]).returncode == 0, "recover failed")
    expect(seg.read_bytes() == encode_segment(0, 4096, [payload]), "short segment was not padded back to capacity")


def main() -> int:
    if not Path(BIN).is_file():
        print(f"missing program: {BIN}")
        return 1
    tests = [
        test_init_layout,
        test_roundtrip_and_exact_records,
        test_recover_clean_is_noop,
        test_exact_fill_rollover,
        test_truncate_second_record,
        test_zero_commit_and_crc_damage,
        test_does_not_skip_damaged_record,
        test_garbage_tail_and_orphan_segment,
        test_delete_empty_torn_later_segment,
        test_payload_too_big_is_noop,
        test_fatal_corruption_is_untouched,
        test_illegal_layouts,
        test_init_rejects_bad_arguments,
        test_short_zero_tail_is_padded,
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
