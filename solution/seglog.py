#!/usr/bin/env python3
"""Crash-safe segmented append-only log."""

import argparse
import os
import sys
import zlib
from pathlib import Path

MAGIC_META = b"SEGLOG1\x00"
MAGIC_SEG = b"SEGMNT1\x00"
MAGIC_REC = b"REC1"
COMMIT = 0xA5
HDR = 32
OVERHEAD = 17
MIN_SEGMENT = 4096
MAX_SEGMENT = 1048576
SEGMENT_STEP = 256


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def die(code: int, message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def valid_segment_bytes(n: int) -> bool:
    return MIN_SEGMENT <= n <= MAX_SEGMENT and n % SEGMENT_STEP == 0


def fsync_dir(path: Path) -> None:
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    fsync_dir(path.parent)


def meta_bytes(segment_bytes: int) -> bytes:
    head = MAGIC_META + (1).to_bytes(4, "little") + segment_bytes.to_bytes(4, "little")
    return head + crc32(head).to_bytes(4, "little") + (b"\x00" * 12)


def segment_header(index: int, segment_bytes: int) -> bytes:
    head = MAGIC_SEG + index.to_bytes(4, "little") + segment_bytes.to_bytes(4, "little")
    return head + crc32(head).to_bytes(4, "little") + (b"\x00" * 12)


def record_bytes(payload: bytes) -> bytes:
    head = MAGIC_REC + len(payload).to_bytes(4, "little") + crc32(payload).to_bytes(4, "little")
    return head + crc32(head).to_bytes(4, "little") + payload + bytes([COMMIT])


def header_ok(header: bytes, index: int, segment_bytes: int) -> bool:
    if len(header) < HDR:
        return False
    if header[0:8] != MAGIC_SEG:
        return False
    if int.from_bytes(header[8:12], "little") != index:
        return False
    if int.from_bytes(header[12:16], "little") != segment_bytes:
        return False
    if int.from_bytes(header[16:20], "little") != crc32(header[0:16]):
        return False
    return header[20:32] == b"\x00" * 12


def parse_records(data: bytes):
    off = HDR
    payloads = []
    while off < len(data):
        tail = data[off:]
        if tail == b"\x00" * len(tail):
            return payloads, off, "clean"
        if len(tail) < OVERHEAD or tail[0:4] != MAGIC_REC:
            return payloads, off, "torn"
        plen = int.from_bytes(tail[4:8], "little")
        pcrc = int.from_bytes(tail[8:12], "little")
        hcrc = int.from_bytes(tail[12:16], "little")
        if hcrc != crc32(tail[0:12]) or 16 + plen + 1 > len(tail):
            return payloads, off, "torn"
        payload = tail[16 : 16 + plen]
        if pcrc != crc32(payload) or tail[16 + plen] != COMMIT:
            return payloads, off, "torn"
        payloads.append(payload)
        off += OVERHEAD + plen
    return payloads, off, "clean"


def encode_segment(index: int, segment_bytes: int, payloads: list[bytes]) -> bytes:
    buf = bytearray(segment_header(index, segment_bytes))
    for payload in payloads:
        buf += record_bytes(payload)
    if len(buf) > segment_bytes:
        die(2, "segment overflow")
    buf += b"\x00" * (segment_bytes - len(buf))
    return bytes(buf)


class SegInfo:
    def __init__(self, path: Path, index: int, payloads: list[bytes], end: int, kind: str):
        self.path = path
        self.index = index
        self.payloads = payloads
        self.end = end
        self.kind = kind


class Report:
    def __init__(self):
        self.segment_bytes = 0
        self.infos: list[SegInfo] = []
        self.paths: list[Path] = []
        self.state = "fatal"


def load_meta(root: Path):
    meta = root / "meta"
    if not root.is_dir() or not meta.is_file():
        return None
    if {child.name for child in root.iterdir()} != {"meta", "segments"}:
        return None
    blob = meta.read_bytes()
    if len(blob) != 32 or blob[0:8] != MAGIC_META:
        return None
    if int.from_bytes(blob[8:12], "little") != 1:
        return None
    segment_bytes = int.from_bytes(blob[12:16], "little")
    if int.from_bytes(blob[16:20], "little") != crc32(blob[0:16]):
        return None
    if blob[20:32] != b"\x00" * 12 or not valid_segment_bytes(segment_bytes):
        return None
    return segment_bytes


def list_segments(root: Path):
    seg_dir = root / "segments"
    if not seg_dir.is_dir():
        return None
    names = [child.name for child in seg_dir.iterdir()]
    paths = []
    index = 0
    while f"{index:06d}.seg" in names:
        paths.append(seg_dir / f"{index:06d}.seg")
        index += 1
    expected = {f"{index:06d}.seg" for index in range(len(paths))}
    if not paths or set(names) != expected:
        return None
    return paths


def inspect(root: Path) -> Report:
    report = Report()
    segment_bytes = load_meta(root)
    paths = None if segment_bytes is None else list_segments(root)
    if segment_bytes is None or paths is None:
        return report
    report.segment_bytes = segment_bytes
    report.paths = paths
    report.state = "clean"
    for index, path in enumerate(paths):
        data = path.read_bytes()
        if len(data) < HDR or len(data) > segment_bytes or not header_ok(data[:HDR], index, segment_bytes):
            report.state = "fatal"
            report.infos = []
            return report
        payloads, end, status = parse_records(data)
        kind = "perfect" if status == "clean" and len(data) == segment_bytes else "repairable"
        report.infos.append(SegInfo(path, index, payloads, end, kind))
        if kind == "repairable":
            report.state = "repairable"
            return report
        if end < segment_bytes and index != len(paths) - 1:
            report.state = "fatal"
            report.infos = []
            return report
    return report


def cmd_init(root: Path, segment_bytes: int) -> None:
    if not valid_segment_bytes(segment_bytes):
        die(2, "segment size must be a multiple of 256 from 4096 through 1048576")
    if root.exists():
        die(2, "log directory already exists")
    if not root.parent.is_dir():
        die(2, "parent directory does not exist")
    root.mkdir()
    atomic_write(root / "meta", meta_bytes(segment_bytes))
    atomic_write(root / "segments" / "000000.seg", encode_segment(0, segment_bytes, []))


def cmd_check(root: Path) -> None:
    report = inspect(root)
    if report.state == "fatal":
        die(2, "log is corrupt")
    if report.state == "repairable":
        die(4, "log has a torn tail")


def cmd_dump(root: Path, output: Path) -> None:
    report = inspect(root)
    if report.state == "fatal":
        die(2, "log is corrupt")
    if not output.parent.is_dir():
        die(2, "output directory does not exist")
    try:
        if root.resolve() == output.resolve() or root.resolve() in output.resolve().parents:
            die(2, "output path is inside the log")
    except OSError:
        die(2, "output path is invalid")
    blob = b"".join(payload for info in report.infos for payload in info.payloads)
    atomic_write(output, blob)


def cmd_recover(root: Path) -> None:
    report = inspect(root)
    if report.state == "fatal":
        die(2, "log is corrupt")
    if report.state == "clean":
        return
    damaged = report.infos[-1]
    if damaged.index > 0 and not damaged.payloads:
        damaged.path.unlink()
    else:
        atomic_write(
            damaged.path,
            encode_segment(damaged.index, report.segment_bytes, damaged.payloads),
        )
    for path in report.paths[damaged.index + 1 :]:
        path.unlink()
    fsync_dir(root / "segments")


def cmd_append(root: Path, payload: bytes) -> None:
    report = inspect(root)
    if report.state == "fatal":
        die(2, "log is corrupt")
    if report.state == "repairable":
        die(4, "log has a torn tail; recover it before appending")
    rec = record_bytes(payload)
    if len(rec) > report.segment_bytes - HDR:
        die(3, "payload does not fit in an empty segment")
    last = report.infos[-1]
    if last.end + len(rec) <= report.segment_bytes:
        punch(last.path, last.end, payload)
        return
    new_index = last.index + 1
    new_path = root / "segments" / f"{new_index:06d}.seg"
    atomic_write(new_path, encode_segment(new_index, report.segment_bytes, []))
    punch(new_path, HDR, payload)


def punch(path: Path, offset: int, payload: bytes) -> None:
    rec = bytearray(record_bytes(payload))
    rec[-1] = 0
    with open(path, "r+b") as fh:
        fh.seek(offset)
        fh.write(rec)
        fh.flush()
        os.fsync(fh.fileno())
        fh.seek(offset + len(rec) - 1)
        fh.write(bytes([COMMIT]))
        fh.flush()
        os.fsync(fh.fileno())


def main() -> None:
    parser = argparse.ArgumentParser(prog="seglog")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init")
    init.add_argument("--dir", required=True)
    init.add_argument("--segment-bytes", required=True, type=int)

    append = sub.add_parser("append")
    append.add_argument("--dir", required=True)
    append.add_argument("--input", required=True)

    recover = sub.add_parser("recover")
    recover.add_argument("--dir", required=True)

    dump = sub.add_parser("dump")
    dump.add_argument("--dir", required=True)
    dump.add_argument("--output", required=True)

    check = sub.add_parser("check")
    check.add_argument("--dir", required=True)

    args = parser.parse_args()
    root = Path(args.dir)
    if args.cmd == "init":
        cmd_init(root, args.segment_bytes)
    elif args.cmd == "append":
        src = Path(args.input)
        if not src.is_file():
            die(2, "input file does not exist")
        cmd_append(root, src.read_bytes())
    elif args.cmd == "recover":
        cmd_recover(root)
    elif args.cmd == "dump":
        cmd_dump(root, Path(args.output))
    elif args.cmd == "check":
        cmd_check(root)


if __name__ == "__main__":
    main()
