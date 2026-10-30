# Crash-safe segmented log

Implement `/app/seglog.py`. The container already has Python 3.12. A verifier runs the program on logs it builds and on logs it damages, and checks exit codes, dumped bytes, and the exact on-disk layout. Match this contract. A program that only round-trips payloads through a private format will fail.

Run it as:

```text
python3 /app/seglog.py init --dir DIR --segment-bytes N
python3 /app/seglog.py append --dir DIR --input FILE
python3 /app/seglog.py recover --dir DIR
python3 /app/seglog.py dump --dir DIR --output FILE
python3 /app/seglog.py check --dir DIR
```

Write every diagnostic to stderr. Write nothing to stdout. `FILE` for append is one payload, read to the end, and may be empty or contain arbitrary bytes. `DIR` is the log directory. Create `DIR` only in `init`. Do not create missing parent directories.

## Exit codes

| Code | When |
| --- | --- |
| 0 | The command finished and the log was usable for that command. |
| 2 | Usage error, illegal size, missing input, or fatal corruption. Do not create or modify the log, and do not create the dump output. |
| 3 | `append` only. The payload cannot fit in an empty segment. Do not modify the log. |
| 4 | `check` found a repairable torn tail, or `append` was asked to write into a torn log. `append` must not modify the log. |

`dump` of a repairable log still exits 0 and writes the committed prefix. `recover` of a repairable log exits 0 after repairing it. `recover` of a clean log exits 0 and must leave every file byte identical.

## Sizes and directory

`--segment-bytes` must be a multiple of 256 in the closed range 4096 through 1048576. Any other integer is exit 2 and must not create `DIR`. `init` is exit 2 if `DIR` already exists.

A valid log directory contains only `meta` and a directory `segments`. `segments` contains only the contiguous files `000000.seg`, `000001.seg`, ... with six-digit decimal names. A missing name, an extra name, a gap, or any other entry at either level is fatal corruption (exit 2), and the command must not modify the log or create a dump output.

## Integers, checksums, headers

All integers are unsigned 32-bit little-endian. The checksum is `zlib.crc32` masked with `0xFFFFFFFF` (the ISO-HDLC polynomial), over the stated byte range only.

`meta` is exactly 32 bytes:

| Offset | Bytes | Contents |
| --- | --- | --- |
| 0 | 8 | `SEGLOG1` followed by a zero byte |
| 8 | 4 | version, which is 1 |
| 12 | 4 | segment size `N` |
| 16 | 4 | checksum of bytes 0 through 15 |
| 20 | 12 | zeros |

Each segment file is normally exactly `N` bytes. The first 32 bytes are the segment header:

| Offset | Bytes | Contents |
| --- | --- | --- |
| 0 | 8 | `SEGMNT1` followed by a zero byte |
| 8 | 4 | zero-based segment index |
| 12 | 4 | the same `N` stored in `meta` |
| 16 | 4 | checksum of bytes 0 through 15 |
| 20 | 12 | zeros |

`init` writes `meta` and one empty `segments/000000.seg` of exactly `N` bytes: a valid header for index 0, then zeros.

A header that is shorter than 32 bytes, longer than `N`, or fails any field above is fatal corruption. Leave those files unchanged.

## Records

Records are packed from offset 32 with no gaps. A record is:

| Offset | Bytes | Contents |
| --- | --- | --- |
| 0 | 4 | `REC1` |
| 4 | 4 | payload length |
| 8 | 4 | checksum of the payload |
| 12 | 4 | checksum of bytes 0 through 11 of this record |
| 16 | length | payload |
| 16 + length | 1 | commit byte `0xA5` |

The record size is `17 + payload length`. A committed record is one whose magic, both checksums, and commit byte are all valid and whose bytes lie entirely inside the file.

The committed prefix ends at the first problem. Do not skip a bad record to read a later one. The tail is clean when every byte from the end of the last committed record through the end of the file is `0x00` (or there are no bytes left because the records fill the segment exactly). Any other tail is torn. That includes a wrong commit byte, a bad checksum, a truncated record, a non-zero garbage byte, and a file shorter than `N` even if the bytes that remain are a clean prefix.

A segment whose file is exactly `N` bytes, whose header is valid, and whose tail is clean is perfect. The next segment may exist only when every earlier segment is perfect and its committed records fill it through offset `N`. A perfect segment that still has room, followed by another segment file, is fatal corruption. An empty perfect last segment is legal: it holds no payloads and is the open tail.

## Commands

`append` requires a clean log (every existing segment perfect, and only a full segment may be followed by another). Otherwise exit 4 for a torn tail, or 2 for fatal corruption.

If `17 + payload length` is greater than `N - 32`, exit 3 and do not modify the log. Otherwise append one record. If it fits in the free tail of the last segment, write it there. If it does not, create the next index as a new pre-sized segment and write the record at offset 32. Write the record in place, not by rewriting the whole file: first write every record byte with the commit byte still `0x00`, flush and `fsync` the file, then write `0xA5` over that commit byte, then flush and `fsync` again. After a successful append the segment bytes must equal the layout above.

`dump` walks the committed prefix, including the committed records of a torn segment, and stops there. It does not open later segment files after a tear. It concatenates those payloads into `OUTPUT` and leaves the log byte-identical. `OUTPUT` must be outside the log directory, and its parent must already exist.

`check` exits 0 on a clean log, 4 on a repairable torn tail, and 2 on fatal corruption. It does not modify the log.

`recover` on a clean log does nothing. On fatal corruption it does nothing and exits 2. On a repairable log it keeps the committed prefix and exits 0:

- Rewrite the damaged segment as a valid segment of exactly `N` bytes: header, the committed records in order, then zeros. If that segment's index is greater than 0 and it has no committed record, delete the file instead of leaving an empty segment.
- Delete every higher segment file.
- Never delete `000000.seg`. If it has no committed record, rewrite it as a valid empty segment of exactly `N` bytes.
- A second `recover` must leave the repaired files byte-identical.

Segment 0 is created by `init` and is the only segment that is allowed to exist while empty after `init`. Higher empty segments are deleted by `recover` only in the torn-tail case above. A clean empty last segment, with every earlier segment filled to `N`, is left in place.

## Self-check

`/app/self_check.py` is already in the workspace. Run:

```text
python3 /app/self_check.py
```

It prints one line, `self-check P/T`. `P` is how many public cases passed and `T` is how many it ran. The process exits 0 only when `P` equals `T`. The cases cover the layout, a round-trip, a segment rollover, torn-tail recovery, and the refusal of a payload that cannot fit. As more of the contract works, `P` rises.

The scored run applies the same rules to other segment sizes and other payloads, including damaged logs that this file does not build. A program that only recognizes the sample bytes inside `self_check.py` can raise `P` and still score 0. Implement the format.
