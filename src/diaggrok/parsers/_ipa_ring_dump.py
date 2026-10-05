# diaggrok-provenance: re
"""Shared decode for the IPA ring-dump records 0x1851 / 0x1852.

Both codes use one layout. The per-code files (`diag_0x1851.py`,
`diag_0x1852.py`) hold the evidence; this module holds only the byte grammar.

Every record is 1036 bytes: a 12-byte header, then a 1024-byte copy of the
start of a ring buffer::

    off  size  field         notes
      0   u8   version       {1,2,3}
      1   u32  dump_tick     same clock value as the other records of the dump
                             (0x184F, 0x1850, 0x1962, 0x1C6E/6F/71), never
                             more than one tick apart
      5   3B   (zero)        in every sampled record
      8   u16  ring_size     32 in every record. The ring's slot count, not a
                             byte stride (see below)
     10   u16  write_index   next slot the ring will write; always < ring_size
     12  1024  ring window   ring entries from slot 0

The entry stride is 32 bytes on every build except the SDX72 0x1851 ring,
which uses 80 bytes. The header still says 32 there. With 80-byte entries the
1024-byte window holds only slots 0-12, while write_index climbs to 23. So
the stride is detected from the body, not read from the header.

32-byte entry, v2/v3 (v1 differs, see below)::

      0  u16  flags       bit0 set on every populated entry
      2  u8   attr        offset-named. attr == 0 exactly when length == 0,
                          with no exceptions in the sample
      3  u8   kind        small enum, offset-named
      4  u16  length      byte-count-shaped
      6  u8   stream_id   entries with the same stream_id have seq values
                          that step by +1 (mod 256) in ring order, apart
                          from a few entry flavours (see the per-code file)
     24  u8   seq         per-stream sequence number
     25  u24  timestamp   CANDIDATE. Non-decreasing modulo 2^24 in ring
                          order on every sampled record. Its clock is not
                          settled: on most rings the newest entry lags
                          dump_tick by tens to hundreds of ticks, but the
                          LV55 0x1852 ring wraps 2^24 twice in 16 entries,
                          which the dump_tick clock cannot do

v1 (MDM9x30) keeps the same kind/length/stream_id offsets. It has no seq.
Its timestamp is a u32 at +20. In the sampled 0x1851 v1 records the newest
entry is exactly one tick before dump_tick.
"""
from __future__ import annotations

from struct import unpack_from
from typing import Any

SIZE = 1036
HEADER = 12
VERSIONS = (1, 2, 3)
_STRIDES = (32, 80)


def _stride_fits(body: bytes, stride: int) -> bool:
    """True when every non-empty ``stride``-sized chunk starts with flags bit0."""
    for off in range(0, len(body), stride):
        chunk = body[off:off + stride]
        if not any(chunk):
            continue
        if len(chunk) < 32 or not chunk[0] & 1:
            return False
    return True


def entry_stride(version: int, body: bytes) -> int | None:
    """Byte stride of the ring entries, or None when no known stride fits."""
    if version == 1:
        return 32
    for stride in _STRIDES:
        if _stride_fits(body, stride):
            return stride
    return None


def _entry(version: int, slot: int, chunk: bytes) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "slot": slot,
        "attr": chunk[2],
        "kind": chunk[3],
        "length": unpack_from("<H", chunk, 4)[0],
        "stream_id": chunk[6],
    }
    if version == 1:
        entry["timestamp"] = unpack_from("<I", chunk, 20)[0]
    else:
        word = unpack_from("<I", chunk, 24)[0]
        entry["flags"] = unpack_from("<H", chunk, 0)[0]
        entry["seq"] = word & 0xFF
        entry["timestamp"] = word >> 8
    entry["raw"] = bytes(chunk)
    return entry


def decode(data: bytes) -> dict[str, Any] | None:
    """Decode one 0x1851/0x1852 payload. None when the size or version gate fails."""
    if len(data) != SIZE:
        return None
    version = data[0]
    if version not in VERSIONS:
        return None
    dump_tick = unpack_from("<I", data, 1)[0]
    ring_size, write_index = unpack_from("<HH", data, 8)
    body = data[HEADER:]
    stride = entry_stride(version, body)
    entries: list[dict[str, Any]] = []
    if stride is not None:
        for slot, off in enumerate(range(0, len(body), stride)):
            chunk = body[off:off + stride]
            if len(chunk) >= 32 and any(chunk):
                entries.append(_entry(version, slot, chunk))
    return {
        "version": version,
        "dump_tick": dump_tick,
        "ring_size": ring_size,
        "write_index": write_index,
        "entry_stride": stride,
        "entries": entries,
        "body_raw": bytes(body),
    }
