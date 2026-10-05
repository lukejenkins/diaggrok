# diaggrok-provenance: re
"""Shared TLV-style decoder for v=0x00 records of 0xB8C5 / 0xB8CB.

A walk of Quectel RM520N-GL / SDX62 captures found 1485 v=0x00 records
across both codes (818 on 0xB8C5, 667 on 0xB8CB). The
v=0x00 layout is NOT a per-code variant — it's a single TLV format
emitted by both codes. The 24-byte records of both codes are
byte-identical except for the 4-byte timestamp at [4:8], confirming
the cross-code identity.

Layout (cross-code, v=0x00 invariant):

    [0]      u8   version = 0x00
    [1]      u8   reserved = 0x00 (invariant across 1485 records)
    [2]      u8   sub_type = 0x02 (family marker)
    [3]      u8   reserved = 0x00 (invariant across 1485 records)
    [4:8]    u32  log_time / timestamp (varies)
    [8:12]   u32  const_marker — 1 across the 1485 RM520N-GL records, but
                  NOT constant fleet-wide: 0xB8CB v0x00 on the Inseego M3100
                  reads {1,2,3,4,6,7,8,12,22,23,373,374}. Not gated; name kept
                  for compatibility.
    [12]     u8   tlv_type = 0xFC (TLV type byte)
    [13:15]  u16  tlv_chunk_len = payload_size - 12 (validated across all
                  12 saved fixtures including sizes 524/548/596/636 where
                  the length crosses 256 and requires the full u16)
    [15:N]   ?B   chunk_body (chunk_len - 3 bytes of as-yet-undecoded payload)

The chunk body contents are not decoded by this shared container decode
(per-code parsers may decode elements; see ``entries``). The 0xFC type
byte plus the length validation gives a strong "is this a recognized
v=0x00 record?" check that distinguishes real v=0x00 records from
corruption.

Source: RM520N-GL captures from two firmware builds; fixtures at
``tests/data/diag_0xb8c{5,b}_rm520ngl_sdx62_v0_sz*.bin``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

V0_TLV_TYPE = 0xFC
V0_HEADER_SIZE = 12
V0_TLV_HEADER_SIZE = 3  # type byte + u16 length
V0_MIN_PAYLOAD_SIZE = 15  # 12-byte header + 3-byte TLV header


@dataclass
class V0TlvRecord:
    """Decoded v=0x00 TLV record — common across 0xB8C5 and 0xB8CB."""
    log_time: int
    version: int            # always 0x00
    sub_type: int           # always 0x02
    const_marker: int       # u32 at offset 8; 1 on RM520N-GL, varies on M3100
    tlv_type: int           # always 0xFC
    tlv_chunk_len: int      # u16, equals payload_size - 12
    chunk_body: bytes       # data[15:payload_size]
    payload_size: int
    # Decoded TLV-element entries — populated by a per-code parser that
    # knows the element grammar (0xB8C5); empty for
    # callers that only use the shared container decode (0xB8CB).
    entries: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'log_time': self.log_time,
            'version': self.version,
            'sub_type': self.sub_type,
            'const_marker': self.const_marker,
            'tlv_type': self.tlv_type,
            'tlv_chunk_len': self.tlv_chunk_len,
            'chunk_body_size': len(self.chunk_body),
            'payload_size': self.payload_size,
            **({'entries': [e.to_dict() for e in self.entries]}
               if self.entries else {}),
        }


def parse_v0_tlv(log_time: int, data: bytes) -> V0TlvRecord | None:
    """Decode a v=0x00 TLV record common to 0xB8C5 / 0xB8CB.

    Layer-1 gates enforced (any failure → return None, layer-2 rejects
    the record):
        - len(data) >= 15 (min header + TLV header)
        - data[0] == 0x00 (version)
        - data[2] == 0x02 (sub_type / family marker)
        - data[12] == 0xFC (TLV type marker)
        - u16@13 == len(data) - 12 (length self-consistency)

    The length self-check is the strongest of the gates — a record that
    matches version/sub_type/type but has a wrong length almost certainly
    is corruption, not a new variant. Reject loudly.
    """
    if len(data) < V0_MIN_PAYLOAD_SIZE:
        return None
    if data[0] != 0x00:
        return None
    if data[2] != 0x02:
        return None
    if data[12] != V0_TLV_TYPE:
        return None
    tlv_chunk_len = unpack_from('<H', data, 13)[0]
    if tlv_chunk_len != len(data) - V0_HEADER_SIZE:
        return None
    const_marker = unpack_from('<I', data, 8)[0]
    return V0TlvRecord(
        log_time=log_time,
        version=data[0],
        sub_type=data[2],
        const_marker=const_marker,
        tlv_type=data[12],
        tlv_chunk_len=tlv_chunk_len,
        chunk_body=bytes(data[V0_MIN_PAYLOAD_SIZE:]),
        payload_size=len(data),
    )
