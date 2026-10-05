# diaggrok-provenance: re
"""Shared dataclass + wrapper-parser for LTE PDCP cipher-data parsers
(0xB0A3 DL, 0xB0B3 UL).

Skipped by ``parsers/__init__.py`` auto-discovery because of the leading
underscore. Imported directly by the two per-code parser modules
(``diag_0xb0a3.py``, ``diag_0xb0b3.py``).

The wrapper layout and decode scope are documented in those per-code
parsers.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

# Canonical DIAG log sub-packet header: the sub-packet is framed
# ``id:u8 / version:u8 / size:u16``, NOT ``type:u16 / length:u16``. The PDCP
# cipher-data sub-packet is id 0xC3; its *format version* is a separate byte
# that varies per firmware/record ({1, 3, 24} DL / {1, 3, 26, 40} UL — corpus
# offset +5). A ``type:u16`` model that packs id+version into one LE word
# matches only the version==3 minority (0x03C3) and mislabels every other
# version (0x01C3, 0x18C3, …) as ``unknown_0x…`` — 156/168 DL records. The
# MobileInsight name ``LTE_PDCP_Cipher_Data_PDU = 0x03C3`` is exactly id 0xC3
# with version 3, confirming the split.
_SUBPKT_ID_PDCP_CIPHER_DATA = 0xC3


@dataclass
class LtePdcpCipherData:
    """One LTE PDCP cipher data record (0xB0A3 DL or 0xB0B3 UL).

    Wraps the multi-sub-packet DIAG format.  Observed on
    EG25-G MDM9207 with a single sub-packet per record.  Multi-sub-pkt
    records aren't ruled out on other chipsets; the parser walks the
    sub-packet list and stores each decoded body in ``sub_packets``.

    ``type_name`` is set by the per-code parser to the ID-only string
    (``"Diag0xB0A3"`` or ``"Diag0xB0B3"``) so downstream JSON consumers
    can distinguish DL vs UL on the type field alone, not just direction.

    Each entry in ``sub_packets`` uses the canonical log sub-packet
    header: ``subpkt_id`` (u8, 0xC3 for PDCP cipher data),
    ``subpkt_version`` (u8, the sub-packet *format* version — {1,3,24} DL /
    {1,3,26,40} UL), ``subpkt_size`` (u16 LE, = record length − 4-byte outer
    wrapper), plus ``subpkt_name`` (derived from ``subpkt_id``), ``body_len``,
    and ``body_hex`` (opaque AES/EEA ciphertext without the AS keys).
    """
    log_time: int
    direction: str          # 'DL' for 0xB0A3, 'UL' for 0xB0B3
    version: int            # u8 at offset 0
    num_sub_packets: int    # u8 at offset 1
    reserved: int           # u16 at offset 2 — varies, possibly seq/RB hash
    sub_packets: list[dict[str, Any]]
    payload_size: int
    type_name: str = "LtePdcpCipherData"

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': self.type_name,
            'log_time': self.log_time,
            'direction': self.direction,
            'version': self.version,
            'num_sub_packets': self.num_sub_packets,
            'reserved': self.reserved,
            'sub_packets': self.sub_packets,
            'payload_size': self.payload_size,
        }


def _parse_pdcp_cipher(
    log_time: int,
    data: bytes,
    direction: str,
    type_name: str,
) -> LtePdcpCipherData | None:
    if len(data) < 8:
        return None
    version = data[0]
    num_sub = data[1]
    reserved = unpack_from('<H', data, 2)[0]

    sub_packets: list[dict[str, Any]] = []
    offset = 4
    for _ in range(num_sub):
        # Every declared sub-packet must fit. A missing
        # header, a size smaller than the 4-byte header, or a size overrunning
        # the record is a truncated / malformed payload -> loud None (registry
        # WARN), never a silently clamped body or a short sub-packet list.
        if offset + 4 > len(data):
            return None
        subpkt_id = data[offset]
        subpkt_version = data[offset + 1]
        subpkt_size = unpack_from('<H', data, offset + 2)[0]
        body_start = offset + 4
        body_end = offset + subpkt_size
        if subpkt_size < 4 or body_end > len(data):
            return None
        body = data[body_start:body_end]
        sub_packets.append({
            'subpkt_id': subpkt_id,
            'subpkt_version': subpkt_version,
            'subpkt_name': (
                'LTE_PDCP_Cipher_Data_PDU'
                if subpkt_id == _SUBPKT_ID_PDCP_CIPHER_DATA
                else f'unknown_0x{subpkt_id:02x}'
            ),
            'subpkt_size': subpkt_size,
            'body_len': len(body),
            'body_hex': body.hex(),
        })
        offset = body_end

    return LtePdcpCipherData(
        log_time=log_time,
        direction=direction,
        version=version,
        num_sub_packets=num_sub,
        reserved=reserved,
        sub_packets=sub_packets,
        payload_size=len(data),
        type_name=type_name,
    )
