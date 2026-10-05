"""LTE PDCP uplink cipher-data parser (0xB0B3).

Carries the ciphered PDCP Data PDU payload in the **uplink** direction.
Same wrapper format as 0xB0A3 (DL); direction discriminated by log code.
The parser decodes the multi-sub-packet DIAG wrapper and preserves the
cipher body as opaque bytes.

The wrapper format and capture observations are documented in
``_lte_pdcp_helpers.py``.

Log name: LTE PDCP UL Cipher Data PDU
Also known as: LOG_LTE_PDCP_UL_DATA_PDU_WITH_CIPHERING, LOG_PDCP_UL_DATA_PDU_WITH_CIPHERING, LOG_LTE_PDCP_UL_CIPHER_DATA_PDU
"""
from __future__ import annotations

from diaggrok.parsers._lte_pdcp_helpers import (
    LtePdcpCipherData,
    _parse_pdcp_cipher,
)
from diaggrok.registry import register


@register(
    0xB0B3,
    name="0xB0B3",
    description=(
        "LTE uplink PDCP cipher-data PDUs. Same wrapper format "
        "as 0xB0A3 (DL); direction discriminated by log code only."
    ),
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE of the DIAG wrapper, first on EG25-G MDM9207 and "
        "then across 144 UL records / 6 captures on EG25-G, Sierra MC7411 "
        "/ MC7455 and Inseego M2000. The sub-packet header is the standard "
        "log sub-packet header id:u8/version:u8/size:u16, decoded by the "
        "decoder shared with DL 0xB0A3. The UL sub-packet version set is "
        "{1, 3, 26, 40} (vs DL {1, 3, 24}); all carry id 0xc3 (PDCP cipher "
        "data) and naming keys on subpkt_id 0xc3 for all versions. The "
        "wrapper version byte is invariant at 0x01 and gated. A sub-packet "
        "whose declared subpkt_size overruns the record (or a missing "
        "sub-packet header) returns None (registry WARN). Body bytes remain "
        "opaque AES/EEA ciphertext."
    ),
    issues=(),
    primary_issue=None,  # canonical primary tracker
    fields_identified=4,
    fields_parsed=4,
    field_invariants={"version": {"enum": [1]}},
)
def parse_0xb0b3(log_time: int, data: bytes) -> LtePdcpCipherData | None:
    if len(data) < 1 or data[0] != 1:
        return None
    return _parse_pdcp_cipher(log_time, data, direction='UL', type_name='Diag0xB0B3')
