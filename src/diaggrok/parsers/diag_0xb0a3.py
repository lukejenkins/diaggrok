"""LTE PDCP downlink cipher-data parser (0xB0A3).

Carries the ciphered PDCP Data PDU payload in the **downlink** direction:
per-packet user-plane data encrypted with the bearer's AS-security key
(K_UP_enc). The parser decodes the multi-sub-packet DIAG wrapper and
preserves the cipher body as opaque bytes. Decryption would require the
AS key, which this log does not carry.

The wrapper format and capture observations are documented in
``_lte_pdcp_helpers.py``.

F3 grounding (v0x01) is inconclusive. Across every F3-bearing capture (13,
370 records, 1.87 M co-temporal prints) there is no PDCP per-PDU print, and
no record field value appears in a print above a shuffled-record baseline.

Log name: LTE PDCP DL Cipher Data PDU
Also known as: LOG_LTE_PDCP_DL_DATA_PDU_WITH_CIPHERING, LOG_PDCP_DL_DATA_PDU_WITH_CIPHERING, LOG_LTE_PDCP_DL_CIPHER_DATA_PDU
"""
from __future__ import annotations

from diaggrok.parsers._lte_pdcp_helpers import (
    LtePdcpCipherData,
    _parse_pdcp_cipher,
)
from diaggrok.registry import register


# Single wrapper version (0x01); MC7411 emits it. The PDCP user-plane PDU
# body is AES/EEA ciphertext (opaque without the AS key), so the groundable
# surface is the DIAG wrapper's PDU-activity counters — data-plane activity
# correlation, the user-plane counterpart to the NAS control-plane codes
# (0xB0E2/E3/EC/ED). The log name LOG_LTE_PDCP_DL_DATA_PDU_WITH_CIPHERING
# agrees with the title (LTE PDCP, DL).

@register(
    0xB0A3,
    name="0xB0A3",
    description=(
        "LTE downlink PDCP cipher-data PDUs. Multi-sub-packet DIAG "
        "wrapper; body bytes are AES/EEA-encrypted with K_UP_enc and "
        "stay opaque."
    ),
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE of the DIAG wrapper, first on EG25-G MDM9207 and "
        "then across 168 DL records on EG25-G, Sierra MC7411 and MC7455. "
        "The sub-packet header is the standard log sub-packet header "
        "id:u8/version:u8/size:u16: +4 (subpkt id) == 0xc3 in 168/168; +5 "
        "(subpkt version) == {0x18 ×144, 0x03 ×12, 0x01 ×12}; +6/+7 (size "
        "u16 LE) == payload_size − 4 in every record. Naming keys on id "
        "0xc3 for all sub-packet versions (MobileInsight's 0x03C3 = id "
        "0xc3/ver 3 agrees). The firmware emits no PDCP per-PDU F3 print, "
        "so F3 neither grounds nor refutes the header; it rests on the "
        "structural byte histogram. The wrapper version byte is invariant "
        "at 0x01 and gated, so a future v=0x02 wrapper returns None rather "
        "than mis-parsing. A sub-packet whose declared subpkt_size overruns "
        "the record (or a missing sub-packet header) returns None (registry "
        "WARN). Body bytes remain opaque AES/EEA ciphertext."
    ),
    issues=(),
    primary_issue=None,  # canonical primary tracker
    fields_identified=4,
    fields_parsed=4,
    field_invariants={"version": {"enum": [1]}},
)
def parse_0xb0a3(log_time: int, data: bytes) -> LtePdcpCipherData | None:
    if len(data) < 1 or data[0] != 1:
        return None
    return _parse_pdcp_cipher(log_time, data, direction='DL', type_name='Diag0xB0A3')
