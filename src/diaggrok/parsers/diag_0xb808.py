"""NR5G NAS 5GSM Security-Protected OTA Incoming parser (0xB808).

Wrapper + 5G NAS PDU dispatch live in ``_nr5g_nas_ota_helpers.py``.
Network->UE (incoming) security-protected NAS message. On the wire the
security envelope is always 5GMM (EPD 0x7e + non-zero security header
type); the "5GSM" in the title refers to the deciphered inner message.
The framing pass exposes the NAS-MAC + sequence number; the inner
(possibly ciphered) message is out of scope.

Log name: LOG_NR5G_NAS_MM5G_SECURITY_PROTECTED_OTA_INCOMING_MSG
"""
from __future__ import annotations

from diaggrok.parsers._nr5g_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    Nr5gNasOtaMsg,
    _parse_nr5g_nas_ota,
)
from diaggrok.registry import register


@register(
    0xB808, domain="nas",
    name="0xB808",
    description="NR5G NAS 5GSM security-protected OTA incoming message — version, rrc_rel, epd, sec_hdr_type, mac, seq, inner_msg_type (integrity-only)",
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Wrapper layout from the Compal RXM-G1 (SDX55) corpus: 7-byte header "
        "01 00 00 00 0f 04 00 invariant; u32-LE version gated to {1}. "
        "Security envelope is 5GMM (EPD 0x7e) per 3GPP TS 24.501 §9.1.1: "
        "byte[2:6]=4-octet NAS-MAC (MSB first), byte[6]=sequence number. "
        "Integrity-only protection (sec_hdr_type 3 = integrity + new 5G NAS "
        "security context) is not ciphered, so the inner NAS PDU is plaintext "
        "and inner_msg_type is decoded per §9.7. In the corpus all 9 "
        "sec_hdr=3 incoming records are Security mode command (DL under a "
        "fresh context); a sec_hdr=2 (ciphered) inner message stays opaque. "
        "Security header types from §9.3.1. SCAT output is used as a "
        "cross-check only."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=12,
    fields_parsed=12,
    field_invariants={"version": {"enum": [_NAS_OTA_VERSION_OBSERVED]}},
)
def parse_0xb808(log_time: int, data: bytes) -> Nr5gNasOtaMsg | None:
    if len(data) < 4 or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nr5g_nas_ota(
        log_time, data, log_code=0xB808, is_uplink=False, type_name="Diag0xB808",
    )
