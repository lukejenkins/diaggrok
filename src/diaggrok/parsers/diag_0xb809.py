"""NR5G NAS 5GSM Security-Protected OTA Outgoing parser (0xB809).

Wrapper + 5G NAS PDU dispatch live in ``_nr5g_nas_ota_helpers.py``.
UE->network (outgoing) security-protected NAS message — twin of 0xB808.
The security envelope is 5GMM (EPD 0x7e + non-zero security header type);
the framing pass exposes the NAS-MAC + sequence number.

Log name: LOG_NR5G_NAS_MM5G_SECURITY_PROTECTED_OTA_OUTGOING_MSG
"""
from __future__ import annotations

from diaggrok.parsers._nr5g_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    Nr5gNasOtaMsg,
    _parse_nr5g_nas_ota,
)
from diaggrok.registry import register


@register(
    0xB809, domain="nas",
    name="0xB809",
    description="NR5G NAS 5GMM security-protected OTA outgoing message — version, rrc_rel, epd, sec_hdr_type, mac, seq, inner_msg_type + inner nas_body (integrity-only plaintext)",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "UE->network twin of 0xB808. Wrapper layout from the Compal RXM-G1 "
        "(SDX55) corpus: 7-byte header 01 00 00 00 0f 04 00 invariant; u32-LE "
        "version gated to {1}. Security envelope is 5GMM (EPD 0x7e) "
        "per 3GPP TS 24.501 §9.1.1: byte[2:6]=4-octet NAS-MAC (MSB first), "
        "byte[6]=sequence number. Integrity-only protection (sec_hdr_type 1 = "
        "integrity protected) is not ciphered, so the inner NAS PDU is "
        "plaintext and decodes in full through the shared "
        "_nr5g_nas_ota_helpers plain-5GMM dispatch: a Service request "
        "surfaces service type + ngKSI + 5G-S-TMSI, a Registration request its "
        "asserted 5GS mobile identity / Requested NSSAI / Last visited TAI. In "
        "the corpus, 14 sec_hdr=1 outgoing records are Registration request "
        "(10) + Service request (4), validated on real RM520N-GL records; a "
        "sec_hdr=2/4 (ciphered) inner message stays opaque. Security header "
        "types from §9.3.1. SCAT output is used as a cross-check only. Test "
        "fixtures use the 0xFFFFFFFF identity sentinel, not real identities."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=12,
    fields_parsed=12,
    field_invariants={"version": {"enum": [_NAS_OTA_VERSION_OBSERVED]}},
)
def parse_0xb809(log_time: int, data: bytes) -> Nr5gNasOtaMsg | None:
    if len(data) < 4 or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nr5g_nas_ota(
        log_time, data, log_code=0xB809, is_uplink=True, type_name="Diag0xB809",
    )
