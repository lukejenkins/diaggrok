"""NR5G NAS 5GSM Plain OTA Outgoing parser (0xB801).

Wrapper + 5G NAS PDU dispatch live in ``_nr5g_nas_ota_helpers.py``.
UE->network (outgoing) plain 5GSM NAS message — twin of 0xB800.

Log name: LOG_NR5G_NAS_SM5G_PLAIN_OTA_OUTGOING_MSG
Also known as: NR5G NAS SM5G Plain OTA Outgoing Msg
"""
from __future__ import annotations

from diaggrok.parsers._nr5g_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    Nr5gNasOtaMsg,
    _parse_nr5g_nas_ota,
)
from diaggrok.registry import register


@register(
    0xB801, domain="nas",
    name="0xB801",
    description="NR5G NAS 5GSM plain OTA outgoing message — version, rrc_rel, epd, pdu_session_id, pti, msg_type; 5GSM cause body decode for reject/status; PDU session establishment request body (integrity max data rate, requested PDU type/SSC, 5GSM capability); release-request optional cause",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "UE->network twin of 0xB800. Wrapper layout from the Compal RXM-G1 "
        "(SDX55) corpus: 7-byte header 01 00 00 00 0f 04 00 invariant across "
        "the NR5G-NAS-OTA band; u32-LE version gated to {1}. 5GSM "
        "message-type names from 3GPP TS 24.501 Table 9.7.2. SCAT output is "
        "used as a cross-check only (no SCAT code is ported). "
        "The nas_body decodes the leading mandatory 5GSM cause octet (TS "
        "24.501 §9.11.4.2), shared with the other NR5G NAS logs; a real "
        "RM520N-GL 5GSM-status PDU 2e0103d62f decodes to cause 0x2f "
        "'PTI mismatch'. "
        "The PDU session establishment request (0xC1, the UE twin of the 0xC2 "
        "accept) decodes the integrity-protection maximum data rate (§9.11.4.3), "
        "the requested PDU session type / SSC mode / always-on flag (type-1 "
        "IEs) and 5GSM-capability presence. The PDU session release request "
        "(0xD1) decodes its optional 5GSM cause (TV IEI 0x59). Validated on "
        "real RM520N-GL outgoing records: establishment requests asking for "
        "IPv4v6/IPv6, and a release request with cause 0x24 'Regular "
        "deactivation'. These messages carry network-policy / capability "
        "fields only (no identity)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=8,
    fields_parsed=8,
    field_invariants={"version": {"enum": [_NAS_OTA_VERSION_OBSERVED]}},
)
def parse_0xb801(log_time: int, data: bytes) -> Nr5gNasOtaMsg | None:
    if len(data) < 4 or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nr5g_nas_ota(
        log_time, data, log_code=0xB801, is_uplink=True, type_name="Diag0xB801",
    )
