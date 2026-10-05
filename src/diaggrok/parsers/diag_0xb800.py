"""NR5G NAS 5GSM Plain OTA Incoming parser (0xB800).

Wrapper + 5G NAS PDU dispatch live in ``_nr5g_nas_ota_helpers.py``.
Network->UE (incoming) plain 5GSM NAS message.

Log name: LOG_NR5G_NAS_SM5G_PLAIN_OTA_INCOMING_MSG
Also known as: NR5G NAS SM5G Plain OTA Incoming Msg
"""
from __future__ import annotations

from diaggrok.parsers._nr5g_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    Nr5gNasOtaMsg,
    _parse_nr5g_nas_ota,
)
from diaggrok.registry import register


@register(
    0xB800, domain="nas",
    name="0xB800",
    description="NR5G NAS 5GSM plain OTA incoming message — version, rrc_rel, epd, pdu_session_id, pti, msg_type; 5GSM cause body decode for reject/release/status; PDU session establishment accept body (selected type/SSC, Session-AMBR, authorized QoS rules + flow descriptions, S-NSSAI, always-on, 5GSM cause, PDU address, DNN); PDU session modification command body (5GSM cause, Session-AMBR, authorized QoS rules + flow descriptions, always-on)",
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Wrapper layout from the Compal RXM-G1 (SDX55) corpus: 7-byte header "
        "01 00 00 00 0f 04 00 invariant across the NR5G-NAS-OTA band; u32-LE "
        "version gated to {1}. 5GSM message-type names from 3GPP "
        "TS 24.501 Table 9.7.2. SCAT output is used as a cross-check only (no "
        "SCAT code is ported). "
        "The nas_body decodes the leading mandatory 5GSM cause octet (TS "
        "24.501 §9.11.4.2) for the PDU-session establishment/modification/"
        "release reject, release command and 5GSM status messages; a real "
        "RM520N-GL release-command PDU 2e0105d324 decodes to cause 0x24 "
        "'Regular deactivation'. "
        "The PDU session establishment accept (0xC2) decodes end-to-end: the "
        "mandatory prefix (selected PDU session type/SSC mode §9.11.4.11/16, "
        "authorized QoS rules §9.11.4.13, Session-AMBR §9.11.4.14) is walked "
        "positionally, then the optional IEs (informational 5GSM cause 0x59, "
        "S-NSSAI 0x22, always-on indication, authorized QoS flow descriptions "
        "0x79, PDU address 0x29, DNN 0x25). The DNN (Data Network Name, "
        "§9.11.2.1B) is the 5G equivalent of the LTE APN and uses the same "
        "DNS-label encoding (_nas_l3.decode_apn); on the RXM-G1 capture it "
        "decodes to 'fast.t-mobile.com', the camped carrier's data network. "
        "The PDU address is decoded in full via _nas_l3.decode_pdn_address "
        "(IPv6 interface id / IPv4); a carrier-assigned IP is ephemeral and "
        "non-identifying. Validated across RM520N-GL + RXM-G1: the IMS PDN "
        "carries 5GSM cause 51 'PDU session type IPv6 only allowed', "
        "consistent with its IPv6 grant. "
        "The PDU session modification command (0xCB) has no mandatory IEs "
        "(TS 24.501 §8.3.9); the whole body is walked by the shared optional-"
        "IE walker for the 5GSM cause (0x59), Session-AMBR (0x2A), authorized "
        "QoS rules (0x7A) + flow descriptions (0x79), and the always-on PDU "
        "session indication (0x8). Validated on a real RM520N-GL record "
        "(2e0223cb81 → always_on required), cross-checked against pycrate "
        "NAS-5GS (5GSMPDUSessionModifCommand → AlwaysOnPDUSess Value 1). "
        "DNN aside, these are network-policy fields; no subscriber identity "
        "appears in these messages."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=8,
    fields_parsed=8,
    field_invariants={"version": {"enum": [_NAS_OTA_VERSION_OBSERVED]}},
)
def parse_0xb800(log_time: int, data: bytes) -> Nr5gNasOtaMsg | None:
    if len(data) < 4 or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nr5g_nas_ota(
        log_time, data, log_code=0xB800, is_uplink=False, type_name="Diag0xB800",
    )
