"""NR5G NAS 5GMM Plain OTA Incoming parser (0xB80A).

Wrapper + 5G NAS PDU dispatch live in ``_nr5g_nas_ota_helpers.py``.
Network->UE (incoming) plain 5GMM NAS message.

Log name: LOG_NR5G_NAS_MM5G_PLAIN_OTA_INCOMING_MSG
Also known as: NR5G NAS MM5G Plain OTA Incoming Msg
"""
from __future__ import annotations

from diaggrok.parsers._nr5g_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    Nr5gNasOtaMsg,
    _parse_nr5g_nas_ota,
)
from diaggrok.registry import register

# ── Ground-truth recipe — WiGLE-direct (NR serving TAC + PLMN) ────────────────
# Validated on an RM520N-GL registered NR5G-SA on T-Mobile 310/260 n41.
# 0xB80A is the NR5G NAS 5GMM plain-OTA incoming message. When the network sends
# a Registration accept (5GMM msg_type 0x42), the parser decodes the 5GS TAI list
# (TS 24.501 §9.11.3.9, 24-bit TAC) and the 5G-GUTI PLMN — both WiGLE-direct NR
# identity. The Registration accept fires on (re)registration, so it is captured
# with cond:cops-dereg (an AT+COPS=2/0 bounce forces a fresh registration).
#
# EMPIRICAL: a 93 s dual-mask DIAG+F3 capture with a mid-window COPS=2/0 bounce
# produced 1 Registration accept whose tai_list decoded
# {mcc:310, mnc:260, tac:2975232 (0x2D6600)} == the AT+QENG="servingcell" serving
# TAC field (0x2D6600) seen across the whole lockstep poll == QMI GetServingSystem
# Current PLMN 310/260 (T-Mobile). The same record's 5G-GUTI carried PLMN 310/260,
# corroborating. F3 messages (100% resolved) show the NR/MM NAS registration
# subsystem (reg_mode.c / gmmutils.c / emm_rrc_if.c) firing during the COPS
# re-registration — a subsystem witness only (no per-value print; the OTA decode
# is the value source). => tac / plmn verified.

@register(
    0xB80A, domain="nas",
    name="0xB80A",
    description="NR5G NAS 5GMM plain OTA incoming message — version, rrc_rel, epd, sec_hdr_type, msg_type; 5GMM cause body decode for registration/service reject + 5GMM status; DL NAS transport payload-container type + embedded SM msg; Registration accept 5G-GUTI / 5GS TAI list / Allowed+Configured NSSAI / Equivalent PLMNs; Security mode command selected ciphering+integrity algorithm (null-cipher flag) + ngKSI; Service accept PDU-session-status bitmaps; Configuration update command NITZ (local time zone / universal time / DST) + operator network name + reassigned 5G-GUTI / TAI list",
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Wrapper layout from the Compal RXM-G1 (SDX55) corpus: 7-byte header "
        "01 00 00 00 0f 04 00 invariant across all 41 NR5G-NAS-OTA-band "
        "records (7 captures); u32-LE version gated to {1}. 5GMM message-type "
        "names from 3GPP TS 24.501 Table 9.7.1; security header types from "
        "§9.3.1. SCAT output is used as a cross-check only (no SCAT code is "
        "ported). "
        "Body decodes: the leading mandatory 5GMM cause octet (TS 24.501 "
        "§9.11.3.2) for registration reject (0x44), service reject (0x4D), "
        "security mode reject (0x5F) and 5GMM status (0x64), validated on "
        "real RM520N-GL registration-reject PDUs (cause 0x09 'UE identity "
        "cannot be derived by the network', 0x1B 'N1 mode not allowed'). "
        "Registration accept (0x42) via the reusable _nas_l3 IE codecs: the "
        "mandatory 5GS registration result (§9.11.3.6) plus the optional "
        "5G-GUTI (network-assigned temporary identity, §9.11.3.4), Allowed / "
        "Configured NSSAI (§9.11.3.37) and Equivalent PLMNs walked by the "
        "shared table-driven optional-IE walker; a Registration accept never "
        "carries a SUCI/SUPI. Its 5GS TAI list (0x54) decodes via "
        "_nas_l3.decode_5gs_tai_list (§9.11.3.9, 24-bit TAC, distinct from "
        "the EPS 16-bit codec), validated on 18 real RM520N-GL "
        "Registration-accept records (e.g. 310/260 TAC 0x2D6600, matching the "
        "GUTI's PLMN and the camped T-Mobile tracking area). "
        "Security mode command (0x5D, §8.2.25): the network-selected NAS "
        "security algorithms (§9.11.3.34), i.e. ciphering + integrity "
        "algorithm names plus null_cipher / null_integrity flags (5G-EA0/"
        "5G-IA0 detection, the IMSI-catcher / downgrade posture signal), the "
        "ngKSI and the IMEISV request flag. Service accept (0x4E, §8.2.19): "
        "the PDU-session-status + reactivation-result PSI bitmaps "
        "(§9.11.3.44) as active-session id lists. Both validated on real "
        "RM520N-GL records (SMC → 128-5G-EA2 / 128-5G-IA2, IMEISV requested; "
        "Service accept → PSI 2 active) and cross-checked against pycrate "
        "NAS-5GS. "
        "Downlink NAS transport (0x68) also reports the payload-container "
        "type (§9.11.3.40), e.g. container type 1 'N1 SM information' "
        "carrying an embedded 0xC2 'PDU session establishment accept' on the "
        "RXM-G1 capture. "
        "UL/DL NAS transport (0x67/0x68): the N1-SM payload container is a "
        "complete 5GSM NAS message and its body decodes through the shared "
        "_decode_5gsm_plain_body, so an embedded 5GSM message decodes "
        "identically to a top-level 0xB800/0xB801 one (sm_pdu_session_id / "
        "sm_pti / sm_body; a PDU session establishment accept inside a "
        "container is 138-177 octets). The corpus holds 83 N1-SM containers "
        "across 0x67/0x68 (24 x 0xC1, 23 x 0xC2, plus modification/release/"
        "status). The transport's own optional IEs, which follow the "
        "container, are walked: PDU session ID (0x12), old PDU session ID "
        "(0x59), request type (0x8- type-1), S-NSSAI (0x22), DNN (0x25, the "
        "'which APN is this session for' field) and additional information "
        "(0x24). A type-2 (SMS) container is not dispatched as 5GSM (16 "
        "corpus containers are type 2; 5GSM-decoding SMS bytes would yield a "
        "fictional session decode). A container whose declared length "
        "exceeds the record sets container_truncated and is not inner-"
        "decoded. Grounded on real Compal RXM-G1 records and confirmed "
        "field-for-field against Wireshark's nas-5gs dissector (DNN "
        "fast.t-mobile.com, request type Initial, PDU session identity 2). "
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=7,
    fields_parsed=7,
    field_invariants={"version": {"enum": [_NAS_OTA_VERSION_OBSERVED]}},
)
def parse_0xb80a(log_time: int, data: bytes) -> Nr5gNasOtaMsg | None:
    # Layer-1 version gate, duplicated here so it is visible at the parser
    # entry point (the gate also lives in _parse_nr5g_nas_ota).
    if len(data) < 4 or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nr5g_nas_ota(
        log_time, data, log_code=0xB80A, is_uplink=False, type_name="Diag0xB80A",
    )
