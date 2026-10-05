"""LTE NAS EMM Plain OTA Outgoing parser (0xB0ED).

Wrapper layout + NAS PDU dispatch live in ``_lte_nas_ota_helpers.py``.

Uses ID-only parser naming.

Log name: LOG_LTE_NAS_EMM_PLAIN_OTA_OUTGOING_MSG
Also known as: LOG_LTE_NAS_EMM_PLAIN_OTA_OUTGOING_MSG_LOG_C, LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C, LOG_LTE_NAS_EMM_PLAIN_OTA_OUTGOING_MESSAGE, LTE NAS EMM Plain OTA Outgoing Message
"""
from __future__ import annotations

from diaggrok.codes import LOG_LTE_NAS_EMM_PLAIN_OTA_OUT_MSG
from diaggrok.parsers._lte_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    LteNasOtaMsg,
    _parse_nas_ota,
)
from diaggrok.registry import register


# --- Ground truth ------------------------------------------------------------
# The EG18-NA (SDX20) is the only EG12/EG18-family modem observed emitting
# this code (v=0x01, 79B and 98B records). This is an OUTGOING (uplink) EMM
# NAS message log — every
# record is a message the UE *sent*. None of the wrapper fields equal a single
# AT value; they ground by PROCEDURE CORRELATION: drive registration state
# changes and the matching outgoing message types appear in sequence.
#   - cond=cops-dereg → forces an outgoing EMM DETACH REQUEST (msg_type 0x45).
#   - a fresh attach (AT+CFUN=0 then AT+CFUN=1, or AT+COPS reselect) drives
#     ATTACH REQUEST (0x41) → AUTH RESPONSE (0x53) → SECURITY MODE COMPLETE →
#     ATTACH COMPLETE, and periodic TAU REQUEST (0x48) on tracking-area change.
# AT+CEREG? exposes the registration-state transitions to correlate the
# msg_type stream against.

@register(
    LOG_LTE_NAS_EMM_PLAIN_OTA_OUT_MSG, domain="nas",
    name="0xB0ED",
    description=(
        "LTE NAS EMM plain OTA outgoing message — sec_hdr_type, prot_disc, "
        "msg_type (attach/auth/identity/TAU); sec_hdr_type=12 is Service "
        "Request short form (no msg_type byte; ksi/seq_num/short_mac_value "
        "extracted); Detach request type + UE-sent reject EMM-cause / EMM "
        "status decoded via the NAS L3 dispatcher; + the UE security "
        "handshake (Authentication response, Security mode complete); "
        "msg_type/sec_hdr_type/prot_disc validated on RM520N-GL (SDX62) "
        "against a forced-LTE CFUN=4->1 attach (uplink Detach/Attach/AuthResp/"
        "SecModeComplete/AttachComplete), F3 emm_security.c witness; + the piggybacked ESM "
        "container body (Attach Request's PDN connectivity request 0xD0: "
        "request/PDN type; Attach Complete's Activate-default-bearer accept "
        "0xC2) decoded via the ESM L3 decoder"
    ),
    version=12,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE: the DIAG NAS-OTA wrapper is derived from DIAG captures "
        "and a vendor decoder's rendered output (which also grounds the "
        "sec_hdr=12 Service Request inner fields); message names from 3GPP TS "
        "24.301. Byte 0 (version) is gated to 0x01, the only value across 283 "
        "captured records; bytes 2/3 are rrc_ver_minor/major. emm_body decodes "
        "the UE-originated Detach request type octet (0x45, TS 24.301 "
        "§9.9.3.7: switch-off flag + direction-aware detach type), reject "
        "EMM-cause / EMM status, Authentication response (0x53: RES, §8.2.8), "
        "Security mode complete (0x5E: IMEISV, §8.2.21) and the Attach "
        "Request Mobile Identity IE (0x23) as ms_identity. The piggybacked ESM "
        "container (Attach Request's PDN connectivity request 0xD0, Attach "
        "Complete's Activate-default-bearer accept 0xC2) is inner-decoded via "
        "decode_esm_message (request/PDN type); PCO/ePCO are surfaced as "
        "presence + length. Validation: Detach type against RM520N-GL / LV55 "
        "outgoing records (switch_off true/false, detach_type=1 'EPS "
        "detach'); Inseego M2000 0x53 RES len 8 and 0x5E IMEISV; RM520N-GL "
        "(SDX62) msg_type/sec_hdr_type/prot_disc on a driven forced-LTE "
        "attach (uplink Detach/Attach/AuthResp/SecModeComplete/"
        "AttachComplete) with an F3 emm_security.c witness; the ESM "
        "container against QCSuper/tshark on an LV55 attach capture (0xD0: "
        "PDN type IPv6, Request type Initial). The EPS mobile identity that "
        "trails a detach is not broken out; its bytes remain in nas_pdu_hex. "
        "The NAS PDU has no wrapper length, so the plain EMM/ESM message's "
        "own TS 24.301 structure is checked (mandatory V/LV/LV-E part + known "
        "optional TV/TLV/TLV-E IEs); a PDU whose declared lengths overrun the "
        "record returns None (registry WARN). Not detectable: a cut that "
        "removes a whole trailing 1-octet IE or bytes past the message's "
        "known IEs."
    ),
    issues=(),
    primary_issue=None,
    # Mirror of 0xB0EC (EMM uplink direction). Same 8-field NAS-OTA wrapper:
    # version, rrc_rel, rrc_ver_major, rrc_ver_minor + prot_disc,
    # sec_hdr_type, msg_type, nas_pdu_hex. All surfaced. The per-msg_type
    # inner-body decode lives in the nested `emm_body` dict and is not counted
    # at the wrapper level.
    fields_identified=8,
    fields_parsed=8,
    field_invariants={"version": {"enum": [0x01]}},  # literal (== _NAS_OTA_VERSION_OBSERVED); AST audits don't resolve the cross-module import
)
def parse_0xb0ed(log_time: int, data: bytes) -> LteNasOtaMsg | None:
    # Layer-1 version gate — duplicated here for gate-ratchet
    # visibility (the gate also lives in _parse_nas_ota across the import).
    if not data or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nas_ota(
        log_time,
        data,
        log_code=LOG_LTE_NAS_EMM_PLAIN_OTA_OUT_MSG,
        is_uplink=True,
        type_name="Diag0xB0ED",
    )
