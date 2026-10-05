"""LTE NAS EMM Plain OTA Incoming parser (0xB0EC).

Wrapper layout + NAS PDU dispatch live in ``_lte_nas_ota_helpers.py``.

Uses ID-only parser naming.

Log name: LOG_LTE_NAS_EMM_PLAIN_OTA_INCOMING_MSG
Also known as: LOG_LTE_NAS_EMM_PLAIN_OTA_INCOMING_MSG_LOG_C, LOG_EMM_STATE, LOG_LTE_NAS_EMM_STATE, LOG_LTE_NAS_EMM_PLAIN_OTA_INCOMING_MESSAGE, LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C, LTE NAS EMM Plain OTA Incoming Message
"""
from __future__ import annotations

from diaggrok.codes import LOG_LTE_NAS_EMM_PLAIN_OTA_IN_MSG
from diaggrok.parsers._lte_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    LteNasOtaMsg,
    _parse_nas_ota,
)
from diaggrok.registry import register


# Single version (0x01). MC7411 (MDM9650) emits it. The canonical log name
# LOG_LTE_NAS_EMM_PLAIN_OTA_INCOMING_MSG agrees
# with the docstring title — LTE EMM (mobility) NAS, network→UE direction. The
# decoded wire fields are NAS message-type/header values, NOT a measured
# quantity, so this grounds by EVENT CORRELATION: the msg_type that fires is
# bound to the EMM procedure you drive (observable via AT+CEREG state).

@register(
    LOG_LTE_NAS_EMM_PLAIN_OTA_IN_MSG, domain="nas",
    name="0xB0EC",
    description=(
        "LTE NAS EMM plain OTA incoming message — sec_hdr_type, prot_disc, "
        "msg_type (attach/auth/identity/TAU); EMM Information (msg_type=0x61) "
        "inner IEs decoded via lte_nas_emm (network names + time/timezone/DST); "
        "reject EMM-cause (attach/TAU/service reject, EMM status) + identity-"
        "request type decoded via the NAS L3 dispatcher; + the security "
        "handshake (Authentication request, Security mode command); + the TAU "
        "Accept mobility outcome (0x49: EPS update result + GUTI / TAI list / "
        "EMM cause / equivalent PLMNs); + the piggybacked ESM container body "
        "(Activate default EPS bearer context request: QCI / APN / PDN address "
        "/ APN-AMBR) decoded via the ESM L3 decoder"
    ),
    version=13,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE: the DIAG NAS-OTA wrapper is derived from DIAG captures "
        "and a vendor decoder's rendered output; message names from 3GPP TS "
        "24.301. Byte 0 (version) is gated to 0x01, the only value across 130 "
        "captured records; bytes 2/3 are rrc_ver_minor/major. emm_body decodes "
        "EMM Information (0x61; TS 24.301 §8.2.13 + TS 24.008 "
        "§10.5.3.5a/8/9/12), reject EMM-cause (Attach 0x44 / TAU 0x4B / "
        "Service 0x4E reject + EMM status 0x60, §9.9.3.9), Identity request "
        "type (0x55, §9.9.3.3), Authentication request (0x52: NAS-KSI + RAND "
        "+ AUTN, §8.2.7), Security mode command (0x5D: selected "
        "ciphering/integrity algorithm, §8.2.20) and TAU Accept (0x49, "
        "§8.2.26: EPS update result + GUTI / TAI list / EMM cause / "
        "equivalent PLMNs / Mobile Identity 0x23 as ms_identity). The "
        "piggybacked ESM container (Activate default EPS bearer context "
        "request 0xC1) is inner-decoded via decode_esm_message (QCI, APN, "
        "PDN address, APN-AMBR); PCO/ePCO are surfaced as presence + length. "
        "Validation: an EG25-G failed-attach PDU 074408 decodes to cause 8 "
        "'EPS services and non-EPS services not allowed', matching tshark's "
        "'Attach reject' on the same frame; Inseego M2000 0x52 RAND/AUTN (16B "
        "each) and 0x5D EEA2/EIA2; RM520N-GL (SDX62) msg_type/sec_hdr_type/"
        "prot_disc on a driven forced-LTE attach (Auth/SecMode/AttachAccept/"
        "EMMInfo) with an F3 emm_security.c witness; the ESM container "
        "field-for-field against QCSuper/tshark on an LV55 attach capture "
        "(QCI 5, IMS APN, IPv6 PDN, AMBR 3968/3968 kbps). TAU Accept tests "
        "are spec-derived (no captured 0x49 fixture yet). The NAS PDU has no "
        "wrapper length, so the plain EMM/ESM message's own TS 24.301 "
        "structure is checked (mandatory V/LV/LV-E part + known optional "
        "TV/TLV/TLV-E IEs); a PDU whose declared lengths overrun the record "
        "returns None (registry WARN). Not detectable: a cut that removes a "
        "whole trailing 1-octet IE or bytes past the message's known IEs."
    ),
    issues=(),
    primary_issue=None,
    # EMM wrapper surfaces 8 wire fields via _parse_nas_ota → LteNasOtaMsg.to_dict():
    # version, rrc_rel, rrc_ver_major, rrc_ver_minor (DIAG outer header),
    # prot_disc, sec_hdr_type, msg_type, nas_pdu_hex (EMM NAS PDU). All
    # surfaced. The per-msg_type inner-IE deep-decode is exposed via the
    # nested `emm_body` dict and is intentionally not counted at the wrapper
    # level — only some EMM msg_types have it implemented, and the convention
    # counts wrapper wire fields, not nested per-msg-type bodies.
    fields_identified=8,
    fields_parsed=8,
    field_invariants={"version": {"enum": [0x01]}},  # literal (== _NAS_OTA_VERSION_OBSERVED); AST audits don't resolve the cross-module import
)
def parse_0xb0ec(log_time: int, data: bytes) -> LteNasOtaMsg | None:
    # Layer-1 version gate — duplicated here for gate-ratchet
    # visibility (the gate also lives in _parse_nas_ota across the import).
    if not data or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nas_ota(
        log_time,
        data,
        log_code=LOG_LTE_NAS_EMM_PLAIN_OTA_IN_MSG,
        is_uplink=False,
        type_name="Diag0xB0EC",
    )
