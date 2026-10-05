"""LTE NAS ESM Plain OTA Incoming parser (0xB0E2).

Wrapper layout + NAS PDU dispatch live in ``_lte_nas_ota_helpers.py``.

Log name: LOG_LTE_NAS_ESM_PLAIN_OTA_INCOMING_MSG
Also known as: LOG_LTE_NAS_ESM_PLAIN_OTA_INCOMING_MSG_LOG_C, LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C, LOG_ESM_BEARER_CONTEXT_STATE, LOG_LTE_NAS_ESM_BEARER_CONTEXT_STATE, LOG_LTE_NAS_ESM_PLAIN_OTA_INCOMING_MESSAGE, LTE NAS ESM Plain OTA Incoming Message
"""
from __future__ import annotations

from diaggrok.codes import LOG_LTE_NAS_ESM_PLAIN_OTA_IN_MSG
from diaggrok.parsers._lte_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    LteNasOtaMsg,
    _parse_nas_ota,
)
from diaggrok.registry import register


# Single version (0x01). MC7411 emits it. LTE NAS
# ESM plain OTA INCOMING (network→UE) — session-management procedures (default/
# dedicated bearer activation, bearer modify/deactivate). Grounds by EVENT
# CORRELATION (msg_type ↔ driven PDN/bearer procedure), not value-equality.

@register(
    LOG_LTE_NAS_ESM_PLAIN_OTA_IN_MSG, domain="nas",
    name="0xB0E2",
    description="LTE NAS ESM plain OTA incoming message — prot_disc, bearer_id, pti, msg_type",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room: DIAG NAS-OTA wrapper derived from DIAG captures and a "
        "vendor decoder's rendered output, not from QCSuper source; msg names "
        "from 3GPP TS 24.301. Byte[2]/byte[3] are rrc_ver_major/rrc_ver_minor "
        "in that order. Byte 0 is `version` (the DIAG NAS extended-header "
        "version), gated to {0x01}, the sole byte-0 across all 164 captured "
        "records (pkt_version=1 in the vendor decoder's output). The NAS PDU "
        "has no wrapper length, so the shared _parse_nas_ota checks the plain "
        "EMM/ESM message's own TS 24.301 structure (mandatory V/LV/LV-E part + "
        "known optional TV/TLV/TLV-E IEs); a PDU whose declared lengths overrun "
        "the record returns None (registry WARN) instead of a silently short "
        "decode. Not detectable: a cut that removes a whole trailing 1-octet IE "
        "or bytes past the message's known IEs."
    ),
    issues=(),
    primary_issue=None,
    # ESM wrapper surfaces 9 wire fields via _parse_nas_ota → LteNasOtaMsg.to_dict():
    # version, rrc_rel, rrc_ver_major, rrc_ver_minor (DIAG outer header),
    # prot_disc, eps_bearer_id, pti, msg_type, nas_pdu_hex (ESM NAS PDU). All
    # surfaced. msg_type_name/prot_disc_name are derivations (excluded per
    # convention). is_uplink is derived from log_code (excluded likewise).
    fields_identified=9,
    fields_parsed=9,
    field_invariants={"version": {"enum": [0x01]}},  # literal (== _NAS_OTA_VERSION_OBSERVED); AST audits don't resolve the cross-module import
)
def parse_0xb0e2(log_time: int, data: bytes) -> LteNasOtaMsg | None:
    # Version gate — duplicated here (the gate also lives in _parse_nas_ota)
    # so a static audit that does not follow the cross-module import can see
    # `data[0] != ...` in this file.
    if not data or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nas_ota(
        log_time,
        data,
        log_code=LOG_LTE_NAS_ESM_PLAIN_OTA_IN_MSG,
        is_uplink=False,
        type_name="Diag0xB0E2",
    )
