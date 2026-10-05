"""LTE NAS ESM Plain OTA Outgoing parser (0xB0E3).

Wrapper layout + NAS PDU dispatch live in ``_lte_nas_ota_helpers.py``.

Log name: LOG_LTE_NAS_ESM_PLAIN_OTA_OUTGOING_MSG
Also known as: LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C, LOG_ESM_BEARER_CONTEXT_INFO, LOG_LTE_NAS_ESM_BEARER_CONTEXT_INFO, LOG_LTE_NAS_ESM_PLAIN_OTA_OUTGOING_MESSAGE, LTE NAS ESM Plain OTA Outgoing Message
"""
from __future__ import annotations

from diaggrok.codes import LOG_LTE_NAS_ESM_PLAIN_OTA_OUT_MSG
from diaggrok.parsers._lte_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    LteNasOtaMsg,
    _parse_nas_ota,
)
from diaggrok.registry import register


# Single version (0x01). MC7411 emits it. The
# UE→network twin of 0xB0E2 — LTE NAS ESM plain OTA OUTGOING. Grounds by EVENT
# CORRELATION (msg_type ↔ driven PDN/bearer procedure), not value-equality.

@register(
    LOG_LTE_NAS_ESM_PLAIN_OTA_OUT_MSG, domain="nas",
    name="0xB0E3",
    description="LTE NAS ESM plain OTA outgoing message — prot_disc, bearer_id, pti, msg_type",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room: DIAG NAS-OTA wrapper derived from DIAG captures and a "
        "vendor decoder's rendered output, not from QCSuper source; msg names "
        "from 3GPP TS 24.301. Byte[2]/byte[3] are rrc_ver_major/rrc_ver_minor "
        "in that order. Byte 0 is `version`, gated to {0x01}, the sole byte-0 "
        "across all 159 captured records (as for 0xB0E1/0xB0E2). The NAS PDU "
        "has no wrapper length, so the shared _parse_nas_ota checks the plain "
        "EMM/ESM message's own TS 24.301 structure (mandatory V/LV/LV-E part + "
        "known optional TV/TLV/TLV-E IEs); a PDU whose declared lengths overrun "
        "the record returns None (registry WARN) instead of a silently short "
        "decode. Not detectable: a cut that removes a whole trailing 1-octet IE "
        "or bytes past the message's known IEs."
    ),
    issues=(),
    primary_issue=None,
    ascii_kinds=("config-token",),  # operator/APN name 't-mobile' in the NAS ESM OTA payload (LV55 SDX55, n=5 frac 1.00; Wistron+Foxconn SDX55 captures)
    # Mirror of 0xB0E2 (ESM uplink direction). Same 9-field NAS-OTA wrapper:
    # version, rrc_rel, rrc_ver_major, rrc_ver_minor + prot_disc,
    # eps_bearer_id, pti, msg_type, nas_pdu_hex. All surfaced.
    fields_identified=9,
    fields_parsed=9,
    field_invariants={"version": {"enum": [0x01]}},  # literal (== _NAS_OTA_VERSION_OBSERVED); AST audits don't resolve the cross-module import
)
def parse_0xb0e3(log_time: int, data: bytes) -> LteNasOtaMsg | None:
    # Version gate — duplicated here so a static audit that does not follow
    # the import can see it (the gate also lives in _parse_nas_ota).
    if not data or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nas_ota(
        log_time,
        data,
        log_code=LOG_LTE_NAS_ESM_PLAIN_OTA_OUT_MSG,
        is_uplink=True,
        type_name="Diag0xB0E3",
    )
