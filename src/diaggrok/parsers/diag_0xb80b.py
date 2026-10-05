"""NR5G NAS 5GMM Plain OTA Outgoing parser (0xB80B).

Wrapper + 5G NAS PDU dispatch live in ``_nr5g_nas_ota_helpers.py``.
UE->network (outgoing) plain 5GMM NAS message — the outgoing twin of the
incoming 0xB80A.

Corpus: 54 records across 6 captures (Compal RXM-G1 SDX55, Quectel
RM520N-GL SDX62, Wistron LV55 SDX55, + two SDX surveys).
The 7-byte wrapper ``01 00 00 00 0f 04 00`` is invariant; EPD == 0x7e (5GMM)
and security header type == 0 (plain) on every record. The observed 5GMM
message types are all UE->network — Registration request (0x41), Registration
complete (0x43), Deregistration request UE-orig (0x45), Service request (0x4c),
Authentication response (0x57), Security mode complete (0x5e), UL NAS transport
(0x67) — confirming the "Outgoing" direction.

Naming note: the log is also known as
``5GNR_NAS_5GMM_PLAIN_OTA_OUTGOING_MSG``.

Log name: LOG_NR5G_NAS_MM5G_PLAIN_OTA_OUTGOING_MSG
Also known as: NR5G NAS MM5G Plain OTA Outgoing Msg
"""
from __future__ import annotations

from diaggrok.parsers._nr5g_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    Nr5gNasOtaMsg,
    _parse_nr5g_nas_ota,
)
from diaggrok.registry import register


@register(
    0xB80B, domain="nas",
    name="0xB80B",
    description="NR5G NAS 5GMM plain OTA outgoing message — version, rrc_rel, epd, sec_hdr_type, msg_type; shared 5GMM cause body decode (reject/status); Deregistration request (UE originating) switch-off/access-type + ngKSI + 5GS mobile identity (5G-GUTI)",
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Wrapper layout from the NR5G NAS OTA corpus: 7-byte header 01 00 00 "
        "00 0f 04 00 invariant across all 54 records of 6 captures (RXM-G1 "
        "SDX55, RM520N-GL SDX62, LV55 SDX55, 2 surveys); u32-LE version gated "
        "to {1}. EPD 0x7e (5GMM) + sec_hdr_type 0 (plain) on every record; "
        "the observed msg_types are all UE->network (Reg request/complete, "
        "Dereg request, Service request, Auth response, Security mode "
        "complete, UL NAS transport). 5GMM message-type names from 3GPP TS "
        "24.501 Table 9.7.1; security header types from §9.3.1. SCAT output "
        "is used as a cross-check only (no SCAT code is ported). "
        "The shared NR5G nas_body decode of the leading mandatory 5GMM cause "
        "octet (TS 24.501 §9.11.3.2) applies to reject/status message types "
        "via _nr5g_nas_ota_helpers (it activates if a UE-sent 5GMM status / "
        "reject is framed to this code). "
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
        "A protected SUCI's scheme output is decomposed into its TS 33.501 "
        "Annex C.3.4 parts: ecc_ephemeral_public_key (32 octets X25519 for "
        "ECIES profile A, 33 octets SEC1-compressed P-256 for profile B), "
        "ciphertext (the variable-length remainder) and the trailing 8-octet "
        "mac_tag, plus a protection_scheme_name. The whole scheme_output blob "
        "is still emitted; the parts are a derivation over bytes already "
        "accounted for, so the wire-field count is unchanged. An unassigned "
        "scheme id, or an output too short to leave a ciphertext octet, is "
        "not split (no guessed boundary); the null scheme is never split "
        "because its 'scheme output' is the plaintext MSIN, not a ciphertext. "
        "Grounded on 8 real SUCI records (3 distinct shapes across 2 "
        "captures) and confirmed field-for-field against Wireshark's nas-5gs "
        "dissector. "
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=7,
    fields_parsed=7,
    field_invariants={"version": {"enum": [_NAS_OTA_VERSION_OBSERVED]}},
)
def parse_0xb80b(log_time: int, data: bytes) -> Nr5gNasOtaMsg | None:
    # Layer-1 version gate, duplicated here so it is visible at the parser
    # entry point (the gate also lives in _parse_nr5g_nas_ota).
    if len(data) < 4 or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nr5g_nas_ota(
        log_time, data, log_code=0xB80B, is_uplink=True, type_name="Diag0xB80B",
    )
