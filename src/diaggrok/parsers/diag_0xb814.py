"""NR5G NAS 5GMM Plain OTA Container parser (0xB814).

Wrapper + 5G NAS PDU dispatch live in ``_nr5g_nas_ota_helpers.py``.
Non-directional plain 5GMM NAS message container
(``5GNR_NAS_5GMM_PLAIN_OTA_CONTAINER`` — the log name carries no IN/OUT,
so ``is_uplink`` is None).

Corpus: 14 records across 5 captures (Compal RXM-G1 SDX55, Quectel
RM520N-GL SDX62, + two SDX surveys). The 7-byte wrapper
``01 00 00 00 0f 04 00`` is invariant; EPD == 0x7e (5GMM) and security header
type == 0 (plain) on every record. Observed 5GMM message types are Registration
request (0x41) and Service request (0x4c) — decoded identically to the
directional 0xB80A/0xB80B codes since they share the wrapper + NAS framing.

Naming note: the log is also known as
``5GNR_NAS_5GMM_PLAIN_OTA_CONTAINER``.

Log name: LOG_NR5G_NAS_PLAIN_MESSAGE_CONTAINER
Also known as: NR5G NAS Plain Message Container
"""
from __future__ import annotations

from diaggrok.parsers._nr5g_nas_ota_helpers import (
    _NAS_OTA_VERSION_OBSERVED,
    Nr5gNasOtaMsg,
    _parse_nr5g_nas_ota,
)
from diaggrok.registry import register


@register(
    0xB814, domain="nas",
    name="0xB814",
    description="NR5G NAS 5GMM plain OTA container — version, rrc_rel, epd, sec_hdr_type, msg_type; shared 5GMM cause body decode (reject/status); Registration request body (5GS mobile identity, requested NSSAI, last visited TAI); Service request body (service type, ngKSI, 5G-S-TMSI); Configuration update command NITZ + network name + 5G-GUTI; Deregistration request (UE originating) 5G-GUTI",
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Wrapper layout from the NR5G NAS OTA corpus: 7-byte header 01 00 00 "
        "00 0f 04 00 invariant across all 14 records of 5 captures (RXM-G1 "
        "SDX55, RM520N-GL SDX62, 2 surveys); u32-LE version gated to {1}. "
        "EPD 0x7e (5GMM) + sec_hdr_type 0 (plain) on every record; observed "
        "msg_types Registration request (0x41) + Service request (0x4c). "
        "Non-directional container code (5GNR_NAS_5GMM_PLAIN_OTA_CONTAINER), "
        "so is_uplink is None. 5GMM message-type names from 3GPP TS 24.501 "
        "Table 9.7.1; security header types from §9.3.1. SCAT output is used "
        "as a cross-check only (no SCAT code is ported). "
        "Body decodes via the shared _nr5g_nas_ota_helpers: Registration "
        "request (0x41) gives 5GS registration type + ngKSI, the UE-asserted "
        "5GS mobile identity (GUTI/SUCI, via _nas_l3 codecs), Requested NSSAI "
        "(§9.11.3.37) and Last visited registered TAI (§9.11.3.8); Service "
        "request (0x4c) gives service type (§9.11.3.50) + ngKSI + the "
        "5G-S-TMSI. Validated on 19 registration-request + 12 service-request "
        "RM520N-GL records (e.g. initial registration, requested NSSAI SST 1, "
        "last visited TAI 310/260 TAC 0x2D6600, matching the camped T-Mobile "
        "network). The leading-5GMM-cause decode (§9.11.3.2) for reject/"
        "status types is shared but inactive here, since the observed types "
        "carry no leading cause. "
        "A SUCI in the Registration request 5GS mobile identity is decoded in "
        "full (supi_format, mcc/mnc, routing_indicator, protection_scheme_id, "
        "home_network_pki, scheme_output; for the null scheme the plaintext "
        "MSIN + reconstructed IMSI), plus the raw value hex. A null-scheme "
        "SUCI is the permanent subscriber identity and is decoded as such. "
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
        "Test fixtures use a synthetic 0xFFFFFFFF sentinel, not real identity "
        "values."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=7,
    fields_parsed=7,
    field_invariants={"version": {"enum": [_NAS_OTA_VERSION_OBSERVED]}},
)
def parse_0xb814(log_time: int, data: bytes) -> Nr5gNasOtaMsg | None:
    # Layer-1 version gate, duplicated here so it is visible at the parser
    # entry point (the gate also lives in _parse_nr5g_nas_ota).
    if len(data) < 4 or data[0] != _NAS_OTA_VERSION_OBSERVED:
        return None
    return _parse_nr5g_nas_ota(
        log_time, data, log_code=0xB814, is_uplink=None, type_name="Diag0xB814",
    )
