# diaggrok-provenance: re
"""LTE NAS EMM message-body decoder (callable from `_lte_nas_ota_helpers.py`).

Layer-2 NAS decoder: takes a NAS PDU whose envelope has already been
parsed by `_lte_nas_ota_helpers.py` (security header type, protocol
discriminator, EMM message type — shared by the per-code
`diag_0xB0E2.py` / `diag_0xB0E3.py` / `diag_0xB0EC.py` / `diag_0xB0ED.py`
parsers) and decodes the remaining message body into structured fields per 3GPP TS
24.301.

The message types covered are listed in :func:`decode_emm_body`. EMM
Information (msg_type=0x61) is the simplest EMM message body (no mandatory
fields — all 5 fields are optional TLV-tagged IEs) and surfaces high-value
WiGLE-tagging information (operator network name, time zone, daylight
saving).

This module is a named NAS decoder that consumes nas_pdu bytes and returns
a structured decode, called from the OTA wrapper rather than inlined into
it.

References:
- 3GPP TS 24.301 §8.2.13 (EMM Information message contents)
- 3GPP TS 24.008 §10.5.3.5a (Network Name IE)
- 3GPP TS 24.008 §10.5.3.8 (Local Time Zone IE)
- 3GPP TS 24.008 §10.5.3.9 (Universal Time and Local Time Zone IE)
- 3GPP TS 24.008 §10.5.3.12 (Daylight Saving Time IE)
- 3GPP TS 23.038 §6.2.1 (SMS Data Coding Scheme — GSM-7 default alphabet
  used for Network Name when coding=00; UCS-2 when coding=01)

Ground truth: an EMM Information record in a vendor decoder's rendered
text export of a signaling trace — Vietnam PLMN 452/04 advertised as "Viettel", capture time 2020-05-22
09:18:19 UTC+7. The 13.2.1 → 16.1.0 rrc_release brackets in the same
trace family give cross-release regression coverage.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.parsers._nas_l3 import (
    IeFormat,
    IeSpec,
    NasL3Error,
    _decode_5gs_imei_digits,
    decode_drx_parameter,
    decode_dst,
    decode_eps_mobile_identity,
    decode_eps_tai_list,
    decode_esm_message,
    decode_gprs_timer,
    decode_gprs_timer3,
    decode_gsm_7_packed,
    decode_lai,
    decode_local_time_zone,
    decode_mobile_identity,
    decode_ms_network_feature_support,
    decode_network_name,
    decode_plmn_list,
    decode_universal_time,
    decode_voice_domain_preference,
    read_lv,
    walk_optional_ies,
)

# Back-compat aliases: these GSM-7 / Network-Name / NITZ codecs live in
# _nas_l3 so the NR5G 5GMM Configuration update command can reuse them.
# The EMM Information call sites below keep the private names. decode_gsm_7_packed
# stays importable from this module (test_lte_nas_emm imports it here).
_decode_network_name = decode_network_name
_decode_local_time_zone = decode_local_time_zone
_decode_universal_time = decode_universal_time
_decode_dst = decode_dst


@dataclass
class EmmInformationDecoded:
    """Structured decode of an EMM Information (msg_type=0x61) NAS PDU body."""
    network_name_full: str | None = None
    network_name_full_encoding: str | None = None
    network_name_short: str | None = None
    network_name_short_encoding: str | None = None
    local_time_zone_qhrs: int | None = None
    universal_time: dict[str, Any] | None = None
    dst_offset: int | None = None
    unrecognized_ieis: list[int] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.network_name_full is not None:
            d["network_name_full"] = self.network_name_full
            d["network_name_full_encoding"] = self.network_name_full_encoding
        if self.network_name_short is not None:
            d["network_name_short"] = self.network_name_short
            d["network_name_short_encoding"] = self.network_name_short_encoding
        if self.local_time_zone_qhrs is not None:
            d["local_time_zone_qhrs"] = self.local_time_zone_qhrs
        if self.universal_time is not None:
            d["universal_time"] = self.universal_time
        if self.dst_offset is not None:
            d["dst_offset"] = self.dst_offset
        if self.unrecognized_ieis:
            d["unrecognized_ieis"] = [f"0x{i:02X}" for i in self.unrecognized_ieis]
        return d


# 3GPP TS 24.301 §8.2.13 — EMM Information IEI assignments.
_IEI_FULL_NETWORK_NAME = 0x43      # TLV (T=1, L=1, V=variable)
_IEI_SHORT_NETWORK_NAME = 0x45     # TLV
_IEI_LOCAL_TIME_ZONE = 0x46        # TV (T=1, V=1)
_IEI_UNIVERSAL_TIME = 0x47         # TV (T=1, V=7)
_IEI_DST = 0x49                    # TLV

# EMM Information IE table (TS 24.301 §8.2.13) for the shared L3 walker.
# All five IEs are optional. 0x46/0x47 are type-3 TV (fixed value length);
# 0x43/0x45/0x49 are type-4 TLV. Uses the reusable _nas_l3 framework.
_EMM_INFORMATION_IE_TABLE: dict[int, IeSpec] = {
    _IEI_FULL_NETWORK_NAME: IeSpec(IeFormat.TLV),
    _IEI_SHORT_NETWORK_NAME: IeSpec(IeFormat.TLV),
    _IEI_LOCAL_TIME_ZONE: IeSpec(IeFormat.TV, length=1),
    _IEI_UNIVERSAL_TIME: IeSpec(IeFormat.TV, length=7),
    _IEI_DST: IeSpec(IeFormat.TLV),
}


# ── EMM cause / identity-type / detach-type code tables ───────────────────

# 3GPP TS 24.301 Table 9.9.3.9.1 — EMM cause values. Carried as a single
# mandatory octet in the reject messages (Attach/TAU/Service reject) and in
# EMM status. Only assigned values are named; reserved/unassigned render as
# the raw 0xNN, matching the forensic-visibility convention elsewhere.
_EMM_CAUSE_NAMES: dict[int, str] = {
    2: "IMSI unknown in HSS",
    3: "Illegal UE",
    5: "IMEI not accepted",
    6: "Illegal ME",
    7: "EPS services not allowed",
    8: "EPS services and non-EPS services not allowed",
    9: "UE identity cannot be derived by the network",
    10: "Implicitly detached",
    11: "PLMN not allowed",
    12: "Tracking area not allowed",
    13: "Roaming not allowed in this tracking area",
    14: "EPS services not allowed in this PLMN",
    15: "No suitable cells in tracking area",
    16: "MSC temporarily not reachable",
    17: "Network failure",
    18: "CS domain not available",
    19: "ESM failure",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    23: "UE security capabilities mismatch",
    24: "Security mode rejected, unspecified",
    25: "Not authorized for this CSG",
    26: "Non-EPS authentication unacceptable",
    35: "Requested service option not authorized in this PLMN",
    39: "CS service temporarily not available",
    40: "No EPS bearer context activated",
    42: "Severe network failure",
    95: "Semantically incorrect message",
    96: "Invalid mandatory information",
    97: "Message type non-existent or not implemented",
    98: "Message type not compatible with the protocol state",
    99: "Information element non-existent or not implemented",
    100: "Conditional IE error",
    101: "Message not compatible with the protocol state",
    111: "Protocol error, unspecified",
}

# TS 24.301 §9.9.3.3 (Identity type 2) — low 3 bits of the identity-request
# type octet. Direction-independent.
_IDENTITY_TYPE_NAMES: dict[int, str] = {
    1: "IMSI",
    2: "IMEI",
    3: "IMEISV",
    4: "TMSI",
}

# TS 24.301 §9.9.3.7 — Detach type value (bits 1-3). The mapping is
# DIRECTION-DEPENDENT: a UE-originated detach uses the EPS/IMSI/combined
# scale, a network-originated detach uses the re-attach scale.
_DETACH_TYPE_NAMES_UE: dict[int, str] = {
    1: "EPS detach",
    2: "IMSI detach",
    3: "Combined EPS/IMSI detach",
}
_DETACH_TYPE_NAMES_NW: dict[int, str] = {
    1: "Re-attach required",
    2: "Re-attach not required",
    3: "IMSI detach",
}


def decode_emm_reject(body: bytes) -> dict[str, Any] | None:
    """Decode a reject-message body: one mandatory EMM cause octet.

    Used by Attach reject (0x44), TAU reject (0x4B), Service reject (0x4E)
    and EMM status (0x60) — all of which begin with a single TS 24.301
    §9.9.3.9 EMM cause octet (optional IEs such as T3346 follow but are not
    decoded here). ``body`` is the bytes AFTER the (sec|prot, msg_type)
    preamble. Returns ``None`` for an empty body (truncated capture).
    """
    if not body:
        return None
    cause = body[0]
    return {
        "emm_cause": cause,
        "emm_cause_name": _EMM_CAUSE_NAMES.get(cause, f"0x{cause:02X}"),
    }


def decode_identity_request(body: bytes) -> dict[str, Any] | None:
    """Decode an Identity request (0x55) body: identity type (low 3 bits).

    TS 24.301 §8.2.18 — the identity type is a type-1 IE occupying the low
    3 bits of the first body octet (the high nibble is spare). ``body`` is
    the bytes after the preamble. Returns ``None`` for an empty body.
    """
    if not body:
        return None
    id_type = body[0] & 0x07
    return {
        "identity_type": id_type,
        "identity_type_name": _IDENTITY_TYPE_NAMES.get(id_type, f"0x{id_type:X}"),
    }


def decode_detach_request(body: bytes, is_uplink: bool = True) -> dict[str, Any] | None:
    """Decode a Detach request (0x45) body: the detach type octet and, for a
    UE-originated detach, the EPS mobile identity (GUTI/IMSI/IMEI).

    TS 24.301 §9.9.3.7 — bit 4 is the switch-off flag, bits 1-3 are the
    detach type (interpreted per ``is_uplink``: UE-originated vs network-
    originated scales). A UE-originated detach carries the subscriber's EPS
    mobile identity as a trailing LV; it is decoded faithfully — the
    tool never withholds it. Returns ``None`` for an empty body.
    """
    if not body:
        return None
    octet = body[0]
    switch_off = bool(octet & 0x08)
    detach_type = octet & 0x07
    names = _DETACH_TYPE_NAMES_UE if is_uplink else _DETACH_TYPE_NAMES_NW
    out: dict[str, Any] = {
        "switch_off": switch_off,
        "detach_type": detach_type,
        "detach_type_name": names.get(detach_type, f"0x{detach_type:X}"),
    }
    # UE-originated detach: the EPS mobile identity follows as an LV. Decode it.
    if is_uplink and len(body) > 1:
        mid_len = body[1]
        if 1 + 1 + mid_len <= len(body):
            mid = decode_eps_mobile_identity(body[2:2 + mid_len])
            if mid is not None:
                out["mobile_identity"] = mid
    return out


# TS 24.301 §9.9.3.23 — type of ciphering / integrity algorithm (EEA/EIA).
_NAS_CIPHER_ALG_NAMES: dict[int, str] = {
    0: "EEA0 (null)", 1: "128-EEA1 (SNOW3G)", 2: "128-EEA2 (AES)",
    3: "128-EEA3 (ZUC)",
}
_NAS_INTEGRITY_ALG_NAMES: dict[int, str] = {
    0: "EIA0 (null)", 1: "128-EIA1 (SNOW3G)", 2: "128-EIA2 (AES)",
    3: "128-EIA3 (ZUC)",
}


def decode_authentication_request(body: bytes) -> dict[str, Any] | None:
    """Decode an Authentication request (0x52) body — TS 24.301 §8.2.7.

    Layout after the (sec_hdr|prot_disc, msg_type) preamble:
      [0]      NAS key set identifierASME (type-1: low 3 bits = NAS-KSI)
      [1:17]   Authentication parameter RAND (type-3, V = 16 octets)
      [17]     AUTN length, [18:18+L] AUTN value (type-4 LV, mandatory)

    RAND/AUTN are the network's cryptographic challenge values — NOT
    subscriber PII (unlike GUTI/IMSI), so they are surfaced as hex.
    """
    if len(body) < 17:
        return None
    nas_ksi = body[0] & 0x07
    rand = body[1:17]
    out: dict[str, Any] = {"nas_ksi": nas_ksi, "rand_hex": rand.hex()}
    if len(body) >= 18:
        autn_len = body[17]
        autn = body[18:18 + autn_len]
        if len(autn) == autn_len and autn_len:
            out["autn_hex"] = autn.hex()
    return out


def decode_authentication_response(body: bytes) -> dict[str, Any] | None:
    """Decode an Authentication response (0x53) body — TS 24.301 §8.2.8.

    Layout: Authentication response parameter RES (type-4 LV, mandatory):
      [0] length, [1:1+L] RES value. RES is the USIM's challenge response
    (not subscriber identity); surfaced as hex + length.
    """
    if not body:
        return None
    res_len = body[0]
    res = body[1:1 + res_len]
    if len(res) != res_len or not res_len:
        return None
    return {"res_len": res_len, "res_hex": res.hex()}


def decode_security_mode_command(body: bytes) -> dict[str, Any] | None:
    """Decode a Security mode command (0x5d) body — TS 24.301 §8.2.20.

    Layout: Selected NAS security algorithms (type-3, 1 octet) +
    NAS key set identifierASME (type-1). The selected-algorithms octet
    packs the negotiated ciphering (bits 5-7) and integrity (bits 1-3)
    algorithms — the headline, non-PII security-negotiation outcome.
    """
    if not body:
        return None
    alg = body[0]
    cipher = (alg >> 4) & 0x07
    integrity = alg & 0x07
    out: dict[str, Any] = {
        "ciphering_alg": cipher,
        "ciphering_alg_name": _NAS_CIPHER_ALG_NAMES.get(cipher, f"0x{cipher:X}"),
        "integrity_alg": integrity,
        "integrity_alg_name": _NAS_INTEGRITY_ALG_NAMES.get(integrity, f"0x{integrity:X}"),
    }
    if len(body) >= 2:
        out["nas_ksi"] = body[1] & 0x07
    return out


def decode_security_mode_complete(body: bytes) -> dict[str, Any] | None:
    """Decode a Security mode complete (0x5e) body — TS 24.301 §8.2.21.

    The only fields are optional: an IMEISV (TLV, IEI 0x23) and a NAS
    message container. The IMEISV is decoded faithfully — the tool
    never withholds the digits — via the shared BCD codec.
    """
    if not body:
        return None
    imeisv_present = False
    imeisv = ""
    i = 0
    while i < len(body):
        iei = body[i]
        if iei == 0x23:  # IMEISV (Mobile identity, TLV)
            imeisv_present = True
            if i + 1 < len(body):
                val = body[i + 2:i + 2 + body[i + 1]]
                if val:
                    imeisv = _decode_5gs_imei_digits(val)
                i += 2 + body[i + 1]
                continue
        break
    return {"imeisv_present": imeisv_present, "imeisv": imeisv}


# ── TAU Accept (0x49) — TS 24.301 §8.2.26 ─────────────────────────────────
# The headline EPS downlink mobility message: it tells the UE the outcome of a
# Tracking Area Update and (re)assigns the network-temporary identity + the
# tracking-area set it may roam within. Decoded end-to-end via the shared
# _nas_l3 codecs, the EPS twin of
# the 5GMM Registration Accept consumer. The GUTI is a network-assigned
# TEMPORARY identity; a TAU Accept normally reassigns it, but any EPS mobile
# identity present (including an IMSI/IMEI) is decoded faithfully.

# TS 24.301 §9.9.3.13 — EPS update result value (low 3 bits of octet 1; the
# high half-octet is a spare half octet).
_EPS_UPDATE_RESULT_NAMES: dict[int, str] = {
    0: "TA updated",
    1: "Combined TA/LA updated",
    4: "TA updated and ISR activated",
    5: "Combined TA/LA updated and ISR activated",
}

# TS 24.008 §10.5.1.4 — Mobile Identity IE (IEI 0x23), the classic IMSI/IMEI/
# IMEISV/TMSI form. Shared across the EMM decoders below. It carries subscriber
# PII and is decoded in full, not withheld: the decoder decodes everything
# faithfully, and any redaction is left to whoever publishes the output.
# Decoded via :func:`decode_mobile_identity`.
_IEI_MS_IDENTITY = 0x23           # TLV — Mobile identity (IMSI/IMEI/IMEISV/TMSI)

# TS 24.301 §8.2.26 — TAU Accept optional-IE IEI assignments. Every IE we have a
# codec for is tabled and decoded (PII included); an IEI not yet modeled falls
# through the walker into ``unrecognized_ieis`` (a not-yet-modeled list, NOT a
# redaction bucket).
_IEI_TAU_GUTI = 0x50              # TLV — EPS mobile identity (GUTI), §9.9.3.12
_IEI_TAU_TAI_LIST = 0x54         # TLV — Tracking area identity list, §9.9.3.33
_IEI_TAU_EMM_CAUSE = 0x53        # TV  — EMM cause (1 value octet), §9.9.3.9
_IEI_TAU_EQUIVALENT_PLMNS = 0x4A  # TLV — Equivalent PLMNs, §9.9.3.45

_TAU_ACCEPT_IE_TABLE: dict[int, IeSpec] = {
    _IEI_TAU_GUTI: IeSpec(IeFormat.TLV),
    _IEI_MS_IDENTITY: IeSpec(IeFormat.TLV),
    _IEI_TAU_TAI_LIST: IeSpec(IeFormat.TLV),
    _IEI_TAU_EMM_CAUSE: IeSpec(IeFormat.TV, length=1),
    _IEI_TAU_EQUIVALENT_PLMNS: IeSpec(IeFormat.TLV),
}


def decode_tau_accept(body: bytes) -> dict[str, Any] | None:
    """Decode a Tracking Area Update Accept (0x49) body — TS 24.301 §8.2.26.

    ``body`` is the bytes AFTER the (sec_hdr|prot_disc, msg_type) preamble.
    The mandatory first IE is the EPS update result — a type-1 V occupying the
    low 3 bits of octet 1 (the high half-octet is a spare half octet) — and the
    remaining IEs are all optional, walked by the shared table-driven
    :func:`walk_optional_ies` framework. The EPS twin of the 5GMM
    Registration Accept consumer.

    Surfaces the groundable network-assigned fields:
      - **GUTI** (0x50) via :func:`decode_eps_mobile_identity` — a network-
        assigned TEMPORARY identity (M-TMSI), surfaced as ``guti``. Any other
        EPS mobile identity form here (IMSI/IMEI) is decoded faithfully into
        ``mobile_identity`` — never withheld.
      - **TAI list** (0x54) via :func:`decode_eps_tai_list` — the EPS 2-octet-TAC
        codec (NOT the 5GS 3-octet form), the camped tracking-area set.
      - **EMM cause** (0x53) named via :data:`_EMM_CAUSE_NAMES`.
      - **Equivalent PLMNs** (0x4A) via :func:`decode_plmn_list`.

      - **MS identity** (0x23) via :func:`decode_mobile_identity` — IMSI/IMEI/
        IMEISV/TMSI, decoded in full into ``ms_identity``; a PII-bearing
        identity is decoded, never withheld.

    Any IEI not yet modeled (timers, bearer-context status, …) is recorded in
    ``unrecognized_ieis`` — a not-yet-modeled list, not a redaction bucket.
    Returns ``None`` for an empty body.
    """
    if not body:
        return None
    result_value = body[0] & 0x07
    out: dict[str, Any] = {
        "eps_update_result": result_value,
        "eps_update_result_name": _EPS_UPDATE_RESULT_NAMES.get(
            result_value, f"0x{result_value:X}"),
    }
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(body[1:], _TAU_ACCEPT_IE_TABLE):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_TAU_GUTI:
            mid = decode_eps_mobile_identity(value)
            # Faithful decode: a TAU Accept's EPS mobile identity is
            # normally the GUTI, but if an IMSI/IMEI appears here we decode it
            # too — the tool never withholds.
            if mid is not None and mid.get("type") == "guti":
                out["guti"] = mid
            elif mid is not None:
                out["mobile_identity"] = mid
        elif iei == _IEI_MS_IDENTITY:
            # Mobile Identity (0x23) — IMSI/IMEI/IMEISV/TMSI. Decoded in full
            #: a PII-bearing IE is a first-class deliverable, not a
            # reason to withhold.
            ms = decode_mobile_identity(value)
            if ms is not None:
                out["ms_identity"] = ms
        elif iei == _IEI_TAU_TAI_LIST:
            tais = decode_eps_tai_list(value)
            if tais is not None:
                out["tai_list"] = tais
        elif iei == _IEI_TAU_EMM_CAUSE:
            if value:
                cause = value[0]
                out["emm_cause"] = cause
                out["emm_cause_name"] = _EMM_CAUSE_NAMES.get(cause, f"0x{cause:02X}")
        elif iei == _IEI_TAU_EQUIVALENT_PLMNS:
            plmns = decode_plmn_list(value)
            if plmns is not None:
                out["equivalent_plmns"] = plmns["plmns"]
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return out


# TS 24.301 §8.2.16 — GUTI Reallocation Command optional-IE IEIs. The GUTI
# itself is a MANDATORY LV (no IEI); only the trailing optional IEs are tabled.
_IEI_GRC_TAI_LIST = 0x54          # TLV — Tracking area identity list, §9.9.3.33
_IEI_GRC_DCN_ID = 0x65            # TLV — DCN-ID (2-octet value), §9.9.3.48

_GUTI_REALLOCATION_IE_TABLE: dict[int, IeSpec] = {
    _IEI_GRC_TAI_LIST: IeSpec(IeFormat.TLV),
    _IEI_GRC_DCN_ID: IeSpec(IeFormat.TLV),
}


def decode_guti_reallocation_command(body: bytes) -> dict[str, Any] | None:
    """Decode a GUTI Reallocation Command (0x50) body — TS 24.301 §8.2.16.

    ``body`` is the bytes AFTER the (sec_hdr|prot_disc, msg_type) preamble. The
    single mandatory IE is the new **GUTI** — an EPS mobile identity in *LV* form
    (a length octet + value, no IEI), so it dogfoods the framework's
    :func:`read_lv` primitive; the remaining IEs are optional and walked by the
    shared table-driven :func:`walk_optional_ies`. This is the dedicated
    GUTI-reassignment sibling of the GUTI that rides inside an Attach/TAU Accept.

    Surfaces the groundable network-assigned fields:
      - **GUTI** via :func:`decode_eps_mobile_identity` — the network-assigned
        TEMPORARY identity (MME group/code + M-TMSI), surfaced as ``guti``.
        Any IMSI/IMEI form an out-of-spec record carries here is decoded
        faithfully into ``mobile_identity`` — never withheld.
      - **TAI list** (0x54) via :func:`decode_eps_tai_list` — the EPS 2-octet-TAC
        codec, the reassigned tracking-area set.
      - **DCN-ID** (0x65) — the Dedicated Core Network identifier (u16), §9.9.3.48.

    Unrecognized IEIs are recorded in ``unrecognized_ieis`` for forensic
    visibility. Returns ``None`` for an empty body or one whose mandatory GUTI
    LV is truncated (nothing decodable).
    """
    if not body:
        return None
    try:
        guti_value, pos = read_lv(body, 0)
    except NasL3Error:
        return None
    out: dict[str, Any] = {}
    # Faithful decode: normally the reassigned GUTI, but any IMSI/IMEI
    # form here is decoded too — the tool never withholds.
    mid = decode_eps_mobile_identity(guti_value)
    if mid is not None and mid.get("type") == "guti":
        out["guti"] = mid
    elif mid is not None:
        out["mobile_identity"] = mid
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(
        body[pos:], _GUTI_REALLOCATION_IE_TABLE
    ):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_GRC_TAI_LIST:
            tais = decode_eps_tai_list(value)
            if tais is not None:
                out["tai_list"] = tais
        elif iei == _IEI_GRC_DCN_ID:
            if len(value) >= 2:
                out["dcn_id"] = int.from_bytes(value[:2], "big")
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return out or None


# TS 24.301 §9.9.3.10 — EPS attach result value (low 3 bits of octet 1; the
# high half-octet is a spare half octet).
_EPS_ATTACH_RESULT_NAMES: dict[int, str] = {
    1: "EPS only",
    2: "combined EPS/IMSI attach",
}

# TS 24.301 §8.2.1 — Attach Accept optional-IE IEI assignments. Only the IEs we
# have grounded codecs for are tabled (PII included). The fixed-length TV timers
# (T3402/T3423) are tabled *specifically so the walker consumes them at their
# spec length* — an untabled type-3 TV with bit-8 clear would otherwise be
# mis-skipped as a TLV and desync the rest of the walk. The MS-identity IE
# (0x23) IS tabled and decoded — a PII-bearing identity is a deliverable, not a
# reason to withhold.
_IEI_AA_GUTI = 0x50               # TLV  — EPS mobile identity (GUTI), §9.9.3.12
_IEI_AA_LAI = 0x13                # TV(5)— Location area identification, §9.9.2.2
_IEI_AA_EMM_CAUSE = 0x53          # TV(1)— EMM cause, §9.9.3.9
_IEI_AA_T3402 = 0x17             # TV(1)— T3402 value (GPRS timer), §9.9.3.16
_IEI_AA_T3423 = 0x59             # TV(1)— T3423 value (GPRS timer), §9.9.3.16
_IEI_AA_EQUIVALENT_PLMNS = 0x4A   # TLV  — Equivalent PLMNs, §9.9.3.45
_IEI_AA_T3412_EXT = 0x5E          # TLV  — T3412 extended value (GPRS timer 3)
_IEI_AA_T3324 = 0x6A              # TLV  — T3324 value (GPRS timer 2), §9.9.3.16

_ATTACH_ACCEPT_IE_TABLE: dict[int, IeSpec] = {
    _IEI_AA_GUTI: IeSpec(IeFormat.TLV),
    _IEI_MS_IDENTITY: IeSpec(IeFormat.TLV),
    _IEI_AA_LAI: IeSpec(IeFormat.TV, length=5),
    _IEI_AA_EMM_CAUSE: IeSpec(IeFormat.TV, length=1),
    _IEI_AA_T3402: IeSpec(IeFormat.TV, length=1),
    _IEI_AA_T3423: IeSpec(IeFormat.TV, length=1),
    _IEI_AA_EQUIVALENT_PLMNS: IeSpec(IeFormat.TLV),
    _IEI_AA_T3412_EXT: IeSpec(IeFormat.TLV),
    _IEI_AA_T3324: IeSpec(IeFormat.TLV),
}


def decode_attach_accept(body: bytes) -> dict[str, Any] | None:
    """Decode an Attach Accept (0x42) body — TS 24.301 §8.2.1.

    ``body`` is the bytes AFTER the (sec_hdr|prot_disc, msg_type) preamble.
    The heaviest EMM consumer: a four-IE mandatory preamble precedes the
    optional table.

    Mandatory part (in wire order, no IEIs):
      - **EPS attach result** — type-1 V in the low 3 bits of octet 1 (high
        half-octet is a spare half octet), §9.9.3.10.
      - **T3412 value** — a single GPRS-timer octet (the periodic-TAU timer),
        decoded via :func:`decode_gprs_timer`.
      - **TAI list** — an LV (1-octet length + value), the camped tracking-area
        set, via :func:`decode_eps_tai_list`.
      - **ESM message container** — an LV-E (2-octet length + value) carrying
        the piggybacked *Activate Default EPS Bearer Context Request*. Its inner
        ESM body is decoded in full via the shared :func:`decode_esm_message`
        and surfaced under ``esm_message`` (QCI / APN / PDN address /
        APN-AMBR, and PCO/ePCO contents as hex) — nothing is withheld.

    Optional IEs (table-driven, shared :func:`walk_optional_ies`) — the
    modeled fields: GUTI (0x50), LAI (0x13), EMM cause (0x53),
    T3402/T3423/T3412-extended/T3324 GPRS timers, Equivalent PLMNs (0x4A). Any
    IEI not yet in the table surfaces in ``unrecognized_ieis`` so nothing is
    silently dropped; that bucket is a "not-yet-modeled" list, **not** a
    redaction bucket. When an untabled IE turns out to carry an identifier
    (MS-identity 0x23 / GUTI / IMSI / IMEI), the correct treatment is to add it
    to the table and decode it in full — never to leave it undecoded *because*
    it is PII-bearing.

    Returns ``None`` for an empty body. A truncated mandatory preamble yields
    whatever decoded before the cut (the partial record is still surfaced).
    """
    if not body:
        return None
    out: dict[str, Any] = {
        "eps_attach_result": body[0] & 0x07,
        "eps_attach_result_name": _EPS_ATTACH_RESULT_NAMES.get(
            body[0] & 0x07, f"0x{body[0] & 0x07:X}"),
    }
    pos = 1
    # T3412 value — one mandatory GPRS-timer octet (the periodic-TAU timer).
    if pos < len(body):
        out["t3412"] = decode_gprs_timer(body[pos])
        pos += 1
    # TAI list — mandatory LV.
    if pos < len(body):
        tai_len = body[pos]
        if pos + 1 + tai_len <= len(body):
            tais = decode_eps_tai_list(body[pos + 1:pos + 1 + tai_len])
            if tais is not None:
                out["tai_list"] = tais
            pos += 1 + tai_len
        else:                       # truncated TAI list — stop, surface partial
            return out
    # ESM message container — mandatory LV-E (2-octet length). The shared reader
    # frames it AND decodes the inner ESM body — for Attach Accept the
    # piggybacked Activate-default-bearer request (QCI / APN / PDN address).
    if pos + 2 <= len(body):
        esm_fields, next_pos = _read_esm_message_container(body, pos)
        out.update(esm_fields)
        if pos + 2 + esm_fields.get("esm_message_container_len", 0) <= len(body):
            pos = next_pos
        else:                       # truncated container — nothing optional left
            return out
    # Optional IEs.
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(
            body[pos:], _ATTACH_ACCEPT_IE_TABLE):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_AA_GUTI:
            mid = decode_eps_mobile_identity(value)
            # Faithful decode (same as TAU Accept): normally the GUTI,
            # but an IMSI/IMEI here is decoded too — never withheld.
            if mid is not None and mid.get("type") == "guti":
                out["guti"] = mid
            elif mid is not None:
                out["mobile_identity"] = mid
        elif iei == _IEI_MS_IDENTITY:
            # Mobile Identity (0x23) — IMSI/IMEI/IMEISV/TMSI, decoded in full
            #; PII is decoded, never withheld.
            ms = decode_mobile_identity(value)
            if ms is not None:
                out["ms_identity"] = ms
        elif iei == _IEI_AA_LAI:
            lai = decode_lai(value)
            if lai is not None:
                out["lai"] = lai
        elif iei == _IEI_AA_EMM_CAUSE:
            if value:
                cause = value[0]
                out["emm_cause"] = cause
                out["emm_cause_name"] = _EMM_CAUSE_NAMES.get(cause, f"0x{cause:02X}")
        elif iei == _IEI_AA_T3402:
            if value:
                out["t3402"] = decode_gprs_timer(value[0])
        elif iei == _IEI_AA_T3423:
            if value:
                out["t3423"] = decode_gprs_timer(value[0])
        elif iei == _IEI_AA_T3412_EXT:
            if value:
                out["t3412_extended"] = decode_gprs_timer3(value[0])
        elif iei == _IEI_AA_T3324:
            if value:
                out["t3324"] = decode_gprs_timer(value[0])
        elif iei == _IEI_AA_EQUIVALENT_PLMNS:
            plmns = decode_plmn_list(value)
            if plmns is not None:
                out["equivalent_plmns"] = plmns["plmns"]
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return out


# TS 24.301 §9.9.3.11 — EPS attach type value (low 3 bits of octet 1; bits
# 5-7 carry the NAS key set identifier, bit 8 its type-of-security-context).
_EPS_ATTACH_TYPE_NAMES: dict[int, str] = {
    1: "EPS attach",
    2: "combined EPS/IMSI attach",
    6: "EPS emergency attach",
    7: "reserved",
}

# Attach Request optional-IE IEIs (TS 24.301 Table 8.2.4.1).
#
# The fixed-length TV rows are load-bearing, not completeness. An
# untabled IEI is skipped by §11.2.4's bit-8 rule: bit 8 SET → one octet (safe),
# bit 8 CLEAR → "assume TLV" → read the next octet as a LENGTH. That guess is
# right for a type-4 TLV and catastrophically wrong for a fixed-length type-3
# TV, whose first VALUE octet then becomes a bogus length and desyncs every IE
# after it (the Attach Accept table carries the same caveat). On an LV55
# attach capture, an untabled DRX parameter `5c 0a 00` would be read as a
# 10-octet TLV, swallowing the Voice-domain-preference, MS-network-feature-
# support and UE-additional-security-capability IEs that follow — and they
# would never reach ``unrecognized_ieis``, so nothing in the output would
# show the loss.
#
# ★ = named, formatted and length-confirmed by Wireshark's TS 24.301 NAS-EPS
# dissector on that same capture (QCSuper pcap export), not from the spec
# alone. That comparison identifies `0xC-` as MS network feature support.
_IEI_AR_OLD_LAI = 0x13            # TV(5) — Old location area identification
_IEI_AR_OLD_PTMSI_SIGNATURE = 0x19  # TV(3) — Old P-TMSI signature, §10.5.5.8
_IEI_AR_MS_NETWORK_CAPABILITY = 0x31  # TLV — MS network capability, §10.5.5.12
_IEI_AR_MS_CLASSMARK_2 = 0x11     # TLV — Mobile station classmark 2, §10.5.1.6
_IEI_AR_MS_CLASSMARK_3 = 0x20     # TLV — Mobile station classmark 3, §10.5.1.7
_IEI_AR_ADDITIONAL_GUTI = 0x50    # TLV — Additional GUTI (the "old GUTI")
_IEI_AR_LAST_VISITED_TAI = 0x52   # TV(5) — Last visited registered TAI, §9.9.3.8
_IEI_AR_DRX_PARAMETER = 0x5C      # ★ TV(2) — DRX parameter, §10.5.5.6
_IEI_AR_VOICE_DOMAIN_PREF = 0x5D  # ★ TLV — Voice domain pref + usage setting
_IEI_AR_T3412_EXTENDED = 0x5E     # TLV — T3412 extended value (GPRS timer 3)
_IEI_AR_T3324 = 0x6A              # TLV — T3324 value (GPRS timer 2)
_IEI_AR_UE_ADDL_SECURITY_CAP = 0x6F  # ★ TLV — UE additional security capability
_IEI_AR_MS_NW_FEATURE_SUPPORT = 0xC  # ★ TV1 — MS network feature support (nibble)

_ATTACH_REQUEST_IE_TABLE: dict[int, IeSpec] = {
    # --- bit-8-CLEAR fixed-length TVs: tabled so the walk cannot desync ---
    _IEI_AR_OLD_LAI: IeSpec(IeFormat.TV, length=5),
    _IEI_AR_OLD_PTMSI_SIGNATURE: IeSpec(IeFormat.TV, length=3),
    _IEI_AR_LAST_VISITED_TAI: IeSpec(IeFormat.TV, length=5),
    _IEI_AR_DRX_PARAMETER: IeSpec(IeFormat.TV, length=2),
    # --- TLVs: the bit-8 fallback already skips these correctly, so tabling
    # them changes no walk offsets — it only turns a bare IEI into a decoded
    # (or at least NAMED) field. ---
    _IEI_MS_IDENTITY: IeSpec(IeFormat.TLV),
    _IEI_AR_MS_NETWORK_CAPABILITY: IeSpec(IeFormat.TLV),
    _IEI_AR_MS_CLASSMARK_2: IeSpec(IeFormat.TLV),
    _IEI_AR_MS_CLASSMARK_3: IeSpec(IeFormat.TLV),
    _IEI_AR_ADDITIONAL_GUTI: IeSpec(IeFormat.TLV),
    _IEI_AR_VOICE_DOMAIN_PREF: IeSpec(IeFormat.TLV),
    _IEI_AR_T3412_EXTENDED: IeSpec(IeFormat.TLV),
    _IEI_AR_T3324: IeSpec(IeFormat.TLV),
    _IEI_AR_UE_ADDL_SECURITY_CAP: IeSpec(IeFormat.TLV),
    # --- type-1 half-octet (bit 8 set — single-octet skip was already safe) ---
    _IEI_AR_MS_NW_FEATURE_SUPPORT: IeSpec(IeFormat.TV_SHORT),
}

#: Tabled (so the walk stays in sync) and surfaced verbatim, but not
#: field-decoded — dense legacy GSM/UMTS capability bitmaps that no capture on
#: hand exercises. Writing a field map for them from the spec alone would be
#: recitation with nothing able to check it against; hex is the honest surface
#: until a capture exercises them, at which point codecs can be added.
_AR_HEX_ONLY_FIELDS: dict[int, str] = {
    _IEI_AR_MS_NETWORK_CAPABILITY: "ms_network_capability_hex",
    _IEI_AR_MS_CLASSMARK_2: "ms_classmark_2_hex",
    _IEI_AR_MS_CLASSMARK_3: "ms_classmark_3_hex",
    _IEI_AR_UE_ADDL_SECURITY_CAP: "ue_additional_security_capability_hex",
}


def _read_esm_message_container(body: bytes, pos: int) -> tuple[dict[str, Any], int]:
    """Read a mandatory ESM message container IE (type-6 LV-E, 2-octet length;
    TS 24.301 §9.9.3.15) at ``pos``. Returns (fields, next_pos).

    Surfaces ``esm_message_container_len`` (matching :func:`decode_attach_accept`)
    plus the inner ESM ``esm_message_type`` byte — the ESM PDU is laid out
    byte[0]=bearer|prot_disc, byte[1]=PTI, byte[2]=msg_type — so the attach
    handshake can be cross-linked to its ESM procedure (0xd0 PDN connectivity
    request / 0xc1 activate-default-bearer / 0xc2 activate-accept).

    Beyond the framing, the inner ESM body is decoded via the shared
    :func:`decode_esm_message` and surfaced under ``esm_message`` —
    e.g. the Activate-default-bearer request's QCI / APN / PDN address /
    APN-AMBR. PCO/ePCO contents are decoded there in full as hex (they can
    carry the subscriber MSISDN / DNS / P-CSCF) — faithfully, never withheld
    .
    """
    if pos + 2 > len(body):
        return {}, pos
    esm_len = (body[pos] << 8) | body[pos + 1]
    value = body[pos + 2:pos + 2 + esm_len]
    fields: dict[str, Any] = {"esm_message_container_len": esm_len}
    if len(value) >= 3:
        fields["esm_message_type"] = value[2]
        esm = decode_esm_message(value)
        if esm is not None:
            fields["esm_message"] = esm
    return fields, pos + 2 + esm_len


def decode_attach_request(body: bytes) -> dict[str, Any] | None:
    """Decode an Attach Request (0x41) body — TS 24.301 §8.2.4.

    ``body`` is the bytes AFTER the (sec_hdr|prot_disc, msg_type) preamble.
    The outgoing/uplink twin of Attach Accept; the message a UE sends to start
    an attach. Mandatory part (wire order, no IEIs):
      - **EPS attach type** + **NAS key set identifier** — two type-1 half
        octets of octet 1 (attach type in bits 1-3, NAS-KSI value in bits 5-7,
        TSC in bit 8), §9.9.3.11/§9.9.3.21.
      - **EPS mobile identity** — an LV; usually the temporary GUTI but may
        carry an IMSI, via :func:`decode_eps_mobile_identity`.
      - **UE network capability** — an LV; the supported-algorithm bitmap
        (not PII), surfaced as hex.
      - **ESM message container** — an LV-E carrying the piggybacked *PDN
        connectivity request* (inner msg 0xd0); its inner body is decoded in
        full via the shared ESM decoder and surfaced under ``esm_message``.

    Optional IEs are table-walked; the Last visited registered TAI (0x52) and
    any Mobile Identity (0x23, IMSI/IMEI/IMEISV/TMSI → ``ms_identity``)
    are decoded.

    The mandatory EPS mobile identity is decoded faithfully into
    ``mobile_identity`` — GUTI, IMSI, or IMEI, whatever the UE presents;
    the tool never withholds it. Returns ``None`` for an empty body; a truncated
    mandatory preamble surfaces a partial record.
    """
    if not body:
        return None
    out: dict[str, Any] = {
        "eps_attach_type": body[0] & 0x07,
        "eps_attach_type_name": _EPS_ATTACH_TYPE_NAMES.get(
            body[0] & 0x07, f"0x{body[0] & 0x07:X}"),
        "nas_ksi": (body[0] >> 4) & 0x07,
        "nas_ksi_tsc": (body[0] >> 7) & 0x01,
    }
    pos = 1
    # EPS mobile identity — mandatory LV.
    if pos < len(body):
        mid_len = body[pos]
        if pos + 1 + mid_len > len(body):
            return out                  # truncated — surface partial
        mid = decode_eps_mobile_identity(body[pos + 1:pos + 1 + mid_len])
        pos += 1 + mid_len
        if mid is not None:             # faithful decode: GUTI/IMSI/IMEI
            out["mobile_identity"] = mid
    # UE network capability — mandatory LV (capability bitmap, not PII).
    if pos < len(body):
        cap_len = body[pos]
        if pos + 1 + cap_len > len(body):
            return out
        out["ue_network_capability_hex"] = body[pos + 1:pos + 1 + cap_len].hex()
        pos += 1 + cap_len
    # ESM message container — mandatory LV-E.
    esm_fields, pos = _read_esm_message_container(body, pos)
    out.update(esm_fields)
    if pos > len(body):                 # truncated container — nothing optional
        return out
    # Optional IEs — table-driven. See _ATTACH_REQUEST_IE_TABLE for why
    # the fixed-length TV rows are load-bearing rather than completeness.
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(
            body[pos:], _ATTACH_REQUEST_IE_TABLE):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_AR_LAST_VISITED_TAI:
            # 0x52 is a single 5-octet TAI (3-octet PLMN + 2-octet TAC), not a
            # list; reuse the EPS TAI-list codec by prepending a "type 0, one
            # element" header octet (0x00) so the one TAI decodes.
            tai = decode_eps_tai_list(bytes([0x00]) + value)
            if tai is not None and tai.get("tais"):
                out["last_visited_registered_tai"] = tai["tais"][0]
        elif iei == _IEI_MS_IDENTITY:
            # Mobile Identity (0x23) — decoded in full, never withheld.
            ms = decode_mobile_identity(value)
            if ms is not None:
                out["ms_identity"] = ms
        elif iei == _IEI_AR_ADDITIONAL_GUTI:
            # The "old GUTI". Faithful decode: normally a
            # GUTI, but an IMSI/IMEI presented here is decoded too, never
            # withheld.
            mid = decode_eps_mobile_identity(value)
            if mid is not None:
                key = "additional_guti" if mid.get("type") == "guti" \
                    else "additional_mobile_identity"
                out[key] = mid
        elif iei == _IEI_AR_OLD_LAI:
            lai = decode_lai(value)
            if lai is not None:
                out["old_location_area_identification"] = lai
        elif iei == _IEI_AR_DRX_PARAMETER:
            drx = decode_drx_parameter(value)
            if drx is not None:
                out["drx_parameter"] = drx
        elif iei == _IEI_AR_VOICE_DOMAIN_PREF:
            vdp = decode_voice_domain_preference(value)
            if vdp is not None:
                out["voice_domain_preference"] = vdp
        elif iei == _IEI_AR_MS_NW_FEATURE_SUPPORT:
            # type-1: the walker hands the low nibble back as a 1-byte value.
            if value:
                out["ms_network_feature_support"] = \
                    decode_ms_network_feature_support(value[0])
        elif iei == _IEI_AR_T3412_EXTENDED:
            if value:
                out["t3412_extended"] = decode_gprs_timer3(value[0])
        elif iei == _IEI_AR_T3324:
            if value:
                out["t3324"] = decode_gprs_timer(value[0])
        elif iei == _IEI_AR_OLD_PTMSI_SIGNATURE:
            out["old_ptmsi_signature_hex"] = value.hex()
        elif iei in _AR_HEX_ONLY_FIELDS:
            # Framed at the right wire format (so the walk stays in sync) and
            # surfaced verbatim, but NOT field-decoded: these are dense legacy
            # GSM/UMTS capability bitmaps, and no capture on hand exercises
            # them, so a field map would be spec-recitation with nothing to
            # check it against. Hex is the honest surface until one does.
            out[_AR_HEX_ONLY_FIELDS[iei]] = value.hex()
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return out


def decode_attach_complete(body: bytes) -> dict[str, Any] | None:
    """Decode an Attach Complete (0x43) body — TS 24.301 §8.2.2.

    The body is a single mandatory ESM message container (LV-E) carrying the
    *Activate default EPS bearer context accept* (inner msg 0xc2). The third
    message of the attach handshake. Records the container length + inner ESM
    message-type; the inner ESM body is decoded in full via the shared ESM
    decoder and surfaced under ``esm_message``. Returns ``None``
    for an empty body or a non-framed container.
    """
    if not body:
        return None
    fields, _ = _read_esm_message_container(body, 0)
    return fields or None


# msg_type → (result-dict key, decoder). EMM Information (0x61) is handled
# specially because its decoder returns a dataclass; the rest return dicts.
_EMM_REJECT_KEYS: dict[int, str] = {
    0x44: "attach_reject",
    0x4B: "tau_reject",
    0x4E: "service_reject",
    0x60: "emm_status",
}


def decode_emm_body(
    msg_type: int, body: bytes, is_uplink: bool = True
) -> dict[str, Any] | None:
    """Dispatch an EMM NAS message body to its per-message-type decoder.

    ``body`` is the bytes AFTER the (sec_hdr|prot_disc, msg_type) preamble.
    Returns ``{message_label: {...decoded fields...}}`` for the message
    types this module decodes, or ``None`` for empty bodies and message
    types whose body is not yet decoded (the caller leaves ``emm_body``
    None for those). ``is_uplink`` disambiguates the direction-dependent
    detach-type naming (TS 24.301 §9.9.3.7).

    Covered message types (TS 24.301 §8.2):
      - 0x44/0x4B/0x4E Attach/TAU/Service reject — EMM cause (§9.9.3.9)
      - 0x60 EMM status — EMM cause
      - 0x55 Identity request — identity type (§9.9.3.3)
      - 0x45 Detach request — detach type (§9.9.3.7)
      - 0x41 Attach request — EPS attach type + NAS-KSI + mobile identity
        (GUTI/IMSI/IMEI) + UE network capability + ESM-container framing +
        last visited registered TAI (§8.2.4)
      - 0x42 Attach accept — EPS attach result + T3412 / TAI list / ESM-
        container framing + GUTI / LAI / EMM cause / timers / equivalent
        PLMNs (§8.2.1)
      - 0x43 Attach complete — ESM message container framing (§8.2.2)
      - 0x49 TAU accept — EPS update result + GUTI / TAI list / EMM cause /
        equivalent PLMNs (§8.2.26)
      - 0x50 GUTI reallocation command — mandatory GUTI (LV) + TAI list /
        DCN-ID (§8.2.16)
      - 0x52 Authentication request — NAS-KSI + RAND + AUTN (§8.2.7)
      - 0x53 Authentication response — RES (§8.2.8)
      - 0x5D Security mode command — selected ciphering/integrity alg (§8.2.20)
      - 0x5E Security mode complete — IMEISV (decoded digits) (§8.2.21)
      - 0x61 EMM Information — network name / time / DST (§8.2.13)
    """
    if not body:
        return None
    if msg_type in _EMM_REJECT_KEYS:
        decoded = decode_emm_reject(body)
        return {_EMM_REJECT_KEYS[msg_type]: decoded} if decoded else None
    if msg_type == 0x55:
        decoded = decode_identity_request(body)
        return {"identity_request": decoded} if decoded else None
    if msg_type == 0x45:
        decoded = decode_detach_request(body, is_uplink=is_uplink)
        return {"detach_request": decoded} if decoded else None
    if msg_type == 0x41:
        decoded = decode_attach_request(body)
        return {"attach_request": decoded} if decoded else None
    if msg_type == 0x42:
        decoded = decode_attach_accept(body)
        return {"attach_accept": decoded} if decoded else None
    if msg_type == 0x43:
        decoded = decode_attach_complete(body)
        return {"attach_complete": decoded} if decoded else None
    if msg_type == 0x49:
        decoded = decode_tau_accept(body)
        return {"tau_accept": decoded} if decoded else None
    if msg_type == 0x50:
        decoded = decode_guti_reallocation_command(body)
        return {"guti_reallocation_command": decoded} if decoded else None
    if msg_type == 0x52:
        decoded = decode_authentication_request(body)
        return {"authentication_request": decoded} if decoded else None
    if msg_type == 0x53:
        decoded = decode_authentication_response(body)
        return {"authentication_response": decoded} if decoded else None
    if msg_type == 0x5D:
        decoded = decode_security_mode_command(body)
        return {"security_mode_command": decoded} if decoded else None
    if msg_type == 0x5E:
        decoded = decode_security_mode_complete(body)
        return {"security_mode_complete": decoded} if decoded else None
    if msg_type == 0x61:
        info = decode_emm_information(body)
        if info is not None:
            d = info.to_dict()
            if d:
                return {"emm_information": d}
        return None
    return None


def decode_emm_information(body: bytes) -> EmmInformationDecoded | None:
    """Decode an EMM Information message body.

    Input: bytes AFTER the (sec_hdr|prot_disc, msg_type) preamble — i.e.
    `_lte_nas_ota_helpers.py` passes `nas_pdu[2:]` for a plain EMM
    Information record (the per-code `diag_0xB0E2.py` / `diag_0xB0E3.py` /
    `diag_0xB0EC.py` / `diag_0xB0ED.py` parsers all reach here via the
    shared helper).

    Walks the body via the shared `_nas_l3.walk_optional_ies` engine
    (the reusable TS 24.007 §11 IEI/TLV framework), driven by
    `_EMM_INFORMATION_IE_TABLE`:
      - 0x43 / 0x45 — Network Name (TLV)
      - 0x46         — Local Time Zone (TV, 1 byte value)
      - 0x47         — Universal Time + Time Zone (TV, 7 byte value)
      - 0x49         — Daylight Saving Time (TLV)

    Unknown IEIs are skipped best-effort by the walker (bit-8 rule) and
    surfaced via `unrecognized_ieis` for forensic visibility.

    Returns None if the body is empty.
    """
    if not body:
        return None

    decoded = EmmInformationDecoded(unrecognized_ieis=[])
    for iei, value, recognized in walk_optional_ies(body, _EMM_INFORMATION_IE_TABLE):
        if not recognized:
            decoded.unrecognized_ieis.append(iei)
            continue
        if iei == _IEI_FULL_NETWORK_NAME:
            result = _decode_network_name(value)
            if result is not None:
                decoded.network_name_full, decoded.network_name_full_encoding = result
        elif iei == _IEI_SHORT_NETWORK_NAME:
            result = _decode_network_name(value)
            if result is not None:
                decoded.network_name_short, decoded.network_name_short_encoding = result
        elif iei == _IEI_LOCAL_TIME_ZONE:
            decoded.local_time_zone_qhrs = _decode_local_time_zone(value)
        elif iei == _IEI_UNIVERSAL_TIME:
            decoded.universal_time = _decode_universal_time(value)
        elif iei == _IEI_DST:
            decoded.dst_offset = _decode_dst(value)

    return decoded
