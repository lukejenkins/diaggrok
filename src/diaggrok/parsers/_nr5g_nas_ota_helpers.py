# diaggrok-provenance: re
"""Shared dataclass + wrapper-parser for the NR5G NAS OTA family
(0xB800, 0xB801, 0xB808, 0xB809, 0xB80A, 0xB80B, 0xB814).

Skipped by ``parsers/__init__.py`` auto-discovery because of the leading
underscore. Imported directly by the per-code parser modules
(``diag_0xb800.py`` etc.).

This is the 5G NR analog of ``_lte_nas_ota_helpers.py``: it frames the
DIAG wrapper and exposes the inner 5G NAS PDU (3GPP TS 24.501 §9). The
framing surfaces the NAS message type; per-message bodies are decoded
where a codec exists (``nas_body``).

For the security-protected codes (0xB808/0xB809), integrity-only
protection (security header type 1 or 3) does NOT cipher the inner
message, so its header is plaintext: ``inner_msg_type`` is decoded from
``nas_pdu[7:]``. Ciphered protection (type 2/4) leaves the
inner opaque and undecoded.

DIAG wrapper layout (invariant ``01 00 00 00 0f 04 00`` across all
41 band records of 7 Compal RXM-G1 SDX55 captures; byte[0:4] is a single
u32 version, as SCAT also reads it as one integer ``pkt_ver``):
    [0:4]  u32 LE  version        (== 1)
    [4]    u8      rrc_rel        (0x0f = rel-15)
    [5]    u8      rrc_ver_major  (0x04)
    [6]    u8      rrc_ver_minor  (0x00)
    [7:]   bytes   5G NAS PDU

5G NAS PDU (3GPP TS 24.501 §9):
    EPD byte (extended protocol discriminator):
        0x7e  5GMM (Mobility Management)
        0x2e  5GSM (Session Management)
    5GMM (0x7e):  [EPD, sec_hdr_type, ...]
        sec_hdr_type == 0 (plain):  byte[2] = message type
        sec_hdr_type 1-4 (protected): byte[2:6] = 4-octet NAS-MAC (MSB
            first), byte[6] = sequence number, byte[7:] = (possibly
            ciphered) inner NAS message. The security-protected codes
            0xB808/0xB809 always carry EPD 0x7e — the 5GMM security layer
            wraps the inner 5GSM/5GMM message, so their titles' "5GSM"
            refers to the deciphered inner content, not the wire EPD.
    5GSM (0x2e):  [EPD, pdu_session_id, pti, message type, ...]

F3 grounding, v0x01. Three RM520N-GL captures with fully
resolved F3.
    0xB808 seq / mac: the NAS integrity code prints ``integrity_maci function
        Direction = %d Bearer = 0x%x Count= 0x%x`` and then ``MAC-I computation
        successful: MAC-I[0x%x]`` for each message. 34/34 v0x01 records pair
        with a Direction=1 (downlink) burst. That burst carries ``Count & 0xFF
        == seq`` and lands +0.01 ms after the record (+0.2 to +0.5 ms for the
        sec_hdr 3 Security mode commands). Its MAC-I equals ``mac`` on all 34
        records, so ``mac`` is MSB-first. Pairing each record with the previous
        Count's burst instead matches 0/30. 0xB809 reads the same with
        Direction=0: seq 47/47, mac 46/47.
    0xB808 sec_hdr_type: no F3 site in this build prints the security header
        type. The DIAG plane settles it instead: the firmware logs its own
        deciphered copy as 0xB80A microseconds later. Of 5 sec_hdr 3 records,
        5 have an inner equal to that copy, so they are not ciphered. Of 29
        sec_hdr 2 records, 29 have an inner of the same length that differs
        from it, so they are ciphered.
    0xB800 body: ``Session_id`` / ``pdu_sess_id ... active_ssc_mode`` (data
        services), ``Resolved APN name``, and ``ADDR MGMT | ALLOCATED |
        PUBLIC`` IPv6 match pdu_session_id, selected_ssc_mode, dnn and the
        pdu_address interface ID. The interface ID matches byte for byte on
        both establishment accepts, and each accept's ID differs from the
        other's. 5GSM cause 51 (IPv6 only allowed) is followed by ``Ipv4
        throttled: 1`` on both. pdu_session_id matches 4/4 records whose window
        prints a session. The two release commands' windows print only the
        sess=2 modification command that precedes them by 20 ms. That is
        window overlap and is not counted as a match.
    Not labelled by F3: the 7-byte wrapper (spec / capture invariant), the EPD
    and message-type octets, and the PTI. TS 24.501 is the oracle for those.
    On one capture, the PTI of each command (sess 2 / PTI 11, sess 1 /
    PTI 12) matches the 0xB801 request that preceded it.

Sources: 3GPP TS 24.501 §9.3 (security header type), Tables 9.7.1
(5GMM message types) / 9.7.2 (5GSM message types). SCAT decoded output
is used as a cross-check (it frames this code to GSMTAP NAS for
Wireshark).
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.parsers._nas_l3 import (
    IeFormat,
    IeSpec,
    NasL3Error,
    decode_5gs_mobile_identity,
    decode_5gs_tai,
    decode_5gs_tai_list,
    decode_apn,
    decode_dst,
    decode_local_time_zone,
    decode_network_name,
    decode_nssai,
    decode_pdn_address,
    decode_plmn_list,
    decode_qos_flow_descriptions,
    decode_qos_rules,
    decode_s_nssai,
    decode_universal_time,
    read_lv,
    read_lv_e,
    walk_optional_ies,
)

# 3GPP TS 24.501 Table 9.7.1 — 5GMM message types.
_MM5G_MSG_NAMES: dict[int, str] = {
    0x41: "Registration request",
    0x42: "Registration accept",
    0x43: "Registration complete",
    0x44: "Registration reject",
    0x45: "Deregistration request (UE originating)",
    0x46: "Deregistration accept (UE originating)",
    0x47: "Deregistration request (UE terminated)",
    0x48: "Deregistration accept (UE terminated)",
    0x4C: "Service request",
    0x4D: "Service reject",
    0x4E: "Service accept",
    0x4F: "Control plane service request",
    0x50: "Network slice-specific authentication command",
    0x51: "Network slice-specific authentication complete",
    0x52: "Network slice-specific authentication result",
    0x54: "Configuration update command",
    0x55: "Configuration update complete",
    0x56: "Authentication request",
    0x57: "Authentication response",
    0x58: "Authentication reject",
    0x59: "Authentication failure",
    0x5A: "Authentication result",
    0x5B: "Identity request",
    0x5C: "Identity response",
    0x5D: "Security mode command",
    0x5E: "Security mode complete",
    0x5F: "Security mode reject",
    0x64: "5GMM status",
    0x65: "Notification",
    0x66: "Notification response",
    0x67: "Uplink NAS transport",
    0x68: "Downlink NAS transport",
}

# 3GPP TS 24.501 §9.11.3.40 — Payload container type (DL/UL NAS transport).
_PAYLOAD_CONTAINER_TYPE_NAMES: dict[int, str] = {
    1: "N1 SM information",
    2: "SMS",
    3: "LTE Positioning Protocol (LPP)",
    4: "SOR transparent container",
    5: "UE policy container",
    6: "UE parameters update transparent container",
    7: "Location services message container",
    8: "CIoT user data container",
}

# 3GPP TS 24.501 Table 9.7.2 — 5GSM message types.
_SM5G_MSG_NAMES: dict[int, str] = {
    0xC1: "PDU session establishment request",
    0xC2: "PDU session establishment accept",
    0xC3: "PDU session establishment reject",
    0xC5: "PDU session authentication command",
    0xC6: "PDU session authentication complete",
    0xC7: "PDU session authentication result",
    0xC9: "PDU session modification request",
    0xCA: "PDU session modification reject",
    0xCB: "PDU session modification command",
    0xCC: "PDU session modification complete",
    0xCD: "PDU session modification command reject",
    0xD1: "PDU session release request",
    0xD2: "PDU session release reject",
    0xD3: "PDU session release command",
    0xD4: "PDU session release complete",
    0xD6: "5GSM status",
}

# 3GPP TS 24.501 Table 9.11.3.2.1 — 5GMM cause values. Carried as a single
# mandatory octet immediately after the message type in the 5GMM reject/status
# messages. Unassigned values render as the raw 0xNN.
_MM5G_CAUSE_NAMES: dict[int, str] = {
    3: "Illegal UE",
    5: "PEI not accepted",
    6: "Illegal ME",
    7: "5GS services not allowed",
    9: "UE identity cannot be derived by the network",
    10: "Implicitly de-registered",
    11: "PLMN not allowed",
    12: "Tracking area not allowed",
    13: "Roaming not allowed in this tracking area",
    15: "No suitable cells in tracking area",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    23: "UE security capabilities mismatch",
    24: "Security mode rejected, unspecified",
    26: "Non-5G authentication unacceptable",
    27: "N1 mode not allowed",
    28: "Restricted service area",
    31: "Redirection to EPC required",
    43: "LADN not available",
    62: "No network slices available",
    65: "Maximum number of PDU sessions reached",
    67: "Insufficient resources for specific slice and DNN",
    69: "Insufficient resources for specific slice",
    71: "ngKSI already in use",
    72: "Non-3GPP access to 5GCN not allowed",
    73: "Serving network not authorized",
    74: "Temporarily not authorized for this SNPN",
    75: "Permanently not authorized for this SNPN",
    76: "Not authorized for this CAG or authorized for CAG cells only",
    77: "Wireline access area not allowed",
    90: "Payload was not forwarded",
    91: "DNN not supported or not subscribed in the slice",
    92: "Insufficient user-plane resources for the PDU session",
    93: "Onboarding services terminated",
    95: "Semantically incorrect message",
    96: "Invalid mandatory information",
    97: "Message type non-existent or not implemented",
    98: "Message type not compatible with the protocol state",
    99: "Information element non-existent or not implemented",
    100: "Conditional IE error",
    101: "Message not compatible with the protocol state",
    111: "Protocol error, unspecified",
}

# 3GPP TS 24.501 Table 9.11.4.2.1 — 5GSM cause values.
_SM5G_CAUSE_NAMES: dict[int, str] = {
    8: "Operator determined barring",
    26: "Insufficient resources",
    27: "Missing or unknown DNN",
    28: "Unknown PDU session type",
    29: "User authentication or authorization failed",
    31: "Request rejected, unspecified",
    32: "Service option not supported",
    33: "Requested service option not subscribed",
    35: "PTI already in use",
    36: "Regular deactivation",
    38: "Network failure",
    39: "Reactivation requested",
    41: "Semantic error in the TFT operation",
    42: "Syntactical error in the TFT operation",
    43: "Invalid PDU session identity",
    44: "Semantic errors in packet filter(s)",
    45: "Syntactical error in packet filter(s)",
    46: "Out of LADN service area",
    47: "PTI mismatch",
    50: "PDU session type IPv4 only allowed",
    51: "PDU session type IPv6 only allowed",
    54: "PDU session does not exist",
    57: "PDU session type IPv4v6 only allowed",
    58: "PDU session type Unstructured only allowed",
    59: "Unsupported 5QI value",
    61: "Insufficient resources for specific slice and DNN",
    67: "Insufficient resources for specific slice",
    68: "Missing or unknown DNN in a slice",
    69: "Invalid PTI value",
    70: "Maximum data rate per UE for user-plane integrity protection is too low",
    71: "Semantic error in the QoS operation",
    72: "Syntactical error in the QoS operation",
    73: "Invalid mapped EPS bearer identity",
    95: "Semantically incorrect message",
    96: "Invalid mandatory information",
    97: "Message type non-existent or not implemented",
    98: "Message type not compatible with the protocol state",
    99: "Information element non-existent or not implemented",
    100: "Conditional IE error",
    101: "Message not compatible with the protocol state",
    111: "Protocol error, unspecified",
}

# 5GMM message types whose body begins with a single mandatory 5GMM cause
# octet (TS 24.501 §8.2). Maps msg_type → nas_body result-dict key.
_MM5G_CAUSE_MSGS: dict[int, str] = {
    0x44: "registration_reject",
    0x4D: "service_reject",
    0x5F: "security_mode_reject",
    0x64: "5gmm_status",
}

# 5GSM message types whose body begins with a single mandatory 5GSM cause
# octet (TS 24.501 §8.3). PDU session modification command (0xCB) is excluded
# — its 5GSM cause is an OPTIONAL IEI-tagged IE, not the leading octet.
_SM5G_CAUSE_MSGS: dict[int, str] = {
    0xC3: "pdu_session_establishment_reject",
    0xCA: "pdu_session_modification_reject",
    0xD2: "pdu_session_release_reject",
    0xD3: "pdu_session_release_command",
    0xD6: "5gsm_status",
}


def _decode_mm5g_cause(body: bytes, key: str) -> dict[str, Any] | None:
    """Decode the leading mandatory 5GMM cause octet of a reject/status body."""
    if not body:
        return None
    cause = body[0]
    return {key: {
        "mm_cause": cause,
        "mm_cause_name": _MM5G_CAUSE_NAMES.get(cause, f"0x{cause:02X}"),
    }}


def _decode_sm5g_cause(body: bytes, key: str) -> dict[str, Any] | None:
    """Decode the leading mandatory 5GSM cause octet of a reject/status body."""
    if not body:
        return None
    cause = body[0]
    return {key: {
        "sm_cause": cause,
        "sm_cause_name": _SM5G_CAUSE_NAMES.get(cause, f"0x{cause:02X}"),
    }}


# 5GSM DNN (Data Network Name) information element — TS 24.501 §9.11.2.1B,
# carried as an optional type-4 TLV with IEI 0x25 in the PDU Session
# Establishment Accept (0xC2). The DNN value uses the same 3GPP DNS-label
# encoding (TS 23.003) as the LTE APN — so it is the 5G equivalent of the
# APN and is groundable against the camped carrier.
_IEI_DNN_5GSM = 0x25

# ── PDU Session Establishment Accept (0xC2) — TS 24.501 §8.3.2 ─────────────
# Mandatory prefix (no IEIs on the wire), in order:
#   octet 1     Selected PDU session type (low 3 bits) + Selected SSC mode
#               (bits 5-7) — two packed type-1 V half-fields (§9.11.4.11 /
#               §9.11.4.16).
#   LV-E        Authorized QoS rules (§9.11.4.13) — decode_qos_rules.
#   LV          Session-AMBR (§9.11.4.14) — DL/UL unit+value pairs.
# then the optional IEIs walked by the shared table-driven walker.
#
# v4: the prior version IEI-scanned only for the DNN because it could
# not step over the two variable-length mandatory IEs (QoS rules LV-E,
# Session-AMBR LV). With the _nas_l3 codecs those now decode
# positionally, so the whole accept is read end-to-end. Surfaced fields are
# the PDU session type, SSC mode, session-AMBR bit rates, authorized QoS rules
# + flow descriptions, S-NSSAI (network slice), informational 5GSM cause,
# always-on indication, the assigned PDU address (IEI 0x29 — a carrier-assigned,
# ephemeral / non-identifying IP; decoding the user's own assignment is a goal,
# so it is shipped in full), and the DNN.

# §9.11.4.11 — PDU session type value (low 3 bits of the selected-type octet).
_PDU_SESSION_TYPE_NAMES: dict[int, str] = {
    1: "IPv4",
    2: "IPv6",
    3: "IPv4v6",
    4: "Unstructured",
    5: "Ethernet",
}

# §9.11.4.14 — Session-AMBR unit (one octet) → (multiplier, unit label). The
# 2-octet value that follows is multiplied by the unit's base rate.
_AMBR_UNITS: dict[int, tuple[int, str]] = {
    1: (1, "Kbps"), 2: (4, "Kbps"), 3: (16, "Kbps"), 4: (64, "Kbps"),
    5: (256, "Kbps"), 6: (1, "Mbps"), 7: (4, "Mbps"), 8: (16, "Mbps"),
    9: (64, "Mbps"), 10: (256, "Mbps"), 11: (1, "Gbps"), 12: (4, "Gbps"),
    13: (16, "Gbps"), 14: (64, "Gbps"), 15: (256, "Gbps"), 16: (1, "Tbps"),
}

_IEI_PSEA_5GSM_CAUSE = 0x59       # TV   — informational 5GSM cause (§9.11.4.2)
_IEI_PSEA_PDU_ADDRESS = 0x29      # TLV  — assigned PDU address (§9.11.4.10)
_IEI_PSEA_S_NSSAI = 0x22          # TLV  — S-NSSAI / network slice (§9.11.2.8)
_IEI_PSEA_ALWAYS_ON = 0x8         # TV1  — always-on PDU session indication
_IEI_PSEA_MAPPED_EPS = 0x75       # TLV-E — mapped EPS bearer contexts
_IEI_PSEA_QOS_FLOWS = 0x79        # TLV-E — authorized QoS flow descriptions
_IEI_PSEA_EPCO = 0x7B             # TLV-E — extended protocol config options

_PSEA_IE_TABLE: dict[int, IeSpec] = {
    _IEI_PSEA_5GSM_CAUSE: IeSpec(IeFormat.TV, length=1),
    _IEI_PSEA_PDU_ADDRESS: IeSpec(IeFormat.TLV),
    _IEI_PSEA_S_NSSAI: IeSpec(IeFormat.TLV),
    _IEI_PSEA_ALWAYS_ON: IeSpec(IeFormat.TV_SHORT),
    _IEI_PSEA_MAPPED_EPS: IeSpec(IeFormat.TLV_E),
    _IEI_PSEA_QOS_FLOWS: IeSpec(IeFormat.TLV_E),
    _IEI_PSEA_EPCO: IeSpec(IeFormat.TLV_E),
    _IEI_DNN_5GSM: IeSpec(IeFormat.TLV),
}


def _decode_session_ambr(value: bytes) -> dict[str, str] | None:
    """Decode a Session-AMBR IE value (TS 24.501 §9.11.4.14): DL then UL, each
    a 1-octet unit + 2-octet (big-endian) value. Returns human bit-rate
    strings (e.g. ``{"downlink": "100 Mbps", "uplink": "100 Mbps"}``)."""
    if len(value) < 6:
        return None

    def one(unit: int, raw: int) -> str:
        spec = _AMBR_UNITS.get(unit)
        if spec is None:
            return f"unit0x{unit:02X}:{raw}"
        mult, label = spec
        return f"{raw * mult} {label}"

    return {
        "downlink": one(value[0], (value[1] << 8) | value[2]),
        "uplink": one(value[3], (value[4] << 8) | value[5]),
    }


def _decode_pdu_session_establishment_accept(body: bytes) -> dict[str, Any] | None:
    """Decode a PDU session establishment accept (0xC2) — TS 24.501 §8.3.2.

    ``body`` is ``nas_pdu[4:]`` (after [EPD, pdu_session_id, pti, msg_type]).
    Walks the mandatory prefix (selected PDU session type/SSC mode octet,
    authorized QoS rules LV-E, Session-AMBR LV) positionally via the _nas_l3
    codecs, then the optional IEIs via the shared table-driven walker. Surfaces
    the accept's network-policy / network-data fields plus the assigned PDU
    address (see the module note above).
    Returns ``None`` only when even the mandatory prefix can't be read.
    """
    if not body:
        return None
    out: dict[str, Any] = {}
    sel = body[0]
    pst = sel & 0x07
    out["selected_pdu_session_type"] = _PDU_SESSION_TYPE_NAMES.get(pst, f"0x{pst:X}")
    out["selected_ssc_mode"] = (sel >> 4) & 0x07
    try:
        qos_val, pos = read_lv_e(body, 1)
        ambr_val, pos = read_lv(body, pos)
    except NasL3Error:
        # Couldn't step the mandatory IEs — fall back to the DNN-by-IEI scan
        # so a truncated/odd record still yields the groundable DNN.
        for i in range(len(body) - 1):
            if body[i] != _IEI_DNN_5GSM:
                continue
            length = body[i + 1]
            value = body[i + 2:i + 2 + length]
            if len(value) == length and length >= 2:
                dnn = decode_apn(value)
                if dnn and "." in dnn:
                    out["dnn"] = dnn
                    break
        return {"pdu_session_establishment_accept": out} if out else None
    qos = decode_qos_rules(qos_val)
    if qos is not None:
        out["authorized_qos_rules"] = qos["rules"]
    ambr = _decode_session_ambr(ambr_val)
    if ambr is not None:
        out["session_ambr"] = ambr
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(body[pos:], _PSEA_IE_TABLE):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_PSEA_5GSM_CAUSE and value:
            cause = value[0]
            out["sm_cause"] = cause
            out["sm_cause_name"] = _SM5G_CAUSE_NAMES.get(cause, f"0x{cause:02X}")
        elif iei == _IEI_PSEA_PDU_ADDRESS and value:
            # The network-assigned PDU address (TS 24.501 §9.11.4.10, same
            # positional layout as the EPS PDN address). A carrier-assigned IP
            # is ephemeral / non-identifying, and decoding the user's own
            # assignment is a goal — ship it in full.
            pdu_addr = decode_pdn_address(value)
            if pdu_addr is not None:
                out["pdu_address"] = pdu_addr
        elif iei == _IEI_PSEA_S_NSSAI:
            snssai = decode_s_nssai(value)
            if snssai is not None:
                out["s_nssai"] = snssai
        elif iei == _IEI_PSEA_ALWAYS_ON and value:
            out["always_on_pdu_session"] = bool(value[0] & 0x01)
        elif iei == _IEI_PSEA_QOS_FLOWS:
            flows = decode_qos_flow_descriptions(value)
            if flows is not None:
                out["authorized_qos_flow_descriptions"] = flows["flows"]
        elif iei == _IEI_DNN_5GSM:
            dnn = decode_apn(value)
            if dnn is not None:
                out["dnn"] = dnn
        # 0x75 mapped EPS bearer contexts / 0x7B extended PCO: recognized
        # (stepped cleanly over) but not yet field-decoded — no per-field
        # codec is implemented for them yet.
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return {"pdu_session_establishment_accept": out} if out else None


# ── 5GMM Registration Accept (0x42) — TS 24.501 §8.2.7 ────────────────────
# The headline 5GMM downlink message. It carries the network-assigned 5G-GUTI,
# the Allowed / Configured NSSAI (which network slices the UE may use), and the
# Equivalent PLMNs — all groundable against the camped carrier and previously
# opaque (only `nas_pdu` hex was surfaced). Now that the _nas_l3 IE codecs
# exist, this message decodes end-to-end: the mandatory 5GS
# registration result is an LV, and the rest are optional IEs walked by the
# shared table-driven walker. Only network-data / temporary-identity IEs are
# surfaced — the 5G-GUTI is a network-assigned temporary identity, NOT
# subscriber PII (a SUCI/SUPI never appears in a Registration *Accept*).
_IEI_RA_5G_GUTI = 0x77            # TLV-E — 5GS mobile identity (5G-GUTI)
_IEI_RA_TAI_LIST = 0x54           # TLV   — 5GS tracking area identity list
_IEI_RA_EQUIVALENT_PLMNS = 0x4A   # TLV   — Equivalent PLMNs
_IEI_RA_ALLOWED_NSSAI = 0x15      # TLV   — Allowed NSSAI
_IEI_RA_CONFIGURED_NSSAI = 0x31   # TLV   — Configured NSSAI

_REGISTRATION_ACCEPT_IE_TABLE: dict[int, IeSpec] = {
    _IEI_RA_5G_GUTI: IeSpec(IeFormat.TLV_E),
    _IEI_RA_TAI_LIST: IeSpec(IeFormat.TLV),
    _IEI_RA_EQUIVALENT_PLMNS: IeSpec(IeFormat.TLV),
    _IEI_RA_ALLOWED_NSSAI: IeSpec(IeFormat.TLV),
    _IEI_RA_CONFIGURED_NSSAI: IeSpec(IeFormat.TLV),
}

# TS 24.501 §9.11.3.6 — 5GS registration result value (low 3 bits of octet 1).
_5GS_REGISTRATION_RESULT_NAMES: dict[int, str] = {
    1: "3GPP access",
    2: "Non-3GPP access",
    3: "3GPP access and non-3GPP access",
}


# ── 5GSM PDU session establishment request (0xC1) — TS 24.501 §8.3.1 ───────
# The UE-side headline 5GSM message (the outgoing twin of the 0xC2 accept).
# Layout: a mandatory 2-octet Integrity-protection maximum data rate, then
# optional IEs — the requested PDU session type (type-1, IEI 0x9), SSC mode
# (type-1, IEI 0xA), always-on-requested (type-1, IEI 0xB), 5GSM capability
# (0x28), and extended PCO (0x7B). All network-policy / capability fields.
_IEI_PSER_PDU_SESSION_TYPE = 0x9   # TV1 — requested PDU session type
_IEI_PSER_SSC_MODE = 0xA           # TV1 — requested SSC mode
_IEI_PSER_ALWAYS_ON = 0xB          # TV1 — always-on PDU session requested
_IEI_PSER_5GSM_CAPABILITY = 0x28   # TLV — 5GSM capability
_IEI_PSER_EPCO = 0x7B              # TLV-E — extended protocol config options

_PSER_IE_TABLE: dict[int, IeSpec] = {
    _IEI_PSER_PDU_SESSION_TYPE: IeSpec(IeFormat.TV_SHORT),
    _IEI_PSER_SSC_MODE: IeSpec(IeFormat.TV_SHORT),
    _IEI_PSER_ALWAYS_ON: IeSpec(IeFormat.TV_SHORT),
    _IEI_PSER_5GSM_CAPABILITY: IeSpec(IeFormat.TLV),
    _IEI_PSER_EPCO: IeSpec(IeFormat.TLV_E),
}

# §9.11.4.3 — Integrity protection maximum data rate octet values.
_INTEGRITY_MAX_DATA_RATE = {0x00: "64 kbps", 0xFF: "full data rate"}


def _fmt_integrity_max_rate(octet: int) -> str:
    return _INTEGRITY_MAX_DATA_RATE.get(octet, f"0x{octet:02X}")


def _decode_pdu_session_establishment_request(body: bytes) -> dict[str, Any] | None:
    """Decode a PDU session establishment request (0xC1) — TS 24.501 §8.3.1.

    ``body`` is ``nas_pdu[4:]`` (after [EPD, pdu_session_id, pti, msg_type]).
    Decodes the mandatory 2-octet integrity-protection maximum data rate, then
    walks the optional IEs for the requested PDU session type / SSC mode /
    always-on flag (all type-1) and the 5GSM-capability presence. Network-policy
    / capability fields only.
    """
    if len(body) < 2:
        return None
    out: dict[str, Any] = {
        "integrity_max_data_rate_uplink": _fmt_integrity_max_rate(body[0]),
        "integrity_max_data_rate_downlink": _fmt_integrity_max_rate(body[1]),
    }
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(body[2:], _PSER_IE_TABLE):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_PSER_PDU_SESSION_TYPE and value:
            pst = value[0] & 0x07
            out["requested_pdu_session_type"] = _PDU_SESSION_TYPE_NAMES.get(
                pst, f"0x{pst:X}")
        elif iei == _IEI_PSER_SSC_MODE and value:
            out["requested_ssc_mode"] = value[0] & 0x07
        elif iei == _IEI_PSER_ALWAYS_ON and value:
            out["always_on_requested"] = bool(value[0] & 0x01)
        elif iei == _IEI_PSER_5GSM_CAPABILITY:
            out["has_5gsm_capability"] = True
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return {"pdu_session_establishment_request": out}


# ── 5GSM PDU session modification command (0xCB) — TS 24.501 §8.3.9 ────────
# Network->UE. Unlike the establishment accept, the modification command has NO
# mandatory IEs after the [EPD, pdu_session_id, pti, msg_type] header — every
# field is an optional IE, so the whole body is walked by the shared
# table-driven walker. Surfaced fields are the modification's network-policy
# payload: the 5GSM cause (why the network is modifying), the new Session-AMBR,
# the authorized QoS rules + flow descriptions, and the always-on indication.
# Observed example (RM520N-GL): a bare `81` body = the always-on
# PDU session indication IE (IEI 0x8, value 1 = "required"); cross-checked
# against the pycrate NAS-5GS oracle (5GSMPDUSessionModifCommand → AlwaysOnPDUSess
# Value 1) and TS 24.501 §9.11.4.1. The network-policy fields are decoded; the
# mapped-EPS-bearer (0x75) / extended-PCO (0x7B) containers are not yet
# field-decoded (no per-field codec implemented yet).
_IEI_PSMC_5GSM_CAUSE = 0x59        # TV   — 5GSM cause (§9.11.4.2)
_IEI_PSMC_SESSION_AMBR = 0x2A      # TLV  — Session-AMBR (§9.11.4.14)
_IEI_PSMC_BACKOFF_TIMER = 0x56     # TLV  — Back-off timer value (§9.11.2.5)
_IEI_PSMC_QOS_RULES = 0x7A         # TLV-E — Authorized QoS rules (§9.11.4.13)
_IEI_PSMC_MAPPED_EPS = 0x75        # TLV-E — Mapped EPS bearer contexts (§9.11.4.8)
_IEI_PSMC_QOS_FLOWS = 0x79         # TLV-E — Authorized QoS flow descriptions
_IEI_PSMC_ALWAYS_ON = 0x8          # TV1  — Always-on PDU session indication
_IEI_PSMC_EPCO = 0x7B              # TLV-E — Extended protocol config options

_PSMC_IE_TABLE: dict[int, IeSpec] = {
    _IEI_PSMC_5GSM_CAUSE: IeSpec(IeFormat.TV, length=1),
    _IEI_PSMC_SESSION_AMBR: IeSpec(IeFormat.TLV),
    _IEI_PSMC_BACKOFF_TIMER: IeSpec(IeFormat.TLV),
    _IEI_PSMC_QOS_RULES: IeSpec(IeFormat.TLV_E),
    _IEI_PSMC_MAPPED_EPS: IeSpec(IeFormat.TLV_E),
    _IEI_PSMC_QOS_FLOWS: IeSpec(IeFormat.TLV_E),
    _IEI_PSMC_ALWAYS_ON: IeSpec(IeFormat.TV_SHORT),
    _IEI_PSMC_EPCO: IeSpec(IeFormat.TLV_E),
}


def _decode_pdu_session_modification_command(body: bytes) -> dict[str, Any] | None:
    """Decode a PDU session modification command (0xCB) — TS 24.501 §8.3.9.

    ``body`` is ``nas_pdu[4:]`` (after [EPD, pdu_session_id, pti, msg_type]).
    The message has no mandatory IEs, so the whole body is the optional-IE
    part; walked by the shared table-driven walker. Surfaces the network-policy
    fields (5GSM cause, Session-AMBR, authorized QoS rules + flow descriptions,
    always-on indication). Returns ``None`` for an empty body, else the
    ``pdu_session_modification_command`` nas_body dict.
    """
    if not body:
        return None
    out: dict[str, Any] = {}
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(body, _PSMC_IE_TABLE):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_PSMC_5GSM_CAUSE and value:
            cause = value[0]
            out["sm_cause"] = cause
            out["sm_cause_name"] = _SM5G_CAUSE_NAMES.get(cause, f"0x{cause:02X}")
        elif iei == _IEI_PSMC_SESSION_AMBR:
            ambr = _decode_session_ambr(value)
            if ambr is not None:
                out["session_ambr"] = ambr
        elif iei == _IEI_PSMC_BACKOFF_TIMER and value:
            # GPRS timer 3 (§9.11.2.5) — surface raw; rarely present.
            out["back_off_timer"] = value.hex()
        elif iei == _IEI_PSMC_QOS_RULES:
            qos = decode_qos_rules(value)
            if qos is not None:
                out["authorized_qos_rules"] = qos["rules"]
        elif iei == _IEI_PSMC_QOS_FLOWS:
            flows = decode_qos_flow_descriptions(value)
            if flows is not None:
                out["authorized_qos_flow_descriptions"] = flows["flows"]
        elif iei == _IEI_PSMC_ALWAYS_ON and value:
            out["always_on_pdu_session"] = bool(value[0] & 0x01)
        # 0x75 mapped EPS bearer contexts / 0x7B extended PCO: recognized
        # (stepped cleanly over) but not yet field-decoded.
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return {"pdu_session_modification_command": out} if out else None


# 5GSM messages that carry an OPTIONAL 5GSM cause as a type-3 TV (IEI 0x59),
# rather than the leading mandatory octet handled by _decode_sm5g_cause. The UE
# PDU-session release request (0xD1) is the corpus example (cause "regular
# deactivation"). Maps msg_type → nas_body key.
_SM5G_OPTIONAL_CAUSE_MSGS: dict[int, str] = {
    0xD1: "pdu_session_release_request",
}
_IEI_SM5G_CAUSE_TV = 0x59


def _decode_sm5g_optional_cause(body: bytes, key: str) -> dict[str, Any] | None:
    """Decode an optional 5GSM cause carried as a TV (IEI 0x59) — TS 24.501
    §9.11.4.2. Used by messages (e.g. PDU session release request) whose cause
    is optional rather than the leading mandatory octet. Scans for the IEI."""
    for i in range(len(body) - 1):
        if body[i] == _IEI_SM5G_CAUSE_TV:
            cause = body[i + 1]
            return {key: {
                "sm_cause": cause,
                "sm_cause_name": _SM5G_CAUSE_NAMES.get(cause, f"0x{cause:02X}"),
            }}
    return None


def _decode_registration_accept(body: bytes) -> dict[str, Any] | None:
    """Decode a 5GMM Registration Accept (0x42) — TS 24.501 §8.2.7.

    ``body`` is ``nas_pdu[3:]`` (after [EPD=0x7e, sec_hdr=0, msg_type=0x42]).
    The mandatory first IE is the 5GS registration result (LV, length 1); the
    remaining IEs are optional and walked by the shared :func:`walk_optional_ies`
    table-driven framework. Surfaces the groundable network-assigned fields —
    5G-GUTI (temporary identity, not PII), the 5GS TAI list (the camped tracking
    area, groundable to the carrier), Allowed / Configured NSSAI, and Equivalent
    PLMNs — and records any unrecognized IEIs for forensic visibility. The 5GS
    TAI list (IEI 0x54) uses the dedicated :func:`decode_5gs_tai_list` codec
    (3-octet TAC), NOT the EPS 2-octet codec which would misalign it.
    """
    if len(body) < 2:
        return None
    # Mandatory 5GS registration result: LV (length octet + value octets).
    res_len = body[0]
    if res_len < 1 or 1 + res_len > len(body):
        return None
    result_octet = body[1]
    result_value = result_octet & 0x07
    out: dict[str, Any] = {
        "registration_result": result_value,
        "registration_result_name": _5GS_REGISTRATION_RESULT_NAMES.get(
            result_value, f"0x{result_value:X}"),
        "sms_over_nas_allowed": bool(result_octet & 0x08),
    }
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(
            body[1 + res_len:], _REGISTRATION_ACCEPT_IE_TABLE):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_RA_5G_GUTI:
            guti = decode_5gs_mobile_identity(value)
            if guti is not None:
                out["guti_5g"] = guti
        elif iei == _IEI_RA_TAI_LIST:
            tais = decode_5gs_tai_list(value)
            if tais is not None:
                out["tai_list"] = tais["tais"]
            else:
                unrecognized.append(iei)
        elif iei == _IEI_RA_EQUIVALENT_PLMNS:
            plmns = decode_plmn_list(value)
            if plmns is not None:
                out["equivalent_plmns"] = plmns["plmns"]
        elif iei == _IEI_RA_ALLOWED_NSSAI:
            nssai = decode_nssai(value)
            if nssai is not None:
                out["allowed_nssai"] = nssai["s_nssais"]
        elif iei == _IEI_RA_CONFIGURED_NSSAI:
            nssai = decode_nssai(value)
            if nssai is not None:
                out["configured_nssai"] = nssai["s_nssais"]
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return {"registration_accept": out}


# ── 5GMM Registration request (0x41) — TS 24.501 §8.2.6 ───────────────────
# The headline 5GMM uplink message — what the UE asserts when it (re-)registers.
# Layout: a packed type-1 octet (5GS registration type low nibble + ngKSI high
# nibble), then the mandatory 5GS mobile identity (LV-E — the GUTI/SUCI the UE
# presents), then optional IEs. Surfaced fields are groundable against the
# camped network: the asserted identity, the requested network slices, and the
# last visited registered TAI (the previous tracking area).
_5GS_REGISTRATION_TYPE_NAMES: dict[int, str] = {
    1: "initial registration",
    2: "mobility registration updating",
    3: "periodic registration updating",
    4: "emergency registration",
}

_IEI_RR_REQUESTED_NSSAI = 0x2F    # TLV   — Requested NSSAI
_IEI_RR_LAST_VISITED_TAI = 0x52   # TV    — Last visited registered TAI (6 oct)
_IEI_RR_ADDITIONAL_GUTI = 0x77    # TLV-E — Additional 5GS mobile identity (GUTI)
_IEI_RR_5GMM_CAPABILITY = 0x10    # TLV   — 5GMM capability
_IEI_RR_UE_SEC_CAPABILITY = 0x2E  # TLV   — UE security capability
_IEI_RR_S1_UE_NW_CAP = 0x17       # TLV   — S1 UE network capability

# Only the well-known TLV/TV optional IEs are tabled; the remaining (mostly
# type-1 half-octet) IEs are surfaced as unrecognized markers. The walker frames
# the tabled IEs positionally and best-effort-skips the rest.
_REGISTRATION_REQUEST_IE_TABLE: dict[int, IeSpec] = {
    _IEI_RR_5GMM_CAPABILITY: IeSpec(IeFormat.TLV),
    _IEI_RR_UE_SEC_CAPABILITY: IeSpec(IeFormat.TLV),
    _IEI_RR_REQUESTED_NSSAI: IeSpec(IeFormat.TLV),
    _IEI_RR_LAST_VISITED_TAI: IeSpec(IeFormat.TV, length=6),
    _IEI_RR_S1_UE_NW_CAP: IeSpec(IeFormat.TLV),
    _IEI_RR_ADDITIONAL_GUTI: IeSpec(IeFormat.TLV_E),
}


def _decode_registration_request(body: bytes) -> dict[str, Any] | None:
    """Decode a 5GMM Registration request (0x41) — TS 24.501 §8.2.6.

    ``body`` is ``nas_pdu[3:]`` (after [EPD=0x7e, sec_hdr=0, msg_type=0x41]).
    Decodes the mandatory packed registration-type/ngKSI octet and the 5GS
    mobile identity (the GUTI/SUCI the UE presents). Both are decoded faithfully
    : a GUTI/S-TMSI is a temporary identity, and a SUCI is decoded in full
    — a null-scheme SUCI carries the plaintext MSIN (the permanent IMSI), which
    is surfaced, never withheld. Then walks the optional IEs for the groundable
    ones: Requested NSSAI, Last visited registered TAI, and any additional GUTI.
    IEIs not yet modeled surface in ``unrecognized_ieis`` (a not-yet-modeled
    list, not a redaction bucket).
    """
    if len(body) < 1:
        return None
    reg_octet = body[0]
    reg_type = reg_octet & 0x07
    out: dict[str, Any] = {
        "registration_type": reg_type,
        "registration_type_name": _5GS_REGISTRATION_TYPE_NAMES.get(
            reg_type, f"0x{reg_type:X}"),
        "follow_on_request": bool(reg_octet & 0x08),
        "ngksi": (reg_octet >> 4) & 0x07,
    }
    try:
        mid, pos = read_lv_e(body, 1)
    except NasL3Error:
        return {"registration_request": out}
    identity = decode_5gs_mobile_identity(mid)
    if identity is not None:
        out["mobile_identity"] = identity
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(
            body[pos:], _REGISTRATION_REQUEST_IE_TABLE):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_RR_REQUESTED_NSSAI:
            nssai = decode_nssai(value)
            if nssai is not None:
                out["requested_nssai"] = nssai["s_nssais"]
        elif iei == _IEI_RR_LAST_VISITED_TAI:
            tai = decode_5gs_tai(value)
            if tai is not None:
                out["last_visited_registered_tai"] = tai
        elif iei == _IEI_RR_ADDITIONAL_GUTI:
            guti = decode_5gs_mobile_identity(value)
            if guti is not None:
                out["additional_guti"] = guti
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return {"registration_request": out}


# ── 5GMM Service request (0x4C) — TS 24.501 §8.2.27 ────────────────────────
# TS 24.501 §9.11.3.50 — service type (octet bits 1-4).
_SERVICE_TYPE_NAMES: dict[int, str] = {
    0: "signalling",
    1: "data",
    2: "mobile terminated services",
    3: "emergency services",
    4: "emergency services fallback",
    5: "high priority access",
    6: "elevated signalling",
}


def _decode_service_request(body: bytes) -> dict[str, Any] | None:
    """Decode a 5GMM Service request (0x4C) — TS 24.501 §8.2.27.

    ``body`` is ``nas_pdu[3:]`` (after [EPD=0x7e, sec_hdr=0, msg_type=0x4C]).
    The mandatory fields are the packed ngKSI (bits 5-8) + service type
    (bits 1-4) octet and the 5GS mobile identity (the 5G-S-TMSI, a temporary
    identity). Optional IEs (uplink/PDU-session status, NAS message container)
    are left to unrecognized markers.
    """
    if len(body) < 1:
        return None
    svc_octet = body[0]
    svc_type = svc_octet & 0x0F
    out: dict[str, Any] = {
        "service_type": svc_type,
        "service_type_name": _SERVICE_TYPE_NAMES.get(svc_type, f"0x{svc_type:X}"),
        "ngksi": (svc_octet >> 4) & 0x07,
    }
    try:
        mid, _ = read_lv_e(body, 1)
    except NasL3Error:
        return {"service_request": out}
    identity = decode_5gs_mobile_identity(mid)
    if identity is not None:
        out["mobile_identity"] = identity
    return {"service_request": out}


# TS 24.501 §8.2.10/§8.2.11 — the UL/DL NAS transport's OWN optional IEs, which
# sit AFTER the payload container. They are easy to miss: the container is a
# TLV-E whose length can run to hundreds of octets, so everything past it reads
# as trailing noise unless it is walked. The DNN here is the "which APN is this
# session for" field, and the request type distinguishes an initial request from
# a handover/emergency one.
_IEI_XPORT_PDU_SESSION_ID = 0x12      # TV    — PDU session ID (1 octet)
_IEI_XPORT_OLD_PDU_SESSION_ID = 0x59  # TV    — Old PDU session ID (1 octet)
_IEI_XPORT_REQUEST_TYPE = 0x8         # TV1   — Request type (type-1 half octet).
# A type-1 IEI is keyed by its NIBBLE VALUE (8), not the masked octet
# (0x80): walk_optional_ies looks up `(octet >> 4) & 0x0F` and yields that
# nibble as the iei. Keying 0x80 makes the row unreachable and the IE reads
# as unrecognized.
_IEI_XPORT_S_NSSAI = 0x22             # TLV   — S-NSSAI
_IEI_XPORT_DNN = 0x25                 # TLV   — DNN (TS 23.003 DNS-label form)
_IEI_XPORT_ADDITIONAL_INFO = 0x24     # TLV   — Additional information

_NAS_TRANSPORT_IE_TABLE: dict[int, IeSpec] = {
    _IEI_XPORT_PDU_SESSION_ID: IeSpec(IeFormat.TV, length=1),
    _IEI_XPORT_OLD_PDU_SESSION_ID: IeSpec(IeFormat.TV, length=1),
    _IEI_XPORT_REQUEST_TYPE: IeSpec(IeFormat.TV_SHORT),
    _IEI_XPORT_S_NSSAI: IeSpec(IeFormat.TLV),
    _IEI_XPORT_DNN: IeSpec(IeFormat.TLV),
    _IEI_XPORT_ADDITIONAL_INFO: IeSpec(IeFormat.TLV),
}

# TS 24.501 §9.11.3.47 — Request type (the type-1 IE's value half-octet).
_REQUEST_TYPE_NAMES: dict[int, str] = {
    1: "initial request",
    2: "existing PDU session",
    3: "initial emergency request",
    4: "existing emergency PDU session",
    5: "modification request",
    6: "MA PDU request",
    7: "reserved",
}


def _decode_dl_nas_transport(body: bytes) -> dict[str, Any] | None:
    """Decode a DL/UL NAS transport (0x68/0x67) — TS 24.501 §8.2.10/§8.2.11.

    ``body`` is ``nas_pdu[3:]`` (after [EPD, sec_hdr=0, msg_type]). Layout:
      [0]      Payload container type (type-1, low nibble) + spare half
      [1:3]    Payload container length (type-6 LV-E, 2-octet big-endian)
      [3:3+L]  Payload container value (e.g. an N1 SM 5GSM NAS message)
      [3+L:]   the transport's own optional IEs (PDU session ID, request
               type, DNN, S-NSSAI, ...)

    For an **N1 SM** container the value is itself a complete 5GSM NAS message
    ([EPD=0x2e, pdu_session_id, pti, msg_type] + body), so its header fields are
    surfaced and its body is dispatched through the shared
    :func:`_decode_5gsm_plain_body` — the same decoder the top-level 5GSM codes
    (0xB800/0xB801) use. Without that dispatch the transport's actual cargo — a
    PDU session establishment accept carrying the DNN, PDU address, QoS rules
    and Session-AMBR — is 138-177 octets of dropped payload.

    The container type check is load-bearing, not decoration. A **type 2
    (SMS)** container is not a 5GSM message; feeding those bytes to the 5GSM
    decoder would yield a confident and entirely fictional session decode.

    A container whose declared length exceeds the record is reported via
    ``container_truncated`` and NOT inner-decoded: the 4-octet header that IS
    present is real and is surfaced, but decoding the fragment past it would
    emit a partial, plausible-looking accept from bytes never captured.
    """
    if len(body) < 3:
        return None
    container_type = body[0] & 0x0F
    out: dict[str, Any] = {
        "payload_container_type": container_type,
        "payload_container_type_name": _PAYLOAD_CONTAINER_TYPE_NAMES.get(
            container_type, f"0x{container_type:X}"),
    }
    clen = (body[1] << 8) | body[2]
    container = body[3:3 + clen]
    truncated = len(container) < clen
    # N1 SM information: the container is itself a 5GSM NAS message
    # [EPD=0x2e, pdu_session_id, pti, msg_type].
    if container_type == 1 and len(container) >= 4 and container[0] == _EPD_5GSM:
        inner_mt = container[3]
        out["sm_pdu_session_id"] = container[1]
        out["sm_pti"] = container[2]
        out["sm_msg_type"] = inner_mt
        out["sm_msg_type_name"] = _SM5G_MSG_NAMES.get(inner_mt, f"0x{inner_mt:02X}")
        if truncated:
            out["container_truncated"] = True
        else:
            sm_body = _decode_5gsm_plain_body(inner_mt, container[4:])
            if sm_body is not None:
                out["sm_body"] = sm_body
    elif truncated:
        out["container_truncated"] = True
    # The transport's own optional IEs follow the container. Only walk them
    # when the container was complete -- otherwise the "IEs" would be the
    # container's own contents read at the wrong offset.
    if not truncated:
        unrecognized: list[int] = []
        for iei, value, recognized in walk_optional_ies(
                body[3 + clen:], _NAS_TRANSPORT_IE_TABLE):
            if not recognized:
                unrecognized.append(iei)
            elif iei == _IEI_XPORT_PDU_SESSION_ID and value:
                out["pdu_session_id"] = value[0]
            elif iei == _IEI_XPORT_OLD_PDU_SESSION_ID and value:
                out["old_pdu_session_id"] = value[0]
            elif iei == _IEI_XPORT_REQUEST_TYPE and value:
                # walk_optional_ies already delivers ONLY the value
                # nibble for a type-1 IE, so masking to 3 bits is not a
                # no-op: it would fold an out-of-range nibble (8-15) onto
                # a defined codepoint -- e.g. 9 -> 1 "initial request" --
                # fabricating a valid-looking value from an invalid one.
                # Surface the nibble as-is; the name table's fallback
                # reports an unassigned value honestly.
                rt = value[0]
                out["request_type"] = rt
                out["request_type_name"] = _REQUEST_TYPE_NAMES.get(rt, f"0x{rt:X}")
            elif iei == _IEI_XPORT_S_NSSAI:
                s_nssai = decode_s_nssai(value)
                if s_nssai is not None:
                    out["s_nssai"] = s_nssai
            elif iei == _IEI_XPORT_DNN:
                dnn = decode_apn(value)
                if dnn is not None:
                    out["dnn"] = dnn
            elif iei == _IEI_XPORT_ADDITIONAL_INFO:
                out["additional_information_hex"] = value.hex()
        if unrecognized:
            out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return {"dl_nas_transport": out}


# ── 5GMM Service accept (0x4E) — TS 24.501 §8.2.19 ────────────────────────
# Network->UE. All optional IEs; the corpus record carries the PDU session
# status (0x50) and PDU session reactivation result (0x26) — both 5GS-PSI
# bitmaps (§9.11.3.44), NOT PII. Surfaced as the list of active PDU session ids.
_IEI_SA_PDU_SESSION_STATUS = 0x50    # TLV — PDU session status (PSI bitmap)
_IEI_SA_PDU_REACT_RESULT = 0x26      # TLV — PDU session reactivation result

_SERVICE_ACCEPT_IE_TABLE: dict[int, IeSpec] = {
    _IEI_SA_PDU_SESSION_STATUS: IeSpec(IeFormat.TLV),
    _IEI_SA_PDU_REACT_RESULT: IeSpec(IeFormat.TLV),
}


def _psi_bitmap(value: bytes) -> list[int]:
    """Decode a 5GS PDU-session-status/PSI bitmap (§9.11.3.44) → active PSI ids.

    2-octet bitmap: octet 0 covers PSI 0-7 (bit i = PSI i), octet 1 covers
    PSI 8-15. PSI 0 is reserved (never a real session)."""
    ids: list[int] = []
    for octet_idx, octet in enumerate(value[:2]):
        for bit in range(8):
            if octet & (1 << bit):
                ids.append(octet_idx * 8 + bit)
    return ids


def _decode_service_accept(body: bytes) -> dict[str, Any] | None:
    """Decode a 5GMM Service accept (0x4E) — TS 24.501 §8.2.19.

    ``body`` is ``nas_pdu[3:]`` (after [EPD=0x7e, sec_hdr=0, msg_type=0x4e]).
    All IEs are optional; surfaces the PDU session status + reactivation result
    PSI bitmaps as lists of active PDU session ids. Non-PII."""
    out: dict[str, Any] = {}
    for iei, value, recognized in walk_optional_ies(body, _SERVICE_ACCEPT_IE_TABLE):
        if not recognized:
            continue
        if iei == _IEI_SA_PDU_SESSION_STATUS:
            out["pdu_session_status"] = _psi_bitmap(value)
        elif iei == _IEI_SA_PDU_REACT_RESULT:
            out["pdu_session_reactivation_result"] = _psi_bitmap(value)
    return {"service_accept": out} if out else None


# ── 5GMM Configuration update command (0x54) — TS 24.501 §8.2.19 ──────────
# Network->UE. No mandatory IEs — every field is an optional IE (§8.2.19). The
# groundable / WiGLE-relevant ones this decoder surfaces: the operator network
# name (full/short — the human-readable carrier string, GSM-7 or UCS-2), the NITZ
# time push (local time zone, universal time, daylight saving — all TS 24.008 IEs
# reused verbatim by 5G), the reassigned 5G-GUTI (a network-assigned
# temporary identity, NOT subscriber PII), and the updated TAI list (24-bit TAC —
# WiGLE-direct NR identity, same as Registration accept). The Configuration update
# indication half-octet flags whether the UE must acknowledge / re-register.
_IEI_CUC_CONFIG_UPDATE_INDICATION = 0xD  # TV1  (half-octet) — ACK/registration req
_IEI_CUC_5G_GUTI = 0x77                  # TLV-E — reassigned 5G-GUTI
_IEI_CUC_TAI_LIST = 0x54                 # TLV  — 5GS tracking area identity list
_IEI_CUC_ALLOWED_NSSAI = 0x15            # TLV  — Allowed NSSAI
_IEI_CUC_CONFIGURED_NSSAI = 0x31         # TLV  — Configured NSSAI
_IEI_CUC_FULL_NETWORK_NAME = 0x43        # TLV  — Full name for network
_IEI_CUC_SHORT_NETWORK_NAME = 0x45       # TLV  — Short name for network
_IEI_CUC_LOCAL_TIME_ZONE = 0x46          # TV   — Local time zone (1 octet)
_IEI_CUC_UNIVERSAL_TIME = 0x47           # TV   — Universal time + tz (7 octets)
_IEI_CUC_DST = 0x49                      # TLV  — Network daylight saving time

_CONFIG_UPDATE_CMD_IE_TABLE: dict[int, IeSpec] = {
    _IEI_CUC_CONFIG_UPDATE_INDICATION: IeSpec(IeFormat.TV_SHORT),
    _IEI_CUC_5G_GUTI: IeSpec(IeFormat.TLV_E),
    _IEI_CUC_TAI_LIST: IeSpec(IeFormat.TLV),
    _IEI_CUC_ALLOWED_NSSAI: IeSpec(IeFormat.TLV),
    _IEI_CUC_CONFIGURED_NSSAI: IeSpec(IeFormat.TLV),
    _IEI_CUC_FULL_NETWORK_NAME: IeSpec(IeFormat.TLV),
    _IEI_CUC_SHORT_NETWORK_NAME: IeSpec(IeFormat.TLV),
    _IEI_CUC_LOCAL_TIME_ZONE: IeSpec(IeFormat.TV, length=1),
    _IEI_CUC_UNIVERSAL_TIME: IeSpec(IeFormat.TV, length=7),
    _IEI_CUC_DST: IeSpec(IeFormat.TLV),
}


def _decode_configuration_update_command(body: bytes) -> dict[str, Any] | None:
    """Decode a 5GMM Configuration update command (0x54) — TS 24.501 §8.2.19.

    ``body`` is ``nas_pdu[3:]`` (after [EPD=0x7e, sec_hdr=0, msg_type=0x54]).
    All IEs are optional. Surfaces the operator network name, the NITZ time
    push (local time zone / universal time / DST), the reassigned 5G-GUTI (a
    temporary identity, not subscriber PII), and the updated TAI list. The
    network-name and time IEs are the TS 24.008 codecs shared with the LTE EMM
    Information message.
    """
    out: dict[str, Any] = {}
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(
            body, _CONFIG_UPDATE_CMD_IE_TABLE):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_CUC_CONFIG_UPDATE_INDICATION:
            # TV_SHORT: the walker returns the half-octet value as bytes([nibble]).
            nibble = value[0] if value else 0
            out["configuration_update_indication"] = {
                "acknowledgement_requested": bool(nibble & 0x1),
                "registration_requested": bool(nibble & 0x2),
            }
        elif iei == _IEI_CUC_5G_GUTI:
            guti = decode_5gs_mobile_identity(value)
            if guti is not None:
                out["guti"] = guti
        elif iei == _IEI_CUC_TAI_LIST:
            tai_list = decode_5gs_tai_list(value)
            if tai_list is not None:
                out["tai_list"] = tai_list
        elif iei in (_IEI_CUC_ALLOWED_NSSAI, _IEI_CUC_CONFIGURED_NSSAI):
            nssai = decode_nssai(value)
            if nssai is not None:
                key = ("allowed_nssai" if iei == _IEI_CUC_ALLOWED_NSSAI
                       else "configured_nssai")
                out[key] = nssai["s_nssais"]
        elif iei == _IEI_CUC_FULL_NETWORK_NAME:
            nn = decode_network_name(value)
            if nn is not None:
                out["network_name_full"], out["network_name_full_encoding"] = nn
        elif iei == _IEI_CUC_SHORT_NETWORK_NAME:
            nn = decode_network_name(value)
            if nn is not None:
                out["network_name_short"], out["network_name_short_encoding"] = nn
        elif iei == _IEI_CUC_LOCAL_TIME_ZONE:
            out["local_time_zone_qhrs"] = decode_local_time_zone(value)
        elif iei == _IEI_CUC_UNIVERSAL_TIME:
            ut = decode_universal_time(value)
            if ut is not None:
                out["universal_time"] = ut
        elif iei == _IEI_CUC_DST:
            out["dst_offset"] = decode_dst(value)
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return {"configuration_update_command": out} if out else None


# ── 5GMM Deregistration request (UE originating, 0x45) — TS 24.501 §8.2.12 ─
# UE->network. Layout: a mandatory packed octet (De-registration type in bits
# 1-4, ngKSI in bits 5-8) then the mandatory 5GS mobile identity (LV-E — the
# 5G-GUTI the UE presents as it detaches; a temporary identity, WiGLE-relevant
# NR identity, NOT subscriber PII). §9.11.3.20 de-registration type.
_5GS_DEREG_ACCESS_TYPE_NAMES: dict[int, str] = {
    1: "3GPP access",
    2: "non-3GPP access",
    3: "3GPP access and non-3GPP access",
}


def _decode_deregistration_request_originating(body: bytes) -> dict[str, Any] | None:
    """Decode a 5GMM Deregistration request (UE originating, 0x45) — §8.2.12.

    ``body`` is ``nas_pdu[3:]`` (after [EPD=0x7e, sec_hdr=0, msg_type=0x45]).
    Decodes the mandatory De-registration-type/ngKSI octet (switch-off flag +
    access type) and the mandatory 5GS mobile identity (the 5G-GUTI the UE
    presents — a temporary identity).
    """
    if len(body) < 1:
        return None
    dereg_octet = body[0]
    access_type = dereg_octet & 0x03
    out: dict[str, Any] = {
        "switch_off": bool(dereg_octet & 0x08),
        "access_type": access_type,
        "access_type_name": _5GS_DEREG_ACCESS_TYPE_NAMES.get(
            access_type, f"0x{access_type:X}"),
        "ngksi": (dereg_octet >> 4) & 0x07,
    }
    try:
        mid, _ = read_lv_e(body, 1)
    except NasL3Error:
        return {"deregistration_request": out}
    identity = decode_5gs_mobile_identity(mid)
    if identity is not None:
        out["mobile_identity"] = identity
    return {"deregistration_request": out}


# ── 5GMM Security mode command (0x5D) — TS 24.501 §8.2.25 ──────────────────
# Network->UE. The headline security-posture message: the network's SELECTED
# NAS security algorithms (which 5G ciphering + integrity algorithm the session
# will use — including the null cipher 5G-EA0, a genuine security signal), the
# ngKSI, and the replayed UE security capabilities. §9.11.3.34 algorithm tables.
# No subscriber identity — algorithm + capability bitmaps only.
_5G_CIPH_ALGO_NAMES: dict[int, str] = {
    0: "5G-EA0 (null)",
    1: "128-5G-EA1",
    2: "128-5G-EA2",
    3: "128-5G-EA3",
    4: "5G-EA4", 5: "5G-EA5", 6: "5G-EA6", 7: "5G-EA7",
}
_5G_INTEG_ALGO_NAMES: dict[int, str] = {
    0: "5G-IA0 (null)",
    1: "128-5G-IA1",
    2: "128-5G-IA2",
    3: "128-5G-IA3",
    4: "5G-IA4", 5: "5G-IA5", 6: "5G-IA6", 7: "5G-IA7",
}
_IEI_SMC_IMEISV_REQUEST = 0xE     # TV1 — IMEISV request

_SMC_IE_TABLE: dict[int, IeSpec] = {
    _IEI_SMC_IMEISV_REQUEST: IeSpec(IeFormat.TV_SHORT),
}


def _decode_security_mode_command(body: bytes) -> dict[str, Any] | None:
    """Decode a 5GMM Security mode command (0x5D) — TS 24.501 §8.2.25.

    ``body`` is ``nas_pdu[3:]`` (after [EPD=0x7e, sec_hdr=0, msg_type=0x5d]).
    Mandatory prefix: selected NAS security algorithms (V, 1) + ngKSI (V, 1/2)
    + replayed UE security capabilities (LV). Then optional IEs (the IMEISV
    request flag is surfaced; others are best-effort skipped). Surfaces the
    negotiated ciphering / integrity algorithm (with a ``null_cipher`` flag when
    5G-EA0 is selected) and the ngKSI. Cross-checked against the pycrate NAS-5GS
    oracle. No PII — algorithm/capability bitmaps only.
    """
    if len(body) < 2:
        return None
    algo = body[0]
    ciph = (algo >> 4) & 0x0F
    integ = algo & 0x0F
    ngksi = body[1]
    out: dict[str, Any] = {
        "ciphering_algorithm": _5G_CIPH_ALGO_NAMES.get(ciph, f"0x{ciph:X}"),
        "integrity_algorithm": _5G_INTEG_ALGO_NAMES.get(integ, f"0x{integ:X}"),
        "null_cipher": ciph == 0,
        "null_integrity": integ == 0,
        "ngksi": ngksi & 0x07,
        "ngksi_tsc": (ngksi >> 3) & 0x01,
    }
    # Replayed UE security capabilities (LV) then optional IEs.
    try:
        _uecap, pos = read_lv(body, 2)
    except NasL3Error:
        return {"security_mode_command": out}
    for iei, value, recognized in walk_optional_ies(body[pos:], _SMC_IE_TABLE):
        if recognized and iei == _IEI_SMC_IMEISV_REQUEST and value:
            out["imeisv_requested"] = bool(value[0] & 0x01)
    return {"security_mode_command": out}


# 3GPP TS 24.501 §9.3.1 — security header type (5GMM byte[1]).
_SEC_HDR_TYPE_NAMES: dict[int, str] = {
    0: "Plain 5GS NAS message",
    1: "Integrity protected",
    2: "Integrity protected and ciphered",
    3: "Integrity protected with new 5G NAS security context",
    4: "Integrity protected and ciphered with new 5G NAS security context",
}

_EPD_5GMM = 0x7E
_EPD_5GSM = 0x2E
_EPD_NAMES: dict[int, str] = {_EPD_5GMM: "5GMM", _EPD_5GSM: "5GSM"}

# 3GPP TS 24.501 §9.3.1: security header types 1 ("integrity protected") and 3
# ("integrity protected with new 5G NAS security context") are NOT ciphered, so
# the inner NAS PDU is plaintext and its message type is recoverable. Types 2/4
# additionally cipher the inner message, leaving it opaque.
_INTEGRITY_ONLY_SEC_HDR_TYPES = frozenset({1, 3})


def _decode_5gsm_plain_body(msg_type: int, body: bytes) -> dict[str, Any] | None:
    """Dispatch a plaintext 5GSM message body by message type.

    ``body`` is the bytes after the 4-octet 5GSM header
    ([EPD=0x2e, pdu_session_id, pti, msg_type]). The 5GSM twin of
    :func:`_decode_5gmm_plain_body`, extracted from the inline dispatch in
    :func:`_parse_nr5g_nas_ota` so the **N1-SM payload container**
    inside a UL/DL NAS transport can reach the same decoders — an embedded
    5GSM message and a top-level one are the same bytes and must decode
    identically. Returns the per-type nas_body dict or ``None``.
    """
    if msg_type in _SM5G_CAUSE_MSGS:
        # Reject/release/status lead with a mandatory 5GSM cause octet
        # (TS 24.501 §9.11.4.2).
        return _decode_sm5g_cause(body, _SM5G_CAUSE_MSGS[msg_type])
    if msg_type == 0xC2:    # PDU session establishment accept — DNN (5G APN)
        return _decode_pdu_session_establishment_accept(body)
    if msg_type == 0xC1:    # PDU session establishment request (outgoing)
        return _decode_pdu_session_establishment_request(body)
    if msg_type == 0xCB:    # PDU session modification command (all optional IEs)
        return _decode_pdu_session_modification_command(body)
    if msg_type in _SM5G_OPTIONAL_CAUSE_MSGS:   # e.g. release request — opt cause
        return _decode_sm5g_optional_cause(body, _SM5G_OPTIONAL_CAUSE_MSGS[msg_type])
    return None


def _decode_5gmm_plain_body(msg_type: int, body: bytes) -> dict[str, Any] | None:
    """Dispatch a plaintext 5GMM message body by message type.

    ``body`` is the bytes after the 3-octet plain 5GMM header
    ([EPD=0x7e, sec_hdr=0, msg_type]). Shared by the outer plain-5GMM path and
    the integrity-only inner-plaintext path so both decode the same
    message types identically. Returns the per-type nas_body dict or ``None``.
    """
    if msg_type in _MM5G_CAUSE_MSGS:
        return _decode_mm5g_cause(body, _MM5G_CAUSE_MSGS[msg_type])
    if msg_type == 0x42:    # Registration accept — 5G-GUTI / TAI list / NSSAI
        return _decode_registration_accept(body)
    if msg_type == 0x41:    # Registration request — UE-asserted identity etc.
        return _decode_registration_request(body)
    if msg_type == 0x4C:    # Service request — service type + 5G-S-TMSI
        return _decode_service_request(body)
    if msg_type == 0x4E:    # Service accept — PDU session status bitmaps
        return _decode_service_accept(body)
    if msg_type == 0x54:    # Configuration update command — NITZ / net name / GUTI
        return _decode_configuration_update_command(body)
    if msg_type == 0x45:    # Deregistration request (UE originating) — GUTI
        return _decode_deregistration_request_originating(body)
    if msg_type == 0x5D:    # Security mode command — negotiated NAS sec algos
        return _decode_security_mode_command(body)
    if msg_type in (0x67, 0x68):  # UL/DL NAS transport — payload container
        return _decode_dl_nas_transport(body)
    return None


def _decode_inner_plaintext_nas(
    inner: bytes,
) -> tuple[int, int | None, int | None, str | None] | None:
    """Decode a plaintext (integrity-only) inner 5G NAS message header.

    The inner PDU is a full NAS message starting with its own EPD. For 5GMM
    (0x7e) it is ``[EPD, sec_hdr_type, msg_type, ...]`` (the inner is itself
    plain, so its sec_hdr_type is 0); for 5GSM (0x2e) it is
    ``[EPD, pdu_session_id, pti, msg_type, ...]``. Returns
    ``(inner_epd, inner_sec_hdr_type, inner_msg_type, inner_msg_type_name)`` or
    ``None`` if the inner is too short to read a message type.
    """
    if len(inner) < 3:
        return None
    inner_epd = inner[0]
    if inner_epd == _EPD_5GSM:
        if len(inner) < 4:
            return None
        msg_type = inner[3]
        return inner_epd, None, msg_type, _SM5G_MSG_NAMES.get(msg_type, f"0x{msg_type:02X}")
    # 5GMM (0x7e) or unknown EPD: [EPD, sec_hdr_type, msg_type].
    inner_sec_hdr = inner[1]
    msg_type = inner[2]
    return inner_epd, inner_sec_hdr, msg_type, _MM5G_MSG_NAMES.get(msg_type, f"0x{msg_type:02X}")

_DIAG_HDR_SIZE = 7  # u32 version + rrc_rel + rrc_ver_major + rrc_ver_minor

# byte[0:4] is the DIAG NR-NAS wrapper version (u32 LE). Corpus-invariant 1
# across all 41 band records (7 Compal RXM-G1 SDX55 captures). Layer-1 gated
# so a future version != 1 emission is rejected rather than mis-parsed against
# this wrapper layout (size-invariance != format-invariance core memory).
_NAS_OTA_VERSION_OBSERVED = 1


@dataclass
class Nr5gNasOtaMsg:
    """Parsed NR5G NAS OTA message (5GMM or 5GSM).

    Shared by 0xB800/0xB801/0xB808/0xB809/0xB80A. ``type_name`` is set by
    the per-code parser to the ID-only string (``"Diag0xB80A"`` etc.).
    """
    log_time: int
    log_code: int
    # True/False for the directional codes (0xB80A incoming / 0xB80B outgoing
    # etc.); None for the non-directional container code 0xB814
    # (5GNR_NAS_5GMM_PLAIN_OTA_CONTAINER carries no IN/OUT in its canonical name).
    is_uplink: bool | None
    version: int            # byte[0:4] u32 LE — DIAG NR-NAS wrapper version
    rrc_rel: int
    rrc_ver_major: int
    rrc_ver_minor: int
    epd: int                # 5G extended protocol discriminator (0x7e/0x2e)
    epd_name: str
    # 5GMM only: security header type (byte[1] of NAS PDU); None for 5GSM.
    sec_hdr_type: int | None
    sec_hdr_type_name: str | None
    # 5GSM only (EPD 0x2e).
    pdu_session_id: int | None
    pti: int | None
    # 5GMM security-protected only (sec_hdr_type 1-4): 4-octet NAS-MAC (MSB
    # first, TS 24.501 §9.8) + sequence number.
    mac: int | None
    seq: int | None
    # msg_type is None for security-protected 5GMM (the type lives in the
    # protected — possibly ciphered — inner message at nas_pdu[7:]).
    msg_type: int | None
    msg_type_name: str | None
    # Integrity-only security-protected 5GMM (sec_hdr_type 1 or 3) is NOT
    # ciphered, so the inner NAS message at nas_pdu[7:] is plaintext and its
    # type is recoverable. None for plain records (no inner) and
    # for ciphered protection (sec_hdr_type 2/4 — inner is opaque ciphertext).
    inner_epd: int | None
    inner_sec_hdr_type: int | None
    inner_msg_type: int | None
    inner_msg_type_name: str | None
    nas_pdu: bytes
    payload_size: int
    # Optional layer-2 NAS-body decode. Populated only for plain (sec_hdr_type=0
    # 5GMM / 5GSM) reject and status messages whose body begins with a single
    # mandatory 5GMM/5GSM cause octet (TS 24.501 §9.11.3.2 / §9.11.4.2). Other
    # message types leave this None.
    nas_body: dict[str, Any] | None = None
    type_name: str = "Nr5gNasOtaMsg"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': self.type_name,
            'log_time': self.log_time,
            'log_code': f"0x{self.log_code:04X}",
            'version': self.version,
            'rrc_rel': self.rrc_rel,
            'rrc_ver_major': self.rrc_ver_major,
            'rrc_ver_minor': self.rrc_ver_minor,
            'epd': self.epd,
            'epd_name': self.epd_name,
            'msg_type': self.msg_type,
            'msg_type_name': self.msg_type_name,
            'payload_size': self.payload_size,
            'nas_pdu_hex': self.nas_pdu.hex(),
        }
        if self.is_uplink is not None:
            d['is_uplink'] = self.is_uplink
        if self.sec_hdr_type is not None:
            d['sec_hdr_type'] = self.sec_hdr_type
            d['sec_hdr_type_name'] = self.sec_hdr_type_name
        if self.pdu_session_id is not None:
            d['pdu_session_id'] = self.pdu_session_id
            d['pti'] = self.pti
        if self.mac is not None:
            d['mac'] = self.mac
            d['seq'] = self.seq
        if self.inner_msg_type is not None:
            d['inner_epd'] = self.inner_epd
            d['inner_sec_hdr_type'] = self.inner_sec_hdr_type
            d['inner_msg_type'] = self.inner_msg_type
            d['inner_msg_type_name'] = self.inner_msg_type_name
        if self.nas_body is not None:
            d['nas_body'] = self.nas_body
        return d


def _parse_nr5g_nas_ota(
    log_time: int,
    data: bytes,
    log_code: int,
    is_uplink: bool | None,
    type_name: str,
) -> Nr5gNasOtaMsg | None:
    if len(data) < _DIAG_HDR_SIZE + 1:
        return None

    # Layer-1 version gate: u32 LE wrapper version, corpus-invariant 1.
    # The per-code parsers carry a duplicate explicit byte[0] gate so the
    # static gate-ratchet (which does not follow this cross-module import)
    # can see it.
    version = unpack_from('<I', data, 0)[0]
    if version != _NAS_OTA_VERSION_OBSERVED:
        return None
    rrc_rel = data[4]
    rrc_ver_major = data[5]
    rrc_ver_minor = data[6]
    nas_pdu = data[_DIAG_HDR_SIZE:]

    epd = nas_pdu[0]
    epd_name = _EPD_NAMES.get(epd, f"0x{epd:02X}")

    sec_hdr_type: int | None = None
    sec_hdr_type_name: str | None = None
    pdu_session_id: int | None = None
    pti: int | None = None
    mac: int | None = None
    seq: int | None = None
    msg_type: int | None = None
    msg_type_name: str | None = None
    inner_epd: int | None = None
    inner_sec_hdr_type: int | None = None
    inner_msg_type: int | None = None
    inner_msg_type_name: str | None = None

    nas_body: dict[str, Any] | None = None

    if epd == _EPD_5GSM:  # [EPD, pdu_session_id, pti, msg_type]
        if len(nas_pdu) < 4:
            return None
        pdu_session_id = nas_pdu[1]
        pti = nas_pdu[2]
        msg_type = nas_pdu[3]
        msg_type_name = _SM5G_MSG_NAMES.get(msg_type, f"0x{msg_type:02X}")
        # Body decode by message type. nas_pdu[4:] is the body after the
        # 4-octet 5GSM header. Shared with the N1-SM payload-container path
        # so an embedded 5GSM message decodes identically to a
        # top-level one.
        nas_body = _decode_5gsm_plain_body(msg_type, nas_pdu[4:])
    else:  # 5GMM (0x7e) or unknown — [EPD, sec_hdr_type, ...]
        if len(nas_pdu) < 2:
            return None
        sec_hdr_type = nas_pdu[1]
        sec_hdr_type_name = _SEC_HDR_TYPE_NAMES.get(sec_hdr_type, f"0x{sec_hdr_type:X}")
        if sec_hdr_type == 0:
            # Plain 5GMM — byte[2] is the message type.
            if len(nas_pdu) < 3:
                return None
            msg_type = nas_pdu[2]
            msg_type_name = _MM5G_MSG_NAMES.get(msg_type, f"0x{msg_type:02X}")
            # Body decode by message type (shared with the inner-plaintext path).
            # nas_pdu[3:] is the body after [EPD, sec_hdr=0, msg_type].
            nas_body = _decode_5gmm_plain_body(msg_type, nas_pdu[3:])
        else:
            # Security-protected 5GMM (TS 24.501 §9.1.1): byte[2:6] is the
            # 4-octet NAS message authentication code (MSB first), byte[6] is
            # the sequence number, byte[7:] is the protected inner NAS message.
            if len(nas_pdu) < 7:
                return None
            mac = unpack_from('>I', nas_pdu, 2)[0]
            seq = nas_pdu[6]
            # Integrity-only protection (sec_hdr_type 1/3) does NOT cipher the
            # inner message, so its header is plaintext and the message type is
            # recoverable. Ciphered protection (2/4) leaves the
            # inner opaque — left undecoded.
            if sec_hdr_type in _INTEGRITY_ONLY_SEC_HDR_TYPES:
                inner = nas_pdu[7:]
                decoded = _decode_inner_plaintext_nas(inner)
                if decoded is not None:
                    (inner_epd, inner_sec_hdr_type,
                     inner_msg_type, inner_msg_type_name) = decoded
                    # The inner plaintext is a full 5GMM message — decode its
                    # body too, reusing the shared plain-5GMM dispatch.
                    # Inner layout: [EPD=0x7e, sec_hdr=0, msg_type, body...].
                    if (inner_epd == _EPD_5GMM and inner_msg_type is not None
                            and len(inner) >= 3):
                        nas_body = _decode_5gmm_plain_body(inner_msg_type, inner[3:])

    return Nr5gNasOtaMsg(
        log_time=log_time,
        log_code=log_code,
        is_uplink=is_uplink,
        version=version,
        rrc_rel=rrc_rel,
        rrc_ver_major=rrc_ver_major,
        rrc_ver_minor=rrc_ver_minor,
        epd=epd,
        epd_name=epd_name,
        sec_hdr_type=sec_hdr_type,
        sec_hdr_type_name=sec_hdr_type_name,
        pdu_session_id=pdu_session_id,
        pti=pti,
        mac=mac,
        seq=seq,
        msg_type=msg_type,
        msg_type_name=msg_type_name,
        inner_epd=inner_epd,
        inner_sec_hdr_type=inner_sec_hdr_type,
        inner_msg_type=inner_msg_type,
        inner_msg_type_name=inner_msg_type_name,
        nas_pdu=nas_pdu,
        payload_size=len(data),
        nas_body=nas_body,
        type_name=type_name,
    )
