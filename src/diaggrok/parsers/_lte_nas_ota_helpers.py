# diaggrok-provenance: re
"""Shared dataclass + wrapper-parser for LTE NAS Plain OTA parsers
(0xB0E2, 0xB0E3, 0xB0EC, 0xB0ED).

Skipped by ``parsers/__init__.py`` auto-discovery because of the leading
underscore. Imported directly by the four per-code parser modules
(``diag_0xb0e2.py``, ``diag_0xb0e3.py``, ``diag_0xb0ec.py``, ``diag_0xb0ed.py``).

DIAG wrapper layout (all four codes; invariant ``01 09 05 00``
across every 0xB0E2/0xB0E3/0xB0EC/0xB0ED record observed — 80+ captures
spanning Foxconn / Inseego / Quectel EG25-G/EG95/RM520N / Sierra, every
record byte[0]==0x01, byte[1]==0x09, byte[2]==0x05, byte[3]==0x00):
    [0]     u8   version  (DIAG NAS extended-header version; legacy name
                           ``ext_header_ver``; Layer-1 gated on 0x01)
    [1]     u8   rrc_rel
    [2]     u8   rrc_ver_major
    [3]     u8   rrc_ver_minor
    [4:]    bytes NAS PDU (raw)

Clean-room basis: the wrapper offsets above are derived from DIAG captures
plus a vendor decoder's rendered output (below) — not from any third-party
decoder's source. The ``_nr5g_nas_ota_helpers.py`` sibling's wrapper is
likewise capture-derived. The inner NAS PDU parsing is straight 3GPP
TS 24.301 §9 (pure interface facts).

Field naming follows 3GPP TS 24.301 release-version convention. The
combined ``rrc_rel.rrc_ver_major.rrc_ver_minor`` reads as e.g. "9.5.0",
matching the published 3GPP release patch (byte[2] is the major, byte[3]
the minor version). Ground truth (a vendor decoder's rendered *output*):
it prints ``pkt_version`` at byte[0], ``rel_number`` at byte[1],
``rel_version_major`` at byte[2] and ``rel_version_minor`` at byte[3].

NAS PDU (3GPP TS 24.301 §9):
    EMM (prot_disc=7):
        sec_hdr_type=0:  [sec_hdr|prot_disc, msg_type, ...]   (plain)
        sec_hdr_type=12: [sec_hdr|prot_disc, KSI|seq, ShortMAC(2)]
                         — Service Request short form; no msg_type byte.
        sec_hdr_type=1-4 are integrity/cipher-protected NAS containers and
        do not appear in 0xB0EC/0xB0ED: those codes log the PLAIN inner
        message after the security header is stripped (F3, below). The
        protected outer is logged elsewhere (0xB0EA in, 0xB0EB out); if one
        were seen here, byte[1:5]=MAC, byte[5]=seq, inner NAS at byte[6:].
    ESM (prot_disc=2):  [eps_bearer_id|prot_disc, pti, msg_type, ...]

F3 grounding of v0x01
---------------------
The modem's own F3 prints, on the same DIAG tick (|dt| <= 1.25 ms) as each
record, name the fields this layout decodes. 16 captures, 6 chipset
generations (MDM9607 EG25-G; MDM9x50/SDX20 EM7565 + LM960; SDX24 EM120R;
SDX55 LV55/FT980m/RM500Q; SDX62 RM520N-GL). Of 198 v0x01 records, 93 carry
a label and every label agrees with the decode. The rest are F3-silent: QSR4
strings with no matched qdb, or no print site on that path.

  code    F3 site (file: print)                              grounds         MATCH
  0xB0EC  lte_nas_msg_parse.c: "MSG ID %d received" /        msg_type        22
          "Message ID -> NAME" / "NAME(SHDR = %d) decoding"
  0xB0ED  emm_rrc_if.c: "... SIM_UPDATE_REQ ... msg_id = %d"  msg_type        30
  0xB0E3  emm_rrc_if.c msg_id + esm_utils.c "carrying NAME"   msg_type        15
  0xB0E2  esm_bpm.c: "Rcved assigned PTI %d w/ msg %d"        pti + msg_type  11

Facts the F3 adds beyond the field values:

* Direction: the DL parse prints sit on 0xB0EC ticks and the send-path prints
  sit on 0xB0ED ticks, so 0xB0EC = incoming and 0xB0ED = outgoing. That
  matches the vendor decoder's render ("EMM Plain OTA Incoming" = 0xB0EC).
  Some name tables swap the two canonical names.
* Plain means "after the security header": the same tick that logs a 0xB0EC
  record with sec_hdr nibble 0 prints "Rcved DL MSG w/ security head 2" (or 3
  for the SMC). The record is the deciphered inner message.
* 0xB0E1 is the security-protected outer of an outgoing ESM message. It is
  logged on the same tick as its 0xB0E3 plain twin, is exactly 6 octets longer
  (sec hdr + MAC(4) + SQN), and the F3 prints "NAS message is security
  protected". Its inner equals the 0xB0E3 PDU byte-for-byte when the
  co-captured SMC picked EEA0, and is ciphered otherwise.
* Incoming protected ESM is logged as 0xB0EA (the EMM-protected code) plus the
  plain 0xB0E2. 0xB0E0 is not emitted on any of these builds.
* Length is grounded too, so a record's PDU is the whole message, not a
  prefix. 0xB0EC: F3 "DSM DL Data found! item len N" equals len(nas_pdu) when
  the outer security head was 0, and len(nas_pdu) + 6 when it was 2 or 3. That
  held on 18/18 labelled records (EM7565, EM120R, LM960 x2). 0xB0ED: F3
  "dsm push len N" equals len(nas_pdu) + 6 for 18 protected messages and
  len(nas_pdu) for 5 unprotected ones.
* EG25-G (MDM9607) 0xB0ED records from one firmware build end in 6 zero octets that the other
  builds do not log. On 5/5 records F3's DSM length equals the padded PDU
  (e.g. "DSM conn_est_req item len 21" for a 15-octet Detach Request), so the
  firmware logs the buffer it reserved for sec hdr + MAC + SQN. The structural
  check below stops at the zero IEI, so the tail is tolerated and never
  judged.

A capture whose qdb is an ambiguous tiebreak can render a wrong message
NAME for a correct numeric arg: one LM960 capture prints
"GUTI REALLOCATION COMMAND(SHDR = 0)" on the tick where its own numeric arg
says msg 85 (Identity request, as decoded). Ground on the numeric args, not on
names from an unconfirmed string table.

Sources: 3GPP TS 24.301 §9 (NAS message types + IE layout); DIAG captures
+ a vendor decoder's rendered output (clean-room wrapper derivation). SCAT
and QCSuper output is used as an A/B cross-check.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

# 3GPP TS 24.301 §9.8.1 Table 9.8.1 — EMM message types.
# The spec has unassigned gaps at 0x47, 0x57-0x5B, 0x65-0x67; listing names
# sequentially without honoring those gaps shifts the upper half of the
# table. tshark dissection of SCAT/QCSuper pcaps confirms the spec values
# independently: observed 0x5E records dissect as "Security mode complete".
_EMM_MSG_NAMES: dict[int, str] = {
    0x41: "Attach request",
    0x42: "Attach accept",
    0x43: "Attach complete",
    0x44: "Attach reject",
    0x45: "Detach request",
    0x46: "Detach accept",
    0x48: "TAU request",
    0x49: "TAU accept",
    0x4A: "TAU complete",
    0x4B: "TAU reject",
    0x4C: "Extended service request",
    0x4D: "Control plane service request",
    0x4E: "Service reject",
    0x4F: "Service accept",
    0x50: "GUTI reallocation command",
    0x51: "GUTI reallocation complete",
    0x52: "Authentication request",
    0x53: "Authentication response",
    0x54: "Authentication reject",
    0x55: "Identity request",
    0x56: "Identity response",
    0x5C: "Authentication failure",
    0x5D: "Security mode command",
    0x5E: "Security mode complete",
    0x5F: "Security mode reject",
    0x60: "EMM status",
    0x61: "EMM information",
    0x62: "Downlink NAS transport",
    0x63: "Uplink NAS transport",
    0x64: "CS service notification",
    0x68: "Downlink generic NAS transport",
    0x69: "Uplink generic NAS transport",
}

# 3GPP TS 24.301 §9.9 — ESM message types
_ESM_MSG_NAMES: dict[int, str] = {
    0xC1: "Activate default EPS bearer context request",
    0xC2: "Activate default EPS bearer context accept",
    0xC3: "Activate default EPS bearer context reject",
    0xC5: "Activate dedicated EPS bearer context request",
    0xC6: "Activate dedicated EPS bearer context accept",
    0xC7: "Activate dedicated EPS bearer context reject",
    0xC9: "Modify EPS bearer context request",
    0xCA: "Modify EPS bearer context accept",
    0xCB: "Modify EPS bearer context reject",
    0xCD: "Deactivate EPS bearer context request",
    0xCE: "Deactivate EPS bearer context accept",
    0xD0: "PDN connectivity request",
    0xD1: "PDN connectivity reject",
    0xD2: "PDN disconnect request",
    0xD3: "PDN disconnect reject",
    0xD4: "Bearer resource allocation request",
    0xD5: "Bearer resource allocation reject",
    0xD6: "Bearer resource modification request",
    0xD7: "Bearer resource modification reject",
    0xD9: "ESM information request",
    0xDA: "ESM information response",
    0xDB: "Notification",
    0xDC: "ESM dummy message",
    0xE8: "ESM status",
}

_PROT_DISC_NAMES: dict[int, str] = {
    2: "ESM",
    7: "EMM",
}

# 3GPP TS 24.301 §9.3.1 — Security header type values (upper nibble of EMM
# byte[0]). Only values that can legitimately appear in a "plain OTA" code
# are named here; reserved values render as the raw int.
_SEC_HDR_TYPE_NAMES: dict[int, str] = {
    0: "Plain NAS message",
    1: "Integrity protected",
    2: "Integrity protected and ciphered",
    3: "Integrity protected with new EPS security context",
    4: "Integrity protected and ciphered with new EPS security context",
    12: "Service request",
}

_DIAG_HDR_SIZE = 4  # version(ext_header_ver) + rrc_rel + ver_major + ver_minor

# byte[0] is the DIAG NAS extended-header version (legacy field name
# ``ext_header_ver``). Invariant 0x01 across every observed 0xB0E2/0xB0E3/
# 0xB0EC/0xB0ED record (E2=164, E3=159, EC=130, ED=283 records, all
# byte-0 == 0x01) AND the vendor decoder's rendered traces (pkt_version=1).
# Sibling 0xB0E1 gates the same byte on {0x01}. Layer-1 gated here.
_NAS_OTA_VERSION_OBSERVED = 0x01


# ── NAS message structural-completeness check ──────────────────────────────
#
# The DIAG wrapper carries NO length field — the NAS PDU is "the rest of the
# record" — so a truncated record is only detectable from the NAS message's own
# structure (TS 24.301 §8 message layouts, TS 24.007 §11.2 IE formats). The
# check walks the mandatory part of each known message type, then the optional
# IEs, and reports whether every declared length fits:
#
#   * mandatory part, per message type: ``int`` = that many fixed octets (a
#     V field, or two half-octet V IEs packed into one octet), ``_LV`` = 1-octet
#     length + value, ``_LVE`` = 2-octet (big-endian) length + value.
#   * optional part (TS 24.007 §11.2.4): an IEI with bit 8 set is a 1-octet
#     type-1/type-2 IE; IEIs 0x70-0x7F are type-6 TLV-E; the few type-3 TV IEIs
#     below have spec-fixed value lengths; the other KNOWN IEIs are type-4 TLV.
#     The walk STOPS (complete=True) at the first IEI that is not a known
#     optional IE of that protocol: bytes beyond the declared structure are not
#     judged here. Measured reason: real 0xB0E2 Activate-default-bearer records
#     carry the rest of the enclosing Attach Accept (GUTI 0x50, LAI 0x13, MS
#     identity 0x23 ...) after the ESM message — treating those as ESM TLVs
#     would wrongly reject them.
#
# Limitation (by construction, not fixable here): a message whose LAST IE is a
# 1-octet type-1/type-2 IE, or that ends in an optional IE dropped whole, is
# indistinguishable from a valid shorter message. Unknown message types and
# security-protected (sec_hdr_type 1-4) PDUs are not checked (None).
_LV = "LV"
_LVE = "LVE"

#: TS 24.301 §8.2 EMM mandatory parts (after the 2-octet sec_hdr|PD + msg type).
_EMM_MANDATORY: dict[int, tuple] = {
    0x41: (1, _LV, _LV, _LVE),  # Attach request: attach type|KSI, EPS MI, UE NW cap, ESM container
    0x42: (1, 1, _LV, _LVE),    # Attach accept: result|spare, T3412, TAI list, ESM container
    0x43: (_LVE,),              # Attach complete: ESM container
    0x44: (1,),                 # Attach reject: EMM cause
    0x46: (),                   # Detach accept
    0x48: (1, _LV),             # TAU request: update type|KSI, old GUTI
    0x49: (1,),                 # TAU accept: update result|spare
    0x4A: (),                   # TAU complete
    0x4B: (1,),                 # TAU reject: EMM cause
    0x4C: (1, _LV),             # Extended service request: service type|KSI, M-TMSI
    0x4D: (1,),                 # Control plane service request: type|KSI
    0x4E: (1,),                 # Service reject: EMM cause
    0x4F: (),                   # Service accept
    0x50: (_LV,),               # GUTI reallocation command: GUTI
    0x51: (),                   # GUTI reallocation complete
    0x52: (1, 16, _LV),         # Authentication request: KSI|spare, RAND, AUTN
    0x53: (_LV,),               # Authentication response: RES
    0x54: (),                   # Authentication reject
    0x55: (1,),                 # Identity request: identity type|spare
    0x56: (_LV,),               # Identity response: mobile identity
    0x5C: (1,),                 # Authentication failure: EMM cause
    0x5D: (1, 1, _LV),          # Security mode command: algs, KSI|spare, replayed UE sec cap
    0x5E: (),                   # Security mode complete
    0x5F: (1,),                 # Security mode reject: EMM cause
    0x60: (1,),                 # EMM status: EMM cause
    0x61: (),                   # EMM information
    0x62: (_LV,),               # Downlink NAS transport: NAS message container
    0x63: (_LV,),               # Uplink NAS transport: NAS message container
    0x64: (1,),                 # CS service notification: paging identity
    0x68: (1, _LVE),            # Downlink generic NAS transport: type, container
    0x69: (1, _LVE),            # Uplink generic NAS transport: type, container
}
#: Detach request (0x45) is direction-dependent (TS 24.301 §8.2.11).
_EMM_DETACH_REQUEST_UL = (1, _LV)   # detach type|KSI, EPS mobile identity
_EMM_DETACH_REQUEST_DL = (1,)       # detach type|spare (EMM cause is optional)

#: EMM type-3 (TV) optional IEIs -> value length (TS 24.301 §8.2).
_EMM_TV: dict[int, int] = {
    0x13: 5,  # (Old) location area identification
    0x17: 1,  # T3402 value / Additional information requested
    0x19: 3,  # Old P-TMSI signature
    0x46: 1,  # Local time zone
    0x47: 7,  # Universal time and local time zone
    0x52: 5,  # Last visited registered TAI
    0x53: 1,  # EMM cause
    0x55: 4,  # NonceUE / Replayed nonceUE
    0x56: 4,  # NonceMME
    0x59: 1,  # T3423 value
    0x5A: 1,  # T3412 value
    0x5B: 1,  # T3442 value
    0x5C: 2,  # DRX parameter
    0x61: 1,  # SS code
    0x62: 1,  # LCS indicator
}

#: EMM type-4 (TLV) optional IEIs known from TS 24.301 §8.2 (walked; any
#: other IEI < 0x70 stops the walk).
_EMM_TLV: frozenset[int] = frozenset((
    0x10, 0x11, 0x16, 0x1D, 0x1E, 0x20, 0x23, 0x30, 0x31, 0x32, 0x34, 0x35,
    0x36, 0x38, 0x40, 0x43, 0x45, 0x49, 0x4A, 0x4F, 0x50, 0x54, 0x57, 0x58,
    0x5D, 0x5E, 0x5F, 0x60, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x6A, 0x6B,
    0x6C, 0x6D, 0x6E, 0x6F,
))

#: TS 24.301 §8.3 ESM mandatory parts (after the 3-octet EBI|PD, PTI, msg type).
_ESM_MANDATORY: dict[int, tuple] = {
    0xC1: (_LV, _LV, _LV),      # Act. default bearer req: EPS QoS, APN, PDN address
    0xC2: (),                   # Act. default bearer accept
    0xC3: (1,),                 # Act. default bearer reject: ESM cause
    0xC5: (1, _LV, _LV),        # Act. dedicated bearer req: linked EBI|spare, EPS QoS, TFT
    0xC6: (),                   # Act. dedicated bearer accept
    0xC7: (1,),                 # Act. dedicated bearer reject: ESM cause
    0xC9: (),                   # Modify bearer req
    0xCA: (),                   # Modify bearer accept
    0xCB: (1,),                 # Modify bearer reject: ESM cause
    0xCD: (1,),                 # Deactivate bearer req: ESM cause
    0xCE: (),                   # Deactivate bearer accept
    0xD0: (1,),                 # PDN connectivity req: PDN type|request type
    0xD1: (1,),                 # PDN connectivity reject: ESM cause
    0xD2: (1,),                 # PDN disconnect req: linked EBI|spare
    0xD3: (1,),                 # PDN disconnect reject: ESM cause
    0xD4: (1, _LV, _LV),        # Bearer resource allocation req: EBI|spare, TFAgg, QoS
    0xD5: (1,),                 # Bearer resource allocation reject: ESM cause
    0xD6: (1, _LV),             # Bearer resource modification req: EBI|spare, TFAgg
    0xD7: (1,),                 # Bearer resource modification reject: ESM cause
    0xD9: (),                   # ESM information request
    0xDA: (),                   # ESM information response
    0xDB: (_LV,),               # Notification: notification indicator
    0xDC: (),                   # ESM dummy message
    0xE8: (1,),                 # ESM status: ESM cause
    0xEB: (_LVE,),              # ESM data transport: user data container
}

#: ESM type-3 (TV) optional IEIs -> value length (TS 24.301 §8.3).
_ESM_TV: dict[int, int] = {
    0x32: 1,  # Negotiated LLC SAPI
    0x58: 1,  # ESM cause
}

#: ESM type-4 (TLV) optional IEIs known from TS 24.301 §8.3: transaction id,
#: negotiated QoS, packet flow id, APN, PCO, NBIFOM, TFT, T3396, new/required
#: EPS QoS, extended EPS QoS, APN-AMBR, extended APN-AMBR, header compression,
#: re-attempt indicator, serving PLMN rate control.
_ESM_TLV: frozenset[int] = frozenset((
    0x27, 0x28, 0x30, 0x33, 0x34, 0x36, 0x37, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x66, 0x6B, 0x6E,
))


def nas_pdu_structurally_complete(nas_pdu: bytes, is_uplink: bool) -> bool | None:
    """Does ``nas_pdu`` hold every octet its own structure declares?

    True  — a known plain EMM/ESM message whose mandatory part and every
            optional IE fit exactly in the PDU.
    False — a mandatory field is missing, or a declared length (LV / LV-E /
            TLV / TLV-E / fixed TV) runs past the end: the record is truncated.
    None  — not checkable (unknown message type, unknown protocol
            discriminator, or a security-protected header).
    """
    n = len(nas_pdu)
    if n < 1:
        return False
    pd = nas_pdu[0] & 0x0F
    if pd == 7:
        if n < 2:
            return False
        if (nas_pdu[0] >> 4) & 0x0F != 0:
            return None
        mt = nas_pdu[1]
        if mt == 0x45:
            layout = _EMM_DETACH_REQUEST_UL if is_uplink else _EMM_DETACH_REQUEST_DL
        else:
            layout = _EMM_MANDATORY.get(mt)
        tv, tlv = _EMM_TV, _EMM_TLV
        pos = 2
    elif pd == 2:
        if n < 3:
            return False
        layout = _ESM_MANDATORY.get(nas_pdu[2])
        tv, tlv = _ESM_TV, _ESM_TLV
        pos = 3
    else:
        return None
    if layout is None:
        return None
    for tok in layout:
        if tok == _LV:
            if pos + 1 > n:
                return False
            pos += 1 + nas_pdu[pos]
        elif tok == _LVE:
            if pos + 2 > n:
                return False
            pos += 2 + ((nas_pdu[pos] << 8) | nas_pdu[pos + 1])
        else:
            pos += tok
        if pos > n:
            return False
    while pos < n:
        iei = nas_pdu[pos]
        if iei & 0x80:              # type 1 / type 2: one octet
            pos += 1
        elif iei in tv:             # type 3: fixed value length
            pos += 1 + tv[iei]
        elif 0x70 <= iei <= 0x7F:   # type 6: TLV-E
            if pos + 3 > n:
                return False
            pos += 3 + ((nas_pdu[pos + 1] << 8) | nas_pdu[pos + 2])
        elif iei in tlv:            # type 4: TLV
            if pos + 2 > n:
                return False
            pos += 2 + nas_pdu[pos + 1]
        else:                       # not a known optional IE: stop, don't judge the tail
            return True
        if pos > n:
            return False
    return True


#: TS 24.301 §9.1: a security-protected NAS PDU is sec-hdr|PD (1) + MAC (4) + SQN (1)
#: + the inner NAS message. The 6 octets are the 0xB0E1 - 0xB0E3 length delta (F3).
SEC_PROTECTED_OVERHEAD = 6


def split_sec_protected(pdu: bytes) -> tuple[int, int, int, int, bytes] | None:
    """Split a security-protected NAS PDU.

    ``pdu`` starts at the security-header octet (0xB0E1/0xB0E0 ``data[4:]``).
    Returns ``(sec_hdr_type, prot_disc, nas_mac, nas_seq, inner)``, where
    ``nas_mac`` is the u32 big-endian NAS-MAC (TS 24.301 §9.5) and ``inner`` is
    the inner NAS message, ciphered unless the network chose EEA0. Returns None
    when the PDU cannot hold the 6-octet header.
    """
    if len(pdu) < SEC_PROTECTED_OVERHEAD:
        return None
    return ((pdu[0] >> 4) & 0x0F, pdu[0] & 0x0F, unpack_from('>I', pdu, 1)[0],
            pdu[5], bytes(pdu[SEC_PROTECTED_OVERHEAD:]))


@dataclass
class LteNasOtaMsg:
    """Parsed LTE NAS plain OTA message (EMM or ESM).

    Shared by 0xB0E2/0xB0E3/0xB0EC/0xB0ED. ``type_name`` is set by the
    per-code parser to the ID-only string (``"Diag0xB0E2"`` etc.) so
    downstream JSON consumers can distinguish the four codes on the
    ``type`` field alone, not just on ``log_code``.
    """
    log_time: int
    log_code: int
    is_uplink: bool
    version: int  # byte[0] — DIAG NAS extended-header version (legacy name `ext_header_ver`)
    rrc_rel: int
    rrc_ver_major: int
    rrc_ver_minor: int
    prot_disc: int
    prot_disc_name: str
    # EMM only: security header type (upper nibble of NAS byte[0]); None for ESM.
    # sec_hdr_type=12 is the SERVICE REQUEST short form (no msg_type byte).
    sec_hdr_type: int | None
    sec_hdr_type_name: str | None
    # msg_type is None for the SERVICE REQUEST short form (sec_hdr_type=12),
    # which has no message-type identifier on the wire.
    msg_type: int | None
    msg_type_name: str
    # ESM-only fields (prot_disc=2)
    eps_bearer_id: int | None
    pti: int | None
    # Service Request short form fields (sec_hdr_type=12 only). The NAS-MAC
    # is u16 big-endian on the wire — see 3GPP TS 24.301 §8.2.25 and a
    # vendor-decoder rendered example (ksi=1, seq_num=5,
    # short_mac_value=0x195e).
    ksi: int | None
    seq_num: int | None
    short_mac_value: int | None
    # raw NAS PDU
    nas_pdu: bytes
    payload_size: int
    # Optional layer-2 NAS-body decode (see lte_nas_emm.py). Populated only
    # for message types this decoder currently handles (EMM Information).
    # Other msg_types leave this None — open scope is tracked per-code on
    # the diag-decode issues.
    emm_body: dict[str, Any] | None = None
    # Optional ESM (prot_disc=2) message-body decode via the shared
    # _nas_l3.decode_esm_message. The bare ESM-OTA nas_pdu IS a complete
    # ESM message (3-octet header + body), so this surfaces the same typed body
    # — Activate-default-bearer QCI/APN/PDN-address/APN-AMBR, PDN-connectivity
    # request/PDN type, accept PCO presence, ESM-info-response APN — that the
    # 0xB0EC/0xB0ED Attach-Accept ESM *container* already decodes. None for EMM
    # records and for ESM msg_types with no dedicated body decoder (the typed
    # header still surfaces inside esm_body for those).
    esm_body: dict[str, Any] | None = None
    # ID-only ``type`` string set by per-code parser.
    type_name: str = "LteNasOtaMsg"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': self.type_name,
            'log_time': self.log_time,
            'log_code': f"0x{self.log_code:04X}",
            'is_uplink': self.is_uplink,
            'version': self.version,
            'rrc_rel': self.rrc_rel,
            'rrc_ver_major': self.rrc_ver_major,
            'rrc_ver_minor': self.rrc_ver_minor,
            'prot_disc': self.prot_disc,
            'prot_disc_name': self.prot_disc_name,
            'msg_type': self.msg_type,
            'msg_type_name': self.msg_type_name,
            'payload_size': self.payload_size,
            'nas_pdu_hex': self.nas_pdu.hex(),
        }
        if self.sec_hdr_type is not None:
            d['sec_hdr_type'] = self.sec_hdr_type
            d['sec_hdr_type_name'] = self.sec_hdr_type_name
        if self.eps_bearer_id is not None:
            d['eps_bearer_id'] = self.eps_bearer_id
            d['pti'] = self.pti
        if self.ksi is not None:
            d['ksi'] = self.ksi
            d['seq_num'] = self.seq_num
            d['short_mac_value'] = self.short_mac_value
        if self.emm_body is not None:
            d['emm_body'] = self.emm_body
        if self.esm_body is not None:
            d['esm_body'] = self.esm_body
        return d


def _parse_nas_ota(
    log_time: int,
    data: bytes,
    log_code: int,
    is_uplink: bool,
    type_name: str,
) -> LteNasOtaMsg | None:
    if len(data) < _DIAG_HDR_SIZE + 1:
        return None

    # Layer-1 version gate: byte[0] is the DIAG NAS extended-header
    # version, corpus-invariant 0x01. Reject foreign byte-0 values rather than
    # mis-parsing them against this wrapper layout (size-invariance ≠ format-
    # invariance core memory). The per-code parsers (diag_0xb0e2.py etc.) carry
    # a duplicate explicit gate so the static gate-ratchet — which does not
    # follow this cross-module import — can see it.
    version = data[0]
    if version != _NAS_OTA_VERSION_OBSERVED:
        return None
    rrc_rel = data[1]
    rrc_ver_major = data[2]
    rrc_ver_minor = data[3]
    nas_pdu = data[_DIAG_HDR_SIZE:]

    if len(nas_pdu) < 1:
        return None
    # No wrapper length field exists, so a truncated record
    # is caught from the NAS message's own structure; one that provably cannot
    # hold what it declares returns None (registry WARN), never a short decode.
    if nas_pdu_structurally_complete(nas_pdu, is_uplink) is False:
        return None

    prot_disc = nas_pdu[0] & 0x0F
    prot_disc_name = _PROT_DISC_NAMES.get(prot_disc, f"0x{prot_disc:X}")

    eps_bearer_id: int | None = None
    pti: int | None = None
    sec_hdr_type: int | None = None
    sec_hdr_type_name: str | None = None
    ksi: int | None = None
    seq_num: int | None = None
    short_mac_value: int | None = None
    msg_type: int | None
    msg_type_name: str

    if prot_disc == 2:  # ESM — byte[0]=bearer_id|prot_disc, byte[1]=pti, byte[2]=msg_type
        if len(nas_pdu) < 3:
            return None
        eps_bearer_id = (nas_pdu[0] >> 4) & 0x0F
        pti = nas_pdu[1]
        msg_type = nas_pdu[2]
        msg_type_name = _ESM_MSG_NAMES.get(msg_type, f"0x{msg_type:02X}")
    else:  # EMM (prot_disc=7) or unknown — byte[0]=sec_hdr|prot_disc
        if len(nas_pdu) < 2:
            return None
        sec_hdr_type = (nas_pdu[0] >> 4) & 0x0F
        sec_hdr_type_name = _SEC_HDR_TYPE_NAMES.get(sec_hdr_type, f"0x{sec_hdr_type:X}")
        if sec_hdr_type == 12:
            # Service Request short form (TS 24.301 §9.3.1, §8.2.25): byte[1]
            # is KSI(3)|seq(5), byte[2:4] is Short MAC (u16 big-endian per
            # TS 24.301 §9.10.2 NAS message authentication code). There is no
            # msg_type byte — the message is identified entirely by
            # sec_hdr_type=12. Total NAS payload is exactly 4 bytes.
            if len(nas_pdu) < 4:
                return None
            ksi = (nas_pdu[1] >> 5) & 0x07
            seq_num = nas_pdu[1] & 0x1F
            short_mac_value = unpack_from('>H', nas_pdu, 2)[0]
            msg_type = None
            msg_type_name = "Service request"
        else:
            # Plain (sec_hdr_type=0) and others — byte[1] is msg_type. For
            # sec_hdr_types 1-4 in a "plain OTA" code byte[1] would actually
            # be the first byte of the MAC, which is meaningless as msg_type;
            # those records shouldn't appear here, and we'd surface them via
            # sec_hdr_type_name so a downstream consumer can spot the
            # mismatch.
            msg_type = nas_pdu[1]
            msg_type_name = _EMM_MSG_NAMES.get(msg_type, f"0x{msg_type:02X}")

    emm_body: dict[str, Any] | None = None
    # Hand-off to lte_nas_emm.py for the plain (sec_hdr_type=0) EMM message
    # types its dispatcher decodes: reject EMM-cause (Attach/TAU/Service
    # reject + EMM status), Identity request type, Detach request type, and
    # EMM Information. Message types not yet decoded leave emm_body None.
    # is_uplink disambiguates the direction-
    # dependent detach-type naming (TS 24.301 §9.9.3.7).
    if prot_disc == 7 and sec_hdr_type == 0 and msg_type is not None and len(nas_pdu) > 2:
        from diaggrok.parsers.lte_nas_emm import decode_emm_body
        emm_body = decode_emm_body(msg_type, nas_pdu[2:], is_uplink=is_uplink)

    # ESM (prot_disc=2) body decode: the bare ESM-OTA nas_pdu is a
    # complete ESM message (3-octet header + body), exactly what
    # decode_esm_message consumes. One call surfaces the typed body — the same
    # decoder the 0xB0EC/0xB0ED Attach-Accept ESM *container* already uses, now
    # wired for the standalone 0xB0E2/0xB0E3 ESM-OTA codes.
    esm_body: dict[str, Any] | None = None
    if prot_disc == 2:
        from diaggrok.parsers._nas_l3 import decode_esm_message
        esm_body = decode_esm_message(nas_pdu)

    return LteNasOtaMsg(
        log_time=log_time,
        log_code=log_code,
        is_uplink=is_uplink,
        version=version,
        rrc_rel=rrc_rel,
        rrc_ver_major=rrc_ver_major,
        rrc_ver_minor=rrc_ver_minor,
        prot_disc=prot_disc,
        prot_disc_name=prot_disc_name,
        sec_hdr_type=sec_hdr_type,
        sec_hdr_type_name=sec_hdr_type_name,
        msg_type=msg_type,
        msg_type_name=msg_type_name,
        eps_bearer_id=eps_bearer_id,
        pti=pti,
        ksi=ksi,
        seq_num=seq_num,
        short_mac_value=short_mac_value,
        nas_pdu=nas_pdu,
        payload_size=len(data),
        emm_body=emm_body,
        esm_body=esm_body,
        type_name=type_name,
    )
