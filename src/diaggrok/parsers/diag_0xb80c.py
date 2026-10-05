"""0xB80C — NR5G NAS 5GMM state (5GMM state / substate, PLMN, 5G-GUTI, TAI).

Emitted on every 5GMM state or substate change: the TS 24.501 §5.1.3 5GMM
state-machine position plus the selected PLMN, the UE's 5G-GUTI, the 5GS
update status and the TAC of the last registered TAI — i.e. the contents of
the USIM's EF 5GS3GPPLOCI (TS 31.102 §4.4.11.2) next to the live state. The
5G twin of 0xB0EE (LTE NAS EMM state).

Two versions, one body layout (9,255 records / 229 captures)::

    v0x01  26 B  header 01 00 00 00   9,219 records, SDX55 / SDX62 / SDX65
    v0x00  27 B  header 00 00 03 00      36 records, T99W640 (SDX72) only;
                                            body identical + 1 trailing byte

    [0:4]    4B    version header   byte 0 is the registry version (gated);
                                    bytes 1..3 are pinned per version
    [4]      u8    mm5g_state       see _MM5G_STATE_NAMES
    [5]      u8    mm5g_substate    state-dependent enum, surfaced raw
    [6]      u8    reserved         0x00 on every record
    [7:10]   3B    plmn             TS 24.008 §10.5.1.3 TBCD; ff ff ff = none
    [10]     u8    guti_id_type     2 = 5G-GUTI (TS 24.501 §9.11.3.4);
                                    0xFF fill when there is no GUTI
    [11:14]  3B    guti_plmn        TBCD, wire order
    [14]     u8    amf_region_id
    [15:17]  u16   amf_set_id       LITTLE-endian, 10 significant bits
    [17]     u8    amf_pointer      6 significant bits
    [18:22]  u32   tmsi_5g          LITTLE-endian (wire 5G-TMSI is big-endian)
    [22]     u8    update_status    5GS update status, TS 31.102 coding
    [23:26]  3B    tac              last registered TAI's TAC, WIRE order
                                    (big-endian); 00 00 00 = none
    [26]     u8    v0_trailer       v0x00 only; 0x00 on all 36 records, raw

When ``guti_id_type != 2`` bytes [10:22] are 0xFF fill and the GUTI fields
are ``None``. Like the EPS GUTI in 0xB0EE, the 5G-GUTI survives
deregistration (it is kept in the USIM).

Grounding:
  * 5G-GUTI — the 5GMM Registration Accept (0xB80A) 5G-GUTI IE (0x77,
    ``f2 <plmn> <region> <set:10|ptr:6> <tmsi BE>``) equals the first
    REGISTERED 0xB80C record after it: 31/31 Registration Accepts across 19
    captures (RM500Q, RM520N-GL, RXM-G1, T99W373, T99W640 — both versions).
    Region and pointer are byte-exact; AMF set ID and 5G-TMSI match once read
    little-endian. This is what pins the mixed endianness.
  * tac / plmn — F3 ``mmgsdi_ss_event.c:1129`` "CM SS Event ... PLMN:
    0x130062 ... TAC_5g: 0x2d6600" equals [7:10] and [23:26]-read-big-endian
    of the latest 0xB80C record 32/32 while the 5GMM state is REGISTERED
    (RM520N-GL, SDX62, v0x01). Outside REGISTERED, CM prints ``0xfffffe``
    (no service) while 0xB80C keeps the last registered TAI, as EF
    5GS3GPPLOCI semantics require. v0x00 (T99W640): 1/1 comparable print
    matches; the rest are 0xfffffe. ``quectel_eng_atc.c:800`` "TAC: 2D6600"
    also agrees. The Registration Accept TAI list TAC matches 37/37.
  * mm5g_state — named from OTA sequencing, the next 0xB80A / 0xB80B
    message after each transition: 1 → 2 precedes Registration request
    (37×), REGISTERED (3) follows Registration accept and carries the
    joined GUTI, 3 → 4 precedes Service request (15×), 3 → 5 precedes
    Deregistration request (19×), and 5 → 1 completes the deregistration
    (23×). The firmware orders SERVICE_REQUEST_INITIATED (4) before
    DEREGISTERED_INITIATED (5), the reverse of the TS 24.501 list. 0 is
    not observed and is named by elimination (candidate).
  * update_status — TS 31.102 EF 5GS3GPPLOCI coding. 0 (5U1 UPDATED)
    holds whenever a GUTI is present: every REGISTERED / SR- / DEREG-
    INITIATED record. 2 (5U3 ROAMING NOT ALLOWED) is set in the
    ``forced_reject`` captures after a Registration reject. 1 (5U2) is the
    no-registration default.
  * SCAT A/B: SCAT's "5GMM State: s/sub/upd, MCC/MNC, TAC, GUTI
    plmn-region-set-ptr-tmsi" equals this decode on 10/10 emitted lines
    (RXM-G1 v0x01 2/2, T99W640 v0x00 8/8); SCAT drops a few records to its
    framer dialect gap.
  * The F3 state-setter sites ``mm5g_database.c:986`` "MM State changed
    from %d to %d" / ``:1041`` "MM sub state changed" exist in the RM520N
    F3 message database but are silent corpus-wide (0 of 27M+ resolved QSR4
    records in four RM520N captures); no ``0x60`` event carries the state (the MM5G events
    are timer events only). mm5g_substate therefore stays raw.

The PLMN / 5G-GUTI are decoded in full; fixtures use a sentinel 5G-TMSI,
never a captured one.

Log name: LOG_NR5G_NAS_MM5G_STATE
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.parsers._nas_l3 import _decode_plmn_tbcd
from diaggrok.registry import register

# version byte -> (payload size, full 4-byte header)
_B80C_LAYOUTS = {
    0x01: (26, b"\x01\x00\x00\x00"),
    0x00: (27, b"\x00\x00\x03\x00"),
}
_5GS_ID_TYPE_GUTI = 0x2

# Grounded values: see the module docstring. "(candidate)" = named by
# elimination, never observed.
_MM5G_STATE_NAMES = {
    0: "MM5G_NULL (candidate)",
    1: "MM5G_DEREGISTERED",
    2: "MM5G_REGISTERED_INITIATED",
    3: "MM5G_REGISTERED",
    4: "MM5G_SERVICE_REQUEST_INITIATED",
    5: "MM5G_DEREGISTERED_INITIATED",
}

_UPDATE_STATUS_NAMES = {
    0: "5U1_UPDATED",
    1: "5U2_NOT_UPDATED",
    2: "5U3_ROAMING_NOT_ALLOWED",
}


def _plmn(b3: bytes) -> dict[str, str] | None:
    """TBCD PLMN, or None for the 0xFF fill / a non-BCD MCC (00 00 00 → 000/00)."""
    if b3 == b"\xff\xff\xff":
        return None
    if any(n > 9 for n in (b3[0] & 0xF, b3[0] >> 4, b3[1] & 0xF)):
        return None
    return _decode_plmn_tbcd(b3)


@dataclass
class Diag0xB80C:
    """0xB80C — NR5G NAS 5GMM state."""
    log_time: int
    version: int
    mm5g_state: int
    mm5g_state_name: str
    mm5g_substate: int
    plmn_raw: bytes
    plmn: dict[str, str] | None
    guti_id_type: int
    guti_plmn: dict[str, str] | None
    amf_region_id: int | None
    amf_set_id: int | None
    amf_pointer: int | None
    tmsi_5g: int | None
    update_status: int
    update_status_name: str
    tac: int | None
    v0_trailer: int | None
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB80C",
            "log_time": self.log_time,
            "version": self.version,
            "mm5g_state": self.mm5g_state,
            "mm5g_state_name": self.mm5g_state_name,
            "mm5g_substate": self.mm5g_substate,
            "plmn_hex": self.plmn_raw.hex(),
            "plmn": self.plmn,
            "guti_id_type": self.guti_id_type,
            "guti_plmn": self.guti_plmn,
            "amf_region_id": self.amf_region_id,
            "amf_set_id": self.amf_set_id,
            "amf_pointer": self.amf_pointer,
            "tmsi_5g": self.tmsi_5g,
            "update_status": self.update_status,
            "update_status_name": self.update_status_name,
            "tac": self.tac,
            "v0_trailer": self.v0_trailer,
            "payload_size": self.payload_size,
        }


@register(
    0xB80C, domain="nas",
    name="0xB80C",
    description=(
        "NR5G NAS 5GMM state — 5GMM state (named, OTA-sequenced) and raw "
        "substate, PLMN, 5G-GUTI (PLMN / AMF region / set / pointer / "
        "5G-TMSI, joined 31/31 to the Registration Accept IE), 5GS update "
        "status and last registered TAC (F3 TAC_5g 32/32)"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full body decoded on v0x01 (26 B) and v0x00 (27 B, T99W640). "
        "5G-GUTI == 0xB80A Registration Accept IE 0x77, 31/31 across 19 "
        "captures, with AMF set ID / 5G-TMSI stored little-endian; TAC == "
        "TAI-list TAC 37/37. F3 mmgsdi_ss_event.c:1129 TAC_5g + PLMN == "
        "[23:26] BE / [7:10] 32/32 while REGISTERED (RM520N-GL v0x01), 1/1 "
        "comparable on T99W640 v0x00. States 1-5 named from OTA sequencing "
        "(Registration / Service / Deregistration request). Update status per "
        "TS 31.102 EF 5GS3GPPLOCI. SCAT agrees on 10/10 emitted lines. The "
        "MM5G F3 state-change sites are silent corpus-wide, so the substate "
        "stays raw."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Wire fields: version, mm5g_state, mm5g_substate, plmn, guti_id_type,
    # guti_plmn, amf_region_id, amf_set_id, amf_pointer, tmsi_5g,
    # update_status, tac, v0_trailer.
    fields_identified=13,
    fields_parsed=13,
    field_invariants={
        "version": {"enum": sorted(_B80C_LAYOUTS)},
        "payload_size": {"enum": sorted(s for s, _ in _B80C_LAYOUTS.values())},
    },
)
def parse_0xb80c(log_time: int, data: bytes) -> Diag0xB80C | None:
    if not data:
        return None
    version = data[0]
    layout = _B80C_LAYOUTS.get(version)
    if layout is None:
        return None
    size, header = layout
    if len(data) != size or bytes(data[0:4]) != header:
        return None
    state = data[4]
    status = data[22]
    has_guti = data[10] == _5GS_ID_TYPE_GUTI
    tac_raw = bytes(data[23:26])
    return Diag0xB80C(
        log_time=log_time,
        version=version,
        mm5g_state=state,
        mm5g_state_name=_MM5G_STATE_NAMES.get(state, f"UNKNOWN_{state}"),
        mm5g_substate=data[5],
        plmn_raw=bytes(data[7:10]),
        plmn=_plmn(data[7:10]),
        guti_id_type=data[10],
        guti_plmn=_plmn(data[11:14]) if has_guti else None,
        amf_region_id=data[14] if has_guti else None,
        amf_set_id=unpack_from("<H", data, 15)[0] if has_guti else None,
        amf_pointer=data[17] if has_guti else None,
        tmsi_5g=unpack_from("<I", data, 18)[0] if has_guti else None,
        update_status=status,
        update_status_name=_UPDATE_STATUS_NAMES.get(status, f"UNKNOWN_{status}"),
        tac=int.from_bytes(tac_raw, "big") if tac_raw != b"\x00\x00\x00" else None,
        v0_trailer=data[26] if version == 0x00 else None,
        payload_size=len(data),
    )
