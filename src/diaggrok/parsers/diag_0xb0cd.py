"""LTE RRC Supported CA Band Combinations parser (0xB0CD).

LOG_LTE_RRC_SUPPORTED_CA_COMBOS — emitted by the modem RRC layer on LTE
attach, SIM power cycle, and periodically during active LTE sessions. Each
emission represents the CA band combination profile active for the current
serving band; the primary band in combo[0] changes with the camped cell.

Payload layout (fixed 3603 bytes, confirmed on MDM9650):
    [0]       u8   version        (0x20 = 32 on SDX20/MDM9650)
    [1]       u8   num_combos     (count of populated combo slots, 0–100)
    [2]       u8   reserved       (always 0x00)
    [3..3602] 100 × 36-byte combo slots, each containing 6 CC slots:
        [0:2] u16 LE  band           (LTE band number; 0x0000 = empty slot)
        [2]   u8      dl_bw_class    (1=A 2=B 3=C 4=D; 0 = empty)
        [3]   u8      reserved_0x02  (per-CC capability byte, NOT reserved:
                                      {2,4} across all v0x20 captures —
                                      surfaced raw; see ComponentCarrier note)
        [4]   u8      ul_bw_class    (0=unspecified/none 1=A 2=B 3=C)
        [5]   u8      ul_enabled     (0=DL-only 1=DL+UL on this CC)

Clean-room RE from EM7511; the byte offsets are validated across all v0x20
captures — 232 records / 3 vendors (Sierra EM7511/EM7565/MC7411 + Telit
LM960), 29 distinct real 3GPP bands, dl_bw_class A–E, ul_bw_class A–C, 0 misses.
The log code name matches fgsect/scat.

Log name: LTE RRC Supported CA Combos
Also known as: LOG_LTE_RRC_SUPPORTED_CA_COMBOS
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_LTE_RRC_SUPPORTED_CA_COMBOS
from diaggrok.registry import register

_EXPECTED_SIZE = 3603
_HDR_SIZE = 3
_MAX_COMBOS = 100
_MAX_CCS = 6
_CC_SIZE = 6
_COMBO_SIZE = _MAX_CCS * _CC_SIZE  # 36 bytes per combo slot

# v0x28 profile (SDX55-class: Inseego M2000, Wistron LV55, Quectel RM500Q).
# Same header (version/num_combos/reserved) and same 100-combo × 6-CC shape as
# v0x20, but each CC is **7 bytes** instead of 6 — a trailing byte appended
# after ul_enabled. 4203 = 3 + 100 × (6 × 7). RE'd cross-modem (Inseego M2000
# + Wistron LV55; real LTE bands all decode cleanly under the 7-byte stride)
# and checked on 1,027 v0x28 records across SDX55 modems. F3-grounded (see the
# v0x28 F3 grounding note below).
_V28_SIZE = 4203
_V28_CC_SIZE = 7
_V28_COMBO_SIZE = _MAX_CCS * _V28_CC_SIZE  # 42 bytes per combo slot

# v0x29 profile (v41) — SDX6x/SDX7x (Sierra EM9291 SDX65, an SDX72 modem).
# VARIABLE-size: keeps v20/v28's fixed 100-combo-slot envelope, but each slot
# is length-prefixed — a 1-byte CC count followed by that many 7-byte CCs —
# so total size varies with how many carriers each combo declares.
#   [0]    u8  version (0x29)
#   [1]    u8  num_combos (count of *populated* slots; advisory)
#   [2..]  100 slots, each: u8 cc_count, then cc_count × 7-byte CC
# Per-CC 7-byte layout (field order follows uecapabilityparser's CA-combo
# model, corroborated by the same value-domains observed on v0x28):
#   [0:2] u16 band  [2] dl_bw_class  [3] ul_bw_class
#   [4] mimo_dl_idx  [5] mimo_ul_idx  [6] modulation
# The mimo/modulation bytes are surfaced as RAW indices: the indexed-MIMO
# lookup (index → actual MIMO layer count) is not ported, so naming them
# decoded values would be a plausible-but-wrong parse.
# Structural model confirmed by exact byte-consumption across 58 EM9291
# SDX65 records (27 distinct sizes) and bands/bw-classes decoding to real
# 3GPP values.
_V29_VERSION = 0x29
_V29_HDR_SIZE = 2
_V29_CC_SIZE = 7
_V29_SLOTS = _MAX_COMBOS  # 100 length-prefixed combo slots

# CA bandwidth classes 3GPP 36.101 Table 5.6A-1: A..F. v0x20 MDM9650 captures
# only ever exercise A-D; v0x28 SDX55 captures surface class E (=5) on wide
# TDD bands (B46/B48/B66), so the name table is extended through F here.
_BW_CLASS_NAMES: dict[int, str] = {
    0: "", 1: "A", 2: "B", 3: "C", 4: "D", 5: "E", 6: "F",
}


@dataclass
class ComponentCarrier:
    """One component carrier entry within a CA band combination slot.

    ``reserved_0x02`` holds the raw byte at CC offset +3. The name comes from
    EM7511 captures, where it is constant 0x02, but it is not reserved: v0x20
    captures (232 records, including Telit LM960) carry value **4** on 5,514
    real-band CCs (B66/B2/B4, dl_bw_class A), so on v0x20 the byte is {2,4},
    not a constant. On v0x28 (SDX55) the **same
    byte position** carries a wider non-constant per-CC value ({2,3,6,8,12,15,20,
    24}). Same conclusion across versions: this is a genuine per-CC capability
    field (candidate: a bandwidth-combination-set / supported-MIMO capability
    code), its semantics not yet pinned, so it is surfaced raw rather than
    mis-named. ``cc_ext`` is the v0x28-only
    trailing 7th byte (None on v0x20); it tracks UL presence (0 when DL-only,
    2/5 when an UL carrier is configured).
    """
    band: int
    dl_bw_class: int
    dl_bw_class_name: str
    reserved_0x02: int | None
    ul_bw_class: int
    ul_bw_class_name: str
    ul_enabled: bool
    cc_ext: int | None = None
    # v0x29 (v41) only — raw indices; None on v0x20/v0x28. The indexed-MIMO
    # lookup is not ported, so these are the on-wire index bytes, not decoded
    # MIMO layer counts.
    mimo_dl_idx: int | None = None
    mimo_ul_idx: int | None = None
    modulation: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'band': self.band,
            'dl_bw_class': self.dl_bw_class,
            'dl_bw_class_name': self.dl_bw_class_name,
            'reserved_0x02': self.reserved_0x02,
            'ul_bw_class': self.ul_bw_class,
            'ul_bw_class_name': self.ul_bw_class_name,
            'ul_enabled': self.ul_enabled,
            'cc_ext': self.cc_ext,
            'mimo_dl_idx': self.mimo_dl_idx,
            'mimo_ul_idx': self.mimo_ul_idx,
            'modulation': self.modulation,
        }


@dataclass
class CaCombo:
    """One CA band combination (list of component carriers)."""
    carriers: list[ComponentCarrier]

    def to_dict(self) -> dict[str, Any]:
        return {'carriers': [c.to_dict() for c in self.carriers]}


@dataclass
class Diag0xB0CD:
    """Parsed LTE RRC Supported CA Band Combinations log (0xB0CD)."""
    log_time: int
    version: int
    num_combos: int
    reserved: int | None
    combos: list[CaCombo]
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0xB0CD',
            'log_time': self.log_time,
            'version': self.version,
            'num_combos': self.num_combos,
            'reserved': self.reserved,
            'combos': [c.to_dict() for c in self.combos],
            'payload_size': self.payload_size,
        }


# v0x20 is the MDM9650 profile emitted by the Sierra MC7411 + EM7511. The log
# name LOG_LTE_RRC_SUPPORTED_CA_COMBOS agrees with the docstring title.
#
# MIMO / modulation index bytes. Besides uecapabilityparser's lookup table or
# AT ground truth, the firmware's own plaintext F3 print is a third source
# for the mimo_dl_idx/mimo_ul_idx/modulation semantics. RM520N-GL captures
# with fully resolved QSR4 F3 co-bear 0xB0CD with:
#     DBG2 comboCap: band N, dl bw class N, dl_mimo_ant_cfg N, horxd_ant_cfg N,
#                    ul bw class N, ul max ant N
# It names the DL MIMO antenna config outright (observed B12->2, B2/B66->4 ant).
# Caveat — this is not a drop-in lookup table: `dl_mimo_ant_cfg` is the
# *active-scouting* antenna count (domain {2,4}), whereas the parser's
# `mimo_dl_idx` is a per-combo *capability index* with the wider domain
# {2,3,6,8,12,15,20,24,30} (same domain as v0x28's reserved_0x02 byte). F3
# gives semantic confirmation and anchor points; a comboCap<->0xB0CD-CC
# correlation (join by band+combo) across captures would be needed to
# constrain index->layers. Raw indices remain the correct surfaced form.
#
# v0x29 F3 grounding: on an RM520N-GL F3 stream (1.20M records, fully
# resolved), comboCap value-matches the parser's v0x29 decode: `band`
# (66/2/12), `dl_bw_class` (=comboCap "dl bw class" 1) and `ul_bw_class`
# (=comboCap "ul bw class" 0/1) agree exactly, so those three CC fields are
# F3-grounded, not just structurally inferred. The antenna/mimo bytes do not
# match (parser {2,3,...} vs comboCap active {2,4}), consistent with the
# raw-index framing. `modulation` (byte[6]) is not covered by the comboCap
# print, so it stays raw. The comboCap burst fires only during RRC
# CA-capability evaluation, so many F3-bearing captures carry none.
#
# Exact byte-consumption is the layout proof for the variable-size v0x29
# format: a wrong stride desyncs and fails the `off != len(data)` gate. The
# parser decodes 252/252 v0x29 records exactly (0 misses, 0 invariant
# violations) across RM520N-GL SDX62 and EM9291 SDX65, over 55 distinct
# sizes; every CC decodes to a real 3GPP band (31 distinct: 1,2,3,4,5,7,8,12,
# 13,14,17,18,19,20,25,26,28,29,30,32,34,38,39,40,41,42,43,46,48,66,71) with
# dl_bw_class in A–F and ul_bw_class in none/A/B/C. As an external oracle,
# uecapabilityparser decodes the same RM520N-GL capture's
# UECapabilityInformation (from QCSuper's RRC PCAP) into a populated LTE+NR
# CA-combo list, corroborating that the device emits the CA-capability data
# that 0xB0CD mirrors.
#
# Fields kept raw: `mimo_dl_idx` (domain {2,3,6,8,12,15,20,24,30}),
# `mimo_ul_idx` ({0,1,4}) and `modulation` ({0,1,2,5}) are on-wire capability
# indices, not decoded layer counts — the index→layers lookup is not ported,
# and comboCap's `dl_mimo_ant_cfg` ({2,4}) anchors but does not equal the
# wider index domain. `ul_enabled` is derived (UL present iff ul_bw_class
# set), not an on-wire field.
#
# v0x20 F3 grounding: the silicon that emits v0x20 (Sierra / Telit LM960,
# MDM9x50/SDX20) has no per-CC comboCap print. Instead an EM7565 F3 capture
# that co-emits 4 × 0xB0CD v0x20 records carries
# `policyman_ca.c:700 policyman_ca_band_combos_evaluate` +
# `policyman_ca.c:677 policyman_ca_band_combos_update` in the same session,
# which grounds the code identity (the LTE supported-CA-band-combos policy
# subsystem). The per-CC field definitions (band / dl_bw_class / ul_bw_class)
# are byte-identical to v0x28/v0x29, whose comboCap F3 value-grounds exactly
# those three, and every v0x20 CC decodes to a real 3GPP band + valid
# bw-class enum (232/232 records, 0 misses, 29 distinct bands, 3 vendors).
# QCSuper's RRC PCAP shows `UECapabilityInformation` (~2267 B) in the same
# attach windows. The CC+3 byte (`reserved_0x02`) is {2,4}, not invariant
# 0x02 (value 4 on 5,514 real-band LM960 CCs), so it stays raw.
#
# v0x28 F3 grounding: the v0x28 (4203 B / 7-byte-CC) SDX55 profile is
# F3-value-grounded on a Quectel RM500Q capture. RM500Q firmware emits the
# same `lte_rrc_llcdb.c:39047` comboCap plaintext print (0x79, wire format,
# not QShrink-resolved):
#     DBG2 comboCap: band 66, dl bw class 1, dl_mimo_ant_cfg 4, horxd_ant_cfg 4,
#                    ul bw class 1, ul max ant 0
#     DBG2 comboCap: band 66, dl bw class 1, ..., ul bw class 0, ...
#     DBG2 comboCap: band 12, dl bw class 1, dl_mimo_ant_cfg 2, ..., ul bw class 0
# All three comboCap tuples value-match the parser's v0x28 decode of the 14
# 0xB0CD v0x28 records co-emitted in the same capture (comboCap bursts fall
# inside the 0xB0CD emission window): B66/dl1/ul1, B66/dl1/ul0, B12/dl1/ul0 all
# appear byte-exact in the decode. So `band`, `dl_bw_class` and `ul_bw_class` are
# F3-grounded on v0x28 (not merely structurally inferred). The two v0x28-only
# bytes stay raw: CC+3 (`reserved_0x02`) tracks
# `dl_bw_class` ({2,3} for dl1, {6,8} for dl2/dl3, {12,14} for dl4) — it is NOT
# comboCap's `dl_mimo_ant_cfg` (domain {2,4}), so it is a distinct per-CC
# capability field (candidate bandwidth-combination-set), semantics unpinned;
# CC+6 (`cc_ext`) tracks UL presence/class (0=DL-only, 2=ul-class-A/B, 5 on
# wider UL). comboCap's `dl_mimo_ant_cfg`/`ul max ant` are the active-scouting
# antenna counts — they anchor but do not equal the raw index bytes, so no
# index→layers lookup is claimed, same as v0x29. QCSuper produces a
# populated RRC PCAP for the same capture; SCAT does not decode 0xB0CD (it is
# an internal CA-combos log, not an OTA message), so the in-capture 0x79
# comboCap print is the operative oracle. The capture's 0x60
# DIAG_EVENT_REPORT_F frames do not carry the CA-combo capability list.

@register(
    LOG_LTE_RRC_SUPPORTED_CA_COMBOS, domain="rrc",
    name="0xB0CD",
    issues=(),
    primary_issue=None,
    description=(
        "LTE RRC CA band combination list — 100 combo slots × 6 CC slots × 6 B "
        "each; emitted on LTE attach and periodically; active profile depends on "
        "serving band (primary band of combo[0] changes per camped cell)"
    ),
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. v0x20/3603B validated across 232 records / 3 vendors — "
        "Sierra EM7511 + EM7565 + MC7411 and Telit LM960 — 29 distinct 3GPP "
        "bands, dl_bw A–E, 0 misses; v0x20 code identity F3-grounded via "
        "policyman_ca_band_combos F3 co-emission on EM7565. v0x28/4203B "
        "across 1,027 records on SDX55-class Inseego M2000 + Wistron LV55 + "
        "Quectel RM500Q — same header + 100×6-CC shape, 7-byte CCs; v0x28 "
        "F3-grounded via the RM500Q `comboCap:` print (lte_rrc_llcdb.c:39047, "
        "0x79 wire) value-matching band/dl_bw_class/ul_bw_class. v0x29 (v41) "
        "is a variable-size 100-slot envelope with length-prefixed "
        "variable-CC slots; F3-grounded via the RM520N-GL comboCap "
        "band/dl_bw_class/ul_bw_class value-match, and decoded 252/252 "
        "records (0 misses) across RM520N-GL SDX62 and EM9291 SDX65, 55 "
        "distinct sizes, 31 real 3GPP bands; exact byte-consumption is the "
        "variable-size layout proof. uecapabilityparser + QCSuper oracles "
        "corroborate. MIMO/modulation bytes stay raw indices. Log code name "
        "matches fgsect/scat."
    ),
    source_url="",
    field_invariants={"version": {"enum": [0x20, 0x28, 0x29]}},
    fields_identified=12,
    fields_parsed=12,
)
def parse_0xb0cd(log_time: int, data: bytes) -> Diag0xB0CD | None:
    """Parse 0xB0CD — LTE RRC Supported CA Band Combinations.

    Three version profiles decode:

    * **v0x20 / 3603 B** — Sierra MDM9650 family (EM7511 + MC7411);
      100 combos × 6 CC × **6 B**.
    * **v0x28 / 4203 B** — SDX55-class (Inseego M2000, Wistron LV55); identical
      header and 100×6-CC shape but 7-byte CCs (one trailing byte per CC).
    * **v0x29 / variable** — SDX6x/SDX7x (Sierra EM9291 SDX65, SDX72);
      a 100-slot envelope where each slot is length-prefixed (1-byte CC count
      then that many 7-byte CCs), so total size varies. Decoded by walking all
      100 slots and requiring exact byte-consumption — a record that doesn't
      consume exactly returns None (surfaces as a parser miss, never a
      mis-parse).

    The byte-0 version gate is the first data access; any other version returns
    None so it surfaces as a parser miss rather than silently mis-parsing.
    """
    if len(data) < _V29_HDR_SIZE:
        return None
    version = data[0]
    if version not in (0x20, 0x28, _V29_VERSION):  # Layer-1 byte-0 gate
        return None
    if version == _V29_VERSION:
        return _parse_v29(log_time, data)
    if version == 0x20 and len(data) == _EXPECTED_SIZE:
        combo_size, cc_size = _COMBO_SIZE, _CC_SIZE
    elif version == 0x28 and len(data) == _V28_SIZE:
        combo_size, cc_size = _V28_COMBO_SIZE, _V28_CC_SIZE
    else:
        return None
    num_combos = data[1]
    reserved = data[2]

    combos: list[CaCombo] = []
    for combo_idx in range(min(num_combos, _MAX_COMBOS)):
        carriers: list[ComponentCarrier] = []
        for cc_idx in range(_MAX_CCS):
            off = _HDR_SIZE + combo_idx * combo_size + cc_idx * cc_size
            band = unpack_from('<H', data, off)[0]
            if band == 0:
                continue
            dl_bw_class = data[off + 2]
            reserved_0x02 = data[off + 3]
            ul_bw_class = data[off + 4]
            ul_enabled = bool(data[off + 5])
            cc_ext = data[off + 6] if cc_size == _V28_CC_SIZE else None
            carriers.append(ComponentCarrier(
                band=band,
                dl_bw_class=dl_bw_class,
                dl_bw_class_name=_BW_CLASS_NAMES.get(dl_bw_class, f"?{dl_bw_class}"),
                reserved_0x02=reserved_0x02,
                ul_bw_class=ul_bw_class,
                ul_bw_class_name=_BW_CLASS_NAMES.get(ul_bw_class, f"?{ul_bw_class}"),
                ul_enabled=ul_enabled,
                cc_ext=cc_ext,
            ))
        if carriers:
            combos.append(CaCombo(carriers=carriers))

    return Diag0xB0CD(
        log_time=log_time,
        version=version,
        num_combos=num_combos,
        reserved=reserved,
        combos=combos,
        payload_size=len(data),
    )


def _parse_v29(log_time: int, data: bytes) -> Diag0xB0CD | None:
    """Parse the v0x29 (v41) variable-size profile.

    Header is 2 bytes (version, num_combos); then exactly 100 length-prefixed
    combo slots, each a 1-byte CC count followed by that many 7-byte CCs. The
    walk MUST consume the buffer exactly — any record that over/under-runs the
    100-slot envelope returns None so it surfaces as a parser miss rather than
    a mis-parse (the differential-RE invariant that validated the layout).
    """
    num_combos = data[1]
    off = _V29_HDR_SIZE
    combos: list[CaCombo] = []
    for _ in range(_V29_SLOTS):
        if off >= len(data):
            return None  # ran off the end before 100 slots — not this layout
        cc_count = data[off]
        off += 1
        carriers: list[ComponentCarrier] = []
        for _ in range(cc_count):
            if off + _V29_CC_SIZE > len(data):
                return None  # truncated CC — reject
            band = unpack_from('<H', data, off)[0]
            dl_bw_class = data[off + 2]
            ul_bw_class = data[off + 3]
            mimo_dl_idx = data[off + 4]
            mimo_ul_idx = data[off + 5]
            modulation = data[off + 6]
            off += _V29_CC_SIZE
            if band == 0:
                continue
            carriers.append(ComponentCarrier(
                band=band,
                dl_bw_class=dl_bw_class,
                dl_bw_class_name=_BW_CLASS_NAMES.get(dl_bw_class, f"?{dl_bw_class}"),
                reserved_0x02=None,  # v0x29 has no reserved byte at this position
                ul_bw_class=ul_bw_class,
                ul_bw_class_name=_BW_CLASS_NAMES.get(ul_bw_class, f"?{ul_bw_class}"),
                ul_enabled=bool(ul_bw_class),  # UL present iff a UL bw class is set
                cc_ext=None,
                mimo_dl_idx=mimo_dl_idx,
                mimo_ul_idx=mimo_ul_idx,
                modulation=modulation,
            ))
        if carriers:
            combos.append(CaCombo(carriers=carriers))

    # Exact-consumption invariant: the 100-slot walk must land precisely at the
    # end of the payload. This is what makes the variable-size parse safe.
    if off != len(data):
        return None

    return Diag0xB0CD(
        log_time=log_time,
        version=_V29_VERSION,
        num_combos=num_combos,
        reserved=None,
        combos=combos,
        payload_size=len(data),
    )
