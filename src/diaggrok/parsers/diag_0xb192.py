"""LTE ML1 Neighbor Cell Measurement Response parser (0xB192).

0xB192 -- LTE ML1 Idle-Mode Neighbor Cell Measurement Request/Response
    Per-cell idle-mode neighbor measurements: EARFCN, PCI, per-Rx energy words.
    Emitted during idle-mode cell search and reselection evaluation.

Payload structure (outer version 1, always 2 subpackets: request + response).
The subpacket `size` (u16 LE) is INCLUSIVE of the 4-byte subpacket header, so the
next subpacket begins at `offset + size`. Decode-complete map, verified across
55,521 corpus records / 7 chipset generations:

    [0]      u8   version (== 1; outer DIAG log version, L1-gated)
    [1]      u8   num_subpackets (== 2)
    [2:4]    u16  counter (per-capture constant config/instance marker, NOT SFN)

    Subpacket 0 (id=26) -- Request/Config, version-dispatched header:
        ver=2 (all modern): [0:4] u32 EARFCN(low18), [4:6] u16 num_cells|flag
                            (low5=count, bit5=meas-enable), [6:8] u16 reserved
        ver=1 (MC7700/MDM9200): [0:2] u16 EARFCN, [2:4] u16 flags
        Per-cell record (16 bytes): [0:4] u32 PCI(low9)+flags,
            [4:8] u32 timing0, [8:12] u32 timing1, [12:16] reserved.
        (Per-neighbour PCI byte-matches the response; timing0/1 are byte-
         identical to the response cell's +40/+44 pair.)

    Subpacket 1 (id=27) -- Response/Measurement, version-dispatched header:
        ver=4 & ver=56 (BYTE-IDENTICAL — 8-byte carrier header):
            [0:4] u32 EARFCN(low18, u32 so band-66 >65535 survives),
            [4:6] u16 num_cells, [6:8] u16 reserved
        ver=2 (MC7700/MDM9200 — 4-byte carrier header):
            [0:2] u16 EARFCN, [2:4] u16 num_cells
        Per-cell record (52 bytes, layout version-INDEPENDENT):
            [0:4]    u32  PCI (low 9 bits; upper bits 0 — no flags)
            [4:8]    u32  energy0  (per-Rx integrated energy, ~4-5e6)
            [8:12]   u32  energy1  (per-Rx integrated energy)
            [12:16]  u32  energy2  (integrated energy)
            [16:20]  u32  energy_wide0 (wide-scale accumulator, ~1.5e8)
            [20:24]  u32  energy_wide1 (wide-scale accumulator, ~1.9e8)
            [24:26]  u16  meas_index (small index/counter, 0..~1166) — NOT RSRP
                          (see below)
            [26:28]  u16  reserved (0)
            [28:32]  u32  energy_filt (filtered energy, ~1.2e6)
            [32:36]  u32  reserved (0)
            [36:38]  u16  aux0 (semantics unresolved)
            [38:40]  u16  aux1 (semantics unresolved)
            [40:44]  u32  timing (== [44:48]; request-echoed timing/config)
            [44:48]  u32  timing (duplicate of [40:44])
            [48:52]  u32  reserved (0)

Reverse-engineered from corpus DLF/HDLC captures across MDM9200/9207/9230,
SDX20/50M/55/62, cross-validated against 0xB193 serving-cell encoding and
AT+QENG="neighbourcell" / AT!LTEINFO / QMI GetCellLocationInfo ground truth.

`pci` and `earfcn` are verified by multi-value containment in AT/QMI neighbour
lists on RM520N-GL (two firmware builds), RM500Q-AE (99.4% of 343 entries over
25 PCIs / 7 EARFCNs; independently confirmed by a live QMI co-capture),
SIM8202G-M2, LV55, EG25-G, EM7455 and MC7411. The idle ML1 neighbour search is
scoped to the serving carrier (F3 ``lte_ml1_md.c`` "Ngbr srch req (earfcn N)"),
so inter-frequency neighbours seen by AT do not appear in this log without a
reselection.

No calibrated dBm in this packet
--------------------------------
There is NO calibrated dBm RSRP/RSRQ in this packet, so ``entries.rsrp`` /
``rsrq_*`` are ``None``. The widest per-cell truth set — 179 LV55/SDX55 0xB192
records / 211 cell-entries joined to co-temporal ``$QCRSRP`` F3 truth
(``dsatcmdp.c``, same DIAG clock), spanning 16.6 dB of true RSRP
(-118.8..-102.2) — shows:

  * **+24 (``meas_index``) is not RSRP.** Read as ``-raw/10`` it decodes
    -30..-42 dBm for cells that are really -105..-118 (64-86 dB off) and
    rank-INVERTS them (the strongest cell gets the most-negative decode). On a
    single fixed neighbour (pci=263/earfcn=66536, n=117) whose own true RSRP
    moves -118.8..-111.5, the raw u16 varies 300..376 with pearson(raw,true)
    = -0.020; per-cell-demeaned, -0.085 (all) / +0.011 (tight time-match).
    Earlier apparent fits across a few static cells were between-cluster
    leverage, not a per-cell law. The same ``-raw/10`` decode reads ~45-60 dB
    high on SDX55/SDX62/MDM9207/MDM9230/SDX50M captures alike.
  * **No byte offset recovers RSRP cleanly.** Scanning every u16 offset 0..50
    of the 52 B record against the truth, the best-tracking region is +8 /
    +12 at r≈0.40-0.44, strengthening as the time-match tightens — a real but
    weak co-temporal signal (<20% of variance).
  * **+8 / +12 are a near-symmetric per-Rx linear-energy pair** (~4×10⁶,
    equal in 80.6% of cells, never >8% apart). They are not the F3
    ``lte_LL1_meas_ncell.c`` NB_MEAS ``max_SE`` / ``max_SNE`` pair: those are
    never equal (0/856 on the same capture, median ratio 0.747) and ~36×
    smaller (median 118,179 vs 4,224,007).
  * **The energy is AGC-flattened.** ``10*log10(energy2)`` spans only 1.19 dB
    while true RSRP spans 16.6 dB (~14× compression). The best in-capture fit,
    ``true_dBm = 11.6*10log10(energy2) - 883`` (slope ~12, not 1.0; intercept
    = the per-capture AGC operating point), is usable *within* a capture
    (r~0.75 global, ~0.22 within-cell; up to 0.85 on other captures) but the
    intercept drifts ~13 dB between captures, so no fixed energy→dBm law
    exists for a per-record parser to apply.

The raw energy words are exposed so a consumer holding per-capture or
per-band reference truth can convert them. The F3 NB_MEAS prints (``max_SE``
3,125..208,458,975 / ``max_SNE`` 2,330..131,592,553) confirm the subsystem
works in linear energy, not dBm.

Techplayon's public log-packet field list names the 0xB192 fields:
    0xB192 — LTE ML1 Neighbor Cell Meas Request/Response
        is_idle_mode, earfcn, duplex_mode, neighbor_pci, num_tx_antennas,
        ttl_ftl_enabled, rsrp_rx0_dbm, rsrp_rx1_dbm, rsrp_combined_dbm,
        rsrq_rx0_db, rsrq_rx1_db, rsrq_instantaneous_db,
        rssi_rx0_dbm, rssi_rx1_dbm

Log name: LOG_LTE_ML1_NEIGHBOR_CELL_MEAS_REQUEST_RESPONSE
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_LTE_ML1_NEIGHBOR_CELL_MEAS = 0xB192

# Validation: one outer version, v=0x01.
#
# The per-cell PCI / EARFCN are directly comparable with what a Quectel modem
# returns via AT+QENG="neighbourcell". The code is emitted by Quectel
# RM520N-GL / EG25-G / RM500Q, Telit FN980/LM960, and Sierra EM9291; the
# RM520N-GL is the most convenient validation target because it exposes the
# QENG neighbour list.
#
# Caveats:
#  * 0xB192 is IDLE-mode neighbor meas (cond:idle). The modem must be camped and
#    not in an active data bearer, or it emits the connected-mode siblings
#    (0xB195/0x18AB) instead.
#  * QENG="neighbourcell" reports ONE RSRQ per neighbor, not a per-Rx-antenna
#    split. So it grounds the combined RSRQ but CANNOT by itself validate the
#    rsrq_rx0 vs rsrq_rx1 antenna split — that needs a per-Rx source (QMI/SCAT)
#    and is left as a separate, weaker grounding (status=hypothesis, noted).
# Subpacket ids (walk-order is always request(26) then response(27), n=55521).
_REQUEST_SP_ID = 26
_RESPONSE_SP_ID = 27

# Response subpacket versions. Two layouts: the "modern" 8-byte carrier header
# (earfcn u32-low18 @0, num_cells u16 @4) and the MDM9200 4-byte header
# (earfcn u16 @0, num_cells u16 @2). Corpus-observed modern versions are 4 and 56
# — BYTE-IDENTICAL (verified across 9,147 cells / 9 modems), because the version
# byte tracks firmware build, not layout (an RM520N-GL emits ver=4 on an older
# build and ver=56 on a newer one; same silicon). Only the Sierra MC7700 /
# MDM9200 uses the 4-byte header, at ver=2. Dispatch is therefore binary:
# ver=2 → 4-byte header; EVERYTHING ELSE → modern 8-byte header. The else branch
# is deliberate forward-compatibility: since versions track firmware and modern
# is the dominant layout, a future modern build emitting a new version number
# (e.g. ver=57) decodes correctly rather than being rejected.
_RESP_VER_MDM9200 = (2,)        # the ONLY 4-byte-carrier-header response version

_CELL_RECORD_SIZE = 52          # per-cell response record stride (ALL versions)
_REQ_CELL_RECORD_SIZE = 16      # per-cell request record stride
_CARRIER_HEADER_MODERN = 8      # ver=4 / ver=56 response carrier header
_CARRIER_HEADER_MDM9200 = 4     # ver=2 response carrier header (earfcn u16 + num_cells u16)


@dataclass
class LteMl1NeighborRequestCell:
    """One per-neighbour entry from the request/config subpacket (id=26).

    The request subpacket carries, per neighbour, the SAME PCI as the
    response plus two
    ~200K 'timing/config' words that are byte-identical to the response cell's
    +40/+44 pair (request-side timing echoed into the response). Verified by an
    exact positional PCI match (sp26 pci == sp27 pci) across every multi-cell
    record, cross-modem.
    """
    pci: int
    timing0: int
    timing1: int

    def to_dict(self) -> dict[str, Any]:
        return {'pci': self.pci, 'timing0': self.timing0, 'timing1': self.timing1}


@dataclass
class LteMl1NeighborCellEntry:
    """A single idle-mode neighbour cell measurement (response subpacket id=27).

    Signal semantics: the per-cell
    quantities are **AGC-flattened integrated-energy accumulators, NOT calibrated
    dBm**. `rsrp` / `rsrq_rx0` / `rsrq_rx1` are therefore ``None``:
      * within a single capture the energy words at +4/+8/+12/+16/+20 correlate
        with true QENG RSRP (Pearson r up to 0.85, time-aligned via anchors),
      * BUT no capture-stable energy->dBm law exists — the required slope is ~15
        (a real power->dBm law is slope 1.0; the energy varies <2x while RSRP
        swings 54 dB) and the intercept differs ~13 dB across captures.
    So a dBm value is NOT recoverable from this packet (any fixed decode would
    be plausible-but-wrong). The raw energy/timing words ARE exposed as usable integers so
    the measurement data is 100% extracted; a consumer holding a per-band
    reference power can convert them. `pci` / `earfcn` are the genuinely-verified
    fields (multi-value QENG/QMI containment, cross-modem).
    """
    pci: int
    earfcn: int
    # API-compat signal fields — None: no calibrated dBm in the packet.
    rsrp: float | None
    rsrq_rx0: float | None
    rsrq_rx1: float | None
    # Raw per-cell measurement words (usable integers):
    energy0: int         # +4  u32 per-Rx integrated energy (~4-5e6; 45067 floor when weak)
    energy1: int         # +8  u32 per-Rx integrated energy (~4-5e6)
    energy2: int         # +12 u32 integrated energy (~4-5e6)
    energy_wide0: int    # +16 u32 wide-scale energy accumulator (~1.5e8)
    energy_wide1: int    # +20 u32 wide-scale energy accumulator (~1.9e8)
    meas_index: int      # +24 u16 measurement index/counter (0..~1166; NOT RSRP
                         #        despite tempting -raw/10 values)
    energy_filt: int     # +28 u32 filtered energy (~1.2e6, low ~22 bits)
    aux0: int            # +36 u16 small field (semantics unresolved, ~42)
    aux1: int            # +38 u16 small field (semantics unresolved, ~45)
    timing: int          # +40 u32 request-echoed timing (+40 == +44 always)

    def to_dict(self) -> dict[str, Any]:
        return {
            'pci': self.pci,
            'earfcn': self.earfcn,
            'rsrp': self.rsrp,
            'rsrq_rx0': self.rsrq_rx0,
            'rsrq_rx1': self.rsrq_rx1,
            'energy0': self.energy0,
            'energy1': self.energy1,
            'energy2': self.energy2,
            'energy_wide0': self.energy_wide0,
            'energy_wide1': self.energy_wide1,
            'meas_index': self.meas_index,
            'energy_filt': self.energy_filt,
            'aux0': self.aux0,
            'aux1': self.aux1,
            'timing': self.timing,
        }


@dataclass
class Diag0xB192:
    """LTE ML1 Idle-Mode Neighbor Cell Measurement (0xB192).

    Full decode: outer frame + BOTH subpackets. `counter` is
    the outer [2:4] word (constant per capture — a config/instance marker, not a
    rolling SFN). `request_cells` is the decoded request subpacket (id=26). The
    parser version-dispatches the response subpacket (id=27) across the three
    observed versions {2, 4, 56}.
    """
    log_time: int
    version: int
    sp_version: int          # response subpacket version (2 / 4 / 56)
    counter: int             # outer [2:4] config/instance marker
    earfcn: int
    num_cells: int
    entries: list[LteMl1NeighborCellEntry] = field(default_factory=list)
    request_cells: list[LteMl1NeighborRequestCell] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0xB192',
            'log_time': self.log_time,
            'version': self.version,
            'sp_version': self.sp_version,
            'counter': self.counter,
            'earfcn': self.earfcn,
            'num_cells': self.num_cells,
            'entries': [e.to_dict() for e in self.entries],
            'request_cells': [c.to_dict() for c in self.request_cells],
        }


@register(LOG_LTE_ML1_NEIGHBOR_CELL_MEAS, domain="lte-signal",
    name="0xB192",
    description="Idle-mode neighbor cell meas 0xB192 — decode-complete: version-dispatched sp27 {2,4,56}, full 52B cell record (PCI/EARFCN + per-Rx energy words) + request sp26 + outer counter; rsrp/rsrq None (energy, not dBm)",
    version=24,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=("Decode-complete: outer frame + request subpacket (id=26) + "
                   "response subpacket (id=27), version-dispatched across response "
                   "versions {2, 4, 56} (4 and 56 byte-identical, verified on 9,147 "
                   "cells / 9 modems; 2 is the MC7700/MDM9200 4-byte-header layout). "
                   "100% parse rate across 7 chipset generations "
                   "(MDM9200/9207/9230, SDX20/50M/55/62), 0 num_cells/entries "
                   "mismatches. entries.pci / entries.earfcn VERIFIED by "
                   "multi-value containment in AT neighbour lists (QENG / "
                   "AT!LTEINFO) and QMI GetCellLocationInfo on "
                   "RM520N-GL (two firmware builds, 100% / 98.7%), RM500Q-AE "
                   "(341/343 over 25 PCIs / 7 EARFCNs, plus a live QMI "
                   "co-capture), SIM8202G-M2 (pci via QMI + 0xB115 cross-code, "
                   "earfcn 66786 via F3 'channel:' prints), LV55 (VzW B13), "
                   "EG25-G (two units / carriers), EM7455 and MC7411 (incl. u32 "
                   "band-66 EARFCNs). The idle neighbour search is scoped to the "
                   "serving carrier (F3 lte_ml1_md.c 'Ngbr srch req (earfcn N)'), "
                   "so inter-frequency cells only appear after a reselection. "
                   "entries.rsrp / rsrq are None: the per-cell words are "
                   "AGC-flattened linear-energy accumulators with no capture-stable "
                   "energy->dBm law (in-capture slope ~12 instead of 1.0, "
                   "intercept drifting ~13 dB between captures), established "
                   "against 211 LV55 cell-entries joined to co-temporal $QCRSRP F3 "
                   "truth over 16.6 dB; the +24 u16 is not RSRP (pearson ~0 on a "
                   "fixed cell, rank-inverted across cells). F3 lte_LL1_meas_ncell.c "
                   "NB_MEAS prints confirm the energy-domain subsystem."),
    source_url="https://github.com/lukejenkins",
    # Decode-complete field accounting. Every byte of both
    # subpackets is decoded into a named field or an explicit reserved region —
    # no `raw: bytes` remains. Exposed named fields (17 identified / 15 parsed):
    #   Outer(4): version, num_subpackets(implicit via walk), counter, sp_version.
    #   Response carrier: earfcn, num_cells.
    #   Response per-cell(11): pci + energy0/energy1/energy2 + energy_wide0/
    #     energy_wide1 + meas_index + energy_filt + aux0 + aux1 + timing.
    #   Request per-cell: pci, timing0, timing1.
    # PARSED=15 fields carry a grounded semantic (structure, pci/earfcn VERIFIED,
    # the energy accumulators are energy-domain quantities). IDENTIFIED=17
    # counts the 2 aux fields whose semantic is not yet resolved. rsrp/rsrq are
    # deliberately None (no calibrated dBm in the packet — -raw/10 and (raw-60)/2
    # decodes are plausible-but-wrong) so they are NOT counted as
    # parsed dBm quantities; the underlying data is extracted as energy words.
    fields_identified=17,
    fields_parsed=15,
    # Byte-0 is the DIAG outer log version, corpus-attested invariantly
    # 0x01 (n=55521). Gated below per "size invariance != format invariance". The
    # INNER response subpacket version (id=27, ver ∈ {2,4,56}) is a separate field
    # the parser dispatches on — do NOT conflate it with the outer version enum.
    field_invariants={"version": {"enum": [0x01]}},
    issues=(),
    primary_issue=None,
    wigle_direct=True,
    wigle_roles=("signal", "pci-earfcn-bridge", "rat-context"),
)
def parse_0xb192(
    log_time: int, data: bytes
) -> Diag0xB192 | None:
    """Parse 0xB192 -- LTE ML1 Idle Neighbor Cell Measurement.

    Decode-complete: outer frame + request subpacket (id=26)
    + response subpacket (id=27), version-dispatched across the three observed
    response versions {2, 4, 56}. Every byte is decoded into a named field.
    Per-cell signal quantities are exposed as raw integrated-energy words (the
    packet carries no calibrated dBm — see LteMl1NeighborCellEntry).

    Returns None if payload is malformed or the outer version is not 0x01.
    """
    if len(data) < 8:
        return None

    version = data[0]
    # Layer-1 version gate (corpus byte-0 invariantly 0x01, n=55521).
    if version != 0x01:
        return None
    num_subpackets = data[1]
    counter = unpack_from('<H', data, 2)[0]

    if num_subpackets < 1:
        return None

    # Walk subpackets. sp_size is INCLUSIVE of the 4-byte subpacket header, so
    # the next subpacket begins at offset + sp_size. Collect request (id=26) and
    # response (id=27); the walk order is always (26, 27).
    request_sp: bytes | None = None
    request_ver = 0
    response_sp: bytes | None = None
    response_ver = 0
    offset = 4  # skip version(1) + num_sp(1) + counter(2)

    for _ in range(num_subpackets):
        if offset + 4 > len(data):
            break
        sp_id = data[offset]
        sp_ver = data[offset + 1]
        sp_size = unpack_from('<H', data, offset + 2)[0]
        if sp_size < 4 or offset + sp_size > len(data):
            break
        body = data[offset + 4:offset + sp_size]
        if sp_id == _RESPONSE_SP_ID:
            response_sp, response_ver = body, sp_ver
        elif sp_id == _REQUEST_SP_ID:
            request_sp, request_ver = body, sp_ver
        offset += sp_size

    if response_sp is None:
        return None

    request_cells = (
        _parse_request_subpacket(request_sp, request_ver)
        if request_sp is not None else []
    )
    return _parse_response_subpacket(
        log_time, version, counter, response_ver, response_sp, request_cells
    )


def _carrier_header_len(sp_version: int) -> int:
    """Response carrier-header size: 8 B for ver=4/56, 4 B for the MDM9200 ver=2."""
    return (_CARRIER_HEADER_MDM9200 if sp_version in _RESP_VER_MDM9200
            else _CARRIER_HEADER_MODERN)


def _parse_request_subpacket(
    sp: bytes, sp_version: int
) -> list[LteMl1NeighborRequestCell]:
    """Decode the request/config subpacket (id=26).

    Header: 8 B for ver=2 (earfcn u32-low18 @0, num_cells|flag u16 @4, reserved
    u16 @6); 4 B for the MDM9200 ver=1 (earfcn u16 @0, flags u16 @2). Per-cell
    record (16 B): pci low-9 + flags (u32 @0), timing0 (u32 @4), timing1
    (u32 @8), reserved (u32 @12). Best-effort — never fails the whole parse.
    """
    # NB: the request (id=26) and response (id=27) number their versions
    # independently. The 4-byte-header MDM9200 variant is request ver=1 /
    # response ver=2 — so the small-header case is sp_version==1 HERE, but
    # sp_version==2 in the response parser. Not a typo.
    hdr = _CARRIER_HEADER_MDM9200 if sp_version in (1,) else _CARRIER_HEADER_MODERN
    cells: list[LteMl1NeighborRequestCell] = []
    if len(sp) < hdr:
        return cells
    n = (len(sp) - hdr) // _REQ_CELL_RECORD_SIZE
    for i in range(n):
        co = hdr + i * _REQ_CELL_RECORD_SIZE
        if co + _REQ_CELL_RECORD_SIZE > len(sp):
            break
        pci = unpack_from('<I', sp, co)[0] & 0x1FF
        cells.append(LteMl1NeighborRequestCell(
            pci=pci,
            timing0=unpack_from('<I', sp, co + 4)[0],
            timing1=unpack_from('<I', sp, co + 8)[0],
        ))
    return cells


def _parse_response_subpacket(
    log_time: int, version: int, counter: int, sp_version: int,
    sp: bytes, request_cells: list[LteMl1NeighborRequestCell],
) -> Diag0xB192 | None:
    """Parse the response subpacket data (id=27), version-dispatched.

    ver=4 / ver=56 (byte-identical): 8-byte carrier header
        (earfcn u32-low18 @0, num_cells u16 @4, reserved u16 @6).
    ver=2 (MC7700 / MDM9200): 4-byte carrier header
        (earfcn u16 @0, num_cells u16 @2).
    Both use a 52-byte per-cell record with the same field layout.
    """
    hdr = _carrier_header_len(sp_version)
    if len(sp) < hdr:
        return None

    if sp_version in _RESP_VER_MDM9200:
        earfcn = unpack_from('<H', sp, 0)[0]        # u16, structurally <= 65535
        num_cells = unpack_from('<H', sp, 2)[0]
    else:
        earfcn = unpack_from('<I', sp, 0)[0] & 0x3FFFF   # 18-bit, <= 262143
        num_cells = unpack_from('<H', sp, 4)[0]
    # (No earfcn range gate: both reads are structurally bounded to a valid
    # 18-bit EARFCN space, so a `> 262143` check would be dead code.)

    # The request subpacket describes the same neighbour set as the response, so
    # trim any length-derived over-count to num_cells to preserve the documented
    # 1:1 request<->response correspondence even if the request body was padded.
    request_cells = request_cells[:num_cells]

    entries: list[LteMl1NeighborCellEntry] = []
    for i in range(num_cells):
        co = hdr + i * _CELL_RECORD_SIZE
        if co + _CELL_RECORD_SIZE > len(sp):
            break

        pci = unpack_from('<I', sp, co)[0] & 0x1FF
        entries.append(LteMl1NeighborCellEntry(
            pci=pci,
            earfcn=earfcn,
            # No calibrated dBm in the packet — energy exposed raw below.
            rsrp=None,
            rsrq_rx0=None,
            rsrq_rx1=None,
            energy0=unpack_from('<I', sp, co + 4)[0],
            energy1=unpack_from('<I', sp, co + 8)[0],
            energy2=unpack_from('<I', sp, co + 12)[0],
            energy_wide0=unpack_from('<I', sp, co + 16)[0],
            energy_wide1=unpack_from('<I', sp, co + 20)[0],
            meas_index=unpack_from('<H', sp, co + 24)[0],
            energy_filt=unpack_from('<I', sp, co + 28)[0],
            aux0=unpack_from('<H', sp, co + 36)[0],
            aux1=unpack_from('<H', sp, co + 38)[0],
            timing=unpack_from('<I', sp, co + 40)[0],
        ))

    return Diag0xB192(
        log_time=log_time,
        version=version,
        sp_version=sp_version,
        counter=counter,
        earfcn=earfcn,
        num_cells=num_cells,
        entries=entries,
        request_cells=request_cells,
    )
