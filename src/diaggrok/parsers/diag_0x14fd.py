"""0x14FD — GNSS data report: two version-specific TLE serving-cell records.

The full byte map is in the comment block below the imports.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# 0x14FD — two version-specific payloads that share only the log code
# ---------------------------------------------------------------------------
# Cross-corpus structural decomposition (one walk over all 364 bearing captures):
#
#   (size|version) is a perfect 1:1 across 89,567 records / 364 captures and no
#   capture mixes the two:
#     218B / v=0x08 (56,221 rec): SDX20 / MDM9x07 / MDM9x30-era parts — Quectel
#       EG25-G / EG18-NA / EG95-NA / EP06-A / EG12-GT, Telit LM960, Sierra
#       MC7455 / EM7455, SIMCom SIM7600NA, Fibocom NL668-AM.
#     391B / v=0x0a (33,346 rec): 5G-NR SDX silicon (SDX55/SDX62/SDX65/SDX72).
#   The two versions are DIFFERENT STRUCTS, not a grown layout. Both are
#   Terrestrial Location Engine (TLE) serving-cell records: v0x08 carries the
#   serving cell's LEARNED (cell-database) position; v0x0a carries the GNSS fix
#   the TLE received, tagged with the serving cell it was taken in. Never read
#   one through the other's offsets.
#
# byte1 (`state`) is an RF/session-state discriminator, not a counter (0x05 /
#   0x02 dominant, 0x01 / 0x03 trace, intra-capture variance). byte2/byte3 mean
#   different things per version: on v0x0a they are the MCC (u16 [2:4] — 310 /
#   311 / 315, see the v0x0a block; the 0x36/0x37/0x3b byte2 values are MCC's
#   low byte, not a chipset/GNSS-config discriminator); on v0x08 byte2 is 0x00..0x2c,
#   copied verbatim at body [40] in 100% and at [112] in 99.9% of records —
#   meaning still unknown, left as `byte2` — and byte3 is 0x00.
#
# --- 218B / v0x08 body: TLE/TLM SERVING-CELL RECORD ------------------------
# What emits it: the Terrestrial Location Engine / Manager (`tle_log.c`,
#   `tlm_ptm.c`, `ale_getpt.c`) on each cell / position / time update; every
#   record is co-emitted (<= 10 ms) with a 0x1476 position report. It is NOT a
#   device fix: no varying field tracks the live 0x1476 fix (the same finder
#   locates v0x0a's live lat/lon as a positive control).
#
#   [4:6]    u16  mcc              \
#   [6:8]    u16  mnc               | F3 `tle_log.c:669` "MCC, MNC, CellId,
#   [8:10]   u16  tac_lac           | Physical CellId, TAC, DL Freq" byte-join
#   [10]     u8   rat  1=GSM 3=LTE  | 36/36 (LM960 SDX20 LTE); GSM form "MCC,
#   [11]     u8   0x07 (const, raw) | MNC, LAC, CellId, Band, BsIc, Arfcn" 6-7/7
#   [12:16]  u32  cell_id           | (EG25-G MDM9607). WiGLE cross-check: 4/5
#   RAT-specific [30:38]:           | SIB1-derived WiGLE cells (one drive) have
#     LTE: [30:34] u32 pci          | the exact MCCMNC_TAC_ECI key. 0x60
#          [34:38] u32 earfcn       | EVENT_GNSS_TLE_TIME_TAG_C payload [3:5]=PCI,
#     GSM: [30:32] u16 arfcn        | [5:7]=EARFCN 55/55. `tlm_ptm.c:2779` "LTE
#          [32]    u8  bsic         | EARFCN: (%u) set to (%u)" -> [34] 30/36.
#          [33]    u8  gsm_band    /  EARFCN is u32 (Band-66/71 values > 65535).
#   [16:26] zero; [26:30] u32 == 220 in every record (raw).
#
#   Block A — time-transfer anchor (GPS time <-> 32.768 kHz slow clock):
#   [45:49]  u32  time_anchor_gps_ms    GPS ms-of-week \ == 0x1476 GPS week 100%,
#   [49:51]  u16  time_anchor_gps_week  GPS week        / lags emission p50 15.5 s
#   [74:78]  u32  time_anchor_slow_clock  sleep-clock tick count ("Tk"): corpus
#            dTk/dms median 32.7646 (n=1,658); the firmware's own "TkMs .. Tk ..
#            GMs" (tick, GPS-ms) pairs predict it within p50 4.8 ticks.
#   [55:59]  u32  time_anchor_unc_ns  time uncertainty of the anchor, ns: joined
#            on the exact time-update identity ([49]/[45] == the print's Week /
#            GPSMsec), F3 `mc_clock.c:5151` "TimeEstPut. FCount Week GPSMsec Bias
#            Unc SrcID" Unc (ms) == [55:59] / 1e6 in 344/346 (EG25-G MDM9607).
#            Non-zero iff A is valid, every record.
#   A is all-zero (time_anchor_valid False) in ~48% of records; [43:45] is then
#   0xffff (a small u16, 0..14, when A is valid — raw). Raw: [42] (0x04/0x44 —
#   NOT an anchor-valid flag, 0x44 occurs on both), [51:55] i32 (always within
#   +/-500,000 when A is valid — sub-millisecond-residual-shaped, ns; no
#   labelling print found).
#
#   Block B — serving-cell position from the TLM cell database:
#   [88:92]  i32  cell_lat_deg  LSB = 180/2^32 deg
#   [92:96]  i32  cell_lon_deg  LSB = 360/2^32 deg
#   [96:98]  i16  cell_alt_m
#            F3 "Serving cell position updated. Lat, Long, Alt, Punc" < 1 m in
#            155/161 (Alt exact); 0x60 EVENT_GNSS_TLE_POS_UPDATE_C (f32 radians)
#            == B within 0.29 m (f32 quantization) 56/56; negative control: the
#            "TPC: ALE position" (device) line matches B 0/133. On mobile drives B
#            steps at serving-cell changes (22/23, 10/13) and is only refined
#            within a cell — it is a per-cell learned position, NOT the device's
#            location, so it must never be used as an observation position.
#            An MCC-level default (38.000, -117.000) with a ~2,300-4,900 km Punc
#            appears when the cell is unknown.
#   [98:101] raw — uncertainty-like, not a function of the printed Punc alone.
#   [101]    u8  cell_pos_time_type — selects what [102:106] holds:
#            1 -> GPS ms-of-week, [106:108] week set (55,563 rec); 2 -> week zero
#            (558); 0 -> no time (100). Same scheme as the aux block's [187].
#   [102:106] u32 cell_pos_time_ms — type 1: GPS ms-of-week of the cell-position
#            update: (week, ms) is a PAST GPS time vs the co-emitted 0x1476 clock
#            in 51,738/51,766 records (lag p50 742 s, p95 14 h); on EG25-G it
#            equals a `ale_proc.c:7648` "PE: Deliver PQWP1 at [GpsWk, GpsMs]"
#            GpsMs exactly in 61/463. Type 2: the modem millisecond tick — on
#            LM960 every exact hit of an `ale_getpt.c:1201` "TLE/Cell-DB time.
#            TimeTickMsec" value is a type-2 record (6/241 type 2, 0/11,509
#            type 1). (Formerly named `cell_pos_time_tick_ms`, before the type
#            byte was identified.)
#   [106:108] u16 cell_pos_gps_week  == `tlm_ptm.c:6346` "GPS_WK" 366/366.
#   B is all-zero (cell_pos_valid False) in 100 of 56,221 records.
#
#   Block C/D — auxiliary positions + area record (CANDIDATE semantics):
#   [157:161]/[165:169] i32 aux1_lat_deg / aux1_lon_deg  (same encoding as B)
#   [161:165]/[169:173] i32 aux2_lat_deg / aux2_lon_deg  (== the MCC default
#            38.000/-117.000 in 45,183 records)
#   [187] u8 aux_time_type: 1 -> [188:194] ms+week both set (30,488/30,488),
#            2 -> week zero (25,733/25,733).
#   [188:192] u32 aux_time_ms — type 1: GPS ms-of-week (a past GPS time vs
#            0x1476 in 27,621/27,626, lag p50 20 s); type 2: modem ms tick.
#            (Formerly named `aux_time_tick_ms`.)
#   [192:194] u16 aux_time_gps_week
#   [207:209] u16 aux_tac_lac  == tac_lac in 56,206/56,221.
#   Raw: [173:187], [196:198] (0xffff const), [198], [209] (== 1 iff state 0x05),
#   [210], [212:214] (0xffff const).
#
# --- 391B / v0x0a body: TLE FIX-TAGGED SERVING-CELL RECORD -------------------
# What it is: the GNSS fix handed to the Terrestrial Location Engine, tagged
#   with the serving cell it was taken in. Emission is co-timed with the
#   `sm_api.c "Fix report for SM"` F3 print (96% nearest-print co-emission).
#   The record carries the serving-cell key, the fix's GPS time,
#   uncertainties, velocity and a leap-second block. On a bench it re-emits
#   the TLE's last stored fix (one FN980 run: 638 records, one payload, a fix
#   older than the whole NMEA log).
#
#   Serving-cell identity (mirrors v0x08's [4:16]/[30:38] content):
#   [2:4]    u16  mcc        \  F3 `tle_base.cpp:104` "MCC, MNC, TAC, CellId,
#   [4:6]    u16  mnc         | PhyId, EARFCN, Freq" (FN980 SDX55 mobile drive):
#   [6:8]    u16  tac_lac     | MCC/MNC/TAC/EARFCN 89/89 on the nearest print;
#   [8:12]   u32  cell_id     | (cell_id, pci) is one of the printed cells' pairs
#   [35:37]  u16  pci         | 83/89 (the record trails the latest print on a
#   [37:39]  u16  == tac_lac  | moving drive). Independent parser cross-check:
#   [39:43]  u32  earfcn     /  the co-emitted 0x1748 (SDX62 v01 serving TAC /
#            ECI / EARFCN) agrees on all three in 2,040/2,216 (the rest are ECIs
#            present elsewhere in the same capture — handover lag). Full walk:
#            all three agree in 30,522/33,343 latest-before joins; the ECI is a
#            0x1748 cell of the same capture in 32,516. 0x60
#            EVENT_GNSS_TLE_CELL_CHANGE_C (1947) payload is
#            `01 00 | 04 | MCC | MNC | TAC | ECI` — the same fields in v0x0a's
#            order; the whole 5-field tuple recurs as a v0x0a record's identity
#            within +/-1 s for 14/31 events (the rest: cells with no fix to tag).
#   [12] u8 == 0x04 in every record (raw; the same byte precedes MCC in the
#   event-1947 payload — a RAT code in the TLE's enum, but constant, so no
#   non-LTE value exists to test it); [13:35] all zero (raw).
#
#   The fix:
#   [43:47] / [47:51] / [51:55] f32 latitude_deg / longitude_deg / altitude_m —
#            LG290P RTCM MSM7 ground truth on two SDX55 modems; and the
#            0x1476 carrying the IDENTICAL (week, TOW) fix time has equal lat
#            11,826 / lon 11,827 / alt 11,673 of 11,832 joins (full walk).
#   [55:59]  f32  hor_unc_m  — the TLE's "Serving cell position updated" print
#            (same lat/lon) has Punc == 20000 + [55] in 1,257/1,563 (RM500Q
#            drive: the fix seeds the cell position with a 20 km inflation); the
#            "PTM:ALE pos .. PUNC, AltUnc" print carrying the same lat/lon has
#            PUNC == [55] 225/373 and
#   [59:63]  f32  vert_unc_m — AltUnc == [59] 230/373 (to 0.01 m).
#   [63]     u8   fix_valid_mask — bit0 = position block set, bit1 = velocity
#            block [65:81] set, bit2 = time/leap block [103:112] set; each bit
#            tracks its block with no exception in all 33,346 records (7: 17,669
#            / 5: 9,949 / 1: 4,407 / 0: 1,321).
#   [65:69]  f32  speed_mps  \  == the same-fixtime 0x1476 speed_mps / heading
#   [73:77]  f32  heading_rad /  (radians) in 7,422/7,575 bit1-set joins; with
#            bit1 clear the block is zero. [69:73] / [77:81] f32 raw
#            (speed-unc- / heading-unc-shaped; no decoded oracle field matches).
#   [81:83]  u16  fix_gps_week \ the fix's GPS time — the join key above; F3 TPC
#   [83:87]  u32  fix_gps_ms   / "Wk" 161/188. Trails emission (stored fix).
#   [87] / [88] u8 raw — 0/2/3/4 (horizontal/vertical-reliability-shaped; the
#            only reliability prints found are constant, so not grounded).
#   [89:103] u8[14] contrib_pct — sums to EXACTLY 100 in every position-valid
#            record (32,025) and to 0 in every no-position record (1,321): a
#            per-source percentage split of the fix. CANDIDATE slot names
#            (docstring only): [91] tracks GPS use (modem NMEA GSA, 1,473/1,473),
#            [92] GLONASS (1,416/1,473), [99] is 100 for cell-only fixes (mask 1).
#   [103]    u8   leap_seconds — 18 (GPS-UTC since 2017) whenever bit2 is set;
#            F3 `lm_tm.c:370` "LeapSec: 18" (RM520N-GL). [105] u8 == 1 with it.
#   [106:110] / [110:112] a second copy of fix_gps_ms / fix_gps_week, present
#            iff bit2 (raw — not re-exposed).
#   [114] == 2, [115] == 1 on every non-empty record (raw). [116:383] zero.
#   [383:385] u16 raw — differs between otherwise-identical back-to-back copies.
#   No-fix record (mask 0): the serving-cell identity [2:13]/[35:43] is still
#   present (every such record) and [43:383] is zero — the cell is known, the
#   TLE has no fix to tag it with.
#
# Oracles: QCSuper / SCAT do not decode 0x14FD (silent for both versions).
#   0x60: LABELED for both — v0x08 via TLE_POS_UPDATE_C /
#   TLE_TIME_TAG_C (1948/1949, MDM9x07/SDX20 builds), v0x0a via
#   TLE_CELL_CHANGE_C (1947; a 4-capture SDX55/SDX62/SDX65/SDX72 event census
#   shows 1947 + TLE_TIME_UPDATE_C 1951 and no 1948/1949).

_LAT_SCALE = 180.0 / 2**32   # deg per LSB, v0x08 i32 latitude
_LON_SCALE = 360.0 / 2**32   # deg per LSB, v0x08 i32 longitude
_RAT_GSM = 1
_RAT_LTE = 3


@dataclass
class Diag0x14FD:
    """GNSS data report (0x14FD) — two version-specific TLE serving-cell records.

    218B variant (v=0x08): serving-cell identity (MCC/MNC/TAC-or-LAC/RAT/cell id
    + LTE PCI/EARFCN or GSM ARFCN/BSIC/band), a GPS-time <-> slow-clock anchor,
    and the serving cell's learned position (``cell_lat_deg`` / ``cell_lon_deg``
    / ``cell_alt_m``, a cell-database estimate — NOT the device location).
    391B variant (v=0x0a): the GNSS fix handed to the TLE, tagged with the
    serving cell (MCC/MNC/TAC/cell id/PCI/EARFCN) — ``latitude_deg`` /
    ``longitude_deg`` / ``altitude_m`` (the device fix), its uncertainties,
    velocity, GPS time and a per-source contribution split. Fields that do not
    apply to a record's version are ``None``; undecoded bytes stay in
    ``body_raw``.
    """
    log_time: int
    version: int       # byte 0 — 0x08 on 218B variant, 0x0a on 391B variant
    state: int         # byte 1 — RF/session-state discriminator (0x05/0x02/0x01/0x03)
    byte2: int         # byte 2 — v0x0a: MCC low byte; v0x08: unknown (copied at [40])
    byte3: int         # byte 3 — v0x0a: MCC high byte; v0x08: 0x00
    payload_size: int
    body_raw: bytes
    # 391B / v0x0a only (None on the 218B variant) — the fix:
    latitude_deg: float | None = None
    longitude_deg: float | None = None
    altitude_m: float | None = None
    position_valid: bool | None = None
    hor_unc_m: float | None = None
    vert_unc_m: float | None = None
    fix_valid_mask: int | None = None   # bit0 position, bit1 velocity, bit2 time/leap
    speed_mps: float | None = None      # bit1 set only
    heading_rad: float | None = None    # bit1 set only
    fix_gps_week: int | None = None
    fix_gps_ms: int | None = None
    leap_seconds: int | None = None     # bit2 set only
    contrib_pct: list[int] | None = None
    # Serving-cell identity — both versions (v0x08 [4:16]/[30:38], v0x0a
    # [2:12]/[35:43]); rat and the GSM fields are v0x08 only:
    mcc: int | None = None
    mnc: int | None = None
    tac_lac: int | None = None
    rat: int | None = None
    cell_id: int | None = None
    pci: int | None = None          # LTE (v0x08 rat 3; every v0x0a record)
    earfcn: int | None = None       # LTE (v0x08 rat 3; every v0x0a record)
    arfcn: int | None = None        # GSM (rat 1)
    bsic: int | None = None         # GSM (rat 1)
    gsm_band: int | None = None     # GSM (rat 1)
    # v0x08 block A — GPS-time <-> slow-clock anchor:
    time_anchor_gps_week: int | None = None
    time_anchor_gps_ms: int | None = None
    time_anchor_slow_clock: int | None = None
    time_anchor_unc_ns: int | None = None
    time_anchor_valid: bool | None = None
    # v0x08 block B — serving cell's learned (cell-database) position:
    cell_lat_deg: float | None = None
    cell_lon_deg: float | None = None
    cell_alt_m: int | None = None
    cell_pos_valid: bool | None = None
    cell_pos_time_type: int | None = None   # 1 GPS ms-of-week, 2 modem ms tick
    cell_pos_time_ms: int | None = None
    cell_pos_gps_week: int | None = None
    # v0x08 block C/D — auxiliary positions + area record (CANDIDATE semantics):
    aux1_lat_deg: float | None = None
    aux1_lon_deg: float | None = None
    aux2_lat_deg: float | None = None
    aux2_lon_deg: float | None = None
    aux_time_type: int | None = None        # 1 GPS ms-of-week, 2 modem ms tick
    aux_time_ms: int | None = None
    aux_time_gps_week: int | None = None
    aux_tac_lac: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x14FD',
            'log_time': self.log_time,
            'version': self.version,
            'state': self.state,
            'byte2': self.byte2,
            'byte3': self.byte3,
            'payload_size': self.payload_size,
        }
        if self.version == 0x0a and self.mcc is not None:
            d['mcc'] = self.mcc
            d['mnc'] = self.mnc
            d['tac_lac'] = self.tac_lac
            d['cell_id'] = self.cell_id
            d['pci'] = self.pci
            d['earfcn'] = self.earfcn
            d['fix_valid_mask'] = self.fix_valid_mask
            d['latitude_deg'] = self.latitude_deg
            d['longitude_deg'] = self.longitude_deg
            d['altitude_m'] = self.altitude_m
            d['position_valid'] = self.position_valid
            d['hor_unc_m'] = self.hor_unc_m
            d['vert_unc_m'] = self.vert_unc_m
            d['speed_mps'] = self.speed_mps
            d['heading_rad'] = self.heading_rad
            d['fix_gps_week'] = self.fix_gps_week
            d['fix_gps_ms'] = self.fix_gps_ms
            d['leap_seconds'] = self.leap_seconds
            d['contrib_pct'] = self.contrib_pct
        elif self.version == 0x08 and self.mcc is not None:
            d['mcc'] = self.mcc
            d['mnc'] = self.mnc
            d['tac_lac'] = self.tac_lac
            d['rat'] = self.rat
            d['cell_id'] = self.cell_id
            if self.rat == _RAT_LTE:
                d['pci'] = self.pci
                d['earfcn'] = self.earfcn
            elif self.rat == _RAT_GSM:
                d['arfcn'] = self.arfcn
                d['bsic'] = self.bsic
                d['gsm_band'] = self.gsm_band
            d['time_anchor_valid'] = self.time_anchor_valid
            d['time_anchor_gps_week'] = self.time_anchor_gps_week
            d['time_anchor_gps_ms'] = self.time_anchor_gps_ms
            d['time_anchor_slow_clock'] = self.time_anchor_slow_clock
            d['time_anchor_unc_ns'] = self.time_anchor_unc_ns
            d['cell_pos_valid'] = self.cell_pos_valid
            d['cell_lat_deg'] = self.cell_lat_deg
            d['cell_lon_deg'] = self.cell_lon_deg
            d['cell_alt_m'] = self.cell_alt_m
            d['cell_pos_time_type'] = self.cell_pos_time_type
            d['cell_pos_time_ms'] = self.cell_pos_time_ms
            d['cell_pos_gps_week'] = self.cell_pos_gps_week
            d['aux1_lat_deg'] = self.aux1_lat_deg
            d['aux1_lon_deg'] = self.aux1_lon_deg
            d['aux2_lat_deg'] = self.aux2_lat_deg
            d['aux2_lon_deg'] = self.aux2_lon_deg
            d['aux_time_type'] = self.aux_time_type
            d['aux_time_ms'] = self.aux_time_ms
            d['aux_time_gps_week'] = self.aux_time_gps_week
            d['aux_tac_lac'] = self.aux_tac_lac
        return d


def _decode_v08(rec: Diag0x14FD, data: bytes) -> None:
    """Fill the 218B / v0x08 serving-cell record fields (offsets per the
    field map above; fixed across every v0x08 chipset in the corpus)."""
    rec.mcc, rec.mnc, rec.tac_lac = unpack_from('<HHH', data, 4)
    rec.rat = data[10]
    rec.cell_id = unpack_from('<I', data, 12)[0]
    if rec.rat == _RAT_LTE:
        rec.pci, rec.earfcn = unpack_from('<II', data, 30)
    elif rec.rat == _RAT_GSM:
        rec.arfcn = unpack_from('<H', data, 30)[0]
        rec.bsic = data[32]
        rec.gsm_band = data[33]
    # Unrecognised RAT values: identity header still decoded; RAT-specific
    # [30:38] left in body_raw rather than guessed.

    rec.time_anchor_gps_ms = unpack_from('<I', data, 45)[0]
    rec.time_anchor_gps_week = unpack_from('<H', data, 49)[0]
    rec.time_anchor_unc_ns = unpack_from('<I', data, 55)[0]
    rec.time_anchor_slow_clock = unpack_from('<I', data, 74)[0]
    rec.time_anchor_valid = not (rec.time_anchor_gps_ms == 0
                                 and rec.time_anchor_gps_week == 0)

    lat_i, lon_i, alt = unpack_from('<iih', data, 88)
    rec.cell_lat_deg = lat_i * _LAT_SCALE
    rec.cell_lon_deg = lon_i * _LON_SCALE
    rec.cell_alt_m = alt
    rec.cell_pos_valid = not (lat_i == 0 and lon_i == 0)
    rec.cell_pos_time_type = data[101]
    rec.cell_pos_time_ms = unpack_from('<I', data, 102)[0]
    rec.cell_pos_gps_week = unpack_from('<H', data, 106)[0]

    a1_lat, a2_lat, a1_lon, a2_lon = unpack_from('<iiii', data, 157)
    rec.aux1_lat_deg = a1_lat * _LAT_SCALE
    rec.aux1_lon_deg = a1_lon * _LON_SCALE
    rec.aux2_lat_deg = a2_lat * _LAT_SCALE
    rec.aux2_lon_deg = a2_lon * _LON_SCALE
    rec.aux_time_type = data[187]
    rec.aux_time_ms = unpack_from('<I', data, 188)[0]
    rec.aux_time_gps_week = unpack_from('<H', data, 192)[0]
    rec.aux_tac_lac = unpack_from('<H', data, 207)[0]


_V0A_POS_VALID = 0x01   # fix_valid_mask bit0 — position block [43:63]
_V0A_VEL_VALID = 0x02   # bit1 — velocity block [65:81]
_V0A_TIME_VALID = 0x04  # bit2 — time/leap block [103:112]


def _decode_v0a(rec: Diag0x14FD, data: bytes) -> None:
    """Fill the 391B / v0x0a fix-tagged serving-cell record fields (offsets per
    the field map above). Velocity and leap seconds are only exposed when their
    ``fix_valid_mask`` bit is set — with the bit clear the bytes are zero, not a
    measured 0 m/s. The cell identity is decoded unconditionally: a no-fix
    record (mask 0) still names its serving cell."""
    rec.mcc, rec.mnc, rec.tac_lac = unpack_from('<HHH', data, 2)
    rec.cell_id = unpack_from('<I', data, 8)[0]
    rec.pci = unpack_from('<H', data, 35)[0]
    rec.earfcn = unpack_from('<I', data, 39)[0]
    lat, lon, alt, hunc, vunc = unpack_from('<fffff', data, 43)
    rec.latitude_deg = lat
    rec.longitude_deg = lon
    rec.altitude_m = alt
    # No-fix sentinel: the whole position block is zero-filled.
    rec.position_valid = not (lat == 0.0 and lon == 0.0)
    rec.hor_unc_m = hunc
    rec.vert_unc_m = vunc
    mask = data[63]
    rec.fix_valid_mask = mask
    if mask & _V0A_VEL_VALID:
        rec.speed_mps = unpack_from('<f', data, 65)[0]
        rec.heading_rad = unpack_from('<f', data, 73)[0]
    rec.fix_gps_week, rec.fix_gps_ms = unpack_from('<HI', data, 81)
    rec.contrib_pct = list(data[89:103])
    if mask & _V0A_TIME_VALID:
        rec.leap_seconds = data[103]


# --- Ground-truth recipe ---------------------------------------------------
# The 391B / v0x0a body position block (latitude/longitude/altitude) is grounded
# offline against LG290P RTCM MSM7 reference truth; its cell identity, fix time,
# uncertainty and velocity are byte-joined to in-capture F3 and co-emitted logs
# (0x1476, 0x1748). The 218B / v0x08 serving-cell record is grounded by
# in-capture F3 + 0x60 event oracles.

@register(
    0x14FD, domain="gnss",
    name="0x14FD",
    description=("GNSS data report (0x14FD) — two TLE serving-cell records: v0x08 218B "
                 "(cell identity + time anchor + cell-DB position) / v0x0a 391B (the "
                 "GNSS fix tagged with the serving cell: identity + position + "
                 "uncertainty + velocity + fix time)"),
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=("Clean-room RE from FN980m SDX55 + EG18-NA SDX20 V2; 391B position "
                   "block cross-validated vs LG290P RTCM MSM7 and byte-joined to the "
                   "same-fixtime 0x1476, its cell identity to F3 tle_base.cpp and the "
                   "co-emitted 0x1748; 218B serving-cell record byte-joined to F3 "
                   "tle_log.c/tlm_ptm.c/ale_getpt.c/mc_clock.c prints and 0x60 "
                   "EVENT_GNSS_TLE_POS_UPDATE_C / EVENT_GNSS_TLE_TIME_TAG_C payloads. "
                   "A payload shorter than its version's fixed record (v0x08 218 B / "
                   "v0x0a 391 B) returns None (registry WARN)."),
    source_url="",
    issues=(),
    primary_issue=None,
    # Both versions carry the serving-cell key (MCC/MNC/TAC/cell id) and its
    # RAT/EARFCN context; v0x0a also carries the device fix. v0x08's
    # cell_lat/lon is a cell-DB estimate, not an observation position.
    wigle_direct=True,
    wigle_roles=("identity", "position", "rat-context"),
    # Completeness metadata. Identified+parsed fields: the 4-byte
    # header (version, state, byte2, byte3) shared by both variants; the cell
    # identity (mcc, mnc, tac_lac, rat, cell_id, pci, earfcn, arfcn, bsic,
    # gsm_band — the non-GSM subset on both versions); v0x0a's fix
    # (latitude_deg, longitude_deg, altitude_m, hor_unc_m, vert_unc_m,
    # fix_valid_mask, speed_mps, heading_rad, fix_gps_week, fix_gps_ms,
    # leap_seconds, contrib_pct); v0x08's time anchor
    # (time_anchor_gps_week/_gps_ms/_slow_clock/_unc_ns), cell position
    # (cell_lat_deg/_lon_deg/_alt_m, cell_pos_time_type, cell_pos_time_ms,
    # cell_pos_gps_week) and auxiliary block (aux1/aux2 lat/lon, aux_time_type,
    # aux_time_ms, aux_time_gps_week, aux_tac_lac). The *_valid flags are
    # derived (not on-wire fields, so not counted). Raw/unnamed bytes of both
    # variants stay in body_raw and are NOT in the denominator — 44/44 means
    # "everything identified is parsed", not "100% of bytes decoded".
    fields_identified=44,
    fields_parsed=44,
    # byte3 is NOT pinned: on v0x0a it is the MCC high byte (0x01 for US MCCs
    # 310-316, 0x02 for e.g. 724), so an enum [0x00, 0x01] would reject every
    # MCC outside 256..511.
    field_invariants={
        "version": {"enum": [0x08, 0x0a]},
        "payload_size": {"enum": [218, 391]},
    },
)
def parse_0x14fd(log_time: int, data: bytes) -> Diag0x14FD | None:
    if len(data) < 4:
        return None
    # Layer-1 enforcement of field_invariants version=[0x08, 0x0a].
    # Clean 1:1 (version, payload_size): v=0x08 @ 218B (SDX20/MDM9x07/MDM9x30
    # era), v=0x0a @ 391B (SDX55/SDX62 5G-NR era).
    if data[0] not in (0x08, 0x0a):
        return None
    # Each version is a fixed-offset record (v0x08 218 B, v0x0a 391 B). A
    # shorter payload is truncated and returns None (registry WARN) rather than
    # degrading to a header-only record. Longer payloads are accepted (body
    # offsets are fixed).
    if len(data) < (391 if data[0] == 0x0a else 218):
        return None
    rec = Diag0x14FD(
        log_time=log_time,
        version=data[0],
        state=data[1],
        byte2=data[2],
        byte3=data[3],
        payload_size=len(data),
        body_raw=data[4:],
    )
    # Version-dispatched body decode. Offsets are fixed per version; the full
    # record length was validated above.
    if data[0] == 0x0a:
        _decode_v0a(rec, data)
    else:
        _decode_v08(rec, data)
    return rec
