"""0x1807 — GNSS position-engine multiplexed measurement log, full per-(version,subtype) decode.

**Subsystem: GNSS, not LTE ML1** (F3-grounded on every F3-bearing capture).
The record's GPS time is printed, as an exact argument, by the GNSS position
engine's own F3 at the same epoch (≤ 1 ms), on every version:

  * subtype 4 (heartbeat) ``tick_ms`` @[5:9] = GPS ms-of-week —
    ``nf_navsolution.c "L1 band jamming detected …"`` args (…, week, msec),
    ``nf_navsolution.c "UpdEnvDetector: [Fcount=%lu, GpsMsec=%lu …"`` arg1,
    ``gile_proc.c "GILE: Virgo Integral not found for GpsMsec %u"`` arg0,
    ``tle_ptm_mgr.cpp`` / ``tlm_ptm.c`` arg2.
  * subtypes 1/2/3 ``ts0_gps_ms mod 604800000`` = the same ms-of-week —
    ``ple_proc.c`` (PLE propagation / de-weighting prints) and ``ale_proc.c``.

A control (the value + 500 ms, still inside the live time range) scores 0 at
≤ 1 ms on every version. Co-temporal ``lte_ml1_*`` F3 in a single capture can
suggest an LTE ML1 log, but those prints are not co-emitted with the record.
Consequences: ``cell_id_cand`` (subtype 2) is NOT supported as an LTE PCI — it
stays a raw u16 (0..503) with unknown GNSS meaning; the subtype-1/2 floats are
GNSS-engine internals. The full decoder rests on a 6,379-record
cross-generation corpus walk (12 captures, MDM9x07 / MDM9x30 /
MDM9x40 / SDX20 / SDX55 / X55 / SDX62 / SDX65) with adversarial verification of
every structural claim.

=== The dispatch model — (version byte0, subtype byte2) ===

0x1807 is a MULTIPLEXED log: one wire code carries four distinct message layouts,
selected by **byte 2 (subtype)**, at a **byte 0 (version)** that tracks the header
format generation. The (version, subtype) pair is 1:1 with the 13 corpus profiles:

  version subtype size  class          emitting chips (generations)
  ------- ------- ----  -------------  ---------------------------------------
  0x01    4        40   heartbeat      em9190/fn980/rm500q/sim8202/lm960/em7511/eg18na
  0x0b    4        40   heartbeat      rm520ngl/em9291                     (SDX62/65)
  0x03    3       248   medium         lm960/em7511/em7455/mc7455/eg18na
  0x04    3       284   medium         em9190/fn980/rm500q/sim8202         (SDX55/X55)
  0x0b    3       368   medium         rm520ngl/em9291                     (SDX62/65)
  0x04    1      2021   large type-1   lm960/em7511/em7455/mc7455/eg18na
  0x05    1      2708   large type-1   em9190/fn980/rm500q/sim8202         (SDX55)
  0x0b    1      2828   large type-1   rm520ngl/em9291                     (SDX62/65)
  0x05    2      1767   fine  type-2   em7455/mc7455                       (MDM9x30)
  0x06    2      1900   fine  type-2   lm960/em7511/eg18na
  0x09    2      2614   fine  type-2   sim8202                             (X55)
  0x0a    2      2593   fine  type-2   em9190/fn980/rm500q                 (SDX55)
  0x0b    2      2939   fine  type-2   rm520ngl/em9291                     (SDX62/65)

`version` is a layout/format tag, NOT a silicon id (0x04 spans 5 generations); do
not read generation from it. **0x09 is a real, corpus-attested version** (SIM8202
X55, 150 records).

=== Universal header (subtypes 1/2/3 share bytes 0..28) ===

  off    field           grnd  meaning
  -----  --------------  ----  --------------------------------------------------
  0      version         ✅    format enum {01,03,04,05,06,09,0a,0b}
  1      hdr_subtag      ❌    minor header tag: 0x03 on MDM9x30 (em7455/mc7455),
                               0x04 everywhere else. Not a physical quantity.
  2      subtype         ✅    message discriminator {1,2,3,4} (size-class above)
  3:5    valid_len (u16) ✅    valid-payload length. subtype-1/2: == stride*N_pop
                               + base (r≈1.00, slope==array stride — this is one
                               of the two proofs the SDX62 stride is 141 not 139);
                               const 4 (subtype-3), 27=0x1b (subtype-4).
  5:13   ts0_gps_ms (u64)✅    GPS time, ms since 1980-01-06 (NO leap correction);
                               second-granular (%1000==0 in subtypes 1/2/3);
                               newest of the three. Decoding it reproduces each
                               capture's wall-clock date (+18 s GPS-UTC leap in
                               2026). High dword is constant within a capture and
                               identical across every profile of that capture —
                               proving a single shared clock.
  13:21  ts1_gps_ms (u64)✅    GPS measurement timestamp (oldest). subtype-1/2 ONLY.
  21:29  ts2_gps_ms (u64)✅    GPS measurement timestamp (middle). subtype-1/2 ONLY.
                               Ordering ts1 <= ts2 <= ts0 holds 100%; ts2-ts1 ~ 1 s.

subtype-3 reuses [13:17] as a local +1000/record ms counter (NOT ts1) and [17:29]
as body. subtype-4 (40B) has no 48-byte header at all (see below).

fmt region [29:33] is subtype-specific:
  subtype-1: phase_flag@29 (✅ 0x01 when ts0>ts2, 0x03 when ts0==ts2, alternates),
             fmt_b30=0x02, fw_fmt_flag@31 (0x0a on a minority of em9190/rm520ngl
             firmware records, else 0x01), fmt_b32=0x02.
  subtype-2: 00 00 00 00.
  subtype-3: 00 00 08 XX (byte31=0x08 const, byte32 per-capture constant).

=== subtype-1 (large type-1) — per-cell measurement grid ===
Layout: header + count × stride rows (+ trailer on SDX62).
  version  header  stride  count  tiling
  0x04     59      109     18     59 + 18*109 = 2021 (exact)
  0x05     48      133     20     48 + 20*133 = 2708 (exact)
  0x0b     48      141     19     48 + 19*141 = 2727, + 101-byte all-zero trailer
Each row = { u8 row_flag ; f32 lane[(stride-1)//4] } (27/33/35 lanes). row_flag is
a grounded per-row type/index marker (do NOT read "flag==0 => empty" — flag 0 also
occurs on populated rows). Recognized IEEE-754 config constants embedded in the
rows/header: 1.0f (100% of records) and 0.1f (100% of v05/v0b). The lane floats are
engine-internal measurement values, NOT dBm RSRP — shipped as structural `lanes`,
with no invented semantic labels. (Idle corpus, RSRP≈-116 dBm,
few rows populated; the qcsuper/SCAT oracle does not decode 0x1807 so there is no
external field labelling to lean on.)

=== subtype-2 (fine type-2) — fully field-decoded 26-byte cell records ===
Header [0:29] then a 26-byte cell lattice (stride 26 proven three ways). Cells
begin at the first lattice slot >= byte 29; the count of full cells is
(size-29)//26. Each 26-byte cell decodes completely:
  +0 flag0(u8) +1 present(u8=0x01 ✅ marker) +2 pad2(u8=0x00 ✅) +3 type_a(u8)
  +4 type_b(u8) +5 subrec_id(u8, per-record-unique index) +6 word6(u16)
  +8 cell_id_cand(u16, 100% in 0..503, stable per subrec_id per capture — the
     name is historical: an LTE PCI reading is not supported for a GNSS record;
     meaning unknown) +10 meas_a(f32, dB-scale) +14 word14(u16)
  +16 word16(u16, 0xffff sentinel) +18 meas_b(f32, normalized) +22 word22(u16)
  +24 word24(u16). present/pad2 grounded; the two measurement floats are structural.

=== subtype-3 (medium) — 248/284/368 ===
Header (version..fmt) + a config/measurement body containing an 8-byte-stride
default table whose empty entries are filled with the sentinel float 599584.9375
(0x4912620f) — 16,974 occurrences corpus-wide, all in subtype-3. Body shipped as
f32 lanes (structural); grounded fields are version/subtype/valid_len/ts0/
local_ms_ctr/fmt.

=== subtype-4 (heartbeat) — 40 bytes ===
  0 version ✅ / 1 subtag / 2 subtype=4 ✅ / 3:5 valid_len=27 ✅ /
  5:9 tick_ms(u32,+1000/rec ✅) / 9:13 zero / 13:21 sys_time_a(u64 ✅) /
  21:24 marker 00 01 01 / 24:32 sys_time_b(u64, == a in ~99.7% ✅) /
  32:35 marker2 00 01 01 / 35 b35 / 36:40 trailer_f32 (structural).

Every byte of every profile is decoded into a typed field or a typed measurement
array — no opaque `raw:` blob remains. fields_parsed counts only the semantically
GROUNDED fields; fields_identified counts every distinct typed field (100% byte
coverage). Every structural claim was adversarially verified.

Log name: LOG_EVENT_LTE_RRC_IRAT_REDIR_FROM_EUTRAN_START
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# Version enum (byte 0). 0x09 (SIM8202 / X55) is a corpus-attested value.
_1807_VERSIONS: tuple[int, ...] = (0x01, 0x03, 0x04, 0x05, 0x06, 0x09, 0x0a, 0x0b)
_1807_SUBTYPES: frozenset[int] = frozenset({0x01, 0x02, 0x03, 0x04})

# subtype-1 (large type-1) geometry, keyed by version byte.
_ST1_HEADER = {0x04: 59, 0x05: 48, 0x0b: 48}
_ST1_STRIDE = {0x04: 109, 0x05: 133, 0x0b: 141}
_ST1_DEFAULT_HEADER = 48          # fallback for an unseen subtype-1 version
_ST1_DEFAULT_STRIDE = 133

_SENTINEL_MEDIUM = 0x4912620F     # 599584.9375f — subtype-3 empty-table-slot fill

# Full record sizes per subtype. 0x1807 records are
# fixed-size, zero-padded buffers; the header's valid_len counts only the valid
# data, so the buffer size is NOT declared on the wire — the subtype-2 cell
# lattice is END-aligned (cells_start = len - count*26) and a record short by
# even one padding byte shifts every cell. These are the corpus-attested sizes
# (693 capture sidecars: every size|byte0 pair with >1,000 records; the ~15
# one-off sizes there are single records). A length below the
# largest known size that is not a known size is a truncated (or unknown)
# record -> None (registry WARN). Lengths ABOVE the largest known size are
# still decoded as before (longer payloads are a separate question).
_ST_KNOWN_SIZES: dict[int, frozenset[int]] = {
    0x04: frozenset({40}),                                       # heartbeat
    0x03: frozenset({248, 284, 368}),                            # medium
    0x01: frozenset({2021, 2708, 2828}),                         # large type-1
    0x02: frozenset({1767, 1900, 2593, 2614, 2905, 2939}),       # fine type-2
}


def _u16(d: bytes, o: int) -> int:
    return unpack_from("<H", d, o)[0]


def _u32(d: bytes, o: int) -> int:
    return unpack_from("<I", d, o)[0]


def _u64(d: bytes, o: int) -> int:
    return unpack_from("<Q", d, o)[0]


def _f32(d: bytes, o: int) -> float:
    return unpack_from("<f", d, o)[0]


def _f32_lanes(d: bytes, start: int, end: int) -> tuple[tuple[float, ...], tuple[int, ...]]:
    """Decode [start:end] as float32 lanes + the trailing (<4) bytes as ints."""
    n = (end - start) // 4
    lanes = tuple(unpack_from("<f", d, start + 4 * i)[0] for i in range(n))
    tail = tuple(d[start + 4 * n:end])
    return lanes, tail


@dataclass
class Diag0x1807FineCell:
    """subtype-2 fine measurement cell (26 bytes) — fully field-decoded.

    present==0x01 & pad2==0x00 mark a populated cell. cell_id_cand is a PCI
    candidate (0..503, stable per subrec_id) — unconfirmed, hence the `_cand`.
    meas_a/meas_b are structural L1-internal measurement floats (no dBm label).
    """
    flag0: int
    present: int
    pad2: int
    type_a: int
    type_b: int
    subrec_id: int
    word6: int
    cell_id_cand: int
    meas_a: float
    word14: int
    word16: int
    meas_b: float
    word22: int
    word24: int

    @property
    def populated(self) -> bool:
        return self.present == 0x01 and self.pad2 == 0x00

    def to_dict(self) -> dict[str, Any]:
        return {
            "flag0": self.flag0, "present": self.present, "pad2": self.pad2,
            "type_a": self.type_a, "type_b": self.type_b, "subrec_id": self.subrec_id,
            "word6": self.word6, "cell_id_cand": self.cell_id_cand,
            "meas_a": self.meas_a, "word14": self.word14, "word16": self.word16,
            "meas_b": self.meas_b, "word22": self.word22, "word24": self.word24,
            "populated": self.populated,
        }


@dataclass
class Diag0x1807MeasRow:
    """subtype-1 large-type-1 measurement row: u8 row_flag + f32 lane vector.

    row_flag is a grounded per-row type/index marker. `lanes` are structural
    L1-internal measurement floats (filter/searcher energies), NOT dBm.
    """
    row_flag: int
    lanes: tuple[float, ...]

    @property
    def populated(self) -> bool:
        return self.row_flag != 0 or any(x != 0.0 for x in self.lanes)

    def to_dict(self) -> dict[str, Any]:
        return {"row_flag": self.row_flag, "lanes": list(self.lanes),
                "populated": self.populated}


@dataclass
class Diag0x1807:
    """LTE ML1 0x1807 — multiplexed measurement log, decoded per (version, subtype).

    Common fields are always set. Subtype-specific fields are None / empty for the
    other subtypes (mirrors the multiplexed wire format). Every payload byte is
    represented: no opaque raw blob.
    """
    log_time: int
    version: int
    subtag: int
    subtype: int
    valid_len: int
    payload_size: int
    # --- universal timestamps (subtypes 1/2/3 carry ts0; 1/2 also carry ts1/ts2) ---
    ts0_gps_ms: int | None = None
    ts1_gps_ms: int | None = None
    ts2_gps_ms: int | None = None
    # --- subtype-1 (large type-1) ---
    phase_flag: int | None = None
    fw_fmt_flag: int | None = None
    meas_rows: tuple[Diag0x1807MeasRow, ...] = ()
    array_trailer: tuple[int, ...] = ()
    # --- subtype-2 (fine type-2) ---
    preamble: tuple[int, ...] = ()
    fine_cells: tuple[Diag0x1807FineCell, ...] = ()
    # --- subtype-3 (medium) ---
    local_ms_ctr: int | None = None
    medium_body: tuple[float, ...] = ()
    medium_tail: tuple[int, ...] = ()
    # --- subtype-4 (40B heartbeat) ---
    tick_ms: int | None = None
    sys_time_a: int | None = None
    # [21:24] / [32:36] — 3+4 raw bytes trailing each sys_time. A 25,444-record
    # corpus walk found these vary in ~14.5% of records (uniq=2..4), so they are
    # not constant markers despite looking constant in small samples. They stay
    # undecoded and NOT pinned as invariants, but they are live per-record bytes, so
    # they are surfaced verbatim (as with 0x158C reserved2 / 0x1C8F residue) rather
    # than discarded — brought into the 3-way diff as raw byte fields.
    marker_a: bytes | None = None
    sys_time_b: int | None = None
    marker_b: bytes | None = None
    hb_trailer_f: float | None = None
    # --- derived ---
    num_populated: int = 0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "Diag0x1807",
            "log_time": self.log_time,
            "version": self.version,
            "subtag": self.subtag,
            "subtype": self.subtype,
            "valid_len": self.valid_len,
            "payload_size": self.payload_size,
            "num_populated": self.num_populated,
        }
        if self.ts0_gps_ms is not None:
            d["ts0_gps_ms"] = self.ts0_gps_ms
        if self.ts1_gps_ms is not None:
            d["ts1_gps_ms"] = self.ts1_gps_ms
            d["ts2_gps_ms"] = self.ts2_gps_ms
        if self.subtype == 0x01:
            d["phase_flag"] = self.phase_flag
            d["fw_fmt_flag"] = self.fw_fmt_flag
            d["meas_rows"] = [r.to_dict() for r in self.meas_rows]
            if self.array_trailer:
                d["array_trailer"] = list(self.array_trailer)
        elif self.subtype == 0x02:
            if self.preamble:
                d["preamble"] = list(self.preamble)
            d["fine_cells"] = [c.to_dict() for c in self.fine_cells]
        elif self.subtype == 0x03:
            d["local_ms_ctr"] = self.local_ms_ctr
            d["medium_body"] = list(self.medium_body)
            if self.medium_tail:
                d["medium_tail"] = list(self.medium_tail)
        elif self.subtype == 0x04:
            d["tick_ms"] = self.tick_ms
            d["sys_time_a"] = self.sys_time_a
            if self.marker_a is not None:
                d["marker_a"] = self.marker_a.hex()
            d["sys_time_b"] = self.sys_time_b
            if self.marker_b is not None:
                d["marker_b"] = self.marker_b.hex()
            d["hb_trailer_f"] = self.hb_trailer_f
        return d


def _parse_heartbeat(log_time: int, d: bytes, ver: int) -> Diag0x1807:
    """subtype 4 — 40-byte heartbeat (no 48-byte universal header)."""
    tick_ms = _u32(d, 5) if len(d) >= 9 else None
    sys_a = _u64(d, 13) if len(d) >= 21 else None
    mk_a = bytes(d[21:24]) if len(d) >= 24 else None
    sys_b = _u64(d, 24) if len(d) >= 32 else None
    mk_b = bytes(d[32:36]) if len(d) >= 36 else None
    trailer_f = _f32(d, 36) if len(d) >= 40 else None
    return Diag0x1807(
        log_time=log_time, version=ver, subtag=d[1], subtype=d[2],
        valid_len=_u16(d, 3), payload_size=len(d),
        tick_ms=tick_ms, sys_time_a=sys_a, marker_a=mk_a,
        sys_time_b=sys_b, marker_b=mk_b, hb_trailer_f=trailer_f,
    )


def _parse_medium(log_time: int, d: bytes, ver: int) -> Diag0x1807:
    """subtype 3 — medium (248/284/368): header + structural f32 body."""
    ts0 = _u64(d, 5) if len(d) >= 13 else None
    local_ms = _u32(d, 13) if len(d) >= 17 else None
    body_lanes, body_tail = _f32_lanes(d, 33, len(d)) if len(d) > 33 else ((), ())
    return Diag0x1807(
        log_time=log_time, version=ver, subtag=d[1], subtype=d[2],
        valid_len=_u16(d, 3), payload_size=len(d), ts0_gps_ms=ts0,
        local_ms_ctr=local_ms, medium_body=body_lanes, medium_tail=body_tail,
    )


def _parse_large_type1(log_time: int, d: bytes, ver: int) -> Diag0x1807:
    """subtype 1 — large per-cell grid: header + count × stride rows (+trailer)."""
    header = _ST1_HEADER.get(ver, _ST1_DEFAULT_HEADER)
    stride = _ST1_STRIDE.get(ver, _ST1_DEFAULT_STRIDE)
    ts0 = _u64(d, 5) if len(d) >= 13 else None
    ts1 = _u64(d, 13) if len(d) >= 21 else None
    ts2 = _u64(d, 21) if len(d) >= 29 else None
    phase = d[29] if len(d) > 29 else None
    fw_flag = d[31] if len(d) > 31 else None
    rows: list[Diag0x1807MeasRow] = []
    if len(d) >= header + stride:
        count = (len(d) - header) // stride
        nlanes = (stride - 1) // 4
        for k in range(count):
            base = header + k * stride
            lanes = tuple(unpack_from("<f", d, base + 1 + 4 * i)[0] for i in range(nlanes))
            rows.append(Diag0x1807MeasRow(row_flag=d[base], lanes=lanes))
        trailer = tuple(d[header + count * stride:])
    else:
        trailer = tuple(d[header:]) if len(d) > header else ()
    num_pop = sum(1 for r in rows if r.populated)
    return Diag0x1807(
        log_time=log_time, version=ver, subtag=d[1], subtype=d[2],
        valid_len=_u16(d, 3), payload_size=len(d),
        ts0_gps_ms=ts0, ts1_gps_ms=ts1, ts2_gps_ms=ts2,
        phase_flag=phase, fw_fmt_flag=fw_flag,
        meas_rows=tuple(rows), array_trailer=trailer, num_populated=num_pop,
    )


def _parse_fine_type2(log_time: int, d: bytes, ver: int) -> Diag0x1807:
    """subtype 2 — fine cell array: header [0:29] + 26-byte cells from >= byte 29."""
    ts0 = _u64(d, 5) if len(d) >= 13 else None
    ts1 = _u64(d, 13) if len(d) >= 21 else None
    ts2 = _u64(d, 21) if len(d) >= 29 else None
    cells: list[Diag0x1807FineCell] = []
    preamble: tuple[int, ...] = ()
    if len(d) >= 29 + 26:
        count = (len(d) - 29) // 26
        cells_start = len(d) - count * 26      # phase-aligned to the verified lattice
        preamble = tuple(d[29:cells_start])
        for k in range(count):
            b = cells_start + k * 26
            cells.append(Diag0x1807FineCell(
                flag0=d[b], present=d[b + 1], pad2=d[b + 2],
                type_a=d[b + 3], type_b=d[b + 4], subrec_id=d[b + 5],
                word6=_u16(d, b + 6), cell_id_cand=_u16(d, b + 8),
                meas_a=_f32(d, b + 10), word14=_u16(d, b + 14),
                word16=_u16(d, b + 16), meas_b=_f32(d, b + 18),
                word22=_u16(d, b + 22), word24=_u16(d, b + 24),
            ))
    num_pop = sum(1 for c in cells if c.populated)
    return Diag0x1807(
        log_time=log_time, version=ver, subtag=d[1], subtype=d[2],
        valid_len=_u16(d, 3), payload_size=len(d),
        ts0_gps_ms=ts0, ts1_gps_ms=ts1, ts2_gps_ms=ts2,
        preamble=preamble, fine_cells=tuple(cells), num_populated=num_pop,
    )


# --- Ground-truth recipe — keyed to RM520N-GL (SDX62), version 0x0b. ---
# See the module docstring for the full field grounding. Not yet run on hardware
# (hw_run_performed stays False until it is).

@register(
    0x1807, domain="gnss",
    name="0x1807",
    description="GNSS position-engine 0x1807 — multiplexed measurement log (GPS-time F3-grounded), full per-(version,subtype) decode",
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Subsystem: GNSS position engine (not LTE ML1). tick_ms (subtype 4) and ts0_gps_ms mod 1 week (subtypes 1/2/3) "
        "equal the GPS ms-of-week argument of co-emitted (<=1 ms) nf_navsolution/"
        "gile_proc/ple_proc/ale_proc F3 on every version (control 0); "
        "cell_id_cand is not an LTE PCI. A record shorter than the largest "
        "corpus-attested size of its subtype that is not itself an attested size "
        "(heartbeat 40; medium 248/284/368; large 2021/2708/2828; fine "
        "1767/1900/2593/2614/2905/2939 B — 693 sidecars) is truncated and "
        "returns None rather than a partial heartbeat, a dropped last row, or a "
        "phase-shifted subtype-2 cell lattice. "
        "Full per-(version,subtype) decode from a 6,379-record cross-generation "
        "corpus walk (MDM9x07/9x30/9x40, SDX20, SDX55, X55, "
        "SDX62/65), adversarially verified. byte2=subtype selects 4 layouts "
        "(4=40B heartbeat, 3=medium, 1=large per-cell grid, 2=fine cell array). "
        "Universal header: version, subtag, subtype, valid_len (u16 length law), "
        "ts0/ts1/ts2 = GPS-time ms since 1980. subtype-1 rows = u8 flag + f32 lanes "
        "(stride 109/133/141 by version, count 18/20/19, +101B trailer on SDX62). "
        "subtype-2 = 26B cells fully field-decoded (present marker, subrec_id, "
        "cell_id_cand 0..503 of unknown meaning, two measurement floats). Version "
        "enum includes 0x09 (SIM8202/X55). 100% byte coverage."
    ),
    source_url="",
    # fields_parsed = semantically GROUNDED fields (version, subtype, valid_len,
    # ts0/ts1/ts2, subtype-3 local_ms_ctr, subtype-1 phase_flag + row_flag + the
    # 1.0f/0.1f config constants, subtype-4 tick/sys_time_a/sys_time_b, subtype-2
    # present-marker). fields_identified = every distinct typed field across all
    # subtypes (grounded + structural measurement lanes) — 100% byte coverage but
    # the L1-internal measurement floats are structurally decoded, not semantically
    # labelled (no oracle; idle corpus). Not a full semantic decode.
    fields_identified=48,
    fields_parsed=13,
    issues=(),
    field_invariants={
        "version": {"enum": list(_1807_VERSIONS)},
    },
)
def parse_0x1807(log_time: int, data: bytes) -> Diag0x1807 | None:
    # Layer-1 version gate: reject any byte-0 outside the enum before
    # any structural decode.
    if len(data) < 5:
        return None
    version = data[0]
    if version not in _1807_VERSIONS:
        return None
    subtype = data[2]
    if subtype not in _1807_SUBTYPES:
        return None
    # Truncated / unknown-length records fail loudly.
    known = _ST_KNOWN_SIZES[subtype]
    if len(data) not in known and len(data) < max(known):
        return None
    if subtype == 0x04:
        return _parse_heartbeat(log_time, data, version)
    if subtype == 0x03:
        return _parse_medium(log_time, data, version)
    if subtype == 0x01:
        return _parse_large_type1(log_time, data, version)
    return _parse_fine_type2(log_time, data, version)
