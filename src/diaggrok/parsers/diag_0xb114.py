"""0xB114 — LTE LL1 serving-cell frame timing: a per-subframe record array, six versions.

Every version is ``<header> + num_records x <record>``, one record per LTE
subframe, at most 20 records per log. All six are decoded field-by-field; the
version byte selects the header size and the record stride.

    version  chipset family (corpus)             header  stride  records
    0x01     MDM9x07 / MDM9x15 (EG25-G, EG95,      12 B     3 B   0..20
             SIM7600, NL668, MC7700, R11e)
    0x2B     MDM9x30 / 9x35 (MC7455, EM7455,       12 B    28 B   1..20
             AC791L)
    0x65     MDM9250 (EP06-A)                      12 B    44 B   1..20
    0x7A     SDX20 / 9x50 (EM7565, LM960, MC7411,  16 B     8 B   1..20
             EM7511, EG12, EG18)
    0x8D     SDX24 (EM120R, EM160R, SC200E)        16 B    48 B   1..20
    0xA1     SDX55 and later (RM5xx, EM919x,       16 B    48 B   2..20
             FN980, M2000, CFW-3212, ...)

The size is exact: ``len == header + stride * num_records``. A payload that is
one byte short or long returns None (loud), and a version this module does not
list returns None (loud).

Header word 0 (u32 @0, little-endian), all versions:

    bits 0..7    version
    bits 8..12   num_records
    v0x01/2B/65/7A/8D:
      bits 13..16  sub_fn   (0..9)   the log window's start subframe
      bits 17..26  sys_fn   (0..1023)
      bits 27..31  hdr_hi5  (0 on every v0x01/2B/65/7A record; 1 or 2 on 24 of
                   5,075 v0x8D EM120R records that run their own SFN sequence,
                   interleaved with the main one: CANDIDATE carrier index)
    v0xA1:
      bits 13..15  hdr_b1_hi3 (0 on 49,534 of 49,877 records; semantics unpinned)
      bits 16..31  hdr_s16    signed (0, +-2, +-4 ...; semantics unpinned)
      v0xA1 moves (sys_fn, sub_fn) into every record; the log-level sys_fn /
      sub_fn here are the FIRST record's, so every version reports the window
      start the same way.

Frame-timing words. ``frame_timing0`` / ``frame_timing1`` are the serving
cell's frame-boundary position. On v0x01/2B/65/7A/8D each is the low 19 bits of
a u32 and is ALWAYS < 307,200 = Ts per 10 ms radio frame (30.72 MHz x 10 ms) on
every walked record (149,125 records, 61 captures). The bits above 19 are
returned separately as ``frame_timing0_hi13`` / ``frame_timing1_hi13`` (0 for
timing0 on every record; timing1's carries values such as 0, 9, 12, 2047 whose
meaning is unpinned). On v0xA1 they are two u16s at @4 / @6 (max 27,201
observed). ``config_word`` (u32 @4 verbatim) is kept as the legacy alias the
per-modem ground-truth recipes key on. On v0xA1 it is the two u16 timing
words side by side, so its high and low halves are often equal.

Per-subframe adjustments. Every version carries three signed per-subframe
adjustment channels:

    v0x01/2B/65/7A/8D: one packed word at record @0 (u24 LE)
        adj0 = s11 bits 0..10,  adj1 = s5 bits 11..15,  adj2 = s8 bits 16..23
    v0xA1: adj0 = s16 @2,  adj1 = s16 @4,  adj2 = s16 @6

The grounding is an ACCOUNTING IDENTITY across consecutive logs of one
capture: sum(adj0 over a log's records) == next log's frame_timing0 - this
log's, and likewise adj1 for frame_timing1. The parser's fields must add up
across records, which a mis-sliced field cannot do. Counts are over contiguous
log pairs whose adj sum is non-zero, computed from this parser's own output
(149,125 records, 61 captures):

    version  sum(adj0) vs d(frame_timing0)     sum(adj1) vs d(frame_timing1)
    v0x01    2,229/3,449 exact, 96 % +-1       1,548/2,427 exact, 93 % +-1
    v0x2B    1,313/1,493 exact, 92 % +-1         876/1,077 exact, 83 % +-1
    v0x65      121/138   exact, 95 % +-1         125/132   exact, 100 % +-1
    v0x7A    5,164/14,031 exact, 99.9 % +-7    6,939/6,973 exact
    v0x8D      281/323   exact, 89 % +-1         371/389   exact, 98 % +-1
    v0xA1    5,686/6,530 exact, 90 % +-1       6,883/7,518 exact, 97 % +-1

The residuals are not noise in the decode. v0x01/2B/65/7A/8D log a window
every 21 subframes but record only 20, so the 21st subframe's adjustment
reaches the next header unlogged. v0x01 over 24,077 21-subframe pairs:
t0 - sum(adj0) is 0 in 22,486 and +-1 in 1,398. v0x7A's loop dithers in +-5..7
steps, so its residual is +-5..7. v0xA1 records are contiguous (the next log's
first record is this log's last + 1 subframe in 16,565 of ~17,500 pairs),
which is why it closes best. v0xA1 records can also skip subframes INSIDE one
log (e.g. 179.7 -> 197.5 across a sleep gap), which is why that version
carries (sys_fn, sub_fn) per record. ``adj2`` has no header partner: it is a third
signed channel (semantics unpinned).

Clocks inside the records, grounded by their per-subframe step (1 subframe =
1 ms):

    ts_ticks  +30,720 / record = 30.72 MHz Ts clock (v0x2B @20, v0x65 @36)
    xo_ticks  +19,200 / record = 19.2 MHz XO clock  (v0x8D @4,  v0xA1 @12)
    ts_counter (header, v0x7A/8D @12, v0xA1 @8): steps 30,720 x subframes
              between logs (85 % / 87 % exact on v0x7A / v0x8D; the rest
              differ by the timing adjustment, e.g. LM960 +614,398 =
              20 x 30,720 + sum(adj0) = -2)

The DIAG timestamp agrees with the decoded (sys_fn, sub_fn): v0x01 logs every
21 subframes and its DIAG clock steps 20.00/21.25/22.50 ms; v0x2B/7A/8D step 20
subframes; v0x65 (EP06-A, DRX idle) steps 1,274 subframes against 1,273.75 ms.

Fields named by OBSERVED BEHAVIOUR only (CANDIDATE, semantics unpinned): the
twin timers ``timer0``/``timer1`` (v0x2B +61,440/subframe = 61.44 MHz, v0x65
+122,880 = 122.88 MHz; they do NOT absorb the adj steps), the duplicated
halfword pairs ``pair_a0/a1`` and ``pair_b0/b1`` (``pair_b*`` steps +1,920 per
subframe mod 30,720), the signed tail ``s32_tail``, the 48 B layouts' ``w8`` ..
``w36`` words, and ``rec_flags`` (byte 3 of the adj word: 0 on v0x2B/65/7A, 0x03 on v0x8D;
v0xA1 u32 @8 = 3/0/15). The
48 B v0xA1 record is v0x8D's shifted by 8 B; the matching words share names.
Words that were zero on every walked record (``zero*``) are returned, not
asserted: a zero across a corpus is not a format invariant.

F3 (0x79 / 0x99 / 0x92): the co-emitted LTE LL1 sites (lte_LL1_doppler_est_algo,
lte_LL1_cmd_proc_sys, lte_LL1_schdr_dl) are timing / subframe-scheduling prints.
F3 joins confirm (sys_fn, sub_fn) on v0x01/2B/7A/8D/A1 (LM960 LL1 rxfe
frame/subframe agrees on 20,093 of 20,104 records); v0x65 has no F3 in any
capture.

Log name: LOG_LTE_LL1_SERVING_CELL_FRAME_TIMING
Also known as: LTE LL1 Serving Cell Frame Timing
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

#: version -> (header bytes, record stride bytes)
_GEOMETRY: dict[int, tuple[int, int]] = {
    0x01: (12, 3),
    0x2B: (12, 28),
    0x65: (12, 44),
    0x7A: (16, 8),
    0x8D: (16, 48),
    0xA1: (16, 48),
}
_B114_VERSIONS = tuple(sorted(_GEOMETRY))
#: Every size the exact gate accepts: header + stride x num_records, for the
#: whole 5-bit count range (0..31; the corpus maximum is 20). Derived from the
#: layout, not fitted to the corpus, so the size audit can see the gate.
_PAYLOAD_SIZES = tuple(sorted({hdr + stride * n for hdr, stride in _GEOMETRY.values()
                               for n in range(32)}))

_TS_PER_FRAME = 307_200          # 30.72 MHz x 10 ms
_FT_MASK = (1 << 19) - 1         # 19-bit frame-timing field

# Per-version record layouts after the adjustment channels: (name, offset, fmt).
# fmt is a struct code: 'I' u32, 'i' s32, 'H' u16, 'h' s16.
_REC_FIELDS: dict[int, tuple[tuple[str, int, str], ...]] = {
    0x01: (),
    0x2B: (
        ("timer0", 4, "I"), ("timer1", 8, "I"),
        ("pair_a0", 12, "H"), ("pair_a1", 14, "H"),
        ("pair_b0", 16, "H"), ("pair_b1", 18, "H"),
        ("ts_ticks", 20, "I"), ("s32_tail", 24, "i"),
    ),
    0x65: (
        ("timer0", 4, "I"), ("timer1", 8, "I"),
        ("zero12", 12, "I"), ("zero16", 16, "I"),
        ("pair_a0", 20, "H"), ("pair_a1", 22, "H"),
        ("zero24", 24, "I"),
        ("pair_b0", 28, "H"), ("pair_b1", 30, "H"),
        ("zero32", 32, "I"),
        ("ts_ticks", 36, "I"), ("s32_tail", 40, "i"),
    ),
    0x7A: (
        ("pair_b0", 4, "H"), ("zero6", 6, "H"),
    ),
    0x8D: (
        ("xo_ticks", 4, "I"), ("w8", 8, "I"), ("zero12", 12, "I"),
        ("s32_16", 16, "i"), ("s32_20", 20, "i"),
        ("w24", 24, "I"), ("w28", 28, "I"), ("w32", 32, "I"),
        ("zero36", 36, "I"), ("zero40", 40, "I"), ("zero44", 44, "I"),
    ),
    0xA1: (
        ("rec_flags", 8, "I"), ("xo_ticks", 12, "I"), ("w8", 16, "I"),
        ("s32_16", 20, "i"), ("s32_20", 24, "i"),
        ("w24", 28, "I"), ("w28", 32, "I"), ("w32", 36, "I"),
        ("zero40", 40, "I"), ("zero44", 44, "I"),
    ),
}


def _sext(value: int, bits: int) -> int:
    return value - (1 << bits) if value >> (bits - 1) & 1 else value


@dataclass
class B114Record:
    """One subframe of 0xB114. Fields absent from a version are None / omitted."""
    index: int
    adj0: int
    adj1: int
    adj2: int
    sys_fn: int | None = None        # v0xA1 only (per-record SFN)
    sub_fn: int | None = None        # v0xA1 only
    rec_flags: int | None = None     # byte 3 (4 B adj word) / v0xA1 u32 @8
    extra: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"index": self.index}
        if self.sys_fn is not None:
            d["sys_fn"] = self.sys_fn
            d["sub_fn"] = self.sub_fn
        d["adj0"] = self.adj0
        d["adj1"] = self.adj1
        d["adj2"] = self.adj2
        if self.rec_flags is not None:
            d["rec_flags"] = self.rec_flags
        d.update(self.extra)
        return d


@dataclass
class Diag0xB114:
    """0xB114 LTE LL1 serving-cell frame timing (all six versions)."""
    log_time: int
    version: int
    num_records: int
    sys_fn: int | None
    sub_fn: int | None
    frame_timing0: int
    frame_timing1: int
    config_word: int
    payload_size: int
    records: list[B114Record]
    hdr_hi5: int | None = None
    hdr_b1_hi3: int | None = None
    hdr_s16: int | None = None
    frame_timing0_hi13: int | None = None
    frame_timing1_hi13: int | None = None
    ts_counter: int | None = None
    ts_counter_b: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "Diag0xB114",
            "log_time": self.log_time,
            "version": self.version,
            "num_records": self.num_records,
            "sys_fn": self.sys_fn,
            "sub_fn": self.sub_fn,
            "frame_timing0": self.frame_timing0,
            "frame_timing1": self.frame_timing1,
            "config_word": self.config_word,
            "payload_size": self.payload_size,
        }
        for name in ("hdr_hi5", "hdr_b1_hi3", "hdr_s16", "frame_timing0_hi13",
                     "frame_timing1_hi13", "ts_counter", "ts_counter_b"):
            value = getattr(self, name)
            if value is not None:
                d[name] = value
        d["records"] = [r.to_dict() for r in self.records]
        return d


def _parse_records(version: int, data: bytes, hdr: int, stride: int,
                   count: int) -> list[B114Record]:
    layout = _REC_FIELDS[version]
    out: list[B114Record] = []
    for i in range(count):
        base = hdr + stride * i
        if version == 0xA1:
            fn_word, adj0, adj1, adj2 = unpack_from("<Hhhh", data, base)
            rec = B114Record(index=i, adj0=adj0, adj1=adj1, adj2=adj2,
                             sys_fn=fn_word & 0x3FF, sub_fn=(fn_word >> 10) & 0xF)
        else:
            word = int.from_bytes(data[base:base + 3], "little")
            rec = B114Record(index=i, adj0=_sext(word & 0x7FF, 11),
                             adj1=_sext((word >> 11) & 0x1F, 5),
                             adj2=_sext(word >> 16, 8))
            if stride >= 4:
                rec.rec_flags = data[base + 3]
        for name, off, fmt in layout:
            value = unpack_from("<" + fmt, data, base + off)[0]
            if name == "rec_flags":
                rec.rec_flags = value
            else:
                rec.extra[name] = value
        out.append(rec)
    return out


@register(
    0xB114,
    name="0xB114",
    description=(
        "0xB114 — LTE LL1 serving-cell frame timing (six versions): header "
        "SFN/subframe, frame-boundary timing words and Ts counter, plus "
        "per-subframe records of three signed timing-adjust channels and Ts / XO clocks"
    ),
    version=14,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "All six versions are decoded field-by-field from a device-diverse walk of "
        "61 captures (149,125 records) spanning MDM9x07/9x15, MDM9x30/9x35, MDM9250, "
        "SDX20, SDX24 and SDX55-and-later modems. Layout = header + num_records x "
        "stride, num_records = u32@0 bits 8..12, with an exact size gate (v0x01 "
        "12+3n, v0x2B 12+28n, v0x65 12+44n, v0x7A 16+8n, v0x8D/v0xA1 16+48n; 100% "
        "of walked records). (sys_fn, sub_fn) at u32@0 bits 17..26 / 13..16 (v0xA1: "
        "per record) agree with the DIAG clock and, on v0x01/2B/7A/8D/A1, with "
        "co-emitted F3 frame/subframe prints (LM960 20,093/20,104). frame_timing0/1 "
        "are < 307,200 Ts (one radio frame) and are closed by the per-subframe "
        "adj0/adj1 sums across consecutive logs (v0x01 22,486/24,077 exact, the rest "
        "+-1 from the unlogged 21st subframe; v0xA1 45,776/46,825 contiguous pairs "
        "exact). ts_ticks step +30,720/subframe, xo_ticks +19,200/subframe. "
        "config_word is kept as the u32@4 legacy alias; it is an acquisition-relative "
        "timing reference that re-bases when the LL1 timing loop resets (F3 "
        "'Inital Reset Done' from lte_LL1_doppler_est_algo co-occurs with the step "
        "on LM960) and varies within a camp, so it is neither a fixed per-cell "
        "constant nor a 100/s SFN; on v0xA1 it is two u16 words that are often equal. "
        "Known gaps: the timer0/timer1, pair_*, s32_tail, w* and rec_flags words are "
        "named by observed behaviour only, and adj2, hdr_hi5, hdr_b1_hi3, hdr_s16 "
        "and frame_timing1_hi13 are unpinned. No capture yet exercises a cross-PCI "
        "handover to test config_word's behaviour there."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=35,
    fields_parsed=35,
    field_invariants={
        "version": {"enum": list(_B114_VERSIONS)},
        "payload_size": {"enum": list(_PAYLOAD_SIZES)},
        "num_records": {"range": [0, 31]},
        "sub_fn": {"range": [0, 9]},
        "sys_fn": {"range": [0, 1023]},
        "frame_timing0": {"range": [0, _TS_PER_FRAME - 1]},
        "frame_timing1": {"range": [0, _TS_PER_FRAME - 1]},
    },
)
def parse_0xb114(log_time: int, data: bytes) -> Diag0xB114 | None:
    if len(data) < 4:
        return None
    version = data[0]
    geometry = _GEOMETRY.get(version)
    if geometry is None:
        return None
    hdr, stride = geometry
    word0 = unpack_from("<I", data, 0)[0]
    count = (word0 >> 8) & 0x1F
    if len(data) != hdr + stride * count:
        return None
    records = _parse_records(version, data, hdr, stride, count)
    config_word = unpack_from("<I", data, 4)[0]
    result = Diag0xB114(
        log_time=log_time, version=version, num_records=count,
        sys_fn=None, sub_fn=None, frame_timing0=0, frame_timing1=0,
        config_word=config_word, payload_size=len(data), records=records,
    )
    if version == 0xA1:
        result.hdr_b1_hi3 = (word0 >> 13) & 0x7
        result.hdr_s16 = _sext(word0 >> 16, 16)
        if records:  # v0xA1 carries (sys_fn, sub_fn) only in its records
            result.sys_fn = records[0].sys_fn
            result.sub_fn = records[0].sub_fn
        result.frame_timing0, result.frame_timing1 = unpack_from("<HH", data, 4)
        result.ts_counter, result.ts_counter_b = unpack_from("<II", data, 8)
        return result

    result.sub_fn = (word0 >> 13) & 0xF
    result.sys_fn = (word0 >> 17) & 0x3FF
    result.hdr_hi5 = word0 >> 27
    t0, t1 = unpack_from("<II", data, 4)
    result.frame_timing0, result.frame_timing0_hi13 = t0 & _FT_MASK, t0 >> 19
    result.frame_timing1, result.frame_timing1_hi13 = t1 & _FT_MASK, t1 >> 19
    if hdr == 16:
        result.ts_counter = unpack_from("<I", data, 12)[0]
    return result
