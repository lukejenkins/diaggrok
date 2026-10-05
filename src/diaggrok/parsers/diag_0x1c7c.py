"""Proprietary-NMEA ($PQME) encapsulation (log code 0x1C7C).

Two versions share the code. **v=0x01** (SDX55, and the Inseego M3100)
carries ME-engine telemetry sentences in a 202 B fixed-size record, e.g.:

  $PQMEPWRRPT  — power/on-time report (20 numeric fields)
  $PQMECC      — clock/channel control dump (8 fields, mixed int/hex)

**v=0x02** (SDX62) is binary: a TLV chain of fixed templates (see the
TLV section further down and ``split_v2_entries``).

On one 65 s EM9190 (SDX55) capture (132 records) PWRRPT + CC happen to
alternate 1:1 (66 + 66). That ratio is **capture-specific, not a framing
rule** — across the broader corpus (1,792 v=0x01 records) the mix is
**~3.9:1 PWRRPT-dominant** (1,428 PWRRPT : 364 CC). Same 202 B size on
every modem in the corpus, so framing is generation-stable. Both talkers
decode at 100% (zero ``parsed=None`` fall-through) — the v=0x01 $PQME
ASCII side has no coverage gap (cf. 0x1384's GLL/DTM gap). v=0x02 records
carry no ASCII — confirmed binary on a 10,208-record v=0x02 sample.

## Layout (v=0x01, 202 B fixed)

    byte 0       : version       (== 0x01 across all observed firmware)
    byte 1       : flag_high     (0x00 on SDX55 firmware; a per-talker ID
                                  on the Inseego M3100 — see below)
    [2 : N]      : ASCII NMEA    ($PQME…,fields…*XX\r\n\x00)
    [N : 101]    : padding + a LIVE RESIDUE up to the block (see below)
    [101 : 201]  : binary block  (25 little-endian u32 values; see below)
    [201 : 202]  : trailing byte (high entropy; semantics TBD)

The binary block is **end-anchored**: regardless of NMEA sentence length
(which varies with the digit width of each numeric field), the 25 u32
values occupy a fixed window at absolute payload offsets ``[101..200]``.
The trailing byte at offset 201 sits outside the u32 array and carries
its own (currently undecoded) value.

The ``[N : 101]`` region is **not** purely zero padding. After the
``\r\n``/NUL terminator run there is a live byte residue immediately
preceding the end-anchored block: on 94 RM500Q-AE v=0x01 records the 7
bytes at ``[94:101]`` are non-zero on 35–69 of them with full entropy
(e.g. ``1600507d77aef0``). It is exposed as ``pre_tail_residue`` — raw and
un-named, because F3 is silent on it. Modelling the record as a byte map
that must close exactly at 202 (the Kaitai layout mirror) makes this gap
explicit.

Byte 0 is named ``version`` and read **first**, ahead of any other data
access; byte 1 is exposed separately as ``flag_high``. The legacy ``flag``
field (the two bytes read as one ``u16``) is preserved on the dataclass for
backward compatibility and is computed as ``version | flag_high << 8`` so
existing callers continue to see ``0x0001`` on SDX55 records.

## Byte 1 is NOT a constant

Byte 1 is 0x00 on all 4,627 SDX55 records, but on the Inseego M3100 it is
a **per-talker ID**: in an M3100 capture every one of ~45 ``$PQ…`` talkers
carries exactly one byte-1 value (``$PQMEPWRRPT`` 0x00, ``$PQME1``..
``$PQME5`` 0x01..0x05, ``$PQMECFG1`` 0x08, ``$PQMEBL`` 0x0f, ``$PQMECLK``
0x10, ``$PQMECC`` 0x29, ``$PQJAM1`` 0x27, …), and only 0x25 is shared, by
the five ``DPO`` talkers (``$PQMEDPO``, ``$PQMEL1DPOT``, ``$PQMEL5DPOT``,
``$PQMEL1DPOT1``, ``$PQMEL5DPOT1``). Gating on byte 1 == 0x00 would reject
every M3100 sentence except PWRRPT (17,893 sampled 202 B records). Byte 1
is therefore exposed raw as ``flag_high`` and not gated. The structural
anchors that hold on BOTH generations stay: byte 0 == 0x01, 202 B, and
``$`` at byte 2. The byte-1 -> talker mapping is self-evident from the
record; no F3 names the byte, so it keeps its legacy name rather than a
semantic one.

## Binary block structure

End-aligned byte-invariance over 12,366 PWRRPT records + 10,379 PQMECC
records (22,745 total / 28 captures across FN980m, RM500Q-AE, EM9190)
shows a 4-byte periodicity in which every 4th byte (at end-offsets 1,
5, 9, …, 97 — i.e. payload offsets 200, 196, 192, …, 104) is restricted
to a tight set of values ``{0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
…}`` while the other three bytes per group have full entropy.  That is
the canonical "MSB-of-small-integer" distribution: little-endian u32
values whose high byte is small because the integer magnitudes are
moderate.  Reading the block as ``unpack_from('<25I', data, 101)``
recovers a clean 25-element u32 array. The byte sequence ``dead0008``
appears at scattered trailer offsets in only ~5% of records; it is
incidental u32-value data, not a sub-record framing magic.

PQMECC records carry the same 25-u32 tail window but with most values
zero (the CC sentence's ME-engine state has no associated periodic
counters to dump).  PWRRPT records carry the meaningful tail values —
per-field semantic decode (whether these are ME-engine clock counters,
duty-cycle accumulators, RSSI snapshots, IEEE 754 floats, fixed-point,
or a mix) remains TBD pending AT-command correlation work.  The
structural framing is firm.

A semantic-classification pass over the 12,366 PWRRPT records rules out
the "per-slot heterogeneous field" reading: all 25 slots are statistically
indistinguishable (uniform 44% zero, identical max 0xF0FFFFFF, no monotone
counters, no inter-slot duplication, no NMEA-field echoes, no plausible
IEEE 754 telemetry distribution).  Records sit in a bimodal "all-zero
(23.7%) / all-25-populated (22.9%) / smooth spread between" pattern that
fingerprints whole-block populating, not per-slot sampling.  Working
hypothesis is a **per-channel GNSS state vector** (25 slots = simultaneous
tracking channels; u32 = packed channel-state bitfield) but field-name
decode of the bitfield awaits AT-correlated acquisition-transition capture.

A bit-level pass over the same 12,366-record corpus decomposes each
non-zero u32 slot into a structurally firm 3-region packing::

    bits 31..28  type tag      (4-bit; 16 frequency-skewed classes)
    bits 27..24  reserved=0    (100% zero across 171,846 non-zero values)
    bits 23..0   value-24      (24-bit numeric quantity)

Bits 27..24 are **identically zero on every one of the 171,846 non-zero
u32 values** in the corpus — this is the structural fingerprint of a
reserved/padding field separating two semantic regions, and is the
direct origin of the observed ``0xF0FFFFFF`` per-slot maximum.  The
top-nibble class distribution is frequency-skewed (0x0 = 31.55% →
0xE = 1.64% with smooth decay) and per-class 24-bit value distributions
differ in zero-frequency (class 0x0: 0% zero-value vs class 0xD: 39.9%
zero-value), confirming the classes are semantically distinct rather
than a uniform random partition.  Per-record top-nibble multiset
signatures are highly diverse (7,060 distinct signatures across the
12,366 records) — the type tag is a per-value class, not a per-slot
positional index.  Adjacent bits in the 24-bit value region co-occur
at ~50% (vs ~8% if independent) which is the soft cluster signature of
a small-magnitude numeric integer rather than 24 independent flag bits.

Per-field semantic decode of the 4-bit type tag and 24-bit value
region awaits AT-correlated acquisition-transition capture; structural
framing is firm.

## Proprietary sentence field layouts (fields after the talker)

    PWRRPT (19 fields after talker): on_time_ms, slot_ms, mclk_counter,
      sclk_counter, mode, slot_ms_echo, on_time_ms_echo, and 12
      reserved/zero slots

    CC     (8 fields): f0, f1, f2, reg0_hex, reg1_hex, reg2_hex,
      reg3_hex, flag

Hex fields in CC use the literal `0x…` prefix (e.g. `0x2088`).  They
are parsed with `int(x, 0)` so both decimal and hex inputs decode.

## First-byte version gate

Byte 0 is **stably 0x01** across 4,627 SDX55 records on 3 distinct modem
variants:

  - FN980m (Telit/SDX55):    3,038 records (11 captures)
  - RM500Q-AE (Quectel/SDX55):  945 records (3 captures)
  - EM9190 (Sierra/SDX55):       70 records (1 capture)

Byte 0 is therefore the DIAG-convention version byte for the 0x1C7C $PQME
proprietary-NMEA submessage layout. A future firmware emitting 0x1C7C
records under a different submessage version would decode plausibly under
a parser that only checks the 202B length and the ``$PQME…`` ASCII region,
but possibly with different sentence-frame semantics or trailer layout, so
any version other than 0x01 / 0x02 is hard-rejected and version drift
surfaces as a no-parser miss rather than a plausible-looking decode.

Log name: LOG_GNSS_ME_PQME_C
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


PAYLOAD_SIZE = 202
FLAG_OFFSET = 0
ASCII_OFFSET = 2

# End-aligned binary block: 25 little-endian u32 values at absolute offsets
# [101..200], followed by a single byte at offset 201. The block is
# *end-anchored* — its absolute position is fixed at the tail of the 202B
# record regardless of how many bytes the preceding NMEA sentence consumed.
TAIL_BLOCK_OFFSET = 101
TAIL_BLOCK_COUNT = 25  # u32 LE
TAIL_TRAILING_OFFSET = 201

# First-byte version gate — byte 0 (``version``) is one of {0x01, 0x02} per
# the cross-vendor corpus. v=0x01 is the original $PQME-wrapped 202B format;
# v=0x02 is the SDX62 successor (binary, variable-size TLV chain).
_VERSION_V1 = 0x01
_VERSION_V2 = 0x02
_EXPECTED_VERSION = _VERSION_V1  # v=0x01 path uses this for the inner gate

# v=0x01 byte 1 is 0x00 on SDX55 firmware (4,627 records, 3 chipsets) but a
# per-talker ID on the Inseego M3100, so it is exposed raw as ``flag_high``
# and NOT gated. The constant is kept as the SDX55-generation value for
# consumers and tests. v=0x02 byte 1 is the entry count (see the TLV section).
_EXPECTED_FLAG_HIGH = 0x00

# v=0x02 template constants. byte[1] is the TLV entry count (historically
# called the "subtype"); bytes [2:5] are the first entry's (tag, tag_version,
# length), which the template decoders below use as structural anchors.
# Cross-vendor corpus: Quectel RM520N-GL SDX62 + Sierra EM9291 SDX62.
_V2_SUB01 = 0x01      # 22B heartbeat record (2,116 records cross-vendor)
_V2_SUB01_SIZE = 22

# v=0x02 byte[1]=0x09 / 375B. Cross-vendor walk (Quectel RM520N-GL SDX62,
# 1,842 records + Sierra EM9291 SDX62, 310 records; single dominant size
# 375B): 221/375 bytes are cross-vendor invariant. The structural decode
# locks three monotonic clock/counter fields plus the vendor-signature-tagged
# fine clock that the v=0x01 $PQME format also carried (mclk/sclk counters)
# — directly serving the registry's cross-capture-ref WiGLE role.
# Per-counter physical units (ticks vs ms vs clock domain) await
# AT-correlated capture; the monotonicity and the +const coupling are firm
# structural properties.
_V2_SUB09 = 0x09
_V2_SUB09_SIZE = 375
_V2_SUB09_HEADER_B2_OFF = 2  # offset of the structural-anchor byte
_V2_SUB09_HEADER_B2 = 0x0E   # cross-vendor structural anchor value (byte[2], 100% invariant)
# Field offsets (u32-LE unless noted), validated across both SDX62 vendors:
_V2_SUB09_SEQ_OFF = 5            # monotonic per-record sequence counter (100% strictly increasing)
_V2_SUB09_SEQ_PAIRED_OFF = 9     # == seq + firmware const (Quectel +19, Sierra +0)
_V2_SUB09_COUNTER_C_OFF = 22     # third monotonic counter
_V2_SUB09_VENDOR_SIG_OFF = 80    # 2-byte vendor sig (0x72,0x05 Quectel / 0x74,0x09 Sierra)
_V2_SUB09_FINE_CLOCK_OFF = 82    # u32 fine clock, echoed identically at offsets 80/152/197

# v=0x02 byte[1]=0x05 / 365B. Cross-vendor walk (Quectel RM520N-GL SDX62,
# 1,812 records + Sierra EM9291 SDX62, 305 records; dominant cross-vendor
# size 365B): 196/365 bytes (53.7%) are cross-vendor invariant. Unlike the
# 375B record, the three monotonic clock fields here are INDEPENDENT (no
# within-record echo). Two of them (clock_eng_a/_b) advance at an identical
# +1000/record cadence on BOTH vendors — shared GNSS-engine ticks; the third
# (clock_vendor) is vendor-rate-specific (Quectel +1000, Sierra +991 — a
# wall-clock/uptime domain whose rate differs by capture). Per-field physical
# units await AT-correlated capture; the monotonicity + the shared-vs-vendor
# cadence split are firm structural properties. byte[37] (0x02 Quectel /
# 0x04 Sierra) is a vendor discriminator.
_V2_SUB05 = 0x05
_V2_SUB05_SIZE = 365
# Cross-vendor structural anchors at the header (100% invariant both vendors).
_V2_SUB05_HEADER_ANCHORS: dict[int, int] = {2: 0x00, 3: 0x01, 4: 0x75}
_V2_SUB05_CLOCK_ENG_A_OFF = 127  # u32-LE engine clock, +1000/record BOTH vendors
_V2_SUB05_CLOCK_ENG_B_OFF = 237  # u32-LE engine clock, +1000/record BOTH vendors
_V2_SUB05_CLOCK_VENDOR_OFF = 29  # u32-LE wall clock, vendor-rate (+1000 Q / +991 S)
_V2_SUB05_VENDOR_BYTE_OFF = 37   # 0x02 Quectel / 0x04 Sierra

# v=0x02 byte[1]=0x05 / 229B template. A SECOND byte[1]=0x05 template,
# structurally distinct from the 365B 3-clock record above: header anchors
# [2:5]==(0x27,0x01,0x2e) vs 365B's (0x00,0x01,0x75). It is ~14% of every
# v=0x02 capture (tens of thousands of records corpus-wide, cross-vendor
# Quectel RM520N-GL + Sierra EM9291). Cross-vendor walk (350 Quectel + 350
# Sierra records): 192/229 bytes (83.8%) are cross-vendor-invariant — a
# largely-static config/status dump carrying ONE live counter:
#   clock_eng   u32-LE @5  +~1003/record, cadence IDENTICAL on both vendors
#               (an engine tick, firmware-independent — like the 365B
#               clock_eng_a/b, NOT the vendor-rate clock). byte[4]=0x2e is a
#               constant header anchor; a monotonic scan hit at offset 4 is
#               that constant LSB, not a field, so the counter starts at [5].
#   vendor_byte byte[22] = 0x14 Quectel / 0x11 Sierra (recurs @59,@76); other
#               vendor-divergent constants at [14] (0x02/0x00) and [66]
#               (0x3a/0x64).
# No F3 site prints any v=0x02 field, so the counter is exposed as a RAW
# monotonic tick, no units.
_V2_SUB05_SZ229 = 229
_V2_SUB05_SZ229_HEADER_ANCHORS: dict[int, int] = {2: 0x27, 3: 0x01, 4: 0x2E}
_V2_SUB05_SZ229_CLOCK_ENG_OFF = 5     # u32-LE engine tick, +~1000/rec IDENTICAL both vendors
_V2_SUB05_SZ229_VENDOR_BYTE_OFF = 22  # 0x14 Quectel / 0x11 Sierra (recurs @59,@76)

# v=0x02 byte[1]=0x03 / 127B. Single-capture walk (Quectel RM520N-GL SDX62,
# 1,834 records at the 127B size — 127B is Quectel-only; Sierra emits
# byte[1]=0x03 at 173B only). The record is 98.4% invariant: only TWO bytes
# vary, and they are a strongly-correlated 2-state status pair (a sibling of
# the 22B heartbeat — no clocks, no counters):
#   byte[5]  in {0x80, 0x02}   state_flag_a
#   byte[69] in {0x0F, 0x01}   state_flag_b
# Joint distribution over 1,834 records: (0x80,0x0F)x1013, (0x02,0x01)x777,
# (0x80,0x01)x22, (0x02,0x0F)x22 — i.e. the two flags co-vary on 1,790/1,834
# (97.6%) records, with 44 transition records carrying the off-diagonal
# combo. Likely a GNSS-engine state indicator (e.g. tracking vs acquiring);
# physical semantics await AT-correlated capture. bytes[2:5]==(0x2c,0x03,
# 0x37) are 100% invariant structural anchors (single-vendor scope — NOT
# asserted cross-vendor, since single-capture invariants can overfit).
_V2_SUB03 = 0x03
_V2_SUB03_SIZE = 127
_V2_SUB03_HEADER_ANCHORS: dict[int, int] = {2: 0x2C, 3: 0x03, 4: 0x37}
_V2_SUB03_FLAG_A_OFF = 5    # state flag, {0x80, 0x02}
_V2_SUB03_FLAG_B_OFF = 69   # paired state flag, {0x0F, 0x01}

# v=0x02 byte[1]=0x07. Cross-vendor walk (Quectel RM520N-GL SDX62 + Sierra
# EM9291 SDX62). byte[1]=0x07 covers several fixed templates — byte[2] (the
# first entry's tag, coupled 1:1 with byte[4], its length) partitions it:
#
#   size  byte[2]  byte[4]   Quectel   Sierra   status
#   ----  -------  -------   -------   ------   ------
#   364   0x03     0x3c      1812      305      decoded (template below)
#   364   0x09     0x3e      1782      300      decoded (template below)
#   337   0x25     0x37      1812      305      decoded (template below)
#   358   0x1a     -          30        5       rare, generic TLV split only
#   386   0x01     -          30        5       rare, generic TLV split only
#   385   0x08     -          30        5       rare, generic TLV split only
#   300   0x27     -           0        1       Sierra-only singleton
#
# The 337B/tag=0x25 template (92.9% invariant on Sierra, 85.8% on Quectel)
# carries a clean GNSS-engine clock: a u32-LE at offset 218 advancing by
# +256,000/record on BOTH vendors — the SAME engine-tick cadence as 0x147C
# v=0x0A/v=0x0D, i.e. a shared GNSS-engine clock encoding. The clock is
# TRIPLE-REDUNDANT: identical value (within each record) echoed at offsets
# 218, 282, 330. Header anchors bytes[2:5]==(0x25,0x01,0x37) are 100%
# cross-vendor invariant.
#
# The 364B templates (tag 0x03/0x09, the dominant byte[1]=0x07 members by
# count): DIAG records are logged slightly out of *emission* order, so a
# capture-order delta hunt desyncs. A **time-sorted** walk (sort by DLF
# log_time before the monotonic hunt) restores monotonicity and pins the
# offsets cross-vendor (Quectel RM520N-GL + Casa Systems CFW3212 (RG520N
# OpenCPU, SDX62), consistent with the Sierra @69 clock).
_V2_SUB07 = 0x07
_V2_SUB07_TAG25_SIZE = 337
_V2_SUB07_TAG25 = 0x25
# bytes[2:5] structural anchors — 100% cross-vendor invariant (2,117 records,
# Quectel RM520N-GL + Sierra EM9291).
_V2_SUB07_TAG25_HEADER_ANCHORS: dict[int, int] = {2: 0x25, 3: 0x01, 4: 0x37}
# u32-LE GNSS-engine clock, +256000/record both vendors, triple-echoed.
_V2_SUB07_TAG25_CLOCK_OFF = 218
_V2_SUB07_TAG25_CLOCK_ECHO1_OFF = 282
_V2_SUB07_TAG25_CLOCK_ECHO2_OFF = 330

# byte[1]=0x07 / 364B templates. byte[2] is the tag; the two 364B members are
# tag=0x03 (byte[4]=0x3c) and tag=0x09 (byte[4]=0x3e), coupled 1:1 with
# byte[4].
_V2_SUB07_364_SIZE = 364
# --- tag=0x03: engine-clock + sequence-counter record (260/364 cross-vendor
#     invariant). engine_clock u32-LE @69 advances +256000/record on BOTH
#     Quectel and CFW3212 — the SAME engine-tick cadence as tag=0x25 (@218) and
#     0x147C v=0x0A/0x0D. record_seq u32-BE @117 is a +1/record sequence
#     counter; @163 and @240 are two SIBLING +1/record BE counters (distinct
#     base values, not echoes — likely separate clock/count domains).
_V2_SUB07_TAG03 = 0x03
_V2_SUB07_TAG03_HEADER_ANCHORS: dict[int, int] = {2: 0x03, 3: 0x01, 4: 0x3C}
_V2_SUB07_TAG03_ENGINE_CLOCK_OFF = 69
_V2_SUB07_TAG03_SEQ_OFF = 117
_V2_SUB07_TAG03_SEQ_SIB1_OFF = 163
_V2_SUB07_TAG03_SEQ_SIB2_OFF = 240
# --- tag=0x09: sequence-counter record (313/364 cross-vendor invariant).
#     record_seq u32-BE @254 advances +1/record on both vendors. (u32-LE @69
#     is a per-vendor CONSTANT here — NOT a clock — confirming the 364B tags
#     carry genuinely different layouts, not one format at two byte[2] values.)
_V2_SUB07_TAG09 = 0x09
_V2_SUB07_TAG09_HEADER_ANCHORS: dict[int, int] = {2: 0x09, 3: 0x01, 4: 0x3E}
_V2_SUB07_TAG09_SEQ_OFF = 254


# ---------------------------------------------------------------------------
# Proprietary-NMEA sentence dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PqmePwrRpt:
    """$PQMEPWRRPT — ME-engine power/duty-cycle telemetry."""
    on_time_ms: int
    slot_ms: int
    mclk_counter: int
    sclk_counter: int
    mode: int
    slot_ms_echo: int
    on_time_ms_echo: int
    reserved: list[int]

    def to_dict(self) -> dict[str, Any]:
        return {
            'sentence_type': 'PQMEPWRRPT',
            'on_time_ms': self.on_time_ms,
            'slot_ms': self.slot_ms,
            'mclk_counter': self.mclk_counter,
            'sclk_counter': self.sclk_counter,
            'mode': self.mode,
            'slot_ms_echo': self.slot_ms_echo,
            'on_time_ms_echo': self.on_time_ms_echo,
            'reserved': self.reserved,
        }


@dataclass
class PqmeCc:
    """$PQMECC — ME-engine clock/channel control register dump."""
    f0: int
    f1: int
    f2: int
    reg0: int
    reg1: int
    reg2: int
    reg3: int
    flag: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'sentence_type': 'PQMECC',
            'f0': self.f0,
            'f1': self.f1,
            'f2': self.f2,
            'reg0': self.reg0,
            'reg1': self.reg1,
            'reg2': self.reg2,
            'reg3': self.reg3,
            'flag': self.flag,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_checksum(sentence: str) -> str:
    idx = sentence.find('*')
    return sentence[:idx] if idx >= 0 else sentence


def _parse_int(s: str, base: int = 0) -> int | None:
    if not s:
        return None
    try:
        return int(s, base)
    except ValueError:
        return None


def _parse_pwrrpt(fields: list[str]) -> PqmePwrRpt | None:
    if len(fields) < 8:
        return None
    try:
        return PqmePwrRpt(
            on_time_ms=int(fields[1]),
            slot_ms=int(fields[2]),
            mclk_counter=int(fields[3]),
            sclk_counter=int(fields[4]),
            mode=int(fields[5]),
            slot_ms_echo=int(fields[6]),
            on_time_ms_echo=int(fields[7]),
            reserved=[int(f) if f else 0 for f in fields[8:]],
        )
    except (ValueError, IndexError):
        return None


def _parse_cc(fields: list[str]) -> PqmeCc | None:
    if len(fields) < 9:
        return None
    vals = [_parse_int(fields[i]) for i in range(1, 9)]
    if any(v is None for v in vals):
        return None
    return PqmeCc(*vals)  # type: ignore[arg-type]


_SENTENCE_PARSERS = {
    'PQMEPWRRPT': _parse_pwrrpt,
    'PQMECC': _parse_cc,
}


def parse_pqme_sentence(sentence: str) -> PqmePwrRpt | PqmeCc | None:
    """Parse a complete $PQME* sentence string into a structured dataclass."""
    stripped = _strip_checksum(sentence)
    fields = stripped.split(',')
    if not fields:
        return None
    talker = fields[0].lstrip('$')
    parser = _SENTENCE_PARSERS.get(talker)
    if parser is None:
        return None
    return parser(fields)


# ---------------------------------------------------------------------------
# Top-level record
# ---------------------------------------------------------------------------

@dataclass
class Diag0x1C7C:
    """$PQME* proprietary-NMEA wrapped in a DIAG log frame (0x1C7C).

    ``version`` is byte 0 of the payload (stably 0x01 across all
    observed firmware — see the module docstring for the cross-chipset
    corpus).  ``flag_high`` is byte 1 (0x00 on SDX55; a per-talker ID on
    the Inseego M3100 — see the module docstring).  ``flag`` is the
    legacy u16-view of the two-byte header (``version | flag_high <<
    8``) and is kept for backward compatibility with downstream
    consumers.

    ``tail_u32`` is the 25-element end-anchored u32 LE array decoded
    from the binary block at absolute offsets [101..200]; per-field
    semantics are not yet known but the structural framing is firm
    across the cross-vendor SDX55 corpus.  ``tail_byte_201`` is the
    single trailing byte at offset 201 (outside the u32 array).

    ``pre_tail_residue`` is the RAW, UN-NAMED byte run between the NMEA
    sentence's terminator and the end-anchored u32 block (also contained
    in ``trailer``).  It is live data, not padding: on
    94 real RM500Q-AE v=0x01 records the 7 bytes at [94:101] are
    non-zero on 35–69 of them.  Deliberately un-named: F3 (mc_pqme.c)
    prints the ASCII sentence and says nothing about this region, so
    naming it would be invention.
    """
    log_time: int
    version: int
    flag_high: int
    flag: int
    nmea_sentence: str
    nmea_talker: str
    trailer: bytes
    trailer_has_dead_marker: bool
    tail_u32: tuple[int, ...]
    tail_byte_201: int
    pre_tail_residue: bytes = b''
    parsed: PqmePwrRpt | PqmeCc | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x1C7C',
            'log_time': self.log_time,
            'version': self.version,
            'flag_high': self.flag_high,
            'flag': self.flag,
            'nmea_talker': self.nmea_talker,
            'nmea_sentence': self.nmea_sentence,
            'trailer_len': len(self.trailer),
            'trailer_has_dead_marker': self.trailer_has_dead_marker,
            'tail_u32': list(self.tail_u32),
            'tail_byte_201': self.tail_byte_201,
            'pre_tail_residue': self.pre_tail_residue.hex(),
            'pre_tail_residue_len': len(self.pre_tail_residue),
        }
        if self.parsed is not None:
            d['parsed'] = self.parsed.to_dict()
        return d


_DEAD_MARKER = b'\xde\xad\x00\x08'


@dataclass
class Diag0x1C7Cv2Sub01:
    """v=0x02 / subtype=0x01 / 22B fixed.

    The simplest attested v=0x02 template. A corpus walk (Quectel
    RM520N-GL SDX62 + Sierra EM9291 SDX62, 2,116 records total) shows 14/22 bytes (63.6%) are corpus-invariant. Four bytes encode a
    vendor signature that uniquely identifies the emitting modem family:

      | byte offset | Quectel SDX62 | Sierra SDX62 | Notes |
      |------------:|:--------------|:-------------|:------|
      |          11 | 0x72          | 0x73         | vendor tag low |
      |          12 | 0x05          | 0x09         | vendor tag high |
      |          13 | 0x01          | 0x00         | vendor flag |
      |          18 | 0x01          | 0x00         | vendor flag (second pair) |

    The 4-byte vendor signature ``(byte[11], byte[12], byte[13], byte[18])``
    is preserved as ``vendor_signature`` on the dataclass for downstream
    cross-modem fingerprinting. byte[0]/[1] are the version + subtype
    discriminators (always 0x02 / 0x01). The remaining variable bytes
    were observed only at offsets 11/12/13/18 — so a future drift in
    any other byte position is itself meaningful.

    Per-subtype semantic naming (heartbeat vs state report) awaits AT-
    correlated capture; structural framing is firm.
    """
    log_time: int
    version: int          # always 0x02
    subtype: int          # always 0x01
    vendor_signature: tuple[int, int, int, int]   # (b11, b12, b13, b18)
    raw: bytes            # full 22B preserved for downstream RE

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1C7Cv2Sub01',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'vendor_signature': list(self.vendor_signature),
            'vendor_signature_hex': '{:02x}{:02x}{:02x}{:02x}'.format(*self.vendor_signature),
            'payload_size': len(self.raw),
        }


@dataclass
class Diag0x1C7Cv2Sub09:
    """v=0x02 / subtype=0x09 / 375B fixed.

    The largest single-size v=0x02 template by record count (1,842 Quectel
    RM520N-GL + 310 Sierra EM9291 records).
    221/375 bytes are cross-vendor invariant; the remaining variable bytes
    fall into a small set of structurally-firm field families:

    **Monotonic clock/counter fields** (the headline finding):

      | field                | offset (u32-LE) | behavior |
      |----------------------|----------------:|----------|
      | ``seq_counter``      |               5 | strictly increasing, +1/record, 100% monotone on both vendors (1841/1841 Quectel, 309/309 Sierra) |
      | ``seq_counter_paired``|              9 | rigidly ``seq_counter + firmware_const`` (Quectel +19, Sierra +0) — a paired clock domain |
      | ``counter_c``        |              22 | third monotonic counter |
      | ``fine_clock``       |              82 | high-resolution clock (advances ~1000/record), echoed *identically* at offsets 80, 152, 197 |

    These are the same ME-engine clock-counter family the v=0x01 $PQME
    PWRRPT format exposed (``mclk_counter`` / ``sclk_counter``), and they
    populate the registry's ``cross-capture-ref`` WiGLE role (ts64-to-ts64
    time alignment across captures). Physical units (tick vs ms vs which
    clock domain) await AT-correlated capture — but the **monotonicity**
    and the **+const coupling** are firm cross-vendor structural facts,
    not byte-width guesses.

    **Vendor signature** ``(byte[80], byte[81])`` = ``(0x72, 0x05)`` on
    Quectel / ``(0x74, 0x09)`` on Sierra — the *same* fingerprint the 22B
    record carries at its bytes 11/12. Here it prefixes the 6-byte
    ``[sig:2][fine_clock:u32]`` block that recurs at offsets 80/152/197.

    **Structural gate:** byte[2]==0x0E is a 100%-invariant cross-vendor
    anchor; a record that fails it is rejected (returns None) rather than
    mis-decoded (size invariance is not format invariance). byte[3]/byte[4] (0x01 / 0x48) are exposed as ``header_const``
    for drift visibility.

    Full 375B preserved as ``raw`` — a *structural* decode; per-field
    semantics of the remaining variable regions are open.
    """
    log_time: int
    version: int                          # always 0x02
    subtype: int                          # always 0x09
    header_const: tuple[int, int, int]    # bytes [2:5] = (0x0e, 0x01, 0x48)
    seq_counter: int                      # u32 LE @5  — monotonic per-record counter
    seq_counter_paired: int               # u32 LE @9  — == seq_counter + firmware const
    counter_c: int                        # u32 LE @22 — third monotonic counter
    fine_clock: int                       # u32 LE @82 — vendor-tagged fine clock (echoed @80/152/197)
    vendor_signature: tuple[int, int]     # (byte[80], byte[81])
    raw: bytes                            # full 375B preserved for downstream RE

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1C7Cv2Sub09',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'header_const': list(self.header_const),
            'seq_counter': self.seq_counter,
            'seq_counter_paired': self.seq_counter_paired,
            'counter_c': self.counter_c,
            'fine_clock': self.fine_clock,
            'vendor_signature': list(self.vendor_signature),
            'vendor_signature_hex': '{:02x}{:02x}'.format(*self.vendor_signature),
            'payload_size': len(self.raw),
        }


@dataclass
class Diag0x1C7Cv2Sub05:
    """v=0x02 / subtype=0x05 / 365B fixed.

    Cross-vendor corpus walk (Quectel RM520N-GL SDX62, 1,812 records +
    Sierra EM9291 SDX62, 305 records; dominant cross-vendor size 365B):
    196/365 bytes (53.7%) are cross-vendor invariant.

    **Monotonic clock fields** — three INDEPENDENT clocks (unlike the
    375B record, there is no within-record echo: u32@127 != u32@237 != u32@29):

      | field            | offset (u32-LE) | cadence |
      |------------------|----------------:|---------|
      | ``clock_eng_a``  |             127 | +1000/record, IDENTICAL on both vendors — GNSS-engine tick |
      | ``clock_eng_b``  |             237 | +1000/record, IDENTICAL on both vendors — second engine tick |
      | ``clock_vendor`` |              29 | vendor-rate (Quectel +1000 / Sierra +991) — a wall-clock/uptime domain whose rate differs by capture |

    The shared-vs-vendor cadence split is itself the finding: two engine
    ticks run at a firmware-independent rate while a third tracks a
    vendor-specific oscillator. All three are part of the same ME-engine
    clock-counter family the v=0x01 $PQME format and the 375B record expose, serving
    the registry's ``cross-capture-ref`` WiGLE role. Physical units (tick
    vs ms) await AT-correlated capture; monotonicity + the cadence split
    are firm cross-vendor structural facts, not byte-width guesses.

    **Vendor discriminator** ``byte[37]`` = 0x02 Quectel / 0x04 Sierra.

    **Structural gate:** bytes [2:5] == (0x00, 0x01, 0x75) are 100%-invariant
    cross-vendor anchors; a 365B sub=0x05 record failing them is rejected
    (returns None) rather than mis-decoded, so a future format drift
    surfaces as a no-parse miss. Exposed as ``header_const`` for drift
    visibility.

    Full 365B preserved as ``raw`` — a *structural* decode; per-field
    semantics of the variable regions are open.
    """
    log_time: int
    version: int                          # always 0x02
    subtype: int                          # always 0x05
    header_const: tuple[int, int, int]    # bytes [2:5] = (0x00, 0x01, 0x75)
    clock_eng_a: int                      # u32 LE @127 — engine tick, +1000/rec both vendors
    clock_eng_b: int                      # u32 LE @237 — engine tick, +1000/rec both vendors
    clock_vendor: int                     # u32 LE @29  — wall clock, vendor-rate
    vendor_byte: int                      # byte[37] — 0x02 Quectel / 0x04 Sierra
    raw: bytes                            # full 365B preserved for downstream RE

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1C7Cv2Sub05',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'header_const': list(self.header_const),
            'clock_eng_a': self.clock_eng_a,
            'clock_eng_b': self.clock_eng_b,
            'clock_vendor': self.clock_vendor,
            'vendor_byte': self.vendor_byte,
            'payload_size': len(self.raw),
        }


@dataclass
class Diag0x1C7Cv2Sub05Sz229:
    """v=0x02 / subtype=0x05 / 229B fixed.

    The SECOND sub=0x05 template, structurally distinct from the 365B
    3-clock record (``Diag0x1C7Cv2Sub05``): its header anchors are
    ``[2:5]==(0x27,0x01,0x2e)`` rather than ``(0x00,0x01,0x75)``. It is
    ~14% of every v=0x02 capture (tens of thousands of records
    corpus-wide).

    Cross-vendor walk (350 Quectel RM520N-GL + 350 Sierra EM9291 records):
    **192/229 bytes (83.8%) are cross-vendor invariant** — a largely-static
    config/status dump carrying a single live counter.

    **Monotonic clock** — one engine tick, unlike the 365B record's three:

      | field       | offset (u32-LE) | cadence |
      |-------------|----------------:|---------|
      | ``clock_eng`` |             5 | +~1003/record, cadence IDENTICAL on both vendors — an engine tick (firmware-independent), the same family as the 365B ``clock_eng_a/b`` |

    ``byte[4]==0x2e`` is a constant header anchor, so the counter begins at
    offset 5 (a monotonic-scan hit at offset 4 is that constant low byte,
    not a field).

    **Vendor discriminator** ``byte[22]`` = 0x14 Quectel / 0x11 Sierra
    (recurs at offsets 59 and 76); further vendor-divergent constants sit
    at ``byte[14]`` (0x02/0x00) and ``byte[66]`` (0x3a/0x64).

    **Structural gate:** ``[2:5]==(0x27,0x01,0x2e)`` are 100%-invariant
    cross-vendor anchors; a 229B sub=0x05 record failing them is rejected
    (returns None) rather than mis-decoded, so a future format drift
    surfaces as a no-parse miss. Exposed as ``header_const``.

    No F3 site prints any v=0x02 field, so ``clock_eng`` is a RAW monotonic
    tick — no physical units are claimed. Full 229B preserved as ``raw``;
    per-field semantic decode of the static regions awaits AT correlation.
    """
    log_time: int
    version: int                          # always 0x02
    subtype: int                          # always 0x05
    header_const: tuple[int, int, int]    # bytes [2:5] = (0x27, 0x01, 0x2e)
    clock_eng: int                        # u32 LE @5 — engine tick, +~1000/rec both vendors
    vendor_byte: int                      # byte[22] — 0x14 Quectel / 0x11 Sierra
    raw: bytes                            # full 229B preserved for downstream RE

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1C7Cv2Sub05Sz229',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'header_const': list(self.header_const),
            'clock_eng': self.clock_eng,
            'vendor_byte': self.vendor_byte,
            'payload_size': len(self.raw),
        }


@dataclass
class Diag0x1C7Cv2Sub03:
    """v=0x02 / subtype=0x03 / 127B fixed.

    Single-capture walk (Quectel RM520N-GL SDX62, 1,834 records). sub=0x03
    at 127B is **Quectel-only** (Sierra emits sub=0x03 at 173B), so this is
    a single-vendor structural decode — gated strictly and scoped as such.

    The record is **98.4% invariant**: only two bytes vary, and they form a
    strongly-correlated 2-state status pair (a sibling of sub=0x01's 22B
    heartbeat — no clock/counter fields at all):

      | field          | offset | values        |
      |----------------|-------:|---------------|
      | ``state_flag_a`` |    5 | {0x80, 0x02}  |
      | ``state_flag_b`` |   69 | {0x0F, 0x01}  |

    Joint distribution (1,834 records): (0x80,0x0F)x1013, (0x02,0x01)x777,
    (0x80,0x01)x22, (0x02,0x0F)x22 — the two flags co-vary on 97.6% of
    records, the 44 off-diagonal records being state transitions. Likely a
    GNSS-engine state indicator (tracking vs acquiring class); physical
    semantics await AT-correlated capture.

    **Structural gate:** bytes [2:5]==(0x2c,0x03,0x37) are 100%-invariant
    anchors on the single-vendor corpus; a 127B sub=0x03 record failing them
    is rejected (returns None) rather than mis-decoded. Exposed as
    ``header_const`` for drift visibility. Full 127B preserved as ``raw``.
    """
    log_time: int
    version: int                          # always 0x02
    subtype: int                          # always 0x03
    header_const: tuple[int, int, int]    # bytes [2:5] = (0x2c, 0x03, 0x37)
    state_flag_a: int                     # byte[5]  — {0x80, 0x02}
    state_flag_b: int                     # byte[69] — {0x0F, 0x01}
    raw: bytes                            # full 127B preserved for downstream RE

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1C7Cv2Sub03',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'header_const': list(self.header_const),
            'state_flag_a': self.state_flag_a,
            'state_flag_b': self.state_flag_b,
            'payload_size': len(self.raw),
        }


@dataclass
class Diag0x1C7Cv2Sub07Tag25:
    """v=0x02 / subtype=0x07 / byte[2]=0x25 / 337B.

    sub=0x07 is a multi-size container family; ``byte[2]`` is a secondary
    report-type tag (coupled 1:1 with ``byte[4]``). This dataclass decodes
    the **tag=0x25 / 337B** member — the cleanest cross-vendor template
    (92.9% invariant Sierra EM9291, 85.8% Quectel RM520N-GL; 2,117 records).

    It carries a **GNSS-engine clock**: a u32-LE at offset 218 advancing by
    +256,000/record on both vendors — the same engine-tick cadence as
    0x147C v=0x0A/v=0x0D. The value is triple-redundant,
    echoed identically (within a record) at offsets 218, 282, 330; the two
    echoes are exposed for drift visibility.

    **Structural gate:** bytes[2:5]==(0x25,0x01,0x37) are 100% cross-vendor
    invariant anchors — a 337B sub=0x07 record failing them (or whose three
    clock echoes disagree) is rejected (returns None) rather than mis-decoded,
    so a future format drift surfaces as a no-parse miss instead of
    plausible-but-garbage clock values. Full 337B
    preserved as ``raw``.
    """
    log_time: int
    version: int                          # always 0x02
    subtype: int                          # always 0x07
    report_tag: int                       # byte[2] — secondary tag, 0x25 here
    header_const: tuple[int, int, int]    # bytes[2:5] = (0x25, 0x01, 0x37)
    engine_clock: int                     # u32-LE @218, +256000/record
    engine_clock_echo1: int               # u32-LE @282 (== engine_clock)
    engine_clock_echo2: int               # u32-LE @330 (== engine_clock)
    raw: bytes                            # full 337B preserved for downstream RE

    @property
    def engine_clock_echoes_ok(self) -> bool:
        return self.engine_clock == self.engine_clock_echo1 == self.engine_clock_echo2

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1C7Cv2Sub07Tag25',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'report_tag': self.report_tag,
            'header_const': list(self.header_const),
            'engine_clock': self.engine_clock,
            'engine_clock_echoes_ok': self.engine_clock_echoes_ok,
            'payload_size': len(self.raw),
        }


@dataclass
class Diag0x1C7Cv2Sub07Tag03:
    """v=0x02 / subtype=0x07 / byte[2]=0x03 / 364B.

    The dominant sub=0x07 template by record count. Carries a **GNSS-engine
    clock** — a u32-LE at offset 69 advancing +256,000/record on both SDX62
    vendors (Quectel RM520N-GL + Casa Systems CFW3212), the same engine-tick
    cadence as the tag=0x25 template (@218) and 0x147C v=0x0A/v=0x0D
    — plus a **sequence counter** (u32-BE @117, +1/record).
    Offsets 163 and 240 hold two further +1/record big-endian counters with
    distinct base values (sibling count/clock domains, exposed as
    ``seq_siblings``), not echoes of @117.

    DIAG capture order is not emission order, so the clock looks
    vendor-divergent in capture order; a time-sorted corpus walk pins
    engine_clock @69 cross-vendor. The +256000 record-level cadence is
    identical on both vendors (a larger median such as 384000 is
    gap-inflated across dropped records).

    **Structural gate:** bytes[2:5]==(0x03,0x01,0x3c) are cross-vendor
    invariant anchors (260/364 bytes invariant cross-vendor); a 364B sub=0x07
    record whose byte[2] tag is 0x03 but which fails them is rejected rather
    than mis-decoded. Full 364B preserved as ``raw``.
    """
    log_time: int
    version: int                          # always 0x02
    subtype: int                          # always 0x07
    report_tag: int                       # byte[2] — secondary tag, 0x03 here
    header_const: tuple[int, int, int]    # bytes[2:5] = (0x03, 0x01, 0x3c)
    engine_clock: int                     # u32-LE @69, +256000/record
    record_seq: int                       # u32-BE @117, +1/record
    seq_siblings: tuple[int, int]         # u32-BE @163/@240, sibling +1 counters
    raw: bytes                            # full 364B preserved for downstream RE

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1C7Cv2Sub07Tag03',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'report_tag': self.report_tag,
            'header_const': list(self.header_const),
            'engine_clock': self.engine_clock,
            'record_seq': self.record_seq,
            'seq_siblings': list(self.seq_siblings),
            'payload_size': len(self.raw),
        }


@dataclass
class Diag0x1C7Cv2Sub07Tag09:
    """v=0x02 / subtype=0x07 / byte[2]=0x09 / 364B.

    The second 364B sub=0x07 template. Carries a **sequence counter**: a u32-BE
    at offset 254 advancing +1/record on both SDX62 vendors (Quectel RM520N-GL
    + Casa Systems CFW3212). Unlike tag=0x03, u32-LE @69 is a per-vendor
    CONSTANT here (not a clock) — direct evidence the two 364B byte[2] tags are
    genuinely distinct layouts, not one format keyed at two tag values.

    **Structural gate:** bytes[2:5]==(0x09,0x01,0x3e) are cross-vendor
    invariant anchors (313/364 bytes invariant cross-vendor); a 364B sub=0x07
    record whose byte[2] tag is 0x09 but which fails them is rejected rather
    than mis-decoded. Full 364B preserved as ``raw``.
    """
    log_time: int
    version: int                          # always 0x02
    subtype: int                          # always 0x07
    report_tag: int                       # byte[2] — secondary tag, 0x09 here
    header_const: tuple[int, int, int]    # bytes[2:5] = (0x09, 0x01, 0x3e)
    record_seq: int                       # u32-BE @254, +1/record
    raw: bytes                            # full 364B preserved for downstream RE

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1C7Cv2Sub07Tag09',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'report_tag': self.report_tag,
            'header_const': list(self.header_const),
            'record_seq': self.record_seq,
            'payload_size': len(self.raw),
        }


# ---------------------------------------------------------------------------
# v=0x02 is a TLV chain
# ---------------------------------------------------------------------------
#
# Every v=0x02 record is
#
#     [0]  version   = 0x02
#     [1]  n_entries (historically called the "subtype")
#     [2:] n_entries x ( tag u8, tag_version u8, length u8, body[length] )
#
# and the chain consumes the payload EXACTLY. Measured on 2,605 v=0x02 records
# from 8 captures (Quectel RM520N-GL and Foxconn T99W640, two firmware
# builds each, plus Sierra EM9291): 2,605 / 2,605 consume to the last byte,
# across all 37 (byte1, size) pairs, decoded and rejected alike. Each
# (tag, tag_version) has ONE length on all three vendors (e.g. 0x14 v1 = 17 B,
# 0x00 v1 = 117 B, 0x0e v1 = 72 B). A newer T99W640 build bumps six tags (0x01 v2->v3
# same length; 0x12 v1 8 B -> v2 68 B; 0x1f v1 31 B -> v2 39 B; 0x22 v1 52 B ->
# v2 59 B; 0x2e v1 55 B -> v2 63 B; 0x2f v1 4 B -> v2 9 B), and those bumps are
# its whole "new sizes" (373 = 365 + 8 from 0x2e; 372 = 364 + 8 from 0x1f).
#
# So bytes [2:5], which the template decoders above anchor on, are the FIRST
# ENTRY's (tag, tag_version, length), and the "templates" are packing
# boundaries: the firmware fills a record with whatever sub-reports are queued
# (the same 0x09-0a-1e-26-17-18 run appears in 364, 384 and 385 B records).
# The template decoders stay for their consumers; any v=0x02 record they do
# not claim falls through to the generic chain below instead of being dropped.
# No F3 site names any tag, so tags stay numeric and bodies stay raw.


@dataclass
class Diag0x1C7Cv2Entry:
    """One ``(tag, tag_version, length, body)`` entry of a v=0x02 record."""
    tag: int
    tag_version: int
    offset: int       # absolute payload offset of the entry's tag byte
    body: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            'tag': self.tag,
            'tag_version': self.tag_version,
            'length': len(self.body),
            'offset': self.offset,
            'body_hex': self.body.hex(),
        }


@dataclass
class Diag0x1C7Cv2Report:
    """v=0x02 record split into its TLV entries (generic).

    Returned for every v=0x02 record the template decoders do not claim,
    provided the entry chain consumes the payload exactly. A chain that
    overruns or stops short is rejected (``None``). That end-exact closure is
    the structural gate, and it is a strong one: a truncated, merged or
    shifted payload does not land on the last byte.
    """
    log_time: int
    version: int                          # always 0x02
    n_entries: int                        # byte[1]
    entries: list[Diag0x1C7Cv2Entry]
    raw: bytes

    @property
    def tags(self) -> tuple[int, ...]:
        return tuple(e.tag for e in self.entries)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1C7Cv2Report',
            'log_time': self.log_time,
            'version': self.version,
            'n_entries': self.n_entries,
            'tags': '-'.join(f'{t:02x}' for t in self.tags),
            'entries': [e.to_dict() for e in self.entries],
            'payload_size': len(self.raw),
        }


def split_v2_entries(data: bytes) -> list[Diag0x1C7Cv2Entry] | None:
    """Split a v=0x02 payload into its entries, or ``None`` if the chain does
    not consume ``data`` exactly (or byte 0 is not 0x02)."""
    if len(data) < 2 or data[0] != _VERSION_V2:
        return None
    off = 2
    entries: list[Diag0x1C7Cv2Entry] = []
    for _ in range(data[1]):
        if off + 3 > len(data):
            return None
        tag, tag_version, length = data[off], data[off + 1], data[off + 2]
        end = off + 3 + length
        if end > len(data):
            return None
        entries.append(Diag0x1C7Cv2Entry(tag, tag_version, off, bytes(data[off + 3:end])))
        off = end
    return entries if off == len(data) else None


# ── Ground-truth recipe — WiGLE-indirect (cross-capture-ref) ─────────────────
# 0x1C7C v=0x01 is the $PQME proprietary-NMEA ME-engine telemetry: the PWRRPT
# sentence exposes GNSS-engine clock counters + uptime. WiGLE-indirect with the
# cross-capture-ref role — these receiver-internal monotonic clocks serve as a
# ts64-to-ts64 reference for aligning GNSS captures (no lat/lon of their own).
# Target = RM500Q-AE (Quectel SDX55), an emitter of the DECODED v=0x01 ASCII
# form (4,679 v0x01 records in the corpus). RM520N-GL (SDX62) emits v=0x02
# (binary) — a different recipe; v=0x01 is the version with decoded telemetry
# fields, so this recipe targets it.
# cond:sky-fix — run a GNSS session so the engine is powered and reporting.

@register(
    0x1C7C,
    name="0x1C7C",
    description=(
        "GNSS ME-engine telemetry. v=0x01: $PQME-wrapped 202B. "
        "v=0x02: binary TLV chain ([0x02][n][n x (tag, ver, len, body)]); "
        "byte[1] (n) + the first entry's tag select fixed templates decoded "
        "structurally: n=0x01 (22B heartbeat), n=0x09 (375B clock/counter "
        "record), n=0x05 (365B 3-clock record and 229B engine-clock config "
        "record), n=0x03 (127B 2-state status record), n=0x07/tag=0x25 (337B "
        "engine-clock record), n=0x07/tag=0x03 & tag=0x09 (364B engine-clock/"
        "seq records). Every other v=0x02 packing splits generically into its "
        "(tag, ver, len, body) entries (Diag0x1C7Cv2Report)."
    ),
    version=16,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v=0x01 F3-grounded: on an RM500Q-AE capture with a live GNSS fix, "
        "245/245 (100%) 0x1C7C ASCII $PQMEPWRRPT sentences are byte-exact "
        "matches of an F3 mc_pqme.c:3634 print (F3 fully resolved); a Compal "
        "RXM-G1 capture matches 119/119. on_time_ms/mclk_counter/mode "
        "verified; cadences mclk +1.7M/rec, sclk +1000/rec, mode=8. "
        "Clean-room RE from EM9190 (SDX55); size-invariant at 202B across "
        "SDX55 modems on 3 vendors (Telit FN980m + Quectel RM500Q-AE + Sierra "
        "EM9190), byte 0 stably 0x01 across 4,627 records; byte 1 is 0x00 on "
        "SDX55 and a per-talker ID on the Inseego M3100. The 7-byte "
        "pre-tail residue is live, un-named data. v=0x02 (Quectel RM520N-GL, "
        "Sierra EM9291, Casa CFW3212, Foxconn T99W640; all SDX6x/SDX7x) is a "
        "TLV chain consumed exactly on 2,605/2,605 sampled records. Template "
        "findings: 375B (2,152 records, 221/375 bytes cross-vendor invariant) "
        "locks three monotonic counters (@5/@9/@22) + a vendor-sig-tagged "
        "fine clock (@82, echoed @80/152/197); 365B (2,117 records, 53.7% "
        "invariant) has two engine ticks @127/@237 at +1000/record on both "
        "vendors plus a vendor-rate wall clock @29 (Quectel +1000 / Sierra "
        "+991); 229B (83.8% invariant) carries one engine tick @5 "
        "(+~1003/record); 127B (Quectel-only, 1,834 records) is a "
        "98.4%-invariant 2-state status pair at byte[5]/byte[69]; 337B "
        "tag=0x25 carries a triple-echoed engine clock @218/282/330 at "
        "+256000/record (same cadence as 0x147C v=0x0A/0x0D); 364B tag=0x03 "
        "carries engine_clock @69 (+256000/record) + BE record_seq @117, "
        "364B tag=0x09 a BE record_seq @254 (time-sorted walk). No F3 site "
        "prints any v=0x02 field, so clocks are raw ticks with no units."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Layer-2 invariant — version enum [0x01, 0x02] reflecting cross-vendor
    # SDX62 v=0x02 attestation (Quectel RM520N-GL + Sierra EM9291 corpus walk).
    # v=0x02 templates are decoded structurally and every other v=0x02
    # packing splits generically into TLV entries.
    field_invariants={
        "version": {"enum": [_VERSION_V1, _VERSION_V2]},
        # No flag_high invariant: byte[1] is the TLV entry count in v=0x02
        # and a per-talker ID on the M3100's v=0x01, so a {0x00}-enum check
        # would falsely flag real records.
    },
    # WiGLE tagging (NMEA carrier): no lat/lon, but the PqmePwrRpt dataclass
    # exposes mclk_counter (ME-engine master clock), sclk_counter (sleep
    # clock), and on_time_ms (uptime) at dataclass level via .parsed. These
    # receiver-internal clock counters serve as a ts64-to-ts64 reference per
    # the cross-capture-ref role definition ("ts64-to-wall-clock or
    # ts64-to-ts64 references"). Validated 4,627 records / 3 cross-vendor
    # SDX55 chipsets (FN980m + RM500Q-AE + EM9190).
    wigle_direct=False,
    wigle_roles=("cross-capture-ref",),
    # v=0x01 records are $PQME-wrapped proprietary NMEA sentences
    # ($PQMECC / $PQMEPWRRPT, '$P…*XX' checksum form) — text, not packed
    # binary. Confirmed cross-vendor on Telit + SIMCom
    # (FN980m + SIM8202G-M2). v=0x02 subtypes are binary (no ASCII).
    ascii_kinds=("nmea",),
    # Ground-truth recipe: WiGLE-indirect cross-capture-ref validation
    # for v0x01 (RM500Q-AE SDX55).
)
def parse_0x1c7c(log_time: int, data: bytes) -> Diag0x1C7C | Diag0x1C7Cv2Sub01 | Diag0x1C7Cv2Sub03 | Diag0x1C7Cv2Sub05 | Diag0x1C7Cv2Sub05Sz229 | Diag0x1C7Cv2Sub07Tag03 | Diag0x1C7Cv2Sub07Tag09 | Diag0x1C7Cv2Sub07Tag25 | Diag0x1C7Cv2Sub09 | Diag0x1C7Cv2Report | None:
    # Layer-1 first-byte version-gate: byte 0 MUST be read FIRST and validated
    # before any other byte access. Reject unknown versions BEFORE
    # dispatching so an unmapped byte[0] hard-rejects rather than
    # falling through to a per-version decoder that might silently
    # mis-parse.
    if len(data) < 2:
        return None
    version = data[0]
    if version not in (_VERSION_V1, _VERSION_V2):
        return None
    if version == _VERSION_V2:
        return _parse_0x1c7c_v2(log_time, data)
    # version == _VERSION_V1 — original $PQME path below.

    if len(data) < PAYLOAD_SIZE:
        return None

    # Byte 1 is NOT gated: 0x00 on SDX55 firmware, a per-talker ID on the
    # Inseego M3100. A ``!= 0x00`` gate would drop every M3100 sentence but
    # PWRRPT. ``$`` at byte 2 (below) is the anchor.
    flag_high = data[1]

    # Byte 2 is uniformly 0x24 ('$') across the same
    # 4,627-record cross-vendor SDX55 corpus that anchors the byte-0 /
    # byte-1 invariants — the NMEA sentence start is byte-aligned, not
    # search-aligned. Promote from implicit `data.find(b'$', ASCII_OFFSET)`
    # to an explicit hard gate so a corrupted byte 2 that lets a later '$'
    # win the search (offset-shifted plausible-but-wrong decode) is
    # rejected instead of silently mis-parsing.
    if data[ASCII_OFFSET] != 0x24:
        return None

    # ``flag`` preserved as the legacy u16 header view for backward
    # compatibility with prior consumers.
    flag = unpack_from('<H', data, FLAG_OFFSET)[0]

    nmea_start = data.find(b'$', ASCII_OFFSET)
    if nmea_start < 0:
        return None

    nmea_end = len(data)
    for terminator in (b'\r\n', b'\r', b'\n', b'\x00'):
        pos = data.find(terminator, nmea_start)
        if 0 <= pos < nmea_end:
            nmea_end = pos

    nmea_sentence = data[nmea_start:nmea_end].decode('ascii', errors='replace')
    nmea_talker = nmea_sentence.split(',', 1)[0] if ',' in nmea_sentence else nmea_sentence

    trailer_start = nmea_end
    for skip_byte in (b'\r', b'\n', b'\x00'):
        while trailer_start < len(data) and data[trailer_start:trailer_start + 1] == skip_byte:
            trailer_start += 1
    trailer = bytes(data[trailer_start:PAYLOAD_SIZE])

    parsed = parse_pqme_sentence(nmea_sentence)

    # End-anchored binary block: 25 LE u32 values at absolute [101..200].
    # See module docstring "Binary block structure" for the end-aligned
    # corpus-invariance analysis that established this framing.
    tail_u32 = unpack_from(f'<{TAIL_BLOCK_COUNT}I', data, TAIL_BLOCK_OFFSET)
    tail_byte_201 = data[TAIL_TRAILING_OFFSET]

    # Live bytes between the sentence's terminator run and the END-ANCHORED
    # u32 block.
    #
    # The byte map closes at 202 as 2 + [2:101] + 25*u4@101 + [201], so the
    # region [trailer_start .. 101] belongs to no other exposed scalar: it is
    # past the ASCII sentence, before tail_u32's absolute 101 anchor, and is
    # not tail_byte_201. ``to_dict()`` publishes only trailer_len and
    # trailer_has_dead_marker from ``trailer``, so this field is the only
    # way the bytes reach a consumer.
    #
    # Not dead padding: on 94 real RM500Q-AE v=0x01 records the 7 bytes at
    # [94:101] are non-zero on 35–69 of them with full entropy (e.g.
    # 1600507d77aef0, 082a901e000000) — a "padding" region that is only zero
    # on some generations (compare 0x158C ``reserved2``).
    #
    # Surfaced RAW and UN-NAMED: F3's mc_pqme.c print covers the ASCII
    # sentence and is SILENT on this region, and the `0x60` events do not
    # ground it by value either. No invented semantic name.
    #
    # Clamped to TAIL_BLOCK_OFFSET because ``trailer_start``'s NUL-skip runs
    # to end-of-record when everything after the sentence is zero (the CC
    # case), which would otherwise slice backwards past the anchor.
    pre_tail_residue = bytes(data[min(trailer_start, TAIL_BLOCK_OFFSET):TAIL_BLOCK_OFFSET])

    return Diag0x1C7C(
        log_time=log_time,
        version=version,
        flag_high=flag_high,
        flag=flag,
        nmea_sentence=nmea_sentence,
        nmea_talker=nmea_talker,
        trailer=trailer,
        trailer_has_dead_marker=(_DEAD_MARKER in trailer),
        tail_u32=tail_u32,
        tail_byte_201=tail_byte_201,
        pre_tail_residue=pre_tail_residue,
        parsed=parsed,
    )


def _parse_0x1c7c_v2(
    log_time: int, data: bytes
) -> Diag0x1C7Cv2Sub01 | Diag0x1C7Cv2Sub03 | Diag0x1C7Cv2Sub05 | Diag0x1C7Cv2Sub05Sz229 | Diag0x1C7Cv2Sub07Tag03 | Diag0x1C7Cv2Sub07Tag09 | Diag0x1C7Cv2Sub07Tag25 | Diag0x1C7Cv2Sub09 | Diag0x1C7Cv2Report | None:
    """v=0x02: the TLV chain must close exactly, or ``None``; then a template
    decoder if one claims the record, else the generic split
    (``Diag0x1C7Cv2Report``).

    The chain check runs FIRST, ahead of the templates: they gate only on size
    and the first entry's header, so a T99W640 128 B record cut to 127 B kept
    the 127 B Sub03 template's (0x2c, 0x03, 0x37) and would otherwise parse
    as a silent truncation. Every template fixture is an exact chain.
    """
    entries = split_v2_entries(data)
    if not entries:     # broken chain, or an empty ``02 00`` (corpus minimum is 1)
        return None
    r = _parse_0x1c7c_v2_template(log_time, data)
    if r is not None:
        return r
    return Diag0x1C7Cv2Report(
        log_time=log_time,
        version=_VERSION_V2,
        n_entries=data[1],
        entries=entries,
        raw=bytes(data),
    )


def _parse_0x1c7c_v2_template(
    log_time: int, data: bytes
) -> Diag0x1C7Cv2Sub01 | Diag0x1C7Cv2Sub03 | Diag0x1C7Cv2Sub05 | Diag0x1C7Cv2Sub05Sz229 | Diag0x1C7Cv2Sub07Tag03 | Diag0x1C7Cv2Sub07Tag09 | Diag0x1C7Cv2Sub07Tag25 | Diag0x1C7Cv2Sub09 | None:
    """v=0x02 template decoders: branch on byte[1] (the "subtype").

    byte[1] is really the entry count and bytes [2:5] the first entry's
    (tag, tag_version, length); see the TLV-chain note above
    ``Diag0x1C7Cv2Entry``. Anything returned ``None`` here falls through to
    the generic chain split in ``_parse_0x1c7c_v2``.

    Decoded structurally:
      - subtype 0x01 (22B fixed)
      - subtype 0x03 (127B fixed)
      - subtype 0x05 (365B and 229B fixed)
      - subtype 0x07 / tag=0x25 (337B), tag=0x03 and tag=0x09 (364B)
      - subtype 0x09 (375B fixed)

    Every other (byte[1], size, byte[2]) packing returns ``None`` HERE and is
    then split generically (e.g. 4,665 sampled records, mostly a T99W640
    build's version-bumped tags).
    """
    if len(data) < 2:
        return None
    subtype = data[1]
    if subtype == _V2_SUB01 and len(data) == _V2_SUB01_SIZE:
        # 22B heartbeat record. Vendor signature lives at bytes 11/12/13/18;
        # everything else is invariant across the cross-vendor corpus.
        return Diag0x1C7Cv2Sub01(
            log_time=log_time,
            version=_VERSION_V2,
            subtype=subtype,
            vendor_signature=(data[11], data[12], data[13], data[18]),
            raw=bytes(data),
        )
    if subtype == _V2_SUB03 and len(data) == _V2_SUB03_SIZE:
        # 127B 2-state status record (Quectel-only at this size).
        # bytes [2:5]==(0x2c,0x03,0x37) are 100%-invariant structural anchors
        # on the single-vendor corpus — reject (rather than mis-decode) a
        # 127B sub=0x03 record that doesn't carry them, so a future format
        # drift surfaces as a no-parse miss instead of plausible-but-garbage
        # flag values.
        if any(data[o] != v for o, v in _V2_SUB03_HEADER_ANCHORS.items()):
            return None
        return Diag0x1C7Cv2Sub03(
            log_time=log_time,
            version=_VERSION_V2,
            subtype=subtype,
            header_const=(data[2], data[3], data[4]),
            state_flag_a=data[_V2_SUB03_FLAG_A_OFF],
            state_flag_b=data[_V2_SUB03_FLAG_B_OFF],
            raw=bytes(data),
        )
    if subtype == _V2_SUB05 and len(data) == _V2_SUB05_SIZE:
        # 365B 3-clock record. bytes [2:5]==(0x00,0x01,0x75) are
        # 100% cross-vendor-invariant structural anchors — reject (rather
        # than mis-decode) a 365B sub=0x05 record that doesn't carry them,
        # so a future format drift surfaces as a no-parse miss instead of
        # plausible-but-garbage clock values.
        if any(data[o] != v for o, v in _V2_SUB05_HEADER_ANCHORS.items()):
            return None
        return Diag0x1C7Cv2Sub05(
            log_time=log_time,
            version=_VERSION_V2,
            subtype=subtype,
            header_const=(data[2], data[3], data[4]),
            clock_eng_a=unpack_from('<I', data, _V2_SUB05_CLOCK_ENG_A_OFF)[0],
            clock_eng_b=unpack_from('<I', data, _V2_SUB05_CLOCK_ENG_B_OFF)[0],
            clock_vendor=unpack_from('<I', data, _V2_SUB05_CLOCK_VENDOR_OFF)[0],
            vendor_byte=data[_V2_SUB05_VENDOR_BYTE_OFF],
            raw=bytes(data),
        )
    if subtype == _V2_SUB05 and len(data) == _V2_SUB05_SZ229:
        # 229B single-clock template. bytes [2:5]==(0x27,0x01,0x2e)
        # are 100% cross-vendor-invariant structural anchors — reject (rather
        # than mis-decode) a 229B sub=0x05 record that doesn't carry them, so a
        # future format drift surfaces as a no-parse miss instead of a
        # plausible-but-garbage clock value.
        if any(data[o] != v for o, v in _V2_SUB05_SZ229_HEADER_ANCHORS.items()):
            return None
        return Diag0x1C7Cv2Sub05Sz229(
            log_time=log_time,
            version=_VERSION_V2,
            subtype=subtype,
            header_const=(data[2], data[3], data[4]),
            clock_eng=unpack_from('<I', data, _V2_SUB05_SZ229_CLOCK_ENG_OFF)[0],
            vendor_byte=data[_V2_SUB05_SZ229_VENDOR_BYTE_OFF],
            raw=bytes(data),
        )
    if subtype == _V2_SUB07 and len(data) == _V2_SUB07_TAG25_SIZE:
        # 337B/tag=0x25 GNSS-engine-clock record. sub=0x07 is a
        # multi-template family keyed on byte[2]; only the tag=0x25/337B
        # member is decoded here. A 337B sub=0x07 record whose byte[2] tag is
        # not 0x25, or which fails the [2:5]==(0x25,0x01,0x37) cross-vendor
        # anchors, hard-rejects (returns None) rather than mis-decoding; the
        # generic TLV split then handles it.
        if any(data[o] != v for o, v in _V2_SUB07_TAG25_HEADER_ANCHORS.items()):
            return None
        clock = unpack_from('<I', data, _V2_SUB07_TAG25_CLOCK_OFF)[0]
        echo1 = unpack_from('<I', data, _V2_SUB07_TAG25_CLOCK_ECHO1_OFF)[0]
        echo2 = unpack_from('<I', data, _V2_SUB07_TAG25_CLOCK_ECHO2_OFF)[0]
        # Triple-echo agreement is a structural invariant on the cross-vendor
        # corpus — disagreement means the offsets drifted or this isn't the
        # tag=0x25 layout, so reject rather than emit a wrong clock.
        if not (clock == echo1 == echo2):
            return None
        return Diag0x1C7Cv2Sub07Tag25(
            log_time=log_time,
            version=_VERSION_V2,
            subtype=subtype,
            report_tag=data[2],
            header_const=(data[2], data[3], data[4]),
            engine_clock=clock,
            engine_clock_echo1=echo1,
            engine_clock_echo2=echo2,
            raw=bytes(data),
        )
    if subtype == _V2_SUB07 and len(data) == _V2_SUB07_364_SIZE:
        # 364B sub=0x07 templates. Sub-dispatch on byte[2] report
        # tag: 0x03 (engine-clock + seq record) and 0x09 (seq record) are the
        # two attested 364B members. A 364B sub=0x07 record whose byte[2] tag
        # is neither, or which fails its (byte2,byte3,byte4) cross-vendor
        # anchors, hard-rejects (returns None) rather than mis-decoding.
        report_tag = data[2]
        if report_tag == _V2_SUB07_TAG03:
            if any(data[o] != v for o, v in _V2_SUB07_TAG03_HEADER_ANCHORS.items()):
                return None
            return Diag0x1C7Cv2Sub07Tag03(
                log_time=log_time,
                version=_VERSION_V2,
                subtype=subtype,
                report_tag=report_tag,
                header_const=(data[2], data[3], data[4]),
                engine_clock=unpack_from('<I', data, _V2_SUB07_TAG03_ENGINE_CLOCK_OFF)[0],
                record_seq=unpack_from('>I', data, _V2_SUB07_TAG03_SEQ_OFF)[0],
                seq_siblings=(
                    unpack_from('>I', data, _V2_SUB07_TAG03_SEQ_SIB1_OFF)[0],
                    unpack_from('>I', data, _V2_SUB07_TAG03_SEQ_SIB2_OFF)[0],
                ),
                raw=bytes(data),
            )
        if report_tag == _V2_SUB07_TAG09:
            if any(data[o] != v for o, v in _V2_SUB07_TAG09_HEADER_ANCHORS.items()):
                return None
            return Diag0x1C7Cv2Sub07Tag09(
                log_time=log_time,
                version=_VERSION_V2,
                subtype=subtype,
                report_tag=report_tag,
                header_const=(data[2], data[3], data[4]),
                record_seq=unpack_from('>I', data, _V2_SUB07_TAG09_SEQ_OFF)[0],
                raw=bytes(data),
            )
        return None
    if subtype == _V2_SUB09 and len(data) == _V2_SUB09_SIZE:
        # 375B clock/counter record. byte[2]==0x0E is a 100%
        # cross-vendor-invariant structural anchor — reject (rather than
        # mis-decode) a 375B sub=0x09 record that doesn't carry it, so a
        # future format drift surfaces as a no-parse miss instead of
        # plausible-but-garbage counter values.
        if data[_V2_SUB09_HEADER_B2_OFF] != _V2_SUB09_HEADER_B2:
            return None
        return Diag0x1C7Cv2Sub09(
            log_time=log_time,
            version=_VERSION_V2,
            subtype=subtype,
            header_const=(data[2], data[3], data[4]),
            seq_counter=unpack_from('<I', data, _V2_SUB09_SEQ_OFF)[0],
            seq_counter_paired=unpack_from('<I', data, _V2_SUB09_SEQ_PAIRED_OFF)[0],
            counter_c=unpack_from('<I', data, _V2_SUB09_COUNTER_C_OFF)[0],
            fine_clock=unpack_from('<I', data, _V2_SUB09_FINE_CLOCK_OFF)[0],
            vendor_signature=(data[_V2_SUB09_VENDOR_SIG_OFF],
                              data[_V2_SUB09_VENDOR_SIG_OFF + 1]),
            raw=bytes(data),
        )
    return None
