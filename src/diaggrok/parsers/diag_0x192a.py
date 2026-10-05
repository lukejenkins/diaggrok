"""0x192A — LOG_LTE_RF_FED_RX_AGC (RF front-end Rx AGC), 3016/3036B fixed record.

Size gate: only 3016 and 3036 B are layouts, checked by an inline
``len(data) not in (3016, 3036)`` guard. Every reject — off-size or
non-v0x02 — is classified, counted (:func:`misframe_counts`) and logged on the
1st/10th/100th hit per kind, at ERROR for ``unrecognised``; any one off-size
recurring 100 times in a run is an ERROR too (a layout recurs, a misframe does
not: corpus max 28). The classes are measured on every off-size corpus record
(459 walked, 0 unrecognised): see ``_MISFRAMES``.

Body decode. The record is one fixed C struct whose layout depends on the
record size (both sizes are v0x02):

==================  =============  ==============  ===========================
region              3016 B (LTE)   3036 B (NR)     content
==================  =============  ==============  ===========================
header              [0:12]         [0:12]          version u8 (=0x02);
                                                   ``hdr_byte1`` u8 (=1, raw);
                                                   [2:8] zero;
                                                   ``chain_valid`` u8[4] at
                                                   [8:12] (1 = chain k valid)
slot table          [12:412] x20   [12:572] x28    20 B slots, ALWAYS the init
                                                   sentinels u16 0xFA,0xFB,
                                                   0xFC,0, u32 0, u32 0xFD,
                                                   u32 0 (18,573/18,573
                                                   records verified)
chain entries       [412:492] x4   [572:652] x4    20 B each (below)
after the chains    [492:812]      [652:1132]      LTE: zero. NR: STALE MEMORY
                                                   (firmware addresses
                                                   0xC9xxxxxx/0xC0xxxxxx, 0xF8
                                                   fill, string fragments;
                                                   differs per chipset) —
                                                   exposed as
                                                   ``stale_region``, NOT fields
summary             [812:852] x4   [1132:1172] x4  10 B each: int32, int32,
                                                   u16 index — a packed copy
                                                   of each chain's first 8 B
zero pad            [852:3015]     [1172:3035]     zero
trailer byte        [3015]         [3035]          u8, raw (0/1/2/3/128/255/…)
==================  =============  ==============  ===========================

``chain_valid[k]`` gates chain k. Measured: every chain with flag 1 is a
well-formed entry (ref ~10.4/11.7 dB); with flag 0 the entry is all-zero
(LM960), a stale repeat of an earlier record (SIM8202), or garbage (EM120R-GL).
Most firmware fills chains 0-1 (``01 01 00 00``); EG12-GT and the
Inseego M2000 fill all four (``01 01 01 01``) and their summaries list all
four indices.

Chain entry (20 B, ``<iiiiHH``), all values signed Q8.24 dB:

  - ``value_q24``  — populated on every valid chain. Observed -58 .. +37 dB
    (FN980 C-V2X captures reach +34). **CANDIDATE** RX-AGC gain/level.
  - ``value2_q24`` — 0x7FFFFFFF (unset) on many records; otherwise a second
    dB value.
  - ``value3_q24`` — a third dB value. Its unset/init form is exactly
    ``ref - 127 dB`` (LM960, SDX55, T77W968) or exactly -127.000 dB
    (0x81000000: MC7411, EM7511, EM7565, FM101-GL). Those exact 127<<24 offsets
    are what pin the Q8.24 scaling.
  - ``ref_q24``    — 10.42 dB on SDX55-class parts, 11.72-11.79 dB on
    MDM9x40/SWI9X50C-class parts (not constant within a capture). CANDIDATE
    calibration reference.
  - ``index`` u16 — per-chain id (0..34 observed; e.g. LM960 1/0, RM500Q
    2/1, MC7411 7/6, M2000 33/34). It follows the RF configuration, not the
    band number: the LV55 band-lock sweep (16 LTE bands) gives 5 pairs —
    (18,17) b12/13/14/25/26/29, (13,14) b2, (12,11) b30, (21,22)
    b38/41/46/48/66/71, (2,1) b5. CANDIDATE RF path/device id.
    ``flag`` u16 — raw (0/1/2/4/5/6/7 seen).

0x7FFFFFFF decodes to ``None`` in the ``*_db`` helpers, never to +128 dB.
An all-zero chain reports ``empty: True``.

Corpus verification: 18,573 v0x02 records (65 captures,
one per module/session directory, <=300 records each, plus the 16-capture
LV55 band sweep): 0 exceptions, 0 layout rejects; slot table all-sentinel and
padding all-zero 18,573/18,573; 34,096 valid chains, ref 10-12 dB on 34,096;
summary == chains 17,529/18,573 (the rest are MC7411-style snapshots). The
walk-free size census: 3016 B x 1,889,672 (200 captures), 3036 B x
1,043,841 (276); 467 v0x02 records at ~410 other sizes are misframes and are
rejected, never guessed at (classified in v6: corrupt / nested_frame /
tail_truncated / head_truncated).

F3 (in-capture oracle): the only RX-AGC F3 sites co-emitted with v0x02 are
``rfe_nr5g_sub6_rxagc.c:900/:997`` on RM500Q-AE (20,248 records,
notch/spur-frequency prints: ``freq_khz``, ``spur_freq_khz``) and
``rflm_cmn_rxagc*.c`` on LM960 (task-skip / API-fail prints). Both confirm the
SUBSYSTEM and are SILENT on the chain values, so the dB semantics stay
CANDIDATE and the raw int32 ships alongside. QCSuper and SCAT do not decode
0x192A.

Naming: the fixed 3016/3036 B size and periodic cadence rule out a
variable-length RRC OTA container (the legacy ``LteRrcReconfig192A`` name);
the only named source is ``LOG_LTE_RF_FED_RX_AGC``.

Version census: v0x02 is the only version. Every other byte0 (0x00, 0x04,
0x24, 0x2C, 0x3C, 0x54, 0x84, 0x9C, 0xEC and ~35 more) is size-4 HDLC
tail-fragment residue, with ONE exception: a 2247 B ``byte0=0x00`` record in
a stress-test capture, which is the tail of a 3036 B record whose first
789 B were lost (aligned that way, its 71 non-zero bytes fall in the stale
region and summary and none in the zero pad; the 3016 alignment puts 70 in
the pad). It is why a version census reads "v0x00 x442" (441 residue + 1):
that byte0 is a padding zero, not a version. ``classify_misframe`` reports it
as ``head_truncated_3036``.

Log name: LOG_LTE_RF_FED_RX_AGC
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

logger = logging.getLogger(__name__)

_LTE_SIZE = 3016
_NR_SIZE = 3036
# size -> (slot_count, chain_offset, summary_offset)
_LAYOUTS = {
    _LTE_SIZE: (20, 412, 812),   # LTE-only silicon (MDM9x40, SWI9X50C)
    _NR_SIZE: (28, 572, 1132),   # NR-capable silicon (SDX55)
}
_SLOT_SIZE = 20
_SLOT_DEFAULT = bytes.fromhex("fa00fb00fc00000000000000fd00000000000000")
_CHAIN_FMT = "<iiiiHH"
_CHAIN_SIZE = 20
_SUMMARY_SIZE = 10
_N_CHAINS = 4  # header bytes [8:12] are the per-chain valid flags
_Q24_UNSET = 0x7FFFFFFF
_HEADER_PREFIX = b"\x02\x01"
_RESIDUE_MAX = 4  # size<=4 payloads are HDLC tail-fragment residue

# ── the size gate's loud channel ─────────────────────────────────────────────
# Only 3016 and 3036 are layouts. Every other payload is rejected, classified,
# counted and logged instead of silently dropped. Measured on every off-size
# record in the 12 captures whose sidecars attest one:
#   corrupt          325  v0x02 header, then a byte that breaks the layout (a
#                         must-be-sentinel slot or must-be-zero pad). Many are
#                         the head of one record + the tail of another, which
#                         per record is indistinguishable from a new layout
#                         sharing that head and tail; recurrence separates
#                         them (below)
#   nested_frame      69  a whole 3016/3036 record behind a second 0x192A log
#                         header (``10 00 LL LL LL LL 2a 19``), e.g. 3055 B
#                         = 3 stray + 16 header + 3036
#   tail_truncated    64  a strict prefix of a layout, every byte consistent
#   head_truncated     1  the tail of a 3036 record, first 789 B lost. byte0
#                         is then a padding zero: this is the corpus's only
#                         non-residue "v0x00" (2247 B, a stress-test capture)
#   unrecognised       0  no v0x02 header and no layout alignment -> ERROR
#   unknown_version    0  exactly 3016/3036 B but byte0 != 0x02 -> ERROR
# A layout RECURS at its size (3016 x1.89M, 3036 x1.04M records); no off-size
# reaches 30 records in the whole 2.9M-record corpus (max 2524 B x28). So the
# first time any one off-size reaches _RECURRING in a run, that is logged at
# ERROR as a possible new layout, whatever its per-record kind.
_RECURRING = 100
_ERROR_KINDS = ("unrecognised", "unknown_version")
_MISFRAMES: Counter[str] = Counter()
_OFF_SIZES: Counter[int] = Counter()


def misframe_counts() -> dict[str, int]:
    """Per-kind count of 0x192A payloads the gate rejected this run."""
    return dict(_MISFRAMES)


def misframe_sizes() -> dict[int, int]:
    """Per-size count of the non-residue rejects this run (the recurrence view)."""
    return dict(_OFF_SIZES)


def reset_misframe_counts() -> None:
    """Clear both counters (tests, or a sweep that reports per run)."""
    _MISFRAMES.clear()
    _OFF_SIZES.clear()


def _nested_layout(data: bytes) -> int | None:
    """Layout size of a whole record behind an embedded 0x192A log header."""
    i = data.find(b"\x2a\x19")
    while i >= 6:
        if data[i - 6:i - 4] == b"\x10\x00" and data[i - 4:i - 2] == data[i - 2:i]:
            inner = unpack_from("<H", data, i - 4)[0] - 12  # minus the 12 B log header
            if inner in _LAYOUTS:
                return inner
        i = data.find(b"\x2a\x19", i + 1)
    return None


def _first_foreign(data: bytes, size: int) -> int | None:
    """First offset where ``data`` breaks layout ``size``'s must-be-sentinel or
    must-be-zero bytes (or runs past its end); None if consistent throughout."""
    slot_count, chain_off, summ_off = _LAYOUTS[size]
    n = len(data)
    if any(data[2:8]):
        return 2
    for k in range(slot_count):
        off = 12 + k * _SLOT_SIZE
        if off >= n:
            return None
        got = data[off:min(off + _SLOT_SIZE, n)]
        if got != _SLOT_DEFAULT[:len(got)]:
            return off
    zero = [(summ_off + _N_CHAINS * _SUMMARY_SIZE, size - 1)]
    if size == _LTE_SIZE:
        zero.insert(0, (chain_off + _N_CHAINS * _CHAIN_SIZE, summ_off))
    for a, b in zero:
        for i in range(a, min(b, n)):
            if data[i]:
                return i
    return size if n > size else None


def classify_misframe(data: bytes) -> str:
    """Why a non-3016/3036 (or non-v0x02) payload is not a 0x192A record."""
    n = len(data)
    if n <= _RESIDUE_MAX:
        return "residue"
    if n in _LAYOUTS:
        return "unknown_version"    # a layout's size, not v0x02: a NEW VERSION?
    inner = _nested_layout(data)
    if inner is not None:
        return f"nested_frame_{inner}"
    if data[:2] == _HEADER_PREFIX:
        # The 21st slot is a sentinel only in the 28-slot NR table.
        size = _NR_SIZE if data[412:432] == _SLOT_DEFAULT else _LTE_SIZE
        if n < size and _first_foreign(data, size) is None:
            return f"tail_truncated_{size}"
        return "corrupt"
    for size, (_sc, _co, summ_off) in _LAYOUTS.items():
        # Align as the tail of `size`: its zero pad must be clean, its head not.
        a = max(summ_off + _N_CHAINS * _SUMMARY_SIZE - (size - n), 0)
        if n < size and n - 1 > a and not any(data[a:n - 1]) and any(data[:a]):
            return f"head_truncated_{size}"
    return "unrecognised"


def _alarm(data: bytes) -> None:
    kind = classify_misframe(data)
    _MISFRAMES[kind] += 1
    if kind == "residue":
        return          # counted; size-4 residue is in nearly every capture
    size = len(data)
    _OFF_SIZES[size] += 1
    if _OFF_SIZES[size] == _RECURRING:
        logger.error(
            "diaggrok 0x192A: %d records at %d B this run — no off-size recurs "
            "like this in the corpus (max 28); a NEW LAYOUT, not a misframe? "
            "", _RECURRING, size,
        )
    n = _MISFRAMES[kind]
    if str(n).rstrip("0") != "1":   # log the 1st, 10th, 100th, ... per kind
        return
    logger.log(
        logging.ERROR if kind in _ERROR_KINDS else logging.WARNING,
        "diaggrok 0x192A size/version gate #%d [%s] len=%d head=%s — not a "
        "3016/3036 B v0x02 record",
        n, kind, size, data[:16].hex(" "),
    )


def _q24_db(raw: int) -> float | None:
    """Signed Q8.24 -> dB; the 0x7FFFFFFF unset sentinel -> None."""
    if raw == _Q24_UNSET:
        return None
    return round(raw / (1 << 24), 3)


@dataclass
class RxAgcChain:
    """One 20 B chain entry (``<iiiiHH``); ``valid`` is header byte 8+k."""
    valid: bool
    value_q24: int
    value2_q24: int
    value3_q24: int
    ref_q24: int
    index: int
    flag: int

    @property
    def empty(self) -> bool:
        """All-zero entry: no chain in this position (seen on EG12/EM7565)."""
        return not (self.value_q24 or self.value2_q24 or self.value3_q24
                    or self.ref_q24 or self.index or self.flag)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "index": self.index,
            "flag": self.flag,
            "empty": self.empty,
            "value_q24": self.value_q24,
            "value_db": _q24_db(self.value_q24),
            "value2_q24": self.value2_q24,
            "value2_db": _q24_db(self.value2_q24),
            "value3_q24": self.value3_q24,
            "value3_db": _q24_db(self.value3_q24),
            "ref_q24": self.ref_q24,
            "ref_db": _q24_db(self.ref_q24),
        }


@dataclass
class RxAgcSummary:
    """One 10 B summary entry: packed copy of a chain's first 8 B + index."""
    value_q24: int
    value2_q24: int
    index: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "value_q24": self.value_q24,
            "value_db": _q24_db(self.value_q24),
            "value2_q24": self.value2_q24,
            "value2_db": _q24_db(self.value2_q24),
        }


@dataclass
class Diag0x192A:
    """0x192A — RF Rx-AGC record (LOG_LTE_RF_FED_RX_AGC, 3016/3036B fixed)."""
    log_time: int
    version: int
    payload_size: int
    layout: str
    hdr_byte1: int
    chain_valid: list[int]
    slot_count: int
    slots_all_default: bool
    nondefault_slots: dict[int, bytes]
    chains: list[RxAgcChain]
    summary: list[RxAgcSummary]
    summary_matches_chains: bool
    trailer_byte: int
    padding_all_zero: bool
    stale_region: bytes = field(default=b"")

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x192A",
            "log_time": self.log_time,
            "version": self.version,
            "payload_size": self.payload_size,
            "layout": self.layout,
            "hdr_byte1": self.hdr_byte1,
            "chain_valid": self.chain_valid,
            "slot_count": self.slot_count,
            "slots_all_default": self.slots_all_default,
            "nondefault_slots": {i: b.hex() for i, b in self.nondefault_slots.items()},
            "chains": [c.to_dict() for c in self.chains],
            "summary": [e.to_dict() for e in self.summary],
            "summary_matches_chains": self.summary_matches_chains,
            "trailer_byte": self.trailer_byte,
            "padding_all_zero": self.padding_all_zero,
            "stale_region_len": len(self.stale_region),
            "stale_region": self.stale_region,
        }


@register(
    0x192A,
    name="0x192A",
    description=(
        "0x192A — LOG_LTE_RF_FED_RX_AGC (RF Rx AGC), 3016B/3036B fixed record: "
        "header + 4 chain-valid flags, sentinel slot table, 4 Q8.24 Rx-AGC chain entries, summary"
    ),
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from FN980m SDX55, extended across MDM9x40, SWI9X50C, "
        "SDX55 and later silicon. version=0x02 at sizes 3016 or 3036; size=4 "
        "outliers are HDLC framing residue. Name: LOG_LTE_RF_FED_RX_AGC (an "
        "RRC-reconfig reading is ruled out by the fixed size and cadence). "
        "Body: size-keyed layout (20/28 sentinel slots, 4 chain entries of 4 x "
        "Q8.24 int32 + index + flag gated by header valid flags [8:12], "
        "4-entry packed summary), NR-variant stale-memory region surfaced as "
        "non-field bytes; Q8.24 pinned by the exact ref-127 dB unset floor "
        "across MDM9x40, SWI9X50C and SDX55. F3 (rxagc sites) confirms the "
        "subsystem, silent on values. Exact size gate; every off-size / "
        "non-v0x02 reject is classified (corrupt / nested_frame / "
        "tail_truncated / head_truncated / unrecognised), counted and logged; "
        "ERROR on unrecognised and on any off-size recurring 100x in a run "
        "(corpus max 28). 459 off-size corpus records walked, 0 unrecognised; "
        "the only non-residue v0x00 is a head-truncated 3036 B tail."
    ),
    issues=(),
    primary_issue=None,  # canonical primary tracker
    field_invariants={
        "version": {"enum": [0x02]},
        "payload_size": {"enum": [3016, 3036]},
    },
    fields_identified=15,
    fields_parsed=15,
)
def parse_0x192a(log_time: int, data: bytes) -> Diag0x192A | None:
    if len(data) < 1:
        return None
    # Layer-1 version gate. Rejects the size=4 HDLC framing residue and any
    # future non-v0x02 emission, loudly.
    if data[0] != 0x02:
        _alarm(data)
        return None
    # Exact size gate, written inline so the static size audit sees it.
    # Every off-size corpus record is a classified misframe (see _MISFRAMES).
    size = len(data)
    if size not in (3016, 3036):
        _alarm(data)
        return None     # the registry also fires its own WARN + tally

    slot_count, chain_off, summ_off = _LAYOUTS[size]

    nondefault: dict[int, bytes] = {}
    for i in range(slot_count):
        off = 12 + i * _SLOT_SIZE
        slot = data[off:off + _SLOT_SIZE]
        if slot != _SLOT_DEFAULT:
            nondefault[i] = bytes(slot)

    chain_valid = list(data[8:8 + _N_CHAINS])
    chains = [
        RxAgcChain(chain_valid[j] == 1,
                   *unpack_from(_CHAIN_FMT, data, chain_off + j * _CHAIN_SIZE))
        for j in range(_N_CHAINS)
    ]
    summary = []
    for j in range(_N_CHAINS):
        off = summ_off + j * _SUMMARY_SIZE
        v, v2 = unpack_from("<ii", data, off)
        (idx,) = unpack_from("<H", data, off + 8)
        summary.append(RxAgcSummary(v, v2, idx))
    summary_matches = all(
        (s.value_q24, s.value2_q24, s.index) == (c.value_q24, c.value2_q24, c.index)
        for s, c in zip(summary, chains) if c.valid
    )

    gap_start = chain_off + _N_CHAINS * _CHAIN_SIZE
    summ_end = summ_off + _N_CHAINS * _SUMMARY_SIZE
    if size == 3036:
        stale = bytes(data[gap_start:summ_off])
        pad_regions = [data[summ_end:size - 1]]
    else:
        stale = b""
        pad_regions = [data[gap_start:summ_off], data[summ_end:size - 1]]
    padding_zero = not any(any(r) for r in pad_regions)

    return Diag0x192A(
        log_time=log_time,
        version=data[0],
        payload_size=size,
        layout="nr_3036" if size == 3036 else "lte_3016",
        hdr_byte1=data[1],
        chain_valid=chain_valid,
        slot_count=slot_count,
        slots_all_default=not nondefault,
        nondefault_slots=nondefault,
        chains=chains,
        summary=summary,
        summary_matches_chains=summary_matches,
        trailer_byte=data[size - 1],
        padding_all_zero=padding_zero,
        stale_region=stale,
    )
