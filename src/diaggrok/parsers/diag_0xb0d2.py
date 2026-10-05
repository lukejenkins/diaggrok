"""0xB0D2 — LTE/NR5G signalling (TBD) — first-observation recognition parser.

The log name is unconfirmed (the only name-table entry is ``RESERVED``).
Observed on Telit FN980m, Quectel RM520N-GL (SDX62), Quectel RM500Q-AE
(SDX55) and Sierra EM9291 — 33 records across 20 captures, every one
**exactly 3142 B** with ``u32[0] == 0x20``.

## Structure

The payload is a **pre-sized slot array** of 10 fixed-stride blocks, each
framed by a ``0xFFFFFFFF`` sentinel:

    offset 0      : u32  lead_word   (invariant 0x00000020)
    offset 4      : block[0]   (303 B)
    offset 307    : block[1]   (303 B)
    ...
    offset 2428   : block[8]   (303 B)
    offset 2731   : block[9]   (411 B — wider tail block)

    each block k : u32  slot_tag        (offset 4 + 303*k)
                   u32  sentinel         (offset 8 + 303*k, == 0xFFFFFFFF)
                   body (295 B for k<9, 403 B for k==9)

The ten sentinels land at fixed offsets
``{8, 311, 614, 917, 1220, 1523, 1826, 2129, 2432, 2735}`` — byte-for-byte
identical across every record and vendor. That fixed sentinel tuple is a
far stronger recognition fingerprint than the size gate alone: a foreign
3142 B record would have to place ``0xFFFFFFFF`` at all ten exact offsets to
false-match. It is the Layer-1 structural gate.

Cross-vendor byte-invariance (10 records): **11.4 % of bytes are constant**
(358/3142 — the sentinels + framing + zero padding); the rest is data.

* The ``slot_tag`` u32 (offset ``4 + 303*k``) is **0x00000000 in every record**
  — it is the zero-padded tail word of the *previous* block, not a meaningful
  per-slot tag. The field is surfaced for completeness but carries no signal.
* **All 10 blocks are populated in every record** (per-block body_nonzero is
  always ≥ 1). What varies is per-block *density* — block bodies range from a
  single nonzero byte up to ~276 (block 9, the wide tail, runs 108..380). This
  is a per-index table that is always fully framed; the *fill*, not the slot
  membership, differs per capture.
* **Every block carries a 12-byte all-zero reserved head**: across 9 records /
  2 vendors (FN980m + RM520N-GL), no record places a nonzero byte before
  block-relative offset 12 in any of the 10 blocks. The per-block layout is
  therefore:

       each block k : u32  slot_tag   (== 0; prev block's tail word)
                      u32  sentinel    (== 0xFFFFFFFF)
                      12 B reserved    (== 0x00…, block-relative body [0:12])
                      data region      (283 B for k<9, 391 B for k==9)

  i.e. the per-block **data region begins at record offset 24 + 303*k**
  (= body offset 12). The recognition parser surfaces the whole body
  (including the 12-byte head) in each slot's ``body_hex``.
* **The 303 B block stride is not u32-aligned** (303 mod 4 = 3): the
  sentinels cycle through 4 alignment phases, realigning only every 4 blocks.
  Record-global u32/u16 reads therefore straddle misaligned block phases; any
  field decode must work in block-relative coordinates.
* Each block's data region shows a recurring shape: a sparse ~80-byte head
  region followed by a denser ~200-byte region (block 9 wider). Block bodies
  are structured **integers** (float32 reads are garbage).
* **Block 9's tail (~bytes 3032..3142) is a constant incrementing byte ramp**
  ``00 01 02 03 04 05 …``, byte-identical across records — a fixed
  enumeration / index pattern, not per-capture data.

## Timing and content

* **Exact 300.0 s periodicity**, on two vendors / three firmware builds
  (FN980m, RM520N-GL ×2): consecutive records are exactly 300.0 s apart —
  a precise 5-minute timer, not per-fix / per-TTI / event-driven.
* **No accumulating counters**: no monotonically increasing field at u32,
  u16 or block-relative-u16 alignment across a 6-record sequence, so this is
  not a statistics counter table. Fields fluctuate (gauge/measurement-like or
  bit-packed).
* **Variable occupancy**: per-block fill density changes at the fixed cadence
  (e.g. block 5 dense from body offset 12 in one record, data only near
  offset 58 in a later one). Roughly 90 % of body bytes vary across a
  5-record sequence.

## What it is not

* **Not a serving-cell identity / signalling record.** On a stationary FN980m
  capture with a paired AT poll (``AT#RFSTS``/``#SERVINFO``, one LTE cell for
  the whole run), none of the serving-cell EARFCN, PCI, TAC, 32-bit Cell ID or
  RSRP integers appear in any of the 6 records in any byte order. On a moving
  RM520N-GL drive capture (9 distinct LTE cells, paired ``AT+QENG`` poll), none
  of the 9 cell IDs or the EARFCN appear in any of the 5 records. The 32-bit
  cell ID is the decisive probe.
* **Not GNSS positions.** The same drive capture's NMEA shows no fix for the
  whole run, yet every block is densely populated and varying.

Every attested capture is a GNSS-comparison or drive run, but variation that
tracks neither GNSS position nor serving-cell identity points to an **RF /
radio-measurement table** (neighbour/beam RSRP/RSRQ/AGC-shaped per carrier or
antenna) as the leading hypothesis. Unconfirmed.

## F3

Two captures carry fully resolvable QSR4 F3 (RM500Q-AE with 1 record,
RM520N-GL with 3). F3 does not cleanly label the fields:

  (a) In the RM500Q capture (a GNSS all-mask run) the co-temporal F3 is
      dominated by GPS-correlator files, but baseline-normalized those sit at
      ratio ~1.0–1.2. The only baseline-enriched file is ``rflte_mc_rx.c`` at
      **2.0×** (LTE RF-Rx) — a weak nudge toward the RF-measurement hypothesis,
      not actionable at N=1.
  (b) In the RM520N-GL capture the ±2 ms co-temporal F3 carries **both**
      ``lte_rrc_stm.c`` (LTE RRC SM active) **and** a dense GPS
      slot/resource-manager burst (``cc_slicer.c:8747`` per-constellation task
      counts) — an ambiguous context, not a single-subsystem attribution.
  (c) Byte-literal field correlation over the 3142 B payload × co-temporal F3
      args explodes the candidate set (>3 M even at ±0.1 s); LTE-RF-narrowed
      correlation (47 samples, N=3) yields **0** hypotheses at conf≥0.6.
      Fields are encoded/sparse, not byte-literal.

The multi-epoch captures have no resolvable F3, while the F3-resolvable
captures have too few epochs. Naming the populated columns needs a capture
with ≥6 0xB0D2 epochs (≥30 min at the 300 s cadence), resolvable F3, and
per-epoch neighbour-measurement ground truth (``AT+QENG`` neighbour rows or a
co-captured ML1 measurement log).

## Version gating

Size invariance != format invariance. byte-0 is the **low byte of the
constant u32 ``lead_word`` (0x00000020)**, not a DIAG version. ``lead_word``
is hard-gated in the body together with the 10 sentinel checks and the fixed
3142 B size — a discriminant strictly stronger than a byte-0 gate. A
``field_invariants["version"]={enum:[0x20]}`` would be semantically false, so
the parser is declared ``version_less=True`` (same pattern as 0x197F: low byte
of a constant u32 state word). The slot array is surfaced verbatim; semantic
naming awaits correlation.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_PAYLOAD_SIZE = 3142
_LEAD_WORD = 0x20            # u32[0]; invariant across 3 vendors
_SENTINEL = 0xFFFFFFFF
_N_SLOTS = 10
_BLOCK_STRIDE = 303
# Sentinel u32 offsets — fixed, byte-for-byte identical across every record.
_SENTINEL_OFFSETS = tuple(8 + _BLOCK_STRIDE * k for k in range(_N_SLOTS))


@dataclass
class Diag0xB0D2:
    """0xB0D2 LTE/NR5G signalling first-observation record.

    A 10-slot sentinel-framed array. ``slots`` carries one entry per block,
    each exposing the raw body verbatim (recognition only — no field decode).
    """
    log_time: int
    lead_word: int
    slot_count: int
    sentinels_ok: bool
    slots: tuple[dict[str, Any], ...]
    populated_slot_indices: tuple[int, ...]
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0xB0D2',
            'log_time': self.log_time,
            'lead_word': self.lead_word,
            'slot_count': self.slot_count,
            'sentinels_ok': self.sentinels_ok,
            'slots': [dict(s) for s in self.slots],
            'populated_slot_indices': list(self.populated_slot_indices),
            'payload_size': self.payload_size,
        }


@register(0xB0D2,
    name="0xB0D2",
    description="LTE/NR5G signalling 0xB0D2 -- fixed 3142B, u32[0]=0x20, 10x sentinel-framed (0xFFFFFFFF) slot array; recognition only",
    version=2, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "First-observation recognition parser from cross-vendor captures: FN980m (Telit), "
        "RM520N-GL (Quectel SDX62), RM500Q-AE (Quectel SDX55), EM9291 (Sierra). All "
        "records 3142B, u32[0]=0x20. Payload is a pre-sized array of 10 blocks, each "
        "framed by a 0xFFFFFFFF sentinel at a fixed offset (stride 303). Slot bodies "
        "surfaced verbatim. Version-less: byte-0 is the low byte of the constant u32 "
        "lead_word (0x20), already gated; not a DIAG version. Serving-cell identity and "
        "GNSS-position readings are excluded by AT/NMEA correlation; field semantics "
        "remain undecoded."
    ),
    issues=(),
    field_invariants={
        "lead_word": {"enum": [_LEAD_WORD]},
        "payload_size": {"enum": [_PAYLOAD_SIZE]},
    },
    # byte-0 is the low byte of the constant u32 lead_word (0x20), already
    # gated via `lead_word != _LEAD_WORD: return None` (+ sentinels + size) —
    # NOT a DIAG version. A byte-0 `version` enum would be semantically false
    # and add no protection. See the byte-0 RE note in the module docstring.
    version_less=True,
)
def parse_0xb0d2(log_time: int, data: bytes) -> Diag0xB0D2 | None:
    # Layer-1 size gate -- single attested size class across 3 vendors.
    if len(data) != _PAYLOAD_SIZE:
        return None
    # Layer-1 lead-word gate -- reject unknown framing before decode.
    lead_word = unpack_from('<I', data, 0)[0]
    if lead_word != _LEAD_WORD:
        return None
    # Layer-1 structural gate: all ten sentinels at their fixed offsets.
    sentinels_ok = all(
        unpack_from('<I', data, off)[0] == _SENTINEL for off in _SENTINEL_OFFSETS
    )
    if not sentinels_ok:
        return None

    slots: list[dict[str, Any]] = []
    populated: list[int] = []
    for k, sent_off in enumerate(_SENTINEL_OFFSETS):
        slot_tag = unpack_from('<I', data, sent_off - 4)[0]
        body_start = sent_off + 4
        body_end = _SENTINEL_OFFSETS[k + 1] - 4 if k + 1 < _N_SLOTS else _PAYLOAD_SIZE
        body = data[body_start:body_end]
        nonzero = sum(1 for b in body if b)
        if nonzero:
            populated.append(k)
        slots.append({
            'index': k,
            'slot_tag': slot_tag,
            'body_offset': body_start,
            'body_len': len(body),
            'body_nonzero': nonzero,
            'populated': bool(nonzero),
            'body_hex': body.hex(),
        })

    return Diag0xB0D2(
        log_time=log_time,
        lead_word=lead_word,
        slot_count=_N_SLOTS,
        sentinels_ok=sentinels_ok,
        slots=tuple(slots),
        populated_slot_indices=tuple(populated),
        payload_size=len(data),
    )
