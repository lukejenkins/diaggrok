"""NR5G ML1 Beam Measurement parser (0xB8FF).

Per-SSB-beam NR5G measurements carrying the serving PCI. The 2944 B
format is 8 beam blocks × 368 bytes; two compact formats carry one beam.

Version v0x01 is the only version observed (102,854 records / 135
captures), but it carries three formats, told apart by (size, byte_2):

    | size   | byte_2 | records | silicon                          | layout          |
    |--------|--------|---------|----------------------------------|-----------------|
    | 2944 B | 0      | ~67.0K  | SDX55: RM500Q-AE, Compal, SIM8202G, M2000 | 8 × 368 B beam blocks |
    | 420 B  | 2      | ~24.9K  | SDX55: Sierra EM9190, FT980m     | compact_420_r2  |
    | 480 B  | 3      | ~6.9K   | SDX62: RM520N-GL, Inseego M3100  | compact_480_r3  |

(byte_2 for 2944 B is from two fixtures only; the 420/480 B values
were checked on every record of 6 captures.)
(22 one-off sizes 95..5395 B, all from one kismet stress capture, are HDLC
misframes. They, and any unseen (size, byte_2) pair, return None: byte_2 is
a hidden format revision, so an unlisted pair is surfaced loudly by the
dispatch WARN rather than decoded with the wrong offsets.)

The compact formats hold one beam struct that is the 368 B block shifted
+8 bytes: the ``0x2f`` byte at +50→+58, PCI at +56→+64, ``word_58`` at
+58→+66, ``meas_word`` at +64→+72. Only PCI is decoded there; the rest of
the body is kept in ``body_raw``.

Compact-format PCI grounding:

- **480 B (SDX62):** an Inseego M3100 capture with full F3 resolution.
  ``gts.c:2769`` — the same ``Proc NR5G ... PCI %u %lu`` format as
  ``gts.c:2660``, at a different line in this build — prints PCI 746,
  NR-ARFCN 647328; u16@+64 == 746 in **4,221/4,221** co-temporal records
  (5,843 total). SCAT independently decodes ``NR-ARFCN 647328, SCell PCI
  746``. The capture is single-cell (no handover), so the cross-capture
  spread backs it up: RM520N-GL captures carry 455 and 596.
- **420 B (SDX55-Sierra):** the EM9190 drive captures carry no F3, so SCAT
  is the reference. On one EM9190 drive the run-length PCI sequence of
  u16@+64 over 2,176 records is identical to SCAT's NR serving-PCI
  sequence on NR-ARFCN 521310 — 11 cells / 10 handovers, in order
  (642→260→487→557→238→488→141→713→104→354→658). A second drive matches
  too (6 steps, incl. a 260→69→260 return), apart from SCAT's leading
  65535 invalid-cell sentinel before the first record.
- The NR-ARFCN printed by F3 / decoded by SCAT does not appear as a u32
  anywhere in the record (F3-silent): no ARFCN field is named.
- ``word_58`` analogue (u16@+66): == PCI + 1008 on every SDX62 480 B
  record, 0 on every EM9190 420 B record. Raw; semantics undecoded.
- ``meas_word`` analogue (u32@+72): not the constant ``0x3f3f`` filler on
  SDX62 (e.g. 0x4b43443f, 0x4944433f) — the filler finding below is
  SDX55-scoped. Raw; no oracle names it.

Per-beam block layout (368 bytes):
    [0:4]   u32  marker (0x00000001 across every observed beam block)
    [4:8]   u32  block_id (SSB beam identifier, increments by 0x4000)
    [8:36]  28B  config/timing data
    [36:56] 20B  measurement config
    [56:58] u16  PCI (PhysCellId, 0..1007) — F3-grounded (see below)
    [58:60] u16  word_58 — per-capture constant, semantics undecoded
    [60:64] u32  reserved
    [64:68] u32  meas_word — raw, semantics undecoded (see the RSRP note)
    [68:368] 300B per-beam measurement body (undecoded)

F3 grounding — ``gts.c:2660`` prints the serving PCI outright::

    "Proc NR5G. Sub %u Val %u %u BS %u TA %ld PCI %u %lu QT 0x%lx%08lx"

On a Compal RXM-G1 drive capture (full F3 resolution, 4,194 × 2944 B
records) the F3 stream reports exactly six distinct PCIs over the drive —
{69, 238, 240, 260, 557, 642} — and ``u16@+56`` of beam block 0
reproduces that set **exactly, with no extra values, in 4,164/4,164
co-temporally-matched records (100%)**. This is a varying, multi-cell
oracle, which is what makes it a real validation.

PCI is u16, not u32. On RM500Q-AE ``u16@+58`` is 0 in all 62,408 observed
beam blocks, so a little-endian u32 at +56 happens to equal the u16 PCI
there. On Compal RXM-G1 ``u16@+58`` is 1248, so a u32 read yields
``1248<<16 | 260 == 81,789,188``, which fails the ``pci <= 1007`` sanity
guard and drops every beam. Reading +56 as u16 is correct on every
observed chipset.

This parser decodes no RSRP. ``rsrp = (meas_word & 0x3FF) * 0.0625 - 156``
looks plausible against a single AT reading (-104.1 dBm) but is an
artifact of filler:

- ``meas_word`` takes only three values across the whole corpus — ``0x0``,
  ``0x18413f3f``, ``0x18423f3f``. Both non-zero forms share the low bytes
  ``0x3f3f``, so ``& 0x3FF`` is always ``0x33F`` (831) and the formula
  always yields -104.1 dBm — on every record, every beam, every chipset.
- Agreement with an AT reading of -104 dBm is therefore coincidence. The
  identical -104.1 appears on Compal RXM-G1 in a different city months
  apart — a real RSRP cannot be bit-identical across chipsets, locations
  and dates.
- No F3 site in any 0xB8FF-bearing capture prints an NR5G RSRP, so there
  is no oracle to derive a real RSRP offset from. ``meas_word`` is kept
  raw and unnamed rather than guessed.

Reverse-engineered from RM500Q-AE (SDX55) live captures; PCI grounded
against Compal RXM-G1 F3; compact-format PCI grounded against M3100 F3 +
SCAT and EM9190 SCAT.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_BLOCK_SIZE = 368
_NUM_BEAMS = 8  # 8 × 368 = 2944

# (size, byte_2) -> format_layout: the only payloads this parser decodes.
# byte_2 is the hidden format revision inside v0x01; anything not listed
# returns None (surfaced loudly by the dispatch WARN). See the module
# docstring for the corpus-wide counts.
_LAYOUTS = {
    (2944, 0): "beams_8x368",  # SDX55: RM500Q-AE, Compal, SIM8202G, M2000
    (420, 2): "compact_420_r2",  # Sierra EM9190 (SDX55), FT980m
    (480, 3): "compact_480_r3",  # SDX62: Quectel RM520N-GL, Inseego M3100
}
# Compact beam struct = the 2944 B block shifted +8: PCI@+64, word_58
# analogue @+66, meas_word analogue @+72.
_COMPACT_PCI_OFF = 64


@dataclass
class Nr5gBeamEntry:
    """A single SSB beam block.

    ``pci`` is the only semantically-decoded field — F3-ground-truthed
    against ``gts.c:2660`` (see the module docstring). ``word_58`` and
    ``meas_word`` are exposed raw with offset-derived names because their
    semantics are undecoded; naming them would be a guess.

    There is deliberately no ``rsrp`` field: the candidate RSRP formula
    on ``meas_word`` decodes a constant ``0x3f3f`` filler and yields
    -104.1 dBm unconditionally. See the module docstring.
    """

    beam_index: int
    block_id: int | None  # None on the compact formats (no grounded analogue)
    pci: int
    word_58: int  # u16@+58, per-capture constant, semantics undecoded
    meas_word: int  # u32@+64, raw; only 3 values corpus-wide, undecoded
    has_data: bool  # True when measurement body is non-zero

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "beam_index": self.beam_index,
            "block_id": self.block_id,
            "pci": self.pci,
            "word_58": self.word_58,
            "meas_word": self.meas_word,
            "has_data": self.has_data,
        }
        return d


@dataclass
class Diag0xB8FF:
    """NR5G ML1 Beam Measurement (0xB8FF).

    Three corpus formats share version byte 0x01 but differ in layout:

    - **8 × 368-byte beam blocks** (2944 B total) — the RM500Q-AE SDX55
      format this parser was reverse-engineered against. ``beams`` is
      populated.
    - **420 B / 480 B compact formats** (``compact_420_r2`` — EM9190/FT980m
      SDX55; ``compact_480_r3`` — SDX62 RM520N-GL / M3100) — one beam
      struct shifted +8 bytes, so PCI is u16@+64. ``beams`` holds that
      single entry; the rest of the body stays in ``body_raw``.
    - any other ``(size, byte_2)`` → the parser returns ``None`` (loud:
      the dispatch WARN and unhandled tally fire), never a raw stub.

    ``format_layout`` names which path was taken so downstream consumers
    don't confuse an empty beam list on the 2944 B format (all beams idle)
    with an unparsed record.
    """

    log_time: int
    version: int
    num_active_beams: int
    payload_size: int
    beams: list[Nr5gBeamEntry] = field(default_factory=list)
    format_layout: str = "beams_8x368"
    body_raw: str | None = None
    byte_2: int | None = None  # raw; discriminates formats (0 / 2 / 3), semantics undecoded

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB8FF",
            "log_time": self.log_time,
            "version": self.version,
            "num_active_beams": self.num_active_beams,
            "payload_size": self.payload_size,
            "beams": [b.to_dict() for b in self.beams],
            "format_layout": self.format_layout,
            "body_raw": self.body_raw,
            "byte_2": self.byte_2,
        }


@register(
    0xB8FF,
    name="0xB8FF",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge",),
    issues=(),
    description="Per-SSB-beam NR5G blocks with ground-truthed serving PCI on all three v0x01 formats: 2944B (8×368B, PCI u16@+56, F3 gts.c:2660 4164/4164 Compal), 420B compact (PCI u16@+64, SCAT 11-step handover sequence exact, EM9190), 480B compact (PCI u16@+64, F3 gts.c:2769 4221/4221 + SCAT, SDX62 M3100). No RSRP.",
    version=5,
    author="Claude Code",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Reverse-engineered from SDX55 (RM500Q-AE) live captures. PCI is u16, F3-grounded against Compal RXM-G1 gts.c:2660 (4164/4164 co-temporal match, 6 distinct PCIs); compact 420B/480B PCI@+64 grounded by SCAT run-length handover sequences on 2 EM9190 drives and by F3 gts.c:2769 + SCAT on M3100. No RSRP is decoded: the only RSRP-like formula reads a constant filler pattern. The rest of the beam body is undecoded.",
    source_url="https://github.com/lukejenkins",
    # byte-0 is the DIAG log version, corpus-attested invariantly 0x01
    # (n=87075, size>4). Gated below because size invariance is not format
    # invariance.
    field_invariants={"version": {"enum": [0x01]}},
)
def parse_0xb8ff(
    log_time: int, data: bytes
) -> Diag0xB8FF | None:
    """Parse 0xB8FF — NR5G ML1 Beam Measurement.

    2944 B: 8 SSB beam blocks × 368 bytes, PCI u16 at block+56.
    420 B / 480 B: one compact beam struct, PCI u16 at +64.
    No RSRP anywhere — see the module docstring.
    """
    if len(data) < 4:
        return None

    version = data[0]
    # Layer-1 version gate (corpus byte-0 invariantly 0x01).
    if version != 0x01:
        return None

    # Hidden-version gate. byte_0 is 0x01 on all three formats, so it does
    # not pin the layout; byte_2 is the hidden format revision (0 / 2 / 3),
    # and the size alone is not trusted either (size invariance is not
    # format invariance). Only the grounded (size, byte_2) pairs decode.
    # Any other pair — a new revision, a new size, an HDLC misframe —
    # returns None so the dispatch WARN and unhandled tally fire instead of
    # a silent raw stub.
    layout = _LAYOUTS.get((len(data), data[2]))
    if layout is None:
        return None

    if layout != "beams_8x368":
        # Compact formats: one beam struct shifted +8 vs the 2944 B block,
        # so PCI sits at u16@+64. Grounded per format — see the module
        # docstring. The rest of the body is undecoded and stays in body_raw.
        pci = unpack_from("<H", data, _COMPACT_PCI_OFF)[0]
        compact_beams: list[Nr5gBeamEntry] = []
        if pci <= 1007:
            compact_beams.append(
                Nr5gBeamEntry(
                    beam_index=0,
                    block_id=None,
                    pci=pci,
                    word_58=unpack_from("<H", data, _COMPACT_PCI_OFF + 2)[0],
                    meas_word=unpack_from("<I", data, _COMPACT_PCI_OFF + 8)[0],
                    has_data=True,
                )
            )
        return Diag0xB8FF(
            log_time=log_time,
            version=version,
            num_active_beams=len(compact_beams),
            payload_size=len(data),
            beams=compact_beams,
            format_layout=layout,
            # The rest of the compact body is undecoded; keep it raw.
            body_raw=data.hex(),
            byte_2=data[2],
        )

    num_beams = min(_NUM_BEAMS, len(data) // _BLOCK_SIZE)

    beams: list[Nr5gBeamEntry] = []
    num_active = 0

    for i in range(num_beams):
        base = i * _BLOCK_SIZE
        if base + 68 > len(data):
            break

        marker = unpack_from("<I", data, base)[0]
        block_id = unpack_from("<I", data, base + 4)[0]

        # Check if beam has measurement data (non-zero beyond header)
        has_data = any(b != 0 for b in data[base + 8 : base + min(_BLOCK_SIZE, len(data) - base)])

        # PCI is u16 (F3-grounded). A u32 read would merge the unrelated
        # u16 at +58 into the high half; on any chipset where +58 != 0
        # (e.g. Compal RXM-G1, word_58=1248) that yields
        # 1248<<16|pci == 81,789,188, which the <=1007 guard below drops,
        # silently emitting zero beams for the whole capture.
        pci = unpack_from("<H", data, base + 56)[0]
        word_58 = unpack_from("<H", data, base + 58)[0]
        meas_word = unpack_from("<I", data, base + 64)[0]

        if has_data and pci <= 1007:
            num_active += 1
            beams.append(
                Nr5gBeamEntry(
                    beam_index=i,
                    block_id=block_id,
                    pci=pci,
                    word_58=word_58,
                    meas_word=meas_word,
                    has_data=True,
                )
            )

    return Diag0xB8FF(
        log_time=log_time,
        version=version,
        num_active_beams=num_active,
        payload_size=len(data),
        beams=beams,
        byte_2=data[2],
    )
