"""0x1843 — 141-entry USTMR-timestamped event log (catalogue name "GNSS ME GAL E6").

Every record is a 4-byte header plus a **fixed array of 141 time-ordered event
entries** (28 B = seven u32le words each). Each entry is an 8-byte descriptor,
two optional u32 USTMR argument words, a **22-bit USTMR timestamp**, and an
optional 8-byte debug sentinel. Consecutive records are **consecutive chunks of one event
stream**: record N+1's first entry follows record N's last one. The array is
not a per-SV measurement table (see "Not a per-SV Galileo E6 table" below).

## Layout (corpus-verified, F3-grounded)

```
+0:  u8    version          = 0x01 (corpus-invariant, 773,138/773,138 records)
+1:  u8    record_id_byte   = 0x8d (corpus-invariant, 773,138/773,138 records)
+2:  u16le header_state     low-cardinality per-record state (raw; see below)
+4:  141 × 28 B event entries   (4 + 141 × 28 = 3952 B exactly)
```

### Event entry (28 B = seven u32le words w0..w6)

```
w0,w1  +0..+7  : 8 × u8  descriptor d0..d7     raw; semantics open (see below)
w2     +8..+11 : u32     aux_ustmr_a            0, or a USTMR target (low 22 bits)
w3     +12..+15: u32     aux_ustmr_b            0, or a USTMR target (low 22 bits)
w4     +16..+19: u32     bits 21:0 = ustmr_lo22 (event time = USTMR[21:0]);
                          bits 31:22 reserved = 0
w5,w6  +20..+27: 8 B     trailer: all-zero OR the debug sentinel
                          ``21 43 34 12 ca db cd ab`` (u32le 0x12344321,
                          0xABCDDBCA). Binary across the corpus: slot 0 shows
                          333,324 zero / 9,635 sentinel, never anything else.
```

One entry in the corpus (an LM960 drive capture, record 1742, entry 71 of
141, descriptor ``05 01 00 02 1e 00 02 00``) carries only the **first**
sentinel word (``21 43 34 12 00 00 00 00``), with ``aux_ustmr_a`` set
(low-22 lead +901 ticks) and ``aux_ustmr_b`` = 0. It is not the newest entry,
so it is not a flush race at the log head. The cause is unexplained (a torn
entry is a CANDIDATE). The parser flags it ``sentinel_partial`` and counts it
in ``sentinel_partial_count``. Only this exact form is accepted.

The parser's ``reserved_nonzero_count`` counts entries whose w4 top bits or
trailer break this layout. It is declared ``∈ {0}`` and checked by the
whole-corpus walk.

**`ustmr_lo22` is the low 22 bits of the 19.2 MHz USTMR (it wraps every
218.45 ms). Measurements:**

- **F3 anchor.** An EM9190 (SDX55) GNSS-acquisition capture carries ``gts.c:1266 USTMR@FCount … `` F3 latches. Their USTMR argument
  advances at **19,198,522 Hz** (p50 over 365 distinct latches, 251 s) against
  the DIAG header timestamp. Predicting USTMR at each 0x1843 record's DIAG time
  and subtracting the record's newest entry puts **134/141** records in 3 of
  16 bins around zero, where a uniform null expects ~26. The spread
  (≈ ±17 ms) is the latch's own FCount-to-print jitter.
- **Direct DIAG-timestamp test (no F3 needed, sub-ms).** The DIAG header
  timestamp ticks on the same USTMR, so
  ``(diag_ts × 19.2 MHz − ustmr_lo22[140]) mod 2²²`` has a median of
  **5,421 ticks (0.28 ms)**, and **83%** of 698 EM9190 records fall within
  ±5 ms. Entry 0 and entry 70 are uniform (a record spans many 218 ms wraps).
  Entry **140 is the newest event**, flushed ≈0.3 ms after it occurred.
  Repeated on other silicon; see the "Cross-chipset" table below.
- **The record chain.** Record N+1's entry 0 follows record N's entry 140
  (``18a70c → 18add7``, ``28282f → 282a30``, ``2f3fcc → 2f4239``). Zero
  28-byte entries repeat between consecutive records (reuse 0.0%). The log is
  streamed chunk by chunk, not snapshotted.
- **Intra-record order.** Of adjacent steps, 97.3% move forward mod 2²²
  (EM9190, 98,418 entries). The backward steps are short interleavings
  between event sources.

**`aux_ustmr_a` / `aux_ustmr_b` carry a USTMR target time in their low 22
bits.** Where non-zero (a minority of entries on LM960, SIM8202G, RM520N-GL,
EM9291, RM500Q, FN980 and similar), the low 22 bits equal the entry's own
``ustmr_lo22`` plus a small positive lead. On the LM960 fixture the two words
are identical, and the lead is +916..941 ticks (47.7–49.0 µs, n=18) for
``01 01 00 02 12 …`` and +1510..1520 ticks (78.6–79.2 µs, n=17) for
``03 01 00 02 1d …``. The sentinel trailer rides on the same entries. On
RM520N-GL (SDX62, ``d3=0x04 d4=0x06`` entries) the leads are deterministic per
``d0``: ``0x41`` gives exactly (+146, +2208) ticks on a/b (4/4 inspected), and
``0x42`` gives (+42..79, +43..81) (4/4). The upper 10 bits
carry an epoch/carry field (e.g. ``0x00ff…``, ``0x0100…``, ``0xffff…``) that
changes when the value crosses a 2²⁴ or sign boundary near the 2²² wrap.
That carry field can make an entry look like a separate "signed pair" type;
it is not. The upper bits are exposed raw inside the u32. The reading as a
scheduled-for time alongside a logged-at time is flagged CANDIDATE.

### Descriptor d0..d7 — raw, semantics OPEN

Low cardinality: 267 distinct descriptors over 98,418 EM9190 entries.
``d7`` is 0 on most parts. The T99W640 sets its bits 7:6 (``0x40`` /
``0x80`` / ``0xc0``).
``d3`` takes 5 values there (0x85, 0x04, 0x07, 0x89, 0x06) and ~20 across the
corpus. The 0x80 bit of ``d3`` splits two families. A ``(d3=0x85, d1=0x1c)``
family cycles ``d2`` through fixed groups of four (e.g. {0x23, 0x51, 0x52,
0x71}) while ``d0`` toggles between 0x00 and 0x80. On the LM960, ``d5`` is a
5-bit rolling sequence number shared across event types. These are
**scheduler/resource-event descriptors, not satellite IDs.** They are exposed
as raw bytes and nothing is named that F3 did not name.

The "active slot" marker ``85 40 00 01`` is simply the descriptor bytes
``d3..d6`` of one event family. ``active_slot_count`` / ``decode_slots`` are
kept for backward compatibility as a count and filter of that one
descriptor pattern.

### Header-state field (bytes [+2:+4]) — raw

Over 773,138 records, 97.8% are ``0x0000``. Discrete non-zero states include
``0xd80d``, ``0xd80b``, ``0xd816``, ``0xff00``, ``0xff01``, ``0xc002``, plus
newer values (``0x636c``, ``0x25e2``, ``0x6e5f``, ``0x6675``, ``0x7420``,
``0x3839``, from pcap/kismet-ingested captures). The field varies within one
capture around GNSS/modem state transitions. It is exposed raw.

## Not a per-SV Galileo E6 table

The array is not 141 per-SV slots: the u24 at +16 is not a
C/N0-or-integrator measurement and ``d2`` is not an encoded PRN. **F3 rules
that reading out:**

- The "measurement" is a timestamp (above). It rises monotonically along the
  array and wraps at 2²², which no per-SV quantity would do.
- **Temporal join on the EM9190 capture** (19,599 events placed on the DIAG
  clock, ±1 ms window, time-shift null at ±2/3/5 s to cancel burstiness):
  every GNSS-ME F3 site sits at **lift ≈ 1.0** (``cc_islandstm_uimage.c``,
  ``cc_msg_uimage.c``, ``gpsfft_spansrchcore.c``, ``mc_jobmanager.c``,
  ``cc_dp_uimage.c``). Every event class instead locks to the modem's
  sleep and resource scheduler in self-describing ``0x79`` plaintext:
  ``lte_LL1_macrosleep_sched.c`` (hit 26–46% vs null 4–7%, lift 4–12),
  ``lte_LL1_resource_mgr.c VFW_RES_ALLOC`` (lift 17–42), and
  ``nrfw_res_mgr.c RES_MGR clock query`` (lift ~4).
- This is consistent with independent observations. The code emits at an
  identical rate with Galileo enabled or disabled, emits with no GNSS antenna
  (MC7411), and emits on the MDM9250 C-V2X parts.

The code name ``LOG_GNSS_ME_GAL_E6`` (``codes.py``) is kept as a catalogue
label only. It carries no content claim, and the parser emits no
constellation / band labels.

## Cross-chipset (v4 layout)

The same 4 + 141 × 28 shape, with ``+7/+11/+15/+19`` = 0, u22 top bits = 0,
and a binary trailer, holds on every family in the corpus (sidecar offset
histograms, slots 0–1, 902 captures / 342,959 records): MDM9x07 (EG25-G,
EG18-NA, EP06, EG12, EG95), SDX20 (LM960), SDX55 (EM9190, EM7511, FN980,
RM500Q, T99W175, SIM8202G, M2000), SDX62 (RM520N-GL), SDX65 (EM9291), MDM9650
(MC7411), MDM9x30 (MC7455), and MDM9150-class (81UMV91B1).

The USTMR rate lock on other silicon uses entry 140 vs the DIAG
timestamp mod 2²². The offset is constant per capture: 0 on the EM9190, a
capture-specific epoch offset elsewhere. Concentration that holds across a
whole capture proves a 19.2 MHz lock. Entry 70 is the null control:

| family (capture) | n | entry 140 within ±5 ms | entry 70 (null) |
|---|--:|--:|--:|
| SDX55 EM9190 (GNSS acquisition) | 698 | 0.83 | uniform |
| MDM9x07 EG25-G (F3 validation) | 130 | 0.90 | 0.03 |
| SDX20 LM960 (drive) | 266 | 0.95 | 0.18 |
| SDX55 T99W175 (GNSS comparison) | 113 | 0.97 | 0.25 |
| SDX55 SIM8202G (drive) | 240 | 0.92 | 0.07 |
| MDM9650 MC7411 (warm GNSS restart) | 91 | 0.99 | 0.38 |
| SDX62 RM520N-GL (F3 validation, LTE) | 448 | 0.99 | 0.83 — weak null |
| MDM9150-class 81UMV91B1 (C-V2X channel) | 140 | 1.00 | 1.00 — non-discriminating |

On the last two, the records are so periodic that the control locks as well.
They are consistent with the layout but not independent evidence for it.

## Test fixtures

One record each from Sierra EM9190 (SDX55), Telit LM960 (SDX20; aux words +
sentinel), Quectel EG25-G (MDM9x07) and Quectel RM520N-GL (SDX62).

## Legacy fields

``time_counter_a`` / ``time_counter_b`` (bytes [4:8] / [8:12]) are entry 0's
descriptor bytes and ``aux_ustmr_a``, not header timestamps. They are kept for
backward compatibility.

Log name: LOG_EVENTS_DS_GPRS_MAC_MSG_RECEIVED
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_ME_GAL_E6
from diaggrok.registry import register


HEADER_BYTES = 4              # +0 version, +1 record_id 0x8d, +2:+4 u16le header_state
SLOT_STRIDE = 28              # one event entry
SLOT_COUNT = 141              # (3952 - 4) / 28 = 141 exactly
RECORD_SIZE = HEADER_BYTES + SLOT_COUNT * SLOT_STRIDE  # 3952

# Legacy: the descriptor bytes d3..d6 of ONE event family (was "active marker").
ACTIVE_SLOT_MARKER = b'\x85\x40\x00\x01'
ACTIVE_MARKER_OFFSET = 3

USTMR_HZ = 19_200_000         # USTMR tick rate (F3 gts.c latch: 19,198,522 Hz p50)
USTMR_LO22_MASK = 0x3FFFFF    # entry timestamp width — wraps every 218.45 ms
TRAILER_SENTINEL = bytes.fromhex('21433412cadbcdab')  # u32le 0x12344321, 0xABCDDBCA
# First sentinel word only (seen once corpus-wide, LM960; see docstring).
TRAILER_SENTINEL_PARTIAL = TRAILER_SENTINEL[:4] + bytes(4)

# Layer-1 version gate (773,138/773,138 corpus records have data[0]=0x01).
_EXPECTED_VERSION = 0x01


def _count_active_slots(data: bytes) -> int:
    """Count entries whose d3..d6 equal the legacy ``85 40 00 01`` pattern."""
    count = 0
    for i in range(SLOT_COUNT):
        marker_start = HEADER_BYTES + i * SLOT_STRIDE + ACTIVE_MARKER_OFFSET
        if marker_start + 4 > len(data):
            break
        if data[marker_start:marker_start + 4] == ACTIVE_SLOT_MARKER:
            count += 1
    return count


def _decode_event(slot: bytes) -> dict[str, Any]:
    """Decode one 28-byte event entry = seven u32le words (layout in the docstring)."""
    w0, w1, w2, w3, w4, w5, w6 = unpack_from('<7I', slot, 0)
    trailer = slot[20:28]
    return {
        'descriptor': slot[0:8].hex(),
        'd0': slot[0], 'd1': slot[1], 'd2': slot[2], 'd3': slot[3],
        'd4': slot[4], 'd5': slot[5], 'd6': slot[6], 'd7': slot[7],
        'aux_ustmr_a': w2,
        'aux_ustmr_b': w3,
        'ustmr_lo22': w4 & USTMR_LO22_MASK,
        'sentinel': trailer == TRAILER_SENTINEL,
        'sentinel_partial': trailer == TRAILER_SENTINEL_PARTIAL,
        # Anything outside the documented layout surfaces here, not silently.
        'reserved_nonzero': bool(
            (w4 & ~USTMR_LO22_MASK)
            or (any(trailer) and trailer not in (TRAILER_SENTINEL, TRAILER_SENTINEL_PARTIAL))
        ),
    }


def decode_events(data: bytes) -> list[dict[str, Any]]:
    """All 141 event entries of a 0x1843 payload, oldest-first (entry 140 newest)."""
    out: list[dict[str, Any]] = []
    for i in range(SLOT_COUNT):
        start = HEADER_BYTES + i * SLOT_STRIDE
        if start + SLOT_STRIDE > len(data):
            break
        ev = _decode_event(data[start:start + SLOT_STRIDE])
        ev['index'] = i
        out.append(ev)
    return out


def decode_slots(data: bytes) -> list[dict[str, Any]]:
    """LEGACY API: entries matching the ``85 40 00 01`` descriptor family.

    Keys keep their original names for compatibility. ``measurement_24`` is the
    entry's USTMR timestamp and ``sv_id_or_state`` is descriptor byte d2, which
    is **not** a satellite ID (see the module docstring). Prefer ``decode_events``.
    """
    out: list[dict[str, Any]] = []
    for i in range(SLOT_COUNT):
        slot_start = HEADER_BYTES + i * SLOT_STRIDE
        if slot_start + SLOT_STRIDE > len(data):
            break
        slot = data[slot_start:slot_start + SLOT_STRIDE]
        if slot[ACTIVE_MARKER_OFFSET:ACTIVE_MARKER_OFFSET + 4] != ACTIVE_SLOT_MARKER:
            continue
        out.append({
            'slot_index': i,
            'slot_flag': slot[0],
            'sv_id_or_state': slot[2],
            'measurement_24': slot[16] | (slot[17] << 8) | (slot[18] << 16),
        })
    return out


@dataclass
class Diag0x1843:
    """0x1843 USTMR-timestamped 141-entry event log (catalogue "GNSS ME GAL E6").

    See the module docstring for the entry layout and the F3 grounding.
    ``events`` holds all 141 decoded entries, oldest-first.
    """
    log_time: int
    version: int
    record_id: int            # byte +1, corpus-invariant 0x8d
    header_state: int         # u16le bytes [+2:+4], raw
    header_marker: int        # bytes [0:4] as u32 (legacy; = version | id<<8 | state<<16)
    time_counter_a: int       # LEGACY: u32 at +4 = entry 0 descriptor d0..d3
    time_counter_b: int       # LEGACY: u32 at +8 = entry 0 aux_ustmr_a (+ reserved byte)
    payload_size: int
    slot_count: int           # 141 event entries
    slot_stride: int          # 28
    active_slot_count: int    # LEGACY: entries whose d3..d6 == 85 40 00 01
    newest_ustmr_lo22: int    # entry 140's timestamp (≈0.3 ms before the DIAG record time)
    sentinel_count: int       # entries carrying the 0x12344321/0xABCDDBCA trailer
    sentinel_partial_count: int  # entries carrying only the first sentinel word (n=1 corpus-wide)
    reserved_nonzero_count: int  # entries violating the reserved-zero layout (expect 0)
    events: list[dict[str, Any]] = field(default_factory=list)
    raw: bytes = b''

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1843',
            'log_time': self.log_time,
            'version': self.version,
            'record_id': self.record_id,
            'header_state': self.header_state,
            'header_marker': self.header_marker,
            'time_counter_a': self.time_counter_a,
            'time_counter_b': self.time_counter_b,
            'payload_size': self.payload_size,
            'slot_count': self.slot_count,
            'slot_stride': self.slot_stride,
            'active_slot_count': self.active_slot_count,
            'newest_ustmr_lo22': self.newest_ustmr_lo22,
            'sentinel_count': self.sentinel_count,
            'sentinel_partial_count': self.sentinel_partial_count,
            'reserved_nonzero_count': self.reserved_nonzero_count,
            'events': self.events,
            'parser_status': 'decoded',
            'parser_note': (
                '141 USTMR-timestamped event entries (ustmr_lo22 F3-grounded); '
                'descriptor d0..d6 raw — semantics open'
            ),
        }


@register(
    LOG_GNSS_ME_GAL_E6, domain="gnss",
    name="0x1843",
    description=(
        "141-entry USTMR-timestamped event log (catalogue name GNSS ME GAL E6; "
        "F3 refutes per-SV E6 content) — descriptors raw"
    ),
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full entry decode. Each of the "
        "141 × 28 B entries is seven u32le words: an 8-byte descriptor (raw), two "
        "u32 aux USTMR-target words, a word whose low 22 bits are the USTMR "
        "timestamp (bits 31:22 = 0), and an 8-byte trailer (zero or the "
        "0x12344321/0xABCDDBCA sentinel). reserved_nonzero_count ∈ {0} is "
        "checked by the whole-corpus walk. The timestamp is "
        "grounded as USTMR[21:0] by the F3 gts.c:1266 USTMR latch (19.2 MHz vs "
        "the DIAG clock; 134/141 records within 3/16 bins, null ~26) and by the "
        "direct DIAG-timestamp test (entry 140 median 0.28 ms before the record, "
        "83% within ±5 ms, n=698 EM9190). Temporal F3 join: GNSS-ME sites lift "
        "≈1.0, while LTE macrosleep / VFW resource-manager plaintext locks at "
        "lift 4–42, so the array is not a per-SV Galileo-E6 measurement table. "
        "Byte-0 version gate + enum invariant. The descriptor bytes and the "
        "header_state field remain undecoded."
    ),
    source_url="",
    # Parsed = identified: version, record_id, header_state, header_marker,
    # time_counter_a/b (legacy aliases), payload_size, slot_count, slot_stride,
    # active_slot_count (legacy), newest_ustmr_lo22, sentinel_count, sentinel_partial_count,
    # reserved_nonzero_count, and per-entry events (d0..d6 raw, aux_ustmr_a/b,
    # ustmr_lo22, sentinel). Every byte of the 3952 B record is assigned.
    fields_parsed=16,
    fields_identified=16,
    issues=(),
    field_invariants={
        "version": {"enum": [_EXPECTED_VERSION]},
        "record_id": {"enum": [0x8d]},
        "reserved_nonzero_count": {"enum": [0]},
    },
)
def parse_0x1843(log_time: int, data: bytes) -> Diag0x1843 | None:
    """Parse a 0x1843 record (layout in the module docstring).

    Layer-1 version gate: ``data[0]`` must be 0x01 and the record must be the
    full 3952 B. The 22 corpus records of other lengths are all from
    pcap/kismet ingests (HDLC misframe), so they are rejected rather than
    decoded into a truncated event array.
    """
    if len(data) < 12:
        return None
    if data[0] != _EXPECTED_VERSION:
        return None
    if len(data) != RECORD_SIZE:
        return None
    events = decode_events(data)
    return Diag0x1843(
        log_time=log_time,
        version=data[0],
        record_id=data[1],
        header_state=unpack_from('<H', data, 2)[0],
        header_marker=unpack_from('<I', data, 0)[0],
        time_counter_a=unpack_from('<I', data, 4)[0],
        time_counter_b=unpack_from('<I', data, 8)[0],
        payload_size=len(data),
        slot_count=SLOT_COUNT,
        slot_stride=SLOT_STRIDE,
        active_slot_count=_count_active_slots(data),
        newest_ustmr_lo22=events[-1]['ustmr_lo22'],
        sentinel_count=sum(e['sentinel'] for e in events),
        sentinel_partial_count=sum(e['sentinel_partial'] for e in events),
        reserved_nonzero_count=sum(e['reserved_nonzero'] for e in events),
        events=events,
        raw=bytes(data),
    )
