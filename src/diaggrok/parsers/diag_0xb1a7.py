"""0xB1A7 — LTE ML1 timestamped event ring-buffer dump (legacy `LteMacB1A7`).

One version byte, v0x10, on every one of 422,918 records in 482 captures,
from MDM9200 (MC7700) to SDX72 (T99W640). The code is a flush of an
up-to-200-slot ring of timestamped ML1 events.

Record layout (16-byte header + ``num_entries`` x ``entry_size`` entries)::

    [0]      u8   version         0x10 (corpus-invariant)
    [1]      u8   header_marker   0x01 (corpus-invariant, 422,918/422,918)
    [2]      u8   num_entries     10 / 100 / 1 (a 200 full-ring flush is seen too)
    [3]      u8   first_idx       ring slot of entries[0]    (0..199)
    [4]      u8   last_idx        ring slot of entries[-1]   (0..199)
    [5:10]   5B   header_reserved all-zero across the corpus (exposed raw)
    [10:12]  u16  entry_size      stride: 28 / 32 / 36 / 40, or 364..404 for a
                                  single type-0x13 snapshot entry
    [12:16]  u32  sclk_timestamp  32.768 kHz sleep-clock time of the flush
    [16:]    num_entries x entry_size

    payload_size == 16 + num_entries * entry_size       (the SIZE LAW)
    (first_idx + num_entries - 1) % 200 == last_idx     (the RING LAW)

One exception to the size law: the R562L5 variable snapshot.
The Orbic R562L5 (SDX62) flushes a single type-0x13 snapshot
whose header says ``num_entries=1, entry_size=404`` (law: 420 B) but whose
length is::

    payload_size == 132 + 404 * (u8@128 + u8@129 + u8@130 + u8@131)

    [16:128]   snapshot head (entry type 0x13, marker 0x1b, sfn, sclk, body)
    [128:132]  4 x u8   snapshot_counts   (per-kind item counts; kinds unknown)
    [132:]     sum(counts) x 8 B snapshot_items, then zero padding to 404 B/item

Measured on all 45 off-law records in the three R562L5 captures:
the length law and the all-zero padding hold on every one. The padding looks
like a log length computed with the wrong element size, but that is a guess.
The counts and items are exposed raw; their meaning is not decoded. A record
that breaks both laws (or carries non-zero padding) returns None, loudly.

Every entry opens with the same 8-byte head::

    [0]    u8   entry_type      2 / 4 / 5 / 9 / 0x0f / 0x11 / 0x12 / 0x13 / ...
    [1]    u8   entry_marker    per-firmware-lineage constant (0x01 MC7700,
                                0x03 EG95, 0x10 EG25/LE910C4, 0x19 EP06,
                                0x1a SDX20..SDX62, 0x1b T99W640). Not a
                                version: the layout is keyed on entry_size.
    [2:4]  u16  sfn_subframe    LTE absolute subframe number = SFN*10+subframe,
                                0..10239; 0xFFFF = no LTE timing
    [4:8]  u32  sclk_timestamp  same 32.768 kHz clock as the header's

and a type-specific body (``body_raw`` = entry[8:], always exposed in full).
Type-2 entries name the cell the event concerns, at offsets that depend on the
entry-size family:

    entry_size  tag        pci        earfcn
    28          —          u16 @12    u16 @14    (MDM9200: pre-EARFCN-ext)
    32 / 40     u16 @8     u16 @16    u32 @20
    36          u16 @12    u16 @20    u32 @24    (+4B word @8 in this lineage)

``pci == 0xFFFF`` means no cell is attached; ``earfcn`` can still be set then.

GROUNDING (all measured on the capture corpus):
  * SIZE LAW + RING LAW: 100% of the ~17,400 records walked in 22 captures
    across 16 modem models, and a header census of all 482 captures agrees
    (every (size, byte2, byte10/11) triple satisfies the size law).
  * sclk_timestamp: header u32@12 advances 32,764..32,768 ticks/s against the
    DIAG log clock on all 10 chipsets checked, which makes it the 32.768 kHz
    sleep clock.
  * sfn_subframe — F3 GROUND: on the EM7455 all-diag capture, 240/240
    ``lte_ml1_sm_idle.c:1532 "... current subfn: %d ..."`` prints and 137/137
    ``lte_ml1_pos_timexfer.c:267 "... Sfn %u"`` prints agree with the entry
    counter projected to the F3 timestamp to within ±2 subframes (median 0).
    The exact printed value is present in the ring in 240/240 cases.
  * pci / earfcn — log-oracle GROUND, plus F3: time-aligned against the
    independent serving-cell codes 0xB193 / 0xB0C0 (±3 s) over 22 captures,
    including 5 multi-cell wardrives: PCI 19,832 match / 703 differ, and EARFCN
    30,105 / 333. Every differing pair is a coherent real cell (for example
    158/5035 while camped on 242/66786), so the fields name the cell the event
    concerns, which is usually but not always the serving cell. The u32 EARFCN
    reads 66786 (band 66) where a u16 cannot. On LE910C4, the
    ``lte_ml1_mgr_stm.c:22151 "... mgr_db_earfcn %d"`` F3 print (5110) matches
    the co-temporal type-2 entry 3/3 where that entry carries a cell.

NOT decoded (raw, never invented-named): the meaning of entry_type values, the
``tag`` values (they behave like message ids: 0x17/0x18/0x69 always carry a
cell, while 0x40/0x43 never do), the 4-byte word at @8 of 36-byte entries, and
the whole body of the type-0x13 snapshot. QCSuper emits nothing for this
code (it produces RRC/NAS PCAP frames only).

Size invariance ≠ format invariance: the entry-size families above are
the ones in the corpus today. A new firmware can ship a new per-entry layout
under the same version byte, so an unknown ``entry_size`` still decodes the
common 8-byte head but leaves ``tag`` / ``pci`` / ``earfcn`` as None.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# Corpus-wide observation (exhaustive census, 422,918 records / 482
# captures): byte-0 invariantly 0x10 and byte-1 invariantly 0x01, across 22
# payload sizes 48..6416 B. Size is genuinely variable, so it is not gated.
_B1A7_VERSION_OBSERVED = 0x10
_B1A7_HEADER_MARKER = 0x01

_HEADER_BYTES = 16
_ENTRY_HEAD_BYTES = 8
# Ring depth implied by first_idx/last_idx (both span exactly 0..199). It is
# documentation only; nothing is gated on it.
RING_SLOTS = 200
ENTRY_TYPE_CELL = 0x02
ENTRY_TYPE_SNAPSHOT = 0x13

# R562L5 variable snapshot: 132 + 404 * sum(u8 counts @128..131).
_VAR_SNAP_ENTRY_SIZE = 404
_VAR_SNAP_COUNTS = 128
_VAR_SNAP_ITEMS = 132
_VAR_SNAP_ITEM_BYTES = 8

# entry_size -> (tag offset | None, pci offset, earfcn offset, earfcn struct fmt)
_CELL_LAYOUT: dict[int, tuple[int | None, int, int, str]] = {
    28: (None, 12, 14, "<H"),
    32: (8, 16, 20, "<I"),
    36: (12, 20, 24, "<I"),
    40: (8, 16, 20, "<I"),
}


@dataclass
class Diag0xB1A7Entry:
    """One ring entry: the common 8-byte head plus the raw type-specific body."""

    entry_type: int
    entry_marker: int
    sfn_subframe: int
    sclk_timestamp: int
    body_raw: bytes
    tag: int | None = None
    pci: int | None = None
    earfcn: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_type": self.entry_type,
            "entry_marker": self.entry_marker,
            "sfn_subframe": self.sfn_subframe,
            "sclk_timestamp": self.sclk_timestamp,
            "tag": self.tag,
            "pci": self.pci,
            "earfcn": self.earfcn,
            "body_raw": self.body_raw,
        }


@dataclass
class Diag0xB1A7:
    """0xB1A7 — LTE ML1 event ring-buffer flush (legacy `LteMacB1A7`)."""
    log_time: int
    version: int
    header_marker: int
    num_entries: int
    first_idx: int
    last_idx: int
    header_reserved: bytes
    entry_size: int
    sclk_timestamp: int
    data_density: float
    payload_size: int
    body_raw: bytes
    # Always set on a returned record: a record that breaks
    # the size law and is not the R562L5 variable snapshot returns None
    # (registry WARN), so there is no header-only form left.
    entries: list[Diag0xB1A7Entry] | None = None
    # R562L5 variable snapshot only (None otherwise): the four u8 item counts
    # at [128:132] and the sum(counts) x 8 B items at [132:].
    snapshot_counts: tuple[int, int, int, int] | None = None
    snapshot_items: list[bytes] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "Diag0xB1A7",
            "log_time": self.log_time,
            "version": self.version,
            "header_marker": self.header_marker,
            "num_entries": self.num_entries,
            "first_idx": self.first_idx,
            "last_idx": self.last_idx,
            "header_reserved": self.header_reserved,
            "entry_size": self.entry_size,
            "sclk_timestamp": self.sclk_timestamp,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }
        if self.entries is not None:
            d["entries"] = [e.to_dict() for e in self.entries]
        if self.snapshot_counts is not None:
            d["snapshot_counts"] = self.snapshot_counts
            d["snapshot_items"] = self.snapshot_items
        return d


def _parse_entry(e: bytes, entry_size: int) -> Diag0xB1A7Entry:
    entry_type, entry_marker, sfn_subframe, sclk = unpack_from("<BBHI", e, 0)
    ent = Diag0xB1A7Entry(
        entry_type=entry_type,
        entry_marker=entry_marker,
        sfn_subframe=sfn_subframe,
        sclk_timestamp=sclk,
        body_raw=e[_ENTRY_HEAD_BYTES:],
    )
    layout = _CELL_LAYOUT.get(entry_size)
    if layout is None:
        return ent
    tag_off, pci_off, earfcn_off, earfcn_fmt = layout
    if tag_off is not None:
        ent.tag = unpack_from("<H", e, tag_off)[0]
    if entry_type == ENTRY_TYPE_CELL:
        ent.pci = unpack_from("<H", e, pci_off)[0]
        # Explicit per-width reads, so an EARFCN-width audit can see both. The
        # 28 B (MDM9200) EARFCN is narrow on the wire: the u16 after it is
        # non-zero in 143/535 corpus type-2 entries, so a u32 read would
        # swallow a neighbouring field (the same shape as 0xB193 v3 on the
        # MC7700).
        if earfcn_fmt == "<H":
            earfcn = unpack_from("<H", e, earfcn_off)[0]
        else:
            earfcn = unpack_from("<I", e, earfcn_off)[0]
        ent.earfcn = earfcn
    return ent


def _var_snapshot(data: bytes, num_entries: int, entry_size: int):
    """(counts, items) when ``data`` is the R562L5 variable snapshot, else None.

    Exact: one type-0x13 entry declared at 404 B, length 132 + 404 * sum of the
    four u8 counts at [128:132], and all-zero padding after the 8 B items."""
    if (num_entries != 1 or entry_size != _VAR_SNAP_ENTRY_SIZE
            or len(data) < _VAR_SNAP_ITEMS or data[_HEADER_BYTES] != ENTRY_TYPE_SNAPSHOT):
        return None
    counts = tuple(data[_VAR_SNAP_COUNTS:_VAR_SNAP_ITEMS])
    k = sum(counts)
    if len(data) != _VAR_SNAP_ITEMS + _VAR_SNAP_ENTRY_SIZE * k:
        return None
    end = _VAR_SNAP_ITEMS + _VAR_SNAP_ITEM_BYTES * k
    if any(data[end:]):
        return None
    items = [data[_VAR_SNAP_ITEMS + i * _VAR_SNAP_ITEM_BYTES:_VAR_SNAP_ITEMS + (i + 1) * _VAR_SNAP_ITEM_BYTES]
             for i in range(k)]
    return counts, items


@register(
    0xB1A7,
    name="0xB1A7",
    description=(
        "0xB1A7 — LTE ML1 timestamped event ring-buffer flush: 16B header "
        "(version, marker, num_entries, first/last ring idx, entry_size, sclk "
        "timestamp) + num_entries x entry_size entries (type, marker, "
        "SFN*10+subframe, sclk, body; type-2 entries carry cell PCI/EARFCN)"
    ),
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Container decoded from an exhaustive census (422,918 records / 482 "
        "captures, MDM9200 through SDX72; byte-0 0x10 and byte-1 0x01 "
        "everywhere): payload_size == 16 + u8@2 num_entries * u16@10 "
        "entry_size on every size class, and (first_idx + n - 1) % 200 == "
        "last_idx on every walked record. Header u32@12 and entry u32@4 are "
        "the 32.768 kHz sleep clock (measured 32,764..32,768 ticks/s on 10 "
        "chipsets). Entry u16@2 = SFN*10+subframe, F3-grounded 240/240 against "
        "lte_ml1_sm_idle.c:1532 'current subfn' and 137/137 against "
        "lte_ml1_pos_timexfer.c:267 'Sfn' (EM7455, within ±2 sf). Type-2 "
        "entries carry PCI/EARFCN at entry_size-keyed offsets, time-aligned "
        "against 0xB193/0xB0C0 over 22 captures: PCI 19,832/20,535, EARFCN "
        "30,105/30,438, with the residue coherent other cells. "
        "The one off-law form is the Orbic R562L5 (SDX62) variable type-0x13 "
        "snapshot, decoded structurally: n=1, entry_size=404, length 132 + "
        "404 * sum(u8@128..131), sum x 8 B items at 132 then zero padding; "
        "exact on all 45 off-law records in the three R562L5 captures, and a "
        "484-capture census finds no other over-long record. Counts and items "
        "are exposed raw. Any other record shorter or longer than the size law "
        "returns None (registry WARN) rather than degrading to a header-only "
        "record. Entry types, tag values and the snapshot body are not "
        "decoded."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    field_invariants={
        "version": {"enum": [_B1A7_VERSION_OBSERVED]},
        # byte-1 is 0x01 on all 422,918 corpus records, MDM9200 through SDX72.
        "header_marker": {"const": _B1A7_HEADER_MARKER},
        # No payload_size / entry_size / entry_type gate: sizes span 22
        # values and strides 5 families, and both will grow.
    },
    fields_identified=14,
    fields_parsed=16,  # + snapshot_counts / snapshot_items (raw, R562L5 only)
)
def parse_0xb1a7(log_time: int, data: bytes) -> Diag0xB1A7 | None:
    # The 16-byte header is the minimum. The corpus minimum is 48 B.
    if len(data) < _HEADER_BYTES:
        return None
    if data[0] != _B1A7_VERSION_OBSERVED:
        return None
    (version, header_marker, num_entries, first_idx, last_idx) = unpack_from("<5B", data, 0)
    entry_size, sclk = unpack_from("<HI", data, 10)
    # Size gate: the header declares num_entries x entry_size bytes of ring
    # entries. A shorter record lost its tail; a longer one is an undecoded
    # form. Either way decline it (registry WARN): a header-only record would
    # be a silent drop. The R562L5 variable snapshot is the one attested
    # off-law form, and it has its own exact law.
    if num_entries and entry_size < _ENTRY_HEAD_BYTES:
        return None  # no room for the 8 B entry head: not a form we know
    snap = None
    if len(data) != _HEADER_BYTES + num_entries * entry_size:
        snap = _var_snapshot(data, num_entries, entry_size)
        if snap is None:
            return None
    nonzero = sum(1 for b in data[2:] if b != 0)
    rec = Diag0xB1A7(
        log_time=log_time,
        version=version,
        header_marker=header_marker,
        num_entries=num_entries,
        first_idx=first_idx,
        last_idx=last_idx,
        header_reserved=data[5:10],
        entry_size=entry_size,
        sclk_timestamp=sclk,
        data_density=round(nonzero / max(len(data) - 2, 1), 2),
        payload_size=len(data),
        body_raw=data[_HEADER_BYTES:],
    )
    if snap is not None:
        rec.snapshot_counts, rec.snapshot_items = snap
        rec.entries = [_parse_entry(data[_HEADER_BYTES:], entry_size)]
    else:
        rec.entries = [
            _parse_entry(data[_HEADER_BYTES + i * entry_size:_HEADER_BYTES + (i + 1) * entry_size], entry_size)
            for i in range(num_entries)
        ]
    return rec
