"""LTE ML1 Intra-Frequency Measurement parser (0x18AB).

0x18AB -- LTE ML1 Intra-Frequency Measurement
    Cell detection records for cells on the serving frequency.
    Emitted ~every 200ms. Fixed 209 bytes (version 7 on SDX20).

    Two subpacket types coexist in the same log code:
        subtype 2 -- Measurement subpacket: reports one detected cell with
                     EARFCN and PCI. Contains raw ML1 measurement data
                     (timing/phase) in bytes 28-47 and a measurement
                     sequence counter at u16@132. RSRP is NOT present;
                     it is derived by the ML1 layer and emitted in 0xB193.
        subtype 3 -- Timing reference subpacket: two u32 timestamps
                     bracketing a measurement interval, plus serving PCI.

    Subtype 2 and 3 records alternate in pairs: a timing record followed
    by a measurement record for each measurement interval.

Reverse-engineered from SDX20 (LM960) drive captures, cross-referenced
against 0xB193 serving cell measurements for validation.

Key findings:
    - Header: version(u8@0) subtype(u8@1) EARFCN(u32@2) PCI(u32@6)
    - Bytes 2-9 are not two u64 timestamps: bytes 2-5 are EARFCN (u32 LE,
      confirmed value 800 = AT&T Band 26), bytes 6-9 are PCI (u32 LE,
      confirmed values 6, 103, etc.).
    - RSRP is NOT encoded anywhere in the 209-byte payload. Exhaustive
      search of all byte offsets, bitfield widths, and the usual DIAG
      RSRP encodings (div10, 0.0625-resolution, bitpacked u32) found
      zero correlation (R^2 < 0.32) with ground truth from 0xB193.
    - The raw measurement data at bytes 32-47 appears to be IQ accumulator
      or timing/phase data: byte 33 always equals byte 41, and values
      vary pseudo-randomly even when RSRP is constant.
    - Byte 30 cycles through multiples of 5 (0,5,10,15,20,25,30,35),
      likely representing subframe timing within a measurement window.
    - u16@132 is a monotonically increasing measurement sequence counter.
    - Bytes 140-208 sometimes contain neighbor cell data when cells are
      detected on the same frequency (e.g., PCI 6 appearing in records
      where the header PCI is 103).

Unique-contribution analysis (relevant to Kismet mapping):
    Across 12 diverse captures (SDX20, MDM9x50, MDM9650, SDX55, SDX62, SDX65;
    6 vendors; v5/v7/v9 framings; drives + surveys + edge-cases), 0x18AB adds
    ZERO unique (pci, earfcn) keys beyond 0xB193/0xB192/0xB195/0xB0C0. Its 32
    decoded cell keys are a strict SUBSET of those codes' union in every
    capture. This mirrors the 0x18AC result: 0x18AB is intra-frequency
    serving-cell measurement, so every cell it names is the serving/intra cell
    that 0xB193 already carries -- it does NOT surface the inter-frequency
    neighbors a Kismet wardrive wants (that is 0x18AC's job, and 0x18AC also
    contributes zero). A latent-neighbor probe shows the result is not an
    artifact of partial decode: the still-undecoded body regions (v9/sub=0x03
    timing slot-array @28-79, v7 tail @140-208) carry NO neighbor PCI identity
    -- the dozens of neighbor PCIs the B19x codes report never appear as a
    consistent u16 field in 0x18AB payloads (the one apparent "hit" at offset 0
    is the [version, subtype] header [0x09, 0x01] read as u16 LE = 265, not a
    cell). Conclusion: not worth mapping into Kismet for LTE cell coverage, and
    finishing the sub=0x03 slot-array decode would add no cells.

Log name: GNSS GTS log
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_LTE_ML1_INTRA_FREQ_MEAS
from diaggrok.registry import register


@dataclass
class Diag0x18AB:
    """LTE ML1 Intra-Frequency Measurement (0x18AB)."""

    log_time: int
    version: int
    subtype: int
    entries: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x18AB',
            'log_time': self.log_time,
            'version': self.version,
            'subtype': self.subtype,
            'entries': self.entries,
        }


# ---------------------------------------------------------------------------
# Subtype 2: measurement record layout
# ---------------------------------------------------------------------------
#   [0]     u8   version (7)
#   [1]     u8   subtype (2)
#   [2:6]   u32  EARFCN
#   [6:10]  u32  PCI
#   [10:28] 18 bytes reserved (zeros)
#   [28]    u8   reserved (0x00)
#   [29]    u8   measurement config flags
#   [30]    u8   subframe timing (cycles 0,5,10,15,20,25,30,35)
#   [31]    u8   timing field 2
#   [32:48] 16 bytes raw measurement data (two 8-byte measurement words)
#   [48:56] 8 bytes reserved
#   [56:60] u32  secondary EARFCN (when non-zero, a second carrier detected)
#   [60:96] 36 bytes reserved
#   [96:100] u32 cell detection metadata
#   [100:128] 28 bytes reserved
#   [128]   u8   summary marker (always 0x01)
#   [129]   u8   summary byte
#   [130:132] u16 copy of u16@36 (raw measurement summary)
#   [132:134] u16 measurement sequence counter (monotonically increasing)
#   [134:140] 6 bytes reserved
#   [140:209] 69 bytes neighbor cell data (variable, often zeros)

_MIN_TYPE2_LEN = 10   # version + subtype + EARFCN + PCI
_MIN_TYPE3_LEN = 18   # version + subtype + 2 timestamps + 2 PCIs
_MIN_TYPE1_V9_LEN = 10  # version + subtype + header

_MAX_LTE_EARFCN = 262143
_MAX_LTE_PCI = 503

# v5 (466-byte Sierra MDM9x50) subtype-2 cell-identity offsets.
# The v7 209-byte layout puts EARFCN@2 / PCI@6; on the 466-byte v5 record those
# offsets read 0. Recovered on an EM7565 against a single CBRS B48 cell
# (EARFCN 55340 / PCI 451): the LE bytes 2c d8 (55340) sit at offset 128 and
# c3 01 (451) at offset 132, consistent across 37/37 v5/st2 records. EARFCN is
# u32 (bytes 130-131 == 0x0000 across all 37); PCI is u16 (bytes 134-135 carry
# a separate varying field, so reading PCI as u32 would range-reject 22/37
# records).
_V5_ST2_EARFCN_OFFSET = 128
_V5_ST2_PCI_OFFSET = 132
_MIN_TYPE2_V5_LEN = 134  # need bytes through the u16 PCI at 132..134


def _parse_subtype2(data: bytes, version: int = 7) -> list[dict[str, Any]]:
    """Parse subtype 2 — measurement subpacket.

    Returns a list of cell entries. The primary cell (from the header)
    is always included with whatever measurement metadata can be
    extracted from the payload. Neighbor cells from bytes 140+
    are not yet decoded (their variable structure requires further RE
    work).

    The v7 (209-byte SDX20) and v5 (466-byte Sierra MDM9x50) layouts place
    the cell identity at different offsets, so the EARFCN/PCI read branches on
    ``version``. The v7-specific measurement words are only meaningful on
    the 209-byte layout and are NOT emitted for v5 (their offsets alias other
    fields there — e.g. the v7 ``meas_seq`` u16@132 is exactly the v5 PCI).

    On v7 this also exposes the raw measurement words (bytes 32..40 and
    40..48) plus the timing fields (bytes 29..32) so downstream consumers can
    attempt their own RE without re-reading captures.
    """
    if version == 0x05:
        # 466-byte Sierra MDM9x50 layout: EARFCN u32@128, PCI u16@132.
        if len(data) < _MIN_TYPE2_V5_LEN:
            return []
        earfcn = unpack_from('<I', data, _V5_ST2_EARFCN_OFFSET)[0]
        pci = unpack_from('<H', data, _V5_ST2_PCI_OFFSET)[0]
        if earfcn > _MAX_LTE_EARFCN or pci > _MAX_LTE_PCI:
            return []
        return [{'pci': pci, 'earfcn': earfcn}]

    earfcn = unpack_from('<I', data, 2)[0]
    pci = unpack_from('<I', data, 6)[0]

    if earfcn > _MAX_LTE_EARFCN or pci > _MAX_LTE_PCI:
        return []

    entry: dict[str, Any] = {
        'pci': pci,
        'earfcn': earfcn,
    }

    # Timing fields at bytes 29..32
    if len(data) >= 32:
        entry['meas_flags'] = data[29]      # config/flag byte
        entry['subframe_timing'] = data[30]  # cycles 0,5,10,15,20,25,30,35
        entry['timing_field2'] = data[31]    # purpose unknown but varies

    # Raw measurement words at bytes 32..40 and 40..48
    # Empirically across 222 EG18-NA records: byte[33] == byte[41]
    # (100% match, stride-8 mirror), bytes 32 and 34..39 vary
    # independently. Likely two parallel per-Rx-antenna measurement
    # blocks where byte 33 is a shared label/rx-id and the other
    # 7 bytes are per-antenna measurement state. Body RE incomplete;
    # exposing as hex for downstream analysis.
    if len(data) >= 48:
        entry['meas_word1_hex'] = data[32:40].hex()
        entry['meas_word2_hex'] = data[40:48].hex()
        entry['meas_word_mirror_byte'] = data[33]  # byte that's shared word1/word2

    # Include measurement sequence counter when available.
    if len(data) >= 134:
        entry['meas_seq'] = unpack_from('<H', data, 132)[0]

    return [entry]


def _parse_subtype3(data: bytes) -> list[dict[str, Any]]:
    """Parse subtype 3 — timing reference subpacket.

    Contains two u32 measurement-window timestamps and the serving PCI.
    Returns a single entry with the serving cell PCI and timing info.
    """
    timestamp_start = unpack_from('<I', data, 2)[0]
    pci_start = unpack_from('<I', data, 6)[0]
    timestamp_end = unpack_from('<I', data, 10)[0]
    pci_end = unpack_from('<I', data, 14)[0]

    if pci_start > _MAX_LTE_PCI:
        return []

    return [{
        'pci': pci_start,
        'earfcn': 0,  # Not present in timing records
        'timestamp_start': timestamp_start,
        'timestamp_end': timestamp_end,
    }]


# 7-byte sentinel pinned at offset 21-27 of v9/st1/sub=3 records. 100%
# constant across 652 EM9190 SDX55 sub=3 records, but firmware-build-specific:
# one EM9190 build emits `f2 ff 68 91 45 3b 08`, while an FN980 build emits
# `05 00 23 db 49 3b 08` across all 3230 sub=3 records of a GNSS reference
# run + 7 state-transition edge captures. The trailing `3b 08` and near-equal
# byte 4 (`45` vs `49`) suggest the last 3 bytes are a chipset-family
# constant while bytes 0-3 are a per-build value (heap pointer / build hash).
# This is a soft pin: other builds simply report `sentinel_match=False`,
# which is the intended drift signal.
_V9_ST1_SUB3_SENTINEL = b"\xf2\xff\x68\x91\x45\x3b\x08"
_V9_ST1_SUB3_SENTINEL_OFFSET = 21

# Sub-subtype values (byte 2) seen across the v9/st1 corpus: 575,274 v9/st1
# records spanning 8 vendor/chipset paths.
#
#   0x03 (525,242 records, 91.3% of v9/st1) — periodic measurement window.
#         Cross-vendor. Carries back-to-back u64 LE start_ts/end_ts at
#         offsets 3 / 11. The sliding-window invariant `record[N+1].start_ts
#         == record[N].end_ts` holds for 99-100% of consecutive records. Body
#         offsets 28-79 form a stride-4 slot array (13 slots × 4 bytes); the
#         per-slot byte+0 varies while bytes +1/+2/+3 are 87-91% zero —
#         classic cell-measurement-array layout. Slot semantics TODO.
#   0x16 (39,089 records, 6.8% of v9/st1) — config / state snapshot.
#         Multi-vendor: EM9190 (851), RM520N-GL (2,870), RM500Q (2,272),
#         M2000 (24), plus 33,072 from drive and survey captures. **NOT
#         Sierra-only** (a small 5-vendor sample can suggest otherwise).
#         Telit FN980 is the only polled vendor that does not emit sub=0x16.
#         Body @ offsets 30-79 is **100% zero across all 39,089 records** —
#         empty in the sampled range. Offsets 80-209 were not sampled
#         corpus-wide; the EM9190 fixture has sparse non-zero bytes at 84-106
#         so the body is NOT fully empty past the structural header. Bytes 3-9
#         carry a 7-byte chipset magic constant `00 8e a6 07 00 54 02`
#         shared between EM9190 SDX55 and RM500Q SDX55 (likely
#         SDX55-chipset-family identifier; analog of the per-build sub=0x03
#         sentinel but with stronger invariance). Bytes 10-29 vary per
#         record. Body decode @ offsets 80-209 remains open.
#   0x02 (10,943 records, 1.9% of v9/st1) — observed on RM520N-GL (8,698),
#         FN980 (1,072), M2000 (291), LV55 (7), plus 875 from drive and
#         survey captures. NEVER observed on Sierra. **Header layout matches
#         v=7 st=2 and st=3**: u32 LE EARFCN @ 3-6, u32 LE PCI @ 7-10.
#         Verified against an RM520N-GL indoor-cell capture (EARFCN 66786,
#         PCI 236 — exact match against the EG18-NA v2 fixture used in
#         `test_eg18na_corpus_regression`). {0x16, 0x02} are not mutually
#         exclusive per vendor — RM520N-GL emits BOTH 0x16 (2,870) AND 0x02
#         (8,698). Body @ offsets 11-209 is sparse: most bytes are zero with
#         small populated regions at {30, 31, 33-38, 40-43, 57-60}.
#
# F3 grounding, v0x09: the v9/st1/sub=0x02 (earfcn@3, pci@7) decode is
# grounded against an independent in-capture F3 source on SDX62 (Casa
# Systems CFW-3212 / RG520N-NA). In one capture all 336 v9/st1/sub=0x02
# records decode to EARFCN 2300 / PCI 236 — matching 336/336 the co-captured
# plaintext F3 (0x79) prints `+QENG "servingcell",...,236,2300` and
# `+QENG "neighbourcell intra","LTE",2300,236` (file dsatrsp.c, the
# AT-response subsystem — a firmware code path independent of the 0x18AB log
# emission). Two subsystems converging on the same (EARFCN,PCI) rule out a
# coincidental byte alignment. NB the field is a measured LTE intra/inter-freq
# CELL identity, NOT always the serving cell: an LV55 SDX55 capture decodes
# sub=0x02 -> (66536, 310) while the serving cell was EARFCN 5230, so
# sub=0x02 can carry a neighbour on a different carrier. earfcn/pci naming is
# therefore correct and deliberately generic (no `serving_` prefix).
_V9_ST1_SUB_MEAS = 0x03
_V9_ST1_SUB_CONFIG = 0x16
_V9_ST1_SUB_OTHER = 0x02

# 7-byte chipset magic at offset 3-9 of v9/st1/sub=0x16 records. Identical
# between EM9190 SDX55 and RM500Q SDX55. Stronger invariance than the
# sub=0x03 sentinel (which is per-build).
_V9_ST1_SUB16_MAGIC = b"\x00\x8e\xa6\x07\x00\x54\x02"  # SDX55 (EM9190/RM500Q)
# SDX72 (Foxconn T99W640 / Dell DW5934e) shares the `07 00 54 02` chipset-
# family tail with SDX55 but carries chipset-id bytes `5e f4` (vs SDX55
# `8e a6`). CONSTANT across two T99W640 captures (8/8 sub=0x16 records in
# the second).
_V9_ST1_SUB16_MAGIC_SDX72 = b"\x00\x5e\xf4\x07\x00\x54\x02"
# SDX62 (Foxconn T99W373 / Dell DW5932e-cobrand).
# Shares the SDX55 chipset-id bytes `8e a6` but carries a DISTINCT tail
# `07 00 04 01` (vs SDX55/SDX72 `07 00 54 02`) — so the tail is build/format-
# specific, not a cross-generation constant. CONSTANT across one capture
# (187/187 sub=0x16 records, camped NR n41 SA).
_V9_ST1_SUB16_MAGIC_SDX62_FOXCONN = b"\x00\x8e\xa6\x07\x00\x04\x01"
# Allowlist of known-good chipset magics. Membership ⇒ a recognized config
# snapshot; an UNKNOWN magic still returns chipset_magic_match=False, which is
# the layout-drift signal a brand-new chipset/firmware would trip.
_V9_ST1_SUB16_MAGICS = (
    _V9_ST1_SUB16_MAGIC,
    _V9_ST1_SUB16_MAGIC_SDX72,
    _V9_ST1_SUB16_MAGIC_SDX62_FOXCONN,
)
_V9_ST1_SUB16_MAGIC_OFFSET = 3


def _parse_subtype1_v9(data: bytes) -> list[dict[str, Any]]:
    """Parse subtype 1, version >= 9 (SDX55+).

    Three sub-subtypes observed across the v9/st1 corpus (575k records,
    8 vendor/chipset paths; byte 2):
    Three sub-subtypes observed across the v9/st1 corpus (byte 2):
      - 0x03 (measurement, 91.3%): exposes start_ts / end_ts (u64 LE @ 3 /
        @ 11) plus the 7-byte build sentinel at offset 21-27 used for
        layout-drift detection. Sliding-window invariant confirmed
        cross-vendor.
      - 0x16 (config snapshot, 6.8%, multi-vendor): exposes a 7-byte
        chipset magic at offset 3-9 via `chipset_magic_match` (True when the
        magic is in the known-chipset allowlist — SDX55 `00 8e a6 07 00 54 02`,
        SDX72 `00 5e f4 07 00 54 02` and Foxconn SDX62 `00 8e a6 07 00 04 01`;
        an unknown magic returns False as a layout-drift signal). Body bytes
        30-79 are 100%-zero across the 39k-record corpus.
      - 0x02 (1.9%, non-Sierra): exposes pci + earfcn via the same v=7
        st=2 header layout (u32 LE EARFCN @ 3, u32 LE PCI @ 7), range-
        validated against 3GPP limits.
    """
    if len(data) < _MIN_TYPE1_V9_LEN:
        return []

    sub_subtype = data[2]
    config_word = unpack_from('<H', data, 2)[0]
    nz_bytes = sum(1 for b in data[2:] if b != 0)

    entry: dict[str, Any] = {
        'format': 'v9_st1',
        'sub_subtype': sub_subtype,
        'config_word': config_word,
        'data_bytes': nz_bytes,
        'total_bytes': len(data) - 2,
    }

    if sub_subtype == _V9_ST1_SUB_MEAS and len(data) >= 28:
        entry['start_ts'] = unpack_from('<Q', data, 3)[0]
        entry['end_ts'] = unpack_from('<Q', data, 11)[0]
        sentinel = data[
            _V9_ST1_SUB3_SENTINEL_OFFSET :
            _V9_ST1_SUB3_SENTINEL_OFFSET + len(_V9_ST1_SUB3_SENTINEL)
        ]
        entry['sentinel_match'] = sentinel == _V9_ST1_SUB3_SENTINEL
    elif sub_subtype == _V9_ST1_SUB_CONFIG and len(data) >= 10:
        magic = data[
            _V9_ST1_SUB16_MAGIC_OFFSET :
            _V9_ST1_SUB16_MAGIC_OFFSET + len(_V9_ST1_SUB16_MAGIC)
        ]
        entry['chipset_magic_match'] = magic in _V9_ST1_SUB16_MAGICS
    elif sub_subtype == _V9_ST1_SUB_OTHER and len(data) >= 11:
        earfcn = unpack_from('<I', data, 3)[0]
        pci = unpack_from('<I', data, 7)[0]
        if earfcn <= _MAX_LTE_EARFCN and pci <= _MAX_LTE_PCI:
            entry['earfcn'] = earfcn
            entry['pci'] = pci

    return [entry]


# ---------------------------------------------------------------------------
# Version 6 (WNC MDM9150, C-V2X context)
# ---------------------------------------------------------------------------
# v0x06 is the 209-byte WNC MDM9150 (81UMV91M21) class. The Kapsch RIS-9260
# captures are NOT a separate device/build — the RIS-9260 is a Linux RSU
# appliance that contains that same modem, so its corpus adds only long
# uptime, not a second silicon/firmware. ~1.1M records, the single largest
# byte0 slice of the whole 0x18AB corpus.
#
# F3 grounding (resolved against the build's own message database): the
# MDM9150 v6 corpus runs in a **C-V2X context**, NOT cellular LTE Uu. In a
# drive capture with 3.0M resolved QSR4 (0x99) F3 frames, the LTE sites are
# `rflte_mc_tx_config.c` ("Rx tuned Freq 5915000" kHz = the 5.915 GHz C-V2X
# band-47 ITS carrier), `cc_srchmgr_uimage.c`, `v2x_rrc_main.c`,
# `mc_gnssmeasreport.c`. NONE of the classic LTE-ML1 intra-freq-meas sites
# that ground v7 (`lte_ml1_sm_conn_meas_intra2.c`, `lte_ml1_mdb.c`) appear.
# So the v7 "intra-freq serving-cell EARFCN@2/PCI@6" semantic does **not**
# transfer to v6 — there is no cellular serving cell to name, and the v6
# layout is distinct anyway (v6 zeros @17-18; v7 zeros @8-9). Cellular
# identity is deliberately NOT emitted for v6 (over-naming guard).
#
# v6 subtypes observed (byte1): 0x00, 0x01, 0x03 — NOT the legacy {0x01,0x02,
# 0x03}. Only subtype 0x03 is safely decodable today: it is a timing-reference
# subpacket with start_ts u32@4 / end_ts u32@12. The sliding-window invariant
# rec[N+1].start_ts == rec[N].end_ts holds 100% across the capture (window
# ~29-30 ticks), the same signature as v7 st3 and v9 sub=0x03 — but shifted
# +2 bytes from v7's @2/@10. Subtypes 0x00/0x01 are measurement bodies whose
# layout has no F3 label to ground in the C-V2X corpus; they are exposed
# structurally/raw.
_V6_VERSION = 0x06
_V6_SUBTYPES = (0x00, 0x01, 0x03)
_V6_ST3_TIMING = 0x03
_V6_ST3_START_TS_OFFSET = 4
_V6_ST3_END_TS_OFFSET = 12
_MIN_V6_ST3_LEN = 16  # need bytes through end_ts u32@12


def _parse_v6(data: bytes, subtype: int) -> list[dict[str, Any]]:
    """Parse version=0x06 (WNC MDM9150, C-V2X context) records.

    F3-grounded as C-V2X: the cellular intra-freq serving-cell semantic
    does NOT apply, so this branch deliberately emits NO ``earfcn`` / ``pci``
    (there is no serving cell; naming the v7 offsets on v6 would be a mis-parse).

    subtype 0x03 is a timing-reference subpacket — ``start_ts`` u32@4 and
    ``end_ts`` u32@12, with the sliding-window invariant rec[N+1].start_ts ==
    rec[N].end_ts confirmed 100% across the corpus. subtypes 0x00/0x01 are
    measurement bodies whose field layout is not yet ground-truthed (no F3
    label in the C-V2X corpus); they are exposed structurally with a bounded
    raw body slice so downstream RE can proceed without re-reading captures.
    """
    if subtype == _V6_ST3_TIMING and len(data) >= _MIN_V6_ST3_LEN:
        start_ts = unpack_from('<I', data, _V6_ST3_START_TS_OFFSET)[0]
        end_ts = unpack_from('<I', data, _V6_ST3_END_TS_OFFSET)[0]
        return [{
            'format': 'v6_st3_timing',
            'context': 'cv2x',
            'start_ts': start_ts,
            'end_ts': end_ts,
        }]

    # subtype 0x00 / 0x01 — measurement body, layout ungrounded. Expose raw.
    sub_subtype = data[2] if len(data) > 2 else None
    nz_bytes = sum(1 for b in data[2:] if b != 0)
    return [{
        'format': f'v6_st{subtype:x}',
        'context': 'cv2x',
        'sub_subtype': sub_subtype,
        'data_bytes': nz_bytes,
        'total_bytes': len(data) - 2,
        'body_hex': data[2:32].hex(),  # bounded raw slice for downstream RE
    }]


_OBSERVED_VERSIONS = (0x05, 0x06, 0x07, 0x09)

# Fixed record sizes. Every corpus record is one of these per-version
# sizes (v5 466 B / 42,909 records; v7 209 B; v9 210 B / 1.2M; v6 209 B for
# subtypes 0x00/0x01 and a 49 B subtype-0x03 timing record on an MDM9250
# unit). The body fields carry no length field, so a payload shorter than
# its (version, subtype) size is a truncated record and returns None (registry
# WARN). Longer payloads are still accepted.
_MIN_RECORD_LEN = {0x05: 466, 0x07: 209, 0x09: 210}
_MIN_V6_RECORD_LEN = {0x00: 209, 0x01: 209, 0x03: 49}
# v6 subtype 0x03 is mostly 209 B; the 49 B form is the short one above. A
# length between them is a cut 209 B record.
_V6_ST3_FULL_LEN = 209
_OBSERVED_SUBTYPES = (0x01, 0x02, 0x03)  # legacy (v5/v7/v9); v6 uses _V6_SUBTYPES


# ---------------------------------------------------------------------------
# Validating the cell identity against AT+QENG
# ---------------------------------------------------------------------------
# Scope caveat: on the RM520N-GL (v=0x09) the cell identity (earfcn/pci) is
# emitted ONLY on the v9/st1/sub_subtype=0x02 records (~1.9% of the v9
# corpus). The dominant sub=0x03 (91.3%) records are timing-only and the
# sub=0x16 (6.8%) records are a chipset-magic config snapshot — neither
# carries cell identity. RSRP is absent from this log code entirely (derived
# by ML1 and emitted in 0xB193), so no signal-strength field can be checked.

@register(LOG_LTE_ML1_INTRA_FREQ_MEAS,
    name="0x18AB",
    description="Cell detection on serving frequency — EARFCN, PCI, timing fields, raw measurement words; v9/st1/sub=0x02 EARFCN+PCI, v9/st1/sub=0x16 chipset magic (SDX55, SDX72, Foxconn SDX62), v5 (MDM9x50, 466-byte) subtype-2 cell identity at EARFCN u32@128 / PCI u16@132, and v6 (MDM9150, C-V2X context) timing records",
    version=19,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE starting from SDX20 (LM960) drive captures, extended by "
        "a 185-capture / 429,827-record corpus pass and a 575,274-record "
        "partition of the v9/st1 variant across 8 vendor/chipset paths. "
        "v7 (209 B): EARFCN u32@2 / PCI u32@6 — on an LM960 camped on a CBRS "
        "B48 cell, earfcn == AT#RFSTS (55340) and pci == an external same-cell "
        "QMI PCI (451); F3 co-emits lte_ml1_dlm_ard.c. "
        "v5 (466 B, EM7565 MDM9x50): EARFCN u32@128 / PCI u16@132, found by "
        "scanning all 37 v5/st2 records for the LE byte patterns of the known "
        "CBRS B48 serving cell; 37/37 decode (55340, 451) == AT!GSTATUS? 'LTE "
        "Rx chan' + QMI GetCellLocationInfo PCI, and F3 co-emits "
        "lte_ml1_sm_conn_meas_intra2.c plus an RF-tune 'LTE PRX Band 178, Chan "
        "55340' print. "
        "v9/st1 is split by sub_subtype (byte 2): sub=0x02 carries u32 LE "
        "EARFCN @ 3 and u32 LE PCI @ 7 (same layout as v=7 st=2/st=3), "
        "range-validated against 3GPP LTE limits, checked on an RM520N-GL "
        "indoor-cell capture, and F3-grounded on a second, independent SDX62 "
        "build (Casa Systems CFW-3212 / RG520N-NA: 336/336 and 125/125 records "
        "in two captures == the firmware's own +QENG prints, 2300/236). It is "
        "a measured cell identity, not always the serving cell. sub=0x16 carries a 7-byte chipset magic at offset 3-9 (SDX55, "
        "SDX72 and Foxconn SDX62 variants) and is emitted by most vendors "
        "(not Sierra-only); its bytes 30-79 are 100%-zero across 39,089 "
        "records. RM520N-GL emits both sub=0x16 and sub=0x02. "
        "v6 (WNC MDM9150, ~1.1M records) is F3-grounded as a C-V2X context "
        "(RF tuned 5915 MHz band-47 ITS; v2x_rrc_main.c / cc_srchmgr_uimage.c "
        "sites; no lte_ml1 intra-freq-meas sites): subtypes {0x00,0x01,0x03}, "
        "subtype 0x03 timing decoded (start_ts u32@4 / end_ts u32@12, "
        "sliding-window 100%), st0/st1 exposed raw with no cellular "
        "earfcn/pci. A payload shorter than its fixed per-(version, subtype) "
        "record size returns None (registry WARN); v6 subtype 0x03 below 209 B "
        "is accepted only at exactly 49 B. Open: the sub=0x03 slot array "
        "(offsets 28-79, stride-4 13-slot structure) and the sub=0x02 sparse "
        "fields (offsets 30-60)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # version, subtype, entries[] — subtype-2 entries carry meas_flags +
    # subframe_timing + meas_word1/2 hex; subtype-3 timing entries
    # carry EARFCN/PCI + two timestamps. All three top-level fields named.
    fields_identified=3,
    fields_parsed=3,
    field_invariants={
        "version": {"enum": list(_OBSERVED_VERSIONS)},
        # union of legacy {0x01,0x02,0x03} + v6 {0x00,0x01,0x03}; the parser body
        # enforces the tighter per-version subtype gate (v6 vs legacy) before
        # emitting, so this net stays sound while admitting v6's subtype 0x00.
        "subtype": {"enum": sorted(set(_OBSERVED_SUBTYPES) | set(_V6_SUBTYPES))},
    },
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge", "rat-context"),
)
def parse_0x18ab(
    log_time: int, data: bytes
) -> Diag0x18AB | None:
    """Parse 0x18AB -- LTE ML1 Intra-Frequency Measurement.

    Header layout:
        [0]    u8   version (corpus-observed: 0x05 / 0x06 / 0x07 / 0x09)
        [1]    u8   subtype (corpus-observed: 0x01 / 0x02 / 0x03; v6 0x00)
        [2:6]  u32  EARFCN   (v7; not part of a u64 timestamp)
        [6:10] u32  PCI      (v7; not part of a u64 timestamp)

    Returns an Diag0x18AB with entries list. Each entry contains
    at minimum 'pci' and 'earfcn'. RSRP is not available from this log code
    (use 0xB193 for RSRP).

    Version/subtype gate (per-version): v5/v7/v9 accept subtypes
    {0x01, 0x02, 0x03}; v6 (MDM9150, C-V2X) accepts {0x00, 0x01, 0x03}. Any
    other (version, subtype) is a future-firmware/uncharacterized variant and
    is rejected rather than mis-parsed against the wrong body layout (the
    same size does not imply the same format).

    Returns None if the payload is shorter than its fixed per-(version,
    subtype) record size (v5 466 / v6 209, st3 49 / v7 209 / v9 210 B — a
    truncated record) or the (version, subtype) pair is outside the
    corpus-grounded enums.
    """
    if len(data) < 2:
        return None

    version = data[0]
    subtype = data[1]
    if version not in _OBSERVED_VERSIONS:
        return None
    allowed_subtypes = _V6_SUBTYPES if version == _V6_VERSION else _OBSERVED_SUBTYPES
    if subtype not in allowed_subtypes:
        return None
    min_len = (_MIN_V6_RECORD_LEN[subtype] if version == _V6_VERSION
               else _MIN_RECORD_LEN[version])
    if len(data) < min_len:
        return None  # truncated fixed-size record
    if (version == _V6_VERSION and subtype == 0x03
            and min_len < len(data) < _V6_ST3_FULL_LEN):
        return None  # a cut 209 B v6/st3 record, not the 49 B form

    if version == _V6_VERSION:
        # MDM9150 C-V2X context (F3-grounded): distinct layout, no cellular

        # identity. Dispatched separately so the v7 offset map never touches v6.
        entries = _parse_v6(data, subtype)
    elif subtype == 2 and len(data) >= _MIN_TYPE2_LEN:
        entries = _parse_subtype2(data, version)
    elif subtype == 3 and len(data) >= _MIN_TYPE3_LEN:
        entries = _parse_subtype3(data)
    elif subtype == 1 and version >= 9:
        # v9/st1 (SDX55): different format, not yet fully decoded.
        # Extract what we can from the payload structure.
        entries = _parse_subtype1_v9(data)
    else:
        entries = []

    return Diag0x18AB(
        log_time=log_time,
        version=version,
        subtype=subtype,
        entries=entries,
    )
