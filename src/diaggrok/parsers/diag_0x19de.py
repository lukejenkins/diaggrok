"""GNSS Measurement Engine Fix Report (0x19DE) — GNSS_ME_GNSS_FIX_REPORT.

Despite the name, this log code does NOT carry a best-available position
(lat/lon/alt).  Empirical analysis of 199 records across four captures
spanning SDX55 and SDX65 chipsets shows that 0x19DE is a per-channel
Measurement Engine tracking state report — it enumerates the ME's per-SV
tracking slots (channels) and their status flags.  No f64 position values
and no plausible velocity f32s are present; payload is dominated by byte
flags / small counters.

## Captures used for RE (2026-04-17, issue #N)

- EM9190 SWIX55C_03.17.09.00 ..................... 70 × 536 B
- RM500Q <redacted-firmware> ................ 69 × 536 B
- RM520N-GL RM520NGLAAR01A05M4G .................. 4  × 848 B
- RM520N-GL RM520NGLAAR03A03M4G .................. 56 × 1136 B

## Size variants (all version byte = 1)

All three sizes share the same 16-byte header and the same two per-slot
sub-record layouts (GPS 104 B, GLONASS 16 B).  The size is purely a
function of total_slots:

    size = 16 + num_gps_slots * 104 + num_glo_slots * 16

  - **536 B** = 16 + 5×104 + 0     — SDX55 baseline (5 GPS slots, no GLONASS)
  - **848 B** = 16 + 8×104 + 0     — SDX65 GPS-only (8 GPS slots)
  - **1136 B** = 16 + 8×104 + 18×16 — SDX65 GPS + GLONASS

Any other size is treated as malformed (returns None).

## Header layout (16 B, bytes 0..15)

    off  type  name           notes
    0    u8    version        always 1 on all observed records
    1    u8    total_slots    total per-slot sub-records following the header
                              (5 / 8 / 26 on the three observed sizes)
    2    u16   reserved1      always 0
    4    u32   reserved2      always 0
    8    u32   tick           32-bit free-running tick / timestamp — wraps.
                              Mean delta between adjacent records ≈ 12.3M
                              counts (≈ 12.3 s if 1 µs ticks).  Monotonic
                              between wraps.
    12   u32   header_word3   Per-capture constant on 3 of 4 RE corpus
                              captures (em9190=27, rm500q=1, rm520ngl
                              A05=1).  On rm520ngl A03 it varies 8..9
                              across the 56 records.  Likely a config
                              bitmask or enabled-constellation bitfield
                              — semantics unverified, left named as
                              ``header_word3`` to avoid false claims.

## Per-slot sub-record — GPS (104 B, signature 0xA163 at offset 2)

    off  type    name                 notes
    0    u8      slot_id              ME tracking channel ID (1-based).
                                      NOT the PRN.  On rm520ngl_a03, the
                                      8 GPS slots are always
                                      [1,2,3,4,8,6,7,9] across all 56
                                      records — fixed channel layout.
    1    u8      reserved             always 0
    2    u16     signature            0xA163 for GPS (confirmed across
                                      1175 GPS slots in the 199-record
                                      corpus)
    4..103 u8[100] (body region)      See body layout below

### GPS body layout (100 B, body_raw offsets [0..99])

    off  type  name                   notes
    99   u8    slot_state             Last byte of the 100-B body
                                      (body_raw[99], absolute slot
                                      offset 103).  Per-capture-stable
                                      tracking-slot state enum.  Active
                                      slot counts observed across the 4
                                      RE rec0 / rec33 fixtures:

                                        em9190 536B (SDX55) : 1 active
                                          → slot_id=1 state=2
                                        rm500q 536B (SDX55) : 1 active
                                          → slot_id=1 state=2
                                        rm520ngl a05 848B (SDX65) :
                                          4 active, (slot_id,state) =
                                          [(1,2),(6,1),(7,1),(9,8)]
                                        rm520ngl a03 1136B (SDX65) :
                                          4 active, (slot_id,state) =
                                          [(1,5),(6,1),(7,2),(9,2)]

                                      So SDX55 runs with a single active
                                      tracking channel per 0x19DE record
                                      while SDX65 runs with four — likely
                                      a measurement-engine configuration
                                      difference worth validating against
                                      additional SDX55 and SDX65 captures.

                                      slot_state enum values observed:
                                      {0, 1, 2, 5, 8}.  State 8 is
                                      SDX65-only so far and tracks the
                                      single densest slot (nz=51 on
                                      rm520ngl a05 slot_id=9) — the
                                      "primary" tracking channel.  States
                                      1/2 are both "secondary tracking"
                                      states.  State 5 appears once on
                                      rm520ngl a03 slot_id=1 and is
                                      currently unverified.
    (remaining 99 body bytes)  body_raw
                                      Held as body_raw because the
                                      *active-slot* populated-byte layout
                                      differs between rm520ngl_a03
                                      (densest at [7]/[14..15]/[34]/
                                      [38..41]/[42..45]/[46..48]) and
                                      rm520ngl_a05 (densest at [32..95]
                                      contiguously).  A single cross-
                                      capture offset map does not hold.
                                      Tracked in the open sub-task of
                                      #N.

Consumers can call ``is_active`` or check ``slot_state != 0`` to filter
to the tracking channel(s) that are actually populated, which is the
fundamental "data density" distinction driving #N.

## Per-slot sub-record — GLONASS (16 B, signature 0xA10B at offset 2)

    off  type    name           notes
    0    u8      slot_id        ME tracking channel ID.  On rm520ngl_a03
                                the 18 GLO slots are [10..18, 20..28]
                                across all records (fixed layout).
    1    u8      reserved       always 0
    2    u16     signature      0xA10B for GLONASS
    4    u8[12]  body_raw       Per-channel state — even sparser than
                                the GPS block.  Typically 1-2 non-zero
                                flag bytes per slot on the RE corpus.

GLONASS slot body last byte (body_raw[11]) behaves as a state enum on
at least one slot: on the 1136 B rm520ngl_a03 rec33 fixture, slot_id=15
has body_raw[11]=2 while every other slot is 0.  Consumers should
therefore treat the "last body byte = slot_state" convention as applying
to GLONASS slots too, though the enum semantics are unverified with only
one observed non-zero sample.

## Notes on signature bytes

    0xA163 = byte pattern "63 a1"  — GPS channel type
    0xA10B = byte pattern "0B a1"  — GLONASS channel type

The high byte (0xA1) appears to be a "channel type" namespace byte and
the low byte identifies the constellation.  **0x19DE structurally carries
only GPS+GLONASS slots.**  The rtcm-revisit `5d3a` pass (#N) verified
this against 6 splitter-paired LG290P captures (5,381 records / 12,475
slots) where the LG290P MSM7 mask confirmed the modem antenna was
simultaneously receiving Galileo (E1+E5a+E5b+**E6**) and BeiDou
(B1I+B3I+B2a+B1C) — yet not a single non-GPS / non-GLONASS slot
signature appeared in any 0x19DE payload.  Multi-constellation
tracking surfaces in different DIAG codes (e.g. 0x1634 ``GnssMeas1634``
or 0x14B0 ``GnssRfSiteMgmt``), not here.

## Status

- 536 B variant: header + 5 GPS slots — **decoded** (header fields named,
  slot array walked, per-slot signature verified).
- 848 B variant: header + 8 GPS slots — **decoded** (same structure).
- 1136 B variant: header + 8 GPS slots + 18 GLONASS slots — **decoded**.
- Per-slot body bytes (100 B GPS / 12 B GLONASS): **held as body_raw**
  pending a denser capture.  The body field layout is an open sub-item
  of #N.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: RESERVED
        source: qxdm_itemtype_list_zukgit_2025_04_03 (authority: community)
    aliases: (none recorded)

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# Layout constants
# ---------------------------------------------------------------------------

HEADER_SIZE = 16
GPS_SLOT_SIZE = 104
GLO_SLOT_SIZE = 16

SIG_GPS = 0xA163
SIG_GLONASS = 0xA10B

# Size table: payload_size -> (num_gps_slots, num_glo_slots)
_SIZE_TABLE: dict[int, tuple[int, int]] = {
    536:  (5, 0),
    848:  (8, 0),
    1136: (8, 18),
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class GnssFixReportSlot:
    """One per-channel tracking slot in a 0x19DE record.

    Body bytes other than ``slot_state`` and ``prn_like`` are preserved
    raw pending further RE — see module docstring for the active/inactive
    slot classification and why a single cross-capture body offset map
    has not held yet.
    """
    slot_id: int          # 1-based ME tracking channel number (NOT a PRN)
    signature: int        # 0xA163 = GPS, 0xA10B = GLONASS
    body_raw: bytes       # 100 B for GPS, 12 B for GLONASS
    # Last byte of the body.  For GPS slots this is the tracking-slot
    # state enum (body_raw[99]); observed values {0, 1, 2, 5, 8} across
    # the 4-capture RE corpus.  For GLONASS slots this is body_raw[11]
    # — in the current corpus always 0 so the "state enum" role is
    # unverified for GLONASS.
    slot_state: int = 0
    # First byte of the body (body_raw[0] for GPS, [0] for GLONASS).
    # **Firmware-specific semantics.**  Originally decoded as a PRN-like
    # field on a 7-capture / 2094-active-slot corpus that happened to
    # include RM520NGL **a08** firmware records emitting PRN-magnitude
    # values {22, 25, 31, 37, 43, 50, 52} on active states {3, 4, 6}.
    # Subsequent rtcm-revisit pass (#N session ``5d3a``) extended the
    # corpus with 5 splitter-paired LG290P captures (5,381 records /
    # 9,476 active GPS slots) and used the LG290P MSM7 truth to falsify
    # the "PRN-like" claim on every other firmware: rm520ngl_a03,
    # em9190 SWIX55C 17.04 + 17.09, rm500q, and fn980m all emit
    # small-integer body[0] values (range {0..6}) that do **not**
    # correlate with the LG290P-visible GPS PRN set during the same
    # capture window.  On rm520ngl_a03 lg290p 04-21, ``(state=3,
    # body[0]=6)`` appeared in 638/638 records — a per-record constant
    # masquerading as a slot field.
    #
    # Conclusion: ``prn_like`` is a faithful copy of ``body[0]`` whose
    # interpretation as a satellite identifier is **only valid on
    # RM520NGL a08 firmware** in this corpus.  Consumers must not treat
    # this field as a PRN without first verifying the firmware-specific
    # encoding.  Kept name for backward-compatibility; consider it the
    # raw byte until a firmware-aware decoder is wired in.
    prn_like: int = 0
    # Count of non-zero body bytes.  Cheap "data density" proxy used by
    # the active-slot classifier and by offline RE tooling.
    body_nonzero_count: int = 0
    # body[0:4] interpreted as u32 LE — per-chipset "body sub-type"
    # prefix that clusters cleanly on a 2026-04-21p 776-record / 949-
    # active-slot corpus scan.  Observed top equivalence classes on
    # dense GPS slots (body_nonzero_count >= 10, 470 records):
    #
    #   0x00000000  236×  em9190 SWIX55C_03.17.04 (all-zero prefix;
    #                     slot populated only in later bytes)
    #   0x00020206   56×  rm520ngl_a03  (bytes 06 02 02 00)
    #   0x00050334   36×  rm520ngl_a08  (bytes 34 03 05 00)
    #   0x00030116   23×  rm520ngl_a08  (bytes 16 01 03 00)
    #   0x38..3a010000  7× each  em9190 SWIX55C_03.17.09
    #                     (bytes 00 00 01 0x38/0x39/0x3a — byte[3]
    #                     is monotonic, consistent with a rolling
    #                     counter rather than a type tag)
    #
    # The u32 is 0 on dormant / non-tracking slots (body_nonzero_count
    # < 10), so consumers should check ``is_active`` first before
    # interpreting this field.  Exact semantics (signal ID, band mask,
    # measurement type) are **unverified** without Qualcomm source
    # reference — exposed as an integer to let downstream code cluster
    # records without making unjustified naming claims.
    body_subtype_prefix_u32: int = 0

    # Slot states under which the original (a08-firmware-specific)
    # ``prn_like`` heuristic deemed body[0] a plausible PRN.  Retained
    # for backward-compatibility but **does not generalize** — see the
    # ``prn_like`` field comment for the rtcm-revisit `5d3a` (#N)
    # finding that body[0] is firmware-dependent and only encodes
    # PRN-magnitude values on RM520NGL a08 firmware in this corpus.
    PRN_ACTIVE_STATES = frozenset({3, 4, 6, 8})

    @property
    def constellation(self) -> str:
        if self.signature == SIG_GPS:
            return 'gps'
        if self.signature == SIG_GLONASS:
            return 'glonass'
        return f'unknown_0x{self.signature:04x}'

    @property
    def is_active(self) -> bool:
        """Whether this slot is an 'active' tracking channel on this record.

        A slot is active iff ``slot_state != 0`` (body_raw's last byte,
        offset 99 for GPS / 11 for GLONASS).  SDX55 GPS captures exhibit
        a single active slot per record; SDX65 GPS captures exhibit four.
        GLONASS slots follow the same state-byte convention with a single
        observed non-zero sample (slot_id=15, state=2) — see module
        docstring.
        """
        return self.slot_state != 0

    @property
    def prn_like_is_plausible(self) -> bool:
        """**Firmware-conditional, not universal.**  Returns True iff
        ``slot_state`` is in the original ``PRN_ACTIVE_STATES`` set
        {3, 4, 6, 8}.  The rtcm-revisit `5d3a` pass (#N) showed this
        heuristic only correctly predicts a PRN-magnitude ``prn_like``
        on RM520NGL a08 firmware; on a03, em9190 17.04+17.09, rm500q,
        and fn980m the same active states emit small-integer body[0]
        values (0..6) that LG290P MSM7 truth confirms are NOT GPS PRNs.
        Consumers should treat the field as advisory pending a
        firmware-aware decoder.
        """
        return self.slot_state in self.PRN_ACTIVE_STATES

    def to_dict(self) -> dict[str, Any]:
        return {
            'slot_id': self.slot_id,
            'signature': self.signature,
            'constellation': self.constellation,
            'body_len': len(self.body_raw),
            'slot_state': self.slot_state,
            'prn_like': self.prn_like,
            'prn_like_is_plausible': self.prn_like_is_plausible,
            'body_nonzero_count': self.body_nonzero_count,
            'body_subtype_prefix_u32': self.body_subtype_prefix_u32,
            'is_active': self.is_active,
        }


@dataclass
class Diag0x19DE:
    """Parsed 0x19DE ME per-channel tracking-state array.

    Original QCA canonical label: ``GNSS_ME_GNSS_FIX_REPORT`` (misleading
    — the payload carries no lat/lon/alt; it's a per-channel tracking-state
    array from the Measurement Engine).  Renamed per #N; kept grep-able
    here so downstream searches still resolve.  See module docstring for
    the RE journal.
    """
    log_time: int
    version: int               # header byte 0 — always 1 on observed data
    total_slots: int           # header byte 1
    tick: int                  # header u32 @8 — free-running 32-bit tick
    header_word3: int          # header u32 @12 — per-capture constant on
                               # 3/4 RE corpus captures (27, 1, 1) and
                               # varies 8..9 on rm520ngl_a03.  Likely a
                               # config/bitfield word; semantics unverified.
    payload_size: int
    num_gps_slots: int
    num_glo_slots: int
    slots: list[GnssFixReportSlot] = field(default_factory=list)

    @property
    def size_variant(self) -> str:
        return f'{self.payload_size}B'

    @property
    def active_gps_slots(self) -> list[GnssFixReportSlot]:
        """Return GPS slots with ``slot_state != 0``.

        Empirically the RE corpus shows at most one active GPS slot per
        record, but the parser does not enforce that invariant — the
        property returns a list to remain honest about what might be in
        future captures.
        """
        return [s for s in self.slots if s.signature == SIG_GPS and s.is_active]

    @property
    def active_glonass_slots(self) -> list[GnssFixReportSlot]:
        """Return GLONASS slots with ``slot_state != 0``.

        Uses the same rule as ``active_gps_slots`` — body_raw's last byte
        is a state enum.  In the current RE corpus only slot_id=15 on
        rm520ngl_a03 exhibits a non-zero state (state=2).
        """
        return [s for s in self.slots
                if s.signature == SIG_GLONASS and s.is_active]

    def to_dict(self) -> dict[str, Any]:
        # Segregate GPS and GLONASS slot lists for easier consumer traversal.
        gps_slots = [s.to_dict() for s in self.slots if s.signature == SIG_GPS]
        glo_slots = [s.to_dict() for s in self.slots if s.signature == SIG_GLONASS]
        unknown_slots = [s.to_dict() for s in self.slots
                         if s.signature not in (SIG_GPS, SIG_GLONASS)]
        out: dict[str, Any] = {
            'type': 'Diag0x19DE',
            'log_time': self.log_time,
            'version': self.version,
            'total_slots': self.total_slots,
            'tick': self.tick,
            'header_word3': self.header_word3,
            'payload_size': self.payload_size,
            'size_variant': self.size_variant,
            'num_gps_slots': self.num_gps_slots,
            'num_glo_slots': self.num_glo_slots,
            'num_active_gps_slots': len(self.active_gps_slots),
            'num_active_glonass_slots': len(self.active_glonass_slots),
            'gps_slots': gps_slots,
            'glonass_slots': glo_slots,
        }
        if unknown_slots:
            out['unknown_slots'] = unknown_slots
        return out


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _parse_slot(data: bytes, off: int, slot_size: int) -> GnssFixReportSlot:
    slot_id = data[off]
    signature = unpack_from('<H', data, off + 2)[0]
    body = bytes(data[off + 4:off + slot_size])
    slot_state = body[-1] if body else 0
    prn_like = body[0] if body else 0
    nz = sum(1 for b in body if b)
    subtype_prefix = unpack_from('<I', body, 0)[0] if len(body) >= 4 else 0
    return GnssFixReportSlot(
        slot_id=slot_id,
        signature=signature,
        body_raw=body,
        slot_state=slot_state,
        prn_like=prn_like,
        body_nonzero_count=nz,
        body_subtype_prefix_u32=subtype_prefix,
    )


# Ground-truth recipe (#N). RM520N-GL emits v=1 (both a05 848B GPS-only and
# a03 1136B GPS+GLONASS in the RE corpus). This is a DISCOVERY design with three
# documented honesty traps baked into the field_map: (1) slot_id is an ME channel
# number, NOT a PRN; (2) prn_like only encodes a real GPS PRN on RM520NGL a08
# firmware — on the house-default a03 and every other firmware the #N
# rtcm-revisit pass falsified the PRN claim against LG290P MSM7 truth; (3)
# slot_state is an unverified enum. The cleanly-groundable surface is the COUNT
# of active tracking channels vs the GSV/GSA tracked-SV count.

@register(
    0x19DE, domain="gnss",
    name="0x19DE",
    description=(
        "ME per-channel tracking state array (16B header + N×GPS[104B] + "
        "M×GLONASS[16B]).  Supports the 536B (5 GPS), 848B (8 GPS), and "
        "1136B (8 GPS + 18 GLO) variants.  Exposes slot_state (GPS body "
        "last byte) + body_nonzero_count + is_active to drive the "
        "active-slot / inactive-slot classification from #N; the rest "
        "of the body is held as body_raw pending denser, cross-capture "
        "corpus.  QCA canonical label: GNSS_ME_GNSS_FIX_REPORT "
        "(misleading — renamed per #N)."
    ),
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from EM9190 SWIX55C + RM500Q + RM520N-GL "
        "A01A05/A03A03 (#N); 2026-04-21 extended to 7-capture corpus "
        "(342 records / 2094 GPS slots) — added prn_like (body[0]) "
        "decoded on active-tracking slot_states {3,4,6,8} (#N); "
        "2026-04-21p v5 extended to 9-capture corpus (776 records / "
        "949 active slots) — added body_subtype_prefix_u32 (body[0:4] "
        "LE) exposing per-chipset equivalence classes including "
        "rm520ngl_a03/0x00020206 (56×), rm520ngl_a08/0x00050334 (36×), "
        "0x00030116 (23×), and em9190_17.09 monotonic 0x00000138-0x0000013a; "
        "2026-05-02 v6 rtcm-revisit `5d3a` (#N) — splitter-paired LG290P "
        "MSM7 truth on 5,381 records / 9,476 active GPS slots falsified "
        "the prn_like-as-PRN claim on every firmware except RM520NGL a08; "
        "docstring + prn_like_is_plausible reframed as firmware-conditional. "
        "Confirmed 0x19DE structurally carries only GPS+GLONASS even with "
        "Galileo+BeiDou+E6 RF active in the same window. "
        "v7 (2026-05-07, #N) populates registry metadata "
        "(fields_identified/fields_parsed/issues/field_invariants) per "
        "the closed-issue audit (#N follow-up) — no parser logic "
        "change; covered by 5-chipset fixture suite (em9190/fn980/"
        "rm500q/rm520ngl_a05/rm520ngl_a08), 28 tests."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Top-level structural fields parsed from the 16B header + slot
    # dispatcher: version, total_slots, tick, header_word3, payload_size,
    # num_gps_slots, num_glo_slots, slots. Per-slot fields (slot_id,
    # signature, slot_state, prn_like, body_nonzero_count,
    # body_subtype_prefix_u32, body_raw) are tracked under the slots[]
    # array but not double-counted at the record level.
    fields_identified=8,
    fields_parsed=8,
    field_invariants={
        # version byte is 1 across the entire RE corpus; non-1 records
        # would land in the registry's no-parser fallback.
        "version": {"enum": [1]},
        # Three confirmed payload sizes covering all observed slot
        # configurations; size dispatch enforces this.
        "payload_size": {"enum": [536, 848, 1136]},
        # total_slots = num_gps_slots + num_glo_slots — enforced by
        # parse_0x19de which returns None on mismatch.
        "total_slots": {"enum": [5, 8, 26]},
        # GPS-slot array is always populated for valid records — the size
        # table guarantees ≥5 GPS slots on every accepted size variant.
        # NOTE: the invariant name must match a to_dict() key, NOT the
        # dataclass field name. The dataclass has a single `slots` field
        # that to_dict() segregates into `gps_slots` and `glonass_slots`
        # arrays for downstream consumer convenience. Declaring this
        # against `slots` (the dataclass field) caused a 100% false-
        # positive violation rate in the 2026-05-10 corpus sweep — the
        # invariant checker uses to_dict() output, where `slots` doesn't
        # exist. (#N follow-up to v7 audit.)
        "gps_slots": {"required_populated": True},
    },
)
def parse_0x19de(log_time: int, data: bytes) -> Diag0x19DE | None:
    """Parse a 0x19DE ME tracking-state payload (QCA label: LOG_GNSS_ME_GNSS_FIX_REPORT).

    Returns ``None`` on malformed input (too short, unsupported size, or
    header inconsistent with the size table).  See module docstring for
    the full layout.
    """
    sz = len(data)
    if sz < HEADER_SIZE:
        return None

    # Explicit version gate — every byte-offset, size dispatch, and slot
    # signature in this parser assumes the v=1 layout. A future v=2
    # record could ship a different struct under the same 536/848/1136
    # payload size; without this gate it would silently mis-parse.
    # Layer-2 field_invariants surface the drift in audit reports but
    # don't return None at parse time (see registry.check_invariants).
    if data[0] != 1:
        return None

    # Size dispatch — known variants only.
    if sz not in _SIZE_TABLE:
        return None
    num_gps_slots, num_glo_slots = _SIZE_TABLE[sz]
    expected_size = HEADER_SIZE + num_gps_slots * GPS_SLOT_SIZE + num_glo_slots * GLO_SLOT_SIZE
    if expected_size != sz:
        return None  # defensive — should be impossible given the table

    version = data[0]
    total_slots = data[1]
    tick = unpack_from('<I', data, 8)[0]
    header_word3 = unpack_from('<I', data, 12)[0]

    # Sanity: total_slots in header should equal num_gps_slots + num_glo_slots.
    # If it doesn't, the record is still parseable but we flag it by
    # returning None to avoid silent misinterpretation.
    if total_slots != num_gps_slots + num_glo_slots:
        return None

    slots: list[GnssFixReportSlot] = []
    off = HEADER_SIZE
    for _ in range(num_gps_slots):
        slots.append(_parse_slot(data, off, GPS_SLOT_SIZE))
        off += GPS_SLOT_SIZE
    for _ in range(num_glo_slots):
        slots.append(_parse_slot(data, off, GLO_SLOT_SIZE))
        off += GLO_SLOT_SIZE

    return Diag0x19DE(
        log_time=log_time,
        version=version,
        total_slots=total_slots,
        tick=tick,
        header_word3=header_word3,
        payload_size=sz,
        num_gps_slots=num_gps_slots,
        num_glo_slots=num_glo_slots,
        slots=slots,
    )
