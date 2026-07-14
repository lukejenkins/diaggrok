"""0x1494 — Large GNSS constellation data.

Split from gnss_nav_db.py per #N tier-3.

Byte 0 (version) is corpus-wide invariant 0x01. Bytes 1..2 split by
chipset family:

    | (b1, b2)     | records | %      | chipset family                        |
    |--------------|--------:|-------:|---------------------------------------|
    | (0xa3, 0x0d) |  42,798 | 98.0 % | Quectel / Sierra / Telit / Inseego — all observed Qualcomm chipsets except SIMCom |
    | (0x89, 0x13) |     876 |  2.0 % | SIMCom SIM7600NA (MDM9x07) — 6 captures, exclusive  |

The (0x89, 0x13) minority was missed in the 2026-04-12 RE because the
original sample was FN980m + EG18-NA only (both Qualcomm-default
family). The 2026-05-11 corpus walk surfaced the SIMCom-exclusive
byte-pair: every SIM7600NA capture emits `(0x89, 0x13)`, and no other
chipset does. Exposed downstream via `type_hi` / `type_lo` in
`to_dict()` so consumers can distinguish the two format families.

Body sizes observed: 1134B (MDM9x07/SDX20/SDX20 V2/MDM9650), 3038B
(SDX55/SDX62/MDM9x30/MDM9x40).

Slot table (v3, RM520N-GL SDX62 R03A03 RE, #N + #N follow-up #N,
refined v4 by <redacted-ref> follow-up):
the 3038B body holds a 175-entry × 17B per-tracker-channel slot table
starting at offset 47. Each slot encodes:

    [0]      u8  reserved (always 0 across all observed records)
    [1:5]    i32 LE state_value — per-tracker-channel opaque state cache.
                                  Decomposes into:
                                    state_hi16 (i16 high) — per-PRN
                                      baseline, stable within one boot
                                      session, partially reproducible
                                      across boot sessions (1/6 GPS
                                      sig=0x04 PRNs exact-match, 3/6
                                      within ±5 LSB cross-run on
                                      RM520N-GL). For sig=0x01 slots,
                                      clustered around -510 with small
                                      flicker; not a per-PRN identity
                                      for that class.
                                    state_lo16 (u16 low) — per-PRN
                                      slow-drifting value (std ~5-40 LSBs
                                      for stable PRNs); ALWAYS ZERO for
                                      sig=0x01 slots across 1,250+ slots
                                      sampled, so the i32 framing is
                                      essentially i16 padded with zeros
                                      for sig=0x01.
                                  NOT correlated with any 0x1477 field
                                  (cno, az/el, Doppler, multipath,
                                  pseudorange) at Pearson |r| > 0.4 on
                                  295-epoch per-PRN scans (#N).
                                  Likely a tracker hardware register
                                  cache rather than a measurement.
    [5:7]    u16 LE active_flag — slot-state marker. Empirically NOT
                                  binary: 0xFFFF in only ~12.5% of slots
                                  (those carrying valid per-channel data
                                  for a tracked SV), 0x0000 in ~35%
                                  (uninitialized), and ~52% of slots
                                  carry other values (0x0001, 0x4000,
                                  0xF0FF, 0x4244, etc.) that look like
                                  uninitialized memory or different
                                  channel-state flags. Downstream
                                  consumers should filter on
                                  `active_flag == 0xFFFF` to get the
                                  set of slots carrying real per-channel
                                  data. The non-0xFFFF, non-0x0000 slots
                                  are NOT yet characterized.
    [7:9]    u16 LE prev_az_deg — integer-degrees azimuth of slot[N-1]'s
                                  PRN (channel-rotation cross-reference,
                                  100% match across 6,329 paired primary-
                                  GPS slots in two RM520N-GL run captures
                                  vs 0x1477 truth, <redacted-ref>).
                                  Meaningful only when slot[N-1] was
                                  active_flag=0xFFFF.
    [9:11]   u16 LE reserved (always 0 across all 2,814+ active GPS
                                  sig=0x04 slots, 1,992 GLONASS sig=0x04,
                                  909 GPS sig=0x01, 296 SBAS sig=0x01,
                                  295 SBAS sig=0x04, 45 GLONASS sig=0x01
                                  in run2/run3 RM520N-GL captures — the
                                  earlier "non-zero in other constellations"
                                  comment was an artifact of including
                                  inactive slots)
    [11:13]  u16 LE prev_el_deg — integer-degrees elevation of slot[N-1]'s
                                  PRN (channel-rotation cross-reference,
                                  100% match across 6,329 paired slots).
                                  Meaningful only when slot[N-1] was
                                  active_flag=0xFFFF.
    [13:15]  u16 LE reserved (always 0 in active slots, see [9:11])
    [15]     u8  sig_type — 0x04 primary signal slot, 0x01 secondary
                            signal slot, 0x00 for empty/uninitialized.
                            Other values (0x10, 0x70, 0x94, 0xAD, …)
                            occur only in non-active (active_flag != 0xFFFF)
                            slots and are likely uninitialized.
    [16]     u8  prn — Qualcomm PRN convention:
                           1..32   = GPS
                           65..96  = GLONASS (PRN - 64 = slot)
                           120..138= SBAS
                           (others observed: BeiDou / Galileo / NavIC ranges
                            pending verification)

Slot classes observed in RM520N-GL R03A03 captures (filtered to
active_flag=0xFFFF on run2):
  - (GPS, sig=0x04)     ~9.5 slots/rec  — primary L1 C/A measurements
  - (GLONASS, sig=0x04) ~6.8 slots/rec  — primary GLONASS L1
  - (GPS, sig=0x01)     ~3.1 slots/rec  — GPS secondary channel
                                          (state_lo16=0, state_hi16
                                          clustered around -515; NOT
                                          per-band measurement data)
  - (SBAS, sig=0x01)    ~1.0 slots/rec  — SBAS secondary
  - (SBAS, sig=0x04)    ~1.0 slots/rec  — SBAS primary (PRN 133)
  - (GLONASS, sig=0x01) ~0.2 slots/rec  — GLONASS secondary (rare)

The <redacted-ref> framing of a "second GPS sig=0x04 block (same SVs as
primary, different state)" was a misread of mixed-constellation slot
interleaving — there is only one (GPS, sig=0x04) class with ~9.5
active slots per record, not a duplicated band block. The L1C/B1C
measurement carrier hunt (#N) should focus elsewhere
(0x1843 / 0x1838 / 0x1886 / 0x14de or an L5 PocketSDR capture).

The 1134B variant on older chipsets (MDM9x07/SDX20/MDM9650) shares the
same version byte (`byte+0 = 0x01`) and (type_hi, type_lo) pair as the
3038B family — so it is NOT a different "version" in the strict
byte+0 sense. It is a body-layout variant at the same version.

**2026-05-21 update (#N).** 17-byte stride hypothesis on the 1134B
body is **REFUTED** at every tested offset (active_flag=0xFFFF density
≤0.5% on 1134B vs ~12.5% on 3038B at the canonical offset 47).  The
1134B body is overwhelmingly 0x00 padding (~74% of slot bytes) with
sparse non-zero content that does not follow the canonical per-tracker-
channel layout.  See #N follow-up.

A candidate header-level discriminator at bytes [18:22] (00*4 on 1134B
LM960/EG25-G captures, ff*4 or ff_ef_ff_f7 on some 3038B captures) was
**refuted** by FN980 SDX55: FN980 emits 3038B records with bytes[18:22]
= 00*4 — the same value as 1134B records — and the `ffffffff` magic
appears at a different offset (bytes[26:30]) on FN980.  No single
byte-position "invariant" within the 47-byte header reliably
discriminates the body layouts across chipsets.  The parser therefore
uses size-only (`len == 3038`) to gate slot decoding; on "compact-body
3038B" FN980 records the slot walk produces 175 all-zero/empty slots
(PRN=0, sig_type=0, EMPTY constellation) — correct behaviour, not a
mis-decode, but downstream consumers wanting "populated records only"
should filter on `any(s.active_flag == 0xFFFF for s in result.slots)`.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_GNSS_PDSM_EXT_STATUS_MEAS_REPORT_C
        source: qualcomm_diag_log_codes_h (authority: vendor_official)
    aliases:
        RESERVED
            source: qxdm_itemtype_list_zukgit_2025_04_03

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


_SLOT_STRIDE = 17
_SLOT_TABLE_OFFSET = 47


@dataclass
class Slot1494:
    """Per-tracker-channel slot from 0x1494 body (17 bytes).

    `prev_az_deg` and `prev_el_deg` cache the previous slot's az/el — a
    channel-rotation debug artifact, NOT this slot's own position. To get
    this slot's az/el, look at the NEXT slot's `prev_az_deg`/`prev_el_deg`,
    or correlate against 0x1477 by PRN.
    """
    slot_index: int
    prn: int
    sig_type: int
    state_value: int    # i32 LE @ [1:5] — per-PRN drifting state, semantics pending
    active_flag: int    # u16 LE @ [5:7] — 0xFFFF / 0x0000
    prev_az_deg: int    # u16 LE @ [7:9] — slot[N-1]'s az (integer degrees)
    reserved_9_11: int  # u16 LE @ [9:11]
    prev_el_deg: int    # u16 LE @ [11:13] — slot[N-1]'s el (integer degrees)
    reserved_13_15: int # u16 LE @ [13:15]
    reserved_0: int     # u8  @ [0] — always 0 observed

    @property
    def constellation(self) -> str:
        p = self.prn
        if 1 <= p <= 32: return 'GPS'
        if 65 <= p <= 96: return 'GLONASS'
        if 120 <= p <= 138: return 'SBAS'
        if p == 0: return 'EMPTY'
        return 'OTHER'

    @property
    def state_hi16(self) -> int:
        """High 16 bits of state_value, interpreted as signed i16.

        Per-PRN baseline that stays stable within a boot session for
        cleanly-tracked GPS sig=0x04 SVs (many PRNs hold a single
        value across all 295 epochs of a 5-minute capture). Partially
        reproducible across boot sessions on the same hardware. See
        #N for semantic-decode work in progress.
        """
        hi_u = (self.state_value >> 16) & 0xFFFF
        return hi_u - 0x10000 if hi_u >= 0x8000 else hi_u

    @property
    def state_lo16(self) -> int:
        """Low 16 bits of state_value, interpreted as unsigned u16.

        Per-PRN slow-drifting value (std ~5-40 LSBs over 295-epoch
        captures) for sig=0x04 slots. **Always zero** for sig=0x01
        slots across the validated corpus (1,250+ samples), so the
        nominal i32 is effectively i16-padded-with-zeros for that
        class. See #N.
        """
        return self.state_value & 0xFFFF

    def to_dict(self) -> dict[str, Any]:
        return {
            'slot_index': self.slot_index,
            'prn': self.prn,
            'sig_type': self.sig_type,
            'constellation': self.constellation,
            'state_value': self.state_value,
            'state_hi16': self.state_hi16,
            'state_lo16': self.state_lo16,
            'active_flag': self.active_flag,
            'prev_az_deg': self.prev_az_deg,
            'prev_el_deg': self.prev_el_deg,
            'reserved_9_11': self.reserved_9_11,
            'reserved_13_15': self.reserved_13_15,
        }


@dataclass
class Diag0x1494:
    """Large GNSS constellation data (0x1494)."""
    log_time: int
    version: int       # byte 0 — corpus-wide invariant 0x01
    type_hi: int       # byte 1 — 0xa3 (Qualcomm-default, 98.0%) or 0x89 (SIMCom SIM7600NA, 2.0%)
    type_lo: int       # byte 2 — 0x0d (Qualcomm-default, 98.0%) or 0x13 (SIMCom SIM7600NA, 2.0%)
    counter: int       # byte 5 — varies (5-40 on SDX55, 12-15 on SDX20 V2)
    payload_size: int
    slots: list[Slot1494] = field(default_factory=list)
    body_raw: bytes = b''

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1494',
            'log_time': self.log_time,
            'version': self.version,
            'type_hi': self.type_hi,
            'type_lo': self.type_lo,
            'counter': self.counter,
            'payload_size': self.payload_size,
            'slots': [s.to_dict() for s in self.slots],
        }


@register(
    0x1494, domain="gnss",
    primary_issue=None,
    name="0x1494",
    description="Large GNSS constellation data (0x1494) — per-tracker-channel slot table (#N, #N, #N, #N)",
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from FN980m SDX55 + EG18-NA SDX20 V2 (#N); v2 added SIMCom (0x89, 0x13) "
        "byte-pair discriminator from 2026-05-11 corpus walk; v3 (2026-05-21, #N follow-up #N) "
        "decoded the 17-byte slot table on the 3038B body: state_value @ [1:5], active_flag @ [5:7], "
        "prev_az_deg @ [7:9], prev_el_deg @ [11:13], sig_type @ [15], prn @ [16]. The prev_az/prev_el "
        "cross-references were validated at 100% across 6,329 paired primary-GPS slots in two RM520N-GL "
        "SDX62 R03A03 captures against 0x1477 az/el truth. v4 (2026-05-21, <redacted-ref> follow-up #N) "
        "corrected the active_flag docstring (empirically only ~12.5% of slots are 0xFFFF, the rest are "
        "uninitialized memory with 200+ distinct non-binary values), corrected the reserved-fields "
        "characterization (reserved_9_11 / reserved_13_15 are zero across all six top active-slot "
        "classes — GPS/GLONASS/SBAS at sig=0x04 and sig=0x01), and exposed state_hi16 / state_lo16 "
        "derived properties. Refuted the <redacted-ref> 'second GPS sig=0x04 block' framing — there is "
        "only one (GPS, sig=0x04) class with ~9.5 active slots/rec. state_value confirmed NOT to "
        "correlate with any 0x1477 field at Pearson |r| > 0.4. v5 (2026-05-21, #N) refuted the "
        "17B-stride hypothesis for the 1134B body at every tested offset (active_flag=0xFFFF density "
        "≤0.5% on 1134B vs ~12.5% on 3038B). Added payload_size: {enum: [1134, 3038]} invariant. "
        "An attempted bytes[18:22] header discriminator was found to be firmware-dependent (FN980 "
        "SDX55 emits 3038B records with the same 00*4 value as 1134B records, with the ffffffff "
        "magic appearing at bytes[26:30] instead) — so the parser still gates slot decoding on size "
        "alone. FN980 3038B records produce 175 all-zero/empty slots (no spurious PRNs) which is "
        "correct; downstream consumers wanting populated records only should filter on "
        "any(s.active_flag == 0xFFFF for s in result.slots)."
    ),
    source_url="",
    field_invariants={
        "version": {"enum": [0x01]},
        "type_hi": {"enum": [0xa3, 0x89]},
        "type_lo": {"enum": [0x0d, 0x13]},
        "payload_size": {"enum": [1134, 3038]},
    },
)
def parse_0x1494(log_time: int, data: bytes) -> Diag0x1494 | None:
    if len(data) < 8:
        return None
    # Layer-1 version gate (#N): byte[0] is the version invariant 0x01 —
    # corpus-wide universal across both 1134B and 3038B body classes.
    # Reject foreign payloads before structural decode.
    if data[0] != 0x01:
        return None
    slots: list[Slot1494] = []
    # Slot table only validated on the 3038B SDX55+/SDX62 body.  The 1134B
    # body has been shown NOT to use the 17B stride at any tested offset
    # (#N, 2026-05-21) and is left undecoded.  Note: this is a SIZE-based
    # gate, not a header-byte gate — an attempted bytes[18:22] discriminator
    # was found to be firmware-dependent (FN980 SDX55 emits 3038B records
    # with bytes[18:22] = 00 00 00 00 same as 1134B records, while RM520N-GL
    # emits ff ff ff ff or ff ef ff f7 there).  The 17B-stride decode is still
    # applied uniformly to all 3038B records; on FN980-style "compact-body
    # 3038B" records the result is 175 all-zero slots (no spurious PRNs),
    # which is correct behaviour but a downstream consumer may want to gate
    # on `any(s.active_flag == 0xFFFF for s in result.slots)` to detect
    # genuinely-populated records.
    if len(data) >= _SLOT_TABLE_OFFSET + _SLOT_STRIDE and len(data) == 3038:
        start = _SLOT_TABLE_OFFSET
        idx = 0
        while start + _SLOT_STRIDE <= len(data):
            s = data[start:start + _SLOT_STRIDE]
            slots.append(Slot1494(
                slot_index=idx,
                prn=s[16],
                sig_type=s[15],
                state_value=unpack_from('<i', s, 1)[0],
                active_flag=unpack_from('<H', s, 5)[0],
                prev_az_deg=unpack_from('<H', s, 7)[0],
                reserved_9_11=unpack_from('<H', s, 9)[0],
                prev_el_deg=unpack_from('<H', s, 11)[0],
                reserved_13_15=unpack_from('<H', s, 13)[0],
                reserved_0=s[0],
            ))
            start += _SLOT_STRIDE
            idx += 1
    return Diag0x1494(
        log_time=log_time,
        version=data[0],
        type_hi=data[1],
        type_lo=data[2],
        counter=data[5],
        payload_size=len(data),
        slots=slots,
        body_raw=data[8:],
    )
