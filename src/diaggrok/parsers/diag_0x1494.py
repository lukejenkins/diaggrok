"""0x1494 — Large GNSS constellation data.

Two grounded on-wire versions (byte 0):

  * **v0x01** — the main fleet (Quectel / Sierra / Telit / Inseego /
    SIMCom; 1134B & 3038B bodies, 17-byte slot stride). Documented in full
    below; this is the dominant version (172k+ records).
  * **v0x00** — the Sierra MC7700 (SWI9200X / MDM9200-era) format: a
    fixed 558B body with a 16-byte slot stride at offset 48. 6 captures /
    805 records, grounded against sibling 0x1477 at 99.8% az/el match.
    See `Slot1494V0` and `_parse_v0x00`. Any other byte-0 is rejected
    (foreign payload).

--- v0x01 body (below) ---

Bytes 1..2 (v0x01) split by chipset family:

    | (b1, b2)     | records | %      | chipset family                        |
    |--------------|--------:|-------:|---------------------------------------|
    | (0xa3, 0x0d) |  42,798 | 98.0 % | Quectel / Sierra / Telit / Inseego — every observed chipset except SIMCom |
    | (0x89, 0x13) |     876 |  2.0 % | SIMCom SIM7600NA (MDM9x07) — 6 captures, exclusive  |

Every SIM7600NA capture emits `(0x89, 0x13)`, and no other chipset does.
Exposed downstream via `type_hi` / `type_lo` in `to_dict()` so consumers
can distinguish the two format families.

Body sizes observed: 1134B (MDM9x07/SDX20/SDX20 V2/MDM9650), 3038B
(SDX55/SDX62/MDM9x30/MDM9x40).

Slot table (validated on RM520N-GL SDX62 captures):
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
                                  295-epoch per-PRN scans.
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
                                  vs 0x1477 truth).
                                  Meaningful only when slot[N-1] was
                                  active_flag=0xFFFF.
    [9:11]   u16 LE reserved (always 0 across all 2,814+ active GPS
                                  sig=0x04 slots, 1,992 GLONASS sig=0x04,
                                  909 GPS sig=0x01, 296 SBAS sig=0x01,
                                  295 SBAS sig=0x04, 45 GLONASS sig=0x01
                                  in two RM520N-GL captures; inactive
                                  slots may carry non-zero values)
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
    [16]     u8  prn — the modem's PRN convention:
                           1..32   = GPS
                           65..96  = GLONASS (PRN - 64 = slot)
                           120..138= SBAS
                           (others observed: BeiDou / Galileo / NavIC ranges
                            pending verification)

Slot classes observed in RM520N-GL captures (filtered to
active_flag=0xFFFF):
  - (GPS, sig=0x04)     ~9.5 slots/rec  — primary L1 C/A measurements
  - (GLONASS, sig=0x04) ~6.8 slots/rec  — primary GLONASS L1
  - (GPS, sig=0x01)     ~3.1 slots/rec  — GPS secondary channel
                                          (state_lo16=0, state_hi16
                                          clustered around -515; NOT
                                          per-band measurement data)
  - (SBAS, sig=0x01)    ~1.0 slots/rec  — SBAS secondary
  - (SBAS, sig=0x04)    ~1.0 slots/rec  — SBAS primary (PRN 133)
  - (GLONASS, sig=0x01) ~0.2 slots/rec  — GLONASS secondary (rare)

There is only one (GPS, sig=0x04) class, with ~9.5 active slots per
record; mixed-constellation slot interleaving does not form a duplicated
band block, and the table carries no second-band (L1C/B1C) measurement
data.

The 1134B variant on older chipsets (MDM9x07/SDX20/MDM9650) shares the
same version byte (`byte+0 = 0x01`) and (type_hi, type_lo) pair as the
3038B family — so it is NOT a different "version" in the strict
byte+0 sense. It is a body-layout variant at the same version.

The 1134B body does not follow the 17-byte stride at any tested offset
(active_flag=0xFFFF density ≤0.5% on 1134B vs ~12.5% on 3038B at the
canonical offset 47). It is overwhelmingly 0x00 padding (~74% of slot
bytes) with sparse non-zero content that does not follow the per-tracker-
channel layout, and is left undecoded.

No header byte discriminates the body layouts. Bytes [18:22] read 00*4 on
1134B LM960/EG25-G records and ff*4 or ff_ef_ff_f7 on some 3038B records,
but FN980 SDX55 emits 3038B records with bytes[18:22] = 00*4 — the same
value as 1134B records — and carries the `ffffffff` magic at a different
offset (bytes[26:30]). No single byte position within the 47-byte header
reliably discriminates the body layouts across chipsets. The parser
therefore uses size-only (`len == 3038`) to gate slot decoding; on
"compact-body 3038B" FN980 records the slot walk produces 175
all-zero/empty slots (PRN=0, sig_type=0, EMPTY constellation) — correct
behaviour, not a mis-decode, but downstream consumers wanting "populated
records only" should filter on
`any(s.active_flag == 0xFFFF for s in result.slots)`.

Log name: LOG_GNSS_PDSM_EXT_STATUS_MEAS_REPORT_C
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


_SLOT_STRIDE = 17
_SLOT_TABLE_OFFSET = 47

# v0x00 (Sierra MC7700 / SWI9200X / MDM9200-era) uses a distinct, more
# compact body: a fixed 558 B record with a 16-byte-stride slot table at
# offset 48 (vs v0x01's 17-byte stride at 47). Grounded against the sibling 0x1477 GPS-measurement report at 99.8 %
# az/el match across 4,314 primary-GPS slots in two MC7700 runs.
_SLOT_STRIDE_V0 = 16
_SLOT_TABLE_OFFSET_V0 = 48
_PAYLOAD_SIZE_V0 = 558
# v0x01 body classes: 1134 B (undecoded) and 3038 B (slot table).
_V01_COMPACT_SIZE = 1134
_V01_SLOT_TABLE_SIZE = 3038


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
        reproducible across boot sessions on the same hardware. Semantics
        not yet decoded.
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
        class.
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
class Slot1494V0:
    """Per-tracker-channel slot from the 0x1494 **v0x00** body (16 bytes).

    v0x00 is the Sierra MC7700 (SWI9200X / MDM9200-era) format — a fixed
    558 B record whose 16-byte slot table sits at offset 48. Like v0x01,
    the slot's az/el are a **channel-rotation cache** of the *previous*
    slot's SV (a debug artifact), NOT this slot's own position. Grounded
    against the sibling 0x1477 GPS-measurement report:
    `prev_az_deg` @ [5:7] and `prev_el_deg` @ [9:11] match 0x1477's
    integer-floored az/el at **99.8 %** across 1,869 paired primary-GPS
    slots / 300 epochs on one run and 99.2 % / 2,445 slots on another. 0x1477 is
    itself MSM7-RTCM-validated in the same capture (0.64 dB mean C/No
    error vs an LG290P reference). Slot layout (offsets within slot):

        [0]      u8  flag — 0x01 on active primary slots.
        [1:5]    i32 field_1_5 — per-channel value, range 9..106; NOT
                                 C/No (Pearson r=0.03 vs 0x1477 cno on
                                 2,146 slots). Exposed raw / CANDIDATE.
        [5:7]    u16 prev_az_deg — integer-degrees azimuth of slot[N-1]'s
                                   PRN (99.8 % vs 0x1477; meaningful only
                                   when slot[N-1] was an active primary).
        [7:9]    u16 reserved (0 across all validated slots).
        [9:11]   u16 prev_el_deg — integer-degrees elevation of slot[N-1]'s
                                   PRN (99.8 % vs 0x1477).
        [11:13]  u16 reserved (0 across all validated slots).
        [13]     u8  sig_type — 0x04 primary, 0x01 secondary, 0x00 empty
                                (same convention as v0x01).
        [14]     u8  prn — the modem's PRN convention (GPS 1..32, GLONASS
                           65..96, SBAS 120..138).
        [15]     u8  trailing_15 — per-slot trailing byte, semantics
                                   pending (exposed raw).

    The header seed at byte [46] carries the PRN whose az/el land in
    slot 0's prev_az/prev_el (the rotation chain's first link) — e.g. in
    the reference record byte[46]=0x02 and slot0.prev_az_deg=313 ==
    0x1477's PRN-2 azimuth (313.6°).
    """
    slot_index: int
    prn: int
    sig_type: int
    prev_az_deg: int    # u16 LE @ [5:7] — slot[N-1]'s az (integer degrees)
    prev_el_deg: int    # u16 LE @ [9:11] — slot[N-1]'s el (integer degrees)
    field_1_5: int      # i32 LE @ [1:5] — per-channel value, NOT cno; raw
    reserved_7_9: int   # u16 LE @ [7:9]
    reserved_11_13: int # u16 LE @ [11:13]
    trailing_15: int    # u8  @ [15]
    flag_0: int         # u8  @ [0]

    @property
    def constellation(self) -> str:
        p = self.prn
        if 1 <= p <= 32: return 'GPS'
        if 65 <= p <= 96: return 'GLONASS'
        if 120 <= p <= 138: return 'SBAS'
        if p == 0: return 'EMPTY'
        return 'OTHER'

    def to_dict(self) -> dict[str, Any]:
        return {
            'slot_index': self.slot_index,
            'prn': self.prn,
            'sig_type': self.sig_type,
            'constellation': self.constellation,
            'prev_az_deg': self.prev_az_deg,
            'prev_el_deg': self.prev_el_deg,
            'field_1_5': self.field_1_5,
            'reserved_7_9': self.reserved_7_9,
            'reserved_11_13': self.reserved_11_13,
            'trailing_15': self.trailing_15,
            'flag_0': self.flag_0,
        }


@dataclass
class Diag0x1494:
    """Large GNSS constellation data (0x1494)."""
    log_time: int
    version: int       # byte 0 — 0x01 (main fleet) or 0x00 (Sierra MC7700 / MDM9200)
    type_hi: int | None  # byte 1 — v0x01: 0xa3 (default family) / 0x89 (SIMCom). None for v0x00 (byte1=0x29 is not the v0x01 discriminator).
    type_lo: int | None  # byte 2 — v0x01: 0x0d (default family) / 0x13 (SIMCom). None for v0x00 (byte2=0x23).
    counter: int       # byte 5 — varies (5-40 on SDX55, 12-15 on SDX20 V2, 7-13 on MC7700 v0x00)
    payload_size: int
    slots: list[Slot1494 | Slot1494V0] = field(default_factory=list)
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
    description="Large GNSS constellation data (0x1494) — per-tracker-channel slot table; v0x01 (17B slots, 1134/3038B) + v0x00 (16B slots, 558B Sierra MC7700)",
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. v0x01 (FN980m SDX55, EG18-NA SDX20 V2, RM520N-GL SDX62, SIMCom "
        "SIM7600NA): bytes 1..2 separate the default (0xa3, 0x0d) family from the "
        "SIMCom-exclusive (0x89, 0x13) pair. The 3038 B body carries a 175 x 17 B slot table at "
        "offset 47: state_value @ [1:5], active_flag @ [5:7], prev_az_deg @ [7:9], prev_el_deg "
        "@ [11:13], sig_type @ [15], prn @ [16]. prev_az/prev_el are a channel-rotation cache of "
        "the previous slot's SV and match 0x1477 az/el at 100% across 6,329 paired primary-GPS "
        "slots in two RM520N-GL SDX62 captures. Only ~12.5% of slots carry active_flag 0xFFFF; "
        "the rest hold 200+ distinct non-binary values (uninitialized memory). reserved_9_11 / "
        "reserved_13_15 are zero across all six active-slot classes (GPS/GLONASS/SBAS at "
        "sig=0x04 and sig=0x01). state_value does not correlate with any 0x1477 field at "
        "Pearson |r| > 0.4; it is exposed raw with derived state_hi16 / state_lo16. The 1134 B "
        "body does not follow the 17 B stride at any tested offset and is left undecoded. No "
        "header byte discriminates the body layouts across firmware (FN980 SDX55 3038 B records "
        "carry 00*4 at bytes[18:22] like 1134 B records, with the ffffffff magic at "
        "bytes[26:30]), so slot decoding is gated on size alone; FN980 3038 B records decode to "
        "175 empty slots, and consumers wanting populated records only should filter on "
        "any(s.active_flag == 0xFFFF for s in result.slots). "
        "v0x00 (Sierra MC7700, SWI9200X / MDM9200-era): a fixed 558 B body with a 16-byte-stride "
        "slot table at offset 48 and its own (byte1, byte2) = (0x29, 0x23) header pair "
        "(type_hi/type_lo left None so the v0x01 chipset-discriminator invariants are not "
        "misapplied). prev_az_deg @ [5:7] and prev_el_deg @ [9:11] match the sibling 0x1477 "
        "GPS-measurement report at 99.8% (1,869 slots / 300 epochs) and 99.2% (2,445 slots) "
        "integer-floored az/el on two runs; 0x1477 is itself MSM7-RTCM-validated in the same "
        "capture (0.64 dB mean C/No error vs an LG290P reference). field_1_5 @ [1:5] is exposed "
        "raw (per-channel value, range 9-106, not C/No: r=0.03). "
        "Truncated payloads return None (registry WARN): v0x00 shorter than 558 B, and v0x01 "
        "shorter than 3038 B unless exactly 1134 B. Corpus v0x01 sizes are 1134 B (102,563) and "
        "3038 B (177,144) plus two one-off records (204 B, 2749 B) that are rejected; payloads "
        "longer than 3038 B are accepted."
    ),
    source_url="",
    field_invariants={
        "version": {"enum": [0x00, 0x01]},
        "type_hi": {"enum": [0xa3, 0x89]},
        "type_lo": {"enum": [0x0d, 0x13]},
        "payload_size": {"enum": [558, 1134, 3038]},
    },
)
def parse_0x1494(log_time: int, data: bytes) -> Diag0x1494 | None:
    if len(data) < 8:
        return None
    # Layer-1 version gate: byte[0] is the version subfield. Two versions
    # are grounded — 0x01 (the main fleet, 1134B/3038B) and 0x00 (Sierra
    # MC7700 / SWI9200X / MDM9200-era, fixed 558B).
    # Reject any other byte-0 as a foreign payload before structural decode.
    version = data[0]
    if version not in (0x00, 0x01):
        return None
    if version == 0x00:
        # v0x00 is a fixed 558 B record; a shorter one is truncated — return None (registry WARN), not a slot-less record.
        if len(data) < _PAYLOAD_SIZE_V0:
            return None
        return _parse_v0x00(log_time, data)
    # v0x01 has two body classes, 1134 B and the 3038 B slot-table body (47 B
    # header + 175 x 17 B slots + 16 B tail). The 1134 B body is undecoded, so
    # a byte lost from it changes no field: only its length can tell. Below
    # 3038 B, exactly 1134 B is a record and anything else is truncated (a cut
    # 1134 B or 3038 B record) — return None (registry WARN) instead of a
    # silently shorter body_raw / skipped slot table.
    if len(data) < _V01_SLOT_TABLE_SIZE and len(data) != _V01_COMPACT_SIZE:
        return None
    slots: list[Slot1494 | Slot1494V0] = []
    # Slot table only validated on the 3038B SDX55+/SDX62 body.  The 1134B
    # body does NOT use the 17B stride at any tested offset and is left
    # undecoded.  Note: this is a SIZE-based gate, not a header-byte gate —
    # a bytes[18:22] discriminator is firmware-dependent (FN980 SDX55 emits 3038B records
    # with bytes[18:22] = 00 00 00 00 same as 1134B records, while RM520N-GL
    # emits ff ff ff ff or ff ef ff f7 there).  The 17B-stride decode is still
    # applied uniformly to all 3038B records; on FN980-style "compact-body
    # 3038B" records the result is 175 all-zero slots (no spurious PRNs),
    # which is correct behaviour but a downstream consumer may want to gate
    # on `any(s.active_flag == 0xFFFF for s in result.slots)` to detect
    # genuinely-populated records.
    if len(data) >= _SLOT_TABLE_OFFSET + _SLOT_STRIDE and len(data) == _V01_SLOT_TABLE_SIZE:
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


def _parse_v0x00(log_time: int, data: bytes) -> Diag0x1494:
    """Decode the Sierra MC7700 v0x00 body (fixed 558 B, 16-byte slots).

    16-byte slot table at offset 48; header carries a distinct
    (byte1, byte2) = (0x29, 0x23) pair that is NOT the v0x01 chipset
    discriminator, so `type_hi`/`type_lo` are left None (invariant check
    skips None fields). Grounded against 0x1477 — see `Slot1494V0`.
    """
    slots: list[Slot1494 | Slot1494V0] = []
    # Slot decoding is gated on the fixed v0x00 size (558B). A truncated
    # record never reaches here (parse_0x1494 returns None); on an
    # oversized v0x00 record the table is simply skipped rather than mis-walked.
    if len(data) == _PAYLOAD_SIZE_V0:
        start = _SLOT_TABLE_OFFSET_V0
        idx = 0
        while start + _SLOT_STRIDE_V0 <= len(data):
            s = data[start:start + _SLOT_STRIDE_V0]
            slots.append(Slot1494V0(
                slot_index=idx,
                prn=s[14],
                sig_type=s[13],
                prev_az_deg=unpack_from('<H', s, 5)[0],
                prev_el_deg=unpack_from('<H', s, 9)[0],
                field_1_5=unpack_from('<i', s, 1)[0],
                reserved_7_9=unpack_from('<H', s, 7)[0],
                reserved_11_13=unpack_from('<H', s, 11)[0],
                trailing_15=s[15],
                flag_0=s[0],
            ))
            start += _SLOT_STRIDE_V0
            idx += 1
    return Diag0x1494(
        log_time=log_time,
        version=data[0],
        type_hi=None,   # v0x00 byte1=0x29 is not the v0x01 (type_hi) discriminator
        type_lo=None,   # v0x00 byte2=0x23 is not the v0x01 (type_lo) discriminator
        counter=data[5],
        payload_size=len(data),
        slots=slots,
        body_raw=data[8:],
    )
