"""0x14B0 — GNSS data report, 166B fixed (GPS time-tag + tagged parameter frame).

Log name: LOG_MOBISENS_OUTPUT_C
Also known as: LOG_SENSOR_MOBISENS_OUPUT
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import pack, unpack_from
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0x14B0:
    """GNSS data report (0x14B0) — 166 bytes fixed size.

    Clean-room RE across 6 DLF captures / 4 chipset generations (1514
    records total, including EM7511/MDM9650); the header time-tag is
    F3-grounded — see below.

        [0]        u8   version = 0x32 (50) — const across all captures
        [1:5]      u32  gps_ms — **GPS time of week, milliseconds**
                        (little-endian). F3-GROUND v0x32: equals the
                        firmware's own
                        ``mc_clock.c: ClockPut_GPS: FC .. Wk .. Ms <this>``
                        print on **1799/1799** co-temporal records of an
                        EG25-G (MDM9207) extended-GNSS capture
                        (e.g. ms=65920393 == F3 "Ms 65920393").
        [5:7]      u16  gps_week — **GPS week number** (little-endian).
                        F3-GROUND v0x32: equals ``mc_clock.c ClockPut_GPS
                        .. Wk <this>`` on 1799/1799 co-temporal records
                        (=2432), AND equals the capture-date calendar GPS
                        week on **16/16** F3-bearing captures spanning
                        weeks 2421..2436 and multiple chipsets (MDM9207,
                        MDM9250, EG12-GT, RM500Q, carcom-g1). Byte [6] is
                        the week's high byte (0x09 for the current
                        2304..2559 epoch), which is why byte[6] reads 0x09
                        on every chipset generation.

                        This region is NOT a firmware fingerprint, although
                        captures taken on different GPS weeks / times-of-day
                        make it look per-chipset: the 6 RE fixtures' [4:7]
                        bytes (MC7455 05 6e 09, LM960 23 6d 09, EM7511
                        00 6f 09, ...) all decode to gps_week 2413/2414/2415,
                        matching their capture dates, with the leading byte
                        the gps_ms high byte. The older names
                        ``counter_block`` [1:4] / ``build_marker`` [4:7] are
                        retained as derived back-compat properties.
        [7:11]     f32  value_a — small positive float, range
                        ~4.6e-4 .. 0.53 across fixtures (semantics TBD;
                        possibly a clock-jitter or frequency-error estimate)
        [11:15]    f32  value_b — small positive float, range
                        ~0.054 .. 1.20 across fixtures (semantics TBD;
                        possibly a companion variance/confidence metric)
        [15]       u8   const = 0x00
        [16:20]    4B   const = ff ff ff ff (sentinel / unused slot marker)
        [20:111]   91B  zero-padding — all 0x00 across all records
        [111:115]  f32  lead_f32 — small-to-large positive float
                        (range ~0.015 .. 9000 across fixtures; likely a
                        magnitude/scale indicator — varies per-record on
                        most captures, const-ish on MC7455 RRLP-idle)
        [115]      u8   tag_05 = 0x05  (const all)
        [116]      u8   reserved = 0x00  (const all)
        [117:121]  f32  param_5 — discrete values in {2,3,5,10,20}
        [121]      u8   tag_01 = 0x01  (const all)
        [122:126]  f32  param_1 — discrete values {1e-3, 1e-9, 1, 9, 27, 30}
        [126]      u8   tag_02 = 0x02  (const all)
        [127:131]  f32  param_2 — discrete values {0.192, 0.48, 1, 1.2, 3}
        [131]      u8   tag_03 = 0x03  (const all)
        [132:136]  f32  param_3 — variable float, range ~1.0 .. 5.0
        [136]      u8   tag_04 = 0x04  (const all)
        [137:141]  f32  param_4 — const=1.0 across all records
        [141:165]  24B  trailing SV/slot status region — structurally
                        decoded (EM7511/MDM9650 + the other fixtures) as
                        **6 × 4-byte slots**:
                          slot_N at [141+4N:145+4N], for N in 0..5
                        Each slot's 4th byte (abs [144,148,152,156,160,164])
                        has **low nibble = 0 in 100% of em7511 non-zero
                        tails** (161/161) — this is a packed flag/status
                        nibble.  Exact semantic mapping per-slot (is it a
                        per-SV tracking entry? per-constellation summary?)
                        is still pending cross-capture correlation with
                        Diag0x1544 (GNSS SV Aggregate) / Diag0x148A (GNSS
                        SV Status) in the same epoch.
        [165]      u8   tail_trailer — 1-byte epilogue (per-record varies,
                        small int 0..~20; semantics TBD — possibly an SV /
                        slot count)

    The tag bytes at [115], [116], [121], [126], [131], [136] are 100 %
    stable across the RE corpus (EP06A/EG18-NA MDM9x07, MC7455 MDM9x30,
    LM960/FN980m SDX55, EM7511 MDM9650) — a fixed GNSS configuration /
    parameter frame (tags 1-5 identify the 5 tagged parameter slots).

    Identity note: the canonical log name is ``LOG_MOBISENS_OUTPUT_C``
    ("Sensors MobiSens Output", a sensor-output name) but the in-capture F3
    plane on these modem builds shows **only
    the GNSS navigation engine** (mgp_me_api / mc_clock / nf_navsolution /
    navrf / loc_pd / tm_core) — no mobisens/sensor source file emits — and
    the header carries a GPS week+ms time-tag. On these modem builds
    0x14B0 is a GNSS-engine data report, not a motion-sensor frame.

    References: field layout derived from byte-variance analysis of the
    fixtures above; the [1:7] time-tag was grounded against the firmware's
    own F3 ``mc_clock.c ClockPut_GPS`` prints (in-capture oracle).
    """
    log_time: int
    version: int
    gps_ms: int            # [1:5] u32 LE — GPS time of week (ms), F3-GROUND
    gps_week: int          # [5:7] u16 LE — GPS week number, F3-GROUND
    value_a: float         # [7:11] f32
    value_b: float         # [11:15] f32
    reserved_15: int       # [15] const 0x00
    sentinel_16_20: bytes  # [16:20] const 0xffffffff
    lead_f32: float        # [111:115] f32
    tag_05: int            # [115] const 0x05
    reserved_116: int      # [116] const 0x00
    param_5: float         # [117:121] f32
    tag_01: int            # [121] const 0x01
    param_1: float         # [122:126] f32
    tag_02: int            # [126] const 0x02
    param_2: float         # [127:131] f32
    tag_03: int            # [131] const 0x03
    param_3: float         # [132:136] f32
    tag_04: int            # [136] const 0x04
    param_4: float         # [137:141] f32
    tail_slots: tuple      # 6 × 4-byte blocks [141:165] — slot[N] at [141+4N:145+4N]
    tail_trailer: int      # u8 at [165]
    payload_size: int

    # --- back-compat views of the [1:7] region (older field names) -------
    # [1:4] ``counter_block`` and [4:7] ``build_marker`` are slices of the
    # little-endian GPS time-tag (gps_ms u32 @1 + gps_week u16 @5). These properties reconstruct the exact byte slices
    # so existing tests / stored JSONL consumers keep working.
    @property
    def counter_block(self) -> bytes:
        """Legacy [1:4] slice — the low 3 bytes of ``gps_ms`` (u32 LE @1)."""
        return pack('<I', self.gps_ms & 0xFFFFFFFF)[0:3]

    @property
    def build_marker(self) -> bytes:
        """Legacy [4:7] slice — gps_ms high byte + gps_week (u16 LE)."""
        return pack('<I', self.gps_ms & 0xFFFFFFFF)[3:4] + pack('<H', self.gps_week & 0xFFFF)

    @property
    def counter(self) -> int:  # backward-compat with an older field layout
        """Compatibility alias: legacy ``counter`` = first byte of counter_block."""
        cb = self.counter_block
        return cb[0] if cb else 0

    @property
    def sub_counter(self) -> int:  # backward-compat
        """Compatibility alias: legacy ``sub_counter`` = second byte of counter_block."""
        cb = self.counter_block
        return cb[1] if len(cb) > 1 else 0

    @property
    def const_block(self) -> bytes:
        """Compatibility alias: legacy ``const_block`` = counter_block[2]|build_marker."""
        # Reconstructs the legacy 4-byte [3:7] slice (gps_ms byte[3] + build_marker)
        cb = self.counter_block
        return bytes([cb[2] if len(cb) > 2 else 0]) + self.build_marker

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x14B0',
            'log_time': self.log_time,
            'version': self.version,
            'gps_ms': self.gps_ms,
            'gps_week': self.gps_week,
            'counter': self.counter,
            'sub_counter': self.sub_counter,
            'counter_block_hex': self.counter_block.hex(),
            'build_marker_hex': self.build_marker.hex(),
            'const_block_hex': self.const_block.hex(),
            'value_a': self.value_a,
            'value_b': self.value_b,
            'lead_f32': self.lead_f32,
            'param_1': self.param_1,
            'param_2': self.param_2,
            'param_3': self.param_3,
            'param_4': self.param_4,
            'param_5': self.param_5,
            'tag_01': self.tag_01,
            'tag_02': self.tag_02,
            'tag_03': self.tag_03,
            'tag_04': self.tag_04,
            'tag_05': self.tag_05,
            'tail_slots_hex': [s.hex() for s in self.tail_slots],
            'tail_trailer': self.tail_trailer,
            'payload_size': self.payload_size,
        }


@register(
    0x14B0, domain="gnss",
    name="0x14B0",
    description="GNSS data report (0x14B0) — 166B fixed, full decode: GPS time-tag header (gps_ms/gps_week, F3-GROUND) + tagged param frame + 6-slot tail + trailer",
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE across 1514 records from EP06A + EG18-NA (MDM9x07) + "
        "MC7455 (MDM9x30) + LM960 + FN980m (SDX55) + EM7511 (MDM9650) "
        "captures. version == 0x32 on every record and is a hard gate; "
        "payloads shorter than the fixed 166 B layout return None. The [1:7] "
        "header is a GPS time-tag — gps_ms (u32 LE @1) + gps_week (u16 LE "
        "@5) — F3-GROUND against the firmware's own mc_clock.c ClockPut_GPS "
        "'Wk .. Ms ..' print on 1799/1799 co-temporal EG25-G (MDM9207) "
        "records, and gps_week == capture-date calendar GPS week on 16/16 "
        "F3-bearing captures / weeks 2421..2436 / multiple chipsets; the "
        "older counter_block/build_marker names are derived back-compat "
        "properties. The tagged parameter frame is structural (5 constant "
        "tags); value_a/value_b, lead_f32, param_1..5, the 6-slot tail and "
        "the trailer are not yet semantically grounded."
    ),
    source_url="",
    issues=(),
    field_invariants={
        # byte 0 is 0x32 across the corpus.
        "version": {"enum": [0x32]},
        "payload_size": {"enum": [166]},
        # Physical bounds on the F3-grounded GPS time-tag.
        # gps_ms is a valid GPS time-of-week in ms (0 .. one week);
        # gps_week is a plausible modern GPS week (generous upper bound so a
        # future week roll past the current 0x09xx epoch is not rejected,
        # while a mis-parse landing in the tens of thousands still fails).
        "gps_ms": {"range": [0, 604800000]},
        "gps_week": {"range": [2000, 4096]},
        # The 5 corpus-constant tag bytes (115/121/126/131/136).
        "tag_05": {"enum": [0x05]},
        "tag_01": {"enum": [0x01]},
        "tag_02": {"enum": [0x02]},
        "tag_03": {"enum": [0x03]},
        "tag_04": {"enum": [0x04]},
    },
)
def parse_0x14b0(log_time: int, data: bytes) -> Diag0x14B0 | None:
    """Parse LOG_GNSS_DATA_14B0 (166B fixed)."""
    # The layout is a fixed 166 B record; a short
    # payload is truncated and returns None (registry WARN) rather than
    # zero-padding the tail slots / trailer.
    if len(data) < 166:
        return None
    # Hard gate on version byte before tail
    # slice read. Corpus: version == 0x32 on every record.
    if data[0] != 0x32:
        return None
    tail = bytes(data[141:166])
    tail_slots = tuple(tail[i:i+4] for i in range(0, 24, 4))
    tail_trailer = tail[24]
    return Diag0x14B0(
        log_time=log_time,
        version=data[0],
        gps_ms=unpack_from('<I', data, 1)[0],   # [1:5] GPS time of week (ms), F3-GROUND
        gps_week=unpack_from('<H', data, 5)[0],  # [5:7] GPS week number, F3-GROUND
        value_a=unpack_from('<f', data, 7)[0],
        value_b=unpack_from('<f', data, 11)[0],
        reserved_15=data[15],
        sentinel_16_20=bytes(data[16:20]),
        lead_f32=unpack_from('<f', data, 111)[0],
        tag_05=data[115],
        reserved_116=data[116],
        param_5=unpack_from('<f', data, 117)[0],
        tag_01=data[121],
        param_1=unpack_from('<f', data, 122)[0],
        tag_02=data[126],
        param_2=unpack_from('<f', data, 127)[0],
        tag_03=data[131],
        param_3=unpack_from('<f', data, 132)[0],
        tag_04=data[136],
        param_4=unpack_from('<f', data, 137)[0],
        tail_slots=tail_slots,
        tail_trailer=tail_trailer,
        payload_size=len(data),
    )
