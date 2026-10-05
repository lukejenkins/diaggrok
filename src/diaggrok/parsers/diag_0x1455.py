"""0x1455 — GNSS epoch counter (7B fixed, all bytes named).

Cross-chipset corpus: 4204 records across 14 chipset+firmware pairs —
EG18-NA (SDX20 V2), EP06A (MDM9x07), EM7511 (MDM9650), FN980m (SDX55),
LM960 (four firmware builds) + LM960A18 (SDX20).

Field map:
  [0]    u8    version          = 0x00 (CONSTANT 4204/4204)
  [1:5]  u32LE sequence         cumulative count of successful GNSS position
                                  fixes (F3-grounded, see below). +1 per record;
                                  cumulative across sessions (not per-capture-
                                  scoped: an EG18-NA capture opened mid-count at
                                  seq=233/299). Occasional skip gaps are an
                                  LM960-specific artifact; the EG18-NA shows
                                  strict +1 steps. u32, not u8: values reach
                                  485,988 (CarCom-G1, see below).
  [5]    u8    flags            = 0x02 (CONSTANT 4204/4204)
  [6]    u8    reserved_6       = 0x00 (CONSTANT 4204/4204)

All 7 bytes named; no body_raw region; fully decoded across 14 chipsets.

F3 value grounding (v0x00, the only version): the firmware prints the counter
itself. ``tm_pdapi_client.c``
``tm_pdapi_pos_event_callback: PDSM_PD_EVENT_POSITION, Successful Fixes %u``
(QSR4) is emitted within a few hundred ticks of each record, and ``sequence``
equals its argument on **713/713** time-nearest pairs (0/713 at value-1 and at
value+1) across four builds and chipsets: CarCom-G1 MDM9250 (line 2631,
188/188, values ~486k), EG18-NA SDX20 (2712, 249/249), M3100 (2792, 46/46) and
SIM8202G-M2 SDX55 (2893, 230/230). ``flags`` (0x02) and ``reserved_6`` (0x00)
are constant on every record and no print labels them.

F3 event alignment: `sequence` also tracks the firmware's fix-report F3 prints
(`ale_proc.c` "NF: PFR, Report FIX to SM" / `lm_mgp.c` "=LM TASK= Received FIX
REPORT from MGP") on two EG18-NA captures with a build-matched message
database. Each 0x1455 record trails a fix-report F3 event by a near-constant
~0.37M ticks (<1% of the ~52M-tick inter-fix interval), and `sequence`
increments in exact 1:1 lockstep with those events (253 records / 250 fix
events across 2 captures; per-record delta == 1 throughout). This matches the
canonical name LOG_CGPS_DIAG_SUCCESSFUL_FIX_COUNT_C.

Log name: LOG_CGPS_DIAG_SUCCESSFUL_FIX_COUNT_C
Also known as: LOG_GPS_TM_ON_DEMAND_DONE
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_GNSS_COUNTER_1455 = 0x1455


@dataclass
class Diag0x1455:
    """GNSS epoch counter (0x1455) — 7B fixed, all bytes named."""
    log_time: int
    version: int         # [0] = 0x00 CONSTANT
    sequence: int        # [1:5] u32 LE — monotonic epoch counter
    flags: int           # [5]   = 0x02 CONSTANT
    reserved_6: int      # [6]   = 0x00 CONSTANT
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1455',
            'log_time': self.log_time,
            'version': self.version,
            'sequence': self.sequence,
            'flags': self.flags,
            'reserved_6': self.reserved_6,
            'payload_size': self.payload_size,
        }


@register(
    LOG_GNSS_COUNTER_1455, domain="gnss",
    name="0x1455",
    description="GNSS epoch counter (0x1455) — 7B fixed, all bytes named",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "4204 records across 14 chipset+firmware pairs — EG18-NA SDX20 V2, "
        "EP06A MDM9x07, EM7511 MDM9650, FN980m SDX55, LM960 (four builds) + "
        "LM960A18 SDX20. Every byte named: version/sequence(u32 LE)/flags/"
        "reserved. sequence == the tm_pdapi_client.c "
        "'PDSM_PD_EVENT_POSITION, Successful Fixes %u' argument on 713/713 "
        "pairs (CarCom-G1 MDM9250, EG18-NA SDX20, M3100, SIM8202G SDX55), "
        "and steps 1:1 with fix-report F3 events on EG18-NA."
    ),
    source_url="",
    issues=(),
    fields_identified=5,
    fields_parsed=5,
    # Layer-2 invariants from the corpus (4204/4204 records across
    # 14 chipset+firmware pairs). version/flags/reserved_6 are corpus-wide
    # constants on every observed record; payload_size is strictly 7B (the
    # parser already rejects len != 7 at Layer 1). Declared so future drift (new chipset emits version=0x01, or a
    # 7B foreign payload routes here) surfaces via the Layer-2 violation
    # pipeline rather than getting silently re-decoded.
    field_invariants={
        "version": {"enum": [0x00]},
        "flags": {"enum": [0x02]},
        "reserved_6": {"enum": [0x00]},
        "payload_size": {"enum": [7]},
    },
)
def parse_0x1455(log_time: int, data: bytes) -> Diag0x1455 | None:
    if len(data) != 7:
        return None
    if data[0] != 0x00:
        return None
    return Diag0x1455(
        log_time=log_time,
        version=data[0],
        sequence=unpack_from('<I', data, 1)[0],
        flags=data[5],
        reserved_6=data[6],
        payload_size=len(data),
    )
