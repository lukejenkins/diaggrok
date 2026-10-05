"""0x1490 — GNSS state/event report (14B fixed, all bytes named).

Cross-chipset RE corpus: 8342 records across 14 chipset+firmware pairs —
EG18-NA (SDX20 V2), EP06A (MDM9x07), EM7511 (MDM9650), FN980m (SDX55),
LM960 (4 firmware builds) + LM960A18 (SDX20).

Field map:
  [0]    u8    version          = 0x00 (CONSTANT 8342/8342)
  [1]    u8    state_byte       ∈ {0xA3 (8310), 0x59 (32)} — 2-state machine:
                                   0xA3 = steady-state (post-init)
                                   0x59 = boot/reset event (32/8342 records,
                                          exclusively on cold-reset post or
                                          reboot-v2 post captures)
  [2]    u8    sub_state        ∈ {0x0D (8310), 0x1B (32)} — locked to
                                   state_byte (A3↔0D, 59↔1B, 32/32 boot-state
                                   records co-occur with sub_state=0x1B).
  [3:5]  u16LE reserved_3_4     = 0 (CONSTANT 8342/8342)
  [5]    u8    status           ∈ {0x07 (4184), 0x01 (4099), 0x1D (32),
                                   0x00 (15), 0x09 (7), 0x08 (5)} —
                                   6-value status enum. 0x1D correlates 1:1
                                   with boot-state (byte[1]=0x59).
                                   0x01/0x07 are the two steady-state values
                                   (49%/50% distribution) — likely a bistable
                                   "fix/no-fix" toggle on 1Hz cadence.
  [6]    u8    event_flag       ∈ {0x00 (8327), 0x0C (9), 0x09 (6)} —
                                   secondary event flag; non-zero iff
                                   status ∈ {0, 8, 9} (transition records).
  [7:14] 7B    reserved_7_13    = 0 (CONSTANT 8342/8342)

All 14 bytes named; no body_raw region; fully decoded across 14 chipsets.

Pre-reset INVALID sentinel. One record in the whole corpus breaks the
"reserved_3_4 = 0" invariant, and it is not noise. It is
``00 ff ff ff ff 00 ff 00 00 00 00 00 00 00`` in an EG12-GT boot-plus-GNSS
edge-case capture, the only 0x1490 of that capture, emitted just before the
reset. Every field that has an
"invalid" value reads it: state_byte 0xFF, sub_state 0xFF, reserved_3_4
0xFFFF, event_flag 0xFF, with version 0x00 and status 0x00. The parser names it
(``invalid_sentinel``) and the invariant admits 0xFFFF, so it decodes instead of
WARNing as an invariant break. A per-offset byte-distribution sweep over 632
of the 676 captures that carry 0x1490 finds no other 0xFF at [3]/[4].

Log name: LOG_GNSS_PDSM_PD_EVENT_CALLBACK_C
Also known as: LOG_GAN_WAKEUP_REQUEST
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_GNSS_STATE_1490 = 0x1490

# Status-byte enum mapping — empirical semantics from edge-case analysis.
GNSS_STATE_1490_STATUS: dict[int, str] = {
    0x00: 'transition',          # correlated with event_flag=9
    0x01: 'steady_01',           # steady-state value A
    0x07: 'steady_07',           # steady-state value B (near-equal counts)
    0x08: 'transition_08',       # rare, correlated with event_flag
    0x09: 'transition_09',       # rare, correlated with event_flag
    0x1D: 'boot_event',          # exclusive with state_byte=0x59/sub_state=0x1B
}

GNSS_STATE_1490_STATE_NAMES: dict[int, str] = {
    0xA3: 'steady',
    0x59: 'boot',
    0xFF: 'invalid',             # pre-reset sentinel record (see module docstring)
}

# The pre-reset sentinel: every "invalid-able" field at its all-ones value.
_SENTINEL_STATE, _SENTINEL_SUB, _SENTINEL_RSV, _SENTINEL_EVT = 0xFF, 0xFF, 0xFFFF, 0xFF


@dataclass
class Diag0x1490:
    """GNSS state/event report (0x1490) — 14B fixed, all bytes named."""
    log_time: int
    version: int             # [0] = 0x00 CONSTANT
    state_byte: int          # [1] ∈ {0xA3, 0x59}
    state_name: str          # derived
    sub_state: int           # [2] ∈ {0x0D, 0x1B}, locked to state_byte
    reserved_3_4: int        # [3:5] u16 LE = 0 CONSTANT
    status: int              # [5] 6-value enum
    status_name: str         # derived
    event_flag: int          # [6] secondary event flag
    reserved_7_13: bytes     # [7:14] 7B = 0 CONSTANT
    payload_size: int

    @property
    def invalid_sentinel(self) -> bool:
        """True for the pre-reset all-0xFF record (state/sub_state/reserved/event)."""
        return (self.state_byte == _SENTINEL_STATE and self.sub_state == _SENTINEL_SUB
                and self.reserved_3_4 == _SENTINEL_RSV and self.event_flag == _SENTINEL_EVT)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1490',
            'log_time': self.log_time,
            'version': self.version,
            'state_byte': self.state_byte,
            'state_name': self.state_name,
            'sub_state': self.sub_state,
            'reserved_3_4': self.reserved_3_4,
            'status': self.status,
            'status_name': self.status_name,
            'event_flag': self.event_flag,
            'invalid_sentinel': self.invalid_sentinel,
            'payload_size': self.payload_size,
        }


# Ground-truth recipe — EC25/EG25 family (MDM9607). The canonical log name
# LOG_GNSS_PDSM_PD_EVENT_CALLBACK_C marks this as a GNSS position-determination
# (PDSM) event callback, NOT a measurement record: its decoded bytes are STATE/
# STATUS/EVENT flags, none of which any AT command returns as a literal value.
# These ground by CORRELATION — the flag must co-vary with an observable GNSS
# engine state, not equal an AT reply.
# cond="sky-fix": run outdoors / with sky view so the engine transitions through
# no-fix → acquiring → fix, exercising the state bytes.

@register(
    LOG_GNSS_STATE_1490, domain="gnss",
    name="0x1490",
    description="GNSS state/event report (0x1490) — 14B fixed, all bytes named",
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Cross-chipset RE: 8342 records across 14 chipset+firmware pairs — "
        "EG18-NA SDX20 V2, EP06A MDM9x07, EM7511 MDM9650, FN980m SDX55, "
        "LM960 (4 firmware builds) + LM960A18 SDX20. Every byte named: "
        "version/state/sub_state/reserved_3_4/status/event_flag/"
        "reserved_7_13. state_byte is 2-state (0xA3 steady, 0x59 boot); "
        "sub_state locked to state. status is a 6-value enum; event_flag is "
        "non-zero on transition records only. version == 0x00 across 50,510 "
        "records / 27+ captures / 15 chipsets and is a hard parser gate. A "
        "single pre-reset all-0xFF record (EG12-GT) is named as "
        "invalid_sentinel. The status enum names are empirical (steady vs "
        "transition), not grounded against firmware."
    ),
    source_url="",
    issues=(),
    fields_identified=9,
    fields_parsed=9,
    field_invariants={
        # Validated against 50,510 records / 27+ captures / 15 chipsets.
        # version and
        # reserved_3_4 are 100% invariant across the entire corpus. Soft
        # enums (state_byte, sub_state, status, event_flag) have rare
        # single-record outliers in pre-reset / corrupted captures and
        # are documented in the field-map comment instead of declared
        # here — the parser falls back to f'unknown_{:#04x}' for them.
        "version": {"enum": [0]},
        # 0 on every record except the pre-reset invalid sentinel, which
        # carries 0xFFFF there (1 record, EG12-GT pre-reset).
        "reserved_3_4": {"enum": [0, 0xFFFF]},
        # payload size is corpus-constant.
        "payload_size": {"enum": [14]},
    },
)
def parse_0x1490(log_time: int, data: bytes) -> Diag0x1490 | None:
    if len(data) != 14:
        return None
    # Hard gate on the version byte before reading state_byte at data[1].
    # Corpus: 50,510 records / 15 chipsets all have version == 0x00.
    if data[0] != 0x00:
        return None
    state_byte = data[1]
    status = data[5]
    return Diag0x1490(
        log_time=log_time,
        version=data[0],
        state_byte=state_byte,
        state_name=GNSS_STATE_1490_STATE_NAMES.get(state_byte, f'unknown_{state_byte:#04x}'),
        sub_state=data[2],
        reserved_3_4=unpack_from('<H', data, 3)[0],
        status=status,
        status_name=GNSS_STATE_1490_STATUS.get(status, f'unknown_{status:#04x}'),
        event_flag=data[6],
        reserved_7_13=bytes(data[7:14]),
        payload_size=len(data),
    )
