"""GNSS lifecycle 0x7153 cross-vendor state-code parser.

Cluster member: 0x7153/0x7154/0x7155/0x7156/0x7160 fire together
during the GNSS-engine-start critical section. 0x7153 is the cluster's
*trailer* — fires last, ~12 seconds after the 0x7154 leader.

## Cross-vendor record content (5 chipset families, 18 records)

The 2-byte payload carries a stateful byte[0] state code. It is not a
static template: two LM960 SDX20 records taken after engine init share
the same byte, but across the full 18-record corpus byte[0] takes 3
distinct values:

| Vendor / chipset            | Scenario / state           | byte[0] |
|-----------------------------|----------------------------|--------:|
| Telit LM960 (SDX20)         | warm-GNSS / boot+GNSS      | `0x06`  |
| Sierra MC7411 (MDM9x50)     | GNSS comparison (active)   | `0x1e`  |
| Sierra MC7455 (MDM9x30)     | full reboot, pre-reset     | `0x1e`  |
| Sierra MC7455 (MDM9x30)     | full reboot, post-reset    | `0x02`  |
| Sierra MC7455 (MDM9x30)     | boot + GNSS, post          | `0x02`  |
| SIMCom SIM7600NA-H (MDM9607)| airplane / SIM / reboot    | `0x02`  |
| Sierra EM9291 (SDX62)       | full reboot / boot+GNSS    | `0x02`  |
| Sierra EM9291 (SDX62)       | **PSM/eDRX cycle**         | `0x02`  |

byte[1] is always `0x00` across all 18 records — reserved.

## Interpretation

byte[0] is best read as a coarse GNSS-engine state code:

  - `0x02` (=2):  post-init / engine-idle (Sierra MC7455 post-reboot,
                  SIMCom SIM7600NA across all edge cases, Sierra
                  EM9291 SDX62 post-reboot + **PSM/eDRX wake**)
  - `0x06` (=6):  warm-restart / mid-cycle  (Telit LM960 in warm-GNSS
                  and boot-plus-GNSS scenarios)
  - `0x1e` (=30): active / steady  (Sierra MC7455 pre-reset,
                  Sierra MC7411 in a GNSS comparison capture)

### `post_init` label is provisional

The `0x02 → post_init` mapping comes from "appears after a hard reset /
boot" scenarios, but an EM9291 SDX62 PSM/eDRX-cycle capture also emits
byte[0]=0x02 on a power-save-mode wake — NOT a boot/reset. So
`post_init` is **too narrow** as a semantic label; "engine-idle /
not-actively-tracking" is closer, but renaming would still be
speculation without ground truth. The label is preserved for stability;
this docstring is the disclosure.

The state values are not contiguous — looks more like an enum of
GNSS-engine sub-states than a counter. Field semantics are inferred
from the scenario-to-byte mapping; not yet ground-truthed against the
GNSS engine's own state labels.

## Cross-cluster role

Cluster ordering (Δ from 0x7154 T0):
  0      0x7154 marker
  ~750µs 0x7155 + 0x7160 paired emission
  ~5s    0x7156
  ~12s   **0x7153 (this code)**

0x7153 is the cluster's *trailer* — fires last in the engine-start
sequence. The state code reflects the engine state reached at that
cycle's terminal step.

Log name: LOG_UMTS_NAS_HPLMN_SEARCH_TIMER_START
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register


_LOG_CODE = 0x7153
_PAYLOAD_SIZE = 2
_RESERVED_BYTE_INDEX = 1  # byte[1] is reserved (0x00 across full corpus)

_STATE_NAMES = {
    0x02: 'post_init',
    0x06: 'warm_restart',
    0x1e: 'active',
}


@dataclass
class Diag0x7153:
    """Parsed 0x7153 GNSS-lifecycle state code."""
    log_time: int
    state_code: int        # byte[0] — observed values: {0x02, 0x06, 0x1e}
    state_name: str        # decoded enum (or 'unknown_state' for unobserved values)
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x7153',
            'log_time': self.log_time,
            'state_code': self.state_code,
            'state_name': self.state_name,
            'payload_size': self.payload_size,
        }


@register(
    _LOG_CODE, domain="gnss",
    name="0x7153",
    description=(
        "GNSS-engine-cycle trailer state code — fixed 2-byte "
        "record. byte[0] is a state code (observed {0x02, 0x06, "
        "0x1e}); byte[1] is reserved (always 0x00 across 11-record "
        "cross-vendor corpus). Fires last in the 0x7153/4/5/6/0x7160 "
        "GNSS-engine-start cluster (~12s after the 0x7154 leader)."
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from an 18-record cross-chipset corpus: Telit LM960 "
        "SDX20 (2 records, byte[0]=0x06), Sierra MC7411 MDM9x50 (2 records, "
        "byte[0]=0x1e), Sierra MC7455 MDM9x30 (3 records: 0x1e pre-reset / "
        "0x02 post-reset / 0x02 boot+GNSS), SIMCom SIM7600NA-H MDM9607 (4 "
        "records, all byte[0]=0x02), Sierra EM9291 SDX62 (7 records, all "
        "byte[0]=0x02: 5 from reboot scenarios + 2 from PSM/eDRX wake). "
        "byte[1] is reserved zero across all records. byte[0] is "
        "data-bearing state, not a static template. state_code (data[0]) is "
        "the first data access; the reserved-byte check (data[1] != 0) "
        "follows. No closed-enum field_invariants on state_code: the "
        "graceful-degradation contract (_STATE_NAMES.get(code, "
        "'unknown_state')) is intentional so future firmware can emit new "
        "sub-states without registry-time rejection. PSM/eDRX wake emits "
        "0x02, widening the trigger surface beyond 'post-boot' — the "
        "post_init label is provisional pending ground truth."
    ),
    source_url="",
    issues=(),
    fields_identified=2,    # state_code + state_name
    fields_parsed=2,
    # RE-evidenced version-less: parser names byte 0 `state_code`; corpus byte0 spans 3 value(s) over 67 records.
    version_less=True,
)
def parse_0x7153(log_time: int, data: bytes) -> Diag0x7153 | None:
    """Parse a 0x7153 GNSS-lifecycle state record (fixed 2 bytes).

    Returns None on size mismatch or non-zero reserved byte. byte[1]
    is the soft-pin against same-size payloads from a different code.
    """
    if len(data) != _PAYLOAD_SIZE:
        return None
    # state_code (data[0]) is the
    # substantive discriminator and a name-match field — it must be the
    # strict-first data access. The reserved-byte check follows.
    state_code = data[0]
    if data[_RESERVED_BYTE_INDEX] != 0:
        return None

    state_name = _STATE_NAMES.get(state_code, 'unknown_state')

    return Diag0x7153(
        log_time=log_time,
        state_code=state_code,
        state_name=state_name,
        payload_size=_PAYLOAD_SIZE,
    )
