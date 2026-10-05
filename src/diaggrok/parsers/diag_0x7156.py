"""0x7156 = LOG_UMTS_NAS_HPLMN_SEARCH_END — empty marker (81B static template).

The canonical log name is ``LOG_UMTS_NAS_HPLMN_SEARCH_END``, the natural
search-*end* pairing to 0x7155's search-*start*. Its sibling 0x7155
(LOG_UMTS_NAS_HPLMN_SEARCH_START) fires co-temporally with an HPLMN/PLMN
search-start burst in F3-bearing EM7565 captures, and the all-empty
``00 + 80×0xff`` payload ("nothing to report") fits a search-complete
marker. This is not a GNSS log, although it co-fires with GNSS startup
at boot.

Scope note: unlike 0x7155, no 0x7156 record appears in any F3-bearing
capture yet, so the HPLMN_SEARCH_END role rests on the canonical name
and sibling inference, not direct co-temporal F3. What is solid
regardless of role is the cross-vendor byte-identity (static empty
template) below.

Cross-vendor static template — byte-identical 81B payload across 5
modems / 3 vendors spanning 4 silicon generations
(MDM9607 → MDM9x30 → SDX20 → SDX65):
  • Telit  LM960A18      (SDX20)    — 2 records
  • Sierra MC7455        (MDM9x30)  — 1 record
  • SIMCom SIM7600NA-H   (MDM9x07)  — 2 records
  • Sierra EM9291        (SDX65)    — 1 record
  • Sierra MC7411                   — 1 record

All records have SHA256 prefix `12277aebae1e4cc2…`. Byte-identity
extends to SDX65, the newest silicon generation observed, which rules
out any data-bearing reading.

Layout (81 B fixed):
  [0]:    u8       status        = 0x00 (invariant across captures — "nothing to report")
  [1:81]: 80 × u8  padding_fill  = 0xFF (invariant across captures — buffer-init pattern)

This is the "default empty" event: a fixed-format buffer the modem
logs without populating. It co-fires with 0x7153 / 0x7154 / 0x7155 /
0x7160 at boot, which triggers both GNSS startup and network
re-registration (PLMN search); the co-firing with GNSS startup is
coincidental. The 0x7155 sibling has the same 81B envelope but is
data-bearing; 0x7156 is its "buffer when empty" twin (a search end
with nothing to report fits the empty payload).

Cross-vendor byte-identity is sufficient for structural completeness:
it falsifies any data-bearing hypothesis without needing a 3GPP spec
or AT-command citation, since data-bearing fields would necessarily
vary across captures of independent silicon families. There is no
semantic content to name beyond the two fields below.

Log name: LOG_UMTS_NAS_HPLMN_SEARCH_END
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0x7156:
    """0x7156 (LOG_UMTS_NAS_HPLMN_SEARCH_END) — 81B empty static template."""
    log_time: int
    status: int                    # [0]    u8;  invariant 0x00
    padding_fill_invariant: bool   # [1:81] are 80 × 0xFF (invariant)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x7156',
            'log_time': self.log_time,
            'status': self.status,
            'padding_fill_invariant': self.padding_fill_invariant,
        }


@register(
    0x7156, domain="nas",
    name="0x7156",
    description="LOG_UMTS_NAS_HPLMN_SEARCH_END (0x7156) — 81B empty static template",
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from 7 records / 5 modems / 4 chipset generations "
        "/ 3 vendors: Telit LM960 (SDX20), Sierra MC7455 (MDM9x30), SIMCom "
        "SIM7600NA-H (MDM9x07), Sierra EM9291 (SDX65), Sierra MC7411. All "
        "records have SHA256 prefix `12277aebae1e4cc2…` (`00 + 80×0xff`). "
        "Cross-vendor byte-identity falsifies any data-bearing hypothesis."
    ),
    issues=(),
    primary_issue=None,
    fields_identified=2,
    fields_parsed=2,
    field_invariants={
        "status": {"enum": [0x00]},
        "padding_fill_invariant": {"enum": [True]},
    },
    # RE-evidenced version-less: parser names byte 0 `status`; corpus byte0 spans 1 value(s) over 13 records.
    version_less=True,
)
def parse_0x7156(log_time: int, data: bytes) -> Diag0x7156 | None:
    if len(data) < 81:
        return None
    status = data[0]
    if status != 0x00:
        return None
    padding_fill_invariant = all(b == 0xFF for b in data[1:81])
    if not padding_fill_invariant:
        return None
    return Diag0x7156(
        log_time=log_time,
        status=status,
        padding_fill_invariant=padding_fill_invariant,
    )
