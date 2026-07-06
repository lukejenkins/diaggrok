"""BeiDou B2b measurement skeleton parser (0x184E) — #N.

Observed across **5 distinct (size, version) profiles** spanning at least
4 chipset families. Variant table extended on session `2484` (2026-04-27)
after a corpus-wide scan (`tools/parser_corpus_summary.py --code 0x184E`,
129 captures / 11,191 records) surfaced two firmware-level variants that
prior RE noted but never wired into the dispatch:

| Variant            | Modems / chipset                                | `version` | Payload | Records |
|--------------------|-------------------------------------------------|-----------|---------|--------:|
| `mdm_v1`           | Sierra EM7511 (MDM9650), Telit LM960 (SDX20),   |           |         |         |
|                    | EP06A / EG18NA / EG12-GT (MDM9x07)              | `0x01`    | 1883 B  | 2,907   |
| `mdm_v1_compact`   | **Quectel EG25-G** (MDM9x07) +                  |           |         |         |
|                    | **Sierra MC7455** (MDM9x30) +                   |           |         |         |
|                    | **Quectel EG95NA, SIMCom SIM7600NA** (MDM9x07)  | `0x01`    | 1871 B  | 2,500+  |
| `sdx55_v2`         | Sierra EM9190, Telit FN980 (SDX55)              | `0x02`    | 1946 B  | 3,510   |
| `sdx55_v2_compact` | **Quectel RM500Q, Inseego M2000** (SDX55-class) | `0x02`    | 1934 B  |   842   |
| `sdx62_v5`         | Quectel RM520N (SDX62)                          | `0x05`    | 1141 B  | 1,400   |

The 2026-04-22 wardrive analysis rejected the "single parser shared SDX5x
/ SDX6x" hypothesis — corpus truth confirms the (size, version) tuples
are non-overlapping across chipset families. SDX62's 1141B is **smaller**
than SDX55's 1946B, suggesting Qualcomm restructured the per-SV slot
layout — likely a more compact representation in the newer chipset.

The two `_compact` variants are each **exactly 12 bytes shorter** than
their full-size sibling at the same `version`. This is suspiciously
uniform and suggests one specific 12-byte field (possibly 3 u32s or a
12-byte counter array) is conditionally present — likely a firmware-era
delta where older builds didn't yet emit some piece of state that newer
builds do.

B2b is the BeiDou-3 signal at **1207.14 MHz** (same carrier as Galileo
E5b), distinct from B1I (1561 MHz) and B1C (1575.42 MHz). RINEX 3.04
obs codes for B2b pilot are the D-suffix family: ``C7D L7D D7D S7D``.
The ``constellation`` / ``band`` fields are emitted so the RINEX writer
(``apps/diaggpsd/rinex_writer.py``) routes records to the right obs
code group when the per-SV tail is decoded (#N umbrella).

## Header structure

- Byte [0]:    u8   `version` — `0x01` / `0x02` / `0x05` (per variant table).
- Byte [1]:    u8   `sub_version` — **NOT a stable constant.** Corpus
  scan (session `2484`) showed 96% `0x01`, 4% `0x00`, plus rare `0x0d`
  and `0x14` values; 24 captures show intra-capture variance. Likely a
  state-dependent flag (RF-state / track-state) rather than a fixed
  subtype identifier.
- Bytes [2:8]: 6 B  reserved / zero (corpus-wide invariant verified).
- Bytes [8:12]: u32 `flag_8` (varies at runtime — confirmed multi-valued
  with intra-capture variance in 7+ captures, so not a structural marker;
  treat as a runtime state field of unknown semantic).

## Subsystem semantic (from RTCM-paired LG290P audit, session `2484`)

0x184E fires at ~0.4 Hz across captures **regardless of whether any B2b
SV is currently being tracked** — across 5 splitter-paired LG290P
captures (where the DUT antenna and LG290P share RF input), only 1 of 5
captures had B2bI (sigid=14) in the LG290P BeiDou MaskSig, but every DUT
emitted hundreds of 0x184E records anyway. Implication: **0x184E is a
periodic B2b-subsystem status / config dump, not per-SV B2b measurement
events.** Per-variant SV-tail RE should plan for "no track" / "stale
data" sentinels in most slots, since most captures will have 0 in-track
B2b SVs at any given moment.

## TBD for full closure (#N)

- **Per-variant** SV slot layouts (each chipset may need its own decoder).
- BDS PRN encoding (likely 201..237 on the v1/v2 variants; SDX62's
  compact layout may use different encoding).
- C/N0 / Doppler / carrier-phase fields.
- Locating the conditional 12-byte field that distinguishes
  `mdm_v1`/`mdm_v1_compact` (and `sdx55_v2`/`sdx55_v2_compact`) — likely
  the same offset in both, since the chipset families differ but the
  delta is identical.

## Test fixtures

- ``<redacted-pii>`` — Sierra EM9190 SDX55 (1946B v2)
- ``<redacted-pii>`` — Telit FN980 SDX55 (1946B v2)
- ``<redacted-pii>`` — Sierra EM7511 MDM9650 (1883B v1)
- ``<redacted-pii>`` — Telit LM960 SDX20 (1883B v1)
- ``<redacted-pii>`` — Quectel RM520N SDX62 (1141B v5)
- ``<redacted-pii>`` — Sierra MC7455 MDM9x30 (1871B v1, mdm_v1_compact) **NEW**

## MC7455 (MDM9x30) cross-chipset confirmation — session `a72c` (2026-05-04)

`mc7455_gnss_live_2026-04-12` + `<redacted-pii>`
both emit 0x184E at 1871B/v1 — the `mdm_v1_compact` variant previously
only seen on Quectel EG25-G (MDM9x07). MC7455 ran 110/110 records
parse OK in the 5-min stationary capture (709,812 total records,
0 parse errors). This widens `mdm_v1_compact` from MDM9x07-specific to
**MDM9x07 + MDM9x30**, suggesting the 12-byte field omission distinguishing
`mdm_v1_compact` from `mdm_v1` is a firmware-era choice rather than a
chipset-architecture difference (the same MDM9x07 silicon shows both
forms across different firmware: EG25-G = compact, EP06A/EG18NA/EG12-GT
= full-size). Notable: this MC7455 is **officially a GPS+GLONASS only
chipset** per Sierra documentation — yet emits 110× B2b records per
5-min capture, confirming the silicon has BeiDou hardware support gated
off only at the AT/NMEA application filter layer. See #N for the
multi-constellation characterization.

## EG95NA + SIM7600NA cross-chipset confirmation — session ``kali`` (2026-05-07)

`mdm_v1_compact` further widens to **{EG25-G, MC7455, EG95NA, SIM7600NA}**
following the 2026-05-04 SIM7600NA + 2026-05-07 EG95NA capture series.
EG95NA emits ~656 records / SIM7600NA ~945 records, all 1871B/v1, all
classifying as `mdm_v1_compact` ×100% (no `unknown` fallthrough). This
strengthens the firmware-era hypothesis: the MDM9x07 silicon now shows
4 chipset/firmware combos under `mdm_v1_compact` (EG25-G + EG95NA +
SIM7600NA all MDM9x07; MC7455 MDM9x30) alongside 3 still under `mdm_v1`
(EP06A, EG18NA, EG12-GT, all MDM9x07). The compact-vs-full split is a
firmware build choice that crosses chipset architectures, not a
silicon-level difference.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_CALL_MANAGER_SERVING_SYSTEM_MSIM_EVENT
        source: qxdm_itemtype_list_zukgit_2025_04_03 (authority: community)
    aliases: (none recorded)

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_ME_BDS_B2B
from diaggrok.registry import register


def _classify_variant(version: int, payload_size: int) -> str:
    """Classify a 0x184E record into one of five known variants, or 'unknown'.

    Variants extended in session `2484` (2026-04-27) after corpus-wide
    scan surfaced 1871B/v1 (EG25-G) and 1934B/v2 (RM500Q + Inseego)
    that the prior 3-variant table treated as `unknown` — accounted for
    ~16% of the 11,191-record corpus.
    """
    if version == 0x01 and payload_size == 1883:
        return 'mdm_v1'             # MDM9650 (EM7511) + SDX20 (LM960) + MDM9x07 (EP06A, EG18NA, EG12-GT)
    if version == 0x01 and payload_size == 1871:
        return 'mdm_v1_compact'     # MDM9x07 (EG25-G) + MDM9x30 (MC7455) — 12B shorter than mdm_v1
    if version == 0x02 and payload_size == 1946:
        return 'sdx55_v2'           # SDX55 (EM9190, FN980)
    if version == 0x02 and payload_size == 1934:
        return 'sdx55_v2_compact'   # SDX55-class (RM500Q, Inseego M2000) — 12B shorter than sdx55_v2
    if version == 0x05 and payload_size == 1141:
        return 'sdx62_v5'           # SDX62 (RM520N) — compact restructured layout
    return 'unknown'


@dataclass
class Diag0x184E:
    """BeiDou B2b measurement report (0x184E) — skeleton parser w/ variant dispatch.

    Identifies header bytes and classifies the record into one of three
    known chipset variants (`mdm_v1` / `sdx55_v2` / `sdx62_v5`). Per-SV
    tail RE is open per-variant — each chipset family will need its own
    decoder (see #N).

    ``constellation`` / ``band`` are set so the RINEX writer can route B2b
    records to the C7D/L7D obs-code group once per-SV measurements decode.
    """
    log_time: int
    version: int
    sub_version: int            # u8 at offset 1 — 96% 0x01, ~4% 0x00 + rare 0x0d/0x14 (state-dependent, NOT constant)
    flag_8: int                 # u32 at offset 8 (runtime state, not structural marker — corpus shows multi-valued + intra-capture variance)
    payload_size: int
    size_variant: str           # 'mdm_v1' | 'mdm_v1_compact' | 'sdx55_v2' | 'sdx55_v2_compact' | 'sdx62_v5' | 'unknown'
    raw: bytes
    constellation: str = 'BeiDou'
    band: str = 'B2b'

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x184E',
            'log_time': self.log_time,
            'version': self.version,
            'sub_version': self.sub_version,
            'flag_8': self.flag_8,
            'payload_size': self.payload_size,
            'size_variant': self.size_variant,
            'constellation': self.constellation,
            'band': self.band,
            'parser_status': 'skeleton',
            'parser_note': (
                'per-variant SV-tail RE open — see #N '
                '(B2b infra — #N wired via band=B2b)'
            ),
        }


@register(
    LOG_GNSS_ME_BDS_B2B,
    name="0x184E",
    description="BeiDou B2b signal measurements — skeleton + 5-variant dispatch, per-SV RE pending (#N)",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v3 (2026-04-27, <redacted-ref>): RTCM-aware revisit added two firmware-level "
        "variants — mdm_v1_compact (1871B/v1, EG25-G) and sdx55_v2_compact (1934B/v2, "
        "RM500Q + Inseego M2000) — that the prior 3-variant table left as 'unknown' "
        "(~16% of corpus). Refuted prior single-record hypotheses for sub_version=0x01 "
        "constant and u32@+8 structural marker; corpus shows both fields are runtime-"
        "variable. Documented 0x184E as periodic B2b-subsystem status (LG290P RTCM "
        "shows it fires regardless of B2b track state). v2 (2026-04-24): added SDX62 "
        "1141B/v5 variant. Cross-chipset header-only; per-variant SV-tail decode "
        "pending."
    ),
    source_url="",
    # Layer-2 version invariant — per #N / #N follow-up (b).
    # Corpus across all observed captures (#N 5-variant table) reports
    # `version` in {0x01, 0x02, 0x05}. A future firmware that ships a
    # v=0x03/0x04/0x06+ record at any payload size would otherwise be
    # silently mis-parsed under one of the existing size-variant maps —
    # core-memory: size invariance ≠ format invariance. Reject unknown
    # versions at the layer-2 invariant check so the parse-rate drop is
    # visible to operators.
    field_invariants={
        "version": {"enum": [0x01, 0x02, 0x05]},
    },
    issues=(),
    primary_issue=None,
)
def parse_0x184e(log_time: int, data: bytes) -> Diag0x184E | None:
    """Parse a LOG_GNSS_ME_BDS_B2B (0x184E) log payload — skeleton (#N)."""
    if len(data) < 12:
        return None
    version = data[0]
    # Layer-1 version-byte reject — closure-rigor pattern (commit 098df7838).
    # The layer-2 `field_invariants["version"]` enum on the @register decorator
    # below catches unknown versions at the registry-check layer, but without
    # this in-function gate, the parser still constructs a `Diag0x184E` with
    # `size_variant='unknown'` for any version byte — the exact "100% parse
    # rate, every offset wrong" anti-pattern the recent 0xB8B5 fix closed.
    # Reject unknown versions here so the parse-miss is unambiguous and the
    # parser body matches what `field_invariants` already enforces.
    if version not in (0x01, 0x02, 0x05):
        return None
    return Diag0x184E(
        log_time=log_time,
        version=version,
        sub_version=data[1],
        flag_8=unpack_from('<I', data, 8)[0],
        payload_size=len(data),
        size_variant=_classify_variant(version, len(data)),
        raw=bytes(data),
    )
