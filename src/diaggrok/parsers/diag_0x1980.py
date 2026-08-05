"""GNSS/RF state flag (0x1980) — 4B fixed, constant state word.

Sibling pair with 0x197F — both codes emit an identical 4-byte payload
during airplane-mode and SIM power-cycle transitions. All 39 observed
records (30 airplane + 9 SIM per code) carry the same constant u32 value
0xC002F2A0. The two codes appear in the same events with the same
counts, suggesting they are the same state word reported by two
different subsystems simultaneously.

Layout (4 B fixed):
    [0:4]  u32 LE  state_word — observed constant 0xC002F2A0 across all records

## byte-0 RE'd version-less (#N, 2026-06-11)

Same determination as the 0x197F sibling: byte-0 is **not** a DIAG version
field — it is the **low byte of the constant u32 `state_word`** (0xC002F2A0
LE ⇒ byte-0 == 0xA0). The whole 4-byte payload is one all-constant state
word across 39/39 records; there is no version axis. The strict `state_word`
enum gate already rejects every foreign payload, so a
`field_invariants["version"]={enum:[0xA0]}` declaration would be semantically
false while adding no protection. Declared `version_less=True` to graduate
0x1980 off the #N worklist as an evidenced conclusion (mirrors 0x117B/#N).

Closure: #N.

## ⚠️ Observed-but-rejected: SDX-era large structured form (#N, 2026-07-14)

The 4-byte `0xC002F2A0` constant above is the **MDM9x50-era** form (Sierra
MC7411 / MC7455 / EM7565 / EM7511). A corpus-wide walk (697 records) surfaced a
**second, entirely distinct 0x1980 payload** on newer chipsets that this parser
knows nothing about and — correctly — rejects (`state_word != 0xC002F2A0`
⇒ `None`, no mis-parse):

    byte0 = chipset-gen version ladder:  0x03 = SDX20 (LM960)
                                         0x05 = SDX55 (RXM-G1, LV55, RM500Q,
                                                       SIM8202G-M2, M2000)
                                         0x06 = SDX65 (EM9291)
    byte1 ∈ {0x0b (SDX55/65), 0x0f (SDX20)},  bytes[2:4] = 0x0000
    size  = variable, 336 B → 3964 B (NOT the 4 B legacy form)

Both RXM-G1 (SDX55) records share an **identical fixed 14-byte header**
(`05 0b 00 00 0a 00 00 00 c6 94 0d 01 00 0e`) across a 1084 B and a 3604 B
record — a real structured record, not DLF mis-framing (mis-framing gives
random byte0). Multi-capture, multi-modem, per-chipset-consistent
(e.g. M2000 wardrive 20×3964 B all `05 0b`, LM960 32×3904 B all `03 0f`).

**This form is almost certainly NOT GNSS.** Co-temporal F3 (RXM-G1
`f3_radio_gnss.dlf`, qdb 77c0963a, resolution 100%) around both large records
is exclusively RF-measurement / FTM: `rfmeas_mdsp.c`, `rfcommon_core.c`
(RB thresholds), `ftm_qlnk_cmd.c` (FTM RF-script), `rflm_lte_txagc.c`,
`rflm_lte_rx.c` — **zero** GNSS source files in-window. This aligns with the
canonical name `RESERVED` (not a GNSS name) and the `codes.py` "RF state flag"
label, and casts doubt on the issue-title "GNSS State Flag" guess for the
modern form. Note: 4 B records with byte0=0x00 in survey/wardrive captures are
the size-4 HDLC tail-fragment residue class (cf. #N 0x192A precedent),
distinct from BOTH real forms.

### Header structure RE (#N, 2026-07-14) — the layout itself is versioned

The header is **re-laid-out across chipset generations** — this is a versioned
RF record, not one format. Per-version field maps (corpus-attested; LE u32):

    v05 (SDX55) — RXM-G1/LV55/M2000/T99W175, gate byte1=0x0b, byte2:4=0x0000
      [0]     0x05        version (chipset-gen)
      [1]     0x0b        subtype
      [2:4]   0x0000      reserved
      [4:8]   0x0000000a  INVARIANT constant = 10  (record-type / subsystem id)
      [8:12]  ~0x010d94c6 config/session tag — near-constant within a capture,
                          steps rarely (+0x40); NOT the record timebase
                          (log_time is separate). High half 0x010d invariant.
      [12]    0x00
      [13]    ∈{0x0e,0x0f,0x01}   per-record small state/subtype
      [14]    ∈{0x01,0x02,0x03}   per-record small count
      … then a nested body (see below); trailer ends ~`03 07 XX 00`.

    v03 (SDX20) — LM960, gate byte1=0x0f, byte2:4=0x0000  — DIFFERENT layout
      [0:4]   03 0f 00 00
      [4:8]   per-record nonce/hash (high entropy, varies every record)
      [8:12]  MONOTONIC counter — +15 per record (0x1c027→0x1c036→0x1c045…)
      [12:16] 0x00000004  INVARIANT constant = 4  (v05's "10" analog, moved)
      [16:20] ~0x00c994c0 signature (shares the middle `94` byte with v05's tag)

    v06 (SDX65) — EM9291, gate byte1=0x0b, byte2:4=0x0000 (layout ~v05; thin sample)

The small invariant constant (10 @ v05[4], 4 @ v03[12]) and the `…94…` signature
exist in both gens but at **different offsets** — same fields, relocated. Both
prove the record is genuinely structured (not mis-framing).

### Body: nested, not a flat array — decode deferred (thin per-version samples)

Fixed-stride array detection on the 3604 B v05 body scores < 0.45 for every
(header-len, stride) pair → the body is **nested / TLV-ish** (plausibly
per-antenna → per-carrier → per-RB, consistent with the `rfcommon_core.c`
"RB thres(5/10/15/20/40)" + `rfmeas_mdsp.c` co-temporal F3), not `count×stride`.
No single header field predicts total size.

**Decode is deliberately NOT attempted here.** Per the size-invariance core
memory and the 0x1855/0x1856 precedent, a structured body is only decoded when
confidently understood; here the per-version header layouts diverge and v03/v06
are each attested by a single firmware, so speculative body decode would risk
silent structured-garbage. The `state_word` gate keeps rejecting the large form
(safe: no mis-parse) until a per-version struct definition is pinned. The real
blocker is the **struct definition**, not capture availability — the large form
is already richly attested (697 records / 72 captures / 3 chipset gens), so the
`needs-capture` label may be stale for this half of the code.

Split from lte_misc.py per #N tier-3 batch 11.

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

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0x1980:
    """0x1980 — GNSS/RF state flag, 4B fixed, constant state word."""
    log_time: int
    state_word: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1980',
            'log_time': self.log_time,
            'state_word': self.state_word,
            'state_word_hex': f'{self.state_word:08x}',
        }


@register(
    0x1980, domain="gnss",
    name="0x1980",
    description="GNSS/RF state flag (0x1980) — 4B fixed, constant u32 during mode transitions (#N)",
    version=1,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from 39 EM7511 MDM9650 records (airplane + SIM cycle) "
        "2026-04-20 — all-constant payload 0xC002F2A0, same as 0x197F (#N)"
    ),
    # Payload is a single u32 (state_word). Every observed record has the
    # same 0xC002F2A0 value as 0x197F — sibling constant-state log. (#N)
    fields_identified=1,
    fields_parsed=1,
    field_invariants={"state_word": {"enum": [0xC002F2A0]}},
    # RE-proven version-less (#N): byte-0 is the low byte of the constant
    # u32 state_word (0xA0), NOT a DIAG version. The state_word enum gate below
    # already rejects every foreign payload; gating byte-0 would be redundant
    # and semantically wrong. See the byte-0 RE note in the module docstring.
    version_less=True,
)
def parse_0x1980(log_time: int, data: bytes) -> Diag0x1980 | None:
    if len(data) < 4:
        return None
    state_word = unpack_from('<I', data, 0)[0]
    if state_word != 0xC002F2A0:
        return None
    return Diag0x1980(
        log_time=log_time,
        state_word=state_word,
    )
