"""GNSS/RF state flag (0x1980) — 4B fixed, constant state word.

Sibling pair with 0x197F — both codes emit an identical 4-byte payload
during airplane-mode and SIM power-cycle transitions. All 39 observed
records (30 airplane + 9 SIM per code) carry the same constant u32 value
0xC002F2A0. The two codes appear in the same events with the same
counts, suggesting they are the same state word reported by two
different subsystems simultaneously.

Layout (4 B fixed):
    [0:4]  u32 LE  state_word — observed constant 0xC002F2A0 across all records

## byte-0 is not a version

Same determination as the 0x197F sibling: byte-0 is **not** a DIAG version
field — it is the **low byte of the constant u32 `state_word`** (0xC002F2A0
LE ⇒ byte-0 == 0xA0). The whole 4-byte payload is one all-constant state
word across 39/39 records; there is no version axis. The strict `state_word`
enum gate already rejects every foreign payload, so a
`field_invariants["version"]={enum:[0xA0]}` declaration would be semantically
false while adding no protection. The parser is declared `version_less=True`
(like 0x117B).

## Observed-but-rejected: SDX-era large structured form

The 4-byte `0xC002F2A0` constant above is the **MDM9x50-era** form (Sierra
MC7411 / MC7455 / EM7565 / EM7511). Across the corpus (697 records) there is
a **second, entirely distinct 0x1980 payload** on newer chipsets that this
parser does not decode and — correctly — rejects (`state_word != 0xC002F2A0`
⇒ `None`, no mis-parse):

    byte0 = chipset-gen version ladder:  0x03 = SDX20 (LM960)
                                         0x05 = SDX55 (RXM-G1, LV55, RM500Q,
                                                       SIM8202G-M2, M2000)
                                         0x06 = SDX65 (EM9291)
    byte1 ∈ {0x0b (SDX55/65), 0x0f (SDX20)},  bytes[2:4] = 0x0000
    size  = variable, 336 B → 3964 B (NOT the 4 B legacy form)

Both RXM-G1 (SDX55) records share an **identical fixed 14-byte header**
(`05 0b 00 00 0a 00 00 00 c6 94 0d 01 00 0e`) across a 1084 B and a 3604 B
record — a real structured record, not capture mis-framing (mis-framing gives
random byte0). Multi-capture, multi-modem, per-chipset-consistent
(e.g. an M2000 drive capture with 20×3964 B all `05 0b`, LM960 32×3904 B all
`03 0f`).

**This form is almost certainly NOT GNSS.** Co-temporal F3 (RXM-G1, resolution
100%) around both large records is exclusively RF-measurement / FTM:
`rfmeas_mdsp.c`, `rfcommon_core.c` (RB thresholds), `ftm_qlnk_cmd.c` (FTM
RF-script), `rflm_lte_txagc.c`, `rflm_lte_rx.c` — **zero** GNSS source files
in-window. This aligns with the name table's `RESERVED` (not a GNSS name)
and the `codes.py` "RF state flag" label, and argues against a "GNSS State
Flag" reading for the modern form.

### Header structure — the layout itself is versioned

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
show the record is genuinely structured (not mis-framing).

### Body: nested, not a flat array — not decoded

Fixed-stride array detection on the 3604 B v05 body scores < 0.45 for every
(header-len, stride) pair → the body is **nested / TLV-ish** (plausibly
per-antenna → per-carrier → per-RB, consistent with the `rfcommon_core.c`
"RB thres(5/10/15/20/40)" + `rfmeas_mdsp.c` co-temporal F3), not `count×stride`.
No single header field predicts total size.

**Decode is deliberately NOT attempted here.** A structured body is only
decoded when confidently understood (the same size does not imply the same
format); here the per-version header layouts diverge and v03/v06 are each
attested by a single firmware, so speculative body decode would risk silent
structured-garbage. The `state_word` gate keeps rejecting the large form
(safe: no mis-parse) until a per-version struct definition is pinned. The
blocker is the **struct definition**, not capture availability — the large
form is already richly attested (697 records / 72 captures / 3 chipset gens).

## F3 evidence per byte-0 key

Every F3-bearing capture (``0x79`` / ``0x99`` / ``0x98``-wrapped) of each
byte-0 key was joined, comparing co-emission within ±1 / ±10 ms of each
record against the same rate at record time ±5 s:

* **v0x00: real event-locked records, not HDLC tail-fragment residue.** 279
  records / 88 captures, overwhelmingly ``00 00 00 00`` (the 4 B state word
  holding 0, rejected by the ``0xC002F2A0`` gate). 175 records on all 63
  F3-bearing captures. Within ±10 ms, 95 % of records sit on the LTE **Tx
  de-init** sequence (``rfcommon_xpt_deinit_tx``, 58 captures;
  ``rfcommon_fbrx_mc_deinit``, ``rfcommon_vswr_deinit_tx``,
  ``rflte_core_xpt_deinit_tx``, 55 captures); within ±1 ms, 58 %. The
  control rate is 0. A residue fragment cannot be event-locked, so these are
  real 4 B state-word records emitted at Tx teardown, even though 4 B
  byte0=0x00 payloads in survey/drive captures look like the size-4 residue
  seen on other codes (e.g. 0x192A).
* **v0x05: inconclusive.** The SDX55 large form (parser rejects it): 26
  records on all 13 F3-bearing captures. 85 % sit within ±1 ms of RF
  front-end **sleep** (``[ASM] sleep()``, ``[FEM] physical_sleep()``,
  ``[PA]/[PAPM] sleep()``, 13/13 captures, control 0). That corroborates the
  RF (not GNSS) attribution above; no print carries the body's values.
* **v0xa0: inconclusive.** The canonical ``0xC002F2A0`` records sit on
  MDM9x50 captures with no F3. Only 2 v0xa0 records are on F3-bearing captures
  (M3100, RM520N-GL; neither is the canonical word, the parser rejects both).
  Both co-fire with RF FEM/ELNA configuration prints. n = 2 grounds nothing.
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
    description="GNSS/RF state flag (0x1980) — 4B fixed, constant u32 during mode transitions",
    version=1,
    issues=(),
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from 39 EM7511 MDM9650 records (airplane + SIM cycle): "
        "all-constant payload 0xC002F2A0, same as 0x197F. F3 by byte-0 key: "
        "the v0x00 (all-zero) form is event-locked to LTE Tx de-init (95% vs "
        "0% control, 58/63 captures), so it is not tail-fragment residue; the "
        "v0x05 SDX55 large form sits on RF front-end sleep (inconclusive); "
        "v0xa0 has n=2 on F3-bearing captures (inconclusive)."
    ),
    # Payload is a single u32 (state_word). Every observed record has the
    # same 0xC002F2A0 value as 0x197F — sibling constant-state log.
    fields_identified=1,
    fields_parsed=1,
    field_invariants={"state_word": {"enum": [0xC002F2A0]}},
    # Version-less: byte-0 is the low byte of the constant u32 state_word
    # (0xA0), NOT a DIAG version. The state_word enum gate below already
    # rejects every foreign payload; gating byte-0 would be redundant and
    # semantically wrong. See the module docstring.

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
