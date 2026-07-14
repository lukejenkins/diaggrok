"""BeiDou B1C measurement skeleton parser (0x1856) — #N.

Cross-chipset corpus scan (2026-04-24) over 11 modem families revealed
**4 distinct version bytes and 12 size variants**:

| Version | Chipset family    | Modems               | Sizes (B)        |
|---------|-------------------|----------------------|------------------|
| `0x01`  | MDM9x07, MDM9x40  | EP06A, MC7455        | 48, 64, 72       |
| `0x02`  | MDM9650, SDX20    | EM7511, LM960        | 40, 400          |
| `0x03`  | SDX55             | EM9190, FN980, LV55  | 44, 172, 180, 680, 776 |
| `0x04`  | SDX62             | RM520N               | 16, 156, 296, 680 |

The original 2026-04-23 docstring claimed 3 size variants (44/180/680)
based on EM9190 alone. The corpus actually has 12 sizes and a 4th
version byte (SDX62) — same multi-version pattern as 0x1855 (#N).

B1C is the BeiDou-3 civil signal at **1575.42 MHz** (same carrier as
GPS L1), distinct from the legacy B1I at 1561.098 MHz. RINEX 3.04
obs codes for B1C are the P-suffix family: ``C1P L1P D1P S1P``. The
``constellation`` / ``band`` fields are emitted so the RINEX writer
(``apps/diaggpsd/rinex_writer.py``) routes records to the right obs
code group when the per-SV tail is eventually decoded (#N umbrella).

## Header structure (12-byte minimum)

- `byte[0]`     u8   `version` — `0x01` / `0x02` / `0x03` / `0x04` (chipset gen)
- `bytes[1:4]`  u24  `session_tag` — **shared with 0x1855 (GPS L1C)** within
                     the same boot session. Cross-code invariant.
- `bytes[4:8]`  u32  reserved — `0x00000000` invariant across all 8 fixtures.
- `bytes[8:12]` u32  `flags_8` — varies (frame counter or status bits)

## Cross-code session_tag invariant (2026-04-25 RE finding)

`bytes[1:4]` is identical to `0x1855` `bytes[1:4]` for records emitted in
the same capture session. Both signals are at **1575.42 MHz** and share
the QCA wide-band tracking block, so the GNSS_ME subsystem stamps both
record streams with the same per-session 24-bit identifier. See
``parsers/gnss_gps_l1c.py`` for the corpus verification table.

Use case: an analyst correlating GPS L1C and BeiDou B1C records across a
multi-code DIAG capture can use this u24 to confirm both streams came
from the same boot session.

## TBD for full closure (#N)

- SV count field location per (version, size) tuple.
- B1C-specific fields (CNR, C/N0, carrier phase, pilot/data channel split).
- Cross-reference against LG290P B1C ground truth when available.

## ★ 2026-05-21 paradigm shift (<redacted-ref>, two-capture differential test)

**0x1856 is NOT a per-SV measurement report — it is a session-init
configuration enumeration of the B1C subsystem.** Same finding as the
parallel 0x1855 (GPS L1C) code: two paired captures ~5 hours apart on
the same RM520N-GL hardware, with different RF / sky-view state, emit
**bit-identical body content** in the 3-record 0x1856 burst other than
the session_tag (bytes [1:4]) and the high 16 bits of the descriptor
field (bytes [14:16]). The 7 ``20 00 15 00`` slots in the 680 B record
are static configuration-state enumeration slots, not per-SV tracker
slots — slot payloads are identical across runs despite the LG290P
B1C-pilot truth potentially differing between captures.

Parallel parser-invariant finding from 0x1855 work:
``descriptor & 0xFFFF == payload_size - 16`` holds for all SDX62 v=0x04
records (run 2 + run 3, all sizes 16 / 44 / 680). Suitable as a v=0x04
parse-validation invariant; needs verification on earlier-chipset
versions before extending.

Title should be revised similarly to #N / 0x1855: this code is the
BeiDou B1C engine's session-init configuration snapshot, NOT periodic
per-SV measurements. The real per-SV B1C measurements live in a
different log code, candidate analysis pending.

## SDX62 v=0x04 structural finding (2026-05-21 RM520N-GL capture, <redacted-ref>, run 2 only)

LG290P MSM7 1127 (BeiDou) sigid 31 (= ``1P`` / B1C pilot per RTCM 10403.3)
is present in the splitter-paired captures. In the 2026-05-21 run 2
paired capture, LG290P emitted B1C pilot observations for BDS PRNs
**``[13, 27, 28, 30, 37]``** (5 unique BDS-3 SVs across all 295 epochs).

Paired modem 0x1856 records — 3 records, v=0x04:

| # | size  | config_word  | descriptor | role hypothesis |
|---|-------|--------------|------------|------------------|
| 0 | 680 B | ``0x3b800003`` | ``0x00000298`` | per-SV slot table — **7 slots** observed |
| 1 |  16 B | ``0x00000202`` | ``0x00000000`` | header-only / no-track sentinel |
| 2 |  44 B | ``0x00800200`` | ``0x0000001c`` | session-summary with ``0xDEADC0FE`` trailer |

Body-tier structural pattern for the 680 B record:

- Body is a sequence of **per-SV slots** introduced by 4-byte prefix
  ``20 00 15 00`` followed by ``[slot_idx u8] [slot_idx*4 u8] 00 00``.
  Slot indices observed: ``0, 1, 2, 3, 4, 5, 6`` — exactly **7 slots**,
  zero-indexed. The ``slot_idx*4`` byte-pair pattern is structurally
  identical to the equivalent 0x1855 slot-header (``82 00 03 00``)
  field, suggesting a shared QCA GNSS_ME slot-allocator across both
  codes.
- Slots are mostly zero-filled with a recurring 8-byte constant
  ``000000f000000040`` or ``000000f000000060`` at slot+16 (a fixed
  flag / state marker). Most per-cell values are 0 in this window,
  suggesting the modem reserves slots for SVs not currently tracking
  B1C, with the ``60`` vs ``40`` distinguishing actively-tracking vs
  reserved.
- Slot 0 spans 128 B, slot 1 spans 128 B, slot 2 spans only 24 B,
  slot 3 spans 104 B, slots 4 + 5 are 128 B each, slot 6 spans 24 B.
  Variable slot sizes within one record suggest slot-internal length
  fields not yet decoded.

Body-tier pattern for the 44 B "summary" record:

- 4-byte prefix ``02 00 11 00`` (different field type from 680 B's
  ``20 00 15 00``) followed by ``[slot_idx u8] [slot_idx*4 u8] 00 00``
  in the same pattern.
- Slot index ``04``, then 8 bytes of payload (``3a 00 00 00 00 00 00 00``
  — 0x3a = 58, possibly an SV count or session-position).
- 8 bytes of zero padding.
- **``fe c0 ad de`` little-endian = ``0xDEADC0FE`` magic trailer** — a
  Qualcomm end-of-record sentinel. This can serve as a parser
  invariant: any 44 B v=0x04 record whose last 4 bytes != ``0xDEADC0FE``
  should be rejected as malformed.

### SV count vs PRN truth

LG290P truth reports **5 BDS PRNs** tracking B1C pilot during the
window. The modem 680 B record exposes **7 slots** — a 2-slot superset.
This is consistent with the splitter-paired hypothesis (same RF input,
modem's SDX62 GNSS engine more sensitive than LG290P's BDS-3 B1C
acquisition).  The 7 slots include some "actively-tracking" slots
(``60`` flag) and some "reserved/idle" slots (``40`` flag). PRN-to-
slot-index mapping is not yet decoded; needs a second paired capture
with a different BDS PRN set to confirm whether slot_idx encodes the
PRN directly or is an index into a separate PRN list.

Capture inputs available:
- <redacted-capture-path>
  - ``rm520ngl.dlf`` — 3× 0x1856 records (sizes 16, 44, 680)
  - ``gnss-20260521T131505Z.pyrtcm.jsonl`` — LG290P RTCM3 1127 with B1C pilot truth
  - ``rm520ngl_diag_parsed.jsonl`` — full DIAG for cross-correlation

## Test fixtures (8 fixtures × 4 versions × 4 chipset generations)

- `bds_b1c_1856_em9190.bin`        — 680B v3 (Sierra EM9190 SDX55)
- `bds_b1c_1856_fn980_680.bin`     — 680B v3 (Telit FN980 SDX55)
- `bds_b1c_1856_eg18na_40.bin`     —  40B v? (Quectel EG18NA SDX20)
- `bds_b1c_1856_rm520ngl_16.bin`   —  16B v4 (Quectel RM520N SDX62) **NEW**
- `bds_b1c_1856_mc7455_48.bin`     —  48B v1 (Sierra MC7455 MDM9x40) **NEW**
- `bds_b1c_1856_em7511_400.bin`    — 400B v2 (Sierra EM7511 MDM9650) **NEW**
- `bds_b1c_1856_lv55_172.bin`      — 172B v3 (Wistron LV55 SDX55) **NEW**
- `bds_b1c_1856_lv55_776.bin`      — 776B v3 (Wistron LV55 SDX55) **NEW**

Audit-noise note (#N, 2026-05-27) — ⛔ RETRACTED 2026-06-11 (#N)
--------------------------------------------------------------------

The 2026-05-27 note dismissed **byte+0=0x06** on the Foxconn T99W640
(4 sizes 16/44/56/1576) as DLF mis-framing and did not widen the enum.
**RETRACTED**: a fresh CLEAN capture (5govalidate 2026-06-11,
`capture_dlf_from_diag.py` over `/dev/mhi_DIAG`, **0 dropped frames**;
`FDE2.F0.0.0.1.2.TO.001/diag/<redacted-pii>`) proves
v=0x06 is a REAL SDX72 variant. The sibling 0x1855's body-length
self-consistency invariant `descriptor & 0xFFFF == payload_size - 16`
holds on all 4 0x1856 records (16/44/56/1576 -> body 0/28/40/1560), and
the cross-code session_tag bytes[1:4]=0x92d080 is IDENTICAL to the 0x1855
(GPS L1C) records in the same boot session — the documented 1575.42 MHz
wide-band GNSS_ME session tag, on a new chipset gen. Byte-misaligned
frames cannot satisfy both. The enum now includes 0x06 and a hw-validated
T99W640 v6 recipe is added (see @register + _GROUND_TRUTH_0x1856).

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_EVENTS_DS_GSM_RESELECT_START
        source: qxdm_3_12_714_2017_diag_log_codes (authority: community)
    aliases:
        LOG_EVENTS_GSM_DS_RESELECT_START
            source: qxdm_3_12_714_2017_diag_log_codes
        RESERVED
            source: qxdm_itemtype_list_zukgit_2025_04_03

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_ME_BDS_B1C
from diaggrok.registry import register


@dataclass
class Diag0x1856:
    """BeiDou B1C measurement report (0x1856) — skeleton parser.

    Recognizes three size variants (44 / 180 / 680 bytes); per-SV tail
    RE remains open (see #N).

    B1C is the BeiDou-3 civil signal at **1575.42 MHz** (same carrier as
    GPS L1), distinct from the legacy B1I at 1561.098 MHz. RINEX 3.04
    obs codes for B1C are the P-suffix family: ``C1P L1P D1P S1P``. The
    ``constellation`` / ``band`` fields are emitted so the RINEX writer
    (``apps/diaggpsd/rinex_writer.py``) routes records to the right obs
    code group when the per-SV tail is eventually decoded (#N).
    """
    log_time: int
    version: int               # u8 at offset 0 — chipset generation
    session_tag: int           # u24 at offset 1 — shared with 0x1855 in same session
    header_marker: int         # bytes [0:4] as u32 — kept for backward compat
    reserved_4: int            # u32 at offset 4 — always zero in corpus (invariant)
    flags_8: int               # u32 at offset 8
    payload_size: int
    size_variant: str          # 'small_44' | 'medium_180' | 'large_680' | 'unknown'
    raw: bytes
    # Constants — not on the wire; emitted for downstream consumers so
    # the RINEX writer can route B1C records to the C1P/L1P obs-code group.
    constellation: str = 'BeiDou'
    band: str = 'B1C'

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1856',
            'log_time': self.log_time,
            'version': self.version,
            'session_tag': self.session_tag,
            'header_marker': self.header_marker,
            'reserved_4': self.reserved_4,
            'flags_8': self.flags_8,
            'payload_size': self.payload_size,
            'size_variant': self.size_variant,
            'constellation': self.constellation,
            'band': self.band,
            'parser_status': 'skeleton',
            'parser_note': 'per-SV tail RE open — see #N (B1C infra — #N wired via band=B1C)',
        }


def _classify_size(n: int) -> str:
    """Classify into a known observed size variant, or 'unknown' for novel sizes.

    Observed corpus-wide (post-2026-04-28 RTCM-revisit corpus walk):
        16 / 40 / 44 / 48 / 56 / 64 / 72 / 156 / 172 / 180 / 196 / 220 /
        296 / 400 / 680 / 728 / 776

    The 196 B v=0x02 variant is the third member of the SDX20-era triple
    `(40 + 196 + 400)`, structurally analogous to SDX55's `(44 + 180 + 680)`.
    The 04-28 corpus walk found it at 596 records — 22.8% of all 0x1856
    records — making it the largest formerly-unclassified bucket.

    The 728 B v=0x03 variant is part of LV55 SDX55's `(728 + 56 + 172)`
    layout family; LV55 does NOT emit the EM9190/FN980 `(44 + 180 + 680)`
    triple despite being the same chipset gen — likely firmware-specific
    serialization (LV55 is on Wistron 3.33.101.0).

    The 16 B v=0x04 RM520N record is part of the SDX62 `(16 + 680 + 44)`
    triple — NOT a no-track sentinel (the 2026-04-24 hypothesis).  The
    structural role is closer to a session-level header / preamble within
    the v=0x04 record set.

    Rare variants `56` (9 records, LV55) and `220` (3 records, SDX55) are
    classified as `small_56` / `medium_220` so they don't fall into
    'unknown' if a capture happens to contain them; fixtures are not
    bundled because no flat .dlf in the current corpus carries them
    (only compressed wardriving captures do).
    """
    if n == 16:
        return 'tiny_16'         # SDX62 RM520N — header within (16+680+44) triple
    if n == 40:
        return 'small_40'        # SDX20 EG18NA, etc.
    if n == 44:
        return 'small_44'        # SDX55 EM9190 / FN980
    if n == 48:
        return 'small_48'        # MDM9x40 MC7455
    if n == 56:
        return 'small_56'        # SDX55 LV55 — rare (9 records corpus-wide)
    if n == 64:
        return 'small_64'        # MDM9x07 EP06A, MDM9x40 MC7455
    if n == 72:
        return 'small_72'        # MDM9x07 EP06A
    if n == 156:
        return 'medium_156'      # SDX62 RM520N
    if n == 172:
        return 'medium_172'      # SDX55 LV55
    if n == 180:
        return 'medium_180'      # SDX55 EM9190 / FN980
    if n == 196:
        return 'medium_196'      # SDX20-era triple member — LM960 dominant
    if n == 220:
        return 'medium_220'      # SDX55 — rare (3 records corpus-wide)
    if n == 296:
        return 'medium_296'      # SDX62 RM520N
    if n == 400:
        return 'large_400'       # SDX20/MDM9650 multi-modem
    if n == 680:
        return 'large_680'       # SDX55/SDX62 multi-modem
    if n == 728:
        return 'large_728'       # SDX55 LV55 — firmware-specific layout
    if n == 776:
        return 'xlarge_776'      # SDX55 LV55
    if n == 1576:
        return 'xxlarge_1576'    # SDX72 T99W640 v=0x06 burst member (largest observed)
    return 'unknown'


# --- Ground-truth recipe (#N) -------------------------------------------
# Authored offline (<redacted-ref>, hypothesis-only). Skeleton parser: the per-SV
# B1C signal tail is opaque (body_raw, #N), so this recipe grounds the
# DECODED header by correlation — chiefly session_tag cross-equality with the
# sibling 0x1855 (L1C) in the same boot session, the same anchor the 0x1855
# recipe already uses. SIM8202G-M2 (SIMCom SDX55, v=0x03) is the recommended
# target; AT+CGPS toggles the engine restart that changes session_tag.

@register(
    LOG_GNSS_ME_BDS_B1C, domain="gnss",
    name="0x1856",
    description="BeiDou B1C signal measurements — skeleton parser, per-SV RE pending (#N)",
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v3 (2026-04-25): split header_marker into version (u8) + "
        "session_tag (u24) — cross-code invariant shared with 0x1855 in "
        "same boot session. Verified across 4 paired-fixture sessions "
        "(FN980/LV55/MC7455/RM520N). reserved_4 confirmed invariant zero "
        "across all 8 fixtures.\n"
        "v4 (2026-05-07, <redacted-ref>): closed the size-variant taxonomy "
        "gap surfaced by the 2026-04-28 RTCM-revisit corpus walk.  Added "
        "5 sizes: medium_196 (the largest formerly-unclassified bucket "
        "at 596 records / 22.8% of corpus, SDX20-era LM960), large_728 "
        "(LV55 SDX55 firmware-specific), small_56 + medium_220 "
        "(stub entries — rare variants, fixtures pending), plus "
        "reclassified the 16 B v=0x04 SDX62 record as part of the "
        "(16+680+44) triple rather than a no-track sentinel.  Two new "
        "fixtures: bds_b1c_1856_lm960_196.bin (LM960 32.01.1X0 "
        "lm960_gnss_live_2026-04-12.dlf) and bds_b1c_1856_lv55_728.bin "
        "(LV55 3.33.101.0 qcsuper_capture_session.dlf).\n"
        "v5 (2026-06-11, #N 5govalidate): ADD version 0x06 — the Foxconn "
        "T99W640 (SDX72/SDXPINN) emits 0x1856 at byte0=0x06. RETRACTS the "
        "Audit-noise note (#N) that dismissed byte0=0x06 on this unit as "
        "DLF mis-framing. A fresh clean capture (capture_dlf_from_diag.py over "
        "/dev/mhi_DIAG, 0 dropped frames; <redacted-pii>) "
        "proves v=0x06 is real: the 0x1855 sibling's `descriptor & 0xFFFF == "
        "payload_size - 16` body-length invariant holds on all 4 0x1856 "
        "records (sizes 16/44/56/1576 -> body 0/28/40/1560), and the "
        "cross-code session_tag (bytes[1:4]=0x92d080) is identical to the "
        "0x1855 (GPS L1C) records in the same session. 12-byte header decodes "
        "identically to v1-v4. Added hw-validated T99W640 v6 recipe."
    ),
    source_url="",
    # 9 named header fields; per-SV signal-metric body still opaque
    # as body_raw — skeleton parser, per-SV RE pending.
    # 9 parsed / 10 identified. (#N)
    fields_parsed=9,
    fields_identified=10,
    # Layer-2 version invariant — per #N / #N follow-up (b).
    # Corpus per #N/#N (v3 docstring): 4 distinct version bytes 0x01..0x04
    # corresponding to chipset generation (MDM9x07/40, MDM9650/SDX20, SDX55,
    # SDX62). A future firmware shipping v=0x05+ in any existing size class
    # would silently route through the existing size→variant map. Reject
    # unknown versions so the parse-rate drop is visible.
    field_invariants={
        "version": {"enum": [0x01, 0x02, 0x03, 0x04, 0x06]},
    },
    issues=(),
    primary_issue=None,
)
def parse_0x1856(log_time: int, data: bytes) -> Diag0x1856 | None:
    """Parse a LOG_GNSS_ME_BDS_B1C (0x1856) log payload — skeleton (#N)."""
    if len(data) < 12:
        return None
    if data[0] not in (0x01, 0x02, 0x03, 0x04, 0x06):
        return None
    return Diag0x1856(
        log_time=log_time,
        version=data[0],
        session_tag=int.from_bytes(data[1:4], 'little'),
        header_marker=unpack_from('<I', data, 0)[0],
        reserved_4=unpack_from('<I', data, 4)[0],
        flags_8=unpack_from('<I', data, 8)[0],
        payload_size=len(data),
        size_variant=_classify_size(len(data)),
        raw=bytes(data),
    )
