"""0xB062 — LTE MAC RACH Attempt (LOG_LTE_MAC_RACH_ATTEMPT).

ID-only naming: registry name "0xB062", class `Diag0xB062`.

=== Subpacket container + RACH body (all 4 versions) ===

Offsets 4-7 are the **subpacket header** (id / version / length), not a
config word. The parser decodes the container and — for **all four**
reverse-engineered subpacket versions (0x02/0x03 MDM-era + 0x31/0x32 SDX) —
the RACH attempt result and the **RAR Timing Advance**.

Container envelope (byte-identical to the 0xB192 subpacket family on every
observed record):

    [0]    u8   version          (== 0x01; outer DIAG log version, L1-gated)
    [1]    u8   num_subpackets    (== 0x01 on every observed record)
    [2:4]  u16  hdr_counter       (per-capture config/instance marker; NOT an SFN)
    [4]    u8   subpacket_id      (== 0x06)
    [5]    u8   subpacket_version (THE structural discriminator — see below)
    [6:8]  u16  subpacket_length  (== len(data) - 4; INCLUSIVE of these 4 header
                                    bytes, so the single subpacket spans [4:len])
    [8:]        subpacket payload

`subpacket_version` is the variant axis (each maps 1:1 to a chipset gen and a
fixed record size — "size invariance != format invariance" holds: byte-0 is a
constant 0x01 across all sizes):

    ver 0x02  →  40 B  →  MDM9x07/9x30 Cat-4  (Sierra MC7455; also Quectel
                                                EG25G/EG95NA, SIMCom SIM7600) [RE'd]
    ver 0x03  →  44 B  →  MDM9x50 Cat-12/18   (Sierra MC7411/EM7511/EM7565;
                                                also Telit LM960, Quectel EG18) [RE'd]
    ver 0x31  →  56 B  →  SDX55  (Quectel RM500Q-AE, SIMCom SIM8202, Inseego
                                   M2000/M3100, Telit FN980, Wistron LV55) [RE'd]
    ver 0x32  →  60 B  →  SDX6x  (Quectel RM520N-GL, Sierra EM9291)        [RE'd]

The subpacket_version keys the RACH body — but the value axis is broader than a
single vendor: ver-0x02 and ver-0x03 valid-TA records occur across Sierra,
Quectel, SIMCom and Telit modems, since
the parser dispatches on subpacket_version (not the modem). "size invariance !=
format invariance" still holds (byte-0 is a constant 0x01 across every size).

RACH-attempt body — reverse-engineered from DLF/HDLC captures, clean-room
(no Rayhunter/SCAT source read; SCAT stdout used only as an A/B output check).
The ver 0x03 body is the ver 0x02 body shifted +2 (a 2-byte `00 00` prefix). The
SDX bodies share the same field grammar with longer
trailers: **ver 0x31 (56 B) uses the ver-0x03 offsets byte-for-byte**; ver 0x32
(60 B) keeps `attempt_result` at the shared offset 11 but shifts `rar_valid`/`TA`
by +3. Absolute offsets in `data`:

                                    ver02  ver03  ver31  ver32
    attempt_seq   u8   monotonic RACH counter    @8    @10    @10    @10
    attempt_result u8  outcome enum (see below)  @9    @11    @11    @11
    rar_valid     u8   1 ⇒ RAR received ⇒ TA set  @18   @20    @20    @23
    timing_advance u16 RAR TA (0xffff ⇒ no RAR)   @21   @23    @23    @26

SDX evidence: same success-vs-failure diff as the Sierra
bodies. ver 0x31 is fully convergent over 111 deduped records (26 fails spanning
Inseego M2000 + Quectel RM500Q-AE + SIMCom SIM8202) — TA reads 0xffff on every
fail, bounded [0,517] on all 85 successes, rar_valid gate 100% consistent, and
attempt_result==1 on every fail / {0,2,4} on success (matching Sierra). ver 0x32
TA@26 + rar_valid@23 are pinned over 165 records (gate 100%; 164 successes all
bounded [4,563]) but the SDX6x captures are success-heavy (a single failed RACH), so
attempt_result@11 there is corroborated by only that one fail — lower confidence.

`attempt_result` observed enum {0, 1, 2, 4} (Techplayon: 0 = success). Grounded
against the SCAT black-box oracle, which flagged the non-success values {1, 4}
on the same MC7455 capture. Value **1 is the failed / no-RAR outcome**: across
2,344 ver-2 records, every record with `attempt_result == 1` (2,234 of them)
has `rar_valid == 0` and `timing_advance == 0xffff`. Values {0, 2, 4} can carry
a valid RAR. Only the offset and the observed set are asserted, not full
per-value semantics.

`timing_advance` — the 11-bit RAR Timing Advance Command (TS 36.321 §6.1.5),
range T_A ∈ [0, 1282]. Pinned by four convergent lines of evidence:
  1. reads 0xffff (all-ones "not available") on every failed RACH
     (2,288 ver-2 + 142 ver-3 records);
  2. bounded to the spec's [0, 1282] on ALL 64 valid records
     (ver-2 ∈ [38, 632]; ver-3 ∈ {8, 9, 12, 14, 161});
  3. gated by the adjacent `rar_valid` flag (0→1 on RAR receipt);
  4. yields physically plausible cell ranges via TS 36.213 §4.2.3
     (78.07 m per unit): ver-3 ≈ 0.6–1.1 km, ver-2 clusters at ~3 km and
     ~42 km (rural).
`timing_advance_m = round(T_A × 78.07, 1)` is a derived convenience (one-way
path length; a biased upper bound under NLOS). Emitted only when
`rar_valid` and `timing_advance != 0xffff`.

=== F3 grounding — record identity confirmed; timing_advance value has no
    F3 counterpart (checked on 2 chipsets) ===

The code's identity as `LOG_LTE_MAC_RACH_ATTEMPT` is F3-grounded — the record
fires at RACH-procedure completion, co-temporal with the firmware's own RACH
state-machine prints on two independent chipset generations:
  * RM520N-GL SDX62 (ver-0x32, survey capture): 46 records
    ↔ 46 `lte_rrc_stm.c:837 LTE_CPHY_RACH_MSG1_SCHED_IND` frames, 1:1, each record
    a consistent +21.6..+23.0 ms after its MSG1 indication (the RAR window).
  * Telit LM960A18 MDM9x50 (ver-0x03, drive capture): 6 records ↔
    `lte_ml1_dlm_rach.c:1952 DLM RACH STM: COMPLETE STATE ENTRY` /
    `lte_ml1_gm_stm.c:1664 GM: Leaving PRACH_MSG3 State` /
    `lte_mac_rach.c:1793 rach_procedure_done`, all at |dt| ≈ 0.01 ms (same tick).

The `timing_advance` value, however, is not recoverable from F3: across 893,459
(SDX62, 100% QSR4-resolved) + 19,837,874 (MDM9x50, plaintext-rich) F3 frames, no
site prints the RAR Timing-Advance COMMAND index that this field decodes. The
firmware logs the RACH *procedure* as state-machine events (cfg/MSG1/MSG3/
contention/complete) but not the numeric RAR TA — the same MAC/LL1-internal
boundary that applies to per-TTI DCI grants. False friend: `lte_ml1_common_rssi_ind.c:971
"Timing Advance- USTMR: N US: M"` is the *maintained ML1 timing advance* in
USTMR ticks / microseconds (observed 0/60/61/62), a different quantity and units
from the RAR command index (observed {6,8,9,18}) — it does not ground this field.
So `timing_advance` rests on the structural evidence above (0xffff-on-fail +
[0,1282] bound + rar_valid gate + plausible range), which F3 corroborates rather
than contradicts.

Across every F3-bearing capture (53): 207/241 records are RACH-event-locked — 171 follow
``RACH_MSG1_SCHED_IND`` by 15-30 ms (QSR4 builds), 36 within ±3 ms of
``rach_procedure_done`` / "Got RACH Confirmation" (plaintext builds). Grounds the
record identity and emit timing; ``timing_advance`` stays F3-N/A (no RACH-family
print carries the RAR TA command).

Log name: LOG_LTE_MAC_RACH_ATTEMPT
Also known as: LOG_RACH_ATTEMPT, LTE MAC Rach Attempt
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0xB062:
    """0xB062 — LTE MAC RACH Attempt (subpacket container + RACH body)."""
    log_time: int
    version: int
    num_subpackets: int
    subpacket_id: int
    subpacket_version: int
    subpacket_length: int
    # RACH-attempt fields — populated for the four known subpacket versions
    # (0x02 / 0x03 / 0x31 / 0x32); None on any other subpacket version.
    attempt_seq: int | None
    attempt_result: int | None
    rar_valid: bool | None
    timing_advance: int | None
    timing_advance_m: float | None
    payload_size: int
    subpacket_payload: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB062",
            "log_time": self.log_time,
            "version": self.version,
            "num_subpackets": self.num_subpackets,
            "subpacket_id": self.subpacket_id,
            "subpacket_version": self.subpacket_version,
            "subpacket_length": self.subpacket_length,
            "attempt_seq": self.attempt_seq,
            "attempt_result": self.attempt_result,
            "rar_valid": self.rar_valid,
            "timing_advance": self.timing_advance,
            "timing_advance_m": self.timing_advance_m,
            "payload_size": self.payload_size,
            "subpacket_payload": self.subpacket_payload,
        }


# byte-0 is the DIAG version field; invariant 0x01 across all payload sizes
# (2683 records). Keep the gate; size is not invariant so no payload_size
# invariant.
_B062_VERSION_OBSERVED = 0x01
_B062_SUBPKT_ID = 0x06
_TA_INVALID = 0xFFFF
_METERS_PER_TA_UNIT = 78.07  # TS 36.213 §4.2.3: 16·T_s·c/2, one-way path length

# Absolute offsets of the RACH body fields keyed by subpacket_version. The
# ver-0x03 body is ver-0x02 shifted +2 (2-byte `00 00` prefix). Offsets are into
# `data` (the full log payload).
#   subpacket_version: (attempt_seq, attempt_result, rar_valid, timing_advance_u16)
_B062_RACH_LAYOUT = {
    0x02: (8, 9, 18, 21),   # MDM9x30 / 40 B
    0x03: (10, 11, 20, 23),  # MDM9x50 / 44 B
    0x31: (10, 11, 20, 23),  # SDX55  / 56 B — byte-identical to ver-0x03, longer trailer
    0x32: (10, 11, 23, 26),  # SDX6x  / 60 B — result@11 shared; rar_valid/TA shifted +3
}


@register(
    0xB062,
    name="0xB062",
    description="0xB062 — LTE MAC RACH Attempt: subpacket container + RACH result/RAR-timing-advance body",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Reverse-engineered from DLF/HDLC captures. Container envelope "
        "(version/num_subpackets/hdr_counter + subpacket id=0x06/version/length) "
        "is byte-identical to the 0xB192 subpacket family. All four subpacket "
        "versions now decode attempt_result + the 11-bit RAR timing advance: "
        "ver-0x02 (40 B, MDM9x07/9x30), ver-0x03 (44 B, MDM9x50), ver-0x31 (56 B, "
        "SDX55) and ver-0x32 (60 B, SDX6x), pinned by the 0xffff-on-failure / "
        "bounded-[0,1282]-on-success / rar_valid-gated / plausible-range evidence "
        "over all captured 0xB062 records (cross-vendor: Sierra, Quectel, "
        "SIMCom, Telit, Inseego, Wistron). Record identity is F3-grounded "
        "against the RACH state-machine prints. A payload shorter than the "
        "subpacket_length its header declares returns None. SCAT stdout used "
        "only as an A/B output check (clean-room; no Rayhunter/SCAT source read)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=9,
    fields_parsed=9,
    field_invariants={
        "version": {"enum": [_B062_VERSION_OBSERVED]},
        "subpacket_id": {"enum": [_B062_SUBPKT_ID]},
    },
    # WiGLE: none. The body is a RACH attempt result + RAR timing advance —
    # no PCI/EARFCN, signal, position or UTC, so it fills no WiGLE CSV field.
    # TA is a tower-range estimate, which is outside the WiGLE role
    # vocabulary. (False, ()) records an explicit decision, not an omission.
    wigle_direct=False,
    wigle_roles=(),
)
def parse_0xb062(log_time: int, data: bytes) -> Diag0xB062 | None:
    if len(data) < 8:
        return None
    version = data[0]
    if version != _B062_VERSION_OBSERVED:
        return None
    num_subpackets = data[1]
    subpacket_id = data[4]
    subpacket_version = data[5]
    subpacket_length = unpack_from("<H", data, 6)[0]
    # subpacket_length is inclusive of its own 4-byte header and spans
    # [4:]. A payload that cannot hold it is truncated -> loud None.
    if 4 + subpacket_length > len(data):
        return None

    attempt_seq = attempt_result = timing_advance = None
    timing_advance_m: float | None = None
    rar_valid: bool | None = None

    layout = _B062_RACH_LAYOUT.get(subpacket_version)
    if layout is not None and subpacket_id == _B062_SUBPKT_ID:
        seq_off, res_off, valid_off, ta_off = layout
        if len(data) >= ta_off + 2:
            attempt_seq = data[seq_off]
            attempt_result = data[res_off]
            rar_valid = bool(data[valid_off])
            ta_raw = unpack_from("<H", data, ta_off)[0]
            if rar_valid and ta_raw != _TA_INVALID:
                timing_advance = ta_raw
                timing_advance_m = round(ta_raw * _METERS_PER_TA_UNIT, 1)

    return Diag0xB062(
        log_time=log_time,
        version=version,
        num_subpackets=num_subpackets,
        subpacket_id=subpacket_id,
        subpacket_version=subpacket_version,
        subpacket_length=subpacket_length,
        attempt_seq=attempt_seq,
        attempt_result=attempt_result,
        rar_valid=rar_valid,
        timing_advance=timing_advance,
        timing_advance_m=timing_advance_m,
        payload_size=len(data),
        subpacket_payload=data[8:],
    )
