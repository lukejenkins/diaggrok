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

`attempt_result` observed enum {0, 1, 2, 3, 4} (Techplayon: 0 = success). Grounded
against the SCAT black-box oracle, which flagged the non-success values {1, 4}
on the same MC7455 capture (and {1, 3, 4} on the EP06A RACH-storm capture).
Value **1 is the failed / no-RAR outcome**: across
2,344 ver-2 records, every record with `attempt_result == 1` (2,234 of them)
has `rar_valid == 0` and `timing_advance == 0xffff`. Per-value semantics, as
far as the in-capture oracles pin them (see the per-layout block
below):
  * 0 — RACH success (F3 `LTE_MAC_ACCESS_CNF` / "RACH Successful"; GROUND).
  * 1 — this preamble got no matching RAR (GROUND).
  * 4 — terminal attempt: preamble budget exhausted, Random Access Problem
    (F3 `LTE_MAC_RANDOM_ACCESS_PROBLEM_IND`; 0x60 ACCESS_RESULT=00; GROUND).
    `rar_valid`/`timing_advance` on a 4 are a CARRY-OVER of the previous
    attempt's RAR, not a new one (2/2 observed) — do not count it twice.
  * 2 — CANDIDATE: RAR matched, then contention resolution failed. It is emitted
    70–95 ms after the RAR (a CR-timer expiry; 0 lands 9–37 ms after), never
    gets an ACCESS_CNF, and the procedure retries (n=8).
  * 3 — seen once (MDM9x50): RAR matched, procedure retried. Meaning unknown.

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

=== Per-layout F3 / 0x60 grounding (by subpacket layout) ===

Each subpacket layout was checked on its own records, against both in-capture
oracles:
  * sp.v2 (40 B, EG25G ×2 builds, 7 records over 4 captures): the record lands on
    the same tick as F3 `[LTE_ML1_DLM_RACH_SM] MSG4_STATE -> COMPLETE_STATE`
    (7/7). Before it come `MSG2_STATE -> MSG4_STATE` (RAR received; rar_valid=1)
    at -9..-14 ms (7/7) and `RACH_MSG1_SCHED_IND` at about -22 ms. After it comes
    `RRC CEP: Received MAC_ACCESS_CNF. RACH Successful` at +0.6 ms. All 7 are
    attempt_result=0. These builds emit no LTE RACH 0x60 events. The failure
    population (MC7455) has no F3-bearing capture.
  * sp.v3 (44 B, EP06A, 9,893 records over 7 captures, 0x60-rich):
    0x60 `EVENT_LTE_RACH_ACCESS_RESULT_V2`=00 follows each attempt_result=4
    record (201/201), and =c1/41 follows each attempt_result=0 (6/6).
    `RAID_MATCH_V2`=c1 precedes rar_valid=1 (14/14), and =c0 precedes
    rar_valid=0 (211/211). attempt_result=4 is always the last attempt of a
    procedure. The plaintext F3 mask here carries only the PRACH-Tx chain:
    `lte_rrc_stm.c:642 MSG1_SCHED_IND` runs about 16 ms before each record,
    1 per preamble, 5,286/5,286.
    The LM960/EM7565 drives also show `rach_procedure_done` within 3 ms.
  * sp.v49 (56 B, RM500Q-AE ×2 + FT980m, 55 records) and sp.v50 (60 B,
    RM520N-GL, 46 records): F3 `LTE_MAC_ACCESS_CNF` within 1.5 ms of the record
    ⇔ attempt_result=0 (79/79). No attempt_result∈{1,2,4} record has one (0/22).
    `MSG3_SENT_IND` comes at -12 ms on sp.v50 (46/46). On sp.v49, attempt_result=4
    comes 1.1 ms after `LTE_MAC_RANDOM_ACCESS_PROBLEM_IND` / "CRE trigger with
    cause: RACH-Problem" (1/1). The SDX55 0x60 RAID/RESULT payloads use a
    different encoding (cd/d1, 01/c1/41), so the MDM9x50 c0/c1 flag reading does
    not transfer.
`timing_advance` remains F3/0x60-N/A on every layout (RAID_MATCH is 1 byte).

=== v5 — preamble / power / TC-RNTI / Msg3 MAC PDU ===

Absolute offsets in `data` (ver-0x31 is ver-0x03 byte-for-byte; ver-0x32
shifts everything from `rar_valid` on by +3):

                                         ver02  ver03  ver31  ver32
    preamble_index        u8  RAPID 0..63    @12    @14    @14    @14
    preamble_target_power s16 dBm            @14    @16    @16    @16
    tc_rnti               u16 RAR TC-RNTI    @19    @21    @21    @24
    msg3_grant_bytes      u8  Msg3 TB bytes  @27    @29    @29    @32
    msg3_mac_pdu          grant bytes        @30    @32    @32    @35

`preamble_target_power_dbm` is PREAMBLE_RECEIVED_TARGET_POWER (TS 36.321
§5.1.3): P0 + (attempt−1)·step. It ramps by exactly the SIB2 powerRampingStep
between consecutive attempts (whole corpus: 9,721 of 9,861 ver-03 pairs step 4,
1,175 of 1,345 ver-02 pairs step 2, the rest step 2/4 from other cells), and the
first-attempt value is a SIB2 preambleInitialReceivedTargetPower (−90…−120).
`tc_rnti` is emitted only when `rar_valid`. `msg3_mac_pdu` is the raw UL-SCH
MAC PDU (TS 36.321 §6.1.2) of `msg3_grant_bytes` bytes. It is split into
subheaders and decoded: a 6-byte CCCH SDU becomes `msg3_ccch`, an UL-CCCH
RRCConnectionRequest / RRCConnectionReestablishmentRequest (TS 36.331 UPER),
and a C-RNTI MAC CE (LCID 27) becomes `msg3_c_rnti`. Typical grants are
9 bytes (`20 06 1f` = CCCH E=1 L=6, then padding, then the SDU) and 7 bytes
(`00` header, then the SDU). Byte [31] on ver-0x03 is left unnamed (it varies
0–7 across captures, so it is a HARQ-id CANDIDATE at best).

Edge values, kept raw: the power is the UNCLAMPED ramp target. EP06A RACH
storms reach attempt 44–52 and read +62…+94 dBm, still exactly
−110 + 4·(attempt−1), so do not clamp it to Pcmax. `preamble_index` reads 0xFF
on 14 sp.v49 records (all success with a RAR, over 6 SDX55 captures): a
"not reported" sentinel, not a RAPID.

Per-layout grounding (whole corpus, 122 captures, 0 parse failures):

  * sp.v3 (MDM9x50 — LM960, EM7565, EP06A): F3 names the fields directly.
    Plaintext `lte_mac_rach.c` sites joined to the record on 5 captures:
    `rach_send_preamble cur_raid` == preamble_index 14/14 (13 matched; one
    value 1 excluded from matching as ambiguous); `pwr_lvl` == power 14/14;
    `rach_preamble_resp_state_handler tmp_rnti` == tc_rnti 15/15;
    `trblk_size` == msg3_grant_bytes 15/15; the RRC `Preamble Initial power`
    print == the attempt-1 power 29/30. The Msg3 SDU equals the 0xB0C0 UL-CCCH
    record 8,906 times over the corpus. On the EP06A capture, qcsuper decodes
    the same RRCConnectionRequest with the same establishmentCause.
  * sp.v2 (MDM9x07 — MC7455, EG25G): no MAC RACH F3 site is enabled on these
    builds, so record identity rests on the MSG1 event lock above. The fields
    are grounded by three things: the Msg3 SDU matches 0xB0C0 (MC7455 452/452);
    the power ramp fits −100 dBm / 2 dB on 452/452; and qcsuper + SCAT decode
    SIB2 on the same capture with exactly `dBm-100` / `dB2`.
  * sp.v49 / sp.v50 (SDX55 / SDX6x): QSR4 builds print no MAC RACH site at the
    captured mask. Identity rests on the MSG1_SCHED_IND lock (SDX62 46/46). The
    Msg3 SDU matches 0xB0C0 114 / 216 times. tc_rnti is non-zero on every
    rar_valid record (161 / 237). The attempt-1 power is −110/−118/−98, all
    valid SIB2 values. The C-RNTI MAC CE path is exercised (45 / 8 records:
    connected-mode RACH).

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
    # RACH preamble / RAR / Msg3 fields (v5) — None as above. tc_rnti is
    # None unless rar_valid; msg3_* are None when the grant does not fit/parse.
    preamble_index: int | None
    preamble_target_power_dbm: int | None
    tc_rnti: int | None
    msg3_grant_bytes: int | None
    msg3_mac_pdu: bytes | None
    msg3_c_rnti: int | None
    msg3_ccch: dict[str, Any] | None
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
            "preamble_index": self.preamble_index,
            "preamble_target_power_dbm": self.preamble_target_power_dbm,
            "tc_rnti": self.tc_rnti,
            "msg3_grant_bytes": self.msg3_grant_bytes,
            "msg3_mac_pdu": self.msg3_mac_pdu,
            "msg3_c_rnti": self.msg3_c_rnti,
            "msg3_ccch": self.msg3_ccch,
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
# ver-0x03 body is ver-0x02 shifted +2 (2-byte `00 00` prefix) up to the TA; the
# Msg3 block sits 2 bytes further out again. Offsets are into `data` (the full
# log payload).
#   subpacket_version: (attempt_seq, attempt_result, preamble_index,
#                       preamble_target_power_s16, rar_valid, tc_rnti_u16,
#                       timing_advance_u16, msg3_grant_u8, msg3_mac_pdu)
_B062_RACH_LAYOUT = {
    0x02: (8, 9, 12, 14, 18, 19, 21, 27, 30),    # MDM9x30 / 40 B
    0x03: (10, 11, 14, 16, 20, 21, 23, 29, 32),  # MDM9x50 / 44 B
    0x31: (10, 11, 14, 16, 20, 21, 23, 29, 32),  # SDX55  / 56 B — == ver-0x03, longer trailer
    0x32: (10, 11, 14, 16, 23, 24, 26, 32, 35),  # SDX6x  / 60 B — rar_valid onward shifted +3
}

# UL-SCH MAC subheader LCIDs (TS 36.321 Table 6.2.1-2) that carry no L field,
# with their fixed control-element sizes in bytes.
_MAC_FIXED_CE = {26: 1, 27: 2, 28: 1, 29: 1, 30: 3, 31: 0}
_LCID_CCCH = 0
_LCID_C_RNTI = 27
_LCID_PADDING = 31
_ESTABLISHMENT_CAUSES = (
    "emergency", "highPriorityAccess", "mt-Access", "mo-Signalling",
    "mo-Data", "delayTolerantAccess-v1020", "mo-VoiceCall-v1280", "spare1",
)
_REESTABLISHMENT_CAUSES = (
    "reconfigurationFailure", "handoverFailure", "otherFailure", "spare1",
)


def _bits(sdu: bytes, start: int, n: int) -> int:
    """Read `n` bits MSB-first from `sdu` starting at bit `start` (PER-aligned)."""
    return (int.from_bytes(sdu, "big") >> (len(sdu) * 8 - start - n)) & ((1 << n) - 1)


def _decode_ul_ccch(sdu: bytes) -> dict[str, Any] | None:
    """Decode a 48-bit UL-CCCH SDU (TS 36.331 UL-CCCH-Message, UPER).

    Both r8 messages that ride Msg3 are exactly 48 bits:
      rrcConnectionRequest        c1 | 1 | ext=0 | ueId choice | 40-bit id | cause(3) | spare(1)
      rrcConnectionReestablishmentRequest
                                  c1 | 0 | ext=0 | c-RNTI(16) | PCI(9) | shortMAC-I(16) | cause(2) | spare(2)
    Any other shape (messageClassExtension, critical-extension future) -> None.
    """
    if len(sdu) != 6 or _bits(sdu, 0, 1) != 0 or _bits(sdu, 2, 1) != 0:
        return None
    if _bits(sdu, 1, 1):
        out: dict[str, Any] = {"message": "rrcConnectionRequest"}
        if _bits(sdu, 3, 1):
            out["ue_identity"] = "randomValue"
            out["random_value"] = _bits(sdu, 4, 40)
        else:
            out["ue_identity"] = "s-TMSI"
            out["mmec"] = _bits(sdu, 4, 8)
            out["m_tmsi"] = _bits(sdu, 12, 32)
        cause = _bits(sdu, 44, 3)
        out["establishment_cause"] = cause
        out["establishment_cause_name"] = _ESTABLISHMENT_CAUSES[cause]
        return out
    cause = _bits(sdu, 44, 2)
    return {
        "message": "rrcConnectionReestablishmentRequest",
        "c_rnti": _bits(sdu, 3, 16),
        "phys_cell_id": _bits(sdu, 19, 9),
        "short_mac_i": _bits(sdu, 28, 16),
        "reestablishment_cause": cause,
        "reestablishment_cause_name": _REESTABLISHMENT_CAUSES[cause],
    }


def _parse_msg3_mac_pdu(pdu: bytes) -> list[tuple[int, bytes]] | None:
    """Split an UL-SCH MAC PDU (TS 36.321 §6.1.2) into (lcid, sdu/ce) pairs.

    Returns None unless the subheaders consume the PDU exactly — the
    self-consistency check that the bytes really are a MAC PDU.
    """
    heads: list[tuple[int, int | None]] = []
    i = 0
    while True:
        if i >= len(pdu):
            return None
        b = pdu[i]
        if b & 0xC0:  # R/R bits must be 0
            return None
        ext, lcid = (b >> 5) & 1, b & 0x1F
        i += 1
        if lcid in _MAC_FIXED_CE:
            heads.append((lcid, _MAC_FIXED_CE[lcid]))
        elif lcid <= 10 and ext:
            if i >= len(pdu):
                return None
            if pdu[i] & 0x80:  # F=1 -> 15-bit L
                if i + 1 >= len(pdu):
                    return None
                length = ((pdu[i] & 0x7F) << 8) | pdu[i + 1]
                i += 2
            else:
                length = pdu[i]
                i += 1
            heads.append((lcid, length))
        elif lcid <= 10:
            heads.append((lcid, None))  # last subheader: SDU fills the rest
        else:
            return None
        if not ext:
            break
    out: list[tuple[int, bytes]] = []
    for lcid, length in heads:
        if lcid == _LCID_PADDING:
            continue  # zero-length here; trailing padding is absorbed below
        if length is None:
            length = len(pdu) - i
        if i + length > len(pdu):
            return None
        out.append((lcid, pdu[i:i + length]))
        i += length
    if heads[-1][0] == _LCID_PADDING:
        i = len(pdu)  # a last padding subheader means the remainder is padding
    return out if i == len(pdu) else None


@register(
    0xB062,
    name="0xB062",
    description="0xB062 — LTE MAC RACH Attempt: subpacket container + RACH preamble/power, RAR TA/TC-RNTI, Msg3 MAC PDU",
    version=5,
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
        "only as an A/B output check (clean-room; no Rayhunter/SCAT source read). "
        "v5 adds preamble_index, preamble_target_power_dbm, tc_rnti, "
        "msg3_grant_bytes and the Msg3 UL-SCH MAC PDU (CCCH SDU decoded as "
        "UL-CCCH per TS 36.331; C-RNTI MAC CE) on all four layouts, F3-named by "
        "lte_mac_rach.c rach_send_preamble / rach_preamble_resp / trblk_size and "
        "the CCCH SDU byte-matched to co-captured 0xB0C0 UL-CCCH PDUs."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=16,
    fields_parsed=16,
    field_invariants={
        "version": {"enum": [_B062_VERSION_OBSERVED]},
        "subpacket_id": {"enum": [_B062_SUBPKT_ID]},
    },
    # F3-sweep layout axis: subpacket_version keys the RACH body.
    layout_axes={"sp": "subpacket_version"},
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
    preamble_index = preamble_target_power_dbm = tc_rnti = msg3_grant_bytes = None
    timing_advance_m: float | None = None
    rar_valid: bool | None = None
    msg3_mac_pdu: bytes | None = None
    msg3_c_rnti: int | None = None
    msg3_ccch: dict[str, Any] | None = None

    layout = _B062_RACH_LAYOUT.get(subpacket_version)
    if layout is not None and subpacket_id == _B062_SUBPKT_ID:
        (seq_off, res_off, pre_off, pwr_off, valid_off, rnti_off, ta_off,
         grant_off, pdu_off) = layout
        if len(data) >= pdu_off:
            attempt_seq = data[seq_off]
            attempt_result = data[res_off]
            preamble_index = data[pre_off]
            preamble_target_power_dbm = unpack_from("<h", data, pwr_off)[0]
            rar_valid = bool(data[valid_off])
            ta_raw = unpack_from("<H", data, ta_off)[0]
            if rar_valid and ta_raw != _TA_INVALID:
                timing_advance = ta_raw
                timing_advance_m = round(ta_raw * _METERS_PER_TA_UNIT, 1)
            if rar_valid:
                # TC-RNTI is assigned by the RAR; without one the slot is stale.
                tc_rnti = unpack_from("<H", data, rnti_off)[0]
            msg3_grant_bytes = data[grant_off]
            if 0 < msg3_grant_bytes <= len(data) - pdu_off:
                msg3_mac_pdu = data[pdu_off:pdu_off + msg3_grant_bytes]
                for lcid, sdu in _parse_msg3_mac_pdu(msg3_mac_pdu) or ():
                    if lcid == _LCID_CCCH:
                        msg3_ccch = _decode_ul_ccch(sdu)
                    elif lcid == _LCID_C_RNTI:
                        msg3_c_rnti = unpack_from(">H", sdu)[0]

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
        preamble_index=preamble_index,
        preamble_target_power_dbm=preamble_target_power_dbm,
        tc_rnti=tc_rnti,
        msg3_grant_bytes=msg3_grant_bytes,
        msg3_mac_pdu=msg3_mac_pdu,
        msg3_c_rnti=msg3_c_rnti,
        msg3_ccch=msg3_ccch,
        payload_size=len(data),
        subpacket_payload=data[8:],
    )
