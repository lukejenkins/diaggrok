"""0xB167 — LTE ML1 Random Access Request (MSG1) Report: PRACH preamble, power, timing.

The legacy registry label
`LtePdcpB167` was a misnomer (this is ML1 RACH, not PDCP). One record per PRACH
preamble the UE schedules (MSG1 of the contention/contention-free RACH).

### Layout

Three wire versions, one shape. v0x05 is 28 B; v0x19 and v0x28 are 32 B (the
same 28 B plus a trailing i32). The only in-body difference is the preamble
word: v0x19/v0x28 pack it from **bit 3** (bits 0-2 always 0), v0x05 from bit 0.

    @0   u8   version                 {0x05, 0x19, 0x28}
    @1   3B   hdr_raw                 raw (usually 0; firmware scratch on some records)
    @4   u32  preamble word           v0x05 shift s=0, v0x19/0x28 s=3:
                bits s+0..s+5    preamble_index     0..63 (RAPID the UE sent)
                bits s+6..s+15   root_sequence_u    physical Zadoff-Chu root u (0..838)
                bits s+16..s+25  cyclic_shift       Cv, samples
                remaining bits   exposed in preamble_word_raw
    @8   u32  prach word
                bits 0-7         prach_tx_power_dbm i8, COMPUTED (target + pathloss, uncapped)
                bits 26-27       preamble_format    TS 36.211 format 0..3
                the rest         prach_word_raw (CANDIDATE: bits 19-25 track SIB2
                                 prach-FreqOffset on RM500Q 7/7 but only 26/40 fleet-wide)
    @12  u16  raw                     padding (0xDEAD-class scratch seen)
    @14  u16  prach timing            bits 0-9 sfn, bits 12-15 subframe
    @16  u16  rar window start        same packing
    @18  u16  rar window end          same packing
    @20  u16  ra_rnti                 TS 36.321 RA-RNTI
    @22  u16  raw                     padding (0xDEAD-class scratch seen)
    @24  i8   actual_tx_power_dbm     after the Pcmax clip (23 dBm on a class-3 UE)
    @25  3B   tail_raw                raw
    @28  i32  word_28_raw             v0x19/v0x28 only, meaning unknown → raw

### Grounding (256 records, 8 captures, all three versions)

* **timing / window / RA-RNTI (256/256, spec arithmetic).** ra_rnti == 1 +
  prach_subframe on every record (TS 36.321 5.1.4, FDD t_id). The window end is
  always 10 subframes after the start (ra-ResponseWindowSize sf10). The window
  start is 3 + (preamble duration - 1) subframes after the PRACH: +3 with format 0,
  +4 with format 1, +5 with format 3. That is exactly the preamble_format field.
* **cyclic_shift (256/256).** Cv == (p mod floor(839/N_CS)) * N_CS for a
  TS 36.211 Table 5.7.2-2 N_CS on every record. Against the same-capture SIB2
  zeroCorrelationZoneConfig it is 39/39 on v0x28.
* **root_sequence_u.** On two MC7455 cells (N_CS=0, one root per preamble) u is a
  strict function of preamble_index (39/39, 40/40). All 35 adjacent (p, p+1) pairs
  sum to exactly 839, which is the (u, 839-u) pairing of Table 5.7.2-4.
* **F3 v0x19** (LM960A18): `lte_ml1_prach.c:4087 "RACH MSG1 SCHED IND on SFN : %d
  SUB-FN : %d"` equals prach_sfn/prach_subframe 3/3 (34/7, 486/1, 577/4).
  `lte_ml1_prach.c:3189 "... dl_pathloss=%d, Target pwr=%d, TX power=%d"`
  equals actual_tx_power_dbm 2/2 (8, -2), and target(-110) + pathloss == the
  computed prach_tx_power_dbm.
* **F3 v0x05** (EG25-G): `pgi_msgr.c:1498 "Tech 0 Band 3 TxPower -6"` equals
  both power bytes (-6), and `lte_ml1_dlm_schd.c:375 "[RA(16bit),Temp(16bit)]
  0x0005_5B89"` equals ra_rnti 5. Both are 1 ms before the record.
* **F3 v0x28** (RM500Q-AE): 7/7 records co-emit 1:1 with `lte_rrc_stm.c`
  `LTE_CPHY_RACH_MSG1_SCHED_IND` (dt 1.4k-2.2k ticks). preamble_format vs SIB2
  prach-ConfigIndex // 16 is 39/39.
* **Power clip.** On the MC7455 prach_tx_power_dbm is 50 but actual_tx_power_dbm
  is 23. On EG18-NA it is 34..50 against 23 actual.
* **0x60.** EVENT_LTE_RACH_ACCESS_START(_V2) / RAID_MATCH / RESULT bracket each
  record (LM960 3/3, EG25 1/1). The RAID_MATCH payload is a 1-byte flag, not the
  RAPID, so the events label no field.

**Whole bearing corpus (109 captures, 2,054 records: v0x05 1,394 / v0x19 225 /
v0x28 435):** 0 rejected, 0 invariant violations. ra_rnti == 1 + subframe,
window length 10, window offset <-> preamble_format (3<->0, 4<->1, 5<->3), Cv on
the N_CS lattice and actual <= computed power all hold 2,054/2,054.

Not every RACH emits 0xB167: the LM960 ran 6 RACH procedures (6 event triples)
but logged 3 records, 1:1 with the 3 F3 `MSG1 SCHED IND` prints.

Log name: LOG_LTE_ML1_RACH_ATTEMPT_LOG_C
Also known as: LOG_CONTENTION_RESOLUTION_MESSAGE_MSG4_REPORT, LOG_LTE_ML1_CONTENTION_RESOLUTION_MESSAGE_MSG4_REPORT, LOG_LTE_ML1_RANDOM_ACCESS_REQUEST_MSG1_REPORT, LOG_LTE_RANDOM_ACCESS_REQUEST_MSG1_REPORT, LTE ML1
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# byte 0 is the version. v0x05 = MDM9x07/9x30 (EG25-G, MC7455), 28 B;
# v0x19 = SDX20/MDM9x50 (LM960, EG18-NA, EM7565) and v0x28 = SDX55/SDX6x, 32 B.
_B167_VERSIONS_OBSERVED = (0x05, 0x19, 0x28)
_SIZE = {0x05: 28, 0x19: 32, 0x28: 32}
_PREAMBLE_SHIFT = {0x05: 0, 0x19: 3, 0x28: 3}


def _sfn_sf(word: int) -> tuple[int, int]:
    """(sfn, subframe) from the packed timing u16: sfn bits 0-9, subframe 12-15."""
    return word & 0x3FF, (word >> 12) & 0xF


@dataclass
class Diag0xB167:
    """0xB167 — LTE ML1 RACH MSG1 report (one per scheduled PRACH preamble)."""
    log_time: int
    version: int
    preamble_index: int
    root_sequence_u: int
    cyclic_shift: int
    preamble_word_raw: int
    prach_tx_power_dbm: int
    preamble_format: int
    prach_word_raw: int
    prach_sfn: int
    prach_subframe: int
    rar_window_start_sfn: int
    rar_window_start_subframe: int
    rar_window_end_sfn: int
    rar_window_end_subframe: int
    ra_rnti: int
    actual_tx_power_dbm: int
    word_28_raw: int | None
    hdr_raw: bytes
    tail_raw: bytes
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB167",
            "log_time": self.log_time,
            "version": self.version,
            "preamble_index": self.preamble_index,
            "root_sequence_u": self.root_sequence_u,
            "cyclic_shift": self.cyclic_shift,
            "preamble_word_raw": self.preamble_word_raw,
            "prach_tx_power_dbm": self.prach_tx_power_dbm,
            "preamble_format": self.preamble_format,
            "prach_word_raw": self.prach_word_raw,
            "prach_sfn": self.prach_sfn,
            "prach_subframe": self.prach_subframe,
            "rar_window_start_sfn": self.rar_window_start_sfn,
            "rar_window_start_subframe": self.rar_window_start_subframe,
            "rar_window_end_sfn": self.rar_window_end_sfn,
            "rar_window_end_subframe": self.rar_window_end_subframe,
            "ra_rnti": self.ra_rnti,
            "actual_tx_power_dbm": self.actual_tx_power_dbm,
            "word_28_raw": self.word_28_raw,
            "hdr_raw": self.hdr_raw,
            "tail_raw": self.tail_raw,
            "payload_size": self.payload_size,
        }


@register(
    0xB167,
    name="0xB167",
    description="0xB167 — LTE ML1 RACH MSG1 report: preamble index / root u / cyclic shift, PRACH power (computed + actual), preamble format, PRACH + RAR-window SFN/subframe, RA-RNTI",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Body decoded on all three versions. u32@4 preamble word "
        "(shift 0 on v0x05, 3 on v0x19/v0x28): preamble_index 6b, root_sequence_u "
        "10b, cyclic_shift 10b. u32@8: prach_tx_power_dbm i8 (computed, uncapped), "
        "preamble_format bits 26-27. u16@14/16/18 PRACH / RAR-window-start / "
        "RAR-window-end timing (sfn bits 0-9, subframe bits 12-15), u16@20 ra_rnti, "
        "i8@24 actual_tx_power_dbm, i32@28 raw on v0x19/v0x28. Spec arithmetic "
        "256/256 over 8 captures (RA-RNTI = 1 + t_id; window = +3/+4/+5 by format, "
        "10 sf long; Cv = (p mod floor(839/Ncs))*Ncs; root u (u, 839-u) pairing "
        "35/35). F3: LM960 v0x19 `lte_ml1_prach.c` SFN/SUB-FN 3/3 + TX power 2/2; "
        "EG25-G v0x05 `pgi_msgr.c` TxPower + `lte_ml1_dlm_schd.c` RA-RNTI; RM500Q "
        "v0x28 LTE_CPHY_RACH_MSG1_SCHED_IND 1:1 7/7. Byte-0 version gate "
        "{0x05, 0x19, 0x28}."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=15,
    fields_parsed=15,
    field_invariants={
        "version": {"enum": [0x05, 0x19, 0x28]},
        "prach_subframe": {"range": (0, 9)},
        "ra_rnti": {"range": (1, 60)},
    },
)
def parse_0xb167(log_time: int, data: bytes) -> Diag0xB167 | None:
    if len(data) < 1:
        return None
    version = data[0]
    if version not in _B167_VERSIONS_OBSERVED or len(data) < _SIZE[version]:
        return None
    s = _PREAMBLE_SHIFT[version]
    pw, cw = unpack_from("<II", data, 4)
    t_prach, t_start, t_end, ra_rnti = unpack_from("<HHHH", data, 14)
    prach_sfn, prach_sf = _sfn_sf(t_prach)
    start_sfn, start_sf = _sfn_sf(t_start)
    end_sfn, end_sf = _sfn_sf(t_end)
    return Diag0xB167(
        log_time=log_time,
        version=version,
        preamble_index=(pw >> s) & 0x3F,
        root_sequence_u=(pw >> (s + 6)) & 0x3FF,
        cyclic_shift=(pw >> (s + 16)) & 0x3FF,
        preamble_word_raw=pw,
        prach_tx_power_dbm=unpack_from("<b", data, 8)[0],
        preamble_format=(cw >> 26) & 0x3,
        prach_word_raw=cw,
        prach_sfn=prach_sfn,
        prach_subframe=prach_sf,
        rar_window_start_sfn=start_sfn,
        rar_window_start_subframe=start_sf,
        rar_window_end_sfn=end_sfn,
        rar_window_end_subframe=end_sf,
        ra_rnti=ra_rnti,
        actual_tx_power_dbm=unpack_from("<b", data, 24)[0],
        word_28_raw=unpack_from("<i", data, 28)[0] if len(data) >= 32 else None,
        hdr_raw=bytes(data[1:4]),
        tail_raw=bytes(data[25:28]),
        payload_size=len(data),
    )
