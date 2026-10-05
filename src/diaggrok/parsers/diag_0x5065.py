"""0x5065 — LOG_GSM_L1_FCCH_ACQUISITION: one GSM FCCH (frequency-correction burst) search attempt.

## Full 16-byte layout, oracle-grounded

One record per FCCH search attempt during GSM cell acquisition (PLMN search,
cell selection, W2G redirection). When the search locks, the GSM L1 reads the
SCH on the same ARFCN next, and **every** 0x5066 SCH record in the corpus
(55/55) is preceded by a 0x5065 record carrying the same ``arfcn_raw`` and
``attempt`` words.

**There is no version byte.** Byte 0 is the low byte of the packed ARFCN
word (``0xAD`` is ARFCN 685, ``0x7D`` 637, ``0xCA`` 714), so treating it as
a version would yield many spurious "versions". Payload size (16 B on every
record, MDM9200 and MDM9207 alike) is the only format guard.

### Grounding

* **Black-box oracle (SCAT 2.0.0, output only).** SCAT prints ``GSM FCCH
  acquistion: ARFCN: <n>/Band: <b>`` for this code. On the four captures
  that carry it (two EG25-G F3 captures, an EG25-G survey, an EC25 drive)
  every printed pair equals ``arfcn``/``band`` decoded
  here: 685/10, 683/10, 637/10, 639/10, 223/11, **983/8**. SCAT drops some
  records to a framer gap, so the join is by value, not by count.
* **Band enum: band-legal on 88/88 records.** 8 holds ARFCNs 27 and 983
  (E-GSM 900: 0–124, 975–1023), 9 holds 537 (DCS 1800), 10 holds 512–809
  (PCS 1900: 512–810), 11 holds 136 and 223 (GSM 850: 128–251). The names in
  ``BAND_NAMES`` are that range fit, a CANDIDATE label. No F3 site names
  the enum.
* **F3 (two EG25-G captures, 0x79 plaintext).** ``rr_gprs_debug.c:4194
  gs1:IMsg: MPH_FCCH_SCH_DECODE_IND`` follows the FCCH→SCH pair on every
  CRC-pass SCH, and ``tle_log.c:669 … BsIc:4, Arfcn:685`` labels the ARFCN the
  pair was on (see 0x5066). No F3 site prints the FCCH metrics themselves.
* **``0x60`` events: silent.** Only a CFUN-cycle capture carries events.
  ``EVENT_GSM_CELL_SELECTION_START/END`` bracket its ten records, but no event
  lands near a burst and none carries an ARFCN.

## Layout (16 B)

======  =====  =================  ==============================================
offset  type   field              ground
======  =====  =================  ==============================================
+0      u16    arfcn_raw          bits 0–11 ``arfcn``, bits 12–15 ``band``
                                  (SCAT A/B, band-legal 88/88)
+2      u16    attempt            1-based search attempt on this ARFCN: runs
                                  1, 2, 3, … across retries (16 retries on an
                                  unlockable 223); copied into the 0x5066 that
                                  follows (55/55)
+4      i16    field_4            0 / 1 / 2 / -1; rises as ``attempt`` grows
                                  (ARFCN 223: 0 at 2–10, 1 at 11–15, 2 at 16).
                                  No label, kept raw
+6      u16    fcch_position_qs   CANDIDATE: burst position in quarter-symbols.
                                  A multiple of 4 on 88/88. Mod 5000 (QS per
                                  TDMA frame) it matches the following SCH's
                                  ``sch_position_qs`` within about ±100 QS on
                                  most pairs, and the SCH sits about 5000 QS
                                  (one frame) later: 45012 → 50000,
                                  22080 → 27044. 3GPP 45.002 puts SCH in the
                                  frame right after FCCH on TS0
+8      i16    freq_offset_0      CANDIDATE frequency-offset estimates. Small
+10     i16    freq_offset_1      (|x| < 500) whenever the SCH then decodes;
                                  ±12,000–32,000 on searches that never reach
                                  an SCH. ``freq_offset_1 - freq_offset_0`` is
                                  a multiple of 50 on 88/88. Unit unlabelled
+12     i16    word_12            saturates at -32768 / 32767 or reads 0 on
                                  most records. No label, kept raw
+14     u16    detect_metric      CANDIDATE detection metric: ~256–500 on
                                  failed searches (floor 258), 300–20,000 when
                                  the SCH follows. Looks like a Q8 ratio
                                  (256 = 1.0), not confirmed
======  =====  =================  ==============================================

Corpus: 88 records / 10 captures (EG25-G MDM9207 ×8, MC7700
MDM9200 ×1, EC25 drive ×1). 100% parse, 0 invariant violations. Future
firmware may change the layout without changing the 16-byte length; the
size gate cannot see that.

Log name: LOG_GSM_L1_FCCH_ACQUISITION
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

SIZE = 16

# CANDIDATE band names: the GSM band whose ARFCN range holds every ARFCN seen
# under each enum value (band-legal on 88/88 0x5065 + 55/55 0x5066 records).
BAND_NAMES = {8: "EGSM900", 9: "DCS1800", 10: "PCS1900", 11: "GSM850"}


def split_arfcn(raw: int) -> tuple[int, int]:
    """Packed GSM L1 ARFCN word → ``(arfcn, band)``. Shared with 0x5066."""
    return raw & 0x0FFF, raw >> 12


@dataclass
class Diag0x5065:
    """One GSM L1 FCCH acquisition attempt."""
    log_time: int
    arfcn_raw: int
    arfcn: int
    band: int
    band_name: str | None
    attempt: int
    field_4: int
    fcch_position_qs: int
    freq_offset_0: int
    freq_offset_1: int
    word_12: int
    detect_metric: int
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x5065",
            "log_time": self.log_time,
            "arfcn_raw": self.arfcn_raw,
            "arfcn": self.arfcn,
            "band": self.band,
            "band_name": self.band_name,
            "attempt": self.attempt,
            "field_4": self.field_4,
            "fcch_position_qs": self.fcch_position_qs,
            "freq_offset_0": self.freq_offset_0,
            "freq_offset_1": self.freq_offset_1,
            "word_12": self.word_12,
            "detect_metric": self.detect_metric,
            "payload_size": self.payload_size,
        }


@register(
    0x5065,
    name="0x5065",
    description=(
        "0x5065 — LOG_GSM_L1_FCCH_ACQUISITION: one FCCH search attempt — packed "
        "ARFCN+band (SCAT A/B), attempt counter, burst position (QS), frequency-"
        "offset pair and detection metric; no version byte"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full 16-byte layout. ARFCN/band match "
        "SCAT's 'GSM FCCH acquistion: ARFCN/Band' on every printed line "
        "(685/683/637/639 band 10, 223 band 11, 983 band 8) and are band-legal on "
        "88/88; attempt is copied into the following 0x5066 (55/55); FCCH->SCH "
        "pairs are joined to F3 MPH_FCCH_SCH_DECODE_IND / SC init Fn via 0x5066. "
        "Byte 0 is the ARFCN low byte, not a version; payload size is the only "
        "format guard. field_4, word_12 kept raw; position, frequency-offset "
        "and detection-metric names are CANDIDATE."
    ),
    issues=(),
    primary_issue=None,
    fields_identified=7,
    fields_parsed=9,
    version_field="none",
    version_less=True,
    field_invariants={
        "payload_size": {"enum": [SIZE]},
        "arfcn": {"range": [0, 1023]},
    },
)
def parse_0x5065(log_time: int, data: bytes) -> Diag0x5065 | None:
    if len(data) != SIZE:
        return None
    raw, attempt, f4, pos, fo0, fo1, w12, metric = unpack_from("<HHhHhhhH", data, 0)
    arfcn, band = split_arfcn(raw)
    return Diag0x5065(
        log_time=log_time,
        arfcn_raw=raw,
        arfcn=arfcn,
        band=band,
        band_name=BAND_NAMES.get(band),
        attempt=attempt,
        field_4=f4,
        fcch_position_qs=pos,
        freq_offset_0=fo0,
        freq_offset_1=fo1,
        word_12=w12,
        detect_metric=metric,
        payload_size=len(data),
    )
