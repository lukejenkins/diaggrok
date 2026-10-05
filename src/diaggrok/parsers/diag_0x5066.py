"""0x5066 — LOG_GSM_L1_SCH_ACQUISITION: one GSM SCH decode, BSIC + TDMA frame number, F3-grounded.

## Full layout, F3-joined

One record per SCH (synchronisation burst) decode during GSM cell acquisition,
read on the ARFCN the preceding 0x5065 FCCH search locked: 55/55 records follow
a 0x5065 with the same ``arfcn_raw`` and ``attempt`` words. It carries the
decoder's CRC verdict and the raw 25-bit SCH information word, which holds
the cell's **BSIC** and the **reduced TDMA frame number** (T1, T2, T3′).

**There is no version byte.** Byte 0 is the ARFCN low byte (``0xAD`` = 685),
so a byte-0 version enum would pin ARFCNs, not versions. Payload size is the only format key: 26 B on the MC7700 (MDM9200),
34 B on the EG25-G (MDM9207), which appends a duplicated u32 metric pair.

### F3 joins (EG25-G, 0x79 plaintext)

Decoding ``sch_word`` per the 3GPP SCH information layout (BSIC 6 bits, T1 11,
T2 5, T3′ 3, packed MSB-first into 4 octets, here bytes +14..+17) and folding it
to a frame number with ``FN = 51·((T3 − T2) mod 26) + T3 + 1326·T1``
(T3 = 10·T3′ + 1, 3GPP 45.002):

* **BSIC.** ``tle_log.c:669 … BsIc:4, Arfcn:685`` is the only BSIC label in
  either capture. Every CRC-pass record on ARFCN 685 in both captures decodes
  BSIC 4 (13/13).
* **Frame number.** ``l1_sc_irat.c:9483 G2X: SC init Fn=%d`` prints the frame
  that RR's ``SC init`` reads right after the decode. Joined bounded (the next
  ``SC init`` before the next 0x5065 record), 11 of the 14 CRC-pass records have
  one. On 8 of those 11 it sits **exactly 3 frames** after the decoded FN
  (502361→502364, 502575→502578, 502779→502782, 524811→524814,
  1927576→1927579, 1927607→1927610, 1927719→1927722, 1927923→1927926;
  ``gl1_arbitrator_interface.c:1391 GARB … FN=524814`` agrees). The other
  3 sit at a constant −12286, a re-based timeline (W2G context): all three
  match each other.
* **CRC status.** ``rr_gprs_debug.c:4194 MPH_FCCH_SCH_DECODE_IND`` (or
  ``MPH_SELECT_SPECIFIC_BCCH_CNF``) follows 14/14 status-2 records in the two
  F3 captures and 0/3 status-0 ones. Across the corpus all 27 status-2 records decode legal T2 ≤ 25 / T3′ ≤ 4.
  9 of the 28 status-0 records do not (T3′ = 7, T2 > 25), and the rest carry
  random BSICs. So status 2 = CRC pass, and ``bsic``…``frame_number`` are left
  ``None`` on any other status.
* **``0x60`` events: silent.** Only a CFUN-cycle capture carries events.
  ``EVENT_GSM_CELL_SELECTION_START/END`` bracket its records, but no event
  carries an ARFCN or BSIC.
* **Black-box (SCAT 2.0.0).** ``GSM SCH acquistion: ARFCN: <n>/Band: <b>``
  agrees on ARFCN/band. Its ``Data:`` field is 25 bits whose value is bytes
  +14..+15 only (the top 9 bits are always 0), so SCAT does not decode BSIC/FN.
  F3 is the ground truth for the SCH word.

## Layout

======  =====  ===============  ================================================
offset  type   field            ground
======  =====  ===============  ================================================
+0      u16    arfcn_raw        bits 0–11 ``arfcn``, 12–15 ``band`` (as 0x5065;
                                SCAT A/B, F3 ``Arfcn:685``)
+2      u16    attempt          the FCCH attempt this SCH follows (55/55)
+4      u16    decode_status    2 = CRC pass, 0 = fail (F3 + T2/T3′ legality
                                above). Only 0 and 2 have been seen
+6      4 B    reserved_6       zero on 55/55
+10     u32    word_10          11 on 55/55. No label, kept raw
+14     u32    sch_word         the 25-bit SCH information word (< 2^25 on 55/55):
                                +14 ``BSIC<<2 | T1[10:9]``, +15 ``T1[8:1]``,
                                +16 ``T1[0]<<7 | T2<<2 | T3′[2:1]``, +17 ``T3′[0]``
+18     u32    sch_position_qs  CANDIDATE burst position in quarter-symbols:
                                ``k·5000 + c``, where ``c`` is stable per cell
                                within a capture (ARFCN 685 on one capture: 2044, 2044,
                                2044, then 2028 ×4). It lands about one TDMA
                                frame (5000 QS) after the FCCH's
                                ``fcch_position_qs``
+22     u32    word_22          14–67. No label, kept raw
+26     u32    metric           34 B form only. CANDIDATE quality metric (median
                                about 900 on CRC pass, about 370 on fail;
                                the ranges overlap)
+30     u32    metric_dup       34 B only; equals ``metric`` on 54/54 records
                                (the F3 shows ``rxdControl = 0``)
======  =====  ===============  ================================================

Corpus: 55 records / 8 captures. 100% parse, 0 invariant
violations. Future firmware may change the layout without changing the size.

Log name: LOG_GSM_L1_SCH_ACQUISITION
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.parsers.diag_0x5065 import BAND_NAMES, split_arfcn
from diaggrok.registry import register

SIZE_MDM9200 = 26
SIZE_MDM9207 = 34
SIZES = (SIZE_MDM9200, SIZE_MDM9207)
STATUS_CRC_PASS = 2


@dataclass
class SchInfo:
    """The 25-bit SCH information word, split (3GPP 44.018 / 45.002)."""
    bsic: int
    ncc: int
    bcc: int
    t1: int
    t2: int
    t3_prime: int
    frame_number: int


def decode_sch_word(b: bytes) -> SchInfo:
    """Split the 4 SCH-information octets (payload +14..+17)."""
    o1, o2, o3, o4 = b[0], b[1], b[2], b[3]
    bsic = o1 >> 2
    t1 = ((o1 & 0x03) << 9) | (o2 << 1) | (o3 >> 7)
    t2 = (o3 >> 2) & 0x1F
    t3p = ((o3 & 0x03) << 1) | (o4 & 0x01)
    t3 = 10 * t3p + 1
    fn = 51 * ((t3 - t2) % 26) + t3 + 51 * 26 * t1
    return SchInfo(bsic=bsic, ncc=bsic >> 3, bcc=bsic & 0x07,
                   t1=t1, t2=t2, t3_prime=t3p, frame_number=fn)


@dataclass
class Diag0x5066:
    """One GSM L1 SCH decode."""
    log_time: int
    arfcn_raw: int
    arfcn: int
    band: int
    band_name: str | None
    attempt: int
    decode_status: int
    crc_pass: bool
    reserved_6: bytes
    word_10: int
    sch_word: int
    sch: SchInfo | None
    sch_position_qs: int
    word_22: int
    metric: int | None
    metric_dup: int | None
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        s = self.sch
        return {
            "type": "Diag0x5066",
            "log_time": self.log_time,
            "arfcn_raw": self.arfcn_raw,
            "arfcn": self.arfcn,
            "band": self.band,
            "band_name": self.band_name,
            "attempt": self.attempt,
            "decode_status": self.decode_status,
            "crc_pass": self.crc_pass,
            "reserved_6": self.reserved_6,
            "word_10": self.word_10,
            "sch_word": self.sch_word,
            "bsic": s.bsic if s else None,
            "ncc": s.ncc if s else None,
            "bcc": s.bcc if s else None,
            "t1": s.t1 if s else None,
            "t2": s.t2 if s else None,
            "t3_prime": s.t3_prime if s else None,
            "frame_number": s.frame_number if s else None,
            "sch_position_qs": self.sch_position_qs,
            "word_22": self.word_22,
            "metric": self.metric,
            "metric_dup": self.metric_dup,
            "payload_size": self.payload_size,
        }


@register(
    0x5066,
    name="0x5066",
    description=(
        "0x5066 — LOG_GSM_L1_SCH_ACQUISITION: one SCH decode — packed ARFCN+band, "
        "CRC status, 25-bit SCH word split to BSIC (NCC/BCC) + T1/T2/T3' + TDMA "
        "frame number (F3-joined), burst position (QS), metrics; no version byte"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full layout, F3-joined on two EG25-G (MDM9207) F3 captures. "
        "BSIC = F3 tle_log.c:669 'BsIc:4, Arfcn:685' on 13/13 "
        "CRC-pass 685 records; decoded FN + 3 = F3 l1_sc_irat.c:9483 'SC init Fn' "
        "on 8/11 (the other 3 at a constant -12286 re-base); the decode-ind "
        "follows 14/14 status-2 and 0/3 status-0 records; T2/T3' are legal on "
        "27/27 status-2 records. ARFCN/band agree with SCAT. Byte 0 is the "
        "ARFCN low byte, not a version; payload size (26 B MDM9200 / 34 B "
        "MDM9207) is the only format key. sch_position_qs and metric are "
        "CANDIDATE; word_10, word_22 kept raw."
    ),
    issues=(),
    primary_issue=None,
    fields_identified=12,
    fields_parsed=16,
    version_field="none",
    version_less=True,
    field_invariants={
        "payload_size": {"enum": list(SIZES)},
        "arfcn": {"range": [0, 1023]},
        "t2": {"range": [0, 25]},
        "t3_prime": {"range": [0, 4]},
    },
)
def parse_0x5066(log_time: int, data: bytes) -> Diag0x5066 | None:
    n = len(data)
    if n not in SIZES:
        return None
    raw, attempt, status = unpack_from("<HHH", data, 0)
    word_10, sch_word, pos, word_22 = unpack_from("<IIII", data, 10)
    metric = metric_dup = None
    if n == SIZE_MDM9207:
        metric, metric_dup = unpack_from("<II", data, 26)
    arfcn, band = split_arfcn(raw)
    crc_pass = status == STATUS_CRC_PASS
    return Diag0x5066(
        log_time=log_time,
        arfcn_raw=raw,
        arfcn=arfcn,
        band=band,
        band_name=BAND_NAMES.get(band),
        attempt=attempt,
        decode_status=status,
        crc_pass=crc_pass,
        reserved_6=bytes(data[6:10]),
        word_10=word_10,
        sch_word=sch_word,
        sch=decode_sch_word(data[14:18]) if crc_pass else None,
        sch_position_qs=pos,
        word_22=word_22,
        metric=metric,
        metric_dup=metric_dup,
        payload_size=n,
    )
