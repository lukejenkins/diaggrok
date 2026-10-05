"""0x506A — LOG_GSM_L1_NEW_BURST_METRICS: serving-cell GSM burst metrics, up to 4 bursts per record.

## Full 150-byte layout, oracle-grounded

One record per received serving-cell block on the GSM idle-mode CCCH/BCCH:
up to four downlink bursts, each with its frame number, ARFCN, raw energy,
received power in dBm×16, and per-burst receiver metrics. An older name
table lists ``LOG_GSM_L1_FCCH_ACQUISITION``, which duplicates 0x5065's name
and does not fit this layout. The alias ``LOG_GSM_L1_NEW_BURST_METRICS``
matches what SCAT prints for it (``GSM Serving Cell New Burst Metric``).

### Grounding

* **Black-box oracle (SCAT, output only).** SCAT prints ``GSM Serving Cell New
  Burst Metric: ARFCN: <a>/BC: <b>, RSSI: <r>, RxPwr: <p>`` once per burst.
  The join is by value, on all 9 captures that carry the code (EG25-G ×6 on
  one firmware build, EG25-G ×1 on a second build, an EG25-G survey, and an
  EC25 drive). Every one of
  SCAT's **930 lines** equals ``arfcn``/``band``/``rssi``/
  ``rx_power_dbm_x16 / 16`` of some burst decoded here, with 0 unmatched.
  SCAT prints fewer lines than there are bursts because of a framer gap.
* **F3 (two EG25-G captures, A and B, 0x79 plaintext).**
  - ``gl1_arbitrator_cxm.c:502 GARB -> CXM : MCS_CXM_COEX_POWER_IND … DL=<n>dBm10``
    is co-emitted (Δt = 0 ms). As a signed value it equals the record's
    mean ``rx_power_dbm_x16 × 10 / 16`` within ±1 on 142/191 lines and within
    ±3 on 186/191 (capture A). On capture B it is within ±3 on 66/79. -32765 is CXM's
    invalid sentinel.
  - ``l1_sc_irat.c:7470 G2X:srch is pending … sc_pwr=<n>`` (dBm×16, filtered)
    prints just before the next record. It is within ±2 of that record's mean
    on 326/~560 lines (capture A) and within about 0.5 dB on most of the rest.
  - ``l1_sc_irat.c:7347 G2X: SC leave_idle: abort=0 Fn=<n>`` equals the last
    burst's ``frame_number`` + 1 or + 2 on 64/66 joins.
* **``0x60`` events: absent.** None of the 9 captures carries a
  ``0x60`` frame.

### Corpus

675 records across 9 captures (EG25-G MDM9207 on two firmware builds, plus
the EC25 drive). Every record is 150 B with byte 0 = ``0x04`` and
byte 1 = ``0x03``. Slots fill from slot 0 with no gaps (675/675). By burst
count: 343 records carry 1 burst, 137 carry 2, 68 carry 3 and 127 carry 4.
Every burst is band 10 (PCS 1900), on ARFCNs 513, 559, 637 and 685.
``frame_number mod 51`` lands only on BCCH (2–5) and CCCH blocks (6–9, 12–15,
36–38, 46–47), and the bursts inside one record are consecutive frames
(654/654).

## Layout (150 B)

======  =====  ==================  ============================================
offset  type   field               ground
======  =====  ==================  ============================================
+0      u8     version             0x04 on 675/675 (2 firmware builds, 2 SKUs)
+1      u8     header_byte1        0x03 on 675/675. No label, kept raw
+2      37 B   burst[0..3]         four slots; an all-zero slot is unused
======  =====  ==================  ============================================

Burst slot (37 B):

======  =====  ==================  ============================================
+0      u32    frame_number        GSM TDMA FN (< 2715648). F3 ``SC leave_idle
                                   Fn`` = last FN + 1/2 (64/66)
+4      u16    arfcn_raw           bits 0–11 ``arfcn``, bits 12–15 ``band``
                                   (the 0x5065 packed word; SCAT A/B 930/930)
+6      u32    rssi                linear energy; SCAT ``RSSI`` 930/930
+10     i16    rx_power_dbm_x16    SCAT ``RxPwr`` ×16 930/930; F3 CXM
                                   ``DL dBm10`` and ``sc_pwr`` (above)
+12     i16    dc_offset_i         CANDIDATE: a signed I/Q pair, range
+14     i16    dc_offset_q         about ±2400. No F3 label
+16     i16    freq_offset         CANDIDATE: clamped to [-200, 200] (0 on
                                   546/1329). No label
+18     i16    timing_offset       CANDIDATE: a multiple of 4 on 1294/1329,
                                   range -8..16. No label
+20     u16    snr                 CANDIDATE: 148–27212. No label
+22     u8     gain_state          CANDIDATE: 2 (1212) / 3 (117)
+23     u8     field_23            0 / 1 / 2. 1 and 2 only on the EC25 drive,
                                   the survey and the second EG25-G build.
                                   No label, kept raw
+24     u16    word_24             spread across the full range. No label, kept raw
+26     u8     snr_coarse          tracks ``snr / 170.67`` within +1
                                   (1328/1329 exact). No single divisor fits
                                   all records exactly, so this is not pinned
+27     u8     reserved            0 on 1329/1329
+28     u8     field_28            0 / 1 (114/1329, mostly the EC25 drive). Raw
+29     8 B    tail_raw            0 on 1329/1329
======  =====  ==================  ============================================

Payload size is only a format guard. A future firmware could change the
layout at 150 B under the same version byte, so both are pinned.

Log name: LOG_GSM_L1_FCCH_ACQUISITION
Also known as: LOG_GSM_L1_NEW_BURST_METRICS
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.parsers.diag_0x5065 import BAND_NAMES, split_arfcn
from diaggrok.registry import register

SIZE = 150
VERSION = 0x04
HEADER = 2
SLOT = 37
SLOTS = 4
_SLOT_FMT = "<IHIhhhhhHBBHBBB"  # through +28; +29..+36 is tail_raw


@dataclass
class Burst0x506A:
    """One serving-cell burst."""
    slot: int
    frame_number: int
    arfcn_raw: int
    arfcn: int
    band: int
    band_name: str | None
    rssi: int
    rx_power_dbm_x16: int
    rx_power_dbm: float
    dc_offset_i: int
    dc_offset_q: int
    freq_offset: int
    timing_offset: int
    snr: int
    gain_state: int
    field_23: int
    word_24: int
    snr_coarse: int
    reserved: int
    field_28: int
    tail_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot": self.slot,
            "frame_number": self.frame_number,
            "arfcn_raw": self.arfcn_raw,
            "arfcn": self.arfcn,
            "band": self.band,
            "band_name": self.band_name,
            "rssi": self.rssi,
            "rx_power_dbm_x16": self.rx_power_dbm_x16,
            "rx_power_dbm": self.rx_power_dbm,
            "dc_offset_i": self.dc_offset_i,
            "dc_offset_q": self.dc_offset_q,
            "freq_offset": self.freq_offset,
            "timing_offset": self.timing_offset,
            "snr": self.snr,
            "gain_state": self.gain_state,
            "field_23": self.field_23,
            "word_24": self.word_24,
            "snr_coarse": self.snr_coarse,
            "reserved": self.reserved,
            "field_28": self.field_28,
            "tail_raw": self.tail_raw,
        }


@dataclass
class Diag0x506A:
    """0x506A — GSM L1 new burst metrics (serving cell), up to 4 bursts."""
    log_time: int
    version: int
    header_byte1: int
    num_bursts: int
    payload_size: int
    bursts: list[Burst0x506A] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x506A",
            "log_time": self.log_time,
            "version": self.version,
            "header_byte1": self.header_byte1,
            "num_bursts": self.num_bursts,
            "payload_size": self.payload_size,
            "bursts": [b.to_dict() for b in self.bursts],
        }


def _parse_slot(index: int, s: bytes) -> Burst0x506A:
    (fn, raw, rssi, pwr, dci, dcq, fo, to, snr, gain, f23, w24, coarse,
     rsv, f28) = unpack_from(_SLOT_FMT, s, 0)
    arfcn, band = split_arfcn(raw)
    return Burst0x506A(
        slot=index,
        frame_number=fn,
        arfcn_raw=raw,
        arfcn=arfcn,
        band=band,
        band_name=BAND_NAMES.get(band),
        rssi=rssi,
        rx_power_dbm_x16=pwr,
        rx_power_dbm=pwr / 16,
        dc_offset_i=dci,
        dc_offset_q=dcq,
        freq_offset=fo,
        timing_offset=to,
        snr=snr,
        gain_state=gain,
        field_23=f23,
        word_24=w24,
        snr_coarse=coarse,
        reserved=rsv,
        field_28=f28,
        tail_raw=bytes(s[29:SLOT]),
    )


@register(
    0x506A,
    name="0x506A",
    description=(
        "0x506A — LOG_GSM_L1_NEW_BURST_METRICS: serving-cell GSM burst metrics, "
        "up to 4 bursts — FN, packed ARFCN+band, RSSI, RxPwr dBm×16 (SCAT A/B "
        "930/930, F3 CXM DL dBm10), DC I/Q, freq/timing offset, SNR"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full 150-byte layout, a 2-byte header "
        "plus 4 × 37-byte burst slots. ARFCN/band/RSSI/RxPwr match all 930 of "
        "SCAT's 'GSM Serving Cell New Burst Metric' lines over the 9 captures "
        "that carry the code (EG25-G MDM9207, EC25); RxPwr agrees with the co-emitted F3 GARB->CXM 'DL=<n>dBm10' "
        "(±1 on 142/191) and with RR 'sc_pwr'; FN agrees with F3 'SC leave_idle "
        "Fn' (+1/+2 on 64/66). DC I/Q, freq/timing offset, SNR and gain are "
        "CANDIDATE (F3-silent)."
    ),
    issues=(),
    primary_issue=None,
    fields_identified=8,
    fields_parsed=20,
    field_invariants={
        "version": {"enum": [VERSION]},
        "payload_size": {"enum": [SIZE]},
        "num_bursts": {"range": [1, SLOTS]},
    },
)
def parse_0x506a(log_time: int, data: bytes) -> Diag0x506A | None:
    if len(data) != SIZE or data[0] != VERSION:
        return None
    bursts: list[Burst0x506A] = []
    for i in range(SLOTS):
        s = data[HEADER + SLOT * i:HEADER + SLOT * (i + 1)]
        if not any(s):
            continue
        bursts.append(_parse_slot(i, s))
    return Diag0x506A(
        log_time=log_time,
        version=data[0],
        header_byte1=data[1],
        num_bursts=len(bursts),
        payload_size=len(data),
        bursts=bursts,
    )
