"""0x506C — LOG_GSM_L1_BURST_METRICS: serving-cell GSM burst metrics, up to 4 bursts per record.

## Full 93-byte layout, oracle-grounded

The legacy twin of 0x506A (``LOG_GSM_L1_NEW_BURST_METRICS``). One record per
received serving-cell block on the GSM idle-mode CCCH/BCCH: up to four
downlink bursts, each with its frame number, ARFCN, raw energy, received power
in dBm×16 and four receiver metrics. SCAT prints it as ``GSM Serving Cell
Burst Metric``.

**There is no version byte** (``version_less=True``). Byte 0 is the
``channel`` byte of the ``gsm_l1_burst_metrics`` struct in the open-source
SRLabs diag-parser. 0x506A carries the same 0x03 byte at +1, after its own
version byte (0x04). Bytes 4..7 fall inside the first burst slot (FN high
byte, ARFCN word, RSSI low byte); they are not a config word.

### Grounding

* **0x506A twin (byte join).** In the 9 captures that carry both codes, every
  burst here (1329/1329) has a 0x506A burst with the same FN and ARFCN word,
  and all 10 shared fields are equal. 670/675 record pairs share a timestamp.
  The MC7700 (MDM9200) emits only 0x506C.
* **Black-box oracle (SCAT, output only).** SCAT prints ``GSM Serving Cell
  Burst Metric: ARFCN: <a>/BC: <b>, RSSI: <r>, RxPwr: <p>`` once per burst.
  Joined by value on all 10 captures that carry the code, every one of SCAT's **1165
  lines** equals ``arfcn``/``band``/``rssi``/``rx_power_dbm_x16 / 16`` of a
  burst decoded here, with 0 unmatched. That includes 235/235 on the MC7700.
  SCAT prints fewer lines than there are bursts because of a framer gap.
* **F3 (four EG25-G captures, 0x79 plaintext).**
  - ``gl1_arbitrator_cxm.c:502 GARB -> CXM : MCS_CXM_COEX_POWER_IND …
    DL=<n>dBm10`` is co-emitted (median Δt 0.01 ms). As a signed value it
    equals the record's mean ``rx_power_dbm_x16 × 10 / 16`` within 1 dB on
    336/341 and within 3 dB on 341/341 (-32765 is CXM's invalid sentinel).
  - ``l1_sc_irat.c:7347 G2X: SC leave_idle: abort=0 Fn=<n>`` equals the last
    burst's ``frame_number`` + 1 or + 2 on 75/85. The other 10 are idle
    exits with no record in the preceding 60 frames.
  - ``l1_sc_irat.c:7470 … sc_pwr=<n>`` (dBm×16, filtered) is within 0.5 dB of
    the next record's mean on 955/1107.
* **``0x60`` events: absent.** None of these captures carries one.

### Corpus

763 records across 10 captures (EG25-G MDM9207 on two firmware builds, an
EC25 drive and the MC7700 MDM9200). Every record is 93 B with byte 0 = ``0x03``. Slots fill
from slot 0 with no gaps (763/763). By burst count, 344 records carry 1 burst,
146 carry 2, 117 carry 3 and 156 carry 4. Every burst is band 10 (PCS 1900),
on ARFCNs 513, 559, 637 and 685. ``frame_number mod 51`` lands only on BCCH
(2–5) and CCCH blocks (6–9, 12–15, 36–38, 46–47), and the bursts inside one
record are consecutive frames (848/848).

## Layout (93 B)

======  =====  ==================  ============================================
offset  type   field               ground
======  =====  ==================  ============================================
+0      u8     channel             0x03 on 763/763. diag-parser name; the enum
                                   is unlabelled (both BCCH and CCCH blocks
                                   carry 3), so it is kept raw
+1      23 B   burst[0..3]         four slots; an all-zero slot is unused
======  =====  ==================  ============================================

Burst slot (23 B) — the first 23 bytes of a 0x506A slot:

======  =====  ==================  ============================================
+0      u32    frame_number        GSM TDMA FN (< 2715648). F3 ``SC leave_idle
                                   Fn`` = last FN + 1/2 (75/85)
+4      u16    arfcn_raw           bits 0–11 ``arfcn``, bits 12–15 ``band``
                                   (the 0x5065 packed word; SCAT 1165/1165)
+6      u32    rssi                linear energy; SCAT ``RSSI`` 1165/1165
+10     i16    rx_power_dbm_x16    SCAT ``RxPwr`` ×16 1165/1165; F3 CXM
                                   ``DL dBm10`` 336/341 within 1 dB
+12     i16    dc_offset_i         CANDIDATE: a signed I/Q pair, range
+14     i16    dc_offset_q         -2432..1728. No F3 label
+16     i16    freq_offset         CANDIDATE: clamped to [-200, 200] (0 on
                                   652/1611). No label
+18     i16    timing_offset       CANDIDATE: -8..16, mostly multiples of 4.
                                   No label
+20     u16    snr                 CANDIDATE: 148–27212. No label
+22     u8     gain_state          CANDIDATE: 1 (6, MC7700 only) / 2 / 3
======  =====  ==================  ============================================

The DC/frequency/timing/SNR/gain names come from the diag-parser struct and
match 0x506A's. F3 does not label them, so they stay CANDIDATE.

The payload size is the format guard. A future firmware could change the
layout at 93 B, so a ``channel`` other than 0x03 is flagged by the invariant
(not rejected) to surface such a record in a corpus audit.

Log name: LOG_GSM_L1_BURST_METRICS
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.parsers.diag_0x5065 import BAND_NAMES, split_arfcn
from diaggrok.registry import register

SIZE = 93
CHANNEL_OBSERVED = 0x03
HEADER = 1
SLOT = 23
SLOTS = 4
_SLOT_FMT = "<IHIhhhhhHB"


@dataclass
class Burst0x506C:
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
        }


@dataclass
class Diag0x506C:
    """0x506C — GSM L1 burst metrics (serving cell), up to 4 bursts."""
    log_time: int
    channel: int
    num_bursts: int
    payload_size: int
    bursts: list[Burst0x506C] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x506C",
            "log_time": self.log_time,
            "channel": self.channel,
            "num_bursts": self.num_bursts,
            "payload_size": self.payload_size,
            "bursts": [b.to_dict() for b in self.bursts],
        }


def _parse_slot(index: int, s: bytes) -> Burst0x506C:
    fn, raw, rssi, pwr, dci, dcq, fo, to, snr, gain = unpack_from(_SLOT_FMT, s, 0)
    arfcn, band = split_arfcn(raw)
    return Burst0x506C(
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
    )


@register(
    0x506C,
    name="0x506C",
    description=(
        "0x506C — LOG_GSM_L1_BURST_METRICS: serving-cell GSM burst metrics, "
        "up to 4 bursts — FN, packed ARFCN+band, RSSI, RxPwr dBm×16 (SCAT A/B "
        "1165/1165, F3 CXM DL dBm10), DC I/Q, freq/timing offset, SNR"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full 93-byte layout, a 1-byte channel "
        "plus 4 × 23-byte burst slots, version-less. ARFCN/band/RSSI/RxPwr "
        "match all 1165 of SCAT's 'GSM Serving Cell Burst Metric' lines over the "
        "10 captures that carry the code (incl. MC7700 235/235); every burst is byte-equal "
        "to its co-emitted 0x506A twin (1329/1329); RxPwr agrees with the "
        "co-emitted F3 GARB->CXM 'DL=<n>dBm10' (within 1 dB on 336/341); FN "
        "agrees with F3 'SC leave_idle Fn' (+1/+2 on 75/85). DC I/Q, "
        "freq/timing offset, SNR and gain are CANDIDATE (F3-silent; names from "
        "the open-source SRLabs diag-parser struct). Byte 0 is a channel "
        "byte, not a version."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=6,
    fields_parsed=17,
    version_less=True,
    field_invariants={
        "channel": {"enum": [CHANNEL_OBSERVED]},
        "payload_size": {"enum": [SIZE]},
        "num_bursts": {"range": [1, SLOTS]},
    },
)
def parse_0x506c(log_time: int, data: bytes) -> Diag0x506C | None:
    if len(data) != SIZE:
        return None
    bursts: list[Burst0x506C] = []
    for i in range(SLOTS):
        s = data[HEADER + SLOT * i:HEADER + SLOT * (i + 1)]
        if not any(s):
            continue
        bursts.append(_parse_slot(i, s))
    return Diag0x506C(
        log_time=log_time,
        channel=data[0],
        num_bursts=len(bursts),
        payload_size=len(data),
        bursts=bursts,
    )
