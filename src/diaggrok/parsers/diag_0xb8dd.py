"""0xB8DD — NR5G LL1 FW Serving FTL (frequency-tracking-loop state).

One record per NR FW frequency-tracking-loop (FTL) update of the serving
carrier. Two corpus layouts, one per version byte:

    v0x07  544 B  SDX55 (RM500Q, EM9190, SIM8202G-M2, RXM-G1, M2000, LV55,
                  R500L5)
    v0x06  588 B  SDX62 RM520N-GL R01A08, SDX65 Inseego M3100

The length must match exactly. Any other size, including one byte short
(587 / 543 B) or the 101/332/361/761/951 B misframe singletons in the corpus,
is rejected (None) and a throttled WARN names the size.

Common header:
    [0]      u8   version
    [2]      u8   hdr_b2 — 0x00 on v0x07, 0x03 on v0x06 (raw)
    [4:6]    u16  SFN (bits 0..9) | slot << 10. SFN == the firmware's own
                  ``RX_IU_TIME_UPDATE … sysframe`` F3 print: RXM-G1 v0x07
                  339/790 exact, RM520N v0x06 32/195, shifted control 0.
    [6:8]    u16  raw. NOT the serving PCI: unlike 0xB8D8's u16@6 it never
                  matches 0xB97F's serving PCI above noise (4 modems).

Body (offsets per version):
                       v0x07     v0x06
    ftl_snr[0..3]      @76 +4k   @80 +12k  u32, per-chain FTL SNR (linear,
                                           unscaled). BIT-EXACT == the
                                           same-tick 0xB8D8 u32@12/16/20/24.
    xo_freq_error_q45  @104      @72       s32, fractional frequency error
                                           ("ferr_by_flo_q45") in Q45.
    nr_arfcn           @92       @128      u32, == 0xB97F CC0 nr_arfcn.
    rf_freq_khz        @96       —         u32, tuned RF frequency in kHz;
                                           u32@100 repeats it on every record.
    rx_blocks          @160      @204      4 x 96 B, raw.

The vendor log viewer's parsed text for this code carries "Carrier Index = N"
and "FTL SNR =" (a community customized view). The FTL SNR words are
located above. The carrier index is NOT located: no byte tracks a CC index on
this corpus, which is single-carrier throughout.

Grounding:

* ``xo_freq_error_q45``, v0x06: equals a ``ferr_by_flo_q45`` value printed in
  the preceding 2 s by ``nrfw_traffic.c:1897`` / ``nrfw_xo_util.c`` ("freq err
  debug sFW/rxiu"). M3100 12,022/12,296 (control 761), RM520N 117/195
  (control 0). The record holds the loop's INPUT, the correction in effect,
  so the same-tick print, which is that iteration's output, does not equal it.
  The firmware prints the same raw value as ``xo_freq_error_ppm``. The Q45
  reading is the print's own name, and the arithmetic closes:
  ``ferr_by_flo_q45 == total_freq_error_q8 * dl_carr_freq_lo_inv >> 15``.
* ``xo_freq_error_q45`` + ``rf_freq_khz``, v0x07: the SDX55 builds do not
  print ferr_by_flo. Instead, ``s32@104 * (u32@96 * 1000) / 2**37`` predicts
  the ``RX_IU_FREQ_UPDATE … freq_err`` (Q8 Hz) print with nothing fitted.
  Within 0.1 % on 704/790 (RXM-G1 f3_enumerate), 621/638 (f3_radio_gnss),
  23/24 (f3_proof) and 216/566 (SIM8202G-M2 drive). A 7 s shifted control
  gets 14 / 16 / 6 / 21.
* ``ftl_snr``: equals the same-tick, same-SFN 0xB8D8 (LL1 Serving SNR)
  words with no tolerance. EM9190 v0x07 2723/2723 + 2694/2694. M3100
  v0x06 12,276/12,276 + 12,276/12,276 + 9,779/9,779 + 9,779/9,779, control 0.
  The SCALE is not grounded: 0xB8D8's analysis reports 10*log10(word) ~= AT SINR + 27 dB
  (r 0.97, one capture), a hypothesis. So the words are exposed raw and no dB
  is emitted.
* ``nr_arfcn``: equals the nearest preceding 0xB97F CC0 nr_arfcn. RXM-G1
  788/788, EM9190 2793/2816, SIM8202G-M2 564/566, RM520N 183/193. A control
  shifted by one raster step gets 0.

The v0x06 words that follow each SNR (@84/@88, …) and the v0x07 words @28..@72
and @108..@156 are F3-silent and stay in ``body_raw``. The 4 x 96 B rx_blocks
hold s16 pairs and are populated on 2 of 4 blocks on these 2-Rx captures. That
suggests per-Rx-chain blocks, which is not grounded, so they are not named.

Log name: NR5G LL1 FW Serving FTL
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from struct import unpack_from
from typing import Any, Optional

from diaggrok.registry import register

V06_VERSION = 0x06
V07_VERSION = 0x07

# (version) -> (payload size, body offsets). A record of another size is
# rejected.
_LAYOUTS: dict[int, dict[str, int]] = {
    V07_VERSION: {"size": 544, "snr": 76, "snr_stride": 4, "ferr": 104,
                  "arfcn": 92, "freq_khz": 96, "rx_blocks": 160},
    V06_VERSION: {"size": 588, "snr": 80, "snr_stride": 12, "ferr": 72,
                  "arfcn": 128, "freq_khz": -1, "rx_blocks": 204},
}
_RX_BLOCK_SIZE = 96
_NUM_RX_BLOCKS = 4
_NUM_SNR = 4
_Q45 = float(1 << 45)

logger = logging.getLogger(__name__)
_LAYOUT_ALARMS: Counter = Counter()


def _layout_alarm(data: bytes, want: int) -> None:
    """WARN on a known-version record whose size is not the layout's, so a
    rejected record (e.g. 588 -> 587 B, 544 -> 543 B) is not dropped silently.
    Logs the 1st, 10th, 100th, ... per (version, len): the registry's own WARN
    fires once per (code, version) only."""
    key = (data[0], len(data))
    _LAYOUT_ALARMS[key] += 1
    n = _LAYOUT_ALARMS[key]
    if str(n).rstrip("0") != "1":
        return
    logger.warning(
        "diaggrok 0xB8DD layout issue #%d: version=0x%02X len=%d, layout wants "
        "%d B (%s) — record rejected", n, data[0],
        len(data), want, "short" if len(data) < want else "long",
    )


@dataclass
class Diag0xB8DD:
    """0xB8DD — NR5G LL1 FW Serving FTL record."""
    log_time: int
    version: int
    hdr_b2: int
    sfn: int
    slot: int
    hdr_word6: int
    payload_size: int
    nr_arfcn: int
    rf_freq_khz: Optional[int]  # v0x07 only
    xo_freq_error_q45: int
    xo_freq_error_ppm: float
    ftl_snr: list[int]
    rx_blocks: list[bytes]
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB8DD",
            "log_time": self.log_time,
            "version": self.version,
            "hdr_b2": self.hdr_b2,
            "sfn": self.sfn,
            "slot": self.slot,
            "hdr_word6": self.hdr_word6,
            "payload_size": self.payload_size,
            "nr_arfcn": self.nr_arfcn,
            "rf_freq_khz": self.rf_freq_khz,
            "xo_freq_error_q45": self.xo_freq_error_q45,
            "xo_freq_error_ppm": self.xo_freq_error_ppm,
            "ftl_snr": self.ftl_snr,
            "rx_blocks": self.rx_blocks,
            "body_raw": self.body_raw,
        }


@register(
    0xB8DD,
    name="0xB8DD",
    description=(
        "0xB8DD — NR5G LL1 FW Serving FTL: SFN/slot, per-chain FTL SNR (== 0xB8D8), "
        "XO frequency error Q45, NR-ARFCN, RF kHz (v0x07); F3-grounded v0x06/v0x07"
    ),
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "v4: exact length per version; any other size is rejected (None + WARN), "
        "no header-only record. v3: v0x07 544 B (SDX55) + v0x06 588 B "
        "(SDX62/SDX65) body decode. sfn == F3 RX_IU_TIME_UPDATE sysframe; "
        "xo_freq_error_q45 == F3 ferr_by_flo_q45 in effect (M3100 12,022/12,296) "
        "and predicts RX_IU_FREQ_UPDATE freq_err via rf_freq_khz within 0.1% "
        "(RXM-G1 704/790, ctl 14); ftl_snr == same-tick 0xB8D8 words bit-exact "
        "(EM9190, RM520N, M3100); nr_arfcn == 0xB97F CC0. v2: version gate "
        "{0x06,0x07}; v1: RM500Q NR5G _simple_parser "
        "stub."
    ),
    source_url="",
    supported_versions=(V06_VERSION, V07_VERSION),
    issues=(),
    primary_issue=None,
    fields_identified=9,
    fields_parsed=9,
    field_invariants={
        "version": {"enum": [V06_VERSION, V07_VERSION]},
    },
    # Community customized views for the vendor log viewer
    # read "FTL SNR" per `Carrier Index` from this code. ftl_snr is
    # located (== 0xB8D8's words) but raw linear: no dB is emitted until the
    # scale is pinned against SINR, as 0xB193 emits rsrp=None on versions
    # without a grounded scale. The cell key needs a 0xB97F join (no PCI here).
    wigle_direct=True,
    wigle_roles=("signal",),
)
def parse_0xb8dd(log_time: int, data: bytes) -> Diag0xB8DD | None:
    if len(data) < 8:
        return None
    version = data[0]
    lay = _LAYOUTS.get(version)
    if lay is None:  # Layer-1 version gate
        return None
    word4, word6 = unpack_from("<HH", data, 4)
    if len(data) != lay["size"]:  # exact length: no partial records
        _layout_alarm(data, lay["size"])
        return None
    nr_arfcn = unpack_from("<I", data, lay["arfcn"])[0]
    rf_freq_khz = None
    if lay["freq_khz"] >= 0:
        rf_freq_khz = unpack_from("<I", data, lay["freq_khz"])[0]
    ferr = unpack_from("<i", data, lay["ferr"])[0]
    snr = [unpack_from("<I", data, lay["snr"] + k * lay["snr_stride"])[0]
           for k in range(_NUM_SNR)]
    base = lay["rx_blocks"]
    blocks = [data[base + k * _RX_BLOCK_SIZE:base + (k + 1) * _RX_BLOCK_SIZE]
              for k in range(_NUM_RX_BLOCKS)]
    return Diag0xB8DD(
        log_time=log_time,
        version=version,
        hdr_b2=data[2],
        sfn=word4 & 0x3FF,
        slot=word4 >> 10,
        hdr_word6=word6,
        payload_size=len(data),
        nr_arfcn=nr_arfcn,
        rf_freq_khz=rf_freq_khz,
        xo_freq_error_q45=ferr,
        xo_freq_error_ppm=ferr * 1e6 / _Q45,
        ftl_snr=snr,
        rx_blocks=blocks,
        body_raw=data[1:],
    )
