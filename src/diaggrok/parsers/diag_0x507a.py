"""0x507A — LOG_GSM_L1_SERVING_AUXILIARY_MEASUREMENTS: GSM serving-cell RX power.

Layout (762/762 corpus records, 10 captures, EG25-G MDM9207 + EC25 +
MC7700 MDM9200):

    [0:2]  rx_power   int16 LE, 1/16 dBm (serving-cell RX level)
    [2]    aux_flag   u8, 0 or 1 (raw; meaning CANDIDATE, see below)

Every record is exactly 3 bytes; any other length is rejected.

**There is no version byte** (``version_less=True``). Byte 0 is the low
byte of the power word and takes 223 distinct values; there is no config
word.

F3 grounding (EG25-G, 3 F3-bearing captures):

* Each record is the log twin of the RR inter-task message
  ``gs1:IMsg: MPH_SERVING_AUX_MEAS_IND`` (``rr_gprs_debug.c:4194``):
  308/313 records sit within 5 ms of one (median 0.01 ms).
* ``rx_power`` / 16 matches the plaintext ``gl1_arbitrator_cxm.c:502``
  ``MCS_CXM_COEX_POWER_IND … DL=<n>dBm10`` emitted in the same tick:
  306/308 within 1 dB, mean difference +0.00 to +0.06 dB per capture.
* AT+QENG "servingcell" on the same session reads GSM ARFCN 685, RX
  level -82 dBm, while these records read -81.1 to -82.9 dBm.

``aux_flag``: 1 on 131/762 records. In the one F3-bearing capture that
has flag-1 records (an EG25-G survey), all 6 sit next to the unlabelled
QSR sites ``rr_resel_calcs.c:842`` / ``:963`` and ``rr_resel_g2w.c:495``,
which fire next to none of the 44 flag-0 records. So the flag tracks an
RR reselection-evaluation path. CANDIDATE only: those sites have no
format string, so the field keeps a neutral name.

QCSuper and SCAT do not decode this code.
``0x60`` events: none in any capture that carries this code.

Log name: LOG_GSM_L1_SERVING_AUXILIARY_MEASURMENTS
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

RECORD_SIZE = 3


@dataclass
class Diag0x507A:
    """0x507A — GSM L1 serving auxiliary measurement (serving RX power)."""
    log_time: int
    rx_power_raw: int
    rx_power_dbm: float
    aux_flag: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x507A",
            "log_time": self.log_time,
            "rx_power_raw": self.rx_power_raw,
            "rx_power_dbm": self.rx_power_dbm,
            "aux_flag": self.aux_flag,
        }


@register(
    0x507A,
    name="0x507A",
    description="GSM L1 serving auxiliary measurement: serving-cell RX power "
                "(int16, 1/16 dBm) + aux flag",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE + F3 grounding (EG25-G MDM9207, EC25, MC7700). 3-byte record "
        "on 762/762 corpus records. Version-less: byte 0 is the power word's low "
        "byte (223 distinct values). Each record twins the RR message "
        "MPH_SERVING_AUX_MEAS_IND (308/313 within 5 ms); rx_power/16 matches the "
        "plaintext CXM DL dBm10 print (306/308 within 1 dB, mean diff <= 0.06 dB). "
        "aux_flag raw (CANDIDATE: RR reselection-evaluation trigger)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=2,
    fields_parsed=2,
    version_less=True,
    field_invariants={
        "rx_power_dbm": {"range": (-130.0, 0.0)},
        "aux_flag": {"enum": [0, 1]},
    },
)
def parse_0x507a(log_time: int, data: bytes) -> Diag0x507A | None:
    if len(data) != RECORD_SIZE:
        return None
    raw = unpack_from("<h", data, 0)[0]
    return Diag0x507A(
        log_time=log_time,
        rx_power_raw=raw,
        rx_power_dbm=raw / 16,
        aux_flag=data[2],
    )
