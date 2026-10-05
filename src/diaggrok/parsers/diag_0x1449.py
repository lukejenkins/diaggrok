"""0x1449 — LOG_1X_RF_WARMUP_C: v0x01 1x RF warm-up profile (F3-grounded) + v0x49 SDX55 LTE-RF-sleep-path record (context-grounded, body raw).

Two structurally-unrelated payloads share this code number; the canonical name
``LOG_1X_RF_WARMUP_C`` is F3-confirmed on v0x01 and does not fit v0x49:

  * v0x01 / 121 B — Netgear AirCard 791L (MDM9x35): the
    1x RF warm-up timing profile. Every named field below is F3-grounded.
  * v0x49 / 1327 B — Quectel RM500Q-AE (SDX55): emitted in
    the LTE RF sleep path. Byte 0 is not a version: ``[0:4]`` is an embedded
    ``{code u16 = 0x1449, len u16 = 0x4000 | payload_len}`` header. The body is
    F3-silent at the value level and is kept raw.

Neither version is GNSS despite the code range (0x1380–0x157F); the F3 in
both captures places them in the RF paths described below.

--- v0x01 layout (121 B, packed; N=1) ---

    [0]       u8   version        = 0x01 (Layer-1 gate)
    [1:4]     raw  hdr_1_3        01 00 00 — undecoded (F3's Dev=0 cannot be
                                  told apart from zero padding)
    [4]       u8   rf_mode        CANDIDATE — == F3 ``Dev 0 mode: 3``
    [5:9]     raw  hdr_5_8        01 75 00 00 — undecoded
    [9:13]    u32  wup_time_us    this warm-up's RF wake-up time, µs
    [13:17]   u32  wup_min_us     running min, µs
    [17:21]   u32  wup_max_us     running max, µs
    [21:25]   u32  wup_avg_us     running average, µs
    [25:29]   u32  unk_25         4700 — no F3 carries it; raw
    [29:45]   raw  zeros
    [45:57]   3×u32 unk_45        11 / 7 / 3 — no F3 carries them; raw
    [57:113]  raw  zeros
    [113:117] u32  wup_count      warm-up (tune) count the stats cover
    [117]     u8   lna_state_0    } F3 ``LNA (FW) 1, LNA (RTR) 0x1`` — both 1,
    [118]     u8   lna_state_1    } so FW-vs-RTR order is unresolved
    [119:121] i16  rx_agc_dbm10   RxAGC, dBm×10 (−845 → −84.5 dBm)

F3 grounding (an AirCard 791L CDMA-search drive capture, legacy ``0x92``
resolved via the build's QSR message index; format text from an MDM9207
EG25-G format-string database, matched on file + line + argc). In frame
order the record lands right after a textbook 1x RF bring-up: ADC DC / IQMC
cal, ``rf_cdma_mdsp_configure_devices`` ×6, ``ASM Enable Rx``,
``cdma1x_msg_proc: Received RX_START`` → ``RX_START Response`` → **0x1449** →
``srch.c: Srch State (CDMA) -> (Acq)``. Every print below fires exactly ONCE in
the capture, like the record:

    rf_cdma_time_profile.c:96   rf_cdma_init_wup_time: Dev %d mode: %d          [0, 3]   → rf_mode (cand.)
    rf_cdma_time_profile.c:129  rf_cdma_init_wup_time: tune_count:%d            [21]     → wup_count
    rf_cdma_time_profile.c:323  RF WU[%d](us) %d avg=%d cnt=%d                  [0, 4731, 5184, 21]
                                                        → wup_time_us, wup_avg_us, wup_count
    rf_cdma_time_profile.c:327  1x_RFWU Stats: Total_SW_time=%d, Min=%d, Max=%d (us)  [4779, 4571, 6501]
                                                        → wup_min_us, wup_max_us
    rf_1x_log.c:190 (193 in the STRING DB build)
                                rf_1x_log_wakeup_rx: Dev, RxLM, Band, Chan, SSMA_Chan,
                                RxAGC (dBm10), LNA (FW), LNA (RTR)   [0,0,0,384,384,-845,1,1]
                                                        → rx_agc_dbm10, lna_state_0/1

``rf_1x_log_wakeup_rx`` is the function that allocates and fills this log
(its other prints: "Unable to allocate Log memory for device", "sample size =
%d"). The four ``rf_cdma_time_profile.c`` sites all match on exact wire line and
argc, and min ≤ this ≤ max, avg ∈ [min, max]. Total_SW_time (4779) and the RX
channel (384) are not in the body. QCSuper, SCAT and rayhunter do not
decode 0x1449; the capture has no ``0x60`` event frames.

--- v0x49 (1327 B; N=1) ---

    [0:2]     u16  embedded_code  = 0x1449 (the log code itself)
    [2:4]     u16  0x452f = embedded_flags (bits 14–15, = 1) | embedded_len
                                  (bits 0–13, = 1327 == payload length)
    [4:8]     u32  slot_count     = 6
    [8:56]    6 × {u32 0xFFFFFFFF, u32 0} — structure only; ``ones_words``
                                  counts the all-ones words body-wide
    [56:]     raw — clusters at @100, @136..157, @332..351, a 16-B-stride
              block @352 (u32 1 / u32 v / u32 1 / f32 small-negative) ×3+1,
              @948, and @1006..1020 (``01 00 | 99 13 2f 05 | u32 u32``: another
              code-shaped u16 beside the same 1327 length, then two u32
              ≈ 9.59e6 of the same magnitude as ``rflm_lte_rx``'s
              prx_action_time in the window). None of it is F3-named.

F3 grounding (an RM500Q-AE drive capture, frame-order window, QSR4 ``0x99``
rendered 2475/2475 with the build-matched message database): the
record is emitted between ``rflte_dispatch.c:1558 RFA_RF_LTE_SLEEP_REQ: Req type
0 received on LTE sub id 0`` (−164 ticks) and ``rflte_mc_rx.c:12062
rflte_mc_rx_sleep: Fill wmss rx handle array`` (+746 ticks), then ASM / ELNA
disable + sleep on the serving band, with idle-camped LTE paging around it. No
1x and no GNSS-measurement print in the window, and no body value matches a
print arg beyond generic constants (512, 65535). So v0x49 is context-grounded
(LTE RF sleep path), body F3-silent. The body is not a GNSS validity-mask
block: no GNSS print falls in the record's F3 window.

Naming note: ``LOG_1X_RF_WARMUP_C`` is F3-confirmed for v0x01 (rf_1x_log_wakeup_rx /
rf_cdma_time_profile.c). v0x49 (SDX55) reuses the number for an LTE-RF record
with no confirmed name.

Log name: LOG_1X_RF_WARMUP_C
Also known as: LOG_BCAST_SECURITY_STKM_RECEIVED, LOG_DVBH_SECURITY_KSM_RECEIVED_SUCCESS
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_1X_RF_WARMUP = 0x1449

V1_VERSION = 0x01
V1_SIZE = 121

V49_VERSION = 0x49          # low byte of the embedded code, not a version
V49_MIN_SIZE = 8
_V49_LEN_MASK = 0x3FFF


@dataclass
class Diag0x1449RfWarmup:
    """0x1449 v0x01 — 1x RF warm-up timing profile (121 B, F3-grounded)."""
    log_time: int
    version: int
    hdr_1_3: bytes
    rf_mode: int            # CANDIDATE: == F3 "rf_cdma_init_wup_time: Dev 0 mode: 3"
    hdr_5_8: bytes
    wup_time_us: int
    wup_min_us: int
    wup_max_us: int
    wup_avg_us: int
    unk_25: int
    unk_45: tuple[int, int, int]
    wup_count: int
    lna_state_0: int
    lna_state_1: int
    rx_agc_dbm10: int
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1449RfWarmup',
            'log_time': self.log_time,
            'version': self.version,
            'hdr_1_3': self.hdr_1_3.hex(),
            'rf_mode': self.rf_mode,
            'hdr_5_8': self.hdr_5_8.hex(),
            'wup_time_us': self.wup_time_us,
            'wup_min_us': self.wup_min_us,
            'wup_max_us': self.wup_max_us,
            'wup_avg_us': self.wup_avg_us,
            'unk_25': self.unk_25,
            'unk_45': list(self.unk_45),
            'wup_count': self.wup_count,
            'lna_state_0': self.lna_state_0,
            'lna_state_1': self.lna_state_1,
            'rx_agc_dbm10': self.rx_agc_dbm10,
            'rx_agc_dbm': self.rx_agc_dbm10 / 10,
            'payload_size': self.payload_size,
        }


@dataclass
class Diag0x1449:
    """0x1449 v0x49 — SDX55 LTE-RF-sleep-path record (1327 B, body raw).

    ``version`` is byte[0] (0x49), kept as the dispatch key; it is the low byte
    of ``embedded_code``. ``embedded_len`` / ``embedded_flags`` split the u16 at
    offset 2; ``embedded_len_matches`` says whether it equals the payload
    length (it does on the only record). ``slot_count`` is the u32 at offset 4
    and ``ones_words`` counts 0xFFFFFFFF words body-wide (both 6 on the only
    record). The rest of the body is ``body_raw``.
    """
    log_time: int
    version: int
    embedded_code: int
    embedded_len: int
    embedded_flags: int
    embedded_len_matches: bool
    slot_count: int
    ones_words: int
    payload_size: int
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1449',
            'log_time': self.log_time,
            'version': self.version,
            'embedded_code': self.embedded_code,
            'embedded_len': self.embedded_len,
            'embedded_flags': self.embedded_flags,
            'embedded_len_matches': self.embedded_len_matches,
            'slot_count': self.slot_count,
            'ones_words': self.ones_words,
            'payload_size': self.payload_size,
        }


def _parse_v01(log_time: int, data: bytes) -> Diag0x1449RfWarmup | None:
    if len(data) < V1_SIZE:
        return None
    return Diag0x1449RfWarmup(
        log_time=log_time,
        version=data[0],
        hdr_1_3=bytes(data[1:4]),
        rf_mode=data[4],
        hdr_5_8=bytes(data[5:9]),
        wup_time_us=unpack_from('<I', data, 9)[0],
        wup_min_us=unpack_from('<I', data, 13)[0],
        wup_max_us=unpack_from('<I', data, 17)[0],
        wup_avg_us=unpack_from('<I', data, 21)[0],
        unk_25=unpack_from('<I', data, 25)[0],
        unk_45=unpack_from('<3I', data, 45),
        wup_count=unpack_from('<I', data, 113)[0],
        lna_state_0=data[117],
        lna_state_1=data[118],
        rx_agc_dbm10=unpack_from('<h', data, 119)[0],
        payload_size=len(data),
    )


def _parse_v49(log_time: int, data: bytes) -> Diag0x1449 | None:
    if len(data) < V49_MIN_SIZE:
        return None
    embedded_code, len_word = unpack_from('<HH', data, 0)
    if embedded_code != LOG_1X_RF_WARMUP:
        return None
    embedded_len = len_word & _V49_LEN_MASK
    # The embedded header declares the record length. A
    # payload shorter than that is truncated — return None (registry WARN)
    # instead of handing back a short body. (Longer is left alone; it surfaces
    # as embedded_len_matches=False.)
    if embedded_len > len(data):
        return None
    ones_words = sum(
        1
        for off in range(V49_MIN_SIZE, len(data) - 3, 4)
        if unpack_from('<I', data, off)[0] == 0xFFFFFFFF
    )
    return Diag0x1449(
        log_time=log_time,
        version=data[0],
        embedded_code=embedded_code,
        embedded_len=embedded_len,
        embedded_flags=len_word >> 14,
        embedded_len_matches=embedded_len == len(data),
        slot_count=unpack_from('<I', data, 4)[0],
        ones_words=ones_words,
        payload_size=len(data),
        body_raw=bytes(data),
    )


@register(
    LOG_1X_RF_WARMUP,
    name="0x1449",
    wigle_direct=False,
    wigle_roles=("rat-context",),
    description="0x1449 LOG_1X_RF_WARMUP_C — v0x01 1x RF warm-up profile (wake-up time/min/max/avg µs, count, LNA, RxAGC; F3-grounded) + v0x49 SDX55 LTE-RF-sleep-path record (embedded code/len header, body raw)",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Both versions F3-grounded in frame order. v0x01 (AirCard 791L "
        "MDM9x35, 121 B) is the 1x RF warm-up profile: "
        "rf_cdma_time_profile.c:323/327 'RF WU[0](us) 4731 avg=5184 cnt=21' + "
        "'1x_RFWU Stats: … Min=4571, Max=6501' and rf_1x_log.c "
        "'rf_1x_log_wakeup_rx: … RxAGC -845 (dBm10), LNA 1/1' land 1:1 on "
        "@9/@21/@113/@13/@17/@119/@117..118, each firing once, like the record. "
        "Format text from an MDM9207 format-string database on exact "
        "file+line+argc. v0x49 (RM500Q-AE SDX55, 1327 B) is emitted between "
        "rflte_dispatch 'RFA_RF_LTE_SLEEP_REQ' and 'rflte_mc_rx_sleep' (QSR4 "
        "2475/2475 resolved). [0:4] is an embedded {code 0x1449, 0x4000|len "
        "1327} header, so byte 0 is not a version; the body is F3-silent and "
        "kept raw. v0x49 payloads shorter than the embedded declared length "
        "return None. Neither version is GNSS. One record of each version "
        "observed; rf_mode and the FW-vs-RTR LNA order remain unconfirmed."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=15,
    fields_parsed=15,
    field_invariants={"version": {"enum": [0x01, 0x49]}},
    supported_versions=(V1_VERSION, V49_VERSION),
)
def parse_0x1449(log_time: int, data: bytes) -> Diag0x1449RfWarmup | Diag0x1449 | None:
    """Parse a 0x1449 record, dispatching on byte 0.

    0x01 → v0x01 1x RF warm-up profile (≥121 B). 0x49 → v0x49 SDX55 record,
    which must also carry the embedded code 0x1449 at [0:2] and hold at least
    its embedded declared length. Any other byte 0, or a runt, returns None.
    """
    # Layer-1 gate first (byte-0 version rule), then per-version dispatch.
    if not data or data[0] not in (V1_VERSION, V49_VERSION):
        return None
    if data[0] == V1_VERSION:
        return _parse_v01(log_time, data)
    return _parse_v49(log_time, data)
