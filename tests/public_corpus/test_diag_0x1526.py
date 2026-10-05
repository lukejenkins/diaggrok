"""Public zero-PII fixture for 0x1526 (GNSS per-satellite measurement report).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x1526] == 1): the parser leaves
an undecoded/unverified tail per the risk-tier table, so this frame is
built entirely from fabricated values via public_corpus.support.synthetic --
no bytes are copied from any capture, private test, or real DIAG log.

Targets the fixed 54-byte v=0x02 layout documented in
diaggrok.parsers.diag_0x1526: version @0, sv_id @1, meas_task_id @3,
signal_marker (u16 @4), meas_age_companion (u16 @6), meas_age_accum
(u16 @24), meas_uncertainty (u16 @28), a 48-bit receiver clock
(u32 @32 | u16 @36 << 32), and two f32 C/N0 fields @38 and @42.
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1526 import parse_0x1526

# Fabricated per-SV measurement values (not from any real capture).
_SV_ID = 14                  # byte 1
_MEAS_TASK_ID = 3            # byte 3
_SIGNAL_MARKER = 0x0002      # u16 @4 -- normal (non-dual-signal) marker
_MEAS_AGE_COMPANION = 1000   # u16 @6
_MEAS_AGE_ACCUM = 500        # u16 @24
_MEAS_UNCERTAINTY = 200      # u16 @28
_RCVR_LO = 123_456_789       # u32 @32 -- low 32 bits of the 48-bit clock
_RCVR_HI = 5                 # u16 @36 -- high 16 bits of the 48-bit clock
_CN0_DBHZ = 25.5             # f32 @38 -- primary C/N0
_CN0_ADJ_DBHZ = 24.0         # f32 @42 -- adjusted C/N0
_CN0_SIG2_DBHZ = 10.0        # f32 @46 -- rare 2nd-signal C/N0 (nonzero -> not None)
_CN0_SIG2_ADJ_DBHZ = 9.0     # f32 @50 -- adjusted 2nd-signal C/N0


def _synthetic_1526() -> bytes:
    """Build a 54-byte v=0x02 0x1526 payload with fabricated values.

      data[0]     version = 0x02          (supplied via diag_frame)
      data[1]     sv_id = 14
      data[2]     reserved = 0
      data[3]     meas_task_id = 3
      data[4:6]   u16 signal_marker = 0x0002
      data[6:8]   u16 meas_age_companion = 1000
      data[8:24]  16 zero-filled reserved bytes
      data[24:26] u16 meas_age_accum = 500
      data[26:28] u16 reserved = 0
      data[28:30] u16 meas_uncertainty = 200
      data[30:32] u16 reserved = 0
      data[32:36] u32 rcvr_time low = 123456789
      data[36:38] u16 rcvr_time high = 5
        -> rcvr_time_ticks = (5 << 32) | 123456789
        -> rcvr_time_ms = rcvr_time_ticks / 65536.0
      data[38:42] f32 cn0_dbhz = 25.5
      data[42:46] f32 cn0_adj_dbhz = 24.0
      data[46:50] f32 cn0_sig2_dbhz = 10.0
      data[50:54] f32 cn0_sig2_adj_dbhz = 9.0
    """
    body = (
        pack('<B', _SV_ID)                    # [1]
        + pack('<B', 0)                       # [2] reserved
        + pack('<B', _MEAS_TASK_ID)            # [3]
        + pack('<H', _SIGNAL_MARKER)           # [4:6]
        + pack('<H', _MEAS_AGE_COMPANION)      # [6:8]
        + bytes(16)                            # [8:24] reserved
        + pack('<H', _MEAS_AGE_ACCUM)          # [24:26]
        + pack('<H', 0)                        # [26:28] reserved
        + pack('<H', _MEAS_UNCERTAINTY)        # [28:30]
        + pack('<H', 0)                        # [30:32] reserved
        + pack('<I', _RCVR_LO)                 # [32:36]
        + pack('<H', _RCVR_HI)                 # [36:38]
        + pack('<f', _CN0_DBHZ)                # [38:42]
        + pack('<f', _CN0_ADJ_DBHZ)            # [42:46]
        + pack('<f', _CN0_SIG2_DBHZ)           # [46:50]
        + pack('<f', _CN0_SIG2_ADJ_DBHZ)       # [50:54]
    )
    frame = diag_frame(0x1526, 0x02, body)
    assert len(frame) == 54
    return frame


def test_1526_decodes_synthetic_frame():
    rec = parse_0x1526(1000, _synthetic_1526())
    assert rec is not None
    assert rec.version == 0x02
    assert rec.sv_id == _SV_ID
    assert rec.meas_task_id == _MEAS_TASK_ID
    assert rec.signal_marker == _SIGNAL_MARKER
    assert rec.meas_age_companion == _MEAS_AGE_COMPANION
    assert rec.meas_age_accum == _MEAS_AGE_ACCUM
    assert rec.meas_uncertainty == _MEAS_UNCERTAINTY
    expected_ticks = (_RCVR_HI << 32) | _RCVR_LO
    assert rec.rcvr_time_ticks == expected_ticks
    assert rec.rcvr_time_ms == expected_ticks / 65536.0
    assert rec.cn0_dbhz == _CN0_DBHZ
    assert rec.cn0_adj_dbhz == _CN0_ADJ_DBHZ
    assert rec.cn0_sig2_dbhz == _CN0_SIG2_DBHZ
    assert rec.cn0_sig2_adj_dbhz == _CN0_SIG2_ADJ_DBHZ
