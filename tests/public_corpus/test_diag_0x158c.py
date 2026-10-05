"""Public zero-PII fixture for 0x158C (GNSS per-constellation RF statistics).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x158C] == 1): the risk-tier table
flags this code's tail as unverified/undecoded, so this frame is built
entirely from fabricated values via public_corpus.support.synthetic -- no
bytes are copied from any capture, private test, or real DIAG log.

Targets the fixed 49-byte record decode in diaggrok.parsers.diag_0x158c
(format '<BBBBBBBBBiiII16sB7s', 49 bytes): version @0 (gated to 0x01),
sub_version @1, seq_num @5, metric_a/b (i32 @9/@13), metric_c/d
(u32 @17/@21), flags @41.
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x158c import parse_0x158c

# Fabricated per-constellation RF-stats values (not from any real capture).
_SUB_VERSION = 0x01
_SEQ_NUM = 1              # constellation slot index -> 'GPS' per _SEQ_CONSTELLATION
_METRIC_A = 34816         # i32 -- primary metric (not the -56 inactive sentinel)
_METRIC_B = 1200          # i32 -- secondary metric
_METRIC_C = 34332         # u32 -- fabricated value near metric_b * 28.61 (documented ratio)
_METRIC_D = 529           # u32 -- fabricated value near metric_b * 0.441 (documented ratio)
_FLAGS = 0x02              # u8 -- most-common observed flags value


def _synthetic_158c() -> bytes:
    """Build a 49-byte v=0x01 0x158C payload with fabricated RF-stats values.

      data[0]     version = 0x01          (supplied via diag_frame)
      data[1]     sub_version = 0x01
      data[2:5]   3 zero-filled reserved bytes
      data[5]     seq_num = 1              -> constellation = 'GPS'
      data[6:9]   3 zero-filled reserved bytes
      data[9:13]  i32 metric_a = 34816      (!= -56 sentinel -> active = True)
      data[13:17] i32 metric_b = 1200
      data[17:21] u32 metric_c = 34332
      data[21:25] u32 metric_d = 529
      data[25:41] 16 zero-filled bytes
      data[41]    flags = 0x02
      data[42:49] 7 zero-filled trailer bytes
    """
    body = (
        pack('<B', _SUB_VERSION)
        + bytes(3)                  # [2:5] reserved
        + pack('<B', _SEQ_NUM)
        + bytes(3)                  # [6:9] reserved
        + pack('<i', _METRIC_A)
        + pack('<i', _METRIC_B)
        + pack('<I', _METRIC_C)
        + pack('<I', _METRIC_D)
        + bytes(16)                 # zeros
        + pack('<B', _FLAGS)
        + bytes(7)                  # trailer
    )
    frame = diag_frame(0x158C, 0x01, body)
    assert len(frame) == 49
    return frame


def test_158c_decodes_synthetic_frame():
    rec = parse_0x158c(1000, _synthetic_158c())
    assert rec is not None
    assert rec.version == 0x01
    assert rec.sub_version == _SUB_VERSION
    assert rec.seq_num == _SEQ_NUM
    assert rec.constellation == 'GPS'
    assert rec.metric_a == _METRIC_A
    assert rec.metric_b == _METRIC_B
    assert rec.metric_c == _METRIC_C
    assert rec.metric_d == _METRIC_D
    assert rec.flags == _FLAGS
    assert rec.active is True
