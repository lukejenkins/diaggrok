"""Public zero-PII fixture for 0x163D (GNSS_ME_RF_BP_AGC skeleton parser).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x163D] == 1): the trailing
per-band block remains undecoded (opaque raw bytes retained on the
dataclass), so this frame is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the 61-byte v=0x04 form decode in diaggrok.parsers.diag_0x163d:
version @0 (gated to {0x03, 0x04}), sub_version @1, counter_a i32 @2:6,
counter_b i32 @6:10, chain_id @19, and (61B v=0x04-only) agc_pair_a/b
(u16 @29/@31) and rf_metric_a/b (big-endian f32 @41/@45).
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x163d import parse_0x163d

# Fabricated values (not from any real capture).
_SUB_VERSION = 0x00      # byte 1
_COUNTER_A = 100         # i32 @2:6
_COUNTER_B = -3          # i32 @6:10
_CHAIN_ID = 0x4C         # byte 19 -- RF-state-dependent marker
_AGC_PAIR_A = 500        # u16 @29:31
_AGC_PAIR_B = 502        # u16 @31:33
_RF_METRIC_A = 20.0      # BE f32 @41:45
_RF_METRIC_B = 32.0      # BE f32 @45:49
_TOTAL_LEN = 61          # 61B v=0x04 form


def _synthetic_163d() -> bytes:
    """Build a fabricated 61-byte v=0x04 0x163D payload.

    Bytes not covered by a named field (2:6 gap fill, 10:19, 20:29,
    33:41, 49:61) are zero-filled -- they are opaque per the parser's own
    docstring and asserting on them would overclaim decode coverage.
    """
    data = bytearray(_TOTAL_LEN - 1)  # payload after the version byte
    # sub_version @ payload offset [0] (data[1] once version is prefixed)
    data[0] = _SUB_VERSION
    # counter_a @ payload offset [1:5] (data[2:6] once version is prefixed)
    data[1:5] = pack('<i', _COUNTER_A)
    # counter_b @ payload offset [5:9] (data[6:10])
    data[5:9] = pack('<i', _COUNTER_B)
    # chain_id @ payload offset [18] (data[19])
    data[18] = _CHAIN_ID
    # agc_pair_a/b @ payload offset [28:30]/[30:32] (data[29:31]/data[31:33])
    data[28:30] = pack('<H', _AGC_PAIR_A)
    data[30:32] = pack('<H', _AGC_PAIR_B)
    # rf_metric_a/b @ payload offset [40:44]/[44:48] (data[41:45]/data[45:49])
    data[40:44] = pack('>f', _RF_METRIC_A)
    data[44:48] = pack('>f', _RF_METRIC_B)
    frame = diag_frame(0x163D, 0x04, bytes(data))
    assert len(frame) == _TOTAL_LEN
    return frame


def test_163d_decodes_synthetic_frame():
    rec = parse_0x163d(1000, _synthetic_163d())
    assert rec is not None
    assert rec.version == 0x04
    assert rec.sub_version == _SUB_VERSION
    assert rec.counter_a == _COUNTER_A
    assert rec.counter_b == _COUNTER_B
    assert rec.chain_id == _CHAIN_ID
    assert rec.payload_size == _TOTAL_LEN
    assert rec.agc_pair_a == _AGC_PAIR_A
    assert rec.agc_pair_b == _AGC_PAIR_B
    assert rec.rf_metric_a == _RF_METRIC_A
    assert rec.rf_metric_b == _RF_METRIC_B
