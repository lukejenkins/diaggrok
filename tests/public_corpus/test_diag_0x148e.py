"""Public zero-PII fixture for 0x148E (Small GNSS status report).

Tier 0 in this parser's own scheme would be "pure enum/status", but the
task's declared risk tier (public_corpus.risk_tiers.RISK_TIER[0x148E] == 0)
means a real byte-snippet would be eligible; this fixture is nonetheless
built entirely synthetically via public_corpus.support.synthetic for
corpus uniformity -- no bytes are copied from any capture, private test,
or real DIAG log.

Targets the 18-byte fixed layout documented at the top of
diaggrok.parsers.diag_0x148e: version=0x01, and 10 more named byte/u16
fields, with reserved-zero bytes at [12, 13, 15, 16, 17].
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x148e import parse_0x148e

# Fabricated values (not from any real capture). Offsets transcribed from
# the parser's own field-map docstring in diag_0x148e.py.
_VERSION = 0x01          # byte 0 -- hard-gated constant
_PARAM_A = 0x48          # byte 1
_COUNTER1 = 1000         # u16LE at [2:4]
_CODE4 = 0x00            # byte 4
_VALUE_A = 500           # u16LE at [5:7]
_FIELD_B = 0x7fff         # u16LE at [7:9]
_COUNT_C = 3             # byte 9
_CODE10 = 2              # byte 10
_CODE11 = 4              # byte 11
_AUX14 = 7               # byte 14


def _synthetic_148e() -> bytes:
    """Build the 18-byte 0x148E payload, every byte named per the
    diag_0x148e.py corpus-validated byte map."""
    buf = bytearray(18)
    buf[0] = _VERSION
    buf[1] = _PARAM_A
    buf[2:4] = pack('<H', _COUNTER1)
    buf[4] = _CODE4
    buf[5:7] = pack('<H', _VALUE_A)
    buf[7:9] = pack('<H', _FIELD_B)
    buf[9] = _COUNT_C
    buf[10] = _CODE10
    buf[11] = _CODE11
    # buf[12], buf[13] left at 0 -- corpus-wide reserved-zero invariant
    buf[14] = _AUX14
    # buf[15], buf[16], buf[17] left at 0 -- corpus-wide reserved-zero invariant
    assert len(buf) == 18
    return bytes(buf)


def test_148e_decodes_synthetic_frame():
    rec = parse_0x148e(1000, _synthetic_148e())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.param_a == _PARAM_A
    assert rec.counter1 == _COUNTER1
    assert rec.code4 == _CODE4
    assert rec.value_a == _VALUE_A
    assert rec.field_b == _FIELD_B
    assert rec.count_c == _COUNT_C
    assert rec.code10 == _CODE10
    assert rec.code11 == _CODE11
    assert rec.aux14 == _AUX14
    assert rec.payload_size == 18
