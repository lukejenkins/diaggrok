"""Public zero-PII fixture for 0x1490 (GNSS state/event report).

Built entirely synthetically via public_corpus.support.synthetic for corpus
uniformity (see public_corpus.risk_tiers for the task's tier assignments) --
no bytes are copied from any capture, private test, or real DIAG log.

Targets the 14-byte fixed layout documented at the top of
diaggrok.parsers.diag_0x1490: version=0x00 (hard-gated), state_byte,
sub_state, a 6-value status enum, and event_flag, with reserved-zero
regions at [3:5] and [7:14].
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1490 import parse_0x1490

# Fabricated values (not from any real capture). Offsets transcribed from
# the parser's own field-map docstring in diag_0x1490.py.
_VERSION = 0x00         # byte 0 -- hard-gated constant
_STATE_BYTE = 0xA3      # byte 1 -- steady-state value (0x59 = boot)
_SUB_STATE = 0x0D       # byte 2 -- locked to state_byte==0xA3
_STATUS = 0x07          # byte 5 -- one of the two steady-state enum values
_EVENT_FLAG = 0x00      # byte 6 -- zero on steady-state (non-transition) records


def _synthetic_1490() -> bytes:
    """Build the 14-byte 0x1490 payload, every byte named per the
    diag_0x1490.py field map ("all 14 bytes named; no body_raw region")."""
    buf = (
        pack('<B', _VERSION)
        + pack('<B', _STATE_BYTE)
        + pack('<B', _SUB_STATE)
        + pack('<H', 0)          # reserved_3_4 -- constant 0
        + pack('<B', _STATUS)
        + pack('<B', _EVENT_FLAG)
        + bytes(7)               # reserved_7_13 -- constant 0
    )
    assert len(buf) == 14
    return buf


def test_1490_decodes_synthetic_frame():
    rec = parse_0x1490(1000, _synthetic_1490())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.state_byte == _STATE_BYTE
    assert rec.state_name == 'steady'
    assert rec.sub_state == _SUB_STATE
    assert rec.reserved_3_4 == 0
    assert rec.status == _STATUS
    assert rec.status_name == 'steady_07'
    assert rec.event_flag == _EVENT_FLAG
    assert rec.reserved_7_13 == bytes(7)
    assert rec.payload_size == 14
