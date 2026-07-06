"""Public zero-PII fixture for 0x7160 (GNSS-engine-start cluster stub).

Tier 1 (synthetic-only, see public_corpus.risk_tiers.RISK_TIER[0x7160] == 1):
the parser is a 4-byte header-only stub -- ``body_raw`` is the ENTIRE
8004/9004-byte payload, undecoded past the header, so a real byte snippet
could carry PII the text-only leak_tokens guard cannot see. This fixture is
built entirely from fabricated (zero-fill) bytes via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the v1 (SDX20) shape: version=0x01, fixed payload_size=8004 (the
parser's ``_VERSION_TO_SIZE`` gate). Offsets below are transcribed from
diaggrok.parsers.diag_0x7160's live ``parse_0x7160`` code, not the module's
prose narrative:

    [0]    u8   version = 0x01           (selects _SIZE_V1 == 8004)
    [1]    u8   sub_flag = 0x01          (gated, corpus-invariant)
    [2:4]  u16  entry_count (LE; high byte [3] gated == 0x00)
    [4:]   opaque body, zero-filled here (not decoded by the parser)
"""
from public_corpus.support.synthetic import diag_frame
from diaggrok.parsers.diag_0x7160 import parse_0x7160

_VERSION = 0x01
_SUB_FLAG = 0x01
_ENTRY_COUNT = 70          # observed value {70, 100}; fits in one byte
_PAYLOAD_SIZE = 8004       # _VERSION_TO_SIZE[0x01]


def _synthetic_7160() -> bytes:
    """Build a v=1 (SDX20), 8004-byte 0x7160 record with a fabricated
    zero-filled body. ``diag_frame`` supplies the version byte at data[0].
    """
    header_tail = bytes([_SUB_FLAG]) + _ENTRY_COUNT.to_bytes(2, "little")
    assert len(header_tail) == 3  # data[1:4]

    filler = bytes(_PAYLOAD_SIZE - 1 - len(header_tail))
    body = header_tail + filler
    assert len(body) == _PAYLOAD_SIZE - 1

    data = diag_frame(0x7160, _VERSION, body)
    assert len(data) == _PAYLOAD_SIZE
    return data


def test_7160_decodes_synthetic_frame():
    rec = parse_0x7160(1000, _synthetic_7160())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.sub_flag == _SUB_FLAG
    assert rec.entry_count == _ENTRY_COUNT
    assert rec.payload_size == _PAYLOAD_SIZE
    assert len(rec.body_raw) == _PAYLOAD_SIZE
