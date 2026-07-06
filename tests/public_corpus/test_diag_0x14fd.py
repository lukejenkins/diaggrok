"""Public zero-PII fixture for 0x14FD (GNSS data report, header-only).

Tier 1 (synthetic-only): the payload body is undecoded/opaque (body_raw) --
see public_corpus.risk_tiers.RISK_TIER[0x14FD] == 1 -- so this frame is
built entirely from fabricated values via public_corpus.support.synthetic --
no bytes are copied from any capture, private test, or real DIAG log.

Targets the 218-byte ("218B") variant documented at the top of
diaggrok.parsers.diag_0x14fd: version=0x08, with state/byte2/byte3 header
fields; the 214-byte body tail is left entirely opaque (zero-filled here,
since none of its content is asserted on).
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x14fd import parse_0x14fd

# Fabricated values (not from any real capture). Offsets transcribed from
# the parser's own field-map docstring in diag_0x14fd.py.
_VERSION = 0x08   # byte 0 -- 218B variant (0x0a selects the 391B variant)
_STATE = 0x05     # byte 1 -- RF/state-dependent discriminator
_BYTE2 = 0x00     # byte 2
_BYTE3 = 0x00     # byte 3 -- 0x00 on the 218B variant (0x01 on 391B)
_BODY_LEN = 214   # 218B total - 4B header


def _synthetic_14fd() -> bytes:
    """Build the 218-byte 0x14FD payload: 4-byte header + opaque zero body,
    per the "218B variant: byte0=0x08, byte3=0x00" corpus decomposition."""
    header = pack('<B', _VERSION) + pack('<B', _STATE) + pack('<B', _BYTE2) + pack('<B', _BYTE3)
    assert len(header) == 4
    body = bytes(_BODY_LEN)
    payload = header + body
    assert len(payload) == 218
    return payload


def test_14fd_decodes_synthetic_frame():
    rec = parse_0x14fd(1000, _synthetic_14fd())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.state == _STATE
    assert rec.byte2 == _BYTE2
    assert rec.byte3 == _BYTE3
    assert rec.payload_size == 218
    assert rec.body_raw == bytes(_BODY_LEN)
