"""Public zero-PII fixture for 0x1516 (Rare GNSS init/event report).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x1516] == 1): the parser leaves
an undecoded ``body_raw`` tail, so this frame is built entirely from
fabricated values via public_corpus.support.synthetic -- no bytes are
copied from any capture, private test, or real DIAG log.

Targets the header-only decode in diaggrok.parsers.diag_0x1516: byte[0]
version (gated to the enum {0x03, 0x06}), byte[1] sub_type, and the
remaining bytes as an opaque body_raw. This is a variable-size,
header-only parser -- the only structural invariant enforced is the
version gate and a minimum length of 4 bytes.
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1516 import parse_0x1516

# Fabricated values (not from any real capture).
_VERSION = 0x06     # byte 0 -- one of the enum {0x03, 0x06} (field_invariants)
_SUB_TYPE = 0x2A    # byte 1 -- arbitrary fabricated sub-type
_BODY_LEN = 68      # bytes 4.. -- opaque tail; 68 zero-fill bytes -> 72B total


def _synthetic_1516() -> bytes:
    """Build a minimal valid 0x1516 payload (72 bytes total).

      data[0]    version = 0x06        (one of the corpus-observed enum)
      data[1]    sub_type = 0x2A        (fabricated; not corpus-derived)
      data[2:4]  2 zero-filled bytes    (not read by the parser)
      data[4:72] 68 zero-filled bytes   (opaque body_raw tail; length chosen
                                          to match the 72B corpus-observed
                                          payload_size enum)
    """
    body = (
        pack('<B', _SUB_TYPE)
        + bytes(2)          # unread padding at [2:4]
        + bytes(_BODY_LEN)  # opaque body_raw tail
    )
    frame = diag_frame(0x1516, _VERSION, body)
    assert len(frame) == 72
    return frame


def test_1516_decodes_synthetic_frame():
    rec = parse_0x1516(1000, _synthetic_1516())
    assert rec is not None
    assert rec.version == 0x06
    assert rec.sub_type == _SUB_TYPE
    assert rec.payload_size == 72
    assert rec.body_raw == bytes(68)
