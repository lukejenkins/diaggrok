"""Public zero-PII fixture for 0x1636 (GNSS_ME_RF_NOISE_EST structural stub).

Tier-1 (public_corpus.risk_tiers.RISK_TIER[0x1636] == 1): the parser leaves
an undecoded body_raw tail, so this frame is built entirely from fabricated
values via public_corpus.support.synthetic -- no bytes are copied from any
capture, private test, or real DIAG log.

Targets the structural decode in diaggrok.parsers.diag_0x1636: version @0
(gated to enum {2, 3, 4}), config_word (u32 @4, taken when len(data) >= 8),
and a computed data_density over the body region.
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1636 import parse_0x1636

# Fabricated values (not from any real capture).
_VERSION = 3                  # byte 0 -- one of the enum {2, 3, 4}
_CONFIG_WORD = 0xAABBCCDD     # u32 @4 (LE)
_TAIL = bytes(4)              # bytes 8:12 -- zero-filled tail


def _synthetic_1636() -> bytes:
    """Build a 12-byte 0x1636 payload with a fabricated config_word.

      data[0]    version = 3               (supplied via diag_frame)
      data[1:4]  3 fabricated filler bytes 0x11, 0x22, 0x33 (unread by parser)
      data[4:8]  u32 LE config_word = 0xAABBCCDD
      data[8:12] 4 zero-filled tail bytes

    data_density is computed over data[2:] (10 bytes: 0x22 0x33 DD CC BB AA
    00 00 00 00) -- 6 of those 10 bytes are nonzero, so
    data_density == round(6 / 10, 2) == 0.6.
    """
    body = (
        pack('<B', 0x11)             # data[1] -- unread filler
        + pack('<B', 0x22)           # data[2]
        + pack('<B', 0x33)           # data[3]
        + pack('<I', _CONFIG_WORD)   # data[4:8]
        + _TAIL                       # data[8:12]
    )
    frame = diag_frame(0x1636, _VERSION, body)
    assert len(frame) == 12
    return frame


def test_1636_decodes_synthetic_frame():
    rec = parse_0x1636(1000, _synthetic_1636())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.config_word == _CONFIG_WORD
    assert rec.data_density == 0.6
    assert rec.payload_size == 12
    assert rec.body_raw == (
        pack('<B', 0x11) + pack('<B', 0x22) + pack('<B', 0x33)
        + pack('<I', _CONFIG_WORD) + _TAIL
    )
