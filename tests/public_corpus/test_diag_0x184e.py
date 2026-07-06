"""Public zero-PII fixture for 0x184E (BeiDou B2b measurement skeleton).

Tier 1 (synthetic-only): the parser retains an undecoded/opaque ``raw`` tail
of unmodeled per-SV bytes (see public_corpus.risk_tiers.RISK_TIER[0x184E]
== 1), so this fixture is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the ``mdm_v1`` variant documented in diaggrok.parsers.diag_0x184e:
version=0x01, payload_size=1883 bytes, header fields sub_version [1],
6-byte reserved region [2:8] (not read by the parser), and flag_8 u32 at
[8:12].
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x184e import parse_0x184e

# Fabricated header values (not from any real capture).
_VERSION = 0x01       # data[0] -- field_invariants enum {0x01, 0x02, 0x05}
_SUB_VERSION = 0x01   # data[1] -- observed 96% of corpus per docstring
_FLAG_8 = 100         # u32 LE at [8:12] -- fabricated runtime state
_MDM_V1_SIZE = 1883   # payload size that selects the 'mdm_v1' variant


def _synthetic_184e() -> bytes:
    """Build an 'mdm_v1' (version=1, 1883B) 0x184E payload.

    Header transcribed from diag_0x184e.py's "Header structure" section:
      [0]    u8  version = 0x01
      [1]    u8  sub_version = 0x01
      [2:8]  6B  reserved/zero (not decoded by the parser)
      [8:12] u32 LE flag_8 = 100 (fabricated runtime state)
    The remaining bytes (per-SV tail, [12:1883)) are opaque per the
    parser's own docstring ("TBD for full closure"), so they're filled
    with a fabricated repeating pattern -- never real capture bytes.
    """
    header = (
        pack('<B', _VERSION)
        + pack('<B', _SUB_VERSION)
        + bytes(6)
        + pack('<I', _FLAG_8)
    )
    assert len(header) == 12
    tail = bytes((i % 251) for i in range(_MDM_V1_SIZE - 12))
    data = header + tail
    assert len(data) == _MDM_V1_SIZE
    return data


def test_184e_decodes_synthetic_mdm_v1_frame():
    rec = parse_0x184e(1000, _synthetic_184e())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.sub_version == _SUB_VERSION
    assert rec.flag_8 == _FLAG_8
    assert rec.payload_size == _MDM_V1_SIZE
    assert rec.size_variant == 'mdm_v1'
    assert rec.constellation == 'BeiDou'
    assert rec.band == 'B2b'
