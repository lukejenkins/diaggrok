"""Public zero-PII fixture for 0x7160 (LOG_UMTS_NAS_PPLMN_LIST).

Tier 1 (synthetic-only, see public_corpus.risk_tiers.RISK_TIER[0x7160] == 1):
built entirely from fabricated bytes via public_corpus.support.synthetic --
no bytes are copied from any capture, private test, or real DIAG log. The one
PLMN used is the 3GPP test network 001-01, not an operator.

Targets the v1 (SDX20) shape: version=0x01, fixed payload_size=8004. Offsets
below are transcribed from diaggrok.parsers.diag_0x7160's live
``parse_0x7160`` code:

    [0]    u8   version = 0x01           (selects the 8004 B / 8 B-stride shape)
    [1]    u8   sub_flag = 0x01          (gated)
    [2:4]  u16  entry_count (LE; <= 1000 slots)
    [4:]   1000 x 8 B entries: plmn[3] BCD | category u8 | num_rats u8 | rat[3]
"""
from public_corpus.support.synthetic import diag_frame
from diaggrok.parsers.diag_0x7160 import parse_0x7160

_VERSION = 0x01
_SUB_FLAG = 0x01
_PAYLOAD_SIZE = 8004
_STRIDE = 8

# (plmn BCD, category, num_rats, rat[3])
_ENTRIES = [
    (bytes([0x00, 0xF1, 0x10]), 3, 1, [2, 0, 0]),  # 001-01, OPLMN, LTE only
    (b"\xff\xff\xff", 3, 3, [2, 1, 0]),           # unset SIM record
]


def _synthetic_7160() -> bytes:
    """Build a v=1 (SDX20), 8004-byte 0x7160 record with two fabricated
    entries. ``diag_frame`` supplies the version byte at data[0].
    """
    table = b"".join(
        plmn + bytes([cat, n, *rats]) for plmn, cat, n, rats in _ENTRIES
    )
    assert len(table) == len(_ENTRIES) * _STRIDE
    header_tail = bytes([_SUB_FLAG]) + len(_ENTRIES).to_bytes(2, "little")
    filler = bytes(_PAYLOAD_SIZE - 1 - len(header_tail) - len(table))
    data = diag_frame(0x7160, _VERSION, header_tail + table + filler)
    assert len(data) == _PAYLOAD_SIZE
    return data


def test_7160_decodes_synthetic_frame():
    rec = parse_0x7160(1000, _synthetic_7160())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.sub_flag == _SUB_FLAG
    assert rec.entry_count == len(_ENTRIES)
    assert rec.payload_size == _PAYLOAD_SIZE
    d = rec.to_dict()
    assert d["num_operator_preferred"] == 2
    assert d["entries"][0]["plmn"] == "001-01"
    assert d["entries"][0]["rat_names"] == ["LTE"]
    assert d["entries"][1]["plmn"] is None
    assert d["entries"][1]["rat_names"] == ["LTE", "UMTS", "GSM"]
