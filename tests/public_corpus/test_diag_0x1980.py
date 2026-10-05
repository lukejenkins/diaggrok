"""Public zero-PII fixture for 0x1980 (GNSS/RF state flag, sibling of 0x197F).

Tier 0 (risk_tiers.RISK_TIER[0x1980] == 0): same structure as 0x197F --
a single version-less u32 ``state_word`` hard-gated by the parser to one
corpus-observed constant (0xC002F2A0). Built via
public_corpus.support.synthetic.pack; no bytes are copied from any
capture, private test, or real DIAG log.

Layout (per diaggrok.parsers.diag_0x1980, ``version_less=True``):
    data[0:4]  u32 LE state_word -- parser hard-rejects any value other
               than 0xC002F2A0 (field_invariants enum).
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1980 import parse_0x1980

# The parser only accepts this exact constant (see diag_0x1980.py
# field_invariants={"state_word": {"enum": [0xC002F2A0]}}).
_STATE_WORD = 0xC002F2A0


def _synthetic_1980() -> bytes:
    data = pack('<I', _STATE_WORD)
    assert len(data) == 4
    return data


def test_1980_decodes_synthetic_frame():
    rec = parse_0x1980(1000, _synthetic_1980())
    assert rec is not None
    assert rec.state_word == _STATE_WORD


def test_1980_to_dict_hex_field():
    rec = parse_0x1980(1000, _synthetic_1980())
    assert rec is not None
    d = rec.to_dict()
    assert d['state_word'] == _STATE_WORD
    assert d['state_word_hex'] == 'c002f2a0'
