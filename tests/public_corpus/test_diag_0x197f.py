"""Public zero-PII fixture for 0x197F (GNSS/RF state flag).

Tier 0 (risk_tiers.RISK_TIER[0x197F] == 0): the payload is a single
version-less u32 ``state_word`` that the parser hard-gates to one
corpus-observed constant (0xC002F2A0). Built here via
public_corpus.support.synthetic.pack from a fabricated-but-matching
constant -- no bytes are copied from any capture, private test, or real
DIAG log. (A real byte snippet would also be fine per the tier-0 rule,
but the whole payload is 4 bytes and trivially synthesized, so
synthesizing keeps this corpus-uniform per the recipe doc.)

Layout (per diaggrok.parsers.diag_0x197f, ``version_less=True`` since
byte-0 is just the low byte of the constant u32, not a DIAG version
field):
    data[0:4]  u32 LE state_word -- parser hard-rejects any value other
               than 0xC002F2A0 (field_invariants enum), so the fabricated
               value here is exactly that constant, not a free choice.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x197f import parse_0x197f

# The parser only accepts this exact constant (see diag_0x197f.py
# field_invariants={"state_word": {"enum": [0xC002F2A0]}}); there is no
# other legal fabricated value for this field.
_STATE_WORD = 0xC002F2A0


def _synthetic_197f() -> bytes:
    data = pack('<I', _STATE_WORD)
    assert len(data) == 4
    return data


def test_197f_decodes_synthetic_frame():
    rec = parse_0x197f(1000, _synthetic_197f())
    assert rec is not None
    assert rec.state_word == _STATE_WORD


def test_197f_to_dict_hex_field():
    rec = parse_0x197f(1000, _synthetic_197f())
    assert rec is not None
    d = rec.to_dict()
    assert d['state_word'] == _STATE_WORD
    assert d['state_word_hex'] == 'c002f2a0'
