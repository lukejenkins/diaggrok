"""Public zero-PII fixture for 0x1856 (IPA routing-rule table dump).

Tier 1 (synthetic-only): a decoded 0x1856 body can carry the UE's own IPv6
address (meq128 rules at IPv6 offset 8/24) — see
public_corpus.risk_tiers.RISK_TIER[0x1856] == 1 — so this fixture is built
entirely from fabricated values via public_corpus.support.synthetic; no bytes
are copied from any capture, private test, or real DIAG log.

Layout (diaggrok.parsers._ipa_rules.decode_dump, version >= 0x02): a 16-byte
header — version u8, timetick u24, dump_word u32, table_id u8, table_sub u8,
table_word u16, body_len u16, pad14 u16 — then IPA v3+ rules. The single
fabricated rule is en_rule 0x0020 (one meq32): IP version nibble == 4.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1856 import parse_0x1856

# Fabricated values (not from any real capture).
_VERSION = 0x04
_TIMETICK = 0x0ABCDE
_TABLE_ID = 0x01
_WORD2 = 0x0003


def _synthetic_rule() -> bytes:
    return (
        pack('<HHHH', 0x0020, _WORD2, 0, 0)       # rule header
        + bytes([0x00]) + bytes(7)                # extra word: meq32 offset 0
        + pack('<II', 0xF0000000, 0x40000000)     # mask / value
    )


def _synthetic_1856() -> bytes:
    body = _synthetic_rule()
    data = (
        pack('<B', _VERSION)
        + _TIMETICK.to_bytes(3, 'little')
        + pack('<I', 0)                           # dump_word
        + pack('<BBH', _TABLE_ID, 0, 0)           # table_id, table_sub, table_word
        + pack('<HH', len(body), 0)               # body_len, pad14
        + body
    )
    assert len(data) == 40
    return data


def test_1856_decodes_synthetic_rule_table():
    rec = parse_0x1856(1000, _synthetic_1856())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.timetick == _TIMETICK
    assert rec.table_id == _TABLE_ID
    assert rec.body_len == 24 and rec.body_len_ok
    assert rec.walk_status == 'exact'
    assert rec.rule_count == 1
    rule = rec.rules[0]
    assert rule['en_rule'] == 0x0020 and rule['word2'] == _WORD2
    assert rule['equations'] == {
        'meq32_0': {'offset': 0, 'mask': 0xF0000000, 'value': 0x40000000}}
