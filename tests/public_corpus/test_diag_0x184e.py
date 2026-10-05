"""Public zero-PII fixture for 0x184E (CM Serving-System MSIM event).

Tier 1 (synthetic-only): the parser keeps an opaque ``subs_block`` and
unmodeled stack bytes (see public_corpus.risk_tiers.RISK_TIER[0x184E] == 1),
so this fixture is built entirely from fabricated values via
public_corpus.support.synthetic -- no bytes are copied from any capture,
private test, or real DIAG log.

Targets the v0x05 layout documented in diaggrok.parsers.diag_0x184e:
10-byte header (version u8, event u32, asubs_id u32, number_of_stacks u8),
a 377-byte subscription block, then one 754-byte stack block.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x184e import parse_0x184e

# Fabricated values (not from any real capture).
_VERSION = 0x05
_EVENT = 1            # CM_SS_EVENT_RSSI
_SYS_MODE = 9         # LTE
_SRV_STATUS = 2       # SRV
_RSSI = 90
_PLMN = bytes([0x00, 0xF1, 0x10])   # MCC 001 / MNC 01 -- the 3GPP test PLMN


def _synthetic_184e() -> bytes:
    header = pack('<B', _VERSION) + pack('<I', _EVENT) + pack('<I', 0) + pack('<B', 1)
    subs = bytes(377)
    stack = bytearray(754)
    stack[0x10:0x14] = pack('<I', 0x10)            # signal_changed_fields
    stack[0x18] = 1                                # is_operational
    stack[0x19:0x1d] = pack('<I', _SRV_STATUS)
    stack[0x29:0x2d] = pack('<I', _SYS_MODE)
    stack[0x3a:0x3d] = _PLMN
    stack[0x28a:0x28c] = pack('<H', _RSSI)
    stack[0x297:0x299] = pack('<h', -_RSSI)
    data = header + subs + bytes(stack)
    assert len(data) == 1141
    return data


def test_184e_decodes_synthetic_v5_frame():
    rec = parse_0x184e(1000, _synthetic_184e())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.event == _EVENT and rec.event_name == 'CM_SS_EVENT_RSSI'
    assert rec.number_of_stacks == 1 and len(rec.stacks) == 1
    st = rec.stacks[0]
    assert (st.srv_status, st.sys_mode) == (_SRV_STATUS, _SYS_MODE)
    assert st.plmn_03a == '001-01'
    assert (st.rssi, st.rssi2) == (_RSSI, -_RSSI)
    assert rec.size_variant == 'v5_1141'
