"""Public zero-PII fixture for 0x14A6 (GNSS per-SV ephemeris/IODE snapshot).

Tier 1 (synthetic-only): fw_tag is an explicit firmware-tag field (see
public_corpus.risk_tiers.RISK_TIER[0x14A6] == 1), so this frame is built
entirely from fabricated values via public_corpus.support.synthetic -- no
bytes are copied from any capture, private test, or real DIAG log.

Targets the 151-byte fixed layout documented at the top of
diaggrok.parsers.diag_0x14a6: version=0x02 (hard-gated), a fully-decoded
header, and a 12-slot x 4-byte per-SV table at payload offset [23:71]
(sv_id u16LE + iode u16LE per slot; iode was named cno_metric ≤v8, #N).
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x14a6 import parse_0x14a6

# Fabricated values (not from any real capture). Offsets transcribed from
# the parser's own field-map docstring in diag_0x14a6.py.
_VERSION = 0x02          # byte 0 -- hard-gated constant
_FLAG_1 = 0               # byte 1
_NUM_SV_FAMILY_A = 6      # byte 14
_FLAG_15 = 0              # byte 15
_NUM_SV_FIX = 5           # byte 16
_NUM_SV_SUBSET = 0        # byte 17
_NUM_SV_TRACKED = 6       # byte 18
_FW_TAG = 0x6d            # byte 21 -- ASCII 'm', one of the documented enum values
_SUB_TYPE = 9             # byte 22 -- populated-record discriminator
_SLOT0_SV_ID = 10         # u16LE at slot [23:25]
_SLOT0_IODE = 350         # u16LE at slot [25:27] (renamed from _SLOT0_CNO, #N)

_TOTAL_LEN = 151


def _synthetic_14a6() -> bytes:
    buf = bytearray(_TOTAL_LEN)
    buf[0] = _VERSION
    buf[1] = _FLAG_1
    # buf[2:10] stats_header -- left zero, not asserted
    # buf[10] reserved_10, buf[11:13] nav_state, buf[13] reserved_13 -- left zero
    buf[14] = _NUM_SV_FAMILY_A
    buf[15] = _FLAG_15
    buf[16] = _NUM_SV_FIX
    buf[17] = _NUM_SV_SUBSET
    buf[18] = _NUM_SV_TRACKED
    # buf[19], buf[20] aux_19/aux_20 -- left zero
    buf[21] = _FW_TAG
    buf[22] = _SUB_TYPE
    buf[23:25] = pack('<H', _SLOT0_SV_ID)
    buf[25:27] = pack('<H', _SLOT0_IODE)
    # remaining 11 sv_slots [27:71] and reserved_tail [71:151] left zero
    assert len(buf) == _TOTAL_LEN
    return bytes(buf)


def test_14a6_decodes_synthetic_frame():
    rec = parse_0x14a6(1000, _synthetic_14a6())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.num_sv_family_a == _NUM_SV_FAMILY_A
    assert rec.num_sv_fix == _NUM_SV_FIX
    assert rec.num_sv_subset == _NUM_SV_SUBSET
    assert rec.num_sv_tracked == _NUM_SV_TRACKED
    assert rec.fw_tag == _FW_TAG
    assert rec.sub_type == _SUB_TYPE
    assert len(rec.sv_slots) == 12
    assert rec.sv_slots[0].sv_id == _SLOT0_SV_ID
    assert rec.sv_slots[0].iode == _SLOT0_IODE
    assert rec.sv_slots[0].cno_metric == _SLOT0_IODE  # deprecated alias (#N)
    assert rec.sv_slots[0].is_populated is True
    assert rec.sv_slots[1].is_populated is False
    assert rec.payload_size == _TOTAL_LEN
