"""Public zero-PII fixture for 0x18AC (LTE ML1 Inter-frequency Measurement).

Tier 1 (synthetic-only): decoded fields carry PCI/EARFCN-shaped neighbor-cell
structure (see public_corpus.risk_tiers.RISK_TIER[0x18AC] == 1, "PCI +
EARFCN together (cell identity)"), so this fixture is built entirely from
fabricated values via public_corpus.support.synthetic -- no bytes are
copied from any capture, private test, or real DIAG log.

Targets the v=0x01 (70-byte, SDX20-era) framing documented in
diaggrok.parsers.diag_0x18ac: 2-byte outer header + two 34-byte cell
records, each gated on three cross-vendor magic-byte anchors
(entry_marker@+0==0x01, magic_a@+3==0x09, magic_b@+16==0x01).
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x18ac import parse_0x18ac

# Fabricated header values (not from any real capture).
_VERSION = 0x01       # data[0] -- field_invariants enum {0x01, 0x04}
_NUM_CARRIERS = 2     # data[1] -- fabricated (not invariant for v=1)
_CELL_SIZE = 34
_ENTRY_MARKER = 0x01  # intra +0 -- field_invariants const (both cells)
_MAGIC_A = 0x09       # intra +3 -- field_invariants const (both cells)
_MAGIC_B = 0x01       # intra +16 -- field_invariants const (both cells)
_CELL1_MEAS_HIGH_BYTE = 0x3E  # intra +11 -- fabricated (bimodal 0x3e/0xbe per docstring)
_CELL2_MEAS_HIGH_BYTE = 0xBE  # intra +11 -- fabricated


def _cell(meas_high_byte: int) -> bytes:
    """Build one 34-byte v=1 cell record with the 3 required magic anchors.

    Offsets transcribed from LteMl1InterFreqV1Cell / _V1_*_OFF constants in
    diag_0x18ac.py:
      intra +0   entry_marker = 0x01
      intra +3   magic_a = 0x09
      intra +11  meas_high_byte (fabricated; not invariant-enforced)
      intra +16  magic_b = 0x01
      other bytes: fabricated fill pattern (not decoded by the parser)
    """
    buf = bytearray(bytes((i * 7 + 3) % 251 for i in range(_CELL_SIZE)))
    buf[0] = _ENTRY_MARKER
    buf[3] = _MAGIC_A
    buf[11] = meas_high_byte
    buf[16] = _MAGIC_B
    return bytes(buf)


def _synthetic_18ac_v1() -> bytes:
    header = pack('<B', _VERSION) + pack('<B', _NUM_CARRIERS)
    data = header + _cell(_CELL1_MEAS_HIGH_BYTE) + _cell(_CELL2_MEAS_HIGH_BYTE)
    assert len(data) == 70
    return data


def test_18ac_decodes_synthetic_v1_frame():
    rec = parse_0x18ac(1000, _synthetic_18ac_v1())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.num_carriers == _NUM_CARRIERS
    assert rec.entries == []
    assert rec.v1_cell1_entry_marker == _ENTRY_MARKER
    assert rec.v1_cell1_magic_a == _MAGIC_A
    assert rec.v1_cell1_magic_b == _MAGIC_B
    assert rec.v1_cell2_entry_marker == _ENTRY_MARKER
    assert rec.v1_cell2_magic_a == _MAGIC_A
    assert rec.v1_cell2_magic_b == _MAGIC_B
    assert len(rec.v1_cells) == 2
    assert rec.v1_cells[0].meas_high_byte == _CELL1_MEAS_HIGH_BYTE
    assert rec.v1_cells[1].meas_high_byte == _CELL2_MEAS_HIGH_BYTE
