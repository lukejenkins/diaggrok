"""Public zero-PII fixture for 0xB195 (LTE ML1 connected-mode neighbor meas).

Tier 1 (synthetic-only, see public_corpus.risk_tiers.RISK_TIER[0xB195] == 1):
PCI + EARFCN together pin a real cell, so this frame is built entirely from
fabricated values via public_corpus.support.synthetic -- no bytes are copied
from any capture, private test, or real DIAG log.

Targets the v4 (MDM9207/EG25-G) response-subpacket layout, outer
version=0x01, ONE response subpacket (id=31, ver=4) with a single fabricated
neighbor cell -- the simplest shape ``parse_0xb195`` decodes. Offsets below
are transcribed from diaggrok.parsers.diag_0xb195's live ``parse_0xb195`` /
``_parse_response_subpacket`` code, not the module's prose narrative:

    Outer header (4 B), data[0:4]:
      [0]    u8   version = 0x01
      [1]    u8   num_subpackets = 1
      [2:4]  u16  counter / SFN (not read by the parser)

    Subpacket (id=31, ver=4), data[4:4+sp_size]:
      [0]    u8   sp_id = 31
      [1]    u8   sp_ver = 4
      [2:4]  u16  sp_size (INCLUSIVE of this 4-byte subpacket header)
      Response body (sp_size - 4 bytes):
        [0:4]   u32  earfcn_raw (low 18 bits)
        [4:6]   u16  num_cells_raw = 1 (<=32, used directly)
        [6:8]   u16  reserved
        Per-cell record (52 B), body[8:60]:
          [+0:2]   u16  pci (<=503, gated)
          [+24:26] u16  rsrp_raw   -> dBm = -raw/10.0, gated -140..-30
          [+36:38] u16  rsrq_rx0_raw -> dB = (raw-60)/2.0, gated -34..2.5
          [+38:40] u16  rsrq_rx1_raw -> dB = (raw-60)/2.0, gated -34..2.5
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0xb195 import parse_0xb195

_VERSION = 0x01
_SP_VER = 4
_EARFCN = 800          # low 18 bits of the u32 at carrier-header+0
_PCI = 45              # u16 at cell+0, <= 503
_RSRP_RAW = 800        # u16 at cell+24 -> dBm = -800/10.0 = -80.0
_RSRQ_RX0_RAW = 40     # u16 at cell+36 -> dB = (40-60)/2.0 = -10.0
_RSRQ_RX1_RAW = 50     # u16 at cell+38 -> dB = (50-60)/2.0 = -5.0


def _synthetic_cell() -> bytes:
    cell = bytearray(52)
    cell[0:2] = pack('<H', _PCI)
    # cell[2:24] reserved/timing fields, not asserted -- zero-filled
    cell[24:26] = pack('<H', _RSRP_RAW)
    # cell[26:36] reserved, zero
    cell[36:38] = pack('<H', _RSRQ_RX0_RAW)
    cell[38:40] = pack('<H', _RSRQ_RX1_RAW)
    # cell[40:52] reserved, zero
    assert len(cell) == 52
    return bytes(cell)


def _synthetic_b195() -> bytes:
    """Build a v0x01 outer / sp-ver=4 response-only 0xB195 record with one
    fabricated neighbor cell. ``diag_frame`` supplies the version byte at
    data[0]; the rest (num_subpackets + counter + one response subpacket)
    is assembled here.
    """
    cell = _synthetic_cell()

    response_body = (
        pack('<I', _EARFCN)  # carrier header: earfcn_raw (low 18 bits used)
        + pack('<H', 1)      # num_cells_raw
        + pack('<H', 0)      # reserved
        + cell
    )
    assert len(response_body) == 60

    subpacket = (
        pack('<B', 31)                            # sp_id (response)
        + pack('<B', _SP_VER)                       # sp_ver
        + pack('<H', 4 + len(response_body))         # sp_size (inclusive)
        + response_body
    )
    assert len(subpacket) == 64

    body = (
        pack('<B', 1)         # num_subpackets
        + pack('<H', 0)       # counter / SFN (not read by the parser)
        + subpacket
    )
    data = diag_frame(0xB195, _VERSION, body)
    assert len(data) == 68
    return data


def test_b195_decodes_synthetic_frame():
    rec = parse_0xb195(1000, _synthetic_b195())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.earfcn == _EARFCN
    assert rec.num_cells == 1
    assert len(rec.entries) == 1

    entry = rec.entries[0]
    assert entry.pci == _PCI
    assert entry.earfcn == _EARFCN
    assert entry.rsrp == -80.0
    assert entry.rsrq_rx0 == -10.0
    assert entry.rsrq_rx1 == -5.0
