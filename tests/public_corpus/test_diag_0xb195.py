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
        Per-cell record (52 B, byte-identical to 0xB192 — #N), body[8:60]:
          [+0:4]   u32  pci (low 9 bits)
          [+8:12]  u32  energy1 (per-Rx integrated energy)
          [+24:26] u16  meas_index (a counter — the byte the pre-#N parser
                        MIS-decoded as "rsrp" via -raw/10; #N v6 REFUTED)
          [+36:38] u16  aux0 (was mis-read as "rsrq_rx0")
          [+40:44] u32  timing
        rsrp/rsrq are None — no calibrated dBm in this packet (#N).
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0xb195 import parse_0xb195

_VERSION = 0x01
_SP_VER = 4
_EARFCN = 800          # low 18 bits of the u32 at carrier-header+0
_PCI = 45              # low 9 bits of the u32 at cell+0
_ENERGY1 = 4224007     # u32 at cell+8 (RSRP-tracking energy, #N)
_MEAS_INDEX = 682      # u16 at cell+24 (a counter — NOT rsrp)
_AUX0 = 40             # u16 at cell+36 (unresolved — was mis-read as rsrq)
_TIMING = 138004       # u32 at cell+40


def _synthetic_cell() -> bytes:
    cell = bytearray(52)
    cell[0:4] = pack('<I', _PCI)
    cell[8:12] = pack('<I', _ENERGY1)
    cell[24:26] = pack('<H', _MEAS_INDEX)
    cell[36:38] = pack('<H', _AUX0)
    cell[40:44] = pack('<I', _TIMING)
    cell[44:48] = pack('<I', _TIMING)   # +44 == +40 always
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
    # rsrp/rsrq are None (energy-not-dBm, #N/#N v6); the raw words are
    # exposed instead (#N).
    assert entry.rsrp is None
    assert entry.rsrq_rx0 is None
    assert entry.rsrq_rx1 is None
    assert entry.energy1 == _ENERGY1
    assert entry.meas_index == _MEAS_INDEX
    assert entry.aux0 == _AUX0
    assert entry.timing == _TIMING
