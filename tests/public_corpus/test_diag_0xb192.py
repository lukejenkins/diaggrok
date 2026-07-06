"""Public zero-PII fixture for 0xB192 (LTE ML1 idle-mode neighbor cell meas).

Tier 1 (synthetic-only, see public_corpus.risk_tiers.RISK_TIER[0xB192] == 1):
PCI + EARFCN together pin a real cell, so this frame is built entirely from
fabricated values via public_corpus.support.synthetic -- no bytes are copied
from any capture, private test, or real DIAG log.

Targets the modern response-subpacket layout (ver=4, 8-byte carrier header),
outer version=0x01, ONE response subpacket (id=27) with a single fabricated
neighbor cell -- the simplest shape ``parse_0xb192`` decodes (no request
subpacket id=26 is included; ``request_cells`` is expected empty). Offsets
below are transcribed from diaggrok.parsers.diag_0xb192's live
``parse_0xb192`` / ``_parse_response_subpacket`` code, not the module's
prose narrative:

    Outer header (4 B), data[0:4]:
      [0]    u8   version = 0x01
      [1]    u8   num_subpackets = 1
      [2:4]  u16  counter

    Subpacket (id=27, ver=4), data[4:4+sp_size]:
      [0]    u8   sp_id = 27
      [1]    u8   sp_ver = 4
      [2:4]  u16  sp_size (INCLUSIVE of this 4-byte subpacket header)
      Response body (sp_size - 4 bytes):
        [0:4]   u32  earfcn_raw (low 18 bits)
        [4:6]   u16  num_cells = 1
        [6:8]   u16  reserved
        Per-cell record (52 B), body[8:60]:
          [+0:4]   u32  pci_raw (low 9 bits)
          [+4:8]   u32  energy0
          [+8:12]  u32  energy1
          [+12:16] u32  energy2
          [+16:20] u32  energy_wide0
          [+20:24] u32  energy_wide1
          [+24:26] u16  meas_index
          [+28:32] u32  energy_filt
          [+36:38] u16  aux0
          [+38:40] u16  aux1
          [+40:44] u32  timing
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0xb192 import parse_0xb192

_VERSION = 0x01
_COUNTER = 5
_SP_VER = 4
_EARFCN = 975       # low 18 bits of the u32 at carrier-header+0
_PCI = 473          # low 9 bits of the u32 at cell+0 (473 < 512, fits exactly)
_ENERGY0 = 4_500_000
_ENERGY1 = 4_600_000
_ENERGY2 = 4_700_000
_ENERGY_WIDE0 = 150_000_000
_ENERGY_WIDE1 = 190_000_000
_MEAS_INDEX = 500
_ENERGY_FILT = 1_200_000
_AUX0 = 42
_AUX1 = 45
_TIMING = 200_000


def _synthetic_cell() -> bytes:
    cell = bytearray(52)
    cell[0:4] = pack('<I', _PCI)
    cell[4:8] = pack('<I', _ENERGY0)
    cell[8:12] = pack('<I', _ENERGY1)
    cell[12:16] = pack('<I', _ENERGY2)
    cell[16:20] = pack('<I', _ENERGY_WIDE0)
    cell[20:24] = pack('<I', _ENERGY_WIDE1)
    cell[24:26] = pack('<H', _MEAS_INDEX)
    # cell[26:28] reserved, zero
    cell[28:32] = pack('<I', _ENERGY_FILT)
    # cell[32:36] reserved, zero
    cell[36:38] = pack('<H', _AUX0)
    cell[38:40] = pack('<H', _AUX1)
    cell[40:44] = pack('<I', _TIMING)
    cell[44:48] = pack('<I', _TIMING)  # duplicate, per documented layout
    # cell[48:52] reserved, zero
    assert len(cell) == 52
    return bytes(cell)


def _synthetic_b192() -> bytes:
    """Build a v0x01 outer / sp-ver=4 response-only 0xB192 record with one
    fabricated neighbor cell. ``diag_frame`` supplies the version byte at
    data[0]; the rest (num_subpackets + counter + one response subpacket)
    is assembled here.
    """
    cell = _synthetic_cell()

    response_body = (
        pack('<I', _EARFCN)  # carrier header: earfcn_raw (low 18 bits used)
        + pack('<H', 1)      # num_cells
        + pack('<H', 0)      # reserved
        + cell
    )
    assert len(response_body) == 60

    subpacket = (
        pack('<B', 27)                            # sp_id (response)
        + pack('<B', _SP_VER)                      # sp_ver
        + pack('<H', 4 + len(response_body))        # sp_size (inclusive)
        + response_body
    )
    assert len(subpacket) == 64

    body = (
        pack('<B', 1)         # num_subpackets
        + pack('<H', _COUNTER)
        + subpacket
    )
    data = diag_frame(0xB192, _VERSION, body)
    assert len(data) == 68
    return data


def test_b192_decodes_synthetic_frame():
    rec = parse_0xb192(1000, _synthetic_b192())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.sp_version == _SP_VER
    assert rec.counter == _COUNTER
    assert rec.earfcn == _EARFCN
    assert rec.num_cells == 1
    assert len(rec.entries) == 1

    entry = rec.entries[0]
    assert entry.pci == _PCI
    assert entry.earfcn == _EARFCN
    # No calibrated dBm in this packet (#N) -- rsrp/rsrq are always None.
    assert entry.rsrp is None
    assert entry.rsrq_rx0 is None
    assert entry.rsrq_rx1 is None
    assert entry.energy0 == _ENERGY0
    assert entry.energy1 == _ENERGY1
    assert entry.energy2 == _ENERGY2
    assert entry.energy_wide0 == _ENERGY_WIDE0
    assert entry.energy_wide1 == _ENERGY_WIDE1
    assert entry.meas_index == _MEAS_INDEX
    assert entry.energy_filt == _ENERGY_FILT
    assert entry.aux0 == _AUX0
    assert entry.aux1 == _AUX1
    assert entry.timing == _TIMING

    # No request subpacket (id=26) was supplied.
    assert rec.request_cells == []
