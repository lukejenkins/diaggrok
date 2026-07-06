"""Public zero-PII fixture for 0xB193 (LTE ML1 Serving Cell Meas Response).

Tier 1 (synthetic-only): PCI + EARFCN together pin a real cell (see
public_corpus.risk_tiers.RISK_TIER[0xB193] == 1), so this frame is built
entirely from fabricated values via public_corpus.support.synthetic -- no
bytes are copied from any capture, private test, or real DIAG log.

Targets the base subpacket_version=36 (SDX20) layout documented at the top
of diaggrok.parsers.diag_0xb193: version=1, one subpacket, per-cell PCI at
cell+0 (low 9 bits of a u32), RSRP at cell+56 (u16, dBm = -raw/10.0), RSRQ
at cell+64 (u16, dB = (raw-60)/2.0). This is the simplest well-documented
variant and needs no version-dispatch branch (v48/v59) to decode.
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0xb193 import parse_0xb193

# Fabricated serving-cell values (not from any real capture).
_PCI = 6           # low 9 bits of the u32 at cell+0
_EARFCN = 800       # low 18 bits of the u32 at carrier-header+0
_RSRP_RAW = 765     # u16 at cell+56 -> dBm = -raw/10.0 = -76.5
_RSRQ_RAW = 40      # u16 at cell+64 -> dB = (raw-60)/2.0 = -10.0


def _synthetic_b193() -> bytes:
    """Build a v1/subpacket-v36 (SDX20) 0xB193 payload with one fabricated
    serving cell. Offsets below are transcribed from the parser's own
    docstring/comments in diag_0xb193.py, not from any capture:

      data[0]    version = 1               (supplied via diag_frame)
      data[1]    num_subpackets = 1
      data[2:4]  system frame number = 0    (not read by the parser)
      data[4]    subpacket_id = 25
      data[5]    subpacket_version = 36     (selects the v36 field offsets)
      data[6:8]  subpacket_size = 78        (4-byte header + 74-byte body)

      subpacket data (data[8:]), 74 bytes:
        sp[0:4]   u32 earfcn_raw = 800      -> earfcn = 800 & 0x3FFFF = 800
        sp[4:6]   u16 num_cells = 1
        sp[6:8]   u16 num_rx_antennas = 1   (not decoded into entries)

        per-cell record (sp[8:74], 66 bytes -- the v36 min_cell_record):
          cell+0:4   u32 pci_raw = 6        -> pci = 6 & 0x1FF = 6
          cell+4:56  52 zero-filled bytes    (intermediate fields, unused
                                               by the v36 decode path)
          cell+56:58 u16 rsrp_raw = 765      -> rsrp = -765 / 10.0 = -76.5
          cell+58:64 6 zero-filled bytes     (unused by the v36 decode path)
          cell+64:66 u16 rsrq_raw = 40       -> rsrq = (40 - 60) / 2.0 = -10.0
    """
    cell = (
        pack('<I', _PCI)
        + bytes(52)
        + pack('<H', _RSRP_RAW)
        + bytes(6)
        + pack('<H', _RSRQ_RAW)
    )
    assert len(cell) == 66

    subpacket_data = (
        pack('<I', _EARFCN)  # carrier header: earfcn_raw
        + pack('<H', 1)      # num_cells
        + pack('<H', 1)      # num_rx_antennas
        + cell
    )
    assert len(subpacket_data) == 74

    body = (
        pack('<B', 1)                          # num_subpackets
        + pack('<H', 0)                         # system frame number
        + pack('<B', 25)                        # subpacket_id
        + pack('<B', 36)                        # subpacket_version
        + pack('<H', 4 + len(subpacket_data))   # subpacket_size
        + subpacket_data
    )
    return diag_frame(0xB193, 1, body)


def test_b193_decodes_synthetic_frame():
    rec = parse_0xb193(1000, _synthetic_b193())
    assert rec is not None
    assert rec.version == 1
    assert rec.subpacket_version == 36
    assert rec.earfcn == 800
    assert len(rec.entries) == 1
    assert rec.entries[0].pci == 6
    assert rec.entries[0].earfcn == 800
    assert rec.entries[0].rsrp == -76.5
    assert rec.entries[0].rsrq == -10.0
