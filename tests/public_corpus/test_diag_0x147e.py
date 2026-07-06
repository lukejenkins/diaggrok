"""Public zero-PII fixture for 0x147E (GNSS RF hardware status report).

Tier 1 (synthetic-only): fw_id is an explicit GNSS RF firmware identifier
string (see public_corpus.risk_tiers.RISK_TIER[0x147E] == 1), so this frame
is built entirely from fabricated values via public_corpus.support.synthetic
-- no bytes are copied from any capture, private test, or real DIAG log.

Targets the v4 (SDX20-class, 349B-in-corpus) header layout documented at the
top of diaggrok.parsers.diag_0x147e: version=4, fixed 64-byte identity
header (fw_id / constellations / sdr_chip / board_id cstrings + a u32 ms
counter), zero-length body (v4's body is binary with no ASCII band labels,
so rf_bands/glonass_channels are expected empty for this variant -- the
parser only requires len(data) >= 64, not any specific total size).
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x147e import parse_0x147e

# Fabricated header values (not from any real capture).
_VERSION = 4                       # byte 0 -- must be in {4, 5, 6} (field_invariants)
_FW_ID = "Gen9HT 9.1.0"             # cstr at [1:16] (15-byte slot)
_CONSTELLATIONS = "GPS/GLO/BDS/GAL"  # cstr at [16:32] (16-byte slot)
_MS_COUNTER = 123456                # u32 LE at [36:40]
_SDR_CHIP = "SDR845"                # cstr at [40:48] (8-byte slot)
_BOARD_ID = "M5ET"                  # cstr at [52:64] (12-byte slot)


def _cstr_slot(s: str, size: int) -> bytes:
    """Fabricated NUL-terminated ASCII string padded with zero bytes to
    fill a fixed-size slot, matching how the parser's `_cstr` reads a
    NUL-terminated run out of a fixed slice."""
    raw = s.encode('ascii')
    assert len(raw) < size
    return raw + bytes(size - len(raw))


def _synthetic_147e() -> bytes:
    """Build a v4, 64-byte-header-only 0x147E payload (no body). Offsets
    below are transcribed from the parser's own header-layout docstring in
    diag_0x147e.py, not from any capture:

      data[0]       version = 4                (SDX20 V2 class)
      data[1:16]    fw_id = "Gen9HT 9.1.0"      cstr, 15-byte slot
      data[16:32]   constellations = "GPS/GLO/BDS/GAL"  cstr, 16-byte slot
      data[32:36]   reserved = 0
      data[36:40]   u32 ms_counter = 123456
      data[40:48]   sdr_chip = "SDR845"         cstr, 8-byte slot
      data[48:52]   reserved = 0
      data[52:64]   board_id = "M5ET"           cstr, 12-byte slot
      data[64:]     body = b'' (empty -- v4 body is binary, no band labels)
    """
    header = (
        pack('<B', _VERSION)
        + _cstr_slot(_FW_ID, 15)
        + _cstr_slot(_CONSTELLATIONS, 16)
        + bytes(4)
        + pack('<I', _MS_COUNTER)
        + _cstr_slot(_SDR_CHIP, 8)
        + bytes(4)
        + _cstr_slot(_BOARD_ID, 12)
    )
    assert len(header) == 64
    return header


def test_147e_decodes_synthetic_frame():
    rec = parse_0x147e(1000, _synthetic_147e())
    assert rec is not None
    assert rec.version == 4
    assert rec.fw_id == _FW_ID
    assert rec.constellations == _CONSTELLATIONS
    assert rec.sdr_chip == _SDR_CHIP
    assert rec.board_id == _BOARD_ID
    assert rec.ms_counter == _MS_COUNTER
    assert rec.rf_bands == ()
    assert rec.glonass_channels == ()
