"""Public zero-PII fixture for 0x147C (GNSS PE WLS position report).

Tier 1 (synthetic-only): body_raw is left undecoded on most versions, and
the decoded v=0x0D per-SV records carry a GPS PRN -- per
public_corpus.risk_tiers.RISK_TIER this frame must be fully synthetic,
built via public_corpus.support.synthetic -- no bytes copied from any
capture.

Targets the v=0x0D body decode documented in diaggrok.parsers.diag_0x147c:
a 44-byte preamble (with 17 cross-capture-invariant bytes) followed by a
grid of 47-byte slots. This fixture uses exactly ONE slot that is itself a
valid per-SV WLS record (signature ``00 00 75 11 01`` at the slot start),
so ``head_slots`` comes out to 0 and ``n_sv_records`` to 1 -- the simplest
non-trivial v=0x0D shape.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x147c import parse_0x147c

# Fabricated preamble values (not from any real capture).
_COUNTER_HI = 0x11   # byte [1]
_COUNTER_LO = 0x22   # byte [2]

# Fabricated per-SV values (not from any real capture).
_PRN = 7             # u8 @ slot+6
_SUBFRAME_TYPE = 3   # u8 @ slot+10
_WLS_F1 = 1.0
_WLS_F2 = 5.0
_WLS_F3 = 1.0
_WLS_F4 = 0.5
_WLS_F5 = 1500.0
_WLS_F6 = 200.0
_WLS_F7 = 0.01
_WLS_F8 = 0.05
_WLS_F9 = 1.0


def _synthetic_147c() -> bytes:
    """Build a 91-byte v=0x0D 0x147C payload: 44B preamble + one 47B SV slot.

    Preamble (44 bytes) -- only the 17 offsets in the parser's
    ``_V0D_PREAMBLE_CONSTS`` are required to hold a specific value (all
    zero except byte[0]); every other preamble byte is left at 0 too
    (structurally arbitrary -- the parser does not check them), except
    bytes[1:4] which form the fabricated ``seq_counter``:

      [0]      u8  version = 0x0D (required)
      [1]      u8  = 0x11 (fabricated, low byte of seq_counter)
      [2]      u8  = 0x22 (fabricated, mid byte of seq_counter)
      [3]      u8  = 0x00 (high byte of seq_counter)
      [9:13]   4 zero bytes (required == 0)
      [18:21]  3 zero bytes (required == 0)
      [22:31]  9 zero bytes (required == 0)
      (all remaining preamble bytes zero-filled; not checked by the parser)

    seq_counter = data[1] | (data[2]<<8) | (data[3]<<16)
                = 0x11 | (0x22 << 8) | (0 << 16) = 0x2211 = 8721

    SV slot (47 bytes, starting at preamble end, offset 44):
      [+0:5]   5-byte signature ``00 00 75 11 01`` (parser's find() target)
      [+5]     0x00 reserved
      [+6]     u8  prn = 7 (fabricated GPS PRN)
      [+7]     0x00 reserved
      [+8:10]  ``00 07`` record-type marker
      [+10]    u8  subframe_type = 3 (fabricated)
      [+11:47] 9 x f32 LE wls_f1..wls_f9 (fabricated measurement floats)
    """
    preamble = bytearray(44)
    preamble[0] = 0x0D
    preamble[1] = _COUNTER_HI
    preamble[2] = _COUNTER_LO
    # bytes [9:13], [18:21], [22:31] already zero from bytearray init --
    # these are the parser's _V0D_PREAMBLE_CONSTS required-zero offsets.
    preamble = bytes(preamble)
    assert len(preamble) == 44

    sig = b'\x00\x00\x75\x11\x01'
    floats = pack(
        '<9f', _WLS_F1, _WLS_F2, _WLS_F3, _WLS_F4, _WLS_F5,
        _WLS_F6, _WLS_F7, _WLS_F8, _WLS_F9,
    )
    slot = (
        sig
        + pack('<B', 0x00)             # [+5] reserved
        + pack('<B', _PRN)             # [+6] prn
        + pack('<B', 0x00)             # [+7] reserved
        + pack('<H', 0x0700)           # [+8:10] record-type marker (LE 00 07)
        + pack('<B', _SUBFRAME_TYPE)   # [+10]
        + floats                       # [+11:47] 9 f32 measurements
    )
    assert len(slot) == 47

    body = preamble + slot
    assert len(body) == 44 + 47
    return body


def test_147c_decodes_synthetic_v0d_frame():
    rec = parse_0x147c(1000, _synthetic_147c())
    assert rec is not None
    assert rec.version == 0x0D
    assert rec.n_slots == 1
    assert rec.n_sv_records == 1
    assert rec.head_slots == 0
    assert rec.preamble_invariants_ok is True
    assert rec.seq_counter == 0x2211
    assert len(rec.wls_records) == 1
    sv = rec.wls_records[0]
    assert sv.prn == 7
    assert sv.subframe_type == 3
    assert sv.wls_f5 == 1500.0
