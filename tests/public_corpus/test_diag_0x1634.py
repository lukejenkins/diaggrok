"""Public zero-PII fixture for 0x1634 (GNSS per-SV range measurement, 31B fixed).

Tier-0 per public_corpus.risk_tiers.RISK_TIER[0x1634] == 0 (no cell-identity /
GNSS-position / IMEI / firmware-string / absolute-time field, and the payload
is fully decoded with no opaque tail) -- real-snippet-eligible. This fixture
still builds a fully synthetic frame (never a byte-for-byte capture copy) via
public_corpus.support.synthetic, keeping the corpus uniform per the recipe
doc's "when in doubt, synthesize" guidance.

Targets the fixed 31-byte record decode in diaggrok.parsers.diag_0x1634:
version @0 (gated to {1, 2}), counter_ms u16 @1:3, aux_counter @3, flag_4 @4,
constellation @5, flags_6 @6, meas_a i32 @7:11, meas_b i32 @11:15,
signal_type @15, flag_16 @16, sub_idx @17, sv_slot @18, reserved_19 @19
(= 0), param_20/21/22 @20/21/22, cno_dbhz @23, reserved_24 @24 (= 0),
metric_25 u16 @25:27, ext_meas i32 @27:31.
"""
from public_corpus.support.synthetic import diag_frame, pack
from diaggrok.parsers.diag_0x1634 import parse_0x1634

# Fabricated per-SV range-measurement values (not from any real capture).
_COUNTER_MS = 1000       # u16 @1:3
_AUX_COUNTER = 7         # byte 3
_FLAG_4 = 1              # byte 4
_CONSTELLATION = 3       # byte 5 -> 'GAL' (Galileo) per constellation_name map
_FLAGS_6 = 2             # byte 6
_MEAS_A = -12345         # i32 @7:11
_MEAS_B = 678            # i32 @11:15
_SIGNAL_TYPE = 2         # byte 15
_FLAG_16 = 1             # byte 16
_SUB_IDX = 4             # byte 17
_SV_SLOT = 3             # byte 18
_PARAM_20 = 4            # byte 20
_PARAM_21 = 2            # byte 21
_PARAM_22 = 5            # byte 22
_CNO_DBHZ = 38           # byte 23
_METRIC_25 = 150         # u16 @25:27
_EXT_MEAS = 99999        # i32 @27:31


def _synthetic_1634() -> bytes:
    """Build a fixed 31-byte v=2 0x1634 payload with fabricated values."""
    body = (
        pack('<H', _COUNTER_MS)      # [1:3]
        + pack('<B', _AUX_COUNTER)   # [3]
        + pack('<B', _FLAG_4)        # [4]
        + pack('<B', _CONSTELLATION)  # [5]
        + pack('<B', _FLAGS_6)       # [6]
        + pack('<i', _MEAS_A)        # [7:11]
        + pack('<i', _MEAS_B)        # [11:15]
        + pack('<B', _SIGNAL_TYPE)   # [15]
        + pack('<B', _FLAG_16)       # [16]
        + pack('<B', _SUB_IDX)       # [17]
        + pack('<B', _SV_SLOT)       # [18]
        + pack('<B', 0)              # [19] reserved_19 = 0 (invariant)
        + pack('<B', _PARAM_20)      # [20]
        + pack('<B', _PARAM_21)      # [21]
        + pack('<B', _PARAM_22)      # [22]
        + pack('<B', _CNO_DBHZ)      # [23]
        + pack('<B', 0)              # [24] reserved_24 = 0 (invariant)
        + pack('<H', _METRIC_25)     # [25:27]
        + pack('<i', _EXT_MEAS)      # [27:31]
    )
    frame = diag_frame(0x1634, 2, body)
    assert len(frame) == 31
    return frame


def test_1634_decodes_synthetic_frame():
    rec = parse_0x1634(1000, _synthetic_1634())
    assert rec is not None
    assert rec.version == 2
    assert rec.counter_ms == _COUNTER_MS
    assert rec.aux_counter == _AUX_COUNTER
    assert rec.flag_4 == _FLAG_4
    assert rec.constellation == _CONSTELLATION
    assert rec.constellation_name == 'GAL'
    assert rec.flags_6 == _FLAGS_6
    assert rec.meas_a == _MEAS_A
    assert rec.meas_b == _MEAS_B
    assert rec.signal_type == _SIGNAL_TYPE
    assert rec.flag_16 == _FLAG_16
    assert rec.sub_idx == _SUB_IDX
    assert rec.sv_slot == _SV_SLOT
    assert rec.reserved_19 == 0
    assert rec.param_20 == _PARAM_20
    assert rec.param_21 == _PARAM_21
    assert rec.param_22 == _PARAM_22
    assert rec.cno_dbhz == _CNO_DBHZ
    assert rec.reserved_24 == 0
    assert rec.metric_25 == _METRIC_25
    assert rec.ext_meas == _EXT_MEAS
    assert rec.payload_size == 31
