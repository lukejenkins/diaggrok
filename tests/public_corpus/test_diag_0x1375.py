"""Public zero-PII fixture for 0x1375 (CGPS IPC data envelope).

Tier 1 (synthetic-only): the v7 decode of the 0x0078 sv_array can expose
per-SV GNSS measurement fields, and the parser docstring flags
gnss_tow_ms + week as GNSS absolute time -- per
public_corpus.risk_tiers.RISK_TIER this frame must be fully synthetic. This
fixture deliberately picks msg_id 0x0009 (the zero-payload heartbeat), so no
per-SV body is present at all -- only the universal 28-byte envelope/header
is exercised, avoiding any GNSS-measurement content.

Targets the fixed 28-byte header documented in diaggrok.parsers.diag_1375:
16B IPC envelope + 12B sub-header, validated cross-generation. This code is
version_less (byte 0 is the low byte of msg_id, a dispatcher, not a version)
-- the parse-gates are the marker==0x0101 @[10:12] and payload_len==len-28
@[24:28] invariants, both enforced below.
"""
from public_corpus.support.synthetic import pack
from diaggrok.parsers.diag_0x1375 import parse_0x1375

# Fabricated envelope values (not from any real capture).
_MSG_ID = 0x0009        # u16 @ [0:2] -- the zero-payload periodic heartbeat
_STREAM_ID = 5          # u32 @ [4:8]
_STREAM_ID_2 = 5        # u16 @ [8:10] -- msg_id 0x0009 always has substream_id == stream_id
_SEQ = 100              # u32 @ [12:16]
_STREAM_MSG_SEQ = 50    # u32 @ [16:20]
_GLOBAL_SEQ = 1000      # u32 @ [20:24]


def _synthetic_1375() -> bytes:
    """Build a 28-byte 0x1375 envelope+sub-header with no message payload.

    Offsets transcribed from the parser's own docstring/comments in
    diag_0x1375.py, not from any capture:

      [0:2]   u16  msg_id          = 0x0009 (fixed heartbeat dispatch id)
      [2:4]   u16  msg_flags       = 0 (fabricated)
      [4:8]   u32  stream_id       = 5 (fabricated)
      [8:10]  u16  substream_id    = 5 (== stream_id, matches 0x0009's shape)
      [10:12] u16  marker          = 0x0101 (universal INVARIANT -- the
                                     parser rejects any other value)
      [12:16] u32  seq             = 100 (fabricated coarse counter)
      [16:20] u32  stream_msg_seq  = 50 (fabricated fine counter)
      [20:24] u32  global_seq      = 1000 (fabricated global counter)
      [24:28] u32  payload_len     = 0 == len(record) - 28 (INVARIANT --
                                     the parser rejects any mismatch)
      [28:]   no payload (msg_id 0x0009 has payload_len == 0 in the corpus)
    """
    body = (
        pack('<H', _MSG_ID)
        + pack('<H', 0)                  # msg_flags
        + pack('<I', _STREAM_ID)
        + pack('<H', _STREAM_ID_2)       # substream_id
        + pack('<H', 0x0101)             # marker invariant
        + pack('<I', _SEQ)
        + pack('<I', _STREAM_MSG_SEQ)
        + pack('<I', _GLOBAL_SEQ)
        + pack('<I', 0)                  # payload_len == 0
    )
    assert len(body) == 28
    return body


def test_1375_decodes_synthetic_heartbeat_frame():
    rec = parse_0x1375(1000, _synthetic_1375())
    assert rec is not None
    assert rec.msg_id == 0x0009
    assert rec.marker_0101_ok is True
    assert rec.payload_len_ok is True
    assert rec.has_subheader is True
    assert rec.stream_id == 5
    assert rec.substream_id == 5
    assert rec.seq == 100
    assert rec.stream_msg_seq == 50
    assert rec.global_seq == 1000
    assert rec.payload_len == 0
    assert rec.payload == b""
    assert rec.msg_kind == "opt_fixed"
    assert rec.sv_report is None
