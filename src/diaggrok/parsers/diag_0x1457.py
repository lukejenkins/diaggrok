"""0x1457 — LOG_CGPS_MC_SBAS_DEMOD_BITS_C: one SBAS L1 frame.

One record per SBAS GEO per second: the Viterbi-decoded bits the CGPS SBAS
demodulator (``mc_sbasdemod.c``) produced for one GEO. When the demodulator is
frame-synced the body is exactly one 250-bit DO-229 frame (preamble, message
type, 212-bit data field, CRC-24Q); before sync it is an unaligned bit buffer
(1..512 bits) that may contain a whole frame at a non-zero bit offset.

**Byte 0 is the SBAS PRN, not a version byte** (``version_less=True``). The
common values 0x85/0x87 differ by one bit but are PRN 133 and PRN 135 — the
two WAAS GEOs visible from the western US. Other observed byte-0 values
(0x7e/0x80/0x89/0x8a, plus 0x7f/0x81) are the PRNs 126/128/137/138/127/129 the
receiver demodulated or searched.

Layout (every record in the corpus; future firmware may change it under the
same length — a matching size does not guarantee a matching format):

  [0]      u8     sv_id        SBAS PRN (120..158) of the GEO this frame is from
  [1:5]    u32LE  rtc_ms       receiver-RTC ms at frame start (= F3 "Frame time:
                               … frameStartRTC %d"); +1000 per frame
  [5]      u8     frame_seq    per-GEO u8 frame counter (wraps)
  [6:8]    u16LE  sync_ref     0xFFFF before frame sync; afterwards a per-GEO
                               constant set at sync (re-set on re-acquisition).
                               Raw — meaning not grounded
  [8]      u8     frame_state  {2, 3} while tracking (sticky; independent of
                               preamble phase / CRC / message type); {6, 7} on
                               MDM9150 / MDM9250 acquisition records. Raw — F3 silent
  [9:21]   12 B   reserved     all zero
  [21:23]  u16LE  num_bits     250 = one aligned frame; otherwise an unaligned
                               buffer (1..512 bits; MDM9150/MDM9250 acquisition emits a
                               512-bit buffer + a short fragment)
  [23:]    u32LE[ceil(num_bits/32)]  bits, each word read MSB-first

Grounding:

* **CRC-24Q** — reading the body as u32-LE words MSB-first, every aligned
  250-bit frame carries a DO-229 preamble (0x53/0x9A/0xC6 in rotation) and the
  vast majority pass CRC-24Q (MC7455 280/280; MDM9250 ≈96-98%, the failures
  being preamble-correct frames with bit errors — the firmware logs a frame
  before its CRC gate, so ``crc_ok`` is a derived field, not an acceptance test).
  Message types are the WAAS broadcast mix (2/3/4 fast corrections, 25, 26, 28,
  63 null, 9 GEO nav, 17 almanac, 18 IGP mask, 1 PRN mask, 7, 10).
* **PRN** — MT9 decoded from ``sv_id=135`` frames places the transmitter at
  124.97°W, r=42,159 km (Galaxy 30 / WAAS PRN 135); MT17 almanacs in the same
  frames list PRN 131 @117.0°W, 133 @129.1°W, 135 @125.0°W.
* **F3** — ``mc_sbasdemod.c`` "Report Frame SV %d, [0]=%8lx … [7]=%8lx" prints
  the same eight u32 words the body carries, same SV, at the same DIAG
  timestamp: 3,606 / 3,618 records on a Wistron 81UMV91M21 (MDM9150) capture; ``rtc_ms`` ==
  "Frame time: … frameStartRTC %d" on every matched frame. No F3 argument tracks
  ``sync_ref`` or ``frame_state`` (F3 silent → exposed raw).
* **Whole corpus** (62,473 records, 104 captures, three chipset
  generations — MDM9x30 (MC7455), MDM9150 (81UMV91M21), MDM9250 (81UMV91B1,
  CarCom-G1 OBU)): 100 %
  parsed; PRN 133 / 135 aligned 99.5 %, CRC-24Q ok 95.3 % / 95.8 % of frames;
  a 0x18F5 report lists the same PRN within ±1.5 s for 99.9 %.
* **0x1458 cross-code** — Viterbi-decoding the sibling 0x1458 soft symbols
  (K=7, 171/133) reproduces these frames bit-for-bit (119/119 on the MC7455
  warm-restart capture).

The body is SBAS frame data, not a SIM/NAS payload; ``rtc_ms`` is one u32
(not a u24 counter plus a reserved byte); and bytes 6-8 / 21-23 are
``sync_ref`` / ``frame_state`` / ``num_bits``, not a signature + length +
type-tag header.

Log name: LOG_CGPS_MC_SBAS_DEMOD_BITS_C
Also known as: LOG_CGPS_MC_SBAS_DEMODULATED_BITS, LOG_GPS_SBAS_DEMODULATOR_REPORT
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from diaggrok import sbas
from diaggrok.registry import register

HEADER_LEN = 23


@dataclass
class Diag0x1457:
    """LOG_CGPS_MC_SBAS_DEMOD_BITS_C — one SBAS frame / pre-sync bit buffer."""
    log_time: int
    sv_id: int
    rtc_ms: int
    frame_seq: int
    sync_ref: int
    frame_state: int
    reserved: bytes
    num_bits: int
    body_raw: bytes
    payload_size: int
    # derived
    frame_bit_offsets: list[int] = field(default_factory=list)
    frame: dict[str, Any] | None = None

    @property
    def aligned(self) -> bool:
        """True when the body is exactly one frame (``num_bits == 250``)."""
        return self.num_bits == sbas.FRAME_BITS

    @property
    def crc_ok(self) -> bool | None:
        return None if self.frame is None else self.frame["crc_ok"]

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1457',
            'log_time': self.log_time,
            'sv_id': self.sv_id,
            'rtc_ms': self.rtc_ms,
            'frame_seq': self.frame_seq,
            'sync_ref': self.sync_ref,
            'frame_state': self.frame_state,
            'reserved': self.reserved.hex(),
            'num_bits': self.num_bits,
            'aligned': self.aligned,
            'frame_bit_offsets': list(self.frame_bit_offsets),
            'frame': self.frame,
            'body_raw': self.body_raw.hex(),
            'payload_size': self.payload_size,
        }


@register(
    0x1457,
    name="0x1457",
    primary_issue=None,
    issues=(),
    description="LOG_CGPS_MC_SBAS_DEMOD_BITS_C — one SBAS L1 frame (DO-229) per GEO per second",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. 23-B header + body = SBAS L1 frame bits as u32-LE "
        "words MSB-first, num_bits u16@21 (250 = one aligned frame). Grounded "
        "by CRC-24Q on aligned frames (MC7455 280/280, MDM9250 ~97%; failures "
        "are bit errors, the firmware logs before its CRC gate), DO-229 "
        "preamble rotation, F3 mc_sbasdemod.c 'Report Frame SV %d [0..7]' "
        "(same 8 words, 3,606/3,618 on MDM9150), and bit-exact Viterbi "
        "reproduction from sibling 0x1458. Byte 0 = SBAS PRN (MT9 GEO position "
        "124.97W for sv_id 135 = WAAS Galaxy 30; MT17 almanac 131/133/135), so "
        "the code is version-less. u32 rtc_ms@1 = F3 frameStartRTC "
        "(+1000/frame). 62,473 records / 104 captures on MDM9x30, MDM9150 and "
        "MDM9250 parse 100%. sync_ref and frame_state are F3-silent and "
        "exposed raw."
    ),
    source_url="",
    # Named header fields: sv_id, rtc_ms, frame_seq, sync_ref, frame_state,
    # reserved, num_bits + the body (bits → full DO-229 frame envelope). sync_ref
    # and frame_state are named for their observed role only (raw values).
    fields_parsed=9,
    fields_identified=9,
    version_less=True,
    field_invariants={
        "sv_id": {"range": [sbas.SBAS_PRN_MIN, sbas.SBAS_PRN_MAX]},
        # {2,3} tracking (all three chipsets); {6,7} MDM9150/MDM9250 acquisition pairs
        # (512-bit buffer + short fragment) — whole-corpus walk.
        "frame_state": {"enum": [2, 3, 6, 7]},
        "reserved": {"const": "000000000000000000000000"},
    },
)
def parse_0x1457(log_time: int, data: bytes) -> Diag0x1457 | None:
    n = len(data)
    if n < HEADER_LEN:
        return None
    if any(data[9:21]):
        return None
    num_bits = data[21] | (data[22] << 8)
    # Body is exactly ceil(num_bits/32) u32 words — a self-describing length
    # (the 55-B aligned frames are the majority).
    if num_bits == 0 or n - HEADER_LEN != ((num_bits + 31) // 32) * 4:
        return None
    body = bytes(data[HEADER_LEN:])
    bits = sbas.bits_from_u32le_words(body, num_bits)
    if num_bits == sbas.FRAME_BITS:
        offsets = [0]
    else:
        offsets = sbas.find_frames(bits)
    frame = None
    if offsets:
        o = offsets[0]
        frame = sbas.decode_frame(bits[o:o + sbas.FRAME_BITS])
    return Diag0x1457(
        log_time=log_time,
        sv_id=data[0],
        rtc_ms=int.from_bytes(data[1:5], "little"),
        frame_seq=data[5],
        sync_ref=data[6] | (data[7] << 8),
        frame_state=data[8],
        reserved=bytes(data[9:21]),
        num_bits=num_bits,
        body_raw=body,
        payload_size=n,
        frame_bit_offsets=offsets,
        frame=frame,
    )
