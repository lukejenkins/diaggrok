"""0x1458 — LOG_CGPS_MC_SBAS_DEMOD_SOFT_SYMBOLS_C: SBAS soft symbols.

One record per SBAS GEO per second: the soft symbols the CGPS SBAS demodulator
(``mc_sbasdemod.c``) fed its Viterbi decoder — carrier-locked (Costas) I-channel
correlator outputs, one per 2 ms rate-1/2 symbol, 500 per second (F3 "SBAS SV
%d demod start: C/No %d, num IQ %d …" prints ``num IQ 500``). Sibling 0x1457
carries the frames these symbols decode to.

**Byte 0 is the SBAS PRN, not a version byte** (``version_less=True``) — see
0x1457. The 0x85 + 0x87 values seen from one modem are two GEOs, PRN 133 and
PRN 135, not two log versions.

Layout (every record in the corpus; future firmware may change it under the
same length — a matching size does not guarantee a matching format):

  [0]      u8     sv_id        SBAS PRN (120..158)
  [1:5]    u32LE  rtc_ms       receiver-RTC ms of the block (= F3 "demod start:
                               … Peak RTC %d"); +1000 per block
  [5]      u8     block_seq    per-GEO u8 counter; advances by the elapsed
                               seconds between blocks (wraps)
  [6:14]   8 B    aux_raw      zero on every MDM9150 / MDM9250 record; on MC7455 only
                               during acquisition (a recurring constant
                               a868ae02…, or a small u16 at [8:10]). Raw.
  [14]     u8     block_type   {1, 3, 5} (1 dominant). Raw.
  [15:25]  10 B   reserved     all zero
  [25:27]  u16LE  num_symbols  (= F3 "num IQ %d") 500 = one second; fewer
                               during acquisition
  [27:]    int8[num_symbols]   soft symbols — sign is the hard decision
                               (negative ⇒ symbol 1), magnitude the confidence;
                               saturates at +127 / -128

Grounding:

* **Code syndrome** — the hard decisions satisfy the parity-check equation of
  the DO-229 rate-1/2 K=7 code (171/133 octal, current input at the MSB) at
  ~100% on locked records (MC7455 warm-restart capture: 1.000); noise-only
  records (no carrier lock) sit at ~0.5. ``code_syndrome_agreement`` exposes it.
* **Viterbi → 0x1457** — soft-decision Viterbi over consecutive blocks yields
  CRC-24Q-valid SBAS frames, 119/119 bit-identical to the co-emitted 0x1457
  frames (constant +128 ms between the 0x1457 time-tag and the frame start
  on the 0x1458 symbol timeline).
* **F3** (5 captures of a Wistron 81UMV91M21 (MDM9150); 13,098 / 13,098 blocks paired with
  ``mc_sbasdemod.c`` "SBAS SV %d demod start: C/No %d, num IQ %d, Peak RTC %d"):
  ``rtc_ms`` == Peak RTC and ``num_symbols`` == num IQ on every block. The
  soft-symbol amplitude tracks the printed C/No monotonically — median
  ``symbols_mean_abs`` 79 @ 28 dB-Hz → 123 @ 45 dB-Hz (saturating at the ±127
  rail), Pearson r = 0.908 — and ``code_syndrome_agreement`` reaches 1.0 from
  ~34 dB-Hz. So ``symbols_mean_abs`` is a saturating C/N0 proxy.
* **Whole corpus** (64,835 records, 104 captures,
  three chipset generations — MDM9x30, MDM9150, MDM9250): 100 % parsed, 0
  invariant violations.

The body bytes are two's-complement, not offset binary: read as offset
binary, +127 and -128 (the two saturation rails) look like adjacent levels at
a "zero crossing gap" and the body resembles quantized IF samples. Records
from a receiver without carrier lock (syndrome ≈0.5) look like white noise.
Byte 4 (values {0x00, 0x05}) is the top byte of the u32 time-tag (receiver
time past 2^24 ms), not a state flag.

Log name: LOG_CGPS_MC_SBAS_DEMOD_SOFT_SYMBOLS_C
Also known as: LOG_GPS_EXTERN_COARSE_POSITION_INJECT_START
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok import sbas
from diaggrok.registry import register

HEADER_LEN = 27
SATURATED_ABS = 127


def soft_symbols(body: bytes) -> list[int]:
    """The body as signed int8 soft symbols (positive ⇒ symbol 0)."""
    return [b - 256 if b > 127 else b for b in body]


@dataclass
class Diag0x1458:
    """LOG_CGPS_MC_SBAS_DEMOD_SOFT_SYMBOLS_C — one block of SBAS soft symbols."""
    log_time: int
    sv_id: int
    rtc_ms: int
    block_seq: int
    aux_raw: bytes
    block_type: int
    reserved: bytes
    num_symbols: int
    symbols_mean_abs: float
    symbols_saturated_fraction: float
    symbols_negative_fraction: float
    code_syndrome_agreement: float
    code_symbol_phase: int
    body_raw: bytes
    payload_size: int

    @property
    def symbols(self) -> list[int]:
        return soft_symbols(self.body_raw)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1458',
            'log_time': self.log_time,
            'sv_id': self.sv_id,
            'rtc_ms': self.rtc_ms,
            'block_seq': self.block_seq,
            'aux_raw': self.aux_raw.hex(),
            'block_type': self.block_type,
            'reserved': self.reserved.hex(),
            'num_symbols': self.num_symbols,
            'symbols_mean_abs': round(self.symbols_mean_abs, 4),
            'symbols_saturated_fraction': round(self.symbols_saturated_fraction, 4),
            'symbols_negative_fraction': round(self.symbols_negative_fraction, 4),
            'code_syndrome_agreement': round(self.code_syndrome_agreement, 4),
            'code_symbol_phase': self.code_symbol_phase,
            'body_raw': self.body_raw.hex(),
            'payload_size': self.payload_size,
        }


@register(
    0x1458,
    name="0x1458",
    description="LOG_CGPS_MC_SBAS_DEMOD_SOFT_SYMBOLS_C — int8 SBAS soft symbols (500/s, rate-1/2 K=7) per GEO",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. 27-B header + body = int8 soft symbols (sign = hard "
        "decision) of the DO-229 rate-1/2 K=7 (171/133, MSB = current input) "
        "code — hard decisions satisfy the code syndrome at ~1.0 on locked "
        "records; soft Viterbi over consecutive blocks yields CRC-24Q-valid "
        "frames bit-identical to sibling 0x1457 (119/119). F3 mc_sbasdemod.c "
        "'demod start: … num IQ %d, Peak RTC %d' matches num_symbols and "
        "rtc_ms on 13,098/13,098 MDM9150 blocks; symbol amplitude tracks the "
        "printed C/No (r = 0.908). Byte 0 = SBAS PRN (version-less, see "
        "0x1457); rtc_ms is a u32 at [1:5]. 64,835 records / 104 captures on "
        "MDM9x30, MDM9150 and MDM9250 parse 100%. aux_raw and block_type are "
        "unexplained and exposed raw."
    ),
    source_url="",
    # Named: sv_id, rtc_ms, block_seq, aux_raw (raw, unexplained), block_type,
    # reserved, num_symbols, soft-symbol body. aux_raw is an honest placeholder.
    fields_parsed=8,
    fields_identified=7,
    issues=(),
    primary_issue=None,
    version_less=True,
    field_invariants={
        "sv_id": {"range": [sbas.SBAS_PRN_MIN, sbas.SBAS_PRN_MAX]},
        "block_type": {"enum": [1, 3, 5]},
        "reserved": {"const": "00000000000000000000"},
    },
)
def parse_0x1458(log_time: int, data: bytes) -> Diag0x1458 | None:
    n = len(data)
    if n < HEADER_LEN:
        return None
    if any(data[15:25]):
        return None
    num_symbols = data[25] | (data[26] << 8)
    if num_symbols == 0 or num_symbols + HEADER_LEN != n:
        return None
    body = bytes(data[HEADER_LEN:])
    sy = soft_symbols(body)
    hard = [1 if s < 0 else 0 for s in sy]
    syn, phase = sbas.syndrome_agreement(hard)
    return Diag0x1458(
        log_time=log_time,
        sv_id=data[0],
        rtc_ms=int.from_bytes(data[1:5], "little"),
        block_seq=data[5],
        aux_raw=bytes(data[6:14]),
        block_type=data[14],
        reserved=bytes(data[15:25]),
        num_symbols=num_symbols,
        symbols_mean_abs=sum(abs(s) for s in sy) / num_symbols,
        symbols_saturated_fraction=sum(1 for s in sy if s >= SATURATED_ABS or s <= -128) / num_symbols,
        symbols_negative_fraction=sum(hard) / num_symbols,
        code_syndrome_agreement=syn,
        code_symbol_phase=phase,
        body_raw=body,
        payload_size=n,
    )
