# diaggrok-provenance: re
"""SBAS L1 message helpers (RTCA DO-229 / ICAO Annex 10) — pure, zero-dependency.

Backs the two CGPS SBAS demodulator logs:

* ``0x1457 LOG_CGPS_MC_SBAS_DEMOD_BITS_C`` carries the Viterbi-decoded bits of
  one SBAS frame (or an unaligned pre-sync bit buffer) packed into little-endian
  u32 words, read MSB-first;
* ``0x1458 LOG_CGPS_MC_SBAS_DEMOD_SOFT_SYMBOLS_C`` carries the int8 soft symbols
  (500 symbols/s, rate-1/2 K=7) those bits were decoded from.

Everything here is a public interface fact of the SBAS L1 signal-in-space: the
250-bit frame (8-bit preamble cycling 0x53/0x9A/0xC6, 6-bit message type,
212-bit data field, 24-bit CRC-24Q), the rate-1/2 constraint-length-7
convolutional code with generators 171/133 (octal, current input at the MSB),
and the per-message-type field tables. Nothing is derived from a third-party
SBAS decoder, keeping diaggrok's Apache-2.0 firewall intact.

Only the message types that carry an identity/geometry ground truth or dominate
the corpus are field-decoded (1, 2-5, 7, 9, 17, 18, 26); every other type is
named and its 212-bit data field is exposed raw.
"""
from __future__ import annotations

from typing import Any, Iterable, Sequence

FRAME_BITS = 250
DATA_BITS = 212
PREAMBLES = (0x53, 0x9A, 0xC6)

#: DO-229 message-type names (L1).
MESSAGE_TYPE_NAMES: dict[int, str] = {
    0: "Do not use (test mode)",
    1: "PRN mask",
    2: "Fast corrections",
    3: "Fast corrections",
    4: "Fast corrections",
    5: "Fast corrections",
    6: "Integrity information",
    7: "Fast correction degradation factor",
    9: "GEO navigation message",
    10: "Degradation parameters",
    12: "SBAS network time / UTC offset",
    17: "GEO satellite almanacs",
    18: "Ionospheric grid point mask",
    24: "Mixed fast / long-term corrections",
    25: "Long-term satellite error corrections",
    26: "Ionospheric delay corrections",
    27: "SBAS service message",
    28: "Clock-ephemeris covariance matrix",
    62: "Internal test message",
    63: "Null message",
}

#: SBAS PRN range (DO-229 / IS-GPS-200 PRN assignment for SBAS GEOs).
SBAS_PRN_MIN = 120
SBAS_PRN_MAX = 158

_CRC24Q_POLY = 0x1864CFB


def crc24q(bits: Sequence[int]) -> int:
    """CRC-24Q over a sequence of 0/1 bits, MSB-first (DO-229 frame CRC)."""
    crc = 0
    for b in bits:
        crc ^= (b & 1) << 23
        crc <<= 1
        if crc & 0x1000000:
            crc ^= _CRC24Q_POLY
    return crc & 0xFFFFFF


def bits_from_u32le_words(body: bytes, nbits: int) -> list[int]:
    """Unpack ``nbits`` bits from ``body`` stored as little-endian u32 words,
    each word read MSB-first — the 0x1457 body layout (F3
    ``mc_sbasdemod.c`` "Report Frame SV %d, [0]=%8lx … [7]=%8lx" prints the
    same eight words)."""
    out: list[int] = []
    for i in range(0, len(body) - 3, 4):
        w = int.from_bytes(body[i:i + 4], "little")
        for k in range(31, -1, -1):
            out.append((w >> k) & 1)
            if len(out) == nbits:
                return out
    return out


def bits_to_int(bits: Sequence[int]) -> int:
    v = 0
    for b in bits:
        v = (v << 1) | (b & 1)
    return v


def _signed(v: int, n: int) -> int:
    return v - (1 << n) if v >> (n - 1) else v


class _Reader:
    """MSB-first bit reader over a 0/1 sequence."""

    def __init__(self, bits: Sequence[int], pos: int = 0):
        self.bits = bits
        self.pos = pos

    def u(self, n: int) -> int:
        v = bits_to_int(self.bits[self.pos:self.pos + n])
        self.pos += n
        return v

    def s(self, n: int) -> int:
        return _signed(self.u(n), n)


def frame_check(bits: Sequence[int]) -> tuple[int, int, int, bool]:
    """``(preamble, message_type, crc, crc_ok)`` for a 250-bit frame."""
    if len(bits) < FRAME_BITS:
        raise ValueError(f"need {FRAME_BITS} bits, got {len(bits)}")
    crc = bits_to_int(bits[226:250])
    return (bits_to_int(bits[0:8]), bits_to_int(bits[8:14]), crc,
            crc24q(bits[0:226]) == crc)


def find_frames(bits: Sequence[int]) -> list[int]:
    """Bit offsets of every CRC-valid 250-bit frame (preamble in the canonical
    set) inside an arbitrary bit buffer — the unaligned pre-sync 0x1457
    records carry 0..1 whole frames at a non-zero offset."""
    hits = []
    for off in range(0, len(bits) - FRAME_BITS + 1):
        if bits_to_int(bits[off:off + 8]) not in PREAMBLES:
            continue
        if frame_check(bits[off:off + FRAME_BITS])[3]:
            hits.append(off)
    return hits


# --- per-message-type field decoders (data field = bits 14..225) -----------

def _mt1(r: _Reader) -> dict[str, Any]:
    mask = [i + 1 for i in range(210) if r.u(1)]
    return {"prn_mask_slots": mask, "iodp": r.u(2)}


def _mt2_5(r: _Reader) -> dict[str, Any]:
    iodf = r.u(2)
    iodp = r.u(2)
    fc = [r.s(12) * 0.125 for _ in range(13)]
    udrei = [r.u(4) for _ in range(13)]
    return {"iodf": iodf, "iodp": iodp, "fast_corrections_m": fc, "udrei": udrei}


def _mt7(r: _Reader) -> dict[str, Any]:
    return {"t_lat_s": r.u(4), "iodp": r.u(2), "spare": r.u(2),
            "ai_indicators": [r.u(4) for _ in range(51)]}


def _mt9(r: _Reader) -> dict[str, Any]:
    out: dict[str, Any] = {"reserved": r.u(8), "t0_s": r.u(13) * 16, "ura": r.u(4)}
    out["x_m"] = r.s(30) * 0.08
    out["y_m"] = r.s(30) * 0.08
    out["z_m"] = r.s(25) * 0.4
    out["xdot_mps"] = r.s(17) * 0.000625
    out["ydot_mps"] = r.s(17) * 0.000625
    out["zdot_mps"] = r.s(18) * 0.004
    out["xddot_mps2"] = r.s(10) * 0.0000125
    out["yddot_mps2"] = r.s(10) * 0.0000125
    out["zddot_mps2"] = r.s(10) * 0.0000625
    out["agf0_s"] = r.s(12) * 2.0 ** -31
    out["agf1_sps"] = r.s(8) * 2.0 ** -40
    return out


def _mt17(r: _Reader) -> dict[str, Any]:
    alm = []
    for _ in range(3):
        entry = {
            "data_id": r.u(2), "prn": r.u(8), "health_status": r.u(8),
            "x_m": r.s(15) * 2600, "y_m": r.s(15) * 2600, "z_m": r.s(9) * 26000,
            "xdot_mps": r.s(3) * 10, "ydot_mps": r.s(3) * 10, "zdot_mps": r.s(4) * 60,
        }
        if entry["prn"]:
            alm.append(entry)
    return {"almanacs": alm, "t0_s": r.u(11) * 64}


def _mt18(r: _Reader) -> dict[str, Any]:
    nb = r.u(4)
    band = r.u(4)
    iodi = r.u(2)
    mask = [i for i in range(201) if r.u(1)]
    return {"num_bands": nb, "band": band, "iodi": iodi, "igp_mask_bits": mask}


def _mt26(r: _Reader) -> dict[str, Any]:
    band = r.u(4)
    block = r.u(4)
    igps = []
    for _ in range(15):
        igps.append({"vertical_delay_m": r.u(9) * 0.125, "givei": r.u(4)})
    return {"band": band, "block_id": block, "igps": igps, "iodi": r.u(2)}


_DECODERS = {1: _mt1, 2: _mt2_5, 3: _mt2_5, 4: _mt2_5, 5: _mt2_5,
             7: _mt7, 9: _mt9, 17: _mt17, 18: _mt18, 26: _mt26}


def decode_frame(bits: Sequence[int]) -> dict[str, Any]:
    """Decode one 250-bit SBAS frame into a JSON-friendly dict.

    Always returns the frame envelope (preamble, message type + DO-229 name,
    CRC, ``crc_ok``) and the 212-bit data field as hex (54 hex digits: the 212
    bits MSB-first, left-aligned into 216). Field-level decode (``fields``) is
    attempted only when ``crc_ok`` — a failed frame's payload is untrustworthy.
    """
    pre, mt, crc, ok = frame_check(bits)
    data = bits_to_int(bits[14:226]) << 4          # pad 212 -> 216 bits
    out: dict[str, Any] = {
        "preamble": pre,
        "preamble_ok": pre in PREAMBLES,
        "message_type": mt,
        "message_type_name": MESSAGE_TYPE_NAMES.get(mt, "unassigned"),
        "crc": crc,
        "crc_ok": ok,
        "data_hex": f"{data:054x}",
    }
    if ok and mt in _DECODERS:
        out["fields"] = _DECODERS[mt](_Reader(bits, 14))
    return out


# --- rate-1/2 K=7 convolutional code (171/133 octal, MSB = current input) ---

#: Generators in shift-register form (newest input bit at bit 0): DO-229's
#: 171/133 octal put the CURRENT input at the MSB, i.e. bit-reverse to
#: 0o117/0o155 here. (Using 171/133 with newest-at-bit-0 is a DIFFERENT, still
#: self-consistent code: an encoder/decoder pair sharing that convention
#: round-trips perfectly yet never matches the air interface.)
G1_REG = 0o117
G2_REG = 0o155


def _parity(x: int) -> int:
    return bin(x).count("1") & 1


def conv_encode(bits: Iterable[int], state: int = 0) -> list[int]:
    """Encode bits into rate-1/2 symbols ``[g1, g2, g1, g2, …]``."""
    out: list[int] = []
    for b in bits:
        state = ((state << 1) | (b & 1)) & 0x7F
        out.append(_parity(state & G1_REG))
        out.append(_parity(state & G2_REG))
    return out


def syndrome_agreement(hard_symbols: Sequence[int]) -> tuple[float, int]:
    """Parity-check agreement of a hard-symbol stream with the K=7 code.

    For a valid codeword ``G2(D)·c1 ⊕ G1(D)·c2 = 0`` at every step, so the
    fraction of zero syndrome bits is ≈1.0 for a genuine (low-error) symbol
    stream and ≈0.5 for noise. Tried at both symbol-pair phases; returns
    ``(best_fraction, phase)``. Needs ≥ 16 symbols, else ``(0.0, 0)``.
    """
    best = (0.0, 0)
    for phase in (0, 1):
        x = hard_symbols[phase:]
        c1, c2 = x[0::2], x[1::2]
        n = min(len(c1), len(c2))
        if n < 8:
            continue
        zeros = 0
        for i in range(7, n):
            s = 0
            for k in range(7):
                if (G2_REG >> k) & 1:
                    s ^= c1[i - k]
                if (G1_REG >> k) & 1:
                    s ^= c2[i - k]
            zeros += s == 0
        frac = zeros / (n - 7)
        if frac > best[0]:
            best = (frac, phase)
    return best


def viterbi_decode(soft: Sequence[float]) -> list[int]:
    """Soft-decision Viterbi decode of rate-1/2 symbols (positive ⇒ symbol 0,
    the 0x1458 int8 sign convention). Start state unknown; full traceback."""
    nb = len(soft) // 2
    trans = []
    for s in range(64):
        for b in (0, 1):
            reg = ((s << 1) | b) & 0x7F
            trans.append((s, ((s << 1) | b) & 63, b,
                          1 - 2 * _parity(reg & G1_REG), 1 - 2 * _parity(reg & G2_REG)))
    pm = [0.0] * 64
    hist: list[list[tuple[int, int]]] = []
    for i in range(nb):
        a, c = soft[2 * i], soft[2 * i + 1]
        new = [float("-inf")] * 64
        back: list[tuple[int, int]] = [(0, 0)] * 64
        for s, ns, b, e1, e2 in trans:
            m = pm[s] + a * e1 + c * e2
            if m > new[ns]:
                new[ns] = m
                back[ns] = (s, b)
        top = max(new)
        pm = [v - top for v in new]
        hist.append(back)
    s = max(range(64), key=lambda k: pm[k])
    out = [0] * nb
    for i in range(nb - 1, -1, -1):
        prev, b = hist[i][s]
        out[i] = b
        s = prev
    return out
