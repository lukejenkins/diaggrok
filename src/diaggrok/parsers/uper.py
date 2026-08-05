# diaggrok-provenance: re
"""diaggrok's canonical from-scratch UPER bit reader — NO pycrate.

This is the project's hand-written ITU-T X.691 Unaligned Packed Encoding
Rules decoder. It is the **canonical** facility for decoding ASN.1 / UPER
structures in 3GPP RRC (TS 36.331 / 38.331) and NAS messages: when you need
to walk a UPER bitstream, use this reader and `asn1_helpers` — do **not**
reach for pycrate or any external ASN.1 library. The no-pycrate policy is
deliberate (headless, dependency-light, auditable); see
``docs/asn1-uper-toolkit.md`` for the rationale and the primitive catalog.

It powers from-scratch decoders for LTE SIB1/3/4/5/6/7/8/16, LTE + NR RRC
Reconfiguration, NR SIB1, and LTE + NR MeasurementReport, and is being
extended (#N) with the primitives UE-Capability / Supported-CA-Combos
decoding (#N, #N, #N, #N, #N) needs:

  * large-range constrained INTEGER (range > 64K, X.691 §11.5.7.4)
  * semi-constrained / unconstrained INTEGER (§11.6 / §11.4)
  * variable-length BIT STRING (§15)
  * fragmented length determinants (§11.9, the 16K/32K/48K/64K loop)

Reference: ITU-T X.691 (Packed Encoding Rules).
"""
from __future__ import annotations

from typing import Iterator

# X.691 §11.9: a length determinant with a constrained SIZE range that fits in
# 64K is encoded as a constrained whole number; a larger or unbounded range uses
# the fragmented form (§11.9.3.8). This threshold governs ONLY that length-form
# decision in read_length / iter_length_fragments — it is NOT used for value
# integers (a *constrained* INTEGER in UPER is always min-bits, any range; see
# read_constrained_int and #N). 65536 == 1 << 16.
_LARGE_RANGE_THRESHOLD = 1 << 16

# X.691 §11.9.3.8: the fragmentation unit. Lengths ≥ 16384 are emitted as one
# or more fragments of ``k * 16384`` items (k ∈ 1..4) followed by a final
# non-fragmented length determinant.
_FRAG_UNIT = 16 * 1024  # 16384


class UperReader:
    """Unaligned PER (X.691) bit reader.

    Reads individual bits and multi-bit fields MSB-first from a byte buffer.
    Beyond the minimal SIB-decoding primitives it started with, it now covers
    the integer / length / bit-string forms UE-Capability decoding exercises.

    Reference: ITU-T X.691 (Packed Encoding Rules).
    """

    def __init__(self, data: bytes):
        self.data = data
        self.bit_pos = 0

    # -- core bit access ---------------------------------------------------

    def read_bits(self, n: int) -> int:
        """Read n bits as an unsigned integer (MSB first)."""
        val = 0
        for _ in range(n):
            byte_idx = self.bit_pos // 8
            bit_idx = 7 - (self.bit_pos % 8)
            if byte_idx < len(self.data):
                val = (val << 1) | ((self.data[byte_idx] >> bit_idx) & 1)
            else:
                val = val << 1
            self.bit_pos += 1
        return val

    def read_bool(self) -> bool:
        return self.read_bits(1) == 1

    def skip_bits(self, n: int):
        self.bit_pos += n

    # -- ENUMERATED / CHOICE ----------------------------------------------

    def read_enum(self, n_values: int) -> int:
        """Read a constrained ENUMERATED (0..n_values-1)."""
        if n_values <= 1:
            return 0
        bits_needed = (n_values - 1).bit_length()
        return self.read_bits(bits_needed)

    def read_choice(self, n_alternatives: int) -> int:
        """Read a CHOICE index (0..n_alternatives-1)."""
        return self.read_enum(n_alternatives)

    # -- INTEGER forms -----------------------------------------------------

    def read_constrained_int(self, lo: int, hi: int) -> int:
        """Read a constrained whole number (lo..hi), X.691 §11.5.7.1.

        In the UNALIGNED variant (UPER) a constrained whole number is ALWAYS a
        bit-field of the minimum number of bits needed to represent the range —
        ``ceil(log2(hi - lo + 1))`` bits — for ANY range, however large
        (§11.5.7.1). There is NO octet / length-prefixed form for a *constrained*
        integer in UPER; the octet forms of §11.5.7.2-4 apply only to the ALIGNED
        variant (APER). The length-prefixed forms this reader does use are for
        *semi-constrained* (§11.6, :meth:`read_semi_constrained_int`) and
        *unconstrained* (§11.4, :meth:`read_unconstrained_int`) integers, which
        genuinely lack a fixed bound.

        History (#N): this previously switched to an APER-style
        length+minimum-octet form once the range exceeded 64K, which silently
        mis-decoded every large-range constrained field — NR/EUTRA ARFCNs
        (0..3279165 → 22 bits; 0..262143 → 18 bits) and the LTE SIB16
        ``timeInfoUTC`` (0..549755813887 → 40 bits). Empirically pinned against
        pycrate: at the correct offset, ``read_bits(22)`` recovers the exact
        NR-ARFCN while the octet form yields garbage. Now correct: always
        min-bits.
        """
        range_val = hi - lo
        if range_val <= 0:
            return lo
        return lo + self.read_bits(range_val.bit_length())

    def read_semi_constrained_int(self, lo: int) -> int:
        """Read a semi-constrained whole number (lower bound only), §11.6.

        Encoded as a length determinant (octet count) followed by the unsigned
        offset ``value - lo`` in that many octets.
        """
        n_octets = self.read_length()
        return lo + self.read_bits(n_octets * 8)

    def read_unconstrained_int(self) -> int:
        """Read an unconstrained whole number, X.691 §11.4 / §10.8.

        Encoded as a length determinant (octet count) followed by a
        two's-complement signed integer in that many octets.
        """
        n_octets = self.read_length()
        if n_octets == 0:
            return 0
        raw = self.read_bits(n_octets * 8)
        sign_bit = 1 << (n_octets * 8 - 1)
        if raw & sign_bit:
            raw -= 1 << (n_octets * 8)
        return raw

    # -- length determinants (X.691 §11.9) ---------------------------------

    def _read_length_chunk(self) -> tuple[int, bool]:
        """Read one length-determinant chunk.

        Returns ``(count, is_fragment)`` where ``is_fragment`` is True when
        more fragments follow (the 16K-multiple form). The three encodings:

          * first byte < 128            → ``first`` (0..127), final
          * first byte 128..191         → 14-bit ``((first & 0x3F) << 8) | nxt``
                                          (128..16383), final
          * first byte ≥ 192            → ``(first & 0x3F) * 16384`` items,
                                          NOT final — more fragments follow
        """
        first = self.read_bits(8)
        if first < 0x80:
            return first, False
        if first < 0xC0:
            second = self.read_bits(8)
            return ((first & 0x3F) << 8) | second, False
        return (first & 0x3F) * _FRAG_UNIT, True

    def iter_length_fragments(self, lo: int | None = None,
                              hi: int | None = None) -> Iterator[int]:
        """Yield each fragment's item count for a length determinant.

        Use this for SEQUENCE OF / SET OF with a large or unconstrained bound,
        where the caller must decode that many variable-size elements between
        successive length reads (X.691 §11.9 fragmentation interleaves the
        element encodings with the fragment headers). For a constrained range
        that fits in 64K the whole length is one chunk and a single value is
        yielded.

        ``lo``/``hi`` select the constrained form when both are supplied and
        the range fits in 64K (matching ``read_length_determinant``).
        """
        if lo is not None and hi is not None and (hi - lo) < _LARGE_RANGE_THRESHOLD:
            yield self.read_constrained_int(lo, hi)
            return
        while True:
            count, is_fragment = self._read_length_chunk()
            yield count
            if not is_fragment:
                return

    def read_length(self, lo: int | None = None, hi: int | None = None) -> int:
        """Read a length determinant, returning the TOTAL item count.

        Correct for OCTET STRING / BIT STRING / open-type byte (or bit) counts,
        where the items are contiguous and the total is simply the sum of the
        fragments (X.691 §11.9). For SEQUENCE OF with fragmentation, use
        :meth:`iter_length_fragments` instead so element decoding can be
        interleaved with the fragment headers.

        This is the corrected replacement for the old "first-fragment hint
        only" behavior that silently mis-sized fragmented (≥16384) structures.
        """
        if lo is not None and hi is not None and (hi - lo) < _LARGE_RANGE_THRESHOLD:
            return self.read_constrained_int(lo, hi)
        return sum(self.iter_length_fragments())

    def read_length_determinant(self, lo: int, hi: int) -> int:
        """Read a constrained length determinant (backward-compatible alias).

        Retained for the existing SIB / Reconfig parsers that always pass a
        small ``(lo, hi)`` SIZE constraint; delegates to :meth:`read_length`.
        """
        return self.read_length(lo, hi)

    # -- BIT STRING (X.691 §15) -------------------------------------------

    def read_bitstring(self, nbits: int) -> int:
        """Read a fixed-width BIT STRING of ``nbits`` bits as an integer.

        The bits are returned MSB-first packed into an int; the caller already
        knows the width. For a SIZE-constrained range, read the length with
        :meth:`read_length_determinant` (or :meth:`read_constrained_int`)
        first, then call this with the decoded width.
        """
        return self.read_bits(nbits)

    def read_bitstring_unconstrained(self) -> tuple[int, int]:
        """Read a variable-length (unconstrained-size) BIT STRING, §15.11.

        Encoded as a length determinant *in bits* followed by that many bits.
        Returns ``(value, nbits)`` — the integer value (MSB-first) and its bit
        width, since a leading-zero bit string is otherwise ambiguous.
        """
        nbits = self.read_length()
        return self.read_bits(nbits), nbits
