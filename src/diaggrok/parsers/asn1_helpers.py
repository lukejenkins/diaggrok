# diaggrok-provenance: re
"""Shared ASN.1 / UPER decoder helpers used across LTE and NR RRC parsers.

Part of diaggrok's canonical, pycrate-free ASN.1/UPER toolkit (built on
``parsers.uper.UperReader``). When you need to decode an ASN.1/UPER structure,
use this stack — do not add an external ASN.1 dependency. Rationale + primitive
catalog: ``docs/asn1-uper-toolkit.md`` (#N).

Consolidates duplicated helpers + ENUMERATED lookup tables that were
previously copy-pasted across multiple parser modules. See #N for the
consolidation scope. Exports:

    skip_extension_additions  — UPER extension-additions block skipper
    read_open_type_length     — UPER open-type length determinant reader
                                (§11.9, fully fragmentation-aware as of #N)
    decode_plmn_identity      — PLMN-Identity decoder (LTE + NR identical)
    PlmnIdentity              — dataclass returned by decode_plmn_identity
    Q_OFFSET_DB               — 31-entry Q-OffsetRange ENUMERATED → dB table
    PCI_RANGE_VALUES          — 16-entry PhysCellIdRange ENUMERATED → count table
    Q_HYST_DB                 — 16-entry q-Hysteresis ENUMERATED → dB table
    ALLOWED_MEAS_BW_RBS       — 6-entry AllowedMeasBandwidth ENUMERATED → RB table (LTE)
    SCS_KHZ                   — 5-entry NR SubcarrierSpacing ENUMERATED → kHz table

Reference: ITU-T X.691 (UPER), 3GPP TS 36.331 / 38.331.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.parsers.uper import UperReader


@dataclass
class PlmnIdentity:
    """3GPP PLMN identity — encoding identical between LTE (TS 36.331) and NR (TS 38.331).

    The MCC field is OPTIONAL in UPER; when omitted, the decoder leaves it as ''
    (the empty string). Real-world SIB1 captures always carry MCC, but other
    contexts (e.g. MeasurementReport additional-PLMN lists, RRCConnectionReconfig
    handover PLMN lists) may omit it.
    """
    mcc: str  # 3-digit MCC string, or '' if absent
    mnc: str  # 2- or 3-digit MNC string

    def to_dict(self) -> dict[str, Any]:
        return {'mcc': self.mcc, 'mnc': self.mnc}


def read_open_type_length(r: UperReader) -> int:
    """Read an open-type length determinant (whole bytes), X.691 §11.9.

    Returns the TOTAL byte length, fully handling the fragmented (≥16384)
    encoding — the 16K/32K/48K/64K fragment loop is summed by the underlying
    :meth:`UperReader.read_length`. Open-type / OCTET-STRING contents are
    contiguous in the bitstream, so the summed length is the correct number of
    bytes to consume.

    Historical note (#N): this previously returned only ``first & 0x3F`` for
    the fragmented case (a fragment *count*, 1..4), which silently mis-sized
    any structure ≥16384 bytes — UE-Capability being the likely first trigger.
    Now delegated to the corrected reader.
    """
    return r.read_length()


def skip_extension_additions(r: UperReader) -> None:
    """Skip a UPER extension-additions block (open-type wrappers).

    Encoding per X.691 §9.3.10 / §11.5:
      1. Number of additions (normally-small-length):
            marker bit 0 → next 6 bits = num_ext (0..63)
            marker bit 1 → next 8 bits = num_ext (semi-constrained;
                           simplified form — handles the > 63 case
                           by reading 8 bits flat, which matches every
                           record in the current corpus).
      2. Bitmap of ``num_ext + 1`` bits indicating which additions
         are present.
      3. For each present addition: an open-type length-determinant
         followed by that many bytes of opaque payload (which we
         skip — extension-additions are forward-compat carriers).
    """
    marker = r.read_bits(1)
    if marker == 0:
        num_ext = r.read_bits(6)
    else:
        num_ext = r.read_bits(8)

    bitmap = r.read_bits(num_ext + 1)

    for i in range(num_ext + 1):
        if (bitmap >> (num_ext - i)) & 1:
            length = read_open_type_length(r)
            r.skip_bits(length * 8)


def decode_plmn_identity(r: UperReader) -> PlmnIdentity:
    """Decode a PLMN-Identity from a UPER bitstream.

    PLMN-Identity ::= SEQUENCE {
        mcc     MCC OPTIONAL,   -- SEQUENCE (SIZE (3)) OF MCC-MNC-Digit
        mnc     MNC             -- SEQUENCE (SIZE (2..3)) OF MCC-MNC-Digit
    }
    MCC-MNC-Digit ::= INTEGER (0..9)

    The MNC length is encoded as a constrained integer in [2, 3] — equivalent
    to read_length_determinant(2, 3) for the SEQUENCE-OF SIZE constraint per
    X.691 §11.9 (length is encoded as a constrained whole number when the
    range is small).

    Identical encoding in 3GPP TS 36.331 (LTE) and 38.331 (NR).
    """
    has_mcc = r.read_bool()
    mcc = ''
    if has_mcc:
        for _ in range(3):
            mcc += str(r.read_constrained_int(0, 9))

    mnc_len = r.read_constrained_int(2, 3)
    mnc = ''
    for _ in range(mnc_len):
        mnc += str(r.read_constrained_int(0, 9))

    return PlmnIdentity(mcc=mcc, mnc=mnc)


# Q-OffsetRange ENUMERATED → dB offset (3GPP TS 36.331 §6.3.4).
# 31 values, indexed by the ENUMERATED ordinal as encoded in UPER.
# Shared across LTE SIB3 / SIB4 / SIB5 neighbor-cell q-offset handling.
Q_OFFSET_DB: list[int] = [
    -24, -22, -20, -18, -16, -14, -12, -10, -8, -6,
    -5, -4, -3, -2, -1, 0, 1, 2, 3, 4,
    5, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24,
]

# PhysCellIdRange `range` ENUMERATED → PCI count (3GPP TS 36.331 §6.3.4).
# 16 values; the encoding repeats 504 at indices 13..15 because the spec
# defines those slots as reserved / equivalent to "all PCIs".
PCI_RANGE_VALUES: list[int] = [
    4, 8, 12, 16, 24, 32, 48, 64, 84, 96, 128, 168, 252, 504, 504, 504,
]

# q-Hysteresis ENUMERATED → dB (3GPP TS 36.331 §6.3.4).
# 16 values; non-uniform spacing — integer steps in [0, 6], then 2-dB steps
# to 24 dB. Used by SIB3 cellReselectionInfoCommon.q-Hyst.
Q_HYST_DB: list[int] = [0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24]

# AllowedMeasBandwidth ENUMERATED → RBs (3GPP TS 36.331).
# {mbw6, mbw15, mbw25, mbw50, mbw75, mbw100} → 6 LTE RB widths.
# LTE-only — NR uses a different bandwidth representation (carrierBandwidth).
ALLOWED_MEAS_BW_RBS: list[int] = [6, 15, 25, 50, 75, 100]

# NR SubcarrierSpacing ENUMERATED → kHz (3GPP TS 38.331).
# {kHz15, kHz30, kHz60, kHz120, kHz240} plus 3 spare slots not modeled here.
# NR-only — LTE has a fixed 15 kHz SCS and no equivalent enum.
SCS_KHZ: list[int] = [15, 30, 60, 120, 240]
