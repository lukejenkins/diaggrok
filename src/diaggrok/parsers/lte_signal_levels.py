# diaggrok-provenance: re
"""LTE RSRP / RSRQ raw-range → dB/dBm conversions.

Per 3GPP TS 36.133, LTE reports RSRP and RSRQ as small integer ranges that
must be linearly mapped to dBm / dB. The mapping table is fixed by the
standard and shared across every log code that carries an RSRP/RSRQ value
(MeasurementReport, RRCConnectionReconfig measConfig, SIB6 inter-RAT
neighbor reports, etc.).

Exports:

    rsrp_to_dbm(val)       — RSRP-Range (0..MAX_RSRP_RANGE) → dBm
    rsrq_to_db(val)        — RSRQ-Range (0..MAX_RSRQ_RANGE) → dB
    MAX_RSRP_RANGE = 97    — TS 36.331 RSRP-Range ASN.1 upper bound
    MAX_RSRQ_RANGE = 34    — TS 36.331 RSRQ-Range ASN.1 upper bound

The NR equivalents live in `nr5g_signal_levels.py` — they have different
ranges and formulas per TS 38.133.
"""
from __future__ import annotations


# ASN.1 upper bounds from 3GPP TS 36.331.
# Held alongside the conversion functions because every caller that uses
# the conversion also needs the matching read_constrained_int(0, MAX) bound.
MAX_RSRP_RANGE = 97   # RSRP-Range ::= INTEGER (0..97)
MAX_RSRQ_RANGE = 34   # RSRQ-Range ::= INTEGER (0..34)


def rsrp_to_dbm(val: int) -> float:
    """Convert RSRP-Range (0..97) to dBm.

    TS 36.133 §9.1.4: RSRP = value - 140 (dBm).
    Range: -140 dBm (0) to -44 dBm (97).
    """
    return float(val - 140)


def rsrq_to_db(val: int) -> float:
    """Convert RSRQ-Range (0..34) to dB.

    TS 36.133 §9.1.7: RSRQ = (value - 40) / 2 (dB).
    Range: -19.5 dB (0) to -3.0 dB (34).
    """
    return (val - 40) / 2.0
