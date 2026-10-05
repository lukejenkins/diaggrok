# diaggrok-provenance: re
"""NR RSRP / RSRQ / SINR raw-range → dB/dBm conversions.

Per 3GPP TS 38.133, NR reports RSRP, RSRQ, and SINR as small integer ranges
that must be linearly mapped to dBm / dB. The mapping table is fixed by the
standard and shared across every log code that carries one of these values
(MeasurementReport, RRCReconfiguration measConfig, B821 RRC OTA SIB
serving-cell measurements, etc.).

Exports:

    rsrp_to_dbm(val)         — NR RSRP-Range (0..MAX_RSRP_RANGE) → dBm
    rsrq_to_db(val)          — NR RSRQ-Range (0..MAX_RSRQ_RANGE) → dB
    sinr_to_db(val)          — NR SINR-Range (0..MAX_SINR_RANGE) → dB
    MAX_RSRP_RANGE = 127     — TS 38.331 RSRP-Range ASN.1 upper bound
    MAX_RSRQ_RANGE = 127     — TS 38.331 RSRQ-Range ASN.1 upper bound
    MAX_SINR_RANGE = 127     — TS 38.331 SINR-Range ASN.1 upper bound

The LTE equivalents live in `lte_signal_levels.py` — they have different
ranges and formulas per TS 36.133.
"""
from __future__ import annotations


# ASN.1 upper bounds from 3GPP TS 38.331.
# Held alongside the conversion functions because every caller that uses
# the conversion also needs the matching read_constrained_int(0, MAX) bound.
MAX_RSRP_RANGE = 127   # RSRP-Range ::= INTEGER (0..127)
MAX_RSRQ_RANGE = 127   # RSRQ-Range ::= INTEGER (0..127)
MAX_SINR_RANGE = 127   # SINR-Range ::= INTEGER (0..127)


def rsrp_to_dbm(val: int) -> float:
    """Convert NR RSRP-Range (0..127) to dBm.

    TS 38.133 Table 10.1.6.1-1: RSRP = value - 156 (dBm).
    Range: -156 dBm (0) to -31 dBm (127), with RSRP < -156 mapping to 0
    and RSRP >= -31 mapping to 127.
    """
    return float(val - 156)


def rsrq_to_db(val: int) -> float:
    """Convert NR RSRQ-Range (0..127) to dB.

    TS 38.133 Table 10.1.11.1-1: RSRQ = (value - 87) / 2 (dB).
    Range: -43.5 dB (0) to 20 dB (127).
    """
    return (val - 87) / 2.0


def sinr_to_db(val: int) -> float:
    """Convert NR SINR-Range (0..127) to dB.

    TS 38.133 Table 10.1.16.1-1: SINR = (value - 46) / 2 (dB).
    Range: -23 dB (0) to 40 dB (127).
    """
    return (val - 46) / 2.0
