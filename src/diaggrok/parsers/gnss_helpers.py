# diaggrok-provenance: re
"""Shared utility helpers for Qualcomm DIAG GNSS parsers.

Non-ASN.1 — this is the home for parser-side utilities that are common to
multiple GNSS log codes (GPS, GLONASS, Galileo, BeiDou, OEMDRE measurement
reports, position fixes, SV polynomials, etc.) but specific to the C-struct
encoding used by DIAG GNSS payloads. Compare with `asn1_helpers.py`, which
serves the same purpose for the UPER-encoded LTE/NR RRC parsers.

Clean-room note: the helper below is generic ``struct`` plumbing, derived from
the Python standard library's documented `struct` semantics — no external prior
art. The *struct shapes* (formats and field name lists) passed in by individual
GNSS parsers carry their own provenance, recorded per-parser in each module's
`source_detail=` field; that provenance does not flow through this helper.
"""
from __future__ import annotations

from struct import unpack_from
from typing import Any


def unpack_dict(fmt: str, field_names: list[str], data: bytes, offset: int = 0) -> dict[str, Any]:
    """Decode a packed C-struct into a ``{field_name: value}`` mapping.

    ``fmt`` is a standard-library ``struct`` format string; ``field_names``
    labels each unpacked value positionally. Reads ``calcsize(fmt)`` bytes from
    ``data`` starting at ``offset``.
    """
    values = unpack_from(fmt, data, offset)
    return {name: value for name, value in zip(field_names, values)}
