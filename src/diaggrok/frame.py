"""Outer frame parsing for DIAG LOG_F (opcode 0x10) packets.

Tick-rate caveat for ``log_time`` (see #N)
----------------------------------------------

The ``log_time`` field returned by :func:`parse_outer_frame` is the
INNER DIAG frame timestamp — distinct from the OUTER HDLC LOG_F /
DLF file-format ``ts64`` (the one documented at ``hdlc.py:88`` and
``dlf.py:10`` as "Qualcomm 1.25 ms ticks").

Empirically (<redacted-ref> / commit ``bc7eb8c9a``, re-confirmed in
<redacted-ref>), this inner ``log_time`` is a CHIPSET-DEPENDENT
high-frequency counter:

    SDX62 (e.g. RM520N-GL R03):   ~17.24 ns/tick (~58.08 MHz)
    SDX20 (e.g. Telit LM960):     ~19.07 ns/tick (~52.43 MHz)

The rate was derived by correlating ``log_time`` with ``gps_tow_ms``
from 0x1476 GNSS position records, and validated via capture-duration
sanity checks. Other chipsets need their own per-chipset derivation
before assuming a rate.

This is the value passed to every parser via the conventional
``parse_xyz(log_time, payload)`` signature in the live diaggpsd
streaming path. The DLF/HDLC offline-read path (``iter_log_records``
in ``dlf.py`` / ``hdlc.py``) instead passes the OUTER 1.25 ms-tick
``ts64`` under the same parameter name — a code-path-dependent
semantic that callers performing absolute-time math should be aware
of.
"""
from __future__ import annotations

from struct import calcsize, unpack_from

_OUTER_HDR_FMT = "<BH"   # pending_msgs uint8, outer_len uint16
# inner_len uint16, log_type uint16, log_time uint64 (chipset-dependent
# rate — see module docstring; NOT 1.25 ms like the outer ts64)
_INNER_HDR_FMT = "<HHQ"

_OUTER_HDR_SZ = calcsize(_OUTER_HDR_FMT)
_INNER_HDR_SZ = calcsize(_INNER_HDR_FMT)


def parse_outer_frame(
    payload: bytes, lenient: bool = False
) -> tuple[int, int, int, bytes]:
    """Parse the DIAG LOG outer frame (opcode=16 payload).

    Returns (pending_msgs, log_type, log_time, log_payload). The returned
    ``log_time`` is the INNER DIAG frame timestamp — see this module's
    docstring for the chipset-dependent tick rate, and do NOT assume the
    1.25 ms rate that applies to the OUTER HDLC LOG_F / DLF ``ts64``.

    Raises ValueError on malformed data.

    If lenient=True, allows small mismatches in declared vs actual lengths
    (needed for QMDL2-sourced data where framing adds/strips bytes).
    """
    if len(payload) < _OUTER_HDR_SZ + _INNER_HDR_SZ:
        raise ValueError(f"Frame too short: {len(payload)} bytes")

    pending_msgs, outer_len = unpack_from(_OUTER_HDR_FMT, payload)
    inner = payload[_OUTER_HDR_SZ:]
    if not lenient and len(inner) != outer_len:
        raise ValueError(
            f"outer_len mismatch: declared {outer_len}, got {len(inner)}"
        )

    inner_len, log_type, log_time = unpack_from(_INNER_HDR_FMT, inner)
    if not lenient and inner_len != len(inner):
        raise ValueError(
            f"inner_len mismatch: declared {inner_len}, got {len(inner)}"
        )

    log_payload = inner[_INNER_HDR_SZ:]
    return pending_msgs, log_type, log_time, log_payload
