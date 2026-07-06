# diaggrok-provenance: re
"""Flat DLF iterator + canonical DIAG-stream format dispatcher.

diaggrok already provides :mod:`diaggrok.hdlc` for raw HDLC byte streams
(0x7E-delimited, CRC-terminated, typically produced by ``diaggulp``).
Many committed captures, however, use the flat DLF layout (as written by
black-box offline capture tools) where each record is already unframed:

    u16 rec_len        total record length incl. header (>= 12)
    u16 log_code
    u64 ts64           Qualcomm 1.25 ms ticks — OUTER file-format
                       timestamp; do NOT confuse with the INNER DIAG
                       frame ``log_time`` (parsed by
                       :func:`diaggrok.frame.parse_outer_frame`),
                       which is a chipset-dependent high-frequency
                       counter (~17.24 ns/tick on SDX62, etc. — see
                       ``frame.py`` docstring). See #N.
    bytes payload[rec_len - 12]

This module exposes:

* :func:`iter_log_records` — flat-DLF walker (was already public).
* :func:`detect_format` — content-only classifier returning a
  :data:`DiagFormat` label.
* :func:`iter_records` — canonical "give me records, figure out the
  format yourself" entry point. Replaces :func:`detect_and_iter`,
  which is deprecated.

**Why this matters:** :func:`diaggrok.hdlc.iter_log_records` applied to
a flat DLF file yields a near-empty result — and the *converse* is
also true. Picking the wrong walker silently produces wrong records.
The previous :func:`detect_and_iter` API required callers to pass a
``registered_codes`` set; passing a too-small set silently flipped the
detection result (#N). :func:`iter_records` always uses the full
diaggrok parser registry, eliminating that footgun.

Format classification — see :data:`DiagFormat`:

* ``"dlf"`` — flat DLF.
* ``"hdlc"`` — raw HDLC (0x7E-delimited).
* ``"qmdl2-v2"`` — QMDL2 v2 with the diag_id multiplexing prefix
  ``10 5f 02``. Iterator not implemented (#N, #N); raises
  :class:`UnsupportedFormatError`.
* ``"unknown"`` — content matched no known format. Raises
  :class:`UnknownFormatError` rather than silently misrouting.

This module consolidates the walker-family bug cluster: #N, #N
(extension-driven misroute in callers), #N (this rewrite). #N's
RM520N container variant is empirically handled by the existing
flat-DLF walker (verified by ``TestRm520nRegression``).
"""
from __future__ import annotations

import struct
import warnings
from typing import Iterable, Iterator, Literal

from diaggrok.hdlc import iter_log_records as _iter_hdlc_log_records

_HEADER_LEN = 12  # u16 rec_len + u16 log_code + u64 ts64

DiagFormat = Literal["dlf", "hdlc", "qmdl2-v2", "unknown"]
"""Format labels emitted by :func:`detect_format`."""


class UnknownFormatError(ValueError):
    """Raised by :func:`iter_records` when content matches no known format."""


class UnsupportedFormatError(ValueError):
    """Raised by :func:`iter_records` when format is recognized but no
    iterator is implemented (e.g. QMDL2 v2 — see #N, #N)."""


# QMDL2 v2 diag_id multiplexing prefix — per #N issue body.
_QMDL2_V2_MAGIC = b"\x10\x5f\x02"
# Window for v2 magic-byte search at file head. Conservative: real captures
# put the prefix early; scanning the whole file would slow detection.
_QMDL2_V2_HEAD_WINDOW = 4096

# HDLC delimiter-density heuristic. The window is sized to catch HDLC
# captures whose initial record is unusually long — observed on the
# Inseego M2000 (MiFiOS2-2.302.1.24): zero ``0x7E`` delimiters in the
# first 4 KB, but 236 k delimiters total across a 118 MB capture (one
# per ~500 bytes on average). 64 KB comfortably finds delimiters in
# that case while still rejecting non-HDLC binary streams.
_HDLC_HEAD_WINDOW = 65536
_HDLC_MIN_DELIMS = 4


def iter_log_records(data: bytes) -> Iterator[tuple[int, int, bytes]]:
    """Yield ``(log_code, ts64, payload)`` for every record in a flat DLF stream.

    The iterator stops at the first malformed record header (``rec_len <
    12`` or overrun) rather than raising, matching the tolerant behavior
    of the private walker in ``tools/diag_scan.py``. Captures that end
    mid-record (truncated downloads) still yield every complete record
    up to the truncation point.
    """
    offset = 0
    n = len(data)
    while offset + _HEADER_LEN <= n:
        rec_len = struct.unpack_from("<H", data, offset)[0]
        if rec_len < _HEADER_LEN or offset + rec_len > n:
            return
        log_code = struct.unpack_from("<H", data, offset + 2)[0]
        ts64 = struct.unpack_from("<Q", data, offset + 4)[0]
        payload = data[offset + _HEADER_LEN : offset + rec_len]
        yield log_code, ts64, payload
        offset += rec_len


def pack_records(records: Iterable[tuple[int, int, bytes]]) -> bytes:
    """Inverse of :func:`iter_log_records` — pack ``(log_code, ts64, payload)``
    tuples into a flat-DLF byte stream.

    Used by recipe-fixture builders (#N Phase 3) so test fixtures live
    in one place and the framing definition isn't duplicated across
    tests/. Mirrors iter_log_records' header layout exactly:
    ``<H rec_len><H log_code><Q ts64><payload>``.

    Raises ValueError if any record's payload pushes rec_len above 65535
    (the uint16 limit), since the iterator would reject such a record.
    """
    out = bytearray()
    for log_code, ts64, payload in records:
        rec_len = _HEADER_LEN + len(payload)
        if rec_len > 65535:
            raise ValueError(
                f"pack_records: rec_len={rec_len} exceeds uint16 max; "
                f"log_code=0x{log_code:04X} payload={len(payload)}B"
            )
        out += struct.pack("<HHQ", rec_len, log_code, ts64)
        out += payload
    return bytes(out)


def _looks_like_flat_dlf(data: bytes, registered_codes: set[int]) -> bool:
    """Walk first 8 records and check every log_code is in ``registered_codes``.

    Requiring registered-parser codes drops the false-positive rate from
    ~1% per record to ~10^-16 across 8 records (with ~700 parsers
    registered).
    """
    MIN_OK = 8
    offset = 0
    ok = 0
    n = len(data)
    while offset + _HEADER_LEN <= n and ok < MIN_OK:
        rec_len = struct.unpack_from("<H", data, offset)[0]
        log_code = struct.unpack_from("<H", data, offset + 2)[0]
        if not (_HEADER_LEN <= rec_len <= 65535):
            return False
        if offset + rec_len > n:
            return False
        if log_code not in registered_codes:
            return False
        ok += 1
        offset += rec_len
    return ok >= MIN_OK


def detect_format(
    data: bytes, registered_codes: set[int] | None = None
) -> DiagFormat:
    """Classify a DIAG byte stream by content.

    Pure content-based — no extension or filename heuristics.

    Parameters
    ----------
    data:
        Bytes to classify.
    registered_codes:
        Set of log_codes the diaggrok parser registry knows about.
        Used during flat-DLF detection to drop the false-positive rate.
        **If ``None`` (the recommended default), the full diaggrok
        registry is loaded and used.** Passing a too-small set was the
        silent footgun documented in #N; new code should leave this
        as ``None`` or use :func:`iter_records`.
    """
    if registered_codes is None:
        from diaggrok.registry import registered_codes as _full

        registered_codes = set(_full())

    if _looks_like_flat_dlf(data, registered_codes):
        return "dlf"

    if data.find(_QMDL2_V2_MAGIC, 0, _QMDL2_V2_HEAD_WINDOW) != -1:
        return "qmdl2-v2"

    if data[:_HDLC_HEAD_WINDOW].count(b"\x7e") >= _HDLC_MIN_DELIMS:
        return "hdlc"

    return "unknown"


def iter_records(data: bytes) -> Iterator[tuple[int, int, bytes]]:
    """Detect format and dispatch to the correct iterator.

    The canonical "give me records, figure out the format yourself"
    entry point. Replaces the deprecated :func:`detect_and_iter`. Uses
    the full diaggrok parser registry for detection — no caller-side
    hint required, which eliminates the small-set footgun from #N.

    Yields
    ------
    ``(log_code, ts64, payload)`` tuples — same shape as
    :func:`iter_log_records` and :func:`diaggrok.hdlc.iter_log_records`.

    Raises
    ------
    UnknownFormatError
        If the byte stream cannot be classified as any known format.
    UnsupportedFormatError
        If the format is recognized but no iterator is implemented
        (currently: ``"qmdl2-v2"`` — see #N, #N).
    """
    fmt = detect_format(data)
    if fmt == "dlf":
        yield from iter_log_records(data)
    elif fmt == "hdlc":
        yield from _iter_hdlc_log_records(data)
    elif fmt == "qmdl2-v2":
        raise UnsupportedFormatError(
            "QMDL2 v2 detected (diag_id multiplexing prefix `10 5f 02`); "
            "iterator not implemented. See #N (fragmentation losses) "
            "and #N (spec recovery)."
        )
    else:
        head = data[:32].hex() if data else "<empty>"
        raise UnknownFormatError(
            f"Byte stream did not match any known format "
            f"(flat-DLF, HDLC, QMDL2 v2). First 32 bytes: {head}"
        )


def detect_and_iter(
    data: bytes, registered_codes: set[int] | None = None
) -> Iterator[tuple[int, int, bytes]]:
    """**Deprecated** — use :func:`iter_records`.

    Kept as a backward-compatibility shim. The original signature took a
    mandatory ``registered_codes`` set whose contents controlled format
    detection — a silent footgun (#N) when a small/wrong set was
    passed. This shim now ignores ``registered_codes`` and always uses
    the full diaggrok registry, eliminating the footgun. It also emits
    a :class:`DeprecationWarning` so callers migrate to
    :func:`iter_records`.

    Behavioral changes vs. the old shim:

    * Callers passing a small/wrong set used to get a misrouted walker
      (silent wrong data). They now get correct data via the full
      registry, plus a deprecation warning.
    * Callers passing the full registry continue to work identically.
    * Unknown formats now raise :class:`UnknownFormatError` instead of
      silently routing to the HDLC walker.
    """
    warnings.warn(
        "diaggrok.dlf.detect_and_iter is deprecated; use iter_records "
        "(content-based detection, no codes-set hint required). "
        "See issue #N.",
        DeprecationWarning,
        stacklevel=2,
    )
    yield from iter_records(data)
