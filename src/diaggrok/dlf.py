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
  :data:`DiagFormat` label. Answers *"which framing is this capture?"*,
  **not** *"is this a capture?"* — its ``"hdlc"`` arm is a last-resort
  default that nearly every binary file satisfies (#N).
* :func:`is_probably_capture` — the *other* question: a structural
  gate for callers holding an arbitrary file. Use this before walking
  anything that wasn't already known to be a capture (#N, #N).
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
* ``"qmdl2-v2"`` — QMDL2 capture carrying the QSHRINK4 binding
  **prologue**: ``[u32 header_length][header_length - 4 bytes of
  binding table][ordinary HDLC to EOF]``. Detected **structurally**
  (see :func:`qmdl2_prologue_length`) and walked by skipping the
  prologue and handing the remainder to the HDLC walker (#N).
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
    iterator is implemented.

    No format currently triggers this — ``"qmdl2-v2"`` used to, and the
    class is kept because callers (``tools/diag_scan.py``,
    ``tools/_capture_io.py``) catch it as their "framing I can't walk"
    signal and it is part of the public API.
    """


# --- QMDL2 prologue detection (#N) -------------------------------------
#
# The old detector sniffed the byte triple ``10 5f 02`` in the first 4 KB.
# That triple is THE PHANTOM (#N/#N): it is not structure. It occurs by
# coincidence inside HDLC frame payloads — overwhelmingly inside 0x9D
# QSH-trace frames, which are ~93% of frames in the reference capture — so
# detection rested on a coincidence being frequent enough, in a window.
#
# MEASURED, and it is worse than the failure mode we expected (#N):
#
#   The corpus contains exactly ONE genuine QMDL2-with-prologue capture
#   (cfw3212_gnss_130s.qmdl2). The old detector classified it as plain
#   ``hdlc`` — a FALSE NEGATIVE on the only true positive there is. The
#   triple's first occurrence in that file is at offset **4801**, i.e.
#   705 bytes past the 4096-byte window. Detection was decided by where a
#   coincidence happened to land.
#
#   The false-POSITIVE direction (a bare-HDLC capture containing the
#   triple early, classifying as ``qmdl2-v2`` and becoming an
#   ``UnsupportedFormatError`` dead end rather than being walked as the
#   ordinary HDLC it is) is real as a mechanism but has **zero** instances
#   across the 165-file corpus. Both directions are gone either way.
#
# Practical impact of the false negative was mild — the HDLC walker is
# tolerant, so the non-frame prologue was silently discarded as one bad
# segment and the record yield was unaffected (1487 either way). What was
# lost is the classification itself, and with it any ability to address
# the prologue: the binding table naming the capture's protection domains
# sat in front of a walker that could only throw it away.
#
# The replacement is structural, and comes from the corrected layout in
# ``libs/diagspec/ksy/framing/diag_qmdl2_file.ksy`` (#N):
#
#     [ u32 LE header_length ][ header_length - 4 bytes ][ HDLC to EOF ]
#
# Two independent conditions, both cheap:
#   1. byte 0 holds a *plausibly small* u32 (a bare HDLC stream's first
#      four bytes read as a huge garbage number — ``7e 4b 12 22`` is
#      0x22124B7E), and
#   2. file offset ``header_length`` is the start of a **CRC-valid** DIAG
#      frame.
#
# Condition 2 is the load-bearing one: a random 16-bit CRC agreeing is a
# 1-in-65536 event, and it must agree at the *exact* offset condition 1
# predicted. A corpus sweep of all 165 <redacted-pii> files under
# CAPTURES_ROOT + DUMPS_ROOT matched exactly one file (the cfw3212
# reference) with zero false positives; the other 164 are bare HDLC
# streams, which is the correct answer for them.
#
# NOTE THE ``- 4``: header_length is measured from file offset 0 and
# therefore counts its own u32. Reading it as "header_length bytes AFTER
# the u32" steals the first four bytes of the following frame — an
# off-by-four that *parses without throwing*, which is exactly why the
# CRC check and not a length check is the discriminator here.
_QMDL2_HL_MIN = 8  # u32 + at least 4 bytes of binding table
_QMDL2_HL_MAX = 4096  # observed 77; the bound only has to exclude garbage u32s
# Cap the 0x7E search after the prologue. A real first frame is tens of
# bytes; without a cap a pathological input costs a full-file scan.
_QMDL2_FRAME_SCAN_LIMIT = 4096
# Shortest thing that can be a CRC-valid DIAG frame: opcode + u16 CRC.
_MIN_DIAG_FRAME_LEN = 3

# HDLC delimiter-density heuristic. The window is sized to catch HDLC
# captures whose initial record is unusually long — observed on the
# Inseego M2000 (MiFiOS2-2.302.1.24): zero ``0x7E`` delimiters in the
# first 4 KB, but 236 k delimiters total across a 118 MB capture (one
# per ~500 bytes on average). 64 KB comfortably finds delimiters in
# that case while still rejecting non-HDLC binary streams.
_HDLC_HEAD_WINDOW = 65536
_HDLC_MIN_DELIMS = 4

# Leading all-zero run skipped before re-classifying an otherwise-`unknown`
# stream (#N). Observed on the Sierra EM9190 capture
# `gnss_diag_capture_2026-04-15_linux.dlf.zst`: 158,157,306 bytes of 0x00
# (76% of the decompressed stream) ahead of ~30 MB of genuine HDLC. Every
# head-window test above sees only zeros, returns "unknown", and the capture
# has been invisible to every corpus walk since 2026-04-15.
#
# A zero prefix carries no framing information by definition, so skipping it
# cannot change a CORRECT verdict — it can only rescue a wrong one. That is
# why the retry is unconditional in length rather than threshold-gated: any
# stream whose head-window classification already succeeded never reaches it.
_ZERO_PREFIX_SCAN_LIMIT = 1 << 31  # 2 GiB — bound the scan on a pathological file

# --- is_probably_capture (#N) ------------------------------------------
#
# Leading magics that positively identify a file as something OTHER than a
# DIAG capture. Anchored at offset 0 (tar's `ustar` at 257 is handled
# separately). Drawn from what the #N census actually had to reject —
# extracted modem filesystems under DUMPS_ROOT are overwhelmingly ELF, and
# the published-wrong number there came from `libdiag.so`, a `data.tar.gz`
# and a NAND dump all passing the delimiter-count gate.
_NON_CAPTURE_MAGICS: tuple[bytes, ...] = (
    b"\x7fELF",              # ELF executable / shared object
    b"\x1f\x8b",             # gzip
    b"BZh",                  # bzip2
    b"\xfd7zXZ\x00",         # xz
    b"\x28\xb5\x2f\xfd",     # zstd
    b"PK\x03\x04",           # ZIP / jar / apk
    b"hsqs", b"sqsh",        # squashfs LE / BE
    b"UBI#",                 # UBI volume table
    b"\x31\x18\x10\x06",     # UBI erase-count block
    b"\x85\x19", b"\x19\x85",  # JFFS2 LE / BE
    b"\xd1\xdc\x4b\x84",     # Qualcomm MBN codeword (0x844BDCD1)
    b"QCDT",                 # Qualcomm device tree blob
    b"<?xml",                # XML manifest
    b"\x89PNG",              # PNG (dumps carry vendor web assets)
    b"SQLite format 3\x00",  # sqlite db
)

# Bound on the CRC probe. A real capture hits a valid frame within the
# first handful of segments; this only stops a pathological input (a file
# that is largely 0x7E) from turning the probe into a long scan.
_CAPTURE_PROBE_MAX_SEGMENTS = 256


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


def qmdl2_prologue_length(data: bytes) -> int | None:
    """Return the QMDL2 prologue length, or ``None`` if this isn't QMDL2.

    Implements the structural test described in the module comment above
    (#N): a plausibly-small ``u32`` at offset 0 **and** a CRC-valid
    DIAG frame beginning at exactly that offset.

    The returned value is the offset at which the ordinary HDLC stream
    starts — i.e. it is inclusive of its own 4-byte length field, per
    ``diag_qmdl2_file.ksy`` (#N). Callers skip exactly this many
    bytes; there is no ``+ 4``.

    Returns
    -------
    int | None
        Offset of the HDLC stream, or ``None`` when the stream is not a
        QMDL2 capture with a binding prologue.
    """
    from diaggrok.hdlc import crc16_ccitt, hdlc_unescape

    if len(data) < _QMDL2_HL_MIN:
        return None
    (header_length,) = struct.unpack_from("<I", data, 0)
    if not (_QMDL2_HL_MIN <= header_length <= _QMDL2_HL_MAX):
        return None
    if header_length >= len(data):
        return None

    end = data.find(b"\x7e", header_length, header_length + _QMDL2_FRAME_SCAN_LIMIT)
    if end < 0:
        return None
    frame = hdlc_unescape(data[header_length:end])
    if len(frame) < _MIN_DIAG_FRAME_LEN:
        return None
    (crc_expected,) = struct.unpack_from("<H", frame, len(frame) - 2)
    if crc16_ccitt(frame[:-2]) != crc_expected:
        return None
    return header_length


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

    ⛔ **The three arms are not peers, and ``"hdlc"`` is not a positive
    identification.** ``"dlf"`` and ``"qmdl2-v2"`` are structural tests
    (8 registered log codes / a CRC-valid frame at a predicted offset,
    #N). ``"hdlc"`` is the **last-resort default**: four ``0x7E``
    bytes anywhere in a 64 KB window, which essentially every binary
    file on disk satisfies — ELF executables, tarballs and NAND dumps
    all classify as ``"hdlc"``.

    That is correct for this function's contract, which is *"this file
    is already known to be a capture — which framing is it?"*. It is
    **wrong as a gate deciding whether an arbitrary file is a capture
    at all**; used that way in #N it admitted ``libdiag.so``, a
    ``data.tar.gz`` and a NAND dump into a ``0x4B`` census and produced
    a confidently wrong published number. Callers who need that
    question answered want :func:`is_probably_capture`, not this.

    ⚠️ **A non-``"unknown"`` verdict does not imply the framing starts at
    byte 0.** When every head-window arm fails, the arms are re-run past a
    leading all-zero run (#N), so a stream can classify as ``"hdlc"``
    while its first frame sits 158 MB in. Callers that *walk* the stream
    must ask :func:`zero_prefix_length` and trim, exactly as they already
    do for :func:`qmdl2_prologue_length`; callers that only want the label
    can ignore it.
    """
    if registered_codes is None:
        from diaggrok.registry import registered_codes as _full

        registered_codes = set(_full())

    fmt = _classify(data, registered_codes)
    if fmt != "unknown":
        return fmt

    # Last resort: the framing may be hidden behind a leading all-zero run
    # (#N). Only reached when every head-window test already failed, so
    # this can rescue a wrong verdict but never overturn a right one.
    skip = _leading_zero_run(data)
    if skip:
        return _classify(data[skip:], registered_codes)

    return "unknown"


def _classify(data: bytes, registered_codes: set[int]) -> DiagFormat:
    """The three head-window arms of :func:`detect_format`, without the
    zero-prefix retry. Split out so the retry can re-run them at an offset
    without recursing through the registry load (#N)."""
    if _looks_like_flat_dlf(data, registered_codes):
        return "dlf"

    if qmdl2_prologue_length(data) is not None:
        return "qmdl2-v2"

    if data[:_HDLC_HEAD_WINDOW].count(b"\x7e") >= _HDLC_MIN_DELIMS:
        return "hdlc"

    return "unknown"


def _leading_zero_run(data: bytes) -> int:
    """Length of the run of ``0x00`` bytes at the start of ``data``.

    Returns 0 when ``data`` does not start with a zero byte, and never
    returns ``len(data)`` — an all-zero stream has no framing to rescue, so
    reporting a prefix for it would only hand callers an empty tail.
    """
    if not data or data[0] != 0:
        return 0
    n = min(len(data), _ZERO_PREFIX_SCAN_LIMIT)
    # `lstrip` is a C-level scan; the alternative (a Python loop or repeated
    # slicing) is minutes rather than milliseconds on the 158 MB run in #N.
    run = n - len(data[:n].lstrip(b"\x00"))
    return 0 if run >= len(data) else run


def zero_prefix_length(data: bytes, registered_codes: set[int] | None = None) -> int:
    """Bytes of leading ``0x00`` padding that :func:`detect_format` had to skip.

    Returns 0 unless **both** hold: the stream's head classifies as
    ``"unknown"``, and skipping the leading zero run makes it classify as
    something walkable. So a nonzero result means *"the framing starts here,
    not at byte 0"* — and callers that walk records must trim exactly this
    many bytes, or every record's file offset is wrong by this amount (#N).

    This is the same shape as :func:`qmdl2_prologue_length`: classification
    reports an offset, and the caller trims before walking.
    """
    if registered_codes is None:
        from diaggrok.registry import registered_codes as _full

        registered_codes = set(_full())

    if _classify(data, registered_codes) != "unknown":
        return 0

    skip = _leading_zero_run(data)
    if skip and _classify(data[skip:], registered_codes) != "unknown":
        return skip
    return 0


def is_probably_capture(
    data: bytes,
    registered_codes: set[int] | None = None,
    window: int = _HDLC_HEAD_WINDOW,
) -> bool:
    """Positively answer *"is this arbitrary file a DIAG capture at all?"*.

    This is the question :func:`detect_format` does **not** answer — see
    its docstring. ``detect_format`` classifies a stream already known to
    be a capture, and its ``"hdlc"`` arm is a last-resort default that
    essentially every binary file passes. Two callers have now reached
    for it as a gate (#N's ``0x4B`` census, and #N's audit) and
    both wanted this function instead; neither had it available.

    The test is deliberately **structural**, matching the philosophy
    #N applied to the other two arms. Byte-needle gates were measured
    failing in #N — ``4B`` is ASCII ``'K'`` and rejects nothing;
    ``7E 4B`` is two bytes and a random 64 KB window holds ~65 000
    positions, so a random binary contains the pair more often than not.

    Three steps, cheapest first:

    1. **Magic-byte reject.** A file that opens with a container/archive/
       executable magic is that thing, whatever else its bytes contain.
    2. **Structural accept.** ``"dlf"`` and ``"qmdl2-v2"`` are already
       structural verdicts; take them.
    3. **CRC gate for the ``"hdlc"`` arm.** Require at least one
       genuinely CRC-valid DIAG frame in the window, rather than a count
       of delimiters. A 16-bit CRC agreeing by chance is a 1-in-65536
       event per candidate segment, so this rejects the arbitrary
       binaries that a delimiter count admits — and unlike a delimiter
       *density* floor it needs no tuned constant, which matters because
       the Inseego M2000 case (see :data:`_HDLC_HEAD_WINDOW`) proves
       real captures can be arbitrarily delimiter-sparse at the head.

    Parameters
    ----------
    data:
        Bytes to test. A head prefix is fine; ``window`` bounds the work.
    registered_codes:
        Passed through to :func:`detect_format`. Sweep callers should
        enumerate the registry **once** and pass it explicitly —
        left ``None`` the registry is re-enumerated per call, which is
        negligible for one file and a hard stall across 100 000 (#N).
    window:
        Bytes of ``data`` to examine. Raise it for captures whose first
        frame is known to sit deep in the file.

    Returns
    -------
    bool
        ``True`` if ``data`` is positively identifiable as a DIAG
        capture. ``False`` is the safe answer: it means "not shown to be
        a capture", not "proven not to be one".
    """
    head = data[:window]
    if not head:
        return False

    if any(head.startswith(m) for m in _NON_CAPTURE_MAGICS):
        return False
    # tar's `ustar` magic is at offset 257, not 0.
    if head[257:262] == b"ustar":
        return False

    fmt = detect_format(head, registered_codes=registered_codes)
    if fmt in ("dlf", "qmdl2-v2"):
        return True
    if fmt != "hdlc":
        return False

    return _has_crc_valid_frame(head)


def _has_crc_valid_frame(head: bytes) -> bool:
    """True if ``head`` contains at least one CRC-valid HDLC DIAG frame.

    Walks ``0x7E``-delimited segments and stops at the first one whose
    trailing u16 matches ``crc16_ccitt`` over its body. Bounded by
    :data:`_CAPTURE_PROBE_MAX_SEGMENTS` so a pathological input (a file
    that is mostly ``0x7E``) can't turn the probe into a long scan.
    """
    from diaggrok.hdlc import crc16_ccitt, hdlc_unescape

    checked = 0
    start = head.find(b"\x7e")
    if start < 0:
        return False
    start += 1
    while checked < _CAPTURE_PROBE_MAX_SEGMENTS:
        end = head.find(b"\x7e", start)
        if end < 0:
            return False
        segment = head[start:end]
        start = end + 1
        if not segment:
            continue  # back-to-back delimiters (idle fill)
        checked += 1
        frame = hdlc_unescape(segment)
        if len(frame) < _MIN_DIAG_FRAME_LEN:
            continue
        (crc_expected,) = struct.unpack_from("<H", frame, len(frame) - 2)
        if crc16_ccitt(frame[:-2]) == crc_expected:
            return True
    return False


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
        If the format is recognized but no iterator is implemented. No
        format currently does this — ``"qmdl2-v2"`` gained an iterator
        in #N — but the branch is part of the contract.
    """
    fmt = detect_format(data)
    if fmt == "dlf":
        yield from iter_log_records(data)
    elif fmt == "hdlc":
        yield from _iter_hdlc_log_records(data)
    elif fmt == "qmdl2-v2":
        # The container is [prologue][ordinary HDLC] — once the boundary
        # is *read* from header_length rather than guessed from payload
        # content, there is nothing left to implement (#N). Skipping
        # the prologue matters: the binding table is not HDLC-framed, so
        # feeding it to the HDLC walker costs a desync at the head of
        # the file.
        prologue = qmdl2_prologue_length(data)
        assert prologue is not None  # detect_format only says so if it isn't
        yield from _iter_hdlc_log_records(data[prologue:])
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
