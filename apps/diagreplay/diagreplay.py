"""Offline DIAG replay reader: a minimal, file-based client for diaggrok.

``diagreplay`` opens a capture file (flat-DLF or raw-HDLC, optionally
``.zst``/``.gz`` compressed) and yields ``(ts, code, payload)`` records by
driving diaggrok's own ``dlf`` / ``hdlc`` / ``frame`` modules. It reads a
**file** only: no live transport, no DGE1 reassembly, no log-mask handshake,
no format conversion.

Why this exists
---------------
Tests and tools that read capture files need the same small loop: split the
stream into records, filter by log code, and decompress ``.zst`` inline. This
module is the shared home for that loop, and it gives diaggrok a client
boundary that keeps every dependency edge pointing inward to the decoder.

Dependency contract
-------------------
``diagreplay -> diaggrok`` only. Nothing in the ``diaggrok`` package imports
this module. A full live client (serial/TCP/UDP transport, DGE1, format
converters) is out of scope here.

Public API
----------
* :class:`ReplayRecord` — a ``(ts, code, payload)`` triple.
* :func:`replay_dlf` — iterate a capture file, optionally filtered by log code.
* :func:`read_capture_bytes` — the decompress-aware file reader (exposed so
  callers that already have a decompressed blob can reuse the fallback logic).

Example
-------
>>> from diagreplay import replay_dlf
>>> for rec in replay_dlf(path, codes={0x1544}):   # codes= optional filter
...     rec.ts        # int64 outer-DLF-header timestamp (1.25 ms DIAG ticks)
...     rec.code      # DIAG log code
...     rec.payload   # bytes after the 12-byte record header

``ts`` is the **outer** file-format timestamp from the DLF record header — NOT
the inner DIAG-frame ``log_time`` (see :mod:`diaggrok.dlf` /
:func:`diaggrok.frame.parse_outer_frame`).
"""
from __future__ import annotations

import gzip
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from diaggrok.dlf import iter_records

__all__ = ["ReplayRecord", "replay_dlf", "read_capture_bytes"]


@dataclass(frozen=True)
class ReplayRecord:
    """One decoded DIAG record from a capture.

    Attributes
    ----------
    ts:
        The ``u64`` outer-DLF timestamp (1.25 ms DIAG ticks). For HDLC
        captures — which carry no outer file timestamp — this is ``0``,
        matching :func:`diaggrok.hdlc.iter_log_records`.
    code:
        The DIAG log code (``u16``).
    payload:
        The record body — bytes after the 12-byte flat-DLF record header
        (or the HDLC-deframed inner bytes), unparsed.
    """

    ts: int
    code: int
    payload: bytes


def read_capture_bytes(path: str | Path) -> bytes:
    """Read a capture file, transparently decompressing ``.zst`` / ``.gz``.

    Prefers the ``zstandard`` Python module and falls back to the ``zstd``
    CLI when the module is not installed. ``.zst`` is the usual compression
    for stored captures.
    """
    path = Path(path)
    name = str(path)
    if name.endswith(".gz"):
        return gzip.decompress(path.read_bytes())
    if name.endswith(".zst"):
        try:
            import zstandard

            return zstandard.ZstdDecompressor().decompress(path.read_bytes())
        except ImportError:
            return subprocess.run(
                ["zstd", "-dc", str(path)], check=True, capture_output=True
            ).stdout
    return path.read_bytes()


def replay_dlf(
    path: str | Path, codes: Iterable[int] | None = None
) -> Iterator[ReplayRecord]:
    """Yield :class:`ReplayRecord` for every record in a capture file.

    Parameters
    ----------
    path:
        Capture file — flat-DLF or raw-HDLC, optionally ``.zst``/``.gz``.
    codes:
        Optional iterable of log codes to keep. ``None`` (default) yields
        every record; a set/list restricts output to those codes.

    Format detection is delegated to :func:`diaggrok.dlf.iter_records`, which
    classifies the stream by content (flat-DLF vs HDLC vs QMDL2) using the full
    diaggrok parser registry, so a caller never has to pick the right walker
    and cannot silently misroute a capture.
    """
    data = read_capture_bytes(path)
    wanted = set(codes) if codes is not None else None
    for log_code, ts64, payload in iter_records(data):
        if wanted is not None and log_code not in wanted:
            continue
        yield ReplayRecord(ts=ts64, code=log_code, payload=payload)


def _main(argv: list[str] | None = None) -> int:
    """``python -m diagreplay <capture> [--code 0xNNNN] [--json]`` — manual
    inspection helper."""
    import argparse
    import json

    ap = argparse.ArgumentParser(
        prog="diagreplay",
        description="Offline DIAG replay reader — dump (ts, code, len) per record.",
    )
    ap.add_argument("capture", help="capture file (flat-DLF/HDLC, optionally .zst/.gz)")
    ap.add_argument(
        "--code",
        action="append",
        default=None,
        help="only records with this log code (hex 0xNNNN or decimal); repeatable",
    )
    ap.add_argument(
        "--json", action="store_true", help="emit one JSON object per record"
    )
    ns = ap.parse_args(argv)

    codes = None
    if ns.code:
        codes = {int(c, 0) for c in ns.code}

    n = 0
    for rec in replay_dlf(ns.capture, codes=codes):
        n += 1
        if ns.json:
            print(
                json.dumps(
                    {
                        "ts": rec.ts,
                        "code": rec.code,
                        "code_hex": f"0x{rec.code:04X}",
                        "len": len(rec.payload),
                        "payload_hex": rec.payload.hex(),
                    }
                )
            )
        else:
            print(f"ts={rec.ts} code=0x{rec.code:04X} len={len(rec.payload)}")
    print(f"# {n} record(s)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
