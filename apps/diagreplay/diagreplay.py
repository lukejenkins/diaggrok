"""Offline DIAG replay reader — the minimal, testable client surface for diaggrok.

``diagreplay`` opens a committed capture file (flat-DLF or raw-HDLC, optionally
``.zst``/``.gz`` compressed) and yields ``(ts, code, payload)`` records by
driving diaggrok's *own* ``dlf`` / ``hdlc`` / ``frame`` modules. It is the
``DiagClient``-*shaped* thing the diaggrok test-suite actually needs: it reads a
**file**, with zero live transport, zero DGE1 reassembly, zero log-mask
handshake, zero munge (issue #N).

Why this exists
---------------
The diaggrok integration tests each hand-rolled a private ``_iter_dlf_records``
(split flat-DLF on the 2-byte length prefix, filter by code, decompress ``.zst``
inline) — the same ~25 lines copy-pasted across ~9 files. That copy is exactly
this module, minus the shared home. Consolidating them here (a) kills the
copy-paste and (b) establishes the in-repo client boundary the public diaggrok
carve (#N/#N) will ship, **without** letting ``libs/diaggrok`` grow any
``apps/*`` import — every edge points inward to the pure decoder.

Dependency contract
-------------------
``diagreplay -> diaggrok`` only. Nothing in ``libs/diaggrok`` imports this
module (verify: ``grep -rn 'apps' libs/diaggrok/src`` stays empty). The full
``DiagClient`` (live serial/TCP/UDP, DGE1, munge converters) lives *downstream*
in ``apps/diaggpsd`` and is out of scope here (#N).

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
...     rec.ts        # int64 outer-DLF-header timestamp (Qualcomm 1.25 ms ticks)
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
        The ``u64`` outer-DLF timestamp (Qualcomm 1.25 ms ticks). For HDLC
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

    Mirrors the decompress-fallback the hand-rolled test readers used: prefer
    the ``zstandard`` Python module, fall back to the ``zstd`` CLI when it is
    not installed in this ``.venv`` (the ``.zst`` is the canonical capture
    compression per AGENTS.md § "Capture-folder compression policy", #N).
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
    diaggrok parser registry — so a caller never has to pick the right walker,
    eliminating the silent-misroute footgun (#N).
    """
    data = read_capture_bytes(path)
    wanted = set(codes) if codes is not None else None
    for log_code, ts64, payload in iter_records(data):
        if wanted is not None and log_code not in wanted:
            continue
        yield ReplayRecord(ts=ts64, code=log_code, payload=payload)


def _main(argv: list[str] | None = None) -> int:
    """``python -m diagreplay <capture> [--code 0xNNNN] [--json]`` — manual
    inspection helper (not required by the test consolidation; #N)."""
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
