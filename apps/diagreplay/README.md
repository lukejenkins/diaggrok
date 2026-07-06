# diagreplay — offline DIAG replay reader

The **minimal, testable client surface** for [`diaggrok`](../../libs/diaggrok).
`diagreplay` opens a committed capture file (flat-DLF or raw-HDLC, optionally
`.zst`/`.gz`) and yields `(ts, code, payload)` records by driving diaggrok's
*own* `dlf` / `hdlc` / `frame` modules. It is the `DiagClient`-*shaped* thing
diaggrok's own tests actually need: it reads a **file** — zero live transport,
zero DGE1 reassembly, zero log-mask handshake, zero munge.

Introduced by **#N** to (a) kill the ~9 copy-pasted `_iter_dlf_records`
readers that were duplicated across the diaggrok integration tests, and (b)
establish the exact in-repo client boundary the public diaggrok carve
(#N/#N) will ship — **without** letting `libs/diaggrok` grow any
`apps/*` import.

## API

```python
from diagreplay import replay_dlf     # apps/diagreplay on sys.path

for rec in replay_dlf(path, codes={0x1544}):   # codes= optional filter
    rec.ts        # int64 outer-DLF-header timestamp (Qualcomm 1.25 ms ticks)
    rec.code      # DIAG log code
    rec.payload   # bytes after the 12-byte record header (unparsed)
```

- `replay_dlf(path, codes=None)` — iterate a capture, optionally restricted to a
  set/list of log codes. Format (flat-DLF vs HDLC vs QMDL2) is auto-detected by
  `diaggrok.dlf.iter_records` using the full parser registry — no caller-side
  walker choice, so no silent-misroute footgun (#N).
- `read_capture_bytes(path)` — the decompress-aware file reader (`.zst` via the
  `zstandard` module, falling back to the `zstd` CLI; `.gz` via stdlib).
- `ReplayRecord` — a frozen `(ts, code, payload)` dataclass.

## CLI (manual inspection — not required by the test consolidation)

```sh
# from within apps/diagreplay/, or with apps/diagreplay on PYTHONPATH
python -m diagreplay <capture> [--code 0xNNNN ...] [--json]
```

## Dependency contract

Every edge points **inward** to the pure decoder:

```
diagreplay ──▶ libs/diaggrok        (this app)
tests      ──▶ libs/diaggrok + diagreplay
```

Nothing in `libs/diaggrok` imports `diagreplay` (verify: `grep -rn 'apps'
libs/diaggrok/src` shows only docstring provenance notes, zero imports). The
full `DiagClient` — live serial/TCP/UDP, DGE1, munge converters — lives
*downstream* in `apps/diaggpsd` and is out of scope here (promotion tracked by
#N).

## Layout

`apps/` are flat script dirs (no `__init__.py`); the dir goes on `sys.path` and
`diagreplay.py` imports as the top-level module `diagreplay`. The diaggrok test
suite wires this in via `libs/diaggrok/tests/conftest.py`; this app's own unit
tests via `apps/diagreplay/tests/conftest.py`.
