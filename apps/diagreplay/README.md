# diagreplay — offline DIAG capture reader

A small reader for DIAG capture files that sit on disk. Point it at a capture
(flat DLF or raw HDLC, optionally `.zst` or `.gz` compressed) and it yields one
`(ts, code, payload)` record per log record, using diaggrok's own `dlf` /
`hdlc` modules to work out the framing. It only reads files: there's no live
modem connection and no log-mask setup.

It doesn't decode anything itself. Hand each payload to `diaggrok.parse()` for
that.

## Setup

`diagreplay.py` is a single module in this directory. `pip install diaggrok`
installs the library but not this app, so put this directory on your Python
path (or run from inside it):

```sh
cd apps/diagreplay
# or: export PYTHONPATH=/path/to/diaggrok/apps/diagreplay
```

It needs diaggrok importable (installed, or `src/` on `PYTHONPATH`). Reading
`.zst` captures uses the `zstandard` Python package if it's installed, and falls
back to the `zstd` command line tool if it isn't. `.gz` uses the standard
library.

## API

```python
import diaggrok
from diagreplay import replay_dlf

for rec in replay_dlf("capture.dlf.zst", codes={0x1526}):  # codes= is optional
    rec.ts        # outer DLF record timestamp (1.25 ms DIAG ticks; 0 for HDLC)
    rec.code      # DIAG log code
    rec.payload   # record body after the 12-byte header, unparsed

    result = diaggrok.parse(rec.code, rec.ts, rec.payload)
```

- `replay_dlf(path, codes=None)`: iterate a capture, optionally keeping only the
  given log codes. The format (flat DLF, HDLC or QMDL2) is detected from the
  file contents by `diaggrok.dlf.iter_records`, so you never pick a walker by
  hand.
- `read_capture_bytes(path)`: the decompress-aware file reader on its own.
- `ReplayRecord`: a frozen `(ts, code, payload)` dataclass.

`ts` is the timestamp from the capture file's record header, not the DIAG
frame's own `log_time` (see `diaggrok.frame.parse_outer_frame`).

## Command line

For a quick look at what's in a capture:

```sh
python -m diagreplay <capture> [--code 0xNNNN ...] [--json]
```

Each record prints as `ts=... code=0x.... len=...`. With `--json` you get one
JSON object per record, including the raw payload as hex. `--code` can be
repeated, and takes hex or decimal.

## Tests

The tests use synthetic records only:

```sh
python -m pytest apps/diagreplay/tests
```
