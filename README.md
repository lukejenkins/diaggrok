# diaggrok

> Part of the **[cellular `diag*` toolkit](https://github.com/lukejenkins/cellular#the-diag-toolkit)**: start there for how the capture/decode pieces fit together.

A 100% reverse engineered library for parsing the diagnostic (DIAG) logs of mobile devices — specifically the `LOG_F` records that modern cell modems built on Qualcomm chipsets emit when you put them into diagnostic mode.

If you've ever pointed a vendor log viewer, QCSuper, or SCAT at a modem and wondered what all those `0x1526`-style log codes actually *mean*, that's the itch this scratches. diaggrok takes the raw bytes of a DIAG log record and hands you back named, typed fields.

## What's in here

This repo is a curated public **carve** out of a much larger private working tree — it ships the parsers I've cleaned up enough to stand behind on their own. As of `v2026.10.04` that's:

* **188 log-code parsers**
* Pure Python, **zero dependencies**, Python 3.11+
* Apache-2.0 licensed

Coverage, by area:

* **GNSS**: fixes, per-SV measurements across GPS / GLONASS / Galileo / BeiDou / QZSS / SBAS / NavIC (including the L5 / E5a / B1C reports), clock and time state, ephemeris, SBAS demod, RF front-end and power-profiling reports, NMEA-over-DIAG
* **LTE**: ML1 / LL1 cell search and measurements (serving, neighbour, IRAT-to-NR), MAC RACH and transport blocks, PDCP, RRC OTA plus MIB / SIB / serving-cell info / CA combos, NAS EMM and ESM messages and state
* **5G NR**: L1 / ML1 measurements and per-beam blocks, cell search, CDRX, MAC, RRC OTA plus MIB / serving-cell / configuration / CA combos, NAS 5GMM and 5GSM messages and state
* **2G / 3G**: a handful of GSM L1 acquisition and measurement records, GSM RR signalling, WCDMA PN search results, and UMTS NAS PLMN lists
* **Everything else**: IMS SIP and registration, SIM / UICC APDU traces, QMI and QCRIL logging, the IPA data path, and some thermal, battery and coexistence reports

Every parser was reverse engineered against real captures. Most of the early work was on a Quectel **RM520N-GL** (SDX62); this release adds parsers validated on chipsets from the MDM9x07 generation through SDX72. Where a decoded field could be matched against the modem's own debug messages (F3 traces), it was, and each parser's metadata says where its decode came from (see `parser_info()` below).

The thing I care most about: each parser knows its own byte layout and **refuses to guess**. If a record isn't the size it was reverse engineered against, or carries a version byte the parser doesn't know, the parser returns `None` instead of emitting plausible-looking garbage. Size invariance is not format invariance, and I'd rather see a parse-rate drop on a new firmware than trust a silently mis-decoded field. Those drops aren't silent either: when a registered parser declines a record, diaggrok logs a rate-limited warning, so a gap in coverage shows up in your logs instead of hiding in them.

(`EXTRACT_MANIFEST.json` in the repo root lists exactly which log codes and modules made it into this carve.)

## Installation

Not on PyPI yet — install straight from GitHub:

```bash
pip install "diaggrok @ git+https://github.com/lukejenkins/diaggrok@main"
```

## Usage

The high-level entry point is `parse()`: give it a log code, a timestamp, and the raw payload bytes, and get back a decoded object (or `None` if nothing's registered for that code).

```python
import diaggrok

result = diaggrok.parse(0x1526, log_time, payload)
if result is not None:
    print(result.to_dict())
```

If you're starting from a raw DIAG `LOG_F` (opcode `0x10`) frame, peel off the outer/inner headers first — `parse_outer_frame()` hands back the log code as `log_type`:

```python
from diaggrok import parse_outer_frame, parse

pending, log_type, log_time, log_payload = parse_outer_frame(frame_bytes)
result = parse(log_type, log_time, log_payload)
```

### Reading capture files

If you've got a whole capture on disk, `diaggrok.dlf.iter_records()` works out the framing for you (flat DLF, raw HDLC, or QMDL2) and yields `(log_code, timestamp, payload)` for every log record:

```python
from pathlib import Path

import diaggrok
from diaggrok.dlf import iter_records

for code, ts, payload in iter_records(Path("capture.dlf").read_bytes()):
    result = diaggrok.parse(code, ts, payload)
    if result is not None:
        print(hex(code), result.to_dict())
```

`apps/diagreplay/` wraps that in a small reader that also handles `.zst` / `.gz` compressed captures and can filter by log code. Its command line lists the records in a capture (timestamp, code, length, and with `--json` the raw payload as hex) without decoding them, which is handy for a first look:

```sh
cd apps/diagreplay
python -m diagreplay capture.dlf.zst --code 0x1526 --json
```

### What's supported

Want to see what's supported, or poke at a parser's metadata (where the decode came from, which payload versions it accepts, how many fields it identifies)?

```python
diaggrok.registered_codes()    # -> [0x10BA, 0x117E, ...]
diaggrok.parser_info(0x1526)   # -> ParserEntry(name='0x1526', source_type='re', ...)
```

### Bring your own parsers

You don't have to fork to extend it. Drop a `.py` file that calls `@register(...)` into `~/.diaggrok/plugins/` (or point `DIAGGROK_PLUGIN_DIR` at a directory of them), then:

```python
diaggrok.load_plugins()
```

## A note on privacy

Some of these log codes carry personal data, because the modem logs it: NAS and RRC messages can include subscriber and device identifiers, the IMS parsers decode SIP traffic and registration identities, the SIM parsers decode APDUs, and GNSS fixes are your location. diaggrok decodes what's in the record and does not redact anything. If you share decoded output (or the captures themselves), check what's in them first.

## Changes between releases

Releases are tagged `vYYYY.MM.DD`. A parser's record shape is part of the public interface, so [CHANGELOG.md](./CHANGELOG.md) lists every renamed, removed, or re-typed field. `v2026.10.04` has breaking changes to 22 existing parsers (mostly placeholder fields replaced by real decodes, plus `0x4179`, which turned out to be a WCDMA record rather than LTE). Read the changelog before upgrading from `v2026.08.23`.

## Scope, and some honesty

This is carved out of an active reverse-engineering project, so a few things are true and worth saying out loud:

* It only covers modems built on Qualcomm chipsets. Other basebands aren't in scope here.
* A parser makes it into this repo only once it's been checked against real captures. Plenty of log codes I've looked at aren't here yet, and the ones that are don't all decode every field. Unknown bytes stay as raw values rather than getting a guessed name.
* 2G/3G is thin — those technologies had been sunset before I got into cellular based tech, and the projects in Kudos below do that far better, so use them for it.

## Kudos

This software is strongly inspired by a few other projects. In many cases they still do a better job parsing logs into usable data. This is especially true for 2G and 3G technologies that had been sunset before I got into cellular based tech. They also have a much longer track record and support ecosystem, so check them out:

* https://osmocom.org/projects/baseband/wiki/Ccch_scan
* https://github.com/p1sec/qcsuper
* https://github.com/fgsect/scat

None of the code from these projects is in diaggrok.

## AI Disclaimer

The AI 'bots are VERY good at finding patterns and matching values, exactly what one needs for taking documented output (e.g. AT commands) and matching it up to help you decode a publicly undocumented protocol (e.g. diag logs from a cell modem). If you're opposed to using this kind of work, there are other open source options and some commercial options that you should seek out.

## License

Apache-2.0. See [LICENSE](./LICENSE).
