# diaggrok

A 100% reverse engineered library for parsing the diagnostic (DIAG) logs of mobile devices — specifically the Qualcomm `LOG_F` records that modern cell modems emit when you put them into diagnostic mode.

If you've ever pointed QCAT, QXDM, qcsuper, or SCAT at a modem and wondered what all those `0x1526`-style log codes actually *mean*, that's the itch this scratches. diaggrok takes the raw bytes of a DIAG log record and hands you back named, typed fields.

## What's in here

This repo is a curated public **carve** out of a much larger private working tree — it ships the parsers I've cleaned up enough to stand behind on their own. Right now that's:

* **59 log-code parsers**, focused on the GNSS and LTE-signal domains
* Reverse engineered and validated mostly against a Quectel **RM520N-GL** (SDX62), and cross-checked on other chipsets where I have captures for them
* Pure Python, **zero dependencies**, Python 3.11+
* Apache-2.0 licensed

The thing I care most about: each parser knows its own byte layout and **refuses to guess**. If a record isn't the size it was reverse engineered against, or carries an unexpected version byte, the parser returns `None` instead of emitting plausible-looking garbage. Size invariance is not format invariance, and I'd rather see a parse-rate drop on a new firmware than trust a silently mis-decoded field.

(`EXTRACT_MANIFEST.json` in the repo root lists exactly which log codes and modules made it into this carve.)

I'll be putting up some example tooling and use cases in the near future to show what you can actually do with this.

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

Want to see what's supported, or poke at a parser's metadata (where the decode came from, which fields are verified)?

```python
diaggrok.registered_codes()    # -> [0x117E, 0x1375, ...]
diaggrok.parser_info(0x1526)   # -> ParserEntry(name='0x1526', source_type='re', ...)
```

### Bring your own parsers

You don't have to fork to extend it. Drop a `.py` file that calls `@register(...)` into `~/.diaggrok/plugins/` (or point `DIAGGROK_PLUGIN_DIR` at a directory of them), then:

```python
diaggrok.load_plugins()
```

## Scope, and some honesty

This is carved out of an active reverse-engineering project, so a few things are true and worth saying out loud:

* It's Qualcomm-centric. Non-Qualcomm basebands aren't in scope here.
* Coverage is deliberately narrow (GNSS + LTE signal) rather than broad-but-shallow. I'd rather ship a handful of parsers I've checked against real hardware than a pile I guessed at.
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
