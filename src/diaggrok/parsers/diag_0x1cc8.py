"""UICC/SIM APDU-parse F3 trace parser (0x1CC8).

Reverse-engineered from a Sierra EM9291 (SDX62) edge-case corpus (102
records across 8 scenarios) and corroborated against the RM520N-GL (SDX62)
header fingerprint.

## This is a UIM trace, not NR5G ML1 / a beam-measurement table

The ``0x1Cxx`` code range and the 11316-B fixed size suggest an NR5G "SSB
beam-sweep measurement table", but every record carries a human-readable
**UICC/SIM APDU parsing trace** — the modem's UIM subsystem dumping an
ISO-7816 APDU parse as F3 debug text. Observed content:

    "APDU Parsing", "UICC instruction class", "CLA - No SM used between
     terminal and card", "Logical Channel: 0", "slot value:1",
     command names: SELECT / STATUS / GET RESPONSE / UPDATE BINARY /
     UPDATE RECORD, "Status Words - 0x90 0x00 - Normal ending of the
     command", "P1 - ...", "P2 - ...", FCP template fields, EF File IDs
     (0x6F06 EF_ARR, 0x6F08, 0x6F09, 0x4F20, ...).

So the family is **UIM / UICC**, not NR5G ML1. bytes[1:3] are one u16 LE
sequence counter (byte[2] is its high byte, not a slot/state field — see
below). The byte[0] version gate guards against a same-size foreign payload.

## Layout (grounded over 102 EM9291 records)

    [0]      u8    version        0x03   (Layer-1 gate)
    [1:3]    u16LE seq            log sequence counter. Strictly increasing by
                                  timestamp; +2/+4/+6 per logged APDU (one
                                  uim_send_command between records), so NOT a
                                  pure APDU count — kept as a raw counter.
    [3]      u8    slot           UICC slot (1-based). Self-labelled: equals the
                                  record's own "slot value:N" text line in 10/10
                                  corpus records (T99W640 carries 1 AND 2).
    [4]      u8    const_4        0x05   (corpus-constant)
    [5]      u8    byte5          varies (0x00 dominant; length/flag candidate)
    [6:10]   4B    zero
    [10:..]  C-str command name (the APDU command — SELECT/STATUS/GET
                                 RESPONSE/UPDATE BINARY/UPDATE RECORD/...),
                                 then NUL-delimited APDU-parse text lines,
                                 then zero padding to offset 10562.
    [10562:11316] 754B trailer   SDX62 ONLY (RM520N-GL / EM9291): binary, not
                                 decoded; ABSENT on SDX7x (T99W640).

## F3 grounding (v0x03)

Each record is time-joined against the UIM driver's own per-APDU F3 print
``uim.c:2036 "UIM_%d: cmd status 0x%x SW1 0x%x,SW2 0x%x, Response data length
0x%x"`` (RM520N-GL SDX62, 0x79 plaintext + 0x99):

* ``status_word`` == the F3's SW1/SW2 in **11/11** records, 2 captures / 2
  firmware builds (6x STATUS 90 00 on one; ENVELOPE 91 2B, FETCH 90 00,
  TERMINAL RESPONSE 91 13 / 90 00 on the other). |dt| <= 1.0 ms.
* ``slot`` == the F3's ``UIM_<n>`` instance in 11/11.
* The command token agrees with the preceding ``uimgen.c "Received generic
  command 0x102"`` → ``uimdrv_hal_iso.c uim_send_command`` pair (~9 ms before).
* ``seq``: bytes[1:3] as ONE u16 LE — 62 records / 3 captures strictly
  increasing, carrying across the byte boundary (0x50fe→0x5104,
  0x3bfd→0x3c01, 0x05ff→0x0603). Every per-firmware byte[2] value in the
  corpus (0x04/0x05, 0x0e/0x0f, 0x3b/0x3c, 0x50/0x51, 0xd8/0xd9) is an
  adjacent pair = a counter's high byte; T99W640 shows 0x00 because its
  captures are shortly after boot.
* ``slot`` on the SDX7x form: == the text's ``slot value:N`` 7/7 in a
  T99W640 F3 capture (slots 1 and 2); that capture's F3 mask did not
  include UIM, so the SW join is SDX62-only.

## Size model — a 10562-B body plus an optional 754-B trailer

The record size differs by chipset family, so a single fixed-size gate
would drop every Foxconn T99W640 (SDX7x) record. Corpus sizes:

* **11316 B** — 13,328 records, SDX62 (RM520N-GL, EM9291).
* **10562 B** — 11 records, 100% T99W640, all from clean DLF captures. Same
  layout (command @10, "APDU Parsing" @322, NUL-terminated text, zero pad) and
  ALL post-text content in the SDX62 form starts at >= 10562 — so 11316 =
  10562 + a 754-B SDX62-only trailer, and SDX7x simply omits it. Independently
  confirmed by the misframes below: one embeds a complete inner 0x1CC8 frame
  whose own length field is 0x294E = 12-B log header + **10562**.
* **8166 / 10585..10722 B** — ~68 records, T99W640 HDLC captures only. NOT a
  variant: a (truncated) 0x1CC8 body with the NEXT 0x98-wrapped LOG_F frame(s)
  (e.g. ``98 01 00 00 01 00 00 00 10 00 34 00 34 00 b7 19 …``) glued on under
  one outer length. Rejected.

So the gate is the coupled map ``_SIZE_TO_TRAILER = {10562: 0, 11316: 754}``.
Any other size returns None and ``registry.parse()`` emits a loud WARN and
tally — the code fails loudly on an unexpected size rather than silently
dropping it.

## Content

A UICC APDU trace can carry SIM-file contents: a READ BINARY / READ RECORD on
EF_IMSI (0x6F07), EF_ICCID (0x2FE2), EF_MSISDN (0x6F40), etc. dumps the
subscriber IMSI / ICCID / MSISDN into the response text. The parser decodes the
full parse trace faithfully into ``apdu_text`` — the tool never withholds
content — alongside the structured command token, status word, and EF File
IDs. (The EM9291 sample used for the layout is SIM-less: config EFs only.)

## Name

The name tables list this code as ``RESERVED``. The observed bytes are
unambiguously a UICC APDU parse trace, so the operative name is UIM/UICC
APDU-parse.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from diaggrok.codes import LOG_UIM_APDU_PARSE_1CC8
from diaggrok.registry import register

_EXPECTED_VERSION = 0x03
# Accepted payload size -> length of the chipset trailer it carries.
# 10562 = the common body (SDX7x / T99W640); 11316 = body + 754-B SDX62 trailer.
_BODY_SIZE = 10562
_SIZE_TO_TRAILER = {_BODY_SIZE: 0, 11316: 754}
_APDU_TEXT_OFFSET = 10

# Recognition marker — present in 102/102 observed records.
_APDU_MARKER = b"APDU Parsing"
# "Status Words - 0x90 0x00" → capture the two SW bytes (non-PII).
_SW_RE = re.compile(rb"Status Words - (0x[0-9A-Fa-f]{2}) (0x[0-9A-Fa-f]{2})")
# EF File IDs referenced in the parse (e.g. "File ID : 0x6F06"). Standard
# 3GPP elementary-file identifiers — not PII.
_FILE_ID_RE = re.compile(rb"File ID\s*:?\s*0x([0-9A-Fa-f]{4})")
# Known ISO-7816 / UICC command tokens observed at offset 10. Anything outside
# this set is surfaced verbatim (still just a command token, never response
# data) so a new command name is visible rather than silently dropped.
_KNOWN_COMMANDS = frozenset({
    "SELECT", "STATUS", "GET RESPONSE", "UPDATE BINARY", "UPDATE RECORD",
    "READ BINARY", "READ RECORD", "VERIFY", "MANAGE CHANNEL", "AUTHENTICATE",
})


@dataclass
class Diag0x1CC8:
    """UICC/SIM APDU-parse F3 trace (0x1CC8).

    The full APDU-parse text is decoded into ``apdu_text``; the
    structured fields (command / status word / EF File IDs) are a convenience
    index over it.
    """
    log_time: int
    version: int             # byte0 == 0x03 (Layer-1 gate)
    seq: int                 # bytes[1:3] u16 LE — log sequence counter
    slot: int                # byte3 — UICC slot, == the text's "slot value:N"
    byte5: int               # byte5 — length/flag candidate
    payload_size: int
    trailer_len: int         # 754 on SDX62 (11316 B), 0 on SDX7x (10562 B)
    is_apdu_parse: bool      # "APDU Parsing" marker present
    command: str             # APDU command token at offset 10
    command_known: bool      # True iff command ∈ the ISO-7816 enum
    status_word: str | None  # e.g. "0x90 0x00", or None
    file_ids: list[str] = field(default_factory=list)  # EF IDs, hex
    ascii_byte_count: int = 0  # count of printable bytes (text size proxy)
    apdu_text: str = ""      # the full decoded APDU-parse trace (faithful decode)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1CC8',
            'log_time': self.log_time,
            'version': self.version,
            'seq': self.seq,
            'slot': self.slot,
            'byte5': self.byte5,
            'payload_size': self.payload_size,
            'trailer_len': self.trailer_len,
            'is_apdu_parse': self.is_apdu_parse,
            'command': self.command,
            'command_known': self.command_known,
            'status_word': self.status_word,
            'file_ids': self.file_ids,
            'ascii_byte_count': self.ascii_byte_count,
            'apdu_text': self.apdu_text,
        }


def _cstr(data: bytes, off: int) -> str:
    end = data.find(b"\x00", off)
    raw = data[off:end] if end != -1 else data[off:]
    return raw.decode("latin1", "replace").strip()


def _extract_apdu_text(data: bytes, marker: bytes) -> str:
    """Decode the full APDU-parse trace: the newline-separated block anchored at
    the ``marker`` ("APDU Parsing") and terminated by the first NUL (after which
    the record is zero/0xFF padding). Faithful decode — the tool never
    withholds this text (on a registered capture the SIM-file contents ride here
    in full)."""
    start = data.find(marker)
    if start == -1:
        return ""
    end = data.find(b"\x00", start)
    if end == -1:
        end = len(data)
    region = data[start:end].rstrip(b"\xff\x00")
    return region.decode("latin1", "replace")


@register(
    LOG_UIM_APDU_PARSE_1CC8,
    name="0x1CC8",
    description="UICC/SIM APDU-parse F3 trace — v=0x03, 10562B body (SDX7x) or 11316B = body + 754B trailer (SDX62) (UIM, NOT NR5G ML1)",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from a Sierra EM9291 (SDX62) edge-case corpus (102 "
        "records / 8 scenarios), corroborated against the RM520N-GL SDX62 "
        "header fingerprint and the Foxconn T99W640 (SDX7x) form. Every record "
        "is a human-readable UICC/SIM ISO-7816 APDU parsing trace (APDU Parsing "
        "/ UICC instruction class / SELECT / STATUS / GET RESPONSE / UPDATE "
        "BINARY / UPDATE RECORD / Status Words 0x90 0x00 / FCP template / EF "
        "File IDs), not an NR5G ML1 beam table. Size gate {10562: 0, 11316: "
        "754}: SDX7x emits the 10562-B common body, SDX62 appends a 754-B "
        "trailer; the 8166 / 10585..10722-B HDLC blobs (a body with the next "
        "0x98-wrapped LOG_F frame glued on) are rejected -> registry WARN. "
        "F3-grounded on SDX62: status_word and slot match uim.c:2036 'UIM_<n>: "
        "cmd status SW1/SW2' in 11/11 records (2 captures, two firmware builds, "
        "|dt|<=1 ms). bytes[1:3] are one u16 LE sequence counter (62 records / "
        "3 captures strictly increasing, clean byte carries); slot (byte3) == "
        "the text's 'slot value:N'. Decodes the command token, status word, EF "
        "File IDs, counts, and the complete apdu_text. The trace can carry "
        "SIM-file contents (IMSI/ICCID/MSISDN) on registered captures; they are "
        "decoded faithfully."
    ),
    source_url="",
    issues=(),
    field_invariants={
        "version": {"enum": [_EXPECTED_VERSION]},
        "payload_size": {"enum": sorted(_SIZE_TO_TRAILER)},
    },
    # ASCII: classifies the content this record carries — free-text F3
    # APDU-parse prose (f3-debug) that can embed SIM-file identifiers
    # (identifier). Content classification only; the decoder emits the full
    # apdu_text faithfully.
    ascii_kinds=("f3-debug", "identifier"),
    fields_identified=13,
    fields_parsed=13,
)
def parse_0x1cc8(log_time: int, data: bytes) -> Diag0x1CC8 | None:
    """Parse a UICC/SIM APDU-parse trace (0x1CC8).

    Layer-1 gates (version-byte-first): ``byte0 == 0x03`` AND a size in the
    coupled ``_SIZE_TO_TRAILER`` map (10562 SDX7x body / 11316 SDX62
    body+trailer). Any other size — e.g. a body fused with the next 0x98
    frame — returns None, which ``registry.parse()`` turns into a loud WARN
    + tally (never a silent drop). Size alone is NOT a
    format guarantee — a future layout under a different version byte is
    rejected by the byte-0 gate, not silently mis-parsed.
    """
    trailer_len = _SIZE_TO_TRAILER.get(len(data))
    if trailer_len is None:
        return None
    if data[0] != _EXPECTED_VERSION:
        return None

    is_apdu_parse = _APDU_MARKER in data
    command = _cstr(data, _APDU_TEXT_OFFSET)

    sw_match = _SW_RE.search(data)
    status_word = (
        f"{sw_match.group(1).decode()} {sw_match.group(2).decode()}"
        if sw_match else None
    )

    # Dedup EF File IDs preserving first-seen order (standard 3GPP IDs, non-PII).
    file_ids: list[str] = []
    seen: set[str] = set()
    for m in _FILE_ID_RE.finditer(data):
        fid = "0x" + m.group(1).decode().upper()
        if fid not in seen:
            seen.add(fid)
            file_ids.append(fid)

    ascii_byte_count = sum(1 for b in data if 0x20 <= b <= 0x7E)
    apdu_text = _extract_apdu_text(data, _APDU_MARKER)

    return Diag0x1CC8(
        log_time=log_time,
        version=data[0],
        seq=data[1] | (data[2] << 8),
        slot=data[3],
        byte5=data[5],
        payload_size=len(data),
        trailer_len=trailer_len,
        is_apdu_parse=is_apdu_parse,
        command=command,
        command_known=command in _KNOWN_COMMANDS,
        status_word=status_word,
        file_ids=file_ids,
        ascii_byte_count=ascii_byte_count,
        apdu_text=apdu_text,
    )
