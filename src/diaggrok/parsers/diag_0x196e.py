"""0x196E — named configuration-parameter record (fixed 256-byte string slots).

## Not an LTE ML1 / MAC record

Neighbouring codes in this numeric range are LTE ML1 / MAC logs, but this one
is not. Both the record bytes and the co-temporal F3 stream rule that out:

* **Record content is self-labelling.** Every corpus record is a 1281-byte blob
  laid out as **1 version byte + 5 fixed 256-byte NUL-terminated ASCII slots**.
  Slot 0 holds a configuration-parameter *name* — ``"bootupRetryMaxCount"`` in
  all 7 corpus records (RM520N-GL, two firmware builds); the remaining slots
  hold its string-encoded values (``"0"`` and ``"5"`` observed). A named
  key/value config blob is categorically not an LTE MAC/ML1 measurement record.
* **F3 ground truth agrees.** The build-matched QSR4 F3 (100% resolution) in
  the same captures shows only NV/config machinery around this activity —
  ``qpIO.c`` ``qpDplIODevicePutItem: NV_file[/nv/item_files/...]``,
  ``nv_tree_api.cpp`` — and GNSS DM-buffer log-commit (``gnss_diag_buf.c:1141``
  ``gnss_dm_log_commit ... log_code 0x....``). **No** LTE-MAC / LTE-ML1 F3 site
  is co-temporal with 0x196E records.

## Layout (validated against the 7-record RM520N-GL corpus)

    Byte  0        : u8    version   (0x00 across the whole corpus)
    Bytes 1..257   : cstr  name      slot 0 — parameter name  ("bootupRetryMaxCount")
    Bytes 257..513 : cstr  value_0   slot 1  ("0" observed)
    Bytes 513..769 : cstr  value_1   slot 2  ("" observed)
    Bytes 769..1025: cstr  value_2   slot 3  ("5" observed)
    Bytes 1025..1281:cstr  value_3   slot 4  ("" observed)

Each slot is an independent fixed 256-byte field NUL-terminated within itself;
``values`` collects the non-empty value slots in order. The full payload is kept
as ``raw`` so downstream RE can continue if more parameters/slots surface.

The specific parameter observed corpus-wide is a single one
(``bootupRetryMaxCount``); a future capture may carry a different name in slot 0
— the parser decodes whatever name/value strings are present rather than
hard-coding this one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register

_196E_VERSION_OBSERVED = 0x00
_SLOT_SIZE = 256
_N_SLOTS = 5  # 1 name + 4 value slots; 1 + 5*256 = 1281 = corpus record size


def _cstr(data: bytes, start: int, size: int) -> str:
    """Extract a NUL-terminated ASCII string from a fixed-size slot.

    Non-decodable bytes fall back to a lossy decode so a garbled slot never
    crashes the parse (the raw payload is preserved separately).
    """
    slot = data[start:start + size]
    nul = slot.find(b"\x00")
    if nul >= 0:
        slot = slot[:nul]
    try:
        return slot.decode("ascii")
    except UnicodeDecodeError:
        return slot.decode("ascii", "replace")


@dataclass
class Diag0x196E:
    """0x196E — named configuration-parameter record (fixed 256-byte slots)."""
    log_time: int
    version: int
    name: str
    values: list[str]
    payload_size: int
    raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x196E",
            "log_time": self.log_time,
            "version": self.version,
            "name": self.name,
            "values": self.values,
            "payload_size": self.payload_size,
            "raw": self.raw,
        }


@register(
    0x196E,
    name="0x196E",
    description=(
        "0x196E — named configuration-parameter record: u8 version + 5 fixed "
        "256-byte NUL-terminated ASCII slots (slot 0 = parameter name, slots "
        "1-4 = string values). NOT LTE ML1/MAC (record content + F3; see "
        "module docstring)."
    ),
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from a 7-record RM520N-GL corpus. Layout = 1 version "
        "byte + 5x256B NUL-terminated ASCII slots; slot 0 carries the "
        "config-parameter name ('bootupRetryMaxCount' corpus-wide), slots 1-4 "
        "its string values ('0','5' observed). Co-temporal QSR4 F3 (100% "
        "resolution) shows NV/config machinery (qpIO.c NV_file[...], "
        "nv_tree_api.cpp) — no LTE-MAC/ML1 F3 site is tied to this code. "
        "version enum {0x00} = every byte-0 observed. A record shorter than "
        "the 1 + 5x256 B layout returns None (registry WARN)."
    ),
    source_url="",
    issues=(),
    fields_identified=3,
    fields_parsed=3,
    field_invariants={
        "version": {"enum": [0x00]},
    },
    ascii_kinds=("config-token",),
)
def parse_0x196e(log_time: int, data: bytes) -> Diag0x196E | None:
    # The whole 1 + 5x256 B layout must be present: a short record would
    # otherwise decode fewer slots and silently lose values.

    if len(data) < 1 + _N_SLOTS * _SLOT_SIZE:
        return None
    version = data[0]
    if version != _196E_VERSION_OBSERVED:
        return None

    slots = [_cstr(data, 1 + i * _SLOT_SIZE, _SLOT_SIZE) for i in range(_N_SLOTS)]

    name = slots[0] if slots else ""
    values = [s for s in slots[1:] if s]

    return Diag0x196E(
        log_time=log_time,
        version=version,
        name=name,
        values=values,
        payload_size=len(data),
        raw=data,
    )
