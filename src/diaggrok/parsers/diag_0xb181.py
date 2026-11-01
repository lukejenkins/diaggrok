"""0xB181 — LTE ML1 intra-frequency cell reselection: subpacket envelope.

Container: the LTE ML1 subpacket envelope shared with 0xB192 /
0xB194. Byte 0 = version (0x01 on every chipset), byte 1 = num_subpackets,
u16@2 = header word, then subpackets ``{id u8, version u8, size u16 (inclusive
of the 4 B subpacket header)}`` that tile the record exactly (134,556/134,556
corpus records). A record that does not tile (short, long, or a subpacket
header that overruns) is rejected (None) with a throttled WARN. Subpacket order is (0x0A, 0x05, 0x0B), or
(0x0A, 0x0B) on SDX20 EG18-NA / SDX72 T99W640.

* **0x0A — serving cell.** v01 (MDM9200 / MDM9625 / BandLuxe C505):
  u16 EARFCN + u16 PCI word. v02 / v38: u32 EARFCN + u32 PCI word. PCI is the
  low 9 bits; bits 9+ are flags (1 on every sample record), the same packing as
  0xB192's per-cell word. The pre-v7 flat ``u32@8`` read was right on v02/v38
  and garbage on v01, where it packs the PCI word above the EARFCN.
* **0x0B — per-frequency reselection measurement list.** A prefix holding the
  count of *other* frequencies, then ``n_other + 1`` frequency entries, each an
  entry header (u32 EARFCN, flags byte, count byte, ...) followed by its cells.
  Every cell starts with the same u16 PCI word. Layout per subpacket version:

  ======  ==============================  =========  ===========  ========
  ver     prefix (n_other)                entry hdr  cell count   cell
  ======  ==============================  =========  ===========  ========
  0x01    none (one entry, u16 EARFCN)    4 B        (b5>>3) + 1  12 B
  0x03    u32, low nibble                 8 B        b5 >> 3      12 B
  0x18    u32                             8 B        b5 >> 3      12 B
  0x20    u32 0, u32                      8 B        b5 >> 3      12 B
  0x28    u32 0, u32                      8 B        b5 >> 3      12 B
  0x38    u32 0, u32                      12 B       b5           12 B
  0x3A    u32 0, u32                      12 B       b5           16 B
  ======  ==============================  =========  ===========  ========

  (b5 = entry byte 5; on v01 the count byte is entry byte 3.) Exact closure on
  every sample record of every version; every decoded PCI is in 0..503.
* **0x05** — not decoded; exposed raw in ``other_subpackets``.

Log name: LOG_LTE_ML1_INTRA_FREQUENCY_CELL_RESELECTION
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0xB181:
    """0xB181 — LTE ML1 intra-frequency cell reselection (subpacket envelope)."""
    log_time: int
    version: int
    config_word: int
    earfcn: int | None
    data_density: float
    payload_size: int
    body_raw: bytes
    num_subpackets: int = 0
    hdr_word: int = 0
    framing_ok: bool = True  # always True: a record that does not tile is rejected
    serving_sp_version: int | None = None
    serving_pci: int | None = None
    serving_pci_flags: int | None = None
    freq_list_version: int | None = None
    frequencies: list[dict[str, Any]] | None = None
    other_subpackets: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB181",
            "log_time": self.log_time,
            "version": self.version,
            "config_word": self.config_word,
            "earfcn": self.earfcn,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
            "num_subpackets": self.num_subpackets,
            "hdr_word": self.hdr_word,
            "framing_ok": self.framing_ok,
            "serving_sp_version": self.serving_sp_version,
            "serving_pci": self.serving_pci,
            "serving_pci_flags": self.serving_pci_flags,
            "freq_list_version": self.freq_list_version,
            "frequencies": self.frequencies,
            "other_subpackets": self.other_subpackets,
        }


# Byte 0 is the DIAG version field: 0x01 on every corpus record, across many
# payload sizes. Size varies with the subpacket content, so there is no
# payload_size invariant (it would reject legitimate records).
_B181_VERSION_OBSERVED = 0x01

_SP_SERVING = 0x0A
_SP_FREQ_LIST = 0x0B
_SERVING_VERSIONS = (0x01, 0x02, 0x38)
_FREQ_LIST_VERSIONS = (0x01, 0x03, 0x18, 0x20, 0x28, 0x38, 0x3A)
_PCI_MASK = 0x1FF
_MAX_FREQS = 32  # sanity bound on the n_other prefix

logger = logging.getLogger(__name__)
_FRAMING_ALARMS: Counter = Counter()


def _framing_alarm(data: bytes, why: str) -> None:
    """WARN on a version-0x01 record whose subpackets do not tile it, so a
    rejected record is not dropped silently. Logs the 1st, 10th, 100th, ... per
    length: the registry's own WARN fires once per (code, version) only."""
    _FRAMING_ALARMS[len(data)] += 1
    n = _FRAMING_ALARMS[len(data)]
    if str(n).rstrip("0") != "1":
        return
    logger.warning(
        "diaggrok 0xB181 framing issue #%d: len=%d, %s — record rejected",
        n, len(data), why,
    )

# 0x0B layout per subpacket version (see the module docstring):
# (prefix bytes, n_other reader, entry-header bytes, count(byte5), cell stride)
_FREQ_LIST_LAYOUT = {
    0x03: (4, lambda b: b[0] & 0x0F, 8, lambda x: x >> 3, 12),
    0x18: (4, lambda b: unpack_from("<I", b, 0)[0], 8, lambda x: x >> 3, 12),
    0x20: (8, lambda b: unpack_from("<I", b, 4)[0], 8, lambda x: x >> 3, 12),
    0x28: (8, lambda b: unpack_from("<I", b, 4)[0], 8, lambda x: x >> 3, 12),
    0x38: (8, lambda b: unpack_from("<I", b, 4)[0], 12, lambda x: x, 12),
    0x3A: (8, lambda b: unpack_from("<I", b, 4)[0], 12, lambda x: x, 16),
}


def _cells(body: bytes, off: int, n: int, stride: int) -> list[dict[str, Any]]:
    out = []
    for k in range(n):
        c = body[off + stride * k: off + stride * (k + 1)]
        word = unpack_from("<H", c, 0)[0]
        out.append({"pci": word & _PCI_MASK, "pci_flags": word >> 9, "raw": c})
    return out


def _decode_serving(ver: int, body: bytes) -> tuple[int, int] | None:
    """(earfcn, pci_word) of subpacket 0x0A, or None for an unknown layout."""
    if ver == 0x01 and len(body) == 4:
        return unpack_from("<HH", body, 0)
    if ver in (0x02, 0x38) and len(body) == 8:
        return unpack_from("<II", body, 0)
    return None


def _decode_freq_list(ver: int, body: bytes) -> list[dict[str, Any]] | None:
    """Frequency entries of subpacket 0x0B, or None unless the layout closes exactly."""
    try:
        if ver == 0x01:
            n = (body[3] >> 3) + 1
            if 4 + 12 * n != len(body):
                return None
            return [{"earfcn": unpack_from("<H", body, 0)[0], "flags": body[2],
                     "count_byte": body[3], "hdr": body[0:4],
                     "cells": _cells(body, 4, n, 12)}]
        lay = _FREQ_LIST_LAYOUT.get(ver)
        if lay is None:
            return None
        prefix, n_other_of, ehdr, count_of, stride = lay
        n_other = n_other_of(body)
        if n_other > _MAX_FREQS:
            return None
        off, freqs = prefix, []
        for _ in range(n_other + 1):
            if off + ehdr > len(body):
                return None
            n = count_of(body[off + 5])
            end = off + ehdr + stride * n
            if end > len(body):
                return None
            freqs.append({"earfcn": unpack_from("<I", body, off)[0],
                          "flags": body[off + 4], "count_byte": body[off + 5],
                          "hdr": body[off:off + ehdr],
                          "cells": _cells(body, off + ehdr, n, stride)})
            off = end
        return freqs if off == len(body) else None
    except IndexError:
        return None


# Serving frequency: the 0x0A EARFCN is the frequency the ML1 reselection
# evaluator is working on, i.e. the serving frequency. On an SDX62 RG520N-NA
# capture it equals the AT+QENG "servingcell" EARFCN and the co-captured
# 0xB193 EARFCN on every record (331/331 and 333/333), and the 0x0A PCI word's
# low 9 bits equal the serving PCI the firmware echoes in the same F3 stream.

@register(
    0xB181,
    name="0xB181",
    description=(
        "0xB181 - LTE ML1 intra-frequency cell reselection: subpacket envelope "
        "(0x0A serving EARFCN/PCI, 0x0B per-frequency reselection measurement "
        "list with per-cell PCI, 0x05 raw); per-subpacket-version layouts, exact "
        "tiling."
    ),
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "The body is the LTE ML1 subpacket envelope shared with 0xB192 / 0xB194; "
        "its subpackets tile 134,556 of 134,556 corpus records exactly, and a record "
        "that does not tile is rejected. 0x0A serving: u16 EARFCN + u16 PCI word on "
        "v01 (MDM9200 / MDM9625 / BandLuxe C505), u32 + u32 on v02 / v38; PCI is the "
        "low 9 bits. (earfcn, pci) equals the co-captured 0xB193 serving cell on every "
        "record checked (FN980 wardrive 2328/2328 across 8+ PCIs, C505 69/69, MC7700 "
        "31/31, T77W595 47/47). F3 grounding: the EARFCN equals rflte_mc_rx.c "
        "'channel:%d' 2328/2328 (including EARFCN 66786, above u16), lte_ml1_cdb.c "
        "'fcn %d' on the C505, and tle_log.c 'DL Freq:%d' on MDM9207. 0x0B "
        "per-frequency reselection list: decoded for subpacket versions "
        "01/03/18/20/28/38/3A with exact closure; at 22 F3 lte_rrc_stm.c "
        "LTE_CPHY_CELL_RESEL_IND events the serving PCI changed 22/22 and the new "
        "PCI was in the prior record's 0x0B cell list 21/22. Byte 0 is 0x01 on every "
        "corpus record; any other value is rejected."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=10,
    fields_parsed=10,
    field_invariants={
        "version": {"enum": [_B181_VERSION_OBSERVED]},
    },
)
def parse_0xb181(log_time: int, data: bytes) -> Diag0xB181 | None:
    if len(data) < 1:
        return None
    version = data[0]
    if version != _B181_VERSION_OBSERVED:
        return None
    if len(data) >= 8:
        config_word = unpack_from('<I', data, 4)[0]
    elif len(data) >= 2:
        config_word = data[1]
    else:
        config_word = 0
    if len(data) > 2:
        nonzero = sum(1 for b in data[2:] if b != 0)
        total = max(len(data) - 2, 1)
        density = round(nonzero / total, 2)
    else:
        density = 0.0
    rec = Diag0xB181(
        log_time=log_time,
        version=version,
        config_word=config_word,
        earfcn=None,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
    if len(data) < 4:
        _framing_alarm(data, "shorter than the 4 B envelope header")
        return None
    rec.num_subpackets = data[1]
    rec.hdr_word = unpack_from("<H", data, 2)[0]

    # Subpacket envelope: {id, version, size incl. 4 B header}, exact tiling.
    subpackets: list[tuple[int, int, bytes]] = []
    off = 4
    for i in range(rec.num_subpackets):
        if off + 4 > len(data):
            _framing_alarm(data, f"subpacket {i} header past the end")
            return None
        sp_id, sp_ver = data[off], data[off + 1]
        sp_len = unpack_from("<H", data, off + 2)[0]
        if sp_len < 4 or off + sp_len > len(data):
            _framing_alarm(data, f"subpacket {i} size {sp_len} overruns")
            return None
        subpackets.append((sp_id, sp_ver, data[off + 4:off + sp_len]))
        off += sp_len
    if off != len(data):
        _framing_alarm(data, f"{len(data) - off} B left after the subpackets")
        return None

    for sp_id, sp_ver, body in subpackets:
        if sp_id == _SP_SERVING and rec.serving_sp_version is None:
            rec.serving_sp_version = sp_ver
            srv = _decode_serving(sp_ver, body)
            if srv is not None:
                rec.earfcn, word = srv
                rec.serving_pci = word & _PCI_MASK
                rec.serving_pci_flags = word >> 9
        elif sp_id == _SP_FREQ_LIST and rec.freq_list_version is None:
            rec.freq_list_version = sp_ver
            rec.frequencies = _decode_freq_list(sp_ver, body)
        else:
            rec.other_subpackets.append({"id": sp_id, "version": sp_ver, "body": body})
    return rec
