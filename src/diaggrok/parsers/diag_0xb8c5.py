"""NR5G L1 measurement parsers (0xB8C5).

NR5G Layer 1 Measurement Status. v0x02 is emitted by SDX55 (RM500Q-AE /
EM9190 / FN980m / M2000 / RXM-G1); v0x00 by SDX62 (RM520N-GL). Both carry
ONE record per 1 ms subframe.

## TLV element model

Both versions wrap the same element list in a 0xFC container. Every element
starts with a u32 header packed as ``type:8 | length:12 | flags:12``; the
length INCLUDES the header, and the elements must tile the container exactly.

    v0x02:  [0] version=0x02, [1:4] zero, [4:8] 0xFC container header
            (12-bit length = size-4), elements from [8]
    v0x00:  [0:12] preamble (version 0x00, sub_type 0x02, u32 timestamp,
            u32 const 1 — see _v0_tlv.py), [12:16] 0xFC container header
            (length = size-12), elements from [16]

    element type 0x00, length 32 — one measurement entry:
        [+0:4]   element header (flags 0x001 on the first entry, 0x008 after)
        [+4:8]   u32 pre_word (1 on v0x02, 0 on v0x00)
        [+8:32]  six u32 words (below)
    element type 0xFE, length 4 — terminator (flags 0x008, or 0x001 twice in
        the container-only 16B record that carries no entries)

The byte[5] values 0x28 / 0x48 / 0x0c, which track record size, are the low
byte of the container length, and the per-element ``block_flags`` byte
(0x10 / 0x80) is the element header's flag nibble. Walking by length decodes
every size class; a fixed ``(size-12)//32`` entry count covers only the 32N
family.

Whole-corpus validation (168/169 sessions; the 169th, a 3,160-record EM9190
capture, could not be read by the capture reader):
v0x02 4,217,950 / 4,217,970 records tile the grammar (the 20 misses are
non-4-aligned HDLC misframes), v0x00 151,777 / 151,778. Only two element
kinds occur: 0x00/len 32 and 0xFE/len 4. Every one of 4,425,357 entries
has subframe < 10, and consecutive records step SFN*10+subframe by exactly
1 on 96.3% (v0x02) / 87.2% (v0x00) of pairs.

Entry words (offsets within the 24-byte entry):
    [+0:4]   word 0 — SFN/subframe timestamp. **F3-GROUNDED:**
             bits[19:10] = SFN — equals the firmware's own
             ``nrfw_iu_cfg.c`` "cmd id = N, sfn = M" print on 916/924
             time-joins (SDX55 RM500Q v0x02, site :4423) and 240/264 (SDX62
             RM520N v0x00, site :5014), and 50/50 on a second SDX55 vendor
             (Compal RXM-G1 v0x02). Shifted-bit-window nulls peak at
             54/924, 4/264 and 4/50.
             bits[9:6] = subframe 0..9 (steps one per record, wraps into
             SFN+1). bits[5:0] = ``entry_tag`` and bits[31:20] =
             ``word0_hi`` are ungrounded (tag steps by 0x20 across entries
             of one record).
    [+4:8]   u32 — ~0x257FFC..0x258000, slow drift; role ungrounded.
    [+8:12]  u32 — a free-running counter, not a measurement: unique on
             every record, high u16 advances exactly +75 per 1 ms record,
             low u16 drifts slowly. (Exposed as ``meas_word``/``meas_lo``/
             ``meas_hi`` for compatibility; the name is historical.)
    [+12:16] u32 status_flags — cycles 0 / 0x3c010 / 0x78010 / 0xb4010
             (bits[19:12] step by 60) with period 5 records; role ungrounded.
    [+16:20] v0x02: bitmask, mostly 0xFFFFFFFF / 0xFFFFFFFE / 0xFFFF0FFF
             (``is_valid`` = != 0xFFFFFFFF — CANDIDATE name).
             v0x00: 0 / 1 — exposed raw as ``word4``.
    [+20:24] v0x02 ``beam_mask`` — CANDIDATE only: mixes 0x1f / 0xdc with
             0x27fb00d7-style values whose bytes do not read as one u32.
             An r=-0.94 correlation against AT-reported RSRP is a mode-segment
             confound (this word changes in long constant runs), not an RSRP
             encoding. v0x00: 0x0100012d-style — exposed raw as ``word5``.

Neither QCSuper nor SCAT decodes 0xB8C5. In-capture evidence: F3 labels the
SFN (above). ``0x60``: present but silent — 6,433 events / 122 ids across
both grounding captures, and the NR5G ones are RRC-level only (UL msg,
HO, new-cell); none carries an NR ML1 SFN or measurement payload.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_NR5G_L1_MEAS_STATUS
from diaggrok.parsers._v0_tlv import V0TlvRecord, parse_v0_tlv
from diaggrok.registry import register


# --- TLV element grammar ---------------------------------------------------
# Both versions carry the same element list. Each element starts with a u32
# header packed as type:8 | length:12 | flags:12 (length INCLUDES the header).
# v0x02 opens the 0xFC container at [4], v0x00 at [12] (after its own 12-byte
# preamble). Inside: type 0x00 len 32 = one measurement entry, type 0xFE len 4
# = terminator. The size-tracking byte[5] (0x28/0x48/0x0c) and "block_flags"
# byte (0x10/0x80) are this header's length and flags.
TLV_CONTAINER = 0xFC
TLV_ENTRY = 0x00
TLV_TERMINATOR = 0xFE
ENTRY_ELEMENT_LEN = 32


@dataclass
class Nr5gTlvElement:
    """One TLV element inside the 0xFC container."""

    elem_type: int
    length: int
    flags: int  # header bits [31:20] — 0x001 on the first entry, 0x008 after
    offset: int

    def to_dict(self) -> dict[str, Any]:
        return {"elem_type": self.elem_type, "length": self.length,
                "flags": self.flags, "offset": self.offset}


def walk_tlv_elements(data: bytes, start: int) -> list[Nr5gTlvElement] | None:
    """Walk TLV elements from ``start`` to the end of ``data``.

    Returns None unless the element lengths tile the remainder exactly — a
    record that does not tile is mis-framed, and a partial walk would hand
    back garbage elements.
    """
    elements: list[Nr5gTlvElement] = []
    off = start
    while off + 4 <= len(data):
        hdr = unpack_from("<I", data, off)[0]
        length = (hdr >> 8) & 0xFFF
        if length < 4 or off + length > len(data):
            return None
        elements.append(Nr5gTlvElement(hdr & 0xFF, length, hdr >> 20, off))
        off += length
    return elements if off == len(data) else None


def _sfn_fields(word0: int) -> dict[str, int]:
    """Split entry word 0: F3-grounded SFN/subframe timestamp.

    bits[19:10] = SFN — matches the firmware's own ``nrfw_iu_cfg.c``
    ``sfn = N`` print on 916/924 joins (SDX55 v0x02) and 240/264 (SDX62
    v0x00); bits[9:6] = subframe 0..9 (one record per 1 ms subframe);
    bits[5:0] and [31:20] are not grounded and stay raw.
    """
    return {
        "entry_tag": word0 & 0x3F,
        "subframe": (word0 >> 6) & 0xF,
        "sfn": (word0 >> 10) & 0x3FF,
        "word0_hi": word0 >> 20,
    }


@dataclass
class Nr5gL1MeasEntry:
    """A single L1 measurement entry from 0xB8C5 v0x02 (TLV type 0x00)."""

    entry_header: int  # word 0 — the SFN/subframe timestamp word
    timing_field: int
    meas_word: int  # word 2 — a free-running counter, not a measurement
    meas_lo: int  # low 16 bits of meas_word
    meas_hi: int  # high 16 bits of meas_word (+75 per 1 ms record)
    status_flags: int
    is_valid: bool  # True when validity_mask != 0xFFFFFFFF
    beam_mask: int
    block_flags: int | None = None  # header byte +2 (= elem flags << 4) — kept for compat
    sfn: int = 0
    subframe: int = 0
    entry_tag: int = 0
    word0_hi: int = 0
    elem_flags: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = {
            "entry_header": self.entry_header,
            "sfn": self.sfn,
            "subframe": self.subframe,
            "entry_tag": self.entry_tag,
            "word0_hi": self.word0_hi,
            "meas_lo": self.meas_lo,
            "meas_hi": self.meas_hi,
            "status_flags": self.status_flags,
            "is_valid": self.is_valid,
            "beam_mask": self.beam_mask,
            "elem_flags": self.elem_flags,
        }
        if self.block_flags is not None:
            d["block_flags"] = self.block_flags
        return d


@dataclass
class Nr5gL1MeasEntryV0:
    """A v0x00 (SDX62) entry. Words 0-3 match v0x02; words 4-5 hold a
    different, ungrounded layout (0/1 and 0x0100012d-style), so they stay raw.
    """

    entry_header: int
    word1: int
    counter: int
    status_flags: int
    word4: int
    word5: int
    sfn: int = 0
    subframe: int = 0
    entry_tag: int = 0
    word0_hi: int = 0
    elem_flags: int = 0
    pre_word: int = 0  # u32 between element header and entry (0 on v0x00, 1 on v0x02)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_header": self.entry_header, "sfn": self.sfn,
            "subframe": self.subframe, "entry_tag": self.entry_tag,
            "word0_hi": self.word0_hi, "word1": self.word1,
            "counter": self.counter, "status_flags": self.status_flags,
            "word4": self.word4, "word5": self.word5,
            "elem_flags": self.elem_flags, "pre_word": self.pre_word,
        }


@dataclass
class Diag0xB8C5:
    log_time: int
    version: int
    record_descriptor: int
    meas_config: int
    num_entries: int
    payload_size: int
    entries: list[Nr5gL1MeasEntry] = field(default_factory=list)
    num_blocks: int = 0  # count of TLV type-0x00 entry elements
    elements: list[Nr5gTlvElement] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "Diag0xB8C5",
            "log_time": self.log_time,
            "version": self.version,
            "record_descriptor": self.record_descriptor,
            "meas_config": self.meas_config,
            "num_entries": self.num_entries,
            "num_blocks": self.num_blocks,
            "payload_size": self.payload_size,
        }
        if self.entries:
            d["entries"] = [e.to_dict() for e in self.entries]
        if self.elements:
            d["elements"] = [e.to_dict() for e in self.elements]
        return d


# --- Ground-truth recipe (Inseego M2000 / SDX55 target) ---------------------
# Offline recipe (not hardware-run): a discovery design for the ungrounded
# entry words (meas_word is a counter; words 1, 3-5 have no grounded role).
# The M2000 (SDX55) emits v=0x02; the v=0x00 variant is the SDX62 minority,
# so this recipe is pinned to v2. The M2000 has no vendor-specific signal AT
# command; ground via QMI_NAS GetSignalInfo (NR5G serving RSRP/RSRQ/SNR) +
# 3GPP AT+CESQ.

@register(
    LOG_NR5G_L1_MEAS_STATUS,
    primary_issue=None,
    name="0xB8C5",
    description="NR5G L1 per-subframe measurement status — TLV element list, F3-grounded SFN/subframe (v=0x02 + v=0x00)",
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "TLV element grammar shared by v0x02 (SDX55) and v0x00 (SDX62): a "
        "0xFC container of elements with a u32 type:8|len:12|flags:12 header; "
        "the elements tile the container on 4,217,950/4,217,970 v0x02 and "
        "151,777/151,778 v0x00 corpus records (misses are HDLC misframes). "
        "Entry word 0 SFN/subframe is F3-grounded against nrfw_iu_cfg.c "
        "'sfn = N' (916/924 SDX55, 240/264 SDX62, 50/50 RXM-G1); word 2 is a "
        "free-running counter, not a measurement. A record shorter than its "
        "0xFC container length (or < 8 B on v0x02), or whose TLV elements do "
        "not tile the container, returns None (registry WARN) rather than a "
        "header-only record with the entries silently dropped. QCSuper and "
        "SCAT do not decode this code; the remaining entry words stay raw or "
        "CANDIDATE."
    ),
    source_url="https://github.com/lukejenkins",
    # v=0x02 is the majority at sizes 44B/76B/16B; v=0x00 is a minority
    # variant at sizes 52B/84B/24B. Byte 5 (the container length's low byte)
    # tracks size: 0x28 → 44B (1-entry), 0x48 → 76B, 0x0c → 16B (sentinel).
    # v=0x00 dispatches into the shared parse_v0_tlv decoder. Both versions
    # enforce a strong layer-1 gate before structural decode.
    field_invariants={"version": {"enum": [0x00, 0x02]}},
    fields_identified=10,
    fields_parsed=10,
)
def parse_0xb8c5(
    log_time: int, data: bytes
) -> Diag0xB8C5 | V0TlvRecord | None:
    """Parse 0xB8C5 — NR5G L1 Measurement Status (v=0x02 and v=0x00).

    Both versions are a 0xFC container of TLV elements (module docstring).
    v0x02 returns ``Diag0xB8C5`` with one ``Nr5gL1MeasEntry`` per type-0x00
    element; v0x00 returns the shared ``V0TlvRecord`` with its ``entries``
    filled by ``Nr5gL1MeasEntryV0``. Each entry carries the F3-grounded
    ``sfn`` / ``subframe`` from word 0. A record that is shorter than its
    0xFC container declares, or whose elements do not tile the container,
    returns None (registry WARN); a v0x02 record longer than its
    container decodes header-only (no elements, no entries).
    """
    if len(data) < 4:
        return None

    version = data[0]
    if version == 0x00:
        rec = parse_v0_tlv(log_time, data)
        if rec is not None:
            # parse_v0_tlv already enforces container length == size-12; an
            # element list that then fails to tile it is malformed.
            v0_elements = walk_tlv_elements(data, 16)
            if v0_elements is None:
                return None
            for el in v0_elements:
                if el.elem_type != TLV_ENTRY or el.length != ENTRY_ELEMENT_LEN:
                    continue
                pre, w0, w1, w2, w3, w4, w5 = unpack_from("<7I", data, el.offset + 4)
                rec.entries.append(Nr5gL1MeasEntryV0(
                    entry_header=w0, word1=w1, counter=w2, status_flags=w3,
                    word4=w4, word5=w5, elem_flags=el.flags, pre_word=pre,
                    **_sfn_fields(w0),
                ))
        return rec
    if version != 0x02:
        return None
    if len(data) < 8:
        return None  # no room for the 0xFC container header
    record_descriptor = unpack_from("<I", data, 4)[0]
    meas_config = unpack_from("<I", data, 8)[0] if len(data) >= 12 else 0
    num_entries = unpack_from("<I", data, 12)[0] if len(data) >= 16 else 0

    # TLV body decode. The 0xFC container header sits at [4] and its 12-bit
    # length must equal size-4; the elements after it are walked by length, so
    # every size class decodes (a fixed "(size-12)//32" count covers only the
    # 32N family).
    size = len(data)
    elements: list[Nr5gTlvElement] = []
    entries: list[Nr5gL1MeasEntry] = []
    if data[4] == TLV_CONTAINER:
        container_len = (record_descriptor >> 8) & 0xFFF
        if container_len > size - 4:
            # The container declares more bytes than the record holds
            # (truncated) — fail loud (registry WARN), not header-only.
            return None
        if container_len == size - 4:
            walked = walk_tlv_elements(data, 8)
            if walked is None:
                return None  # elements overrun/do not tile the container
            elements = walked
        # container_len < size-4: unexplained trailing bytes — kept header-only.
    for el in elements:
        if el.elem_type != TLV_ENTRY or el.length != ENTRY_ELEMENT_LEN:
            continue
        off = el.offset + 8
        w0, timing_field, meas_word, status_flags, validity_mask, beam_mask = \
            unpack_from("<6I", data, off)
        entries.append(
            Nr5gL1MeasEntry(
                entry_header=w0,
                timing_field=timing_field,
                meas_word=meas_word,
                meas_lo=meas_word & 0xFFFF,
                meas_hi=(meas_word >> 16) & 0xFFFF,
                status_flags=status_flags,
                is_valid=(validity_mask != 0xFFFFFFFF),
                beam_mask=beam_mask,
                block_flags=data[el.offset + 2],
                elem_flags=el.flags,
                **_sfn_fields(w0),
            )
        )
    num_blocks = len(entries)

    return Diag0xB8C5(
        log_time=log_time,
        version=version,
        record_descriptor=record_descriptor,
        meas_config=meas_config,
        num_entries=num_entries,
        payload_size=size,
        entries=entries,
        num_blocks=num_blocks,
        elements=elements,
    )
