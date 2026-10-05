"""0xB9B9 — NR5G CDRX sleep/wakeup record (legacy name `CodeB9B9`).

Registered under the ID-only naming convention (registry name "0xB9B9",
class `Diag0xB9B9`, type string `Diag0xB9B9`). Besides the decoded fields
below, the record keeps the generic fields ``config_word`` (u32@4),
``data_density`` and ``body_raw``.

## Two coupled forms

Runtime extraction of all 8 bearing captures (8.0M records walked) finds
exactly two forms, never crossed:

  64 B  | hdr 02 00 03 00 | u32 @24 = 0x80  |   266 records / 3 captures
                                               RM520N-GL, two firmware builds
  132 B | hdr 02 00 03 00 | u32 @24 = 0x110 | 2,729 records / 5 captures
                                               Inseego M3100 (SDX65),
                                               RM520N-GL (the newer of those builds)

The 132 B form is 91% of the code's corpus. The M3100 + RM520N-GL pairing
is the same firmware-vintage pair behind 0xB8E2 v0x02, 0x1D21 and 0x1D0B,
and the ``02 00 03 00`` header is the same two-u16-half header as 0xB8E2
v0x02.

Byte map (both forms; the 132 B form adds the tail):

    offset 0   : u16 LE  version      = 2        (gated)
    offset 2   : u16 LE  hdr_u16_2    = 3        (gated; meaning unknown)
    offset 4   : u32 LE  sys_time word (config_word), NR frame timing, grounded:
                   bits 29..31 numerology (mu)
                   bits 19..28 SFN (0..1023)
                   bits 15..18 subframe (0..9)
                   bits 10..14 slot within subframe (0..2^mu - 1)
                   bits  0..9  reserved, 0 on 2,995/2,995
    offset 8   : u8      ref_flag     {0, 1}                     (raw)
    offset 9   : u16 LE  ref_ms_counter, candidate SFN*10+subframe
    offset 11  : u8      scs_byte     0x10 * mu                  (2,995/2,995)
    offset 12  : u16 LE  ref_abs_slot, candidate SFN*slots_per_frame + slot
    offset 16  : u8      toggle       {0, 1}                     (raw)
    offset 20  : u32 LE  = 1
    offset 24  : u32 LE  layout_word  0x80 (64 B) / 0x110 (132 B), gated
                                      as a coupled size selector
    offset 28  : u32 LE  = 0x88
    offset 32  : 5 B     ff 01 00 {00,02} ff
    offset 37  : zero to offset 64
    offset 64  : 68 B    tail (132 B form only), byte-identical on all
                         2,729 records: 11 01 00 00, two
                         "?? 03 00 02 00 04 00 01 02 03" blocks (lead 0x01 at
                         [68], 0xff at [96]), zero fill, u32 1 at [128]

## F3 grounding (v0x02)

0xB9B9 is an NR5G ML1 connected-mode DRX (CDRX) sleep/wakeup record. Every
record lands on an MCPM/NRFW wakeup, and on an RM520N-GL capture the plaintext F3
site ``nrfw_cmd_proc_sys.c:8956`` "NRFW: wakeup error recovery ... new wakeup
subframe S, slot L, scs N" fires exactly as often as the log (185/185).

* sys_time SFN + subframe: the next ``nrfw_cmd_proc_sys.c:12299`` "CDRX Error
  RECOVER: ... current frame = F, subframe = S" print is 6..9 subframes after
  the record's (SFN, subframe) on 427/427 joined records, 0 contradicted. The
  joins cover 5 captures, both forms and both numerologies: RM520N-GL 64 B
  mu=0 117/117 (+8/+9), RM520N-GL 132 B mu=1 121/121, M3100 132 B mu=1
  34 + 2 + 153. The records with no print are the mid-cycle repeats that have
  no recovery event of their own.
* numerology: equals the 8956 print's ``scs N`` on 495/495 joins, and
  ``scs_byte >> 4`` equals it too.
* ref_abs_slot (u16 @12): always at slot 0 or 1 of a frame, and 0..18 slots
  before the sys_time slot on all 2,995 records. Its counter rate is 1 slot/ms
  at mu=0 and 2 slots/ms at mu=1, and it stays under 1024 * slots_per_frame.
  That makes it an absolute slot index. Which event it marks (the DRX
  on-duration or sleep start) is not named by any F3 print, so it is a
  candidate.
* ref_ms_counter (u16 @9): below 10240 on 2,995/2,995 and wraps at 10240 on
  M3100 (0x26d5 + 320 -> 0x0015). That makes it an SFN*10+subframe millisecond
  counter. It steps in 320 ms (32-frame) units there and is constant on the
  RM520N 15 kHz camp. Its meaning is a candidate.
* 0x60: present on the RM520N capture (84 events, 5 ids) but none is a DRX or
  sleep event, so it is silent. QCSuper and SCAT do not decode this code.

Every varying byte sits in [5..16] and is shared by both forms, so the tail
carries no per-record data in the corpus. It is exposed as ``tail_raw`` and
``tail_matches_observed``, a flag rather than a gate: a different tail value
at the attested (header, layout_word, size) is reported, not dropped.
Whether layout_word is a bitmask of the sub-blocks present is unverified.

The gate is strict and coupled: version u16 == 2, hdr_u16_2 == 3, and
``len(data) == _FORMS[layout_word]``. Any other header, layout word or size,
or a crossed pair (0x80 at 132 B, 0x110 at 64 B), returns None, so the
registry's dispatch WARN and the unhandled tally report it. A new form is new
firmware or a misframe and must be investigated.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0xB9B9:
    """0xB9B9 — NR5G CDRX sleep/wakeup record: F3-grounded sys_time (legacy `CodeB9B9`)."""
    log_time: int
    version: int
    config_word: int
    data_density: float
    payload_size: int
    body_raw: bytes
    hdr_u16_2: int
    layout_word: int
    tail_raw: bytes
    tail_matches_observed: bool | None
    numerology: int
    sfn: int
    subframe: int
    slot_in_subframe: int
    slot: int
    sys_time_reserved: int
    ref_flag: int
    ref_ms_counter: int
    scs_byte: int
    ref_abs_slot: int
    ref_sfn: int
    ref_slot: int
    toggle: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB9B9",
            "log_time": self.log_time,
            "version": self.version,
            "config_word": self.config_word,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
            "hdr_u16_2": self.hdr_u16_2,
            "layout_word": self.layout_word,
            "tail_raw": self.tail_raw,
            "tail_matches_observed": self.tail_matches_observed,
            "numerology": self.numerology,
            "sfn": self.sfn,
            "subframe": self.subframe,
            "slot_in_subframe": self.slot_in_subframe,
            "slot": self.slot,
            "sys_time_reserved": self.sys_time_reserved,
            "ref_flag": self.ref_flag,
            "ref_ms_counter": self.ref_ms_counter,
            "scs_byte": self.scs_byte,
            "ref_abs_slot": self.ref_abs_slot,
            "ref_sfn": self.ref_sfn,
            "ref_slot": self.ref_slot,
            "toggle": self.toggle,
        }


# The version gate is enforced because size invariance is not format
# invariance: a future v!=0x02 emission at an attested byte count is
# rejected rather than silently mis-parsed as v=0x02. The corpus carries
# two forms, 64 B and 132 B (2,729 records, M3100 SDX65 + RM520N-GL); both
# share the header and u32 @24 selects the size. See the module docstring.
_B9B9_VERSION_OBSERVED = 0x02
_B9B9_HDR_U16_2 = 3
_B9B9_BASE_SIZE = 64
# layout_word (u32 @24) -> the only payload size it is attested at.
_B9B9_FORMS: dict[int, int] = {0x80: 64, 0x110: 132}
# [64:132] of the 132 B form, byte-identical on all 2,729 corpus records.
_B9B9_TAIL_132 = bytes.fromhex(
    "11010000"
    "01030002000400010203" + "00" * 18
    + "ff030002000400010203" + "00" * 22
    + "01000000"
)


@register(
    0xB9B9,
    name="0xB9B9",
    description="0xB9B9 — NR5G CDRX sleep/wakeup record: F3-grounded NR sys_time (mu/SFN/subframe/slot) + candidate reference slot counters (legacy CodeB9B9)",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Runtime extraction of all 8 bearing captures (RM520N-GL, M3100 SDX65): two forms, 64 B (266 records) and 132 B (2,729 records), behind a strict coupled layout_word (u32 @24) -> size gate {0x80: 64, 0x110: 132} and a two-half header check (u16 2, u16 3). u32@4 is F3-grounded as NR CDRX sys_time (mu 29..31 / SFN 19..28 / subframe 15..18 / slot-in-subframe 10..14): the F3 nrfw_cmd_proc_sys.c:12299 CDRX current frame+subframe is +6..+9 subframes after it on 427/427 joins (5 captures, both forms, mu 0 and 1), and the nrfw_cmd_proc_sys.c:8956 scs equals mu on 495/495. u16@12 ref_abs_slot and u16@9 ref_ms_counter are candidates; the 132 B tail is constant across the corpus.",
    source_url="",
    issues=(),
    fields_identified=13,
    fields_parsed=13,
    field_invariants={
        "version": {"enum": [_B9B9_VERSION_OBSERVED]},
        "payload_size": {"enum": sorted(_B9B9_FORMS.values())},
        "subframe": {"range": [0, 9]},
        "ref_ms_counter": {"range": [0, 10239]},
    },
)
def parse_0xb9b9(log_time: int, data: bytes) -> Diag0xB9B9 | None:
    if len(data) < 28:
        return None
    version, hdr_u16_2 = unpack_from('<HH', data, 0)
    if version != _B9B9_VERSION_OBSERVED or hdr_u16_2 != _B9B9_HDR_U16_2:
        return None
    layout_word = unpack_from('<I', data, 24)[0]
    if _B9B9_FORMS.get(layout_word) != len(data):
        return None
    config_word = unpack_from('<I', data, 4)[0]
    nonzero = sum(1 for b in data[2:] if b != 0)
    density = round(nonzero / (len(data) - 2), 2)
    tail_raw = data[_B9B9_BASE_SIZE:]
    mu = config_word >> 29
    subframe = (config_word >> 15) & 0xF
    slot_in_subframe = (config_word >> 10) & 0x1F
    ref_abs_slot = unpack_from('<H', data, 12)[0]
    ref_sfn, ref_slot = divmod(ref_abs_slot, 10 << mu)
    return Diag0xB9B9(
        log_time=log_time,
        version=data[0],
        config_word=config_word,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
        hdr_u16_2=hdr_u16_2,
        layout_word=layout_word,
        tail_raw=tail_raw,
        tail_matches_observed=(tail_raw == _B9B9_TAIL_132) if tail_raw else None,
        numerology=mu,
        sfn=(config_word >> 19) & 0x3FF,
        subframe=subframe,
        slot_in_subframe=slot_in_subframe,
        slot=(subframe << mu) + slot_in_subframe,
        sys_time_reserved=config_word & 0x3FF,
        ref_flag=data[8],
        ref_ms_counter=unpack_from('<H', data, 9)[0],
        scs_byte=data[11],
        ref_abs_slot=ref_abs_slot,
        ref_sfn=ref_sfn,
        ref_slot=ref_slot,
        toggle=data[16],
    )
