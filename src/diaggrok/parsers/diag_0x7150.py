"""0x7150 — ``LOG_UMTS_NAS_EPLMN_LIST`` — NAS equivalent-PLMN list snapshot.

19 B fixed record. Grounded against QCSuper's NAS decode in the two
RM520N-GL SDX62 survey captures that carry a populated list: the 3-byte entry
at [4:7] (``13 02 52``) is a **BCD-encoded equivalent PLMN — 312-250
(T-Mobile US supplemental)** — and that exact PLMN appears in the same
captures' NAS Attach-Accept (EMM 0x42) / TAU-Accept (EMM 0x49)
equivalent-PLMN IE, paired with the serving PLMN 310-260 (T-Mobile).

Layout (19 B fixed):
  [0]      u8    length_marker  0x13 (=19) on every initialized record across all
                                12 chipset families; 0xFF only on uninitialized
                                post-reboot records (whole frame 0xFF-filled).
                                Self-length prefix — NOT the low byte of a u16.
  [1]      u8    field_1        role TBD (RF/NAS-state dependent) — open set
                                {0x00,0x01,0x02,0x03,0x05}; 0xFF uninit. Left raw.
  [2]      u8    field_2        role TBD (RF/NAS-state dependent) — open set
                                {0x01,0x10,0x14,0x38,0x62,0x84,0x91}; 0xFF uninit. Left raw.
  [3]      u8    num_eplmn      count of equivalent PLMNs in the list (0 or 1 across
                                the whole corpus; ==1 ⇔ slot 1 populated). Grounded:
                                perfectly gates the [4:19] array population.
  [4:19]   15B   eplmn_raw      5-slot × 3-byte BCD equivalent-PLMN array. Slot 1 =
                                312-250 on the RM520N-GL surveys; every empty slot is
                                0xFFFFFF (the 3GPP "no PLMN" filler). Every non-RM520N
                                chipset emits num_eplmn=0 → all 5 slots 0xFFFFFF.

### Structure notes
- Bytes [0:4] are not two u16 fields: byte[0] is a const length marker, so u16
  groupings would straddle (const|var) and (var|flag).
- [4:19] is a single 5-entry PLMN array, not a 3-byte payload plus 12 reserved
  bytes: entry 1 is populated, entries 2-5 are empty. Byte[3] is the entry
  **count**, not a presence flag.

Ground truth (RM520N-GL survey, num_eplmn=1):

    13 00 62 01 | 13 02 52 | ff ff ff ff ff ff ff ff ff ff ff ff
    │  │  │  │    └slot1 = BCD PLMN 312-250 (equivalent PLMN)
    │  │  │  └num_eplmn=1
    │  │  └field_2=0x62 (TBD)
    │  └field_1=0x00 (TBD)
    └length_marker=0x13
    └────────────── eplmn_raw [4:19]: slot1 + 4 empty (0xFFFFFF) slots ──────────────┘

No hard byte-0 gate: 0xFF uninitialized records are legitimate observations
(gating would drop them). Drift is caught at Layer-2
via the ``length_marker``/``num_eplmn`` enums.

field_1/field_2 remain ungrounded (role TBD) — the NAS oracle labels the PLMN
list, not these two leading bytes. They are RF/NAS-state dependent and left raw
pending a capture whose F3/NAS layer disambiguates them.

Log name: LOG_UMTS_NAS_EPLMN_LIST
Also known as: LOG_UMTS_NAS_EPLMN_LIST_LOG_PACKET
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register

# 3GPP TS 24.008 §10.5.1.3 "no PLMN" filler — an empty equivalent-PLMN slot.
_EMPTY_PLMN = b"\xff\xff\xff"


def decode_plmn_bcd(three: bytes) -> str | None:
    """Decode a 3-octet BCD PLMN (3GPP TS 24.008 §10.5.1.3) to ``"MCC-MNC"``.

    Returns ``None`` for the all-0xFF empty-slot filler. A trailing MNC digit
    of 0xF signals a 2-digit MNC (rendered without the third digit).
    """
    if len(three) != 3 or three == _EMPTY_PLMN:
        return None
    o1, o2, o3 = three[0], three[1], three[2]
    mcc_d1, mcc_d2 = o1 & 0x0F, o1 >> 4
    mcc_d3 = o2 & 0x0F
    mnc_d3 = o2 >> 4
    mnc_d1, mnc_d2 = o3 & 0x0F, o3 >> 4
    mcc = f"{mcc_d1}{mcc_d2}{mcc_d3}"
    mnc = f"{mnc_d1}{mnc_d2}" if mnc_d3 == 0xF else f"{mnc_d1}{mnc_d2}{mnc_d3}"
    return f"{mcc}-{mnc}"


@dataclass
class Diag0x7150:
    """0x7150 — NAS equivalent-PLMN list snapshot: count + 5-slot BCD PLMN array."""
    log_time: int
    length_marker: int    # [0] u8: 0x13 (=19) initialized; 0xFF uninitialized
    field_1: int          # [1] u8: role TBD (RF/NAS-state dependent), left raw
    field_2: int          # [2] u8: role TBD (RF/NAS-state dependent), left raw
    num_eplmn: int        # [3] u8: count of equivalent PLMNs (0/1 in corpus)
    eplmn_raw: bytes      # [4:19] 5-slot × 3-byte BCD PLMN array (0xFFFFFF = empty)

    def equivalent_plmns(self) -> list[str]:
        """Decoded non-empty equivalent PLMNs as ``"MCC-MNC"`` strings."""
        out = []
        for i in range(0, 15, 3):
            plmn = decode_plmn_bcd(self.eplmn_raw[i:i + 3])
            if plmn is not None:
                out.append(plmn)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x7150',
            'log_time': self.log_time,
            'length_marker': self.length_marker,
            'field_1': self.field_1,
            'field_2': self.field_2,
            'num_eplmn': self.num_eplmn,
            'eplmn_raw_hex': self.eplmn_raw.hex(),
            'equivalent_plmns': self.equivalent_plmns(),
        }


@register(
    0x7150,
    name="LOG_UMTS_NAS_EPLMN_LIST",
    description="0x7150 — NAS equivalent-PLMN list: count + 5-slot BCD PLMN array",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE over a 182-record / 63-capture / ~12-chipset corpus, "
        "semantically grounded against QCSuper's NAS decode in two RM520N-GL "
        "SDX62 survey captures: "
        "the [4:19] region is a 5-slot BCD equivalent-PLMN array, slot 1 = 312-250 "
        "(T-Mobile US supplemental) — the same equivalent PLMN carried in those "
        "captures' NAS Attach/TAU-Accept EMM messages. byte[3]=num_eplmn count; "
        "byte0=0x13 const length marker. field_1/field_2 ungrounded, left raw."
    ),
    issues=(),
    primary_issue=None,
    fields_identified=6,
    fields_parsed=6,
    # Layer-2 drift net. length_marker is 0x13 on initialized records, 0xFF when
    # the whole frame is uninitialized (post-reboot). num_eplmn is the equivalent-
    # PLMN count (0/1 observed). Neither is hard-gated in the body — 0xFF uninit
    # records are real observations that are kept; the enums
    # only flag drift.
    field_invariants={
        "length_marker": {"enum": [0x13, 0xFF]},
        "num_eplmn": {"enum": [0x00, 0x01]},
    },
    # RE-evidenced version-less: parser names byte 0 `length_marker`; corpus byte0 spans 2 value(s) over 307 records.
    version_less=True,
)
def parse_0x7150(log_time: int, data: bytes) -> Diag0x7150 | None:
    if len(data) < 19:
        return None
    return Diag0x7150(
        log_time=log_time,
        length_marker=data[0],
        field_1=data[1],
        field_2=data[2],
        num_eplmn=data[3],
        eplmn_raw=bytes(data[4:19]),
    )
