"""0x7160 — LOG_UMTS_NAS_PPLMN_LIST, the NAS preferred-PLMN list.

Full decode: 4-byte header + a fixed 1000-slot table of
per-(PLMN, RAT-set) entries, of which the first ``entry_count`` are live. The
list is the SIM-derived **preferred PLMN list** that REG uses for PLMN
selection (3GPP TS 23.122 §4.4.3): an optional **user-controlled** block
(EF_PLMNwAcT) followed by the **operator-controlled** block (EF_OPLMNwAcT),
each entry carrying the access technologies the SIM's AcT bitmask allows.

## Layout

  byte[0]    = version       0x01 (SDX20) | 0x02 (SDX55 / SDX62 / SDX65)
  byte[1]    = sub_flag      corpus-invariant 0x01 (role unknown; CANDIDATE:
                             subscription / list-set id — raw, not named)
  bytes[2:4] = entry_count   LE u16 — live entries at the head of the table
  bytes[4:]  = entry table   1000 fixed slots, stride = 8 B (v1) / 9 B (v2):

      +0  plmn[3]     3GPP TS 24.008 §10.5.1.3 BCD PLMN; FF FF FF = the SIM
                      record is unset ("undefined" slot, still counted)
      +3  category    u8  2 = USER_PREFERRED (UPLMN, EF_PLMNwAcT)
                          3 = OPERATOR_PREFERRED (OPLMN, EF_OPLMNwAcT)
      +4  num_rats    u8  number of valid rat[] entries (1..3 v1, 1..4 v2)
      +5  rat[N]      u8 × 3 (v1) / × 4 (v2) — sys RAT enum, priority order:
                          0 GSM, 1 UMTS, 2 LTE, 3 TDS, 4 NR5G
                      slots past num_rats are NOT initialised (stale stack
                      bytes, e.g. ASCII fragments) and are not decoded.

  Slots past ``entry_count`` are likewise uninitialised buffer and are not
  decoded. v1 = 4 + 1000×8 = 8004 B; v2 = 4 + 1000×9 = 9004 B — the second
  version adds one rat[] slot for NR5G, nothing else.

## Evidence (760 records, 77 captures — 23 v1 on LM960 / MC7411 /
## EM7565; 737 v2 on RM520N-GL / RG520N / FN980 / FT980 / LV55 / EM9291 /
## SIM8202G — zero violations of every rule below)

* **Stride.** Every live v2 entry parses on a 9 B stride and every v1 entry
  on 8 B — the 3-byte BCD PLMN recurs every 9 / 8 bytes from offset 4.
  The body is not 100 slots × 90 B / 80 B.
* **entry_count = SIM EF sizing.** Observed {70, 100, 140, 200}. The live
  entries are always one ``category=2`` run followed by one ``category=3``
  run, and the run lengths are 50 / 70 / 100 — the EF_PLMNwAcT /
  EF_OPLMNwAcT record capacities (TS 31.102 §4.2.5 / §4.2.53, 5 B/record):
  70 = 0+70, 100 = 50+50 | 0+100, 140 = 70+70, 200 = 100+100. This is why
  entry_count is "dynamic" (it follows the SIM) and is not bounded by 255
  (200 is observed; capacity is 1000).
* **Unset SIM records** (plmn FF FF FF, AcT FF FF → every bit set) expand to
  every RAT the modem supports: v1 ``num_rats=3 rat=[2,1,0]`` (LTE, UMTS,
  GSM) on SDX20, v2 ``num_rats=4 rat=[4,2,1,0]`` (NR5G, LTE, UMTS, GSM) on
  SDX55+. NR5G=4 appears only on the 5G silicon (v2, 5,354 rat values); v1
  never carries it. rat values are always distinct within an entry.
* **F3 join.** REG prints its available-PLMN list
  (``reg_mode.c`` ``# MCC-MNC F RAT DOMAIN CAT Q RSSI`` rows) with a CAT
  column rendered from the same list-category enum. Joined per capture
  against the co-emitted 0x7160 list: a row rendered ``OPLMN`` is a PLMN
  whose 0x7160 entry has ``category=3`` AND lists the row's RAT; ``HPLMN``
  rows are absent (the home PLMN comes from EF_HPLMNwAcT, not this list);
  an ``OTHER`` row is either absent or present with the row's RAT *missing*
  from the entry's rat[] — i.e. the firmware classifies per (PLMN, RAT),
  confirming the rat[]/num_rats decode.

## Not a GNSS log

Despite co-firing with GNSS startup at boot, this is a NAS PLMN list: the
reg_mode PLMN-list F3 prints are co-temporal with the record and no GNSS
F3 is, the code sits in the 0x715x–0x716x UMTS-NAS name family, and LV55
emits it in NAS contexts (manual PLMN scan / COPS dereg / airplane / SIM
cycle).

## "Size invariance ≠ format invariance" hedge

A future firmware can ship version 0x03 in the same envelope under a new
struct layout. ``field_invariants`` pins version {1, 2} and sub_flag 0x01, and
the parser rejects (returns None) on any structural drift: unknown
(version, size) tuple, entry_count beyond the 1000-slot capacity, or a live
entry with num_rats outside 1..rat-slot-capacity. Category / RAT values
outside the named enums are kept raw (``*_name`` = ``"UNKNOWN(n)"``) rather
than rejected — e.g. TDS (3) is legal but not yet observed.

Log name: LOG_UMTS_NAS_PPLMN_LIST
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.parsers.diag_0x7150 import decode_plmn_bcd
from diaggrok.registry import register


_LOG_CODE = 0x7160

_VERSION_SDX20 = 0x01
_VERSION_SDX55_PLUS = 0x02
_OBSERVED_VERSIONS: tuple[int, ...] = (_VERSION_SDX20, _VERSION_SDX55_PLUS)

_HEADER_LEN = 4
_NUM_SLOTS = 1000
# Per-version entry geometry: rat[] capacity; stride = plmn(3) + category(1)
# + num_rats(1) + rat[capacity].
_RAT_CAPACITY = {_VERSION_SDX20: 3, _VERSION_SDX55_PLUS: 4}
_STRIDE = {v: 5 + n for v, n in _RAT_CAPACITY.items()}
_VERSION_TO_SIZE = {v: _HEADER_LEN + _NUM_SLOTS * s for v, s in _STRIDE.items()}

# byte[1] — invariant 0x01 across 760 records, role unknown.
_EXPECTED_SUB_FLAG = 0x01

# sys list-category enum, as REG's F3 available-list CAT column renders it.
_CATEGORY_NAMES = {
    0: "HPLMN",
    1: "PREFERRED",
    2: "USER_PREFERRED",       # UPLMN — EF_PLMNwAcT
    3: "OPERATOR_PREFERRED",   # OPLMN — EF_OPLMNwAcT
    4: "OTHER",
}
_CATEGORY_USER = 2
_CATEGORY_OPERATOR = 3

# sys radio-access-technology enum.
_RAT_NAMES = {0: "GSM", 1: "UMTS", 2: "LTE", 3: "TDS", 4: "NR5G"}


def _enum_name(table: dict[int, str], value: int) -> str:
    return table.get(value, f"UNKNOWN({value})")


@dataclass
class PplmnEntry:
    """One live preferred-PLMN entry (a SIM PLMNwAcT / OPLMNwAcT record)."""
    index: int
    plmn: str | None        # "MCC-MNC"; None = unset SIM record (FF FF FF)
    category: int           # 2 USER_PREFERRED | 3 OPERATOR_PREFERRED
    num_rats: int
    rats: list[int]         # sys RAT enum, priority order, len == num_rats

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "plmn": self.plmn,
            "category": self.category,
            "category_name": _enum_name(_CATEGORY_NAMES, self.category),
            "num_rats": self.num_rats,
            "rats": list(self.rats),
            "rat_names": [_enum_name(_RAT_NAMES, r) for r in self.rats],
        }


@dataclass
class Diag0x7160:
    """0x7160 — LOG_UMTS_NAS_PPLMN_LIST preferred-PLMN list."""
    log_time: int
    version: int            # byte[0] — 0x01 (SDX20) | 0x02 (SDX55+)
    sub_flag: int           # byte[1] — corpus-invariant 0x01, role unknown
    entry_count: int        # bytes[2:4] LE u16 — live entries
    payload_size: int
    entries: list[PplmnEntry] = field(default_factory=list)

    @property
    def num_user_preferred(self) -> int:
        return sum(1 for e in self.entries if e.category == _CATEGORY_USER)

    @property
    def num_operator_preferred(self) -> int:
        return sum(1 for e in self.entries if e.category == _CATEGORY_OPERATOR)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x7160",
            "log_time": self.log_time,
            "version": self.version,
            "sub_flag": self.sub_flag,
            "entry_count": self.entry_count,
            "payload_size": self.payload_size,
            "num_user_preferred": self.num_user_preferred,
            "num_operator_preferred": self.num_operator_preferred,
            "entries": [e.to_dict() for e in self.entries],
        }


# The decoded list can be checked against the modem's preferred-PLMN list
# as read by AT+CPOL / AT+COPS (v1 on MC7411, v2 on RM520N-GL).

@register(
    _LOG_CODE, domain="nas",
    name="0x7160",
    description=(
        "LOG_UMTS_NAS_PPLMN_LIST — NAS preferred-PLMN list, full decode "
        ". Header (version, sub_flag, entry_count) + 1000-slot entry "
        "table, stride 8 B (v1, 8004 B, SDX20: LM960/MC7411/EM7565) / 9 B "
        "(v2, 9004 B, SDX55+: RM520N-GL/RG520N/FN980/FT980/LV55/EM9291/"
        "SIM8202G). Entry: BCD PLMN (FFFFFF = unset SIM record), list "
        "category (2 UPLMN / 3 OPLMN), num_rats, rat[] (0 GSM 1 UMTS 2 LTE "
        "4 NR5G). entry_count = UPLMN + OPLMN SIM EF record capacity "
        "({70,100,140,200}). F3-grounded via the reg_mode available-list "
        "CAT column."
    ),
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. Full per-entry decode from 760 records / 77 "
        "captures (23 v1, 737 v2; 9+ modems) with zero structural "
        "violations: 8/9 B stride, category runs = SIM EF record "
        "capacities, unset-record rat default = modem RAT capability "
        "(v1 [LTE,UMTS,GSM], v2 [NR5G,LTE,UMTS,GSM]). F3 oracle: REG "
        "available-PLMN-list rows (reg_mode.c, CAT column) joined per "
        "capture against the co-emitted 0x7160 list. The NAS (not GNSS) "
        "role is F3-grounded (reg_mode.c prints co-temporal) and matches "
        "the 0x715x-0x716x UMTS-NAS name family and LV55 emission context."
    ),
    source_url=(
        "F3 ground truth: reg_mode.c available-PLMN-list rows (CAT column) "
        "joined against 0x7160 in co-emitting captures"
    ),
    issues=(),
    # version, sub_flag, entry_count, payload_size, plmn, category,
    # num_rats, rats
    fields_parsed=8,
    fields_identified=8,
    field_invariants={
        "version": {"enum": list(_OBSERVED_VERSIONS)},
        "sub_flag": {"enum": [_EXPECTED_SUB_FLAG]},
        "entry_count": {"range": (0, _NUM_SLOTS)},
    },
)
def parse_0x7160(log_time: int, data: bytes) -> Diag0x7160 | None:
    """Parse a 0x7160 preferred-PLMN list.

    Returns None (structural drift, never a silent mis-decode) if:
      - byte[0] (version) is not 0x01 / 0x02, or the payload length is not
        that version's 8004 / 9004 B envelope
      - byte[1] (sub_flag) is not 0x01
      - entry_count exceeds the 1000-slot table
      - a live entry's num_rats is outside 1..rat-slot-capacity
    """
    if len(data) < _HEADER_LEN:
        return None

    version = data[0]
    if version not in _OBSERVED_VERSIONS:
        return None
    if len(data) != _VERSION_TO_SIZE[version]:
        return None

    sub_flag = data[1]
    if sub_flag != _EXPECTED_SUB_FLAG:
        return None

    entry_count = unpack_from("<H", data, 2)[0]
    if entry_count > _NUM_SLOTS:
        return None

    stride = _STRIDE[version]
    rat_capacity = _RAT_CAPACITY[version]
    entries: list[PplmnEntry] = []
    for i in range(entry_count):
        off = _HEADER_LEN + i * stride
        num_rats = data[off + 4]
        if not 1 <= num_rats <= rat_capacity:
            return None
        entries.append(PplmnEntry(
            index=i,
            plmn=decode_plmn_bcd(data[off:off + 3]),
            category=data[off + 3],
            num_rats=num_rats,
            rats=list(data[off + 5:off + 5 + num_rats]),
        ))

    return Diag0x7160(
        log_time=log_time,
        version=version,
        sub_flag=sub_flag,
        entry_count=entry_count,
        payload_size=len(data),
        entries=entries,
    )
