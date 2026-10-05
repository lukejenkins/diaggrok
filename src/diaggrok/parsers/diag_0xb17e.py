"""0xB17E — LTE ML1 UE mobility state: serving-cell change history (legacy `LtePdcpB17E`).

**This is the ML1 UE-mobility (speed-state) record, not a cell-barred
status change.** It is the binary twin of the F3
prints in ``lte_ml1_common_uemob.c``::

    Serv cell change: old (%d,%d) new (%d,%d) time %d UE mob %d
    UE Mob Params Tcrmax %d Thyst %d NcrH %d NcrM %d

i.e. the TS 36.304 §5.2.4.3 mobility-state estimation, which counts
serving-cell changes inside ``T_CRmax`` against ``N_CR_M`` / ``N_CR_H``.
The alias ``LOG_LTE_ML1_UE_MOBILITY_STATE_CHANGE`` from a newer item-type
list fits the content; the canonical "Cell Barred/Unbarred status change"
name does not. Layout
(52 B header + N x 24 B history entries)::

    0  u8   version            0x10 (fixed 17-slot table, 460 B) | 0x38 (52+24*N)
    1..3    reserved (0 on every sampled record)
    4  u32  earfcn             serving cell EARFCN  (F3-grounded, both versions)
    8  u16  pci:9 | flags:7    serving PCI (F3-grounded); flags raw (always 5)
    10..11  reserved (0)
    12 u64  anchor_time_ms     ML1 ms clock; = newest entry time at a change (CANDIDATE)
    20 u64  current_time_ms    ML1 ms clock at log time
    28 [16] speed_params_raw   all 0xFF on every sampled record (CANDIDATE: SIB3
                               speed-state params, F3 sentinels Tcrmax/Thyst
                               0xFFFFFFFF, NcrH/NcrM 0xFF when not broadcast)
    44 u8   hdr_byte44         0x77 or 0x00 (raw)
    45 u8   hdr_byte45         0x00 or 0xA5 (raw)
    46 u8   num_entries        v0x38 entry count (= (len-52)/24); 0 on v0x10
    47..51  reserved (0)
    52 N x 24 B history entry:
        0  u64 time_ms         F3 `time %d`
        8  u32 old_earfcn, u16 old_pci:9|old_flags:7, u16 reserved
        16 u32 new_earfcn, u16 new_pci:9|new_flags:7, u16 reserved

Entries are newest-first (100% of the 1,066 sampled records). Usually
``entries[i].old == entries[i+1].new`` (431/625), but not always: the table
skips some returns to a previous cell, so it is not a strict chain. On v0x10
unused slots carry the sentinel ``(earfcn 0xFFFFFFFF, pci 511)``: the F3
``old (4294967295,65535)`` truncated to the 9-bit PCI field, and they are
omitted from ``entries``.

The EARFCN at offset 4 was first attributed by DIAG×AT correlation;
``to_dict()`` keeps the ``earfcn`` key (never ``config_word``).

Log name: LOG_CELL_BARRED_UNBARRED_STATUS_CHANGE
Also known as: LOG_LTE_ML1_CELL_BARRED_UNBARRED_STATUS_CHANGE, LOG_LTE_ML1_UE_MOBILITY_STATE_CHANGE
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# byte-0 version/layout discriminator — both values observed at size>4: 0x38
# (the 52..340B size family) and 0x10 (the 460B form). 460B/0x10 is the
# dominant cross-vendor form (2,893/4,235 records, 58 models), not a rare boot
# transient, and carries a valid EARFCN@4 like the 0x38 records. 0xFFFFFFFF@4
# is a minority search-mode/no-cell sentinel within some captures, not a 460B
# property.
_B17E_VERSIONS_OBSERVED = (0x10, 0x38)


# Header + 24 B serving-cell-change history entries.
_B17E_HEADER_LEN = 52
_B17E_ENTRY_LEN = 24
_B17E_MAX_ENTRIES = 17
_PCI_MASK = 0x1FF
_U64_NONE = 0xFFFFFFFFFFFFFFFF


def _cell(data: bytes, off: int) -> tuple[int, int, int]:
    """(earfcn, pci, flags) from a u32 earfcn + u16 {pci:9, flags:7}."""
    earfcn, word = unpack_from("<IH", data, off)
    return earfcn, word & _PCI_MASK, word >> 9


@dataclass
class Diag0xB17E:
    """0xB17E — LTE ML1 UE mobility state / serving-cell change history.

    See the module docstring for the full layout and its F3 twin
    (``lte_ml1_common_uemob.c``). A frame shorter than the 52 B header plus
    its declared history (17 slots on v0x10, ``data[46]`` entries on v0x38)
    is truncated and the parser returns None.

    * ``earfcn`` u32@4 / ``pci`` 9 bits of u16@8 — the serving cell,
      F3-grounded on both versions (T99W175 v0x10 ``PhyId:471``→``236``,
      RM520N-GL v0x38 ``+QENG servingcell`` 236/66786).
    * ``entries`` — newest-first serving-cell changes, each
      ``{time_ms, old_earfcn, old_pci, old_flags, new_earfcn, new_pci,
      new_flags}``: the fields of F3 ``Serv cell change: old (E,P) new (E,P)
      time T``. ``*_flags`` are the raw 7 bits above the PCI (CANDIDATE:
      ``old_flags`` always 0; ``new_flags`` 1 on 3,289/3,348 entries, where F3
      reads ``UE mob 1``; 2 on 59, both same-cell and cell-to-cell).
    """
    log_time: int
    version: int
    earfcn: int
    pci: int | None
    serving_flags: int | None
    anchor_time_ms: int | None
    current_time_ms: int | None
    speed_params_raw: bytes | None
    hdr_byte44: int | None
    hdr_byte45: int | None
    num_entries: int | None
    entries: list[dict[str, int]]
    data_density: float
    payload_size: int
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB17E",
            "log_time": self.log_time,
            "version": self.version,
            "earfcn": self.earfcn,
            "pci": self.pci,
            "serving_flags": self.serving_flags,
            "anchor_time_ms": self.anchor_time_ms,
            "current_time_ms": self.current_time_ms,
            "speed_params_raw": self.speed_params_raw,
            "hdr_byte44": self.hdr_byte44,
            "hdr_byte45": self.hdr_byte45,
            "num_entries": self.num_entries,
            "entries": self.entries,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }


@register(
    0xB17E,
    name="0xB17E",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge",),
    description="0xB17E — LTE ML1 UE mobility state: serving cell + serving-cell change history (F3 lte_ml1_common_uemob.c twin; earfcn@4, pci@8, 24B old/new-cell entries; legacy mislabel LtePdcpB17E)",
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full-record decode. The record is the ML1 UE-mobility (TS 36.304 "
        "§5.2.4.3 speed-state) log, binary twin of F3 lte_ml1_common_uemob.c "
        "`Serv cell change: old (%d,%d) new (%d,%d) time %d UE mob %d` (found "
        "in 7 LM960/EM7565 F3 sidecars; none of them also logs 0xB17E, so the "
        "join is on format + cell + clock). Byte 0 is 0x10 (fixed 460 B, 17 "
        "slots; the dominant cross-vendor form, 2,893/4,235 records over 58 "
        "models) or 0x38 (52+24*N, byte46 == N). Layout = 52B header + N x 24B "
        "entries {u64 time_ms, old cell, new cell}; each cell = u32 earfcn + "
        "u16 {pci:9, flags:7} + u16 pad. Evidence: (a) stratified sample, "
        "73/284 captures x 41 model groups, 1,066 records: (len-52)%24==0 on "
        "100%, unused v0x10 slots = earfcn 0xFFFFFFFF/pci 511 sentinel = F3 "
        "`old (4294967295,65535)` truncated to 9 bits; header pci-flags == 5 "
        "and bytes 1..3/10..11 == 0 on all. (b) Serving earfcn@4 / pci@8 "
        "F3-grounded on both versions: a T99W175 v0x10 SIM power-cycle capture "
        "reads u32@4=66786 against a co-temporal `EARFCN:66786` 0x79 print, and "
        "its entry0 = (66786,471)->(66786,236) at the header anchor time is "
        "co-temporal with F3 `PhyId:471` -> `PhyId:236`; three RM520N-GL v0x38 "
        "records (76B) read earfcn 66786 / pci 236, bracketing a co-temporal "
        "`+QENG servingcell` print giving pci=236 earfcn=66786 band=66. (c) "
        "CFW3212 v0x38 history 420->129->277->24->453, newest-first on 625/625 "
        "entry-bearing records; old == previous new on 431/625 (the table skips "
        "some returns, e.g. 147->240, 240->404, 240->147), header cell == "
        "entries[0].new on 468/625. (d) u64@12/@20 and the F3 `time` arg share "
        "one ms clock: 52,431 / 52,439 diag ticks per unit vs the nominal "
        "52,428.8. Raw/CANDIDATE (not grounded): speed_params_raw @28 (all 0xFF "
        "in the sample; F3 prints the same not-broadcast sentinels, but the one "
        "cell with Tcrmax 30000 still logged 0xFF), hdr_byte44/45, the 7 flag "
        "bits (old_flags always 0; new_flags 1 on 3,289/3,348 entries vs F3 "
        "`UE mob 1`, 2 on 59, both same-cell and cell-to-cell). Validation walk "
        "over the 73-capture sample: the only earfcn invariant hits are the "
        "0xFFFFFFFF no-cell sentinel, flagged by design; earfcn=0 search-mode "
        "records are valid. Payloads shorter than the header + declared history "
        "return None (registry warning). Neither QCSuper nor SCAT decodes 0xB17E."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=17,
    fields_parsed=17,
    field_invariants={
        "version": {"enum": list(_B17E_VERSIONS_OBSERVED)},
        "earfcn": {"range": (0, 262143)},
        "pci": {"range": (0, 511)},
        "num_entries": {"range": (0, _B17E_MAX_ENTRIES)},
    },
)
def parse_0xb17e(log_time: int, data: bytes) -> Diag0xB17E | None:
    if len(data) < 1:
        return None
    version = data[0]
    # Layer-1 byte-0 version gate.
    if version not in _B17E_VERSIONS_OBSERVED:
        return None
    # The payload must hold the 52 B header plus the history it declares —
    # 17 fixed slots on v0x10, data[46] entries on v0x38. Anything shorter is
    # truncated -> None (registry warning).
    if len(data) < _B17E_HEADER_LEN:
        return None
    declared = _B17E_MAX_ENTRIES if version == 0x10 else data[46]
    if len(data) < _B17E_HEADER_LEN + declared * _B17E_ENTRY_LEN:
        return None
    if len(data) >= 8:
        earfcn = unpack_from('<I', data, 4)[0]
    elif len(data) >= 2:
        earfcn = data[1]
    else:
        earfcn = 0
    if len(data) > 2:
        nonzero = sum(1 for b in data[2:] if b != 0)
        total = max(len(data) - 2, 1)
        density = round(nonzero / total, 2)
    else:
        density = 0.0

    pci = serving_flags = anchor = current = None
    speed_raw = None
    b44 = b45 = num_entries = None
    entries: list[dict[str, int]] = []
    if len(data) >= _B17E_HEADER_LEN:
        _, pci, serving_flags = _cell(data, 4)
        anchor, current = unpack_from("<QQ", data, 12)
        anchor = None if anchor == _U64_NONE else anchor
        current = None if current == _U64_NONE else current
        speed_raw = bytes(data[28:44])
        b44, b45 = data[44], data[45]
        n_slots = (len(data) - _B17E_HEADER_LEN) // _B17E_ENTRY_LEN
        for i in range(n_slots):
            off = _B17E_HEADER_LEN + i * _B17E_ENTRY_LEN
            time_ms = unpack_from("<Q", data, off)[0]
            old_e, old_p, old_f = _cell(data, off + 8)
            new_e, new_p, new_f = _cell(data, off + 16)
            if time_ms == _U64_NONE and old_e == 0xFFFFFFFF and new_e == 0xFFFFFFFF:
                continue  # v0x10 unused slot
            entries.append({
                "time_ms": time_ms,
                "old_earfcn": old_e, "old_pci": old_p, "old_flags": old_f,
                "new_earfcn": new_e, "new_pci": new_p, "new_flags": new_f,
            })
        # v0x38 carries an explicit count; v0x10 is a fixed table.
        num_entries = data[46] if version == 0x38 else len(entries)
    return Diag0xB17E(
        log_time=log_time,
        version=version,
        earfcn=earfcn,
        pci=pci,
        serving_flags=serving_flags,
        anchor_time_ms=anchor,
        current_time_ms=current,
        speed_params_raw=speed_raw,
        hdr_byte44=b44,
        hdr_byte45=b45,
        num_entries=num_entries,
        entries=entries,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
