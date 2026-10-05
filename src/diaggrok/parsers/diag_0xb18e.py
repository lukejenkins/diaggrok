"""LTE ML1 System Scan Results parser (0xB18E).

0xB18E -- LTE ML1 System Scan Results
    Per-frequency scan results: EARFCN, band, bandwidth, RSSI.
    Emitted during initial cell search / band scanning.

Payload structure (version 0x20 / 0x02, fixed 124 bytes; version 0x29 is
4 + 16*num_entries bytes, same entry prefix on a 16-byte stride):
    [0]      u8   version (0x20 = 32)
    [1]      u8   flags (0x00 = complete scan, nonzero = intermediate)
    [2:4]    u16  num_entries (up to 10)

    Per-entry (12 bytes each, starting at offset 4):
        [0:4]    u32  EARFCN (low 18 bits)
        [4:6]    u16  band number (e.g. 2, 12, 13, 66, 71)
        [6:8]    u16  bandwidth enum (0=1.4, 1=3, 2=5, 3=10, 4=15, 5=20 MHz)
        [8:10]   s16  RSSI (dBm)
        [10:12]  u16  reserved (always 0)

Reverse-engineered from SDX20 (LM960) DLF captures.

Techplayon's public log-packet field list names the 0xB18E fields:
    0xB18E — LTE ML1 System Scan Results
        earfcn, band, bandwidth_mhz, energy_dbm_per_100khz

Log name: LTE ML1 System Scan Results
Also known as: LOG_LTE_ML1_SYSTEM_SCAN_RESULTS, LTE PUSCH Power Control
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_LTE_ML1_SYSTEM_SCAN = 0xB18E

_ENTRY_SIZE = 12
_HEADER_SIZE = 4
_MAX_ENTRIES = 10
# v0x02/v0x20 are a fixed 124 B buffer (4 + 10 x 12 B entries);
# v0x29 packs num_entries x 16 B entries back-to-back (size == 4 + 16*N on every
# sampled record: 20/36/52/100/116/164 B for N = 1/2/3/6/7/10). The extra 4 B of
# a v0x29 entry follow the same 12 B prefix and are not decoded.
_FIXED_BUFFER_SIZE = _HEADER_SIZE + _MAX_ENTRIES * _ENTRY_SIZE  # 124
_ENTRY_SIZE_V29 = 16

# Bandwidth enum → MHz
_BW_MHZ = {0: 1.4, 1: 3.0, 2: 5.0, 3: 10.0, 4: 15.0, 5: 20.0}


@dataclass
class LteMl1ScanEntry:
    """A single frequency scan result."""
    earfcn: int
    band: int
    bandwidth_mhz: float
    rssi: float   # dBm

    def to_dict(self) -> dict[str, Any]:
        return {
            'earfcn': self.earfcn,
            'band': self.band,
            'bandwidth_mhz': self.bandwidth_mhz,
            'rssi': self.rssi,
        }


@dataclass
class Diag0xB18E:
    """LTE ML1 System Scan Results (0xB18E)."""
    log_time: int
    version: int
    is_complete: bool
    num_entries: int
    entries: list[LteMl1ScanEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0xB18E',
            'log_time': self.log_time,
            'version': self.version,
            'is_complete': self.is_complete,
            'num_entries': self.num_entries,
            'entries': [e.to_dict() for e in self.entries],
        }


# RM520N-GL SDX62 emits this at v=0x29 with the per-frequency scan entries
# fully decoded (earfcn/band/bandwidth_mhz/rssi — verified against a live
# RM520N-GL capture: earfcn=66786 band=66 rssi=-107.0). On the 16 B stride
# every sampled v0x29 entry is a valid EARFCN/band/RSSI (a 12 B stride yields
# bogus rssi >= +800 values). A system scan fires on a fresh cell search, so
# force one with a COPS de-register/re-register cycle and correlate the found
# cells against the neighbour list.

@register(LOG_LTE_ML1_SYSTEM_SCAN,
    name="0xB18E",
    wigle_direct=True,
    wigle_roles=("signal", "pci-earfcn-bridge"),
    description="Per-frequency scan results: EARFCN, band, bandwidth, RSSI from 0xB18E",
    version=16,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Layout reverse-engineered from SDX20 (LM960) band-scan captures: a 4 B "
        "header (version, flags, num_entries) + up to 10 entries {u32 earfcn "
        "(low 18 bits), u16 band, u16 bandwidth enum, s16 rssi, u16 reserved}. "
        "Three version bytes: 0x02 (dominant on SIM7600NA, MC74xx, EG25-G, "
        "EM7565, MC7411) and 0x20 (LM960) use a fixed 124 B buffer with 12 B "
        "entries; 0x29 (RM520N-GL SDX62, SIM8202G-M2 / FN980 SDX55, LM960A18) "
        "packs num_entries x 16 B entries (size == 4 + 16*k on all 6,394 "
        "census records, 20..164 B; the buffer may carry unused slots past "
        "num_entries), with the same 12 B prefix. entries.earfcn is verified "
        "on every version family: AT-confirmed serving EARFCNs are contained in "
        "the scan set on RM520N-GL (975/66536/5230 over COPS cycles), EG25-G "
        "(5035/2300), MC7411 (66786 via AT!LTEINFO), LM960A18 band-lock B66→B2→B12 "
        "(serving + neighbour EARFCNs, AT#MONI + F3) and LM960 v0x20 (serving "
        "55340); on FN980 and SIM8202G-M2 the decoded EARFCNs are independently "
        "witnessed by co-temporal F3 rflte_mc_rx.c 'channel:' tune prints, and "
        "on EM7565 v0x02 the transient scan EARFCN 43390 (B42, 20 MHz) appears in "
        "F3 mc_msgr.c 'Channel 43390, Freq 3580000 kHz, BW 20000000 Hz' prints "
        "co-temporal with the scan, grounding earfcn + per-frequency bandwidth "
        "there. entries.band is verified on LM960A18 (== the band-locked band per "
        "phase), FN980 (serving 66 == AT#RFSTS) and SIM8202G-M2 (32/32 "
        "EARFCN-to-band consistent). bandwidth_mhz (outside EM7565), rssi and "
        "num_entries remain partial (AT-anchored only on the serving entry). "
        "Truncated payloads return None (registry warning): a v0x02/v0x20 buffer "
        "shorter than 124 B, a v0x29 payload shorter than 4 + 16*num_entries or "
        "off the 4 + 16*k grid, or num_entries > 10."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Header fields: version, is_complete, num_entries (3) + each entry has
    # earfcn/band/bandwidth_mhz/rssi (4) — total identified+parsed = 7.
    fields_identified=7, fields_parsed=7,
    field_invariants={
        "version": {"enum": [0x02, 0x20, 0x29]},
    },
)
def parse_0xb18e(
    log_time: int, data: bytes
) -> Diag0xB18E | None:
    """Parse 0xB18E -- LTE ML1 System Scan Results.

    Returns None if the version is unsupported or the payload is shorter than
    its layout (fixed 124 B for v0x02/v0x20; 4 + 16*num_entries for v0x29), or
    declares more than 10 entries, or is a v0x29 payload off the
    4 + 16*k slot grid.
    """
    if len(data) < _HEADER_SIZE:
        return None

    version = data[0]
    # Layer-1 version gate. The docstring already promises this rejection;
    # this makes it explicit + audit-visible.
    if version not in (0x02, 0x20, 0x29):
        return None
    flags = data[1]
    num_entries = unpack_from('<H', data, 2)[0]

    is_complete = (flags == 0)

    # Validate the declared entry count against the
    # payload instead of clamping / breaking silently. A count above the 10-slot
    # maximum, a v0x02/v0x20 buffer shorter than its fixed 124 B, or a v0x29
    # payload shorter than 4 + 16*N is truncated/unknown -> None (registry warning).
    if num_entries > _MAX_ENTRIES:
        return None
    if version == 0x29:
        stride = _ENTRY_SIZE_V29
        if len(data) < _HEADER_SIZE + num_entries * stride:
            return None
        # The buffer may hold unused slots past num_entries, so
        # the floor above cannot see a byte lost from one. Every attested v0x29
        # record is a whole number of 16 B slots; anything else is truncated.
        if (len(data) - _HEADER_SIZE) % stride != 0:
            return None
    else:
        stride = _ENTRY_SIZE
        if len(data) < _FIXED_BUFFER_SIZE:
            return None

    entries: list[LteMl1ScanEntry] = []

    for i in range(num_entries):
        offset = _HEADER_SIZE + i * stride

        earfcn_raw = unpack_from('<I', data, offset)[0]
        earfcn = earfcn_raw & 0x3FFFF
        band = unpack_from('<H', data, offset + 4)[0]
        bw_enum = unpack_from('<H', data, offset + 6)[0]
        rssi = float(unpack_from('<h', data, offset + 8)[0])

        if earfcn > 262143 or band > 255:
            continue

        bandwidth_mhz = _BW_MHZ.get(bw_enum, 0.0)

        entries.append(LteMl1ScanEntry(
            earfcn=earfcn,
            band=band,
            bandwidth_mhz=bandwidth_mhz,
            rssi=rssi,
        ))

    return Diag0xB18E(
        log_time=log_time,
        version=version,
        is_complete=is_complete,
        num_entries=len(entries),
        entries=entries,
    )
