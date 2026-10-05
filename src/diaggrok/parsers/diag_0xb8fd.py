"""NR5G ML1 Searcher Measurement Status parser (0xB8FD).

Fixed 80-byte records with NR5G cell search measurement statistics.
The searcher cycles through SSB beam positions, reporting raw correlator
energy at each position. These are not calibrated RSRP values - they are
intermediate search metrics used by the modem to detect new cells.

Layout (80 bytes, version 0):
    [0]     u8   version (0 - invariant across a 25,763-record / 74-capture
                 corpus)
    [1]     u8   reserved (0 - invariant)
    [2]     u8   sub_tag (0x00 on 25,138 records; 0x03 on the 625 records from
                 two older RM520N-GL SDX62 firmware builds - a chipset/firmware
                 sub-tag, not part of the version. The parser reads only
                 byte[0] as `version`, so this variance does not affect the
                 version invariant.)
    [3]     u8   reserved (0 - invariant)
    [4:8]   u32  search_tick (search cycle counter, small monotonic-ish int)
    [8:12]  u32  beam_config - SSB beam position being searched
                 byte3: mode flag (0x01=active search, 0x00=idle). Active is the
                 dominant corpus state: 23,611 active vs 2,152 idle; the Compal
                 RXM-G1 captures are all-active. Idle records (where beam_config
                 is essentially 0x00000000 - nothing being searched) concentrate
                 in boot / reboot / COPS-dereg / reject / GNSS-only captures.
                 lo16: SSB beam position. On sub-6 active records the encoding is
                 `beam_idx*64 + 62` (RM500Q: lo16=190 -> idx 2, in range). On
                 FR2/mmWave active records (Telit FN980m) lo16 runs to ~10000
                 (0x2714) and does not fit that form - the FR2 beam-position
                 encoding differs and `ssb_beam_index = lo16//64` is out of SSB
                 range there (candidate, ungrounded; raw beam_config is exposed).
    [12:16] u32  energy_a (wide range - raw correlator energy)
    [16:20] u32  energy_b (filtered energy estimate)
    [20:24] u32  timing_a (timing accumulator)
    [24:28] u32  timing_b (timing delta)
    [28:32] u32  quality_a (signal quality metric)
    [32:36] u32  quality_b (noise estimate)
    [36:40] u32  beam_metric (beam tracking quality)
    [40:60] 5×u32 measurement counters
    [60:76] 4×u32 paired metrics (60≈72, 64≈68 - mirror pattern)
    [76:80] u32  reserved (0)

Note: energy_a/energy_b are raw searcher energy, not calibrated RSRP.
For calibrated NR5G RSRP, use 0xB97F or 0xB8FF. (0x1C64 is not an
alternative: it carries DSM heap-pool watermarks, not NR5G measurements.)

F3 status v0x00: not applicable (searcher internal metrics are not
F3-serialized). The 189 active-search records of a Telit FN980m mmWave burst
(F3 resolution 1,700,152/1,700,152 = 100%) were correlated against the
NR5G-ML1 searcher/meas subsystems and then the NR5G RF-layer rx/meas
subsystems (±70 ms): both found 0 co-temporal F3 samples. An unfiltered pass
over the same window yields abundant co-temporal F3, so the absence is
specific: the firmware emits plenty of F3 during the burst, none of it
labelling a searcher quantity. Idle captures show the same:
energy_*/timing_*/quality_*/beam_metric are raw internal correlator metrics
the firmware never re-prints.

Reverse-engineered from an SDX55 (RM500Q-AE) drive capture.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_RECORD_SIZE = 80  # fixed v0 layout (see docstring)


@dataclass
class Diag0xB8FD:
    """NR5G ML1 Searcher Measurement Status (0xB8FD)."""

    log_time: int
    version: int
    search_tick: int
    beam_config: int
    ssb_beam_index: int  # decoded from beam_config: lo16 // 64
    is_active_search: bool  # True when byte3 of beam_config is 0x01
    energy_a: int
    energy_b: int
    timing_a: int
    timing_b: int
    quality_a: int
    quality_b: int
    beam_metric: int
    counters: list[int]
    pair_a: int
    pair_b: int
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB8FD",
            "log_time": self.log_time,
            "version": self.version,
            "search_tick": self.search_tick,
            "ssb_beam_index": self.ssb_beam_index,
            "is_active_search": self.is_active_search,
            "energy_a": self.energy_a,
            "energy_b": self.energy_b,
            "quality_a": self.quality_a,
            "quality_b": self.quality_b,
            "beam_metric": self.beam_metric,
            "payload_size": self.payload_size,
        }


@register(
    0xB8FD,
    name="0xB8FD",
    issues=(),
    description="NR5G cell searcher statistics - 14 measurement fields (80B fixed, SDX55)",
    version=4,
    author="Claude Code",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Reverse-engineered from an SDX55 (RM500Q-AE) drive capture; version "
        "byte invariant at 0 across a 25,763-record / 74-capture corpus "
        "(SDX55 and SDX62, including FR2). Active-search path F3-checked on a "
        "Telit FN980m mmWave burst (100% F3-resolved): searcher internal "
        "metrics are not F3-serialized. Payloads shorter than the fixed 80 B "
        "layout return None. The FR2 beam-position encoding is not decoded."
    ),
    source_url="https://github.com/lukejenkins",
    # version, search_tick, beam_config, ssb_beam_index, is_active_search,
    # energy_a, energy_b, timing_a, timing_b, quality_a, quality_b,
    # beam_metric, counters[], pair_a, pair_b, payload_size - 16 named
    # fields covering the 80B fixed record; 4B trailing reserved
    # (offset 76..80) excluded.
    fields_identified=16,
    fields_parsed=16,
    # Size invariance is not format invariance: byte[0] is a version field,
    # invariant at 0 across the 25,763-record / 74-capture corpus (RM500Q
    # SDX55, RM520N-GL SDX62, EM9190 SDX55, Compal RXM-G1, Wistron LV55,
    # SIMCom SIM8202GM2, Telit FN980m). A future firmware could ship a
    # different 80B layout under version=1; the invariant below rejects it
    # rather than silently mis-parsing.
    field_invariants={
        "version": {"enum": [0]},
    },
)
def parse_0xb8fd(
    log_time: int, data: bytes
) -> Diag0xB8FD | None:
    # The v0 layout is a fixed 80 B record; anything shorter is a
    # truncated record — fail loudly (registry WARN) rather than zero-filling
    # the missing fields. Longer payloads still decode the 80 B prefix.
    if len(data) < _RECORD_SIZE:
        return None

    version = data[0]
    # Hard-gate the version byte: reject any record that is not the observed
    # v=0 layout instead of decoding foreign bytes into these 16 fields.
    if version != 0:
        return None
    search_tick, beam_config = unpack_from("<2I", data, 4)

    # Decode SSB beam index from beam_config:
    # lo16 encodes beam position as (beam_idx * 64 + offset)
    # byte3 = 0x01 for active search, 0x00 for idle
    ssb_beam_index = (beam_config & 0xFFFF) // 64
    is_active_search = ((beam_config >> 24) & 0xFF) == 1

    (energy_a, energy_b, timing_a, timing_b,
     quality_a, quality_b, beam_metric) = unpack_from("<7I", data, 12)
    counters = list(unpack_from("<5I", data, 40))
    pair_a, pair_b = unpack_from("<2I", data, 60)

    return Diag0xB8FD(
        log_time=log_time,
        version=version,
        search_tick=search_tick,
        beam_config=beam_config,
        ssb_beam_index=ssb_beam_index,
        is_active_search=is_active_search,
        energy_a=energy_a,
        energy_b=energy_b,
        timing_a=timing_a,
        timing_b=timing_b,
        quality_a=quality_a,
        quality_b=quality_b,
        beam_metric=beam_metric,
        counters=counters,
        pair_a=pair_a,
        pair_b=pair_b,
        payload_size=len(data),
    )
