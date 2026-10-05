"""0x1C0D — NR5G SDRIU info, fixed 50-entry self-describing array.

Name tables list 0x1C0D as ``LOG_NR5G_SDRIU_INFO``.
Every corpus record is a 4-byte header followed by exactly 50 fixed-width
entries, each entry prefixed with a self-describing ``0a 01 <len> 00`` TLV tag.

Wire layout (little-endian), verified on the **whole 0x1C0D corpus**
(1,281 records):

  off  0  u8         version       silicon-class version byte (see table)
  off  1  u8         num_entries   populated-entry count (0x32 = 50 in corpus)
  off  2  u16        seq           per-record counter (varies)
  off  4  entry[50]               each ``stride`` bytes; entry[i] @ 4 + stride*i
                                    entry[i][0]   == 0x0a  (tag,  invariant)
                                    entry[i][1]   == 0x01  (type, invariant)
                                    entry[i][2:4] == stride (u16 LE self-len)

The entry array is fixed-capacity (50 slots), so the record size never varies
within a version even though ``num_entries`` is a real field — all 50 slots are
exposed raw and ``num_entries`` reports how many are populated.

**Per-version stride.** The 4-byte header and the 50-slot capacity are
invariant across *every* silicon, but the per-entry STRIDE tracks the SDRIU
entry width of the chipset. The embedded TLV length (u16 @ entry+2) EQUALS
the stride on every version — the firmware writes the entry width into each
entry header, so the array is fully self-describing and the table below is
cross-checked against the wire at parse:

  ver   silicon-class            stride  payload  entry TLV tag
  0x04  SDX55  (RXM-G1/M2000/RM500Q)  48    2404   0a 01 30 00 (len=48)
  0x05  mmWave (Foxconn FT980M)       40    2004   0a 01 28 00 (len=40)
  0x06  SDX62  (RM520N-GL/M3100/T99W373) 48  2404   0a 01 30 00 (len=48)
  0x07  SDX7x  (Foxconn T99W640)      60    3004   0a 01 3c 00 (len=60)

All four versions carry the same 4-B header + 50-slot self-describing TLV
array, only with a different entry width. Because the same size does not
imply the same format, ``version`` is enum-gated to {4,5,6,7},
``payload_size`` to the observed sizes, and ``entry_stride`` to the observed
strides so a future variant is rejected, not mis-parsed; the first-entry TLV
(tag/type/embedded-len) is validated at parse as a misframe guard.

Per-entry BODY semantics (the measurement fields after each TLV header) are
decomposed structurally (live vs reserved byte map) but the field SEMANTICS
still need a co-temporal F3 source and stay deferred. The v0x04 and v0x06
bodies are NOT the same layout — the live/const maps diverge — so the
version-gating is load-bearing (a shared body layout would mis-decode). The
mmWave v0x05 (40 B) and SDX7x v0x07 (60 B) bodies are, respectively, narrower
and wider than the 48 B SDX55/SDX62 body and have not yet had their
live/reserved maps profiled.

F3 evidence per version. SDR855 is the RF SDR front-end for the SDX line
across ALL RF functions, NOT a GNSS part, and SDRIU = "SDR Interface Unit",
so SDR/RFFE subsystem F3 is TOPICALLY CENTRAL to this log — and it does
co-emit. The useful test is therefore NOT "does any SDR F3 fire near the
record" (it does, heavily) but "does any F3 print the record's per-entry
measurement VALUES, or fire ENRICHED (specifically near SDRIU vs its own
background)". Both answers are no on the captures held:
  * v0x06 — not F3-groundable from the captures held. On an SDX62 capture
    (94 records, 1,564,059/1,564,059 0x99 resolved @ 100%) the SDR/RFFE
    subsystem F3 IS heavily co-temporal (±70ms, 187,983 samples):
    navrx_sdr855.cpp (the nav-receiver code path ON the shared SDR855
    front-end), rflm_qlnk_* (RF-LM Qlink/RFFE bus, dt as tight as 58 ticks),
    rfdevice_* (RF device drivers), plus the highest-rate cc_slicer / cc_dp /
    cc_srchmgr carrier-config/cell-search and dcvsq_* clock/voltage. BUT none
    of those is ENRICHED beyond background (they fire near every log — their
    co-temporality is density, not association): the global-baseline
    enrichment tops out entirely on UNRELATED time/URSP/SIM bursts
    (time_genoff / ds_nr5g_ursp_hdlr / mmgsdi / uim_polling), and NO F3
    prints the SDRIU record's per-entry measurement VALUES. So the RF F3
    present cannot LABEL the fields (same outcome as the 0xB84x and 0xB886
    siblings, though for those the subsystem was quiet whereas here it is
    loud-but-non-labelling).
  * v0x04 — same outcome. On an RXM-G1 SDX55 capture (5 v0x04 records +
    18,399 0x79 + 170,923/170,923 0x99 @ 100% resolved) the co-temporal F3 is
    data-session / RF-hardware-driver / SSL housekeeping (ds_3gpp_apn_table,
    rfdevice_elna / rfcommon_atuner / rfdevice_fem = RF tuner/LNA/FEM
    *hardware control*, ds_Sock/ds_Net) with the nearest F3 ~1.15ms off —
    not tight. The sole >1x-enriched NR5G-RF-adjacent file at ±1ms is
    rfe_nr5g_vstmr.c (RF front-end NR5G slot TIMER) at a weak 4.1x (5/822)
    — a timing marker, not a measurement-value print; everything else
    de-enriched (<=0.6x). No value-printing emitter, and only 5 records.
  * v0x07 — no F3 available. The version's only capture (T99W640 bring-up,
    9 records) is a LOG-only capture with no ``0x79``, ``0x99`` or ``0x98``
    stream at all. Container decoded; per-entry semantics deferred.
  * v0x05 — inconclusive. The version's only F3-bearing capture (Foxconn
    FT980M mmWave drive capture, 77 records, 100 % resolved) was joined
    record by record. Nothing near the records is enriched over its control
    (the top ±1 ms co-emitters, ``lte_LL1_*`` macrosleep / ENDC LNA prints,
    fire at 0.71-0.75 of records vs 0.49-0.54 of control points;
    ``mcpm``/MCVS clock votes 0.26 vs 0.10), and no print carries an entry's
    values (the only "value matches" are the version byte and the entry
    count, at near-control rates).

QCSuper and SCAT: N/A for 0x1C0D. Both run cleanly on an SDX62 capture and
emit only the air-interface planes (RRC/NAS/L1/GNSS-geo into GSMTAP/PCAP);
LOG_NR5G_SDRIU_INFO is a modem-INTERNAL SDR/RF-front-end info log, not an
over-the-air message, so neither tool has a decoder for it — no independent
A/B cross-check is available for the entry-body semantics.

Log name: LOG_NR5G_SDRIU_INFO
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# version byte (offset 0) -> (total payload size, per-entry stride). The stride
# is ALSO self-described by each entry's TLV len (u16 @ entry+2 == stride), which
# the parser cross-checks against this table as a misframe guard.
_1C0D_VERSION_LAYOUT: dict[int, tuple[int, int]] = {
    0x04: (2404, 48),  # SDX55-class  (RXM-G1 / M2000 / RM500Q)
    0x05: (2004, 40),  # mmWave       (Foxconn FT980M)
    0x06: (2404, 48),  # SDX62-class  (RM520N-GL / M3100 / T99W373)
    0x07: (3004, 60),  # SDX7x-class  (Foxconn T99W640)
}
_1C0D_HEADER_SIZE = 4
_1C0D_ENTRY_CAPACITY = 50
_1C0D_ENTRY_TAG = 0x0A
_1C0D_ENTRY_TYPE = 0x01

_1C0D_VERSIONS_OBSERVED = sorted(_1C0D_VERSION_LAYOUT)
_1C0D_SIZES_OBSERVED = sorted({s for s, _ in _1C0D_VERSION_LAYOUT.values()})
_1C0D_STRIDES_OBSERVED = sorted({st for _, st in _1C0D_VERSION_LAYOUT.values()})


@dataclass
class Diag0x1C0D:
    """0x1C0D — NR5G fixed 50-entry SDRIU array (structural, self-describing)."""
    log_time: int
    version: int
    num_entries: int
    seq: int
    entry_stride: int
    entries: list[bytes]
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1C0D",
            "log_time": self.log_time,
            "version": self.version,
            "num_entries": self.num_entries,
            "seq": self.seq,
            "entry_stride": self.entry_stride,
            "entries": self.entries,
            "payload_size": self.payload_size,
        }


@register(
    0x1C0D,
    name="0x1C0D",
    description=(
        "0x1C0D — NR5G SDRIU info (LOG_NR5G_SDRIU_INFO): 4B header + 50 "
        "self-describing TLV entries; per-silicon stride v0x04/06=48B (SDX55/62), "
        "v0x05=40B (mmWave FT980M), v0x07=60B (SDX7x T99W640); per-entry "
        "measurement semantics deferred (F3-negative/capture-gated)"
    ),
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Array shape RE'd + verified on the whole 0x1C0D corpus (1,281 records) "
        "across four silicon versions: v0x04 (SDX55) 2404B/48B-stride, v0x05 "
        "(mmWave FT980M) 2004B/40B, v0x06 (SDX62) 2404B/48B, v0x07 (SDX7x "
        "T99W640) 3004B/60B; 4B header + 50 entries, each a self-describing TLV "
        "(tag=0x0a type=0x01 len=stride) whose embedded len equals the stride. "
        "Per-entry measurement semantics deferred: for v0x06 and v0x04 the "
        "SDR/RFFE F3 (navrx_sdr855/rflm/rfdevice; SDR855 is the shared RF "
        "front-end, not GNSS) co-emits but is not enriched and prints no "
        "per-entry values, so it cannot label the fields; v0x05 is "
        "inconclusive (single FT980M F3 capture, 77 records, nothing enriched "
        "over control, no value print); v0x07 has no F3-bearing capture."
    ),

    source_url="",
    issues=(),
    fields_identified=5,
    fields_parsed=5,
    field_invariants={
        "version": {"enum": _1C0D_VERSIONS_OBSERVED},
        "payload_size": {"enum": _1C0D_SIZES_OBSERVED},
        "entry_stride": {"enum": _1C0D_STRIDES_OBSERVED},
    },
)
def parse_0x1c0d(log_time: int, data: bytes) -> Diag0x1C0D | None:
    if len(data) < _1C0D_HEADER_SIZE:
        return None
    version = data[0]
    layout = _1C0D_VERSION_LAYOUT.get(version)
    if layout is None:
        return None
    payload_size, stride = layout
    if len(data) != payload_size:
        return None
    # Misframe guard: the first entry must be the self-describing TLV whose
    # embedded length equals the expected stride. A 2404/2004/3004-byte HDLC
    # misframe with a matching version byte but garbage body is rejected here.
    if data[_1C0D_HEADER_SIZE] != _1C0D_ENTRY_TAG:
        return None
    if data[_1C0D_HEADER_SIZE + 1] != _1C0D_ENTRY_TYPE:
        return None
    if unpack_from("<H", data, _1C0D_HEADER_SIZE + 2)[0] != stride:
        return None
    entries = [
        data[_1C0D_HEADER_SIZE + i * stride:
             _1C0D_HEADER_SIZE + (i + 1) * stride]
        for i in range(_1C0D_ENTRY_CAPACITY)
    ]
    return Diag0x1C0D(
        log_time=log_time,
        version=version,
        num_entries=data[1],
        seq=unpack_from("<H", data, 2)[0],
        entry_stride=stride,
        entries=entries,
        payload_size=len(data),
    )
