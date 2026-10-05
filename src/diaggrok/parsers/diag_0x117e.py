"""0x117E -- GPS multi-peaks verbose searcher: grid descriptor + fragmented grid dump.

Identity: ``LOG_SRCH_GPS_MULTI_PEAKS_VERBOSE_INFO_C`` (canonical log name). It
fires only inside GNSS sessions, across every vendor.

The whole code is one record format. Every record, whatever its size, starts
with the same 8-byte header. The 55/58/62 B records and the 152..10248 B
records are the two halves of one search-grid log: a **descriptor**
(fragment 0) followed by one or more **dump fragments** that carry the
correlation grid.

Common header (all sizes, all chipsets)::

    [0:4]  u32  record_seq     shared by a descriptor and its dump fragments
    [4:6]  u16  fragment       0 = descriptor; else bit15 = last fragment,
                               bits0..14 = 1-based fragment index
                               (0x8001 = a single-fragment dump)
    [6:8]  u16  body_len       == payload_size - 8  (drift guard)

Note that ``[0:2]`` alone looks like a u16 counter, ``[2:6]`` like a reserved
zero and ``[6]`` like a length marker; they are the low half of
``record_seq``, the ``fragment`` word (0 on a descriptor) and the low byte of
``body_len``.

Dump size is fixed by the descriptor's grid dims ``(grid_a, grid_n, grid_m)``,
in one of two element encodings (sampled over 26 chipsets, every pair class exact):

* u16 samples:         ``A*N*M*2`` bytes     (EG25/EG95/MC7455, EM7511, EM9291, FN980/RM500Q 1920/10240 B)
* u8 samples + 4 B/row: ``A*N*(M+4)`` bytes  (SDX20/SDX55/SDX62/MDM9x50 1300/5200/3640 B ...)

The descriptor selects the encoding. d58
byte ``[57]`` is ``0`` for u16 samples and ``1`` for u8 + 4 B/row, exact on
every paired descriptor/dump of 22 captures over 20 chipset families (MDM9x50,
SDX20, MDM9150, MDM9250, SDX50M, SDX55, SDX62, SDX65, SDX72; e.g. RM500Q
wardrive 3458/3458 and CFW-3212 3499/3499, each mixing both encodings in one
capture). Every ``d55`` pair (MC7455, EG95, EP06, EG25-G; 4,854 pairs) is u16.
On u8-only builds (EG18-NA) ``[57]`` is a constant 1. ``sample_encoding`` /
``dump_bytes`` expose the selected size; both candidate sizes
(``dump_bytes_u16`` / ``dump_bytes_u8``) stay for consumers. A large dump is split across fragments: e.g. 20x40x8 u16 = 12800 B
arrives as 3 x 3500 B (fragments 1,2,3) + 2300 B (``0x8004``). Dump bodies are
raw correlation energies, exposed as ``body_len`` only.

Descriptor layouts, grounded against in-capture F3 by joining on SV and then on
the exact job id (the shifted-SV baseline is shown beside each count):

``d58`` -- 58 B (MDM9x50/SDX20/MDM9x5x) and 62 B (SDX55/SDX62/SDX65/SDX72)::

    [8:10]  u16 descriptor_tag  == 0x0066 (drift guard)
    [11]    u8  sv              join key, 596/611 exact-jobid joins (EG18-NA),
                                216/216 (RXM-G1 SDX62)
    [12]    u8  search_mode     == F3 ``New jobid ... Mode`` 595/596 (EG18-NA),
                                216/216 (RXM-G1); == ``Full PP ... SrchMode``
                                278/306 (baseline 36/80)
    [17]    u8  field_17        CANDIDATE num_noncoh: on SDX62 == low half of
                                F3 jobid ``NxM`` 209/216 and == ``DP: RPT ... NC``
                                104/216 (baseline 0), the analogue of d55 [15];
                                NOT on SDX20 (NxM lo 16/596), so kept raw
    [25:27] u16 grid_a
    [27:29] u16 grid_n          == high half of F3 jobid ``NxM`` 545/596 (EG18-NA)
    [29:31] u16 grid_m
    [33:37] u32 job_id          == F3 ``New jobid`` (low 32 bits of the 64-bit
                                SDX55+ jobid) and ``PkRpt 0x%08x`` 143/163
    [37:41] u32 ms              == F3 ``New Ch ... Ms`` (EG18-NA); tracks it
                                closely but not exactly on SDX62
    [45:49] i32 doppler         == F3 ``New Ch ... Dopp`` 152/227 (EG18-NA),
                                141/215 (RXM-G1); baseline 0
    [49:53] u32 code_phase      == F3 ``New Ch ... CP`` 68/227, 84/215
    [41:45], [53:57]            zero on all 6,957 paired SDX55/SDX62 descriptors
                                (RM500Q, CFW-3212); not named
    [57]    u8  sample_encoding 0 = u16 dump samples, 1 = u8 + 4 B/row (see above)
    62 B only: [58:62] trailing u32, unmapped ([60] only ever has its low
                                nibble clear; zero on ~half the records)

``d55`` -- 55 B (MDM9x07 / MDM9x30: EG25-G, EG95, EP06, MC7455)::

    [8]     u8  descriptor_tag  == 0x33 (drift guard)
    [11]    u8  sv              100/100 same-SV joins (baseline 15-49)
    [12]    u8  search_mode     == F3 ``Pk ... sMode`` 100/100
    [15]    u8  num_noncoh      == F3 ``Pk ... Numnoncoh`` 97/100; == ``No Pk
                                Rpt ... NxM`` M 81/100
    [23:29] u16 x3 grid_a / grid_n / grid_m
    [29:31] u16 peak_index      == F3 ``Pk %d`` 97/100
    [31:35] u32 job_id          == F3 ``No Pk Rpt ... Job 0x%X`` 76/87
    [35:39] u32 ms              == F3 ``No Pk Rpt ... GRTC`` 76/87
    [39:43] u32 peak_bin_idx    == F3 ``Pk ... Idx %lu`` 96/100
    [47:51] u32 code_phase      == F3 ``New Ch ... CP`` 37/100

F3-joined captures: an EG18-NA GNSS capture (SDX20, 611 descriptors), an
RXM-G1 radio/GNSS capture (SDX62, 216) and an EG25-G GNSS capture (MDM9x07,
100).

Log name: LOG_SRCH_GPS_MULTI_PEAKS_VERBOSE_INFO_C
Also known as: LOG_INTERNAL_GPS_VERBOSE_MULTIPEAK_VERSION_2
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_HEADER_LEN = 8
_LAST_FRAGMENT = 0x8000
_D55_TAG = 0x33      # u8 @ [8] of the 55 B descriptor
_D58_TAG = 0x0066    # u16 @ [8:10] of the 58/62 B descriptor
_D58_ENCODING = {0: 'u16', 1: 'u8x4'}   # d58 byte [57] -> dump sample encoding


@dataclass
class Diag0x117E:
    """0x117E -- GPS multi-peaks searcher descriptor or grid-dump fragment.

    Descriptor-only fields are ``None`` on a dump fragment, and a field a
    layout does not carry is ``None`` on that layout.
    """

    log_time: int
    payload_size: int
    record_seq: int
    fragment_index: int           # 0 = descriptor
    last_fragment: bool
    body_len: int
    record_kind: str              # 'descriptor' | 'dump'
    layout: str | None            # 'd55' | 'd58' (descriptors only)
    descriptor_tag: int | None
    sv: int | None
    search_mode: int | None
    grid_a: int | None
    grid_n: int | None
    grid_m: int | None
    job_id: int | None
    ms: int | None
    doppler: int | None           # d58 only
    code_phase: int | None
    num_noncoh: int | None        # d55 only
    peak_index: int | None        # d55 only
    peak_bin_idx: int | None      # d55 only
    field_17: int | None          # d58 only, CANDIDATE (see module doc)
    sample_encoding: str | None = None   # 'u16' | 'u8x4' (descriptors only)

    @property
    def dump_bytes_u16(self) -> int | None:
        """Grid dump size if the samples are u16."""
        if self.grid_a is None:
            return None
        return self.grid_a * self.grid_n * self.grid_m * 2

    @property
    def dump_bytes_u8(self) -> int | None:
        """Grid dump size if the samples are u8 with a 4-byte row suffix."""
        if self.grid_a is None:
            return None
        return self.grid_a * self.grid_n * (self.grid_m + 4)

    @property
    def dump_bytes(self) -> int | None:
        """Grid dump size in the encoding the descriptor selects."""
        if self.sample_encoding == 'u16':
            return self.dump_bytes_u16
        if self.sample_encoding == 'u8x4':
            return self.dump_bytes_u8
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x117E',
            'log_time': self.log_time,
            'payload_size': self.payload_size,
            'record_seq': self.record_seq,
            'fragment_index': self.fragment_index,
            'last_fragment': self.last_fragment,
            'body_len': self.body_len,
            'record_kind': self.record_kind,
            'layout': self.layout,
            'descriptor_tag': self.descriptor_tag,
            'sv': self.sv,
            'search_mode': self.search_mode,
            'grid_a': self.grid_a,
            'grid_n': self.grid_n,
            'grid_m': self.grid_m,
            'job_id': self.job_id,
            'ms': self.ms,
            'doppler': self.doppler,
            'code_phase': self.code_phase,
            'num_noncoh': self.num_noncoh,
            'peak_index': self.peak_index,
            'peak_bin_idx': self.peak_bin_idx,
            'field_17': self.field_17,
            'sample_encoding': self.sample_encoding,
            'dump_bytes': self.dump_bytes,
            'dump_bytes_u16': self.dump_bytes_u16,
            'dump_bytes_u8': self.dump_bytes_u8,
        }


@register(0x117E, domain="gnss",
    name="0x117E",
    description=(
        "0x117E -- GPS multi-peaks verbose searcher (canonical name "
        "LOG_SRCH_GPS_MULTI_PEAKS_VERBOSE_INFO_C). Common 8 B header "
        "(record_seq, fragment, body_len). Fragment 0 is a search-grid "
        "descriptor (SV, search mode, grid dims, job id, ms, Doppler, code "
        "phase: F3-grounded), and fragments 1..N carry the correlation-grid "
        "dump (u16, or u8 + 4 B per row, selected by d58 byte [57])."
    ),
    version=6, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "One fragmented log across all record sizes: a common 8 B header "
        "(u32 record_seq, u16 fragment [bit15=last], u16 body_len==size-8), "
        "a fragment-0 descriptor and 1..N grid-dump fragments sharing "
        "record_seq. Dump size == grid_a*grid_n*grid_m*2 (u16) or "
        "grid_a*grid_n*(grid_m+4) (u8 + 4 B/row), exact on every sampled "
        "pair class (26 chipsets). d58 byte [57] selects the dump encoding "
        "(0 = u16, 1 = u8 + 4 B/row), exact on every descriptor/dump pair of "
        "22 captures over 20 chipset families; d55 is always u16. "
        "Descriptor fields F3-grounded on three "
        "builds by exact job-id join: EG18-NA SDX20 (sv/search_mode 596/611, "
        "doppler/code_phase/ms vs 'New Ch'), RXM-G1 SDX62 (216/216), EG25-G "
        "MDM9x07 55 B layout (sMode 100/100, Numnoncoh 97, Pk 97, Idx 96, "
        "Job/GRTC 76/87). Dump bodies are raw correlation energies, exposed "
        "as body_len only."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=22,
    fields_parsed=22,
    # byte-0 is the low byte of the record_seq counter, NOT a DIAG version.
    # The body_len and descriptor-tag drift guards are the real gate.
    version_less=True,
)
def parse_0x117e(log_time: int, data: bytes) -> Diag0x117E | None:
    n = len(data)
    if n < _HEADER_LEN:
        return None
    record_seq, fragment, body_len = unpack_from('<IHH', data, 0)
    # Drift guard: body_len == payload_size - 8 on every record of the corpus.
    if body_len != n - _HEADER_LEN:
        return None
    fragment_index = fragment & ~_LAST_FRAGMENT
    last_fragment = bool(fragment & _LAST_FRAGMENT)

    rec = Diag0x117E(
        log_time=log_time, payload_size=n, record_seq=record_seq,
        fragment_index=fragment_index, last_fragment=last_fragment,
        body_len=body_len, record_kind='dump', layout=None,
        descriptor_tag=None, sv=None, search_mode=None,
        grid_a=None, grid_n=None, grid_m=None, job_id=None, ms=None,
        doppler=None, code_phase=None, num_noncoh=None, peak_index=None,
        peak_bin_idx=None, field_17=None,
    )
    if fragment != 0:
        return rec

    rec.record_kind = 'descriptor'
    if n == 55:
        if data[8] != _D55_TAG:
            return None
        rec.layout = 'd55'
        rec.descriptor_tag = data[8]
        rec.sv = data[11]
        rec.search_mode = data[12]
        rec.num_noncoh = data[15]
        rec.sample_encoding = 'u16'
        rec.grid_a, rec.grid_n, rec.grid_m = unpack_from('<3H', data, 23)
        rec.peak_index = unpack_from('<H', data, 29)[0]
        rec.job_id, rec.ms, rec.peak_bin_idx = unpack_from('<3I', data, 31)
        rec.code_phase = unpack_from('<I', data, 47)[0]
    elif n in (58, 62):
        tag = unpack_from('<H', data, 8)[0]
        if tag != _D58_TAG:
            return None
        rec.layout = 'd58'
        rec.descriptor_tag = tag
        rec.sv = data[11]
        rec.search_mode = data[12]
        rec.field_17 = data[17]
        rec.grid_a, rec.grid_n, rec.grid_m = unpack_from('<3H', data, 25)
        rec.job_id, rec.ms = unpack_from('<2I', data, 33)
        rec.doppler = unpack_from('<i', data, 45)[0]
        rec.code_phase = unpack_from('<I', data, 49)[0]
        # 0/1 on every descriptor seen; any other value is surfaced as None.
        rec.sample_encoding = _D58_ENCODING.get(data[57])
    else:
        # A descriptor at a size no chipset has emitted: surface the drift.
        return None
    return rec
