"""0x13C6 LOG_CGPS_SLOW_CLOCK_REPORT_C — kind-0 (28B) + kind-1 (30B / 34B) pair.

The "LTE Config" title some older tables give this code is a misnomer: the
canonical log name is the CGPS slow-clock report, and the F3 grounding below
confirms the GNSS time/slow-clock subsystem.

## Record family

Every event emits TWO records back-to-back on the same DIAG tick (1:1 on
2,977/2,977 MC7700 + 25/25 AirCard 791L + 231/231 newer-silicon pairs): a
**kind-0** time report and a **kind-1** slow-clock time report. Both open with
the same 4-byte header::

    [0]    u8   0x01       CONST (gated)
    [1]    u8   kind       0 = kind-0 (28B), 1 = kind-1 (30B / 34B body)
    [2:4]  u16  subtype    0x0000 = no GPS time; 0x0301 / 0x0303 = time valid

Kind-0, 28B (all silicon)::

    [4:12]  f64  time_tick_ms   local ms time tick; tracks the co-temporal
                                ale_proc.c:6705 "Nav solution time (TT=%u …)"
                                F3 TimeTick within a few ms (MDM9250)
    [12:20] f64  gps_time_ms    GPS time, ms since the GPS epoch
                                (= week*604.8e6 + tow; agrees with the paired
                                kind-1 (gps_week, gps_tow_ms) within 1.9 ms on
                                2,850/2,850 MC7700 pairs, ≤101 ms newer silicon)
    [20:28] f64  time_unc_ms    time uncertainty, ms; 1e100 = "unknown"
                                sentinel; tracks the F3 Tunc (see below)

Kind-1 body, 26B after the header — the **30B** record on MDM9200 (Sierra
MC7700) and MDM9x35 (AirCard 791L); on MDM9x07 and later it is the **34B**
record, i.e. the same body behind a 4-byte u32 ``prefix_counter`` (a monotonic
counter, +1 per record on MDM9250)::

    body[4:8]   u32  fcount            GNSS ME frame count — F3 "Rtc"/"FCnt"
    body[8:12]  u32  slow_clock_count  32.768 kHz slow-clock count (low 32 b)
    body[12:16] u32  word_12           {0,1}; NOT the F3 "Vd" flag (0 with Vd=1)
    body[16:18] u16  gps_week          F3 "Wk"
    body[18:22] u32  gps_tow_ms        F3 "Ms" (GPS time of week, ms)
    body[22:26] f32  time_bias_ms      F3 "TBias"; (-1, 0] on 3,065/3,065
    body[26:30] f32  tunc_ms           F3 "Tunc", stored floored at 0.1 ms

### F3 ground truth

On a 30-second Ficosa CarCom-G1 (MDM9250) capture with plaintext 0x79 F3,
every one of the 71 time-valid pairs is printed on the SAME
tick by ``mc_slow_clk.c:2434 "Slow_Clk time: Vd %u Tunc %f Rtc %u Wk %u Ms %u
TBias %f Src %u"``. Joined on exact (Wk, Ms), 71/71: ``Rtc == fcount``,
``TBias == time_bias_ms`` (6 dp), ``Src (3) == subtype`` bytes [2] and [3]
(both 3 on this capture, so which byte carries Src is not separable here), and
``tunc_ms == max(Tunc, 0.1)`` (the record floors it; the print does not).
``mgp_pe_api.c:715/720 "PE: Slow Clock Time: Wk=%u, Ms=%lu, Tunc/FCnt=%lu"``
repeats Wk/Ms/FCnt 71/71, and ``gts.c:8039 "GetClockAndRtc: … SlwClk 0x%x%08x
…"`` carries ``slow_clock_count`` as its low word. The slow-clock rate against
the paired ``gps_time_ms`` is 32.768 ticks/ms (median over 606 MC7700 and 52
newer intervals). ``fcount`` advances ~1/ms on MDM9250/EG25-G but ~0.36/ms on
the MDM9200 MC7700 — its unit there is not established.

The MC7700 (SWI9200X) reports ``gps_week`` values 1024 weeks behind the true
week (e.g. 1397 against a true 2421: the 2019 week-number rollover). The DIAG frame
timestamps of the same captures carry the same offset. The parser exposes the
raw value.

Time-unknown state (subtype 0x0000, 168/168 pairs across all silicon): kind-0
``time_unc_ms`` = 1e100, ``gps_time_ms`` == ``time_tick_ms``, kind-1 body all
zero.

### Gates

- 28B: CONST ``01 00`` header (unchanged).
- 30B: CONST ``01 01`` header (3,002/3,002 corpus records).
- 34B: no gate. The kind-1 body fields are populated only when
  bytes [4:6] carry the ``01 01`` kind-1 header (231/231 measured records);
  otherwise the record is still accepted with those fields ``None``.

## byte-0 is not a DIAG version

byte-0 is the CONST 0x01 of the record header on the 28B/30B forms and the low
byte of the 34B ``prefix_counter`` (per-record data). There is no single byte-0
"version" value that spans the code, so a ``field_invariants["version"]`` enum
would be semantically false. The real discriminant is the ``payload_size``
enum [28, 30, 34] size-dispatch plus the header gates. Declared
``version_less=True``; the legacy ``version`` field is ``byte0``.

Log name: LOG_CGPS_SLOW_CLOCK_REPORT_C
Also known as: LOG_INTERNAL_CGPS_SLOW_CLOCK_REPORT
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_KIND0_SIZE = 28
_KIND1_SIZE = 30            # MDM9200 / MDM9x35: header + 26B body
_KIND1_PREFIXED_SIZE = 34   # MDM9x07+: u32 prefix_counter + the 30B record
_KIND0_HEADER = b'\x01\x00'
_KIND1_HEADER = b'\x01\x01'

_KIND0_FIELDS = ('time_tick_ms', 'gps_time_ms', 'time_unc_ms')
_KIND1_FIELDS = ('fcount', 'slow_clock_count', 'word_12', 'gps_week',
                 'gps_tow_ms', 'time_bias_ms', 'tunc_ms')


@dataclass
class Diag0x13C6:
    """0x13C6 CGPS slow-clock report: kind-0 (28B) or kind-1 (30B / 34B).

    Fields emitted by ``to_dict`` depend on ``size_class`` (see the module
    docstring). ``byte0`` / ``reserved_1`` / ``subtype_28`` / ``subtype_34`` /
    ``reserved_3`` are older field names, kept for back-compat.
    """

    log_time: int
    byte0: int              # byte[0]: CONST 0x01 on 28B/30B; prefix LSB on 34B
    payload_size: int       # 28, 30 or 34
    size_class: int         # alias for payload_size for explicit dispatch
    kind: int | None = None      # header byte[1]: 0 = kind-0, 1 = kind-1
    subtype: int | None = None   # header u16 [2:4]
    # 28B legacy fields
    reserved_1: int | None = None
    subtype_28: int | None = None
    # 34B legacy fields
    subtype_34: int | None = None   # u32 [4:8] = the kind-1 header as a u32
    reserved_3: int | None = None   # byte[3] (MSB of prefix_counter)
    prefix_counter: int | None = None  # 34B only: u32 [0:4]
    # kind-0 body
    time_tick_ms: float | None = None
    gps_time_ms: float | None = None
    time_unc_ms: float | None = None
    # kind-1 body
    fcount: int | None = None
    slow_clock_count: int | None = None
    word_12: int | None = None
    gps_week: int | None = None
    gps_tow_ms: int | None = None
    time_bias_ms: float | None = None
    tunc_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x13C6',
            'log_time': self.log_time,
            'byte0': self.byte0,
            'payload_size': self.payload_size,
            'size_class': self.size_class,
            'kind': self.kind,
            'subtype': self.subtype,
        }
        if self.size_class == _KIND0_SIZE:
            d['reserved_1'] = self.reserved_1
            d['subtype_28'] = self.subtype_28
            for f in _KIND0_FIELDS:
                d[f] = getattr(self, f)
        else:
            if self.size_class == _KIND1_PREFIXED_SIZE:
                d['subtype_34'] = self.subtype_34
                d['reserved_3'] = self.reserved_3
                d['prefix_counter'] = self.prefix_counter
            for f in _KIND1_FIELDS:
                d[f] = getattr(self, f)
        return d


def _decode_kind1(rec: Diag0x13C6, data: bytes, base: int) -> None:
    """Fill the kind-1 header + 26B body starting at ``data[base]``."""
    rec.kind = data[base + 1]
    rec.subtype = unpack_from('<H', data, base + 2)[0]
    (rec.fcount, rec.slow_clock_count, rec.word_12, rec.gps_week,
     rec.gps_tow_ms, rec.time_bias_ms, rec.tunc_ms) = unpack_from(
        '<3IHI2f', data, base + 4)


@register(0x13C6,
    name="0x13C6",
    description=(
        "0x13C6 — CGPS slow-clock report pair: kind-0 28B (time tick, GPS "
        "time ms, time unc) + kind-1 (30B MDM9200/9x35, 34B = u32 prefix + "
        "the same body on MDM9x07+: fcount, 32.768 kHz slow-clock count, GPS "
        "week/tow, TBias, Tunc; F3-grounded on mc_slow_clk.c)"
    ),
    version=4, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Decodes the kind-0 (28B) / kind-1 record pair across a 9,928-record "
        "cross-chipset corpus. The 30B form (MC7700 MDM9200 2,977 + AirCard "
        "791L MDM9x35 25 records, each the 1:1 partner of a 28B record) is the "
        "kind-1 record (CONST `01 01` header, gated); the 34B form is the same "
        "26B body behind a u32 prefix_counter. Kind-1 body F3-grounded 71/71 on "
        "a CarCom-G1 MDM9250 capture against the co-tick mc_slow_clk.c:2434 'Slow_Clk time: Vd Tunc "
        "Rtc Wk Ms TBias Src' print (Rtc=fcount, Wk, Ms, TBias exact; tunc_ms = "
        "max(Tunc, 0.1)), mgp_pe_api.c:715/720 (Wk/Ms/FCnt) and gts.c:8039 "
        "(SlwClk low word = slow_clock_count); slow-clock rate 32.768 ticks/ms vs "
        "the paired kind-0 gps_time_ms, which equals week*604.8e6+tow within "
        "1.9 ms on 2,850/2,850 MC7700 pairs. byte-0 is not a version byte "
        "(version_less=True; the legacy `version` field is `byte0`). fcount's "
        "unit on MDM9200 is not established."
    ),
    issues=(),
    fields_identified=15,
    fields_parsed=15,
    field_invariants={
        "payload_size": {"enum": [_KIND0_SIZE, _KIND1_SIZE, _KIND1_PREFIXED_SIZE]},
        "size_class": {"enum": [_KIND0_SIZE, _KIND1_SIZE, _KIND1_PREFIXED_SIZE]},
    },
    # byte-0 is the CONST 0x01 of the record header on 28B/30B and the low
    # byte of the 34B prefix_counter — NOT a code-wide version. The
    # payload_size enum [28,30,34] size-dispatch + the 28B/30B header gates
    # are the real discriminants (see the module docstring).
    version_less=True,
)
def parse_0x13c6(log_time: int, data: bytes) -> Diag0x13C6 | None:
    n = len(data)
    if n not in (_KIND0_SIZE, _KIND1_SIZE, _KIND1_PREFIXED_SIZE):
        return None
    # Layer-1 gates: the 28B / 30B forms open with a CONST two-byte header
    # (`01 00` on 3,000+ kind-0 records across the corpus, `01 01` on 3,002/
    # 3,002 30B kind-1 records). Reject anything else so a foreign payload of
    # the same size fails loudly instead of mis-decoding.
    if n == _KIND0_SIZE and data[:2] != _KIND0_HEADER:
        return None
    if n == _KIND1_SIZE and data[:2] != _KIND1_HEADER:
        return None
    rec = Diag0x13C6(
        log_time=log_time,
        byte0=data[0],
        payload_size=n,
        size_class=n,
    )
    if n == _KIND0_SIZE:
        rec.kind = data[1]
        rec.subtype = rec.subtype_28 = unpack_from('<H', data, 2)[0]
        rec.reserved_1 = data[1]
        rec.time_tick_ms, rec.gps_time_ms, rec.time_unc_ms = unpack_from(
            '<3d', data, 4)
    elif n == _KIND1_SIZE:
        _decode_kind1(rec, data, 0)
    else:  # 34B: u32 prefix_counter + the 30B kind-1 record
        rec.subtype_34 = unpack_from('<I', data, 4)[0]
        rec.reserved_3 = data[3]
        rec.prefix_counter = unpack_from('<I', data, 0)[0]
        if data[4:6] == _KIND1_HEADER:
            _decode_kind1(rec, data, 4)
    return rec
