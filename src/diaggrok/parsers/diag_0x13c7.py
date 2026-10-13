"""Converged GPS Medium Grid (0x13C7): multi-size, self-describing u16 body_len.

Chipset-gated to the MDM9x00 / MDM9x07 / MDM9x30 generations (MC7700,
EG25-G, EG95, EP06, SIM7600, MC7455, EM7455). It emits zero records on SDX20
(LM960, FN980), SDX55 (FN980 SDX55, RM500Q SDX55, EM9190), SDX62
(RM520N-GL), and X12 (Inseego M2000).

Variable-length, with 74+ distinct sizes. The top classes are
200B / 170B / 602B / 109B / 115B / 135B / 206B.

Key correctness invariant: ``payload_size == 8 + body_len`` where
``body_len`` is u16 LE at bytes[6:8]. The parser returns ``None`` on any
record that violates it, which covers truncated records and any future
format change that breaks the length field. byte[2:4] is universal
CONST 0x0000.

## One record = one GNSS search dwell; byte-0 pairs its two halves

Each 0x13C7 record reports one search **dwell** (one SV on one channel)
from the GNSS peak post-processor ``pp_columnpeaks.c``. ``mode_flags``
(u16 LE @ [4:6]) **bit 0** selects the half:

* **bit0 == 0** (mode 0x0000 / 0x8000) → **grid-summary**
  (200B / 170B / 135B / 109B …). This is the dwell's peak report.
* **bit0 == 1** (mode 0x8001) → **grid-array** (602B / 314B / 212B …).
  This is the dwell's energy grid.

A detected dwell emits a 200B summary immediately followed by a 602B grid
with the **same byte-0 `seq` and the same log timestamp** (1725/1775 on
the em7455 grounding capture). So byte-0 is a per-dwell pair counter
(uniform over 256 values), not a DIAG version.

Mode 0x8000 summaries are **no-detection** dwells: code phase, C/No and
code-hypothesis count are all 0, and no ``:3428`` / ``Pk Rpt`` line is
printed for them. They join SWI ``pp_columnpeaks.c:3147`` instead. Its hash
equals EG25-G ``:3132`` = ``"No Pk Rpt Ch %d GRTC %d SV %d Job 0x%X Mode %d
NxM %dx%d MC Sent %d"``. On the 150 200B / 27 170B / 10 135B mode-0x8000
records, ``body[0]`` = GRTC (150/150, 41 distinct) and ``body[54]`` = the M of
NxM (150/150, 45 distinct), the same slot as ``NC`` on detected dwells.
``body[66]`` = N (always 20) and ``body[8]`` = MC Sent (always 1) also match,
but each is a single value, so neither is a discriminating grounding. They
stay unnamed (``grid_count`` keeps its v4 name).

## Grid-summary layout (body offsets; header is bytes [0:8])

| body off | field | F3 label (site) | match on em7455 |
|--:|---|---|---|
| ``[0:4]`` | ``rtc_dwell_ms`` | ``RTC(of dwell)`` (``:3428`` arg1) | 1392/1392 distinct |
| ``[4:8]`` | ``reserved_body4`` | CONST 0 | |
| ``[8:12]`` | ``grid_count`` | 1 on 200B; bitmask-like on 170B | semantic open |
| ``[12:16]`` | ``doppler_nco_word`` (i32) | ``Dp`` (``:3579 Pk Rpt``) | r=1.00000 per Md |
| ``[16:20]`` | ``rtc_dwell_ms_echo`` | == ``[0:4]`` | 100% |
| ``[20:24]`` | ``grid_resolution`` | per-class const 25000/50000/100000/500000 | |
| ``[24:28]`` | ``code_phase_cx1024`` | ``CodePhase Cx1024`` (``:3428`` arg2) | 1775/1775 |
| ``[28:32]`` | ``reserved_body28`` | CONST 0 | |
| ``[50:52]`` | ``code_hyp_count`` | ``CHyp`` (``Pk Rpt``) | 1775/1775 |
| ``[54:56]`` | ``noncoh_count`` | ``NC`` (``Pk Rpt``) | 1775/1775 |
| ``[56:58]`` | ``threshold`` | CANDIDATE ``Thr`` (``:4133 Full PP``) | 1395/1775; EG25 880/6499 |
| ``[68:70]`` | ``cno_x100`` | ``CNo`` ×100 (``Pk Rpt``) | 1612/1775 exact |
| ``[75]`` | ``sv`` | ``SV`` (``Pk Rpt``) | 1775/1775 |
| ``[76]`` | ``srch_mode`` | ``Md`` (``Pk Rpt``) | 1775/1775 |

The overlay fields at body[50:77] are read only when the body reaches
byte 77 **and** ``body[74]`` holds the 0x33 marker. The marker is on every
grounded record and on 556,760 of 575,600 corpus summaries; the rest are
rare tail layouts left raw. ``grid_body_raw`` keeps body[32:] whole, so the
overlay never hides a byte.

``srch_mode`` values seen with their SV ranges (corpus walk): 3 → SV 1–32
(GPS), 17 → SV 1–14 (GLONASS), 7 → SV 125–135 (SBAS PRNs), plus 0, 1, 2,
12, 30, 31, 33, 35, 38, 39. Only 3 and 17 carry a Doppler-scale grounding.

**``doppler_nco_word`` is an NCO frequency word**, where
Doppler_Hz = word × f_s / 2³². The fitted slope is word/Dp = **2099.58** for
``Md`` 3 (2³²/2.046 MHz = 2099.2; GPS, 2× the 1.023 Mcps chip rate) and
**4203.14** for ``Md`` 17 (2³²/1.022 MHz = 4202.5; GLONASS, 2× 0.511 Mcps),
both with r = 1.00000 over n = 1022 and 744. Both fits share the same
intercept in Hz (−24980/2099.6 ≈ −49944/4203.1 ≈ −11.9 Hz), so ``Pk Rpt Dp``
reads a constant ~12 Hz above the word. The word is read as the dwell's
Doppler hypothesis and ``Dp`` as the refined peak (median |residual| ≈ 2.4 Hz
after the offset). ``doppler_hz`` is derived only
for those two modes. ``Md`` 30/31 (n=2, ratio 1049.7 ≈ 2³²/4.092 MHz) and
``Md`` 0/12/33 (inconsistent ratios) are left raw.

``code_phase_cx1024`` sits 0..64 Cx1024 units above the ``Pk Rpt``
``CPh (chips, frac)`` peak (chips×1024 + frac). That confirms the
chip×1024 unit.

The ``cno_x100`` misses (163/1775) differ from the F3 value in multiples
of 9 (0.09 dB-Hz). They look like a second report for the same SV, not a
layout error.

## Grid-array layout (602B)

The 594-byte body is **297 u16 energy cells, a 33 × 9 row-major grid**
centered on the peak. The argmax is cell **148** = [16][4] in 1762/1775
records, and **max(cells) == ``:4133 Full PP MaxGrid``** of the paired
dwell in 1707/1725 records. The mean normalized energy profile is high at
±1 (0.68) and ±9 (0.63) and flat at the noise floor (≈0.38) at ±11/±27/±33,
so the stride-9 axis is real. Which axis is code phase and which is
Doppler is not pinned (``"Can't read 3x3 energies for peak (phase, freq)"``
names the two axes, not their order). Other grid-array sizes stay raw. 206B
(99 cells = 11 × 9) and 314B (153 = 17 × 9) share the 9-wide stride and are
candidates; 212/178/246/280B do not divide by 9.

## MC7700 (MDM9200) is a different family

The MC7700 (``SWI9200X_03.05.20.03AP``, 28,304 records) emits 494B mode
0x0001 grids, **116B mode 0x8002** records and 198B summaries (9296 /
9296 / 9294). The 198B summaries keep the sub-header (echo holds) but carry
no 0x33 marker, so the overlay is skipped. Mode 0x8002 (bit 1 set) is a
third kind whose body[16:20] never echoes body[0:4]; it is routed to
``layout="other"`` and kept raw.

## Corpus (104 capture files)

732,112 records, **0 rejected** by the length gate, ``reserved_2`` = 0 on
all. The 602B grid argmax is cell 148 on 130,518 of 130,559 grids across
the six modems that emit 602B (EG25-G, EG95, EP06, MC7455, EM7455,
SIM7600; MC7700 emits none). The echo ``body[16:20] == body[0:4]`` holds on
566,304 of 575,600 bit0==0 records; all 9296 misses are the MC7700 mode-0x8002
records, now ``layout="other"``.

## Second chipset: EG25-G A0.301 (MDM9207)

A GNSS cold-start capture (46,457 records) was
joined with that build's own INDEX lines (``:3414`` = the RTC/CodePhase
site, ``:4130`` = Full PP, ``:3132`` = No Pk Rpt).

* ``(rtc_dwell_ms, code_phase_cx1024)`` joins ``:3414`` on **7186/7186**
  detected summaries across all five size classes.
* ``sv`` = Full PP ``SV`` on 7185/7186.
* Every mode-0x8000 summary joins ``No Pk Rpt`` on (GRTC, SV), and
  ``body[54]`` = M on all 32,085 of them.
* Every paired 602B grid (6172) has max == ``MaxGrid`` and argmax == 148.

``threshold`` matches Full PP ``Thr`` on only 880/6499 200B records here
(37/37 135B, 44/44 170B), so it stays a CANDIDATE: probably a threshold,
but not always the one ``:4130`` prints.

## F3 grounding method

The capture is an EM7455 (SWI9X30C_02.24.03.00) all-codes capture with F3
enabled (3801 records). It carries both
legacy-QSR ``0x92`` and plaintext ``0x79`` F3.

* ``0x92`` sites resolve to ``file:line`` via the SWI9X30C INDEX.
  Their **format strings** come from a cross-build hash join:
  QShrink hashes are text-derived, so the SWI9X30C hash finds the same
  message in an EG25-G INDEX, whose ``(file, line)`` keys the OCPU STRING DB.
  For example, ``pp_columnpeaks.c:3428``
  = ``"Ch %d, RTC(of dwell) %d, CodePhase Cx1024 %d"`` and ``:4133`` =
  ``"Full PP Ch %d MaxGrid %d Idx %d Thr %d Noise %d Cno %d SV %d PFA %d Blnk 0x%x"``.
* ``0x79`` ``pp_columnpeaks.c:3579`` = ``"Pk Rpt Ch .. GRTC .. SV .. Md .. CHyp ..
  CPh (.., ..) Dp .. CNo .. NC .. BE .."``. It is joined per record by SV,
  nearest timestamp (median dt −538 ticks).

History: an earlier version grounded body[0:4]/[24:28] to
``:3428`` arg1/arg2 by value only. Without the format string it named them
``col_peak_value`` / ``col_peak_energy``, which the rendered text shows are
wrong (they are a ms-timebase dwell RTC and a Cx1024 code phase). v5
renames them.

Log name: LOG_CONVERGED_GPS_MEDIUM_GRID_C
Also known as: LOG_INTERNAL_CGPS_MEDIUM_GRID
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# Grid-summary sub-header (mode_flags bit0 == 0): 32-byte fixed prefix of the
# body. The F3-named overlay fields run to body[76]; see the module docstring.
_GRID_SUMMARY_SUBHDR = 32
_GRID_SUMMARY_OVERLAY_END = 77
# body[74] is 0x33 on every grounded summary (96.7% of corpus summaries); the
# overlay is read only when it is present, so an unseen tail layout is not
# misnamed.
_OVERLAY_MARKER = 0x33

# doppler_nco_word -> Hz: word * f_s / 2**32, f_s = 2x the chip rate. Only the
# two search modes with an r=1.0 fit on the grounding capture are mapped.
_NCO_SAMPLE_HZ_BY_MODE = {
    3: 2_046_000.0,    # GPS (2 x 1.023 Mcps); slope 2099.58 vs 2099.2 expected
    17: 1_022_000.0,   # GLONASS (2 x 0.511 Mcps); slope 4203.14 vs 4202.5 expected
}

# 602B grid-array: 297 u16 cells, 33 x 9 row-major, peak at cell 148 = [16][4].
_GRID_ARRAY_BODY_LEN = 594
_GRID_ROWS, _GRID_COLS = 33, 9


@dataclass
class Diag0x13C7:
    """0x13C7: one GNSS search dwell, as a peak summary or an energy grid.

    The 8-byte header is fully named. The body is ``mode_flags``-bit0
    discriminated (see the module docstring). **grid_summary** (bit0==0)
    exposes an F3-labeled sub-header plus overlay fields. **grid_array**
    (bit0==1) exposes the 33 x 9 energy grid on the 602B class and keeps
    other sizes raw.

    Key correctness invariant: ``payload_size == 8 + body_len``. The parser
    returns ``None`` on any record that violates this.
    """

    log_time: int
    seq: int             # byte[0]: per-dwell counter; pairs a summary with its grid
    flags1: int          # byte[1]: per-record varying, semantic unknown
    reserved_2: int      # u16 from bytes[2:4]: universal CONST 0x0000
    mode_flags: int      # u16 from bytes[4:6]: bit0 selects body layout
    body_len: int        # u16 from bytes[6:8]: body length; size = 8 + body_len
    payload_size: int    # total record size (always == 8 + body_len)
    # "grid_summary" (bit0==0) | "grid_array" (bit0==1) | "other" (bit1==1) | "header_only"
    layout: str = "header_only"
    # --- grid-summary sub-header (populated only when layout=="grid_summary") ---
    rtc_dwell_ms: int | None = None          # body[0:4]   = pp_columnpeaks:3428 "RTC(of dwell)"
    reserved_body4: int | None = None         # body[4:8]   = CONST 0
    grid_count: int | None = None             # body[8:12]  = 1 on 200B; semantic open
    doppler_nco_word: int | None = None       # body[12:16] i32 NCO word ~ Pk Rpt "Dp"
    rtc_dwell_ms_echo: int | None = None      # body[16:20] == rtc_dwell_ms
    grid_resolution: int | None = None        # body[20:24] = per-class const (25000/...)
    code_phase_cx1024: int | None = None      # body[24:28] = pp_columnpeaks:3428 "CodePhase Cx1024"
    reserved_body28: int | None = None        # body[28:32] = CONST 0
    # --- overlay fields inside the tail (body_len >= 77) ---
    code_hyp_count: int | None = None         # body[50:52] = Pk Rpt "CHyp"
    noncoh_count: int | None = None           # body[54:56] = Pk Rpt "NC"
    threshold: int | None = None              # body[56:58] = :4133 "Thr"
    cno_x100: int | None = None               # body[68:70] = Pk Rpt "CNo" x 100 (dB-Hz)
    sv: int | None = None                     # body[75]    = Pk Rpt "SV"
    srch_mode: int | None = None              # body[76]    = Pk Rpt "Md" (3 GPS, 17 GLONASS, ...)
    grid_body_raw: bytes | None = None        # body[32:] tail (grid_summary, overlay included)
                                              # OR entire body (grid_array, non-602B)
    # --- grid-array (602B class) ---
    grid_cells: tuple[int, ...] | None = None  # 297 u16 energies, 33 x 9 row-major
    grid_peak_energy: int | None = None        # max(grid_cells) == :4133 "MaxGrid"

    @property
    def doppler_hz(self) -> float | None:
        """Doppler in Hz from the NCO word, only for the grounded search modes."""
        fs = _NCO_SAMPLE_HZ_BY_MODE.get(self.srch_mode)
        if fs is None or self.doppler_nco_word is None:
            return None
        return self.doppler_nco_word * fs / 2**32

    @property
    def cno_dbhz(self) -> float | None:
        return None if self.cno_x100 is None else self.cno_x100 / 100.0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x13C7',
            'log_time': self.log_time,
            'seq': self.seq,
            'flags1': self.flags1,
            'reserved_2': self.reserved_2,
            'mode_flags': self.mode_flags,
            'body_len': self.body_len,
            'payload_size': self.payload_size,
            'layout': self.layout,
        }
        if self.layout == "grid_summary":
            d.update({
                'rtc_dwell_ms': self.rtc_dwell_ms,
                'reserved_body4': self.reserved_body4,
                'grid_count': self.grid_count,
                'doppler_nco_word': self.doppler_nco_word,
                'rtc_dwell_ms_echo': self.rtc_dwell_ms_echo,
                'grid_resolution': self.grid_resolution,
                'code_phase_cx1024': self.code_phase_cx1024,
                'reserved_body28': self.reserved_body28,
            })
            if self.sv is not None:
                d.update({
                    'code_hyp_count': self.code_hyp_count,
                    'noncoh_count': self.noncoh_count,
                    'threshold': self.threshold,
                    'cno_x100': self.cno_x100,
                    'cno_dbhz': self.cno_dbhz,
                    'sv': self.sv,
                    'srch_mode': self.srch_mode,
                    'doppler_hz': self.doppler_hz,
                })
            d['grid_body_raw'] = self.grid_body_raw
        elif self.layout == "other":
            d['grid_body_raw'] = self.grid_body_raw
        elif self.layout == "grid_array":
            if self.grid_cells is not None:
                d['grid_rows'] = _GRID_ROWS
                d['grid_cols'] = _GRID_COLS
                d['grid_cells'] = list(self.grid_cells)
                d['grid_peak_energy'] = self.grid_peak_energy
            else:
                d['grid_body_raw'] = self.grid_body_raw
        return d


@register(0x13C7,
    name="0x13C7",
    description=(
        "Converged GPS Medium Grid 0x13C7: GNSS search-dwell peak summary + "
        "33x9 energy grid; pp_columnpeaks; MDM9x00/9x07/9x30-gated; 8-byte "
        "header with u16 LE body_len (payload_size = 8 + body_len); mode_flags "
        "bit0 selects summary (200/170/135/115/109B) vs grid (602B)"
    ),
    version=5, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Header (8B) fully named; payload_size == 8 + body_len and reserved_2 "
        "CONST 0x0000 across the MDM9x07 + MDM9x30 corpus (Quectel EG25-G, "
        "EG18-NA, EG95-NA, EP06-A; Sierra MC7455, EM7455; SIMCom SIM7600NA). "
        "Zero records on SDX20/SDX55/SDX62/X12. F3-labeled on SWI9X30C EM7455 "
        "alldiag-f3 (3801 records). 0x92 format strings via a cross-build "
        "hash join (SWI9X30C INDEX -> EG25-G INDEX -> OCPU STRING DB), "
        "plus the 0x79 'Pk Rpt' (pp_columnpeaks.c:3579) joined per record by "
        "SV. Summary: rtc_dwell_ms = :3428 'RTC(of dwell)' 1392/1392; "
        "code_phase_cx1024 = :3428 'CodePhase Cx1024' 1775/1775; CHyp/NC/SV/Md "
        "1775/1775 at body[50]/[54]/[75]/[76]; CNo x100 at body[68] 1612/1775; "
        "body[56] CANDIDATE Thr (1395/1775); mode 0x8000 = 'No Pk Rpt' "
        "(:3147 == EG25 :3132), body[0]=GRTC, body[54]=M of NxM; doppler_nco_word (body[12]) = Dp x "
        "2^32/f_s, r=1.00000 for Md 3 (f_s 2.046 MHz, GPS) and Md 17 (1.022 MHz, "
        "GLONASS). Grid: 602B body = 297 u16 cells, 33x9 row-major, argmax "
        "cell 148 (1762/1775), max == :4133 MaxGrid of the paired dwell "
        "(1707/1725); summary+grid share seq byte and timestamp. MC7700 "
        "(MDM9200) mode 0x8002 116B -> layout 'other' (raw). Reproduced on "
        "EG25-G A0.301 MDM9207: RTC/CodePhase 7186/7186, SV 7185/7186, No Pk "
        "Rpt 32085/32085, grid max+argmax 6172/6172. Corpus 732,112 records "
        "/ 104 files, 0 rejects. v4 names "
        "col_peak_value/col_peak_energy were value-only guesses, renamed. "
        "Open: grid axes order, grid_count, mode-0x8000 :3147 words, the rest "
        "of the summary tail, non-602B grid sizes."
    ),
    issues=(),
    # 7 header/layout + 8 sub-header + 6 overlay + grid_cells = 22.
    fields_identified=22,
    fields_parsed=22,
    field_invariants={
        "reserved_2": {"enum": [0x0000]},
    },
    # byte-0 is a per-dwell pair counter (256/256 values), NOT a DIAG version;
    # the `payload_size == 8 + body_len` length gate and reserved_2 CONST
    # 0x0000 already reject foreign payloads. A byte-0 `version` enum would be
    # semantically false and reject 255/256 of the corpus.
    version_less=True,
)
def parse_0x13c7(log_time: int, data: bytes) -> Diag0x13C7 | None:
    n = len(data)
    if n < 8:
        return None
    body_len = unpack_from('<H', data, 6)[0]
    if 8 + body_len != n:
        # Layer-2 plausibility: the self-describing length must match the
        # record size. Any record that breaks this is either truncated or
        # a future format variant — reject so the corpus-decode pipeline
        # surfaces it rather than silently misparsing.
        return None
    mode_flags = unpack_from('<H', data, 4)[0]
    rec = Diag0x13C7(
        log_time=log_time,
        seq=data[0],
        flags1=data[1],
        reserved_2=unpack_from('<H', data, 2)[0],
        mode_flags=mode_flags,
        body_len=body_len,
        payload_size=n,
    )
    if body_len == 0:
        return rec  # layout stays "header_only"
    if mode_flags & 0x0002:
        # mode 0x8002 (MC7700 / MDM9200 116B): a third record kind, not a
        # summary (its body[16:20] never echoes body[0:4]). Kept raw.
        rec.layout = "other"
        rec.grid_body_raw = bytes(data[8:])
        return rec
    if mode_flags & 0x0001:
        rec.layout = "grid_array"
        if body_len == _GRID_ARRAY_BODY_LEN:
            cells = unpack_from('<%dH' % (_GRID_ROWS * _GRID_COLS), data, 8)
            rec.grid_cells = cells
            rec.grid_peak_energy = max(cells)
        else:
            rec.grid_body_raw = bytes(data[8:])
        return rec
    if body_len >= _GRID_SUMMARY_SUBHDR:
        # Offsets below are body-relative (+8 for the header).
        rec.layout = "grid_summary"
        rec.rtc_dwell_ms = unpack_from('<I', data, 8)[0]
        rec.reserved_body4 = unpack_from('<I', data, 12)[0]
        rec.grid_count = unpack_from('<I', data, 16)[0]
        rec.doppler_nco_word = unpack_from('<i', data, 20)[0]
        rec.rtc_dwell_ms_echo = unpack_from('<I', data, 24)[0]
        rec.grid_resolution = unpack_from('<I', data, 28)[0]
        rec.code_phase_cx1024 = unpack_from('<I', data, 32)[0]
        rec.reserved_body28 = unpack_from('<I', data, 36)[0]
        if (body_len >= _GRID_SUMMARY_OVERLAY_END
                and data[8 + 74] == _OVERLAY_MARKER):
            rec.code_hyp_count = unpack_from('<H', data, 8 + 50)[0]
            rec.noncoh_count = unpack_from('<H', data, 8 + 54)[0]
            rec.threshold = unpack_from('<H', data, 8 + 56)[0]
            rec.cno_x100 = unpack_from('<H', data, 8 + 68)[0]
            rec.sv = data[8 + 75]
            rec.srch_mode = data[8 + 76]
        rec.grid_body_raw = bytes(data[40:])
        return rec
    # bit0==0 but body too short for the sub-header — preserve raw, name known.
    rec.layout = "grid_array"
    rec.grid_body_raw = bytes(data[8:])
    return rec
