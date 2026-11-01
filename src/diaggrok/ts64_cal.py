# diaggrok-provenance: re
"""DIAG ts64 → wall-clock timestamp calibration.

This calibrator operates on the OUTER HDLC LOG_F / DLF file-format
``ts64`` — the 64-bit monotonic counter at offset [8:16] of each
HDLC LOG_F frame body / DLF record header, counting in 1.25 ms ticks
since modem boot.

Do NOT feed the INNER DIAG-frame ``log_time`` (parsed by
``diaggrok.frame.parse_outer_frame`` in the diaggpsd live-streaming
path) to this calibrator — that field is a chipset-dependent
high-frequency counter (~17.24 ns/tick on SDX62, ~19.07 ns on SDX20,
etc.) and the rate mismatch would produce wildly incorrect UTC. See
``frame.py`` docstring for the two-timestamps layout.

Which module should new code use?
---------------------------------
Prefer :mod:`diaggrok.ts64_anchor`. Both anchor a capture
from its own ``0x1476`` GNSS reports and both *fit* the tick rate rather than
assuming one, but ``ts64_anchor.AnchorTable`` is the stronger model: it
refuses a capture it cannot anchor instead of falling back to a nominal rate
off one anchor, it interpolates between bracketing anchors inside the span
(tracking short-term clock wander a single global fit averages out), it says
whether each answer was interpolated or extrapolated, and it inverts.

This module stays for its existing callers (``diagmunge.munge.dlf_to_pcap``
among them) and is correct: it fits the tick rate from the anchors. It is the
weaker of the two, not a wrong one. The
shared line-fitting algebra lives in :func:`fit_line`, used by both, so there
is one implementation of the fit even though there are two façades over it.

Converting ts64 to wall-clock UTC requires an anchor point pairing a
known ts64 with a known wall-clock time.

This module provides anchor extraction from GNSS position reports (0x1476)
which contain both the outer ts64 (from the HDLC/DLF frame header) and
GPS time (gps_week + gps_tow_ms) — giving an exact ts64↔UTC correspondence.

Usage:
    cal = Ts64Calibrator()

    # Feed position reports as they're parsed
    cal.add_anchor(outer_ts64, gps_week, gps_tow_ms)

    # Convert any ts64 to UTC
    utc = cal.ts64_to_utc(some_ts64)

The calibrator handles:
    - Multiple anchors (uses linear fit for drift correction)
    - Invalid GPS times (gps_week=65535 → not yet fixed)
    - ts64 wraparound (unlikely but handled)

GPS time is **not** UTC: it does not observe leap seconds, and the offset has
been 18 s since the leap second at the end of 2016. :func:`gps_to_utc` subtracts
:data:`GPS_UTC_LEAP_SECONDS` and the calibrator records the value it used.
Omitting it is invisible inside one stream — a constant offset cancels
in relative timing — and a straight 18 s bias the moment DIAG time is compared
to a host clock, a gpsd track, or an ``at_poll.jsonl`` ``ts_utc``, which is the
normal case for wardrive analysis.

"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

# GPS epoch: January 6, 1980 00:00:00 UTC
_GPS_EPOCH = datetime(1980, 1, 6, tzinfo=timezone.utc)

# ts64 tick rate. Applies to the OUTER HDLC LOG_F / DLF file-format ts64 — not
# the inner DIAG-frame log_time. See the module docstring.
#
# The outer field is **Q16 fixed-point 1.25 ms ticks**, so one raw tick
# is 1.25e-3 / 65536 = 19.0735 ns. This module used to multiply the raw field by
# the un-shifted 1.25e-3, which is off by exactly 65536.
_TS64_Q16_SHIFT = 65536
_TS64_TICK_S = 1.25e-3 / _TS64_Q16_SHIFT     # 19.0735 ns

#: Nominal rate, used only when a single anchor makes a fit impossible.
#: Measured independently on two chipsets against clocks the fit never saw:
#: LM960A18 (SDX20) **19.0735** ns/tick from its own 217 ``0x1476`` GPS anchors
#: (residual sigma 0.30 ms), and SIM8202G-M2 (SDX55) **19.0743** ns/tick from
#: its own ``diag_verno_response`` host anchors. The outer field's rate is
#: therefore not chipset-varying — but it is still only *nominal* here, and
#: :attr:`Ts64Calibrator.rate_fitted` says whether it was assumed or measured.
TS64_NOMINAL_TICK_S = _TS64_TICK_S

#: A fit is rejected when its anchors are this far from collinear. The anchors
#: come from one modem's own GNSS clock, so genuine scatter is sub-millisecond
#: (0.30 ms measured over 217 anchors); a second of residual means the anchors
#: disagree about what time it is, not that the clock is noisy.
_MAX_FIT_RESIDUAL_S = 1.0

#: Plausibility band for a fitted tick rate, as a factor either side of
#: :data:`TS64_NOMINAL_TICK_S`. Deliberately enormous — 10x is far beyond any
#: real clock drift — because its job is not precision but catching the
#: order-of-magnitude class of error: the 65536x Q16 mistake, or a
#: **two-anchor** fit off a bad anchor pair. Two points are always perfectly
#: collinear, so :data:`_MAX_FIT_RESIDUAL_S` cannot see them; this can.
#:
#: Rejecting rather than accepting an implausible rate is the lesson in
#: its general form: a wrong rate that still produces monotonic, plausible-
#: looking timestamps is worse than an honest refusal.
_TICK_RATE_TOLERANCE_FACTOR = 10.0

#: Stage-1 outlier gate: an anchor whose nominal-rate offset
#: (``utc - ts64 * TS64_NOMINAL_TICK_S``) is further than this from the median
#: offset is dropped before any fit. Coarse on purpose: it is measured against
#: the *assumed* rate, so it must absorb real drift across the whole capture
#: (60 ppm over 24 h is 5.2 s end to end), while the stale 0x1476 time-of-week
#: reports it exists for lag by hundreds of seconds (378..1,336 s measured on
#: the RM500Q-AE wardrive capture).
_STALE_OFFSET_WINDOW_S = 60.0

#: Stage-2 outlier gate: after a fit on the stage-1 survivors, anchors
#: more than this from the *fitted* line are dropped and the line refitted once.
#: Catches a stale anchor too close for stage 1, without any rate assumption.
#: 2 s is a working inlier band on real captures; the genuine
#: scatter it must keep is the 0 / -1 s whole-second split of time-only 0x1476.
_INLIER_RESIDUAL_S = 2.0

# Invalid GPS week sentinel
_GPS_WEEK_INVALID = 65535

#: GPS-UTC offset in seconds. GPS time does not observe leap seconds;
#: UTC does. The offset has been **18 s since the leap second at the end of 2016** and IERS has
#: announced none through at least 2026.
#:
#: This is a named constant, and :func:`gps_to_utc` takes it as an explicit
#: parameter, so a future leap second is a one-line edit with a visible blast
#: radius rather than a magic number buried in a conversion. It matches the
#: constants already used by ``apps/diaggpsd/gnss_compare.py`` and
#: ``apps/diaggpsd/gpsd_server.py``.
GPS_UTC_LEAP_SECONDS = 18


def fit_line(xs: list[float], ys: list[float]) -> Optional[tuple[float, float, list[float]]]:
    """Least-squares fit of ``y = intercept + slope * x``.

    Returns ``(slope, intercept, residuals)``, or ``None`` when the slope is
    unobservable — fewer than two points, or every x identical. Callers decide
    what to do about that; this function does not invent a rate.

    Least squares over **all** points, never just first/last: a two-point fit
    is maximally sensitive to one bad anchor *and* yields no residual, so
    nothing can sanity-check it. That is the failure this guards against.

    Extracted here because both :class:`Ts64Calibrator` and
    :class:`diaggrok.ts64_anchor.AnchorTable` fit exactly this line. Two copies
    of one algebra is how a wrong rate persisted in one of them while the other
    was right. The residual *summary* is deliberately left to the caller — this
    module reports a population stdev, ``AnchorTable`` a sample stdev and a
    max — so unifying the fit does not silently change either one's reported
    quality metric.
    """
    n = len(xs)
    if n < 2:
        return None
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    if sxx <= 0:
        return None
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / sxx
    intercept = mean_y - slope * mean_x
    resid = [y - (intercept + slope * x) for x, y in zip(xs, ys)]
    return slope, intercept, resid


@dataclass
class Ts64Anchor:
    """A single ts64 ↔ UTC anchor point from a GNSS position report."""
    ts64: int              # OUTER HDLC/DLF ts64 (1.25 ms ticks) — see module docstring
    utc: datetime          # UTC from GPS time
    gps_week: int
    gps_tow_ms: int


@dataclass
class Ts64Calibrator:
    """Convert DIAG ts64 timestamps to wall-clock UTC.

    Collects anchor points from GNSS position reports and uses them
    to convert arbitrary ts64 values to UTC datetimes.

    With a single anchor: constant offset (assumes no clock drift).
    With multiple anchors: a least-squares line through every anchor, after
    stale ones are excluded — :attr:`num_inliers` says how many were
    fitted, :attr:`num_outliers` how many were not.
    """
    anchors: list[Ts64Anchor] = field(default_factory=list)
    #: GPS-UTC offset applied when converting anchors. Recorded on the
    #: instance rather than only applied, so a consumer can tell what was
    #: assumed.
    leap_seconds: int = GPS_UTC_LEAP_SECONDS
    #: Seconds per raw ts64 tick. **Fitted** from the anchors when there are at
    #: least two; :data:`TS64_NOMINAL_TICK_S` otherwise.
    tick_s: float = TS64_NOMINAL_TICK_S
    #: True when :attr:`tick_s` was measured from this capture's own anchors,
    #: False when it is the nominal fallback. Never assume — read this.
    rate_fitted: bool = False
    #: Standard deviation of the fit residual, in seconds. The honest quality
    #: metric to report alongside any timestamp derived from this calibrator.
    residual_stdev_s: Optional[float] = None
    #: Why calibration was refused, when it was. None while healthy.
    reject_reason: Optional[str] = None
    #: How many of :attr:`anchors` the line was fitted on. The rest were
    #: judged stale by the outlier gate and are kept in :attr:`anchors` but
    #: ignored. None when there are no anchors.
    num_inliers: Optional[int] = None
    _epoch_s: Optional[float] = None    # cached: UTC epoch seconds at ts64 == 0

    def add_anchor(self, ts64: int, gps_week: int, gps_tow_ms: int,
                   *, refit: bool = True) -> bool:
        """Add an anchor from a GNSS position report.

        Args:
            ts64: OUTER HDLC LOG_F / DLF file-format ts64 (1.25 ms ticks).
                NOT the inner DIAG-frame ``log_time`` — see module docstring
                for the two-timestamps layout.
            gps_week: GPS week number from position report
            gps_tow_ms: GPS time of week in milliseconds
            refit: Refit the model now (the default). Pass False when adding
                many anchors in a row and call :meth:`refit` once afterwards —
                the model is stale until then. A refit is O(n), so refitting
                per anchor is O(n^2) over a capture's thousands of anchors.

        Returns:
            True if the anchor was accepted (valid GPS time), False if rejected.
        """
        if gps_week == _GPS_WEEK_INVALID or gps_week == 0:
            return False
        if gps_tow_ms > 604800000:  # > 7 days in ms
            return False

        utc = gps_to_utc(gps_week, gps_tow_ms, self.leap_seconds)
        anchor = Ts64Anchor(ts64=ts64, utc=utc,
                            gps_week=gps_week, gps_tow_ms=gps_tow_ms)
        self.anchors.append(anchor)
        if refit:
            self._update_calibration()
        return True

    def refit(self) -> None:
        """Refit the model from every anchor added so far."""
        self._update_calibration()

    def ts64_to_utc(self, ts64: int) -> Optional[datetime]:
        """Convert a ts64 timestamp to UTC datetime.

        Returns None when there is no usable model — no anchors, or a fit that
        was rejected (see :attr:`reject_reason`). Also returns None rather than
        raising when the result is not a representable datetime: the old code
        raised ``ValueError: year 13129 is out of range`` from deep inside a
        pcap writer, which is a worse failure than an honest None.
        """
        if self._epoch_s is None or not self.anchors:
            return None
        if self.reject_reason is not None:
            # A rejected fit must not hand out timestamps. Callers guard on
            # is_calibrated, but the two must not be able to disagree.
            return None
        try:
            return datetime.fromtimestamp(self._epoch_s + ts64 * self.tick_s,
                                          tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None

    def ts64_to_unix(self, ts64: int) -> Optional[float]:
        """Convert ts64 to Unix timestamp (seconds since 1970-01-01)."""
        utc = self.ts64_to_utc(ts64)
        return utc.timestamp() if utc else None

    @property
    def is_calibrated(self) -> bool:
        """Whether this calibrator has a model that is actually usable.

        This used to answer "did I accept an anchor?", so it returned
        True alongside ``drift_ppm == -999984.74`` — a clock losing a full
        second per second — and a 194 s span reported as 12,713,979 s. It now
        also requires the fit to have survived the sanity gate.
        """
        return (len(self.anchors) > 0
                and self._epoch_s is not None
                and self.reject_reason is None)

    @property
    def num_anchors(self) -> int:
        return len(self.anchors)

    @property
    def num_outliers(self) -> Optional[int]:
        """Anchors the outlier gate excluded from the fit."""
        if self.num_inliers is None:
            return None
        return len(self.anchors) - self.num_inliers

    @property
    def drift_ppm(self) -> Optional[float]:
        """Modem clock drift vs the nominal tick rate, in parts per million.

        None until the rate has actually been fitted — with one anchor the rate
        is *assumed*, so its "drift" would be 0 by construction and reporting
        that as a measurement would be a lie.

        What this measures has changed. It used to be the ratio between UTC
        elapsed and *assumed-rate* ts64 elapsed, which on real reader output
        was dominated by the 65536x rate error rather than by any clock drift —
        hence -999984.74 ppm on a healthy capture.
        """
        if not self.rate_fitted:
            return None
        return (self.tick_s / TS64_NOMINAL_TICK_S - 1.0) * 1e6

    def _update_calibration(self) -> None:
        """Refit the raw-tick → UTC line from the anchors.

        The model is ``utc_epoch_s = _epoch_s + ts64 * tick_s`` over the **raw**
        tick field. Fitting the slope is the fix: the previous code
        assumed a rate and then folded the resulting error into a "drift" term,
        which silently absorbed a 65536x mistake for any ts64 inside the
        anchored span and diverged wildly outside it.

        With one anchor no slope is observable, so the nominal rate is used and
        :attr:`rate_fitted` stays False.

        With three or more, stale anchors are excluded first — see
        :func:`_inlier_indices`. Fewer than half surviving is a refusal: with
        no majority there is no telling which group is the stale one.
        """
        self.reject_reason = None
        if not self.anchors:
            self._epoch_s = None
            self.tick_s = TS64_NOMINAL_TICK_S
            self.rate_fitted = False
            self.residual_stdev_s = None
            self.num_inliers = None
            return

        xs = [float(a.ts64) for a in self.anchors]
        ys = [a.utc.timestamp() for a in self.anchors]
        consensus = True
        if len(xs) >= 3:
            keep = _inlier_indices(xs, ys)
            if 2 * len(keep) > len(xs):
                xs = [xs[i] for i in keep]
                ys = [ys[i] for i in keep]
            else:
                consensus = False
        n = len(xs)
        self.num_inliers = n if consensus else len(keep)
        no_consensus = (
            f"no consensus among anchors: only {self.num_inliers} of {n} agree "
            f"on what time it is — cannot tell which ones are stale")

        if n == 1:
            self.tick_s = TS64_NOMINAL_TICK_S
            self.rate_fitted = False
            self.residual_stdev_s = None
            self._epoch_s = ys[0] - xs[0] * self.tick_s
            return

        fit = fit_line(xs, ys)
        if fit is None:
            # Every anchor at one ts64 — no slope is observable. Fall back
            # rather than divide by zero.
            self.tick_s = TS64_NOMINAL_TICK_S
            self.rate_fitted = False
            self.residual_stdev_s = None
            self._epoch_s = (sum(ys) / n) - (sum(xs) / n) * self.tick_s
            if not consensus:
                self.reject_reason = no_consensus
            return

        slope, intercept, resid = fit
        stdev = (sum(r * r for r in resid) / n) ** 0.5

        self.tick_s = slope
        self.rate_fitted = True
        self.residual_stdev_s = stdev
        self._epoch_s = intercept

        # Sanity gate. The absence of one is what made the Q16 error silent: a caller
        # that did not itself check the implied capture duration got
        # plausible-looking wrong timestamps out of a calibrator reporting
        # is_calibrated == True.
        lo = TS64_NOMINAL_TICK_S / _TICK_RATE_TOLERANCE_FACTOR
        hi = TS64_NOMINAL_TICK_S * _TICK_RATE_TOLERANCE_FACTOR
        if not consensus:
            self.reject_reason = no_consensus
        elif slope <= 0:
            self.reject_reason = (
                f"fitted tick rate is not positive ({slope:.6g} s/tick) — "
                f"UTC does not advance with ts64 across these anchors")
        elif not (lo <= slope <= hi):
            self.reject_reason = (
                f"fitted tick rate {slope:.6g} s/tick is implausible "
                f"({slope / TS64_NOMINAL_TICK_S:.4g}x the nominal "
                f"{TS64_NOMINAL_TICK_S:.6g}) — the anchors imply a capture "
                f"duration that cannot be right")
        elif stdev > _MAX_FIT_RESIDUAL_S:
            self.reject_reason = (
                f"anchors are not collinear: fit residual sigma "
                f"{stdev:.3f} s > {_MAX_FIT_RESIDUAL_S} s — the anchors "
                f"disagree about what time it is")


def _inlier_indices(xs: list[float], ys: list[float],
                    rate: float = TS64_NOMINAL_TICK_S) -> list[int]:
    """Indices of the anchors that agree on what time it is.

    Two stages, because a single fit is what stale anchors break:

    1. **Median offset, nominal rate.** ``y - x * TS64_NOMINAL_TICK_S`` is
       constant for a perfect clock at the nominal rate, so its median is the
       capture's time base whatever a minority of anchors claims. Anchors
       further than :data:`_STALE_OFFSET_WINDOW_S` from it are dropped. The
       window is wide so real drift never trips it.
    2. **Residual from a fit on the survivors.** Drops what stage 1 was too
       coarse to see, measured against the fitted rate rather than an assumed
       one. Applied once; iterating would let the band creep.

    ``rate`` is the s/tick stage 1 measures offsets against. The default is
    the nominal rate, which is right for :class:`Ts64Calibrator` (it assumes
    that rate anyway). :class:`diaggrok.ts64_anchor.AnchorTable` passes a
    robust estimate instead, since it accepts any chipset's rate and a
    10% rate error walks the offset out of the 60 s window after ten minutes.

    The caller decides whether the survivors are a majority. This only sorts.
    """
    offs = [y - x * rate for x, y in zip(xs, ys)]
    med = statistics.median(offs)
    keep = [i for i, o in enumerate(offs) if abs(o - med) <= _STALE_OFFSET_WINDOW_S]
    fit = fit_line([xs[i] for i in keep], [ys[i] for i in keep])
    if fit is None:
        return keep
    slope, intercept, _ = fit
    return [i for i in keep
            if abs(ys[i] - (intercept + slope * xs[i])) <= _INLIER_RESIDUAL_S]


# GNSS position report — carries both the outer ts64 and GPS time, giving an
# exact ts64<->UTC anchor. This is the only anchor source implemented today.
GNSS_POS_LOG_CODE = 0x1476


def gnss_anchor_from_payload(ts64: int, payload: bytes) -> Optional[tuple[int, int]]:
    """Best-effort ``(gps_week, gps_tow_ms)`` from a 0x1476 payload, or None.

    Routes through ``diaggrok.parse`` so the field offsets stay in sync with the
    parser. Returns None when the parser rejects the record, when the
    fields are absent, or when the range gates exclude a sentinel/uninitialised
    anchor (``gps_week`` in {0, 0xFFFF}; ``gps_tow_ms`` > one week).

    A parser ``ValueError`` (raised by the 0x1476 parser on
    short/truncated/out-of-range records) is treated the same as a None return
    : a clipped record at a capture boundary should be skipped, not fatal.
    The except is scoped narrowly to ValueError so genuine parser bugs surface.

    The ``diaggrok`` import is deferred to call time so importing this module
    never pulls in the parser registry (keeps ``ts64_cal`` cheap and cycle-free).
    """
    import diaggrok  # lazy: triggers parser registration; avoids an import cycle

    try:
        parsed = diaggrok.parse(GNSS_POS_LOG_CODE, ts64, payload)
    except ValueError:
        return None  # truncated/foreign/out-of-range record — skip this anchor
    if parsed is None:
        return None
    gps_week = getattr(parsed, "gps_week", None)
    gps_tow_ms = getattr(parsed, "gps_tow_ms", None)
    if gps_week is None or gps_tow_ms is None:
        return None
    if gps_week in (0, _GPS_WEEK_INVALID):
        return None
    if gps_tow_ms > 604_800_000:  # > 7 days in ms
        return None
    return gps_week, gps_tow_ms


def build_calibrator(records,
                     leap_seconds: int = GPS_UTC_LEAP_SECONDS) -> Ts64Calibrator:
    """Build a :class:`Ts64Calibrator` from an iterable of ``(code, ts64, payload)``.

    Walks the records once and feeds every usable GNSS-position (0x1476) anchor
    into a fresh calibrator. The caller supplies the iterator (e.g. a tool's
    ``iter_capture_records(data)`` or ``diaggrok.dlf.iter_records(data)``), so
    this stays agnostic of capture-format detection. When the stream carries no
    usable anchor the returned calibrator is simply ``is_calibrated == False``,
    and callers fall back to synthetic timestamps.

    ``leap_seconds`` is threaded through to :func:`gps_to_utc` and recorded on
    the returned calibrator, so a consumer can read the assumption back
    rather than having to know it.
    """
    cal = Ts64Calibrator(leap_seconds=leap_seconds)
    for code, ts64, payload in records:
        if code != GNSS_POS_LOG_CODE:
            continue
        anchor = gnss_anchor_from_payload(ts64, payload)
        if anchor is not None:
            cal.add_anchor(ts64, anchor[0], anchor[1], refit=False)
    cal.refit()
    return cal


def gps_to_utc(gps_week: int, gps_tow_ms: int,
               leap_seconds: int = GPS_UTC_LEAP_SECONDS) -> datetime:
    """Convert GPS week + time-of-week to UTC datetime, leap-second corrected.

    Args:
        gps_week: GPS week number.
        gps_tow_ms: GPS time of week, in milliseconds.
        leap_seconds: GPS-UTC offset to subtract. Defaults to
            :data:`GPS_UTC_LEAP_SECONDS`. Pass ``0`` for raw GPS time.

    History. This function used to skip the correction outright, on the
    reasoning that *"sub-second accuracy is sufficient and leap second
    correction is not applied (would add ~18s error which is constant and
    cancels in relative timing)"*.

    That reasoning holds **within** one DIAG stream, and only there. It breaks
    the moment a GNSS-derived DIAG timestamp is compared against a clock that
    is actually UTC — a host wall clock, a gpsd track, an ``at_poll.jsonl``
    ``ts_utc``. Then the 18 s does not cancel; it is a straight bias. That
    cross-clock comparison is the *normal* case for wardrive analysis (joining
    DIAG observations to GPS fixes) and for ``diaggrok_at_correlate``.

    Measured on an LM960A18 wardrive capture, anchored from its own 217
    ``0x1476`` records:

    ==================  ================  ==========================
    leap correction     capture end       vs its own AT poll end
    ==================  ================  ==========================
    omitted (was)       15:13:41.716      **+19.9 s**
    18 s applied (now)  15:13:23.716      **+1.9 s**
    ==================  ================  ==========================

    1.9 s is plausible capture teardown; 19.9 s is not — and it was being
    absorbed silently into every derived rate and every GPS join. The corrected
    value is independently corroborated: ``go_wardrive`` stops all three modems
    in one shutdown, the two modems with genuine ``diag_verno_response`` anchors
    recorded end ``host_mono_ns`` 29 us apart, and the leap-corrected LM960A18
    reconstruction lands **9.00 ms** from their mean (uncorrected: ~18 s off).

    Note this function was the repo's **outlier**, not its convention —
    ``apps/diaggpsd/gnss_compare.py`` and ``apps/diaggpsd/gpsd_server.py`` have
    always subtracted 18 s.
    """
    total_seconds = gps_week * 604800 + gps_tow_ms / 1000.0 - leap_seconds
    return _GPS_EPOCH + timedelta(seconds=total_seconds)


def utc_to_gps(dt: datetime, leap_seconds: int = GPS_UTC_LEAP_SECONDS) -> tuple[int, int]:
    """Inverse of :func:`gps_to_utc`: a UTC datetime → ``(gps_week, gps_tow_ms)``.

    Exists so a non-GNSS absolute-time source — a ``DIAG_TS_F`` (0x1D) host-clock
    reading — can be handed to :meth:`Ts64Calibrator.add_anchor`, whose
    contract is a GPS week + time-of-week pair. Feeding the **host** wall clock
    (rather than the modem's own decoded time) is the point: it makes the fitted
    line map ts64 → host UTC, so :attr:`Ts64Calibrator.drift_ppm` measures the
    modem oscillator's real error against the host, not zero-by-construction.

    Round-trips ``gps_to_utc`` exactly at the same ``leap_seconds`` (the whole-ms
    rounding is the only lossy step, matching that function's ms-granular input).
    A naive-``datetime`` argument is treated as UTC.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # gps_to_utc computes: EPOCH + (week*604800 + tow_ms/1000 - leap). Invert:
    gps_seconds = (dt - _GPS_EPOCH).total_seconds() + leap_seconds
    gps_week = int(gps_seconds // 604800)
    tow_ms = round((gps_seconds - gps_week * 604800) * 1000.0)
    # A tow that rounds up to a full week rolls into the next week (keeps
    # gps_tow_ms strictly < 604800000, which add_anchor's range gate requires).
    if tow_ms >= 604800000:
        gps_week += 1
        tow_ms -= 604800000
    return gps_week, tow_ms
