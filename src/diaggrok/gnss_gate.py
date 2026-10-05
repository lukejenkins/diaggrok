# diaggrok-provenance: re
"""GNSS fix validity gates — what is WITHHELD, on what test, and why.

The standing rule: *absent* and *zero* must never render alike, because a
healthy-looking zero is how a dead field survives review. Every gate here
returns a NAMED decline reason rather than a bare False, so an operator
reading a run's counters can tell "indoors" (``no_position``) from "this
modem lies" (``no_time_solution``). Collapsing those into one number hides
a chipset defect behind a benign-sounding count.

Gate order is load-bearing: plausible degrees, then placeholder, then time
solution. A seed position passes the first two, so reordering relabels every
``no_time_solution`` as something else.

This is DIAG decode semantics, not transport, so every consumer that geo-tags
records from a GNSS fix (a Kismet bridge, a WiGLE exporter) shares this one
copy.
"""
from __future__ import annotations


def is_placeholder_position(lat, lon):
    """True if (lat, lon) is a known vendor "no fix" sentinel that looks like
    valid degrees but is not a real observation:
      * the baseband's Nevada default (38.0, -117.0)
      * Telit FN980m "no antenna" placeholder (~5.5, ~6.6) emitted by 0x1476
      * (0, 0) generic "value unavailable" sentinel
    """
    if abs(lat - 38.0) < 0.5 and abs(lon + 117.0) < 0.5:
        return True
    if abs(lat - 5.5) < 0.5 and abs(lon - 6.6) < 0.5:
        return True
    if lat == 0 and lon == 0:
        return True
    return False


def gps_latlonalt(log_code, d):
    """Pull (lat, lon, alt) from a parsed GNSS result dict, per-code, matching
    the parsers' field names. Returns None if the code is not a GNSS code."""
    if log_code == 0x1476:
        return (d.get("lat_deg", 0), d.get("lon_deg", 0),
                d.get("alt_m", d.get("alt_ellipsoid_m", 0)))
    if log_code == 0x14D8:
        return (d.get("lat", 0), d.get("lon", 0), d.get("alt", 0))
    return None


#: GPS week-number sentinel meaning "the receiver has no time solution".
#: A GNSS position is a time-of-arrival solution, so a receiver that does not
#: know the week cannot have computed a fix -- any lat/lon accompanying it is a
#: seed/almanac position, not an observation.
_GPS_WEEK_UNKNOWN = 0xFFFF


def gps_time_is_valid(log_code, d):
    """False when a 0x1476 result carries the "week unknown" sentinel.

    Measured on the RM520N-GL (SDX62, v24) camped on T-Mobile NR5G-SA while its
    own NMEA reported NO fix (GGA quality 0 / RMC status V): 448 of 450 records
    carried a CONSTANT lat/lon at alt exactly 0.0, far from the receiver's
    actual position. The raw radians are a float32 pair promoted to double --
    a coarse seed rounded to 3 decimal places (0.001 rad ~= 57 km), which is
    the error scale observed.

    The seed's value is deliberately not recorded here: the gate keys on
    ``gps_week``, never on the coordinate, so nothing here needs the number.

    ``pos_source`` is NOT the discriminator, however plausible it looks. It
    reads 4 (DB) on the bogus v24 records AND on the correct v13 (RM500Q/SDX55)
    and v10 (LM960/SDX20) records captured alongside them -- gating on it would
    silently kill GNSS on both of those chipsets. ``gps_week`` separates them
    cleanly: 2429 on both correct captures, 0xFFFF on the bogus one.

    Scoped to 0x1476: 0x14D8 exposes no week field, and its own branch can never
    emit a fix anyway (hardcoded 0.0 lat/lon)."""
    if log_code != 0x1476:
        return True
    return d.get("gps_week") != _GPS_WEEK_UNKNOWN


#: Why ``gps_gate_verdict`` declined a GNSS record. Stable strings -- they are
#: counted and reported, so renaming one silently rewrites an operator's history.
#:
#: A single ``nofix`` counter would collapse OPPOSITE findings into one number.
#: "A GNSS record that decodes but has no usable position" reads as "the modem
#: has no sky view" -- which is true of ``NO_POSITION`` and false of
#: ``NO_TIME_SOLUTION``. The latter is a receiver that DID report a position, at
#: plausible-looking degrees, measured far from truth on the SDX62: a
#: chipset-level defect that would otherwise read as benign weather. A reader
#: of ``fixes=0 nofix=113`` cannot tell "indoors" from "this modem lies".
GPS_DECLINE_NOT_GNSS = "not_a_gnss_code"
#: Coordinates fail ``1 < |lat| < 90`` / ``1 < |lon| < 180``. Includes the (0,0)
#: all-zero record, which is what an engine with no sky view emits -- the benign
#: reading, and the ONLY one of these that means "point the antenna at the sky".
GPS_DECLINE_NO_POSITION = "no_position"
#: A known vendor no-fix sentinel at otherwise-plausible degrees.
GPS_DECLINE_PLACEHOLDER = "placeholder_position"
#: ``gps_week == 0xFFFF`` -- no time solution, so the position is a seed.
#: Not a sky-view problem. A run reporting this is a run whose cells would
#: ALL have been geo-tagged wrong had the gate not held.
GPS_DECLINE_NO_TIME = "no_time_solution"
#: The record's own GNSS clock is older than ``max_fix_age_ms`` behind the
#: newest GNSS time seen in the same stream. Not a sky-view problem
#: and not a seed either: the receiver HAS a time solution, at real degrees,
#: where it genuinely was -- yesterday. Measured on an RM500Q-AE: 106 of 406
#: accepted records were **13.68 h** stale and every existing gate passed them,
#: correctly on its own terms.
GPS_DECLINE_STALE = "stale_fix"


#: Milliseconds in a GPS week -- the (week, tow) pair's radix.
_MS_PER_GPS_WEEK = 604_800_000

#: Default staleness bound. Deliberately NOT tuned tightly: with the
#: STREAM-RELATIVE reference below, the bound is nearly inert on the measured
#: capture (60 s and 300 s both reject exactly the same 106 records), because
#: each record is compared against its own neighbourhood rather than against
#: the run's end. The same data judged against the stream's GLOBAL newest is
#: violently bound-sensitive -- 224 rejects at 60 s vs 106 at 300 s -- so the
#: choice of primitive, not the choice of number, is what makes this gate
#: stable.
DEFAULT_MAX_FIX_AGE_MS = 60_000


def gnss_time_ms(log_code, d):
    """The record's own GNSS clock as a single monotone scalar, or ``None``.

    HOST-CLOCK-FREE by construction, and that is the point rather than a
    nicety. Comparing a fix's age against the host wall clock assumes the host
    clock is sane; on a capture host with no NTP that assumption *inverts* the
    defect -- a correct receiver gets rejected because the host is wrong.
    ``(week, tow_ms)`` is the receiver's own timebase, so a stream can be
    judged against itself with nothing external in the loop.

    Returns ``None`` when the code carries no clock (0x14D8 exposes no week
    field) or when the week is the unknown sentinel -- a record with no time
    solution is already refused by ``gps_time_is_valid``, and giving it a
    nominal age here would let it re-enter through the staleness gate.
    """
    if log_code != 0x1476:
        return None
    week = d.get("gps_week")
    tow = d.get("gps_tow_ms")
    if week is None or tow is None or week == _GPS_WEEK_UNKNOWN:
        return None
    return week * _MS_PER_GPS_WEEK + tow


def gps_gate_verdict(log_code, result, reference_gnss_ms=None,
                     max_fix_age_ms=DEFAULT_MAX_FIX_AGE_MS):
    """``(accepted, reason)`` for a decoded GNSS result: the accepted
    ``(lat, lon, alt)`` and ``None``, or ``None`` and the ``GPS_DECLINE_*``
    constant naming the gate that refused it.

    Split from ``gps_fix_for`` for the same reason ``gps_fix_for`` is split
    from any record writer: a decision that cannot be interrogated gets
    re-assembled by its consumers, and a re-assembly drifts. ``gps_fix_for``
    stays the one-value entry point (an equivalence harness and a C++
    byte-parity contract depend on it) -- this returns the same verdict with
    its justification attached.

    Order is load-bearing: coordinate plausibility, then placeholder, then
    time solution, then staleness. A seed position passes the first two, so
    reordering would relabel every ``no_time_solution`` as something else --
    and staleness must come LAST, because a record with no time solution has no
    meaningful age and must be reported as ``no_time_solution``, not as stale.

    STALENESS IS OPT-IN, and the default keeps this function identical to the
    three-gate form. ``reference_gnss_ms=None`` makes the staleness arm inert,
    which is not timidity: ``gps_fix_for`` is held to a C++ byte-parity
    contract, and turning a gate on in one leg scores the *correct* other leg
    as the deviant. More fundamentally: the C++ seam is a **pure per-record
    function of a payload**, and staleness is not a per-record property. It
    needs a reference the seam has no way to carry, so supporting it there is
    a **signature** change, not a predicate change, and it is deliberately not
    smuggled in under a default.

    Callers that want the gate hold the reference themselves -- see
    :class:`GnssFreshnessTracker`, which is the supported way to obtain one.
    """
    d = result.to_dict()
    latlonalt = gps_latlonalt(log_code, d)
    if latlonalt is None:
        return None, GPS_DECLINE_NOT_GNSS
    lat, lon, alt = latlonalt
    if not (1 < abs(lat) < 90 and 1 < abs(lon) < 180):
        return None, GPS_DECLINE_NO_POSITION
    if is_placeholder_position(lat, lon):
        return None, GPS_DECLINE_PLACEHOLDER
    if not gps_time_is_valid(log_code, d):
        return None, GPS_DECLINE_NO_TIME
    if reference_gnss_ms is not None:
        own = gnss_time_ms(log_code, d)
        if own is not None and (reference_gnss_ms - own) > max_fix_age_ms:
            return None, GPS_DECLINE_STALE
    return (lat, lon, alt), None


class GnssFreshnessTracker:
    """Stream-relative freshness reference for the staleness gate.

    Holds the newest GNSS time seen so far and judges each record against it.
    Nothing here reads the host clock; see :func:`gnss_time_ms`.

    **The warm-up hole is real and exactly one record wide.** The first record
    with a clock defines the reference, so it cannot be judged -- it is always
    its own newest. Measured on an RM500Q-AE capture (406 accepted records,
    106 of them 13.68 h stale, interleaved from index **1**): the tracker
    rejects 106/406, and a stream deliberately reordered to *start* on a stale
    record still rejects 105 -- only the seeding record slips.

    **Why max-seen-so-far rather than the stream's global newest.** The
    global form needs the whole capture before it can judge the first record --
    unusable live -- and it is far more sensitive to the bound: on the same
    data it rejects 224 at 60 s and 106 at 300 s, where the running form
    rejects 106 at both. The running form compares a record against its own
    neighbourhood, so ordinary 1-10 minute clock lag does not accumulate into a
    reject the way it does against a fixed end-of-run instant.

    ``pos_source`` is NOT a substitute, however well it fits. On this
    capture it separates the two populations perfectly -- every stale record is
    ``pos_source=4, hdop=0.0`` and every live one is ``pos_source=8`` with a
    real hdop -- which is exactly what makes it a trap: the LM960A18's
    *correct* records are all ``pos_source=4, hdop=0.0`` too. A
    discriminator that is perfect on one modem and inverted on another is worse
    than none. The clock generalises; the source field does not.
    """

    def __init__(self, max_fix_age_ms=DEFAULT_MAX_FIX_AGE_MS):
        self.max_fix_age_ms = max_fix_age_ms
        self.newest_gnss_ms = None
        #: Records that arrived before any reference existed and so were
        #: accepted unjudged. Counted, not hidden -- a reader comparing
        #: `fixes` against `stale_fix` is entitled to know the gate was blind
        #: for part of the run.
        self.unjudged = 0

    def judge(self, log_code, result):
        """``(accepted, reason)`` for one record, then fold it into the
        reference. Same shape as :func:`gps_gate_verdict`.

        The reference advances on **every** record carrying a clock, including
        ones the coordinate gates refuse: a no-position record can still carry
        a perfectly good time solution, and dropping it would let a run with
        poor sky view slowly fall behind its own stream.
        """
        own = gnss_time_ms(log_code, result.to_dict())
        if self.newest_gnss_ms is None and own is not None:
            self.unjudged += 1
        verdict = gps_gate_verdict(
            log_code, result,
            reference_gnss_ms=self.newest_gnss_ms,
            max_fix_age_ms=self.max_fix_age_ms,
        )
        if own is not None:
            if self.newest_gnss_ms is None or own > self.newest_gnss_ms:
                self.newest_gnss_ms = own
        return verdict


def gps_fix_for(log_code, result):
    """The DECISION half of the ``gps_fix`` record emitter, as a PURE function:
    the accepted ``(lat, lon, alt)`` for a decoded 0x1476 / 0x14D8 GNSS result,
    or ``None`` if any gate declines it.

    Split out of the writer deliberately, not for tidiness. A writer *writes*
    rather than returns, so an equivalence harness cannot call it and has to
    RE-ASSEMBLE the decision from the helpers -- and a re-assembly that omits
    ``gps_time_is_valid`` accepts a no-time-solution record the real gate
    rejects, scoring a correct C++ leg as the deviant. **Anything that decides
    must be callable; only the write stays unreachable.** Add new gates HERE,
    never in a writer.

    Coordinates come back UNROUNDED. ``round(_, 6)`` is JSON presentation applied
    by the emitter, not part of the decode contract the C++ leg reproduces.

    This DELEGATES to ``gps_gate_verdict`` rather than repeating the gate
    sequence. The gates it applies are, in order: plausible degrees (which also
    rejects the (0,0) sentinel), then ``is_placeholder_position``, then
    ``gps_time_is_valid`` -- a seed position looks like perfectly plausible
    degrees, so only the time solution catches it, and that one matters more
    than a normal reject because a geo-tagging consumer tags EVERY DIAG cell
    observation from the last fix, so one bad fix relocates the whole run.
    Two copies of that sequence drift apart. One implementation, two entry
    points.
    """
    accepted, _reason = gps_gate_verdict(log_code, result)
    return accepted
