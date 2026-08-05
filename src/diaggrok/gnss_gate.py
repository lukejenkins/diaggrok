# diaggrok-provenance: re
"""GNSS fix validity gates — what is WITHHELD, on what test, and why.

The standing rule: *absent* and *zero* must never render alike, because a
healthy-looking zero is how a dead field survives review. Every gate here
returns a NAMED decline reason rather than a bare False, so an operator
reading a run's counters can tell "indoors" (``no_position``) from "this
modem lies" (``no_time_solution``) — collapsing those into one number is the
defect #N was filed for.

Gate order is load-bearing: plausible degrees, then placeholder, then time
solution. A seed position passes the first two (#N), so reordering
relabels every ``no_time_solution`` as something else.

Home note: this logic lived in ``tools/kismet_diag_decode.py`` until
2026-08-04 (#N). It is DIAG decode semantics, not Kismet transport — it
would be equally true if Kismet did not exist — so it belongs here, where
both the Kismet bridge and ``tools/dlf_to_wigle.py`` can share one copy.
"""
from __future__ import annotations


def is_placeholder_position(lat, lon):
    """True if (lat, lon) is a known vendor "no fix" sentinel that looks like
    valid degrees but is not a real observation. Mirrors
    dlf_to_wigle._is_placeholder_position:
      * Qualcomm Nevada default (38.0, -117.0) -- #N
      * Telit FN980m "no antenna" placeholder (~5.5, ~6.6) emitted by 0x1476 -- #N
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
    dlf_to_wigle's field names. Returns None if the code is not a GNSS code."""
    if log_code == 0x1476:
        return (d.get("lat_deg", 0), d.get("lon_deg", 0),
                d.get("alt_m", d.get("alt_ellipsoid_m", 0)))
    if log_code == 0x14D8:
        return (d.get("lat", 0), d.get("lon", 0), d.get("alt", 0))
    return None


#: GPS week-number sentinel meaning "the receiver has no time solution" (#N).
#: A GNSS position is a time-of-arrival solution, so a receiver that does not
#: know the week cannot have computed a fix -- any lat/lon accompanying it is a
#: seed/almanac position, not an observation.
_GPS_WEEK_UNKNOWN = 0xFFFF


def gps_time_is_valid(log_code, d):
    """False when a 0x1476 result carries the "week unknown" sentinel (#N).

    Measured on the RM520N-GL (SDX62, v24) camped on T-Mobile NR5G-SA while its
    own NMEA reported NO fix (GGA quality 0 / RMC status V): 448 of 450 records
    carried a CONSTANT lat/lon at alt exactly 0.0, far from the receiver's
    actual position. The raw radians are a float32 pair promoted to double --
    a coarse seed rounded to 3 decimal places (0.001 rad ~= 57 km), which is
    the error scale observed.

    ⛔ The seed's VALUE is deliberately not recorded here, in either degrees or
    radians. It is an inert firmware constant on its own, but stated beside a
    distance-to-true-position it becomes a locus through the measuring site --
    a disclosure synthesizable from the published text alone, and invisible to
    the token scanners (a bare decimal pair is their declared blind spot). The
    gate keys on ``gps_week``, never on the coordinate, so nothing here needs
    the number.

    ⚠️ ``pos_source`` is NOT the discriminator, however plausible it looks. It
    reads 4 (DB) on the bogus v24 records AND on the correct v13 (RM500Q/SDX55)
    and v10 (LM960/SDX20) records in the same session -- gating on it would
    silently kill GNSS on both of those chipsets. ``gps_week`` separates them
    cleanly: 2429 on both correct captures, 0xFFFF on the bogus one.

    Scoped to 0x1476: 0x14D8 exposes no week field, and its own branch can never
    emit a fix anyway (hardcoded 0.0 lat/lon, #N)."""
    if log_code != 0x1476:
        return True
    return d.get("gps_week") != _GPS_WEEK_UNKNOWN


#: Why ``gps_gate_verdict`` declined a GNSS record. Stable strings -- they are
#: counted and reported, so renaming one silently rewrites an operator's history.
#:
#: ⛔ These exist because ``nofix`` collapsed OPPOSITE findings into one number.
#: ``capture_cell_diag.c``'s counter is documented as *"a GNSS record that
#: decodes but has no usable position is the modem having no sky view"* -- which
#: is true of ``NO_POSITION`` and false of ``NO_TIME_SOLUTION``. The latter is a
#: receiver that DID report a position, at plausible-looking degrees, measured
#: far from truth on the SDX62 (#N): a chipset-level defect the bridge
#: caught, filed under a name that reads as benign weather. An operator watching
#: ``fixes=0 nofix=113`` cannot tell "indoors" from "this modem lies".
GPS_DECLINE_NOT_GNSS = "not_a_gnss_code"
#: Coordinates fail ``1 < |lat| < 90`` / ``1 < |lon| < 180``. Includes the (0,0)
#: all-zero record, which is what an engine with no sky view emits -- the benign
#: reading, and the ONLY one of these that means "point the antenna at the sky".
GPS_DECLINE_NO_POSITION = "no_position"
#: A known vendor no-fix sentinel at otherwise-plausible degrees (#N / #N).
GPS_DECLINE_PLACEHOLDER = "placeholder_position"
#: ``gps_week == 0xFFFF`` -- no time solution, so the position is a seed (#N).
#: 🔴 Not a sky-view problem. A run reporting this is a run whose cells would
#: ALL have been geo-tagged wrong had the gate not held.
GPS_DECLINE_NO_TIME = "no_time_solution"


def gps_gate_verdict(log_code, result):
    """``(accepted, reason)`` for a decoded GNSS result: the accepted
    ``(lat, lon, alt)`` and ``None``, or ``None`` and the ``GPS_DECLINE_*``
    constant naming the gate that refused it.

    ⛔ Split from ``gps_fix_for`` for the same reason ``gps_fix_for`` was split
    from the record writer (#N / #N): a decision that cannot be
    interrogated gets re-assembled by its consumers, and a re-assembly drifts.
    ``gps_fix_for`` stays the one-value entry point so the diagspec equivalence
    harness and the C++ byte-parity contract are untouched -- this returns the
    same verdict with its justification attached.

    ⚠️ Order is load-bearing and matches the shipping gate exactly: coordinate
    plausibility, then placeholder, then time solution. A seed position passes
    the first two (that is the whole point of #N), so reordering would
    relabel every ``no_time_solution`` as something else.
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
    return (lat, lon, alt), None


def gps_fix_for(log_code, result):
    """The DECISION half of the ``gps_fix`` record emitter, as a PURE function:
    the accepted ``(lat, lon, alt)`` for a decoded 0x1476 / 0x14D8 GNSS result,
    or ``None`` if any gate declines it.

    ⛔ Split out of the writer deliberately (#N / #N), not for tidiness.
    The writer -- which now lives in the Kismet transport helper, not here --
    *writes* rather than returns, so the equivalence harness
    (``libs/diagspec/harness/diag_0x1476_gpsfix_verify.py``) could not call it and
    had to RE-ASSEMBLE the decision from the private helpers — the only harness of
    34 in that class, and the one place #N's defect was possible: the
    re-assembly omitted ``gps_time_is_valid`` entirely, so the "source of truth"
    accepted a no-time-solution record the shipping bridge rejects, and the C++
    leg — which had the gate right — was scored as the deviant. **Anything that
    decides must be callable; only the write stays unreachable.** Add new gates
    HERE, never in the writer, or the harness goes back to mirroring a subset.

    Coordinates come back UNROUNDED. ``round(_, 6)`` is JSON presentation applied
    by the emitter, not part of the decode contract the C++ leg reproduces.

    ⛔ This DELEGATES to ``gps_gate_verdict`` rather than repeating the gate
    sequence. The gates it applies are, in order: plausible degrees (which also
    rejects the (0,0) sentinel), then ``is_placeholder_position``, then
    ``gps_time_is_valid`` -- a seed position looks like perfectly plausible
    degrees, so only the time solution catches it (#N), and that one matters
    more than a normal reject because the helper geo-tags EVERY DIAG
    cell_observation from the last fix, so one bad fix relocates the whole run.
    Two copies of that sequence is exactly the drift #N paid for: the
    equivalence harness re-assembled the decision, omitted ``gps_time_is_valid``
    and scored the correct C++ leg as the deviant. One implementation, two
    entry points.
    """
    accepted, _reason = gps_gate_verdict(log_code, result)
    return accepted
