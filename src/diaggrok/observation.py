# diaggrok-provenance: re
"""Parsed DIAG result -> normalized ``cell_observation`` records.

A cell_observation is a decoder concept, not a Kismet one: ``rat``, ``pci``,
``earfcn``, optional ``rsrp``/``rsrq``, optional SIB1 identity, and a
provenance block. Consumers render it — Kismet as JSON lines, dlf_to_wigle as
WiGLE CSV rows — but the mapping itself is what the DIAG bytes MEAN.

⛔ The rule this module exists to hold: an unbound field is OMITTED, never
emitted as 0. A plausible-but-wrong number outlives the review that would have
caught a missing key.

Home note: this lived in ``tools/kismet_diag_decode.py`` until 2026-08-04
(#N).
"""
from __future__ import annotations

import sys

from diaggrok.parsers.diag_0xb0c0 import Diag0xB0C0
from diaggrok.parsers.diag_0xb192 import Diag0xB192
from diaggrok.parsers.diag_0xb193 import Diag0xB193
from diaggrok.parsers.diag_0xb195 import Diag0xB195
from diaggrok.parsers.diag_0xb821 import Diag0xB821
from diaggrok.parsers.diag_0xb97f import Diag0xB97F


def provenance(origin: str, imei: str, captured_at: float,
               log_tick: float | None = None) -> dict:
    """Build the data-lineage provenance block stamped on every observation.

    ``captured_at`` is a Unix epoch (seconds) - the wall-clock at which this
    helper processed the record, mirroring the gettimeofday stamp the kismet
    capture binary already applies on cf_send_json. It is deliberately NOT
    derived from the DIAG ts64: that field is a since-boot 1.25 ms-tick counter
    (see diaggrok.ts64_cal) with no wall-clock offset absent a GNSS calibration
    anchor, which this passive bridge does not carry. Feeding the raw tick as an
    absolute timestamp (the prior behaviour, #N) produced values like
    60345938315396.0 - nonsense as an epoch. The raw tick is preserved as
    ``log_tick`` for lineage / intra-capture ordering.
    """
    return {"src": "diag", "origin": origin, "imei": imei,
            "captured_at": captured_at, "log_tick": log_tick}


def result_to_observations(log_type, result, imei, sib1_map, captured_at,
                           log_tick=None):
    """Map one parsed diaggrok result to zero or more cell_observation dicts.

    ``captured_at`` is the Unix-epoch wall-clock stamped into prov (see
    :func:`provenance`); ``log_tick`` is the raw DIAG ts64 preserved alongside
    it. sib1_map is
    {(pci, earfcn): identity_dict}; empty in M1 (DIAG contributes only signal to
    towers whose identity came from the AT side). In M2 it is populated from
    SIB1 so DIAG can produce full-identity towers standalone.
    """
    if result is None:
        return []

    out = []
    if isinstance(result, Diag0xB193):
        for i, e in enumerate(result.entries):
            # ⛔ Do NOT drop the observation when rsrp is None. 0xB193 carries
            # THREE wigle_roles — "signal", "pci-earfcn-bridge" and "rat-context"
            # — and only the first needs RSRP. The pci/earfcn identity is VERIFIED
            # on every version the parser emits (it is the signal SCALE that is
            # version-gated), so discarding the row threw away two grounded roles
            # to avoid reporting one absent field.
            #
            # This mattered the moment #N gated the refuted scales: v35 (17.6%
            # of the 0xB193 corpus), v18, v22 and v48-RSRQ all report rsrp/rsrq
            # None (v36, 28.9%, was in that list until its 2026-07-30 RE), so the
            # old `continue` would have deleted ~50% of all
            # 0xB193 identity observations and read as a data regression — when in
            # fact the same rows previously carried a ~30 dB-wrong RSRP. Emit the
            # identity; omit only the field we cannot ground. (dlf_to_wigle.py
            # already does the equivalent, mapping a missing rsrp to 0.)
            o = {
                "rat": "LTE",
                "pci": e.pci,
                "earfcn": e.earfcn,
                "prov": provenance("0xB193", imei, captured_at, log_tick),
            }
            if e.rsrp is not None:
                o["rsrp"] = e.rsrp
            if e.rsrq is not None:
                o["rsrq"] = e.rsrq
            # Serving identification: prefer the parser's grounded serving_flag
            # (v59 bit15 of the PCI word, #N; and the single-cell v50/v56
            # serving cell) over positional inference. `i == 0` was doubly wrong —
            # it assumed cell[0] is always serving, AND the old `continue` above
            # shifted `i` so a dropped entry could promote a neighbour to
            # "serving". Fall back to the index only where no flag is grounded.
            is_serving = (e.serving_flag == 1) if e.serving_flag is not None else (i == 0)
            o["observation_type"] = "serving" if is_serving else "observation"
            o["is_serving"] = is_serving
            enrich(o, sib1_map)
            out.append(o)

    elif isinstance(result, Diag0xB0C0):
        # Gap-closer (M3.1): a SIB1-bearing 0xB0C0 LTE RRC OTA self-emits its own
        # identity cell -- mirrors dlf_to_wigle scanning 0xB0C0 as a Pass-2
        # measurement, which is what lets DIAG-only match its full WiGLE cell set.
        # SIB1 is OTA identity, not a signal measurement, so there is no rsrp.
        if result.sib1_tac is not None:
            o = {
                "rat": "LTE",
                "pci": result.pci,
                "earfcn": result.earfcn,
                "mcc": result.sib1_mcc,
                "mnc": result.sib1_mnc,
                "tac": result.sib1_tac,
                "cell_id": result.sib1_cell_id,
                "observation_type": "observation",
                "is_serving": False,
                "prov": provenance("0xB0C0", imei, captured_at, log_tick),
            }
            out.append(o)

    elif isinstance(result, Diag0xB192):
        # LTE idle-mode neighbor cells. The packet carries AGC-flattened energy,
        # NOT calibrated dBm (#N), so the parser sets rsrp/rsrq to None and we
        # emit PCI/EARFCN only -- no plausible-but-wrong signal number.
        for e in result.entries:
            o = {
                "rat": "LTE",
                "pci": e.pci,
                "earfcn": e.earfcn,
                "observation_type": "observation",
                "is_serving": False,
                "prov": provenance("0xB192", imei, captured_at, log_tick),
            }
            enrich(o, sib1_map)
            out.append(o)

    elif isinstance(result, Diag0xB195):
        # LTE connected-mode neighbor cells. Unlike 0xB192, the parser surfaces a
        # dBm-shaped rsrp per neighbor, so we forward it (same rule as 0xB193).
        for e in result.entries:
            o = {
                "rat": "LTE",
                "pci": e.pci,
                "earfcn": e.earfcn,
                "observation_type": "observation",
                "is_serving": False,
                "prov": provenance("0xB195", imei, captured_at, log_tick),
            }
            if e.rsrp is not None:
                o["rsrp"] = e.rsrp
            enrich(o, sib1_map)
            out.append(o)

    elif isinstance(result, Diag0xB97F):
        # M3.5: NR5G ML1 measurement DB -- the NR analog of the LTE 0xB193/0xB195
        # quartet, and net-new vs dlf_to_wigle (which maps NO NR measurement, only
        # 0xB821 identity). Per component carrier, each measured cell carries
        # per-cell SS-RSRP/RSRQ (ground-truthed vs AT+QSCAN, #N) and a derived
        # is_serving flag (pci == the CC's serving_pci). The NR-ARFCN rides in the
        # `earfcn` field -- rat:"NR" disambiguates -- so the (pci, earfcn) enrich
        # key matches the 0xB821-fed NR sib1_map (keyed by (pci, arfcn)). We
        # iterate every carrier (not the CC0-only .entries view) so
        # carrier-aggregated neighbours are not dropped. rsrp/rsrq are attached
        # only when present (out-of-band cells still emit PCI/EARFCN identity,
        # mirroring 0xB192 -- never a plausible-but-wrong signal number).
        for cc in result.carriers:
            for cell in cc.cells:
                # ⛔ Spec invariant: NR PCI is 0..1007 (38.211 §7.4.2.1 -- 3
                # SSS sequences x 336 PSS groups). A value outside that range
                # is not a cell, it is a decode that walked off its stride, so
                # emitting it would put a fabricated tower in the dataset.
                #
                # Observed live (#N): 10 of 679 NR observations on an
                # RM520N-GL (SDX62, v9) carried pci 51372-51828, all in one
                # ~3 ms burst on one ARFCN, all with rsrp=None and rsrq
                # exactly 0.0, while in-range cells on the SAME carrier
                # decoded normally. A 1459-observation recapture on the same
                # unit two hours later reproduced ZERO -- so this is
                # intermittent, and a guard that only fires on the bad burst
                # is the only thing that keeps it out of the data between
                # sightings. Dropping the row (rather than clamping) is
                # deliberate: the stride is wrong, so `earfcn` and the signal
                # fields from the same row are equally untrustworthy.
                if cell.pci is not None and not (0 <= cell.pci <= 1007):
                    # Announce it on stderr (never stdout — that is the JSON
                    # record pipe the C relay parses). The burst is intermittent:
                    # 10/679 observations in one session, 0/1459 in a recapture
                    # two hours later on the same unit. A silent drop would throw
                    # away the only signal that a stride bug just fired, so the
                    # next capture-with-a-burst has to be found by luck rather
                    # than by noticing the log line.
                    print(f"celldiag WARN 0xB97F out-of-range NR pci={cell.pci} "
                          f"(spec 0..1007, 38.211 §7.4.2.1) arfcn={cc.nr_arfcn} "
                          f"rsrp={cell.rsrp} rsrq={cell.rsrq} — row dropped (#N)",
                          file=sys.stderr, flush=True)
                    continue
                o = {
                    "rat": "NR",
                    "pci": cell.pci,
                    "earfcn": cc.nr_arfcn,
                    "observation_type": "serving" if cell.is_serving else "observation",
                    "is_serving": cell.is_serving,
                    "prov": provenance("0xB97F", imei, captured_at, log_tick),
                }
                if cell.rsrp is not None:
                    o["rsrp"] = cell.rsrp
                if cell.rsrq is not None:
                    o["rsrq"] = cell.rsrq
                enrich(o, sib1_map)
                out.append(o)

    return out


def enrich(obs, sib1_map):
    """Merge cached SIB1 identity onto an observation keyed by (pci, earfcn),
    if any -- turning a bare signal measurement into a full-identity tower."""
    ident = sib1_map.get((obs["pci"], obs["earfcn"]))
    if ident:
        obs.update(ident)


def update_sib1_map(sib1_map, log_type, result):
    """Record cell identity from a SIB1-bearing RRC OTA result.

    Two sources, mirroring dlf_to_wigle's build_identity_map:
      0xB0C0 -- LTE RRC OTA; identity keyed by the serving (pci, earfcn).
      0xB821 -- NR5G RRC OTA; identity keyed by (pci, arfcn) (NR ARFCN).
    Both parsers auto-decode SystemInformationBlockType1 and expose
    MCC/MNC/TAC/CellID, so a later measurement on that cell can be enriched to a
    full-identity tower with no AT source (the AT-optional wardriving path).

    First write wins per key, mirroring dlf_to_wigle -- SIB1 identity for a cell
    does not change within a camp, so we keep the first decode and skip churn.
    """
    if isinstance(result, Diag0xB0C0):
        if result.sib1_tac is None:
            return
        key = (result.pci, result.earfcn)
    elif isinstance(result, Diag0xB821):
        if result.sib1_tac is None:
            return
        key = (result.pci, result.arfcn)
    else:
        return
    if key in sib1_map:
        return
    sib1_map[key] = {
        "mcc": result.sib1_mcc,
        "mnc": result.sib1_mnc,
        "tac": result.sib1_tac,
        "cell_id": result.sib1_cell_id,
    }
