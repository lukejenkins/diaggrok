# diaggrok-provenance: re
"""Parsed DIAG result -> normalized ``cell_observation`` records.

A cell_observation is a decoder concept, not a Kismet one: ``rat``, ``pci``,
``earfcn``, optional ``rsrp``/``rsrq``, optional SIB1 identity, and a
provenance block. Consumers render it — Kismet as JSON lines, a WiGLE exporter
as CSV rows — but the mapping itself is what the DIAG bytes MEAN.

The rule this module exists to hold: an unbound field is OMITTED, never
emitted as 0. A plausible-but-wrong number outlives the review that would have
caught a missing key.
"""
from __future__ import annotations

import sys

from diaggrok.parsers.diag_0x512f import Diag0x512F
from diaggrok.parsers.diag_0xb0c0 import Diag0xB0C0
from diaggrok.parsers.diag_0xb17f import Diag0xB17F
from diaggrok.parsers.lte_tables import band_to_duplex, earfcn_to_band
from diaggrok.parsers.diag_0xb192 import Diag0xB192
from diaggrok.parsers.diag_0xb193 import Diag0xB193
from diaggrok.parsers.diag_0xb195 import Diag0xB195
from diaggrok.parsers.diag_0xb197 import Diag0xB197
from diaggrok.parsers.diag_0xb821 import Diag0xB821
from diaggrok.parsers.diag_0xb97f import Diag0xB97F


def provenance(origin: str, imei: str, captured_at: float,
               log_tick: float | None = None) -> dict:
    """Build the data-lineage provenance block stamped on every observation.

    ``captured_at`` is a Unix epoch (seconds) - the wall-clock at which this
    helper processed the record, mirroring the gettimeofday stamp a Kismet
    capture source applies when it sends JSON. It is deliberately NOT
    derived from the DIAG ts64: that field is a since-boot 1.25 ms-tick counter
    (see diaggrok.ts64_cal) with no wall-clock offset absent a GNSS calibration
    anchor, which a passive bridge does not carry. Fed as an absolute timestamp,
    the raw tick produces values like 60345938315396.0 - nonsense as an epoch. The raw tick is preserved as
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
            # Do NOT drop the observation when rsrp is None. 0xB193 carries
            # THREE wigle_roles — "signal", "pci-earfcn-bridge" and "rat-context"
            # — and only the first needs RSRP. The pci/earfcn identity is VERIFIED
            # on every version the parser emits (it is the signal SCALE that is
            # version-gated), so discarding the row would throw away two grounded
            # roles to avoid reporting one absent field. Several versions (v35,
            # 17.6% of observed 0xB193 records; v18, v22 and v48-RSRQ) report
            # rsrp/rsrq None because their scale is not grounded; dropping them
            # would delete a large share of 0xB193 identity observations. Emit the
            # identity; omit only the field that cannot be grounded.
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
            # (v59 bit15 of the PCI word; and the single-cell v50/v56 serving
            # cell) over positional inference — cell[0] is not always serving.
            # Fall back to the index only where no flag is grounded.
            is_serving = (e.serving_flag == 1) if e.serving_flag is not None else (i == 0)
            o["observation_type"] = "serving" if is_serving else "observation"
            o["is_serving"] = is_serving
            enrich(o, sib1_map)
            add_band_duplex(o)
            add_lte_cell_config(o, sib1_map)
            out.append(o)

    elif isinstance(result, Diag0xB0C0):
        # Gap-closer (M3.1): a SIB1-bearing 0xB0C0 LTE RRC OTA self-emits its own
        # identity cell, which is what lets a DIAG-only run produce its full
        # WiGLE cell set.
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
            # SIB9 Home-eNB / femtocell name. Co-temporal: the SIB9
            # is decoded from this same 0xB0C0 SystemInformation message that
            # carries the SIB1 identity above, so it belongs to THIS cell. Two
            # optional layers, both omit-when-unbound: the record may carry no
            # SIB9 at all (sib9_hnb is None), and a present SIB9's hnb-Name is
            # itself OPTIONAL (hnb_name None is a legal HNB that declines to name
            # itself) -- neither is a fabricated value, so both are simply
            # left off rather than emitted as "".
            hnb = getattr(result, "sib9_hnb", None)
            if hnb is not None and getattr(hnb, "hnb_name", None) is not None:
                o["hnb_name"] = hnb.hnb_name
            # SIB1 flags + MOCN PLMN list. Co-temporal: all decoded from
            # THIS 0xB0C0 SystemInformation message's SIB1, so they belong to this
            # cell. Omit-when-unbound: a parser that could not decode the flag left
            # it None. `plmns` is emitted only for a genuinely multi-operator
            # (RAN-shared / MOCN) cell -- a single-PLMN list is already fully
            # represented by mcc/mnc above, so repeating it as a 1-element array
            # would be noise, not information.
            if result.sib1_cell_barred is not None:
                o["cell_barred"] = result.sib1_cell_barred
            if result.sib1_csg_indication is not None:
                o["csg"] = result.sib1_csg_indication
            if result.sib1_plmn_list is not None and len(result.sib1_plmn_list) > 1:
                o["plmns"] = result.sib1_plmn_list
            # band / duplex: pure functions of the EARFCN (3GPP TS 36.101
            # tables), derived by the shared helper so all four LTE paths agree.
            add_band_duplex(o)
            add_lte_cell_config(o, sib1_map)
            out.append(o)
        if result.meas_report_id is not None:
            out.extend(_lte_meas_report_neighbours(
                result, imei, sib1_map, captured_at, log_tick))

    elif isinstance(result, Diag0xB192):
        # LTE idle-mode neighbor cells. The packet carries AGC-flattened energy,
        # NOT calibrated dBm, so the parser sets rsrp/rsrq to None and only
        # PCI/EARFCN are emitted -- no plausible-but-wrong signal number.
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
            add_band_duplex(o)
            add_lte_cell_config(o, sib1_map)
            out.append(o)

    elif isinstance(result, Diag0xB195):
        # LTE connected-mode neighbor cells.
        #
        # The per-Rx words are AGC-flattened energies, not dBm, so `e.rsrp` is
        # None on every entry of every version the parser handles. The `if e.rsrp is not None` guard below is therefore the
        # live path, not the exceptional one, and 0xB195 rows are emitted
        # IDENTITY-ONLY (pci + earfcn) exactly like 0xB192's.
        #
        # The guard stays rather than being replaced by an unconditional
        # identity-only emit: it is the seam that flips the day a scale IS
        # grounded, and deleting it would make that a code change here instead
        # of a parser change there.
        #
        # Identity-only is NOT a dropped row: identity always lands, only signal
        # population is conditional. Measured on an RM500Q-AE (SDX55, LTE B66,
        # RRC-connected): 97 x 0xB195 records -> **112 cell_observations**
        # through this function, 0 carrying rsrp.
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
            add_band_duplex(o)
            add_lte_cell_config(o, sib1_map)
            out.append(o)

    elif isinstance(result, Diag0xB17F):
        # LTE ML1 per-cell measurement. Unlike 0xB193's entries[] list,
        # ONE 0xB17F record IS one cell: it carries (earfcn, pci) identity plus
        # rsrp/rsrq/rssi in the same record, for serving AND neighbour cells.
        # This is the DIAG path's per-cell `rssi` source -- 0xB193
        # forwards only rsrp/rsrq, and its per-RX rssi is a decode gap. rssi is
        # SCAT-oracle grounded (MAE 0.46 dB) and AT+QENG-cross-checked across
        # three chipset generations (EG25-G / CFW-3212 / MC7411), so it is
        # forwarded as decoded -- no cross-mapping. Same-record emit: never a
        # cross-record join.
        #
        # earfcn==0 is a search-mode / no-serving-cell record (parser docstring):
        # it has no groundable cell identity, so it emits nothing rather than a
        # phantom (0, pci) cell.
        #
        # is_serving is False: the record carries NO serving flag, and serving
        # is never GUESSED from position. Disposition is
        # observation-type, exactly as 0xB192/0xB195 do without a grounded flag.
        if result.earfcn != 0:
            o = {
                "rat": "LTE",
                "pci": result.pci,
                "earfcn": result.earfcn,
                "observation_type": "observation",
                "is_serving": False,
                "prov": provenance("0xB17F", imei, captured_at, log_tick),
            }
            if result.rsrp is not None:
                o["rsrp"] = result.rsrp
            if result.rsrq is not None:
                o["rsrq"] = result.rsrq
            if result.rssi is not None:
                o["rssi"] = result.rssi
            enrich(o, sib1_map)
            add_band_duplex(o)
            add_lte_cell_config(o, sib1_map)
            out.append(o)

    elif isinstance(result, Diag0xB97F):
        # NR5G ML1 measurement DB -- the NR analog of the LTE 0xB193/0xB195
        # quartet. Per component carrier, each measured cell carries
        # per-cell SS-RSRP/RSRQ (ground-truthed vs AT+QSCAN) and a derived
        # is_serving flag (pci == the CC's serving_pci). The NR-ARFCN rides in the
        # `earfcn` field -- rat:"NR" disambiguates -- so the (pci, earfcn) enrich
        # key matches the 0xB821-fed NR sib1_map (keyed by (pci, arfcn)). Every
        # carrier is iterated (not the CC0-only .entries view) so
        # carrier-aggregated neighbours are not dropped. rsrp/rsrq are attached
        # only when present (out-of-band cells still emit PCI/EARFCN identity,
        # mirroring 0xB192 -- never a plausible-but-wrong signal number).
        for cc in result.carriers:
            for cell in cc.cells:
                # Spec invariant: NR PCI is 0..1007 (38.211 §7.4.2.1 -- 3
                # SSS sequences x 336 PSS groups). A value outside that range
                # is not a cell, it is a decode that walked off its stride, so
                # emitting it would put a fabricated tower in the dataset.
                #
                # Observed live: 10 of 679 NR observations on an
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
                    # record pipe a relay parses). The burst is intermittent:
                    # 10/679 observations in one capture, 0/1459 in a recapture
                    # two hours later on the same unit. A silent drop would throw
                    # away the only signal that a stride bug just fired, so the
                    # next capture-with-a-burst has to be found by luck rather
                    # than by noticing the log line.
                    print(f"celldiag WARN 0xB97F out-of-range NR pci={cell.pci} "
                          f"(spec 0..1007, 38.211 §7.4.2.1) arfcn={cc.nr_arfcn} "
                          f"rsrp={cell.rsrp} rsrq={cell.rsrq} — row dropped",
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
                # Per-SSB-beam blocks. A PER-CELL property (each beam
                # rides in THIS cell's 0xB97F block), so it lands on every NR
                # observation -- serving AND neighbour -- unlike serving_ssb_index
                # below, which is the serving beam only. Attached AFTER the
                # pci-range guard above, so a cell dropped for an out-of-range PCI
                # takes its (equally suspect) beams with it.
                add_nr_beams(o, cell)
                # NR SSB index of the SERVING beam. Co-temporal: it rides
                # in this same 0xB97F record's CC header (cc.serving_ssb_index),
                # so attaching it is a same-record read, not a cross-record join —
                # no stale-measurement risk. It is a property of the serving cell
                # (== that cell's serving beam's ssb_index on 507/507 CC0 cells),
                # so it is attached only to the serving observation; the
                # parser already resolves the version-dependent bit position
                # (v7/v9 flags[3:0] vs SDX72 v0/v0A flags[11:8]) and yields None
                # for the 0xF NA sentinel, which the omit-when-unbound guard drops.
                if cell.is_serving and cc.serving_ssb_index is not None:
                    o["serving_ssb_index"] = cc.serving_ssb_index
                # SSB burst periodicity in ms. Co-temporal: a record-level
                # property (config_word bits[15:8]), so it belongs to THIS
                # measurement, not a cached cross-record value. It is a serving
                # cell-configuration constant, so it rides on the serving
                # observation -- but INDEPENDENTLY of serving_ssb_index (a record
                # can carry a valid period while the SSB index is the 0xF NA
                # sentinel). SCAT-grounded 801/801 records over v0x07/v0x09
                # (0x1402 -> 20 ms). 0 means the field was not set in this record's
                # config word -> omit rather than emit a spurious 0 ms period.
                if cell.is_serving and result.ssb_periodicity_ms:
                    o["ssb_periodicity_ms"] = result.ssb_periodicity_ms
                enrich(o, sib1_map)
                # NR SSB subcarrier spacing: a per-cell config constant
                # cached from any 0xB821 MIB on this cell, attached to every
                # observation of it (serving or neighbour). Keyed by (pci, arfcn)
                # == this observation's (pci, earfcn), so it is the same cell.
                add_nr_scs(o, sib1_map)
                out.append(o)

    elif isinstance(result, Diag0xB821):
        # NR MeasurementReport self-observation -- the only DIAG source of NR
        # SINR. A UL-DCCH MeasurementReport carries the UE's own
        # serving-cell RSRP/RSRQ/SINR (ASN.1, TS 38.331) AND the camped serving
        # cell's (pci, arfcn) identity in the SAME record (pci@byte7,
        # arfcn@arfcn_offset are the camped cell), so attaching the metrics is a
        # same-record read -- co-temporal, no cross-record join, no
        # stale-measurement risk. 0xB97F, the NR ML1 measurement DB, carries NO
        # SINR on any version, so without this the decoded serving SINR
        # is simply dropped.
        #
        # Gated on meas_report_id: a SIB1/MIB/reconfig 0xB821 contributes
        # *identity* via update_sib1_map, not a signal measurement, so only a
        # measurement report emits an observation here -- otherwise every RRC
        # OTA record would double-emit a serving cell.
        if result.meas_report_id is not None:
            # Spec invariant: NR PCI is 0..1007 (38.211 §7.4.2.1). A camped-
            # cell pci outside that range is a decode that walked off its
            # stride, so drop the row rather than emit a fabricated tower --
            # same discipline as the 0xB97F path.
            if result.pci is not None and 0 <= result.pci <= 1007:
                o = {
                    "rat": "NR",
                    "pci": result.pci,
                    "earfcn": result.arfcn,
                    "observation_type": "serving",
                    "is_serving": True,
                    "prov": provenance("0xB821", imei, captured_at, log_tick),
                }
                # Co-temporal serving metrics from THIS report's ASN.1
                # (omit-when-unbound: a metric the report did not carry is left
                # off, never emitted as a spurious 0 dB -- RXM-G1 reports carry
                # SINR only, rsrp/rsrq absent).
                if result.meas_report_serving_rsrp is not None:
                    o["rsrp"] = result.meas_report_serving_rsrp
                if result.meas_report_serving_rsrq is not None:
                    o["rsrq"] = result.meas_report_serving_rsrq
                if result.meas_report_serving_sinr is not None:
                    o["sinr"] = result.meas_report_serving_sinr
                # Full-identity enrich + per-cell SCS if a SIB1/MIB for this NR
                # cell was already cached (keyed by (pci, arfcn) == this obs's
                # (pci, earfcn)); both no-op when nothing is cached.
                enrich(o, sib1_map)
                add_nr_scs(o, sib1_map)
                out.append(o)

    elif isinstance(result, Diag0x512F):
        out.extend(_gsm_si3_observation(result, imei, captured_at, log_tick))

    return out


def _gsm_si3_observation(result, imei, captured_at, log_tick):
    """0x512F GSM RR signalling -> at most one GSM identity cell.

    Only **System Information Type 3** emits: it is the one BCCH message that
    carries the full WiGLE identity (MCC, MNC, LAC, CI) in a single record.

    No ARFCN, and no SI1/SI2 join to supply one. SI3 carries no serving
    ARFCN, and the tempting fix -- take the single-entry SI1 cell-allocation
    list -- is a CROSS-RECORD join with no key: SI1 names no cell. Captures
    contradict the "SI1 and SI3 are the same cell" premise outright: one EC25
    drive capture logs SI3s for six different cells (CI 11633,
    55384, 55382, 3822, 3821, 10751) within seconds, most with no SI1/SI2 of
    their own -- the modem reads NEIGHBOUR BCCHs during reselection ranking. An
    SI1 arriving after an SI3 can belong to either, so the join would put a
    plausible-but-wrong channel on a real tower. The grounded ARFCN source is a
    record carrying the TUNED channel (0x5134 LOG_GSM_RR_CELL_INFORMATION).

    Not serving. For the same reason, an SI3 does not say it is the camped
    cell; serving is never guessed from context, so every row is an
    ``observation``.

    ``tac`` carries the LAC as well as ``lac``: it is the generic area-code
    slot (WiGLE's ``MCCMNC_xAC_CID``), and a downstream device key is built
    from ``tac``. Without it a GSM cell keys
    ``MCC_MNC_0_CID``, a different tower to WiGLE.

    Everything else emits nothing, deliberately:
      * SI4 -- LAI only, no CI: not a full identity, and no PCI/ARFCN either.
      * SI1 / SI2 / SI2bis / SI2quater / SI13 -- channel lists and GPRS
        config with no cell to bind them to (above).
      * CCCH 0x83 (Paging Request, Immediate Assignment) -- not cell
        broadcasts, and paging carries OTHER subscribers' TMSI/IMSI. It must
        never produce a row or leak an identity into one.
    """
    if result.channel_name != "BCCH":
        return []
    if result.message_name != "system_information_3":
        return []
    if None in (result.mcc, result.mnc, result.lac, result.cell_identity):
        return []
    return [{
        "rat": "GSM",
        "mcc": result.mcc,
        "mnc": result.mnc,
        "lac": result.lac,
        "tac": result.lac,
        "cell_id": result.cell_identity,
        "observation_type": "observation",
        "is_serving": False,
        "prov": provenance("0x512F", imei, captured_at, log_tick),
    }]


#: sib1_map key of the per-session LTE measConfig state. A 1-tuple, so it
#: cannot collide with enrich()'s (pci, earfcn) identity keys or the 3-tuple
#: ("scs", ...) / ("lte_cfg", ...) caches.
_LTE_MEAS_KEY = ("lte_meas",)


def _lte_meas_state(sib1_map):
    """The UE's measConfig as far as this session has seen it.

    ``objects``: measObjectId -> effective EARFCN, or None for a non-EUTRA
    object (UTRA/GERAN/CDMA2000/NR...). ``links``: measId -> measObjectId.
    """
    return sib1_map.setdefault(_LTE_MEAS_KEY, {"objects": {}, "links": {}})


def _lte_meas_state_update(sib1_map, result):
    """Apply one 0xB0C0 record to the measId -> EARFCN state.

    measConfig is a DELTA on state the UE holds (TS 36.331 §5.5.2), so a
    mapping is only as good as its invalidation. Rules, each chosen so that an
    unknown carrier is OMITTED rather than guessed:

    * DL-DCCH rrcConnectionRelease / mobilityFromEUTRACommand, DL-CCCH
      rrcConnectionSetup -- the UE leaves (or has not yet entered) the
      connection the config belonged to: clear everything.
    * DL-CCCH rrcConnectionReestablishment, and an RRCConnectionReconfiguration
      carrying mobilityControlInfo (handover) -- §5.5.6.1 re-links measIds
      between the source and target frequencies. The swap is not modelled;
      every measId link is dropped (objects survive, as they do on the UE). Links the
      same message re-adds are applied afterwards, per §5.3.5.4's order.
    * measConfig itself, in §5.5.1 order: measObject removal (which also
      removes every measId linked to it, §5.5.2.4), measObject add/modify,
      measId removal, measId add/modify.

    fullConfig-r9 (in the reconfiguration's nonCriticalExtension, not
    decoded) releases the whole measConfig, but only rides a handover or the
    first reconfiguration after re-establishment -- both of which already drop
    the links, and a later measId may only reference an object re-added after
    the release, so a stale object cannot be reached through a valid link.
    """
    ch = result.channel_name
    md = result.msg_data
    if not md:
        return
    state = _lte_meas_state(sib1_map)
    if ch == "DL-CCCH" and md[0] >> 7 == 0:
        c1 = (md[0] >> 5) & 0b11      # DL-CCCH c1: 0 reestablishment .. 3 setup
        if c1 == 3:
            state["objects"].clear()
            state["links"].clear()
        elif c1 == 0:
            state["links"].clear()
        return
    if ch != "DL-DCCH" or md[0] >> 7 != 0:
        return
    c1 = (md[0] >> 3) & 0b1111        # DL-DCCH c1 (16 alternatives)
    if c1 in (3, 5):                  # mobilityFromEUTRACommand, rrcConnectionRelease
        state["objects"].clear()
        state["links"].clear()
        return
    mc = getattr(result, "meas_config", None)
    if mc is None:                    # not a (decodable) reconfiguration
        return
    objects, links = state["objects"], state["links"]
    if mc.has_mobility_control:
        links.clear()
    for obj_id in mc.meas_object_remove:
        objects.pop(obj_id, None)
        for meas_id in [m for m, o in links.items() if o == obj_id]:
            del links[meas_id]
    for obj_id in mc.non_eutra_object_ids:
        objects[obj_id] = None
    for obj in mc.meas_objects:
        objects[obj.meas_object_id] = obj.earfcn
    for meas_id in mc.meas_id_remove:
        links.pop(meas_id, None)
    for link in mc.meas_ids:
        links[link.meas_id] = link.meas_object_id


def _lte_meas_report_neighbours(result, imei, sib1_map, captured_at, log_tick):
    """LTE MeasurementReport neighbour rows.

    The neighbours the UE measured for handover evaluation, carrying same-record
    RSRP/RSRQ. ``MeasResultEUTRA`` holds only ``physCellId``; the carrier is the
    measId's measObject, from :func:`_lte_meas_state_update`. When that map has
    no EUTRA carrier for the measId, a PCI-only neighbour is OMITTED -- "same as
    serving" would be the plausible-but-wrong guess this module forbids.

    A neighbour with ``cgi-Info`` has full identity (MCC/MNC/TAC/CI), which keys
    on its own; it is emitted even when the carrier is unknown, with the EARFCN
    attached only when mapped. Its CGI is authoritative, so it is not
    overwritten by a SIB1 cache hit.

    Not serving: every row is an ``observation``. RSRP/RSRQ are forwarded
    from lte_signal_levels as-is (with its bin-edge convention).
    """
    state = sib1_map.get(_LTE_MEAS_KEY) or {"objects": {}, "links": {}}
    obj_id = state["links"].get(result.meas_report_id)
    earfcn = state["objects"].get(obj_id) if obj_id is not None else None
    out = []
    for n in result.meas_report_neighbors:
        # LTE PCI is 0..503; outside it the decode walked off its stride.
        if not 0 <= n.pci <= 503:
            continue
        has_cgi = None not in (n.mcc, n.mnc, n.tac, n.cid)
        if earfcn is None and not has_cgi:
            continue
        o = {
            "rat": "LTE",
            "pci": n.pci,
            "observation_type": "observation",
            "is_serving": False,
            "prov": provenance("0xB0C0", imei, captured_at, log_tick),
        }
        if earfcn is not None:
            o["earfcn"] = earfcn
        if n.rsrp is not None:
            o["rsrp"] = n.rsrp
        if n.rsrq is not None:
            o["rsrq"] = n.rsrq
        if has_cgi:
            o.update(mcc=n.mcc, mnc=n.mnc, tac=n.tac, cell_id=n.cid)
        elif earfcn is not None:
            enrich(o, sib1_map)
        add_band_duplex(o)
        add_lte_cell_config(o, sib1_map)
        out.append(o)
    return out


def enrich(obs, sib1_map):
    """Merge cached SIB1 identity onto an observation keyed by (pci, earfcn),
    if any -- turning a bare signal measurement into a full-identity tower."""
    ident = sib1_map.get((obs["pci"], obs["earfcn"]))
    if ident:
        obs.update(ident)


def add_band_duplex(obs):
    """Attach LTE ``band`` + ``duplex`` to an observation from its ``earfcn``.

    band/duplex are pure functions of the EARFCN (3GPP TS 36.101 tables), not a
    per-cell decode, so they are grounded on EVERY LTE observation regardless of
    which log code emitted it. There is no cross-record join and no
    measurement staleness -- the EARFCN that keys the lookup is a same-record
    field of the observation itself -- so unlike SINR/RSSI these are safe on the
    idle/connected-neighbour codes (0xB192/0xB193/0xB195), not only the 0xB0C0
    self-observation that first carried them.

    EARFCN->band is unambiguous: each band owns a distinct EARFCN range, so the
    B4/B66-style split is a *frequency* overlap for PCI-only cells, a
    different problem than this map. Omit band 0 (unknown/unmapped EARFCN) and an
    unclassified duplex rather than emit a plausible-but-wrong value -- the
    omit-never-zero rule this module exists to hold.

    Centralised so the four LTE emission paths cannot drift on the derivation
    (two writers that disagree).
    """
    earfcn = obs.get("earfcn")
    if earfcn is None:
        return
    band = earfcn_to_band(earfcn)
    if not band:
        return
    obs["band"] = band
    duplex = band_to_duplex(band)
    if duplex is not None:
        obs["duplex"] = duplex


# LTE DL bandwidth: resource blocks -> MHz (TS 36.101 Table 5.6-1). 6 RB is
# 1.4 MHz, which the integer-MHz ``bandwidth`` key (Kismet
# ``cellular.cell.bandwidth``, "Channel bandwidth MHz", uint16) cannot carry, so
# it is deliberately ABSENT here: a 1.4 MHz cell gets ``bandwidth_rb`` only,
# never a truncated ``bandwidth: 1``.
_LTE_RB_TO_MHZ = {15: 3, 25: 5, 50: 10, 75: 15, 100: 20}

# 0xB197 truncates its EARFCN to the low 16 bits, so the cell-config
# cache is keyed on the truncated value.
_EARFCN_LOW16 = 0xFFFF


def add_lte_cell_config(obs, sib1_map):
    """Attach the 0xB197 serving-cell config to an LTE observation.

    0xB197 (LTE ML1 Serving Cell Information) decodes the cell's DL bandwidth
    (RB count, SCAT-grounded) and Tx antenna port count (SCAT 237/237).
    Both are per-cell CONFIGURATION constants, not measurements, so a cached
    value attached to a later observation of the SAME cell is grounded -- the
    NR ``scs`` footing (:func:`add_nr_scs`), not the stale-measurement join the
    signal keys forbid. :func:`update_sib1_map` caches them under
    ``("lte_cfg", pci, earfcn & 0xFFFF)``.

    Keys (all omit-when-unbound): ``bandwidth_rb`` (lossless RB count),
    ``bandwidth`` (MHz, integer; absent for 1.4 MHz -- see ``_LTE_RB_TO_MHZ``),
    ``tx_antennas`` (1/2/4).

    The truncated key aliases: B66 EARFCN 66786 and B3 EARFCN 1250 are both
    ``1250`` to 0xB197. So every full EARFCN seen under a truncated key is
    recorded (``("lte_cfg_full", pci, low16)``), and once two DIFFERENT full
    EARFCNs have shared a key the config is no longer attached to either -- the
    cache cannot tell which cell it describes, and a plausible-but-wrong
    bandwidth is worse than none.
    """
    earfcn = obs.get("earfcn")
    pci = obs.get("pci")
    if earfcn is None or pci is None:
        return
    low16 = earfcn & _EARFCN_LOW16
    cfg = sib1_map.get(("lte_cfg", pci, low16))
    if not cfg:
        return
    seen = sib1_map.setdefault(("lte_cfg_full", pci, low16), set())
    seen.add(earfcn)
    if len(seen) > 1:
        return
    rb = cfg.get("bandwidth_rb")
    if rb is not None:
        obs["bandwidth_rb"] = rb
        mhz = _LTE_RB_TO_MHZ.get(rb)
        if mhz is not None:
            obs["bandwidth"] = mhz
    ant = cfg.get("tx_antennas")
    if ant is not None:
        obs["tx_antennas"] = ant

# NR-ARFCN of 24250 MHz -- the FR1/FR2 boundary (TS 38.104 5.4.2.1). The global
# frequency raster steps 15 kHz over 3000-24250 MHz, so 24250 MHz == ARFCN
# 2016667. An NR-ARFCN at or above this is FR2, below it is FR1. This is a
# deterministic spec constant, not a guess -- the same footing as earfcn->band.
_FR2_ARFCN_FLOOR = 2016667

# MIB subCarrierSpacingCommon (TS 38.331) is ENUMERATED {scs15or60, scs30or120}
# -- the value alone is ambiguous, but the frequency range resolves it:
# scs15or60 == 15 kHz (FR1) / 60 kHz (FR2); scs30or120 == 30 kHz (FR1) / 120 kHz
# (FR2). Keyed by (enum_name, is_fr2) so the resolution is total, never partial.
_MIB_SCS_KHZ = {
    ("scs15or60", False): 15,  ("scs15or60", True): 60,
    ("scs30or120", False): 30, ("scs30or120", True): 120,
}


def _mib_scs_khz(result):
    """Resolve a 0xB821 record's MIB subCarrierSpacingCommon to kHz, or None.

    Returns None when the record carries no MIB SCS or the enum is unrecognised
    -- never a guessed default, so an unknown SCS is omitted rather than emitted
    as a plausible-but-wrong number. FR1/FR2 is derived from the record's own
    NR-ARFCN, so the disambiguation is co-temporal and grounded."""
    name = getattr(result, "mib_scs_common", "") or ""
    if not name:
        return None
    arfcn = getattr(result, "arfcn", None)
    is_fr2 = arfcn is not None and arfcn >= _FR2_ARFCN_FLOOR
    return _MIB_SCS_KHZ.get((name, is_fr2))


def add_nr_scs(obs, sib1_map):
    """Attach NR ``scs`` (kHz) to an NR observation from the scs cache.

    scs is the MIB subCarrierSpacingCommon, a per-cell configuration constant
    cached under a distinct ``("scs", pci, arfcn)`` key by :func:`update_sib1_map`
    -- distinct from the ``(pci, earfcn)`` identity namespace enrich() reads, so
    it can never leak onto an LTE observation that collides on (pci, arfcn) (low-
    band NR ARFCNs overlap the LTE EARFCN range). Because it is a constant keyed
    to the cell, attaching a cached value to a later measurement of the SAME cell
    is grounded, NOT the stale-measurement cross-record join the signal fields
    forbid. Omit-when-unbound: no cached scs -> no key."""
    scs = sib1_map.get(("scs", obs["pci"], obs["earfcn"]))
    if scs is not None:
        obs["scs"] = scs


# Contract-relevant per-beam keys: the SSB index and the RSRP/RSRQ a/b
# pairs. beam_id_a/b, filtered_* and word*_raw are grounded-NAME but
# no-grounded-SEMANTIC -- their names come from SCAT output but no observed
# capture exercises them -- so they are deliberately kept
# OUT of the observation contract, not forwarded as plausible-but-meaningless.
def _beam_contract(beam):
    """Project one ``Nr5gBeam`` to its contract subset.

    ``ssb_index`` is the beam's identity and is always present (an ``int`` -- 0 is
    a real, distinct beam, not absence). The RSRP/RSRQ a/b pairs are omitted when
    unbound (the 44-B v0x07/v0x09 beam carries no per-beam RSRQ; a beam whose
    RSRP scaled to the no-measurement sentinel resolves to None) -- omit-never-zero
    applied per beam."""
    d = {"ssb_index": beam.ssb_index}
    if beam.rsrp_a is not None:
        d["rsrp_a"] = beam.rsrp_a
    if beam.rsrp_b is not None:
        d["rsrp_b"] = beam.rsrp_b
    if beam.rsrq_a is not None:
        d["rsrq_a"] = beam.rsrq_a
    if beam.rsrq_b is not None:
        d["rsrq_b"] = beam.rsrq_b
    return d


def add_nr_beams(obs, cell):
    """Attach an NR cell's per-SSB-beam blocks as a ``beams`` list.

    NR has no CRS: a cell is measured per SSB beam inside SMTC windows, and the
    parser already decodes each beam onto ``Nr5gCellMeasurement.beams[]``. The
    beams ride in the SAME 0xB97F cell block as the cell's own rsrp/rsrq, so this
    is a same-record, same-cell read -- co-temporal, NOT the cross-record join
    the signal-forward rule forbids. Each beam is projected to its contract
    subset by :func:`_beam_contract`.

    Omit-never-empty: a cell with no decoded beam blocks gets no ``beams`` key at
    all, so the many single-cell records whose beam tail did not decode do not
    sprout an empty ``beams: []`` -- the same discipline as the module's
    omit-never-zero rule, applied to the array."""
    beams = getattr(cell, "beams", None)
    if not beams:
        return
    obs["beams"] = [_beam_contract(b) for b in beams]


def _cache_lte_cell_config(sib1_map, result):
    """Cache one 0xB197 record's serving-cell config for add_lte_cell_config.

    Each field is written first-wins and only when the parser bound it: the
    no-measurement sentinels (dl_bandwidth {0, 101}, num_antennas 3) are already
    None, so a sentinel record caches nothing and cannot shadow a later real
    one. ``earfcn == 0`` has no groundable cell identity (the 0xB17F rule) and is
    skipped."""
    if not result.earfcn:
        return
    cfg = sib1_map.setdefault(
        ("lte_cfg", result.pci, result.earfcn & _EARFCN_LOW16), {})
    if result.dl_bandwidth_rb is not None:
        cfg.setdefault("bandwidth_rb", result.dl_bandwidth_rb)
    if result.num_antennas is not None:
        cfg.setdefault("tx_antennas", result.num_antennas)

def update_sib1_map(sib1_map, log_type, result):
    """Record cell identity from a SIB1-bearing RRC OTA result.

    Two sources:
      0xB0C0 -- LTE RRC OTA; identity keyed by the serving (pci, earfcn).
      0xB821 -- NR5G RRC OTA; identity keyed by (pci, arfcn) (NR ARFCN).
    Both parsers auto-decode SystemInformationBlockType1 and expose
    MCC/MNC/TAC/CellID, so a later measurement on that cell can be enriched to a
    full-identity tower with no AT source (the AT-optional wardriving path).

    First write wins per key -- SIB1 identity for a cell does not change within
    a camp, so the first decode is kept and churn skipped.

    0xB821 also feeds a second, independent cache: the MIB SSB SCS under
    a distinct ``("scs", pci, arfcn)`` key. It is written REGARDLESS of the SIB1
    gate below, because subCarrierSpacingCommon rides in the MIB and can arrive
    on a 0xB821 record that carries no SIB1. The 3-tuple namespace keeps it out of enrich()'s
    identity merge; :func:`add_nr_scs` reads it explicitly on the NR path.
    0xB197 feeds a third: LTE serving-cell config (DL bandwidth, Tx antenna
    ports) under ``("lte_cfg", pci, earfcn & 0xFFFF)``, read by
    :func:`add_lte_cell_config`.
    0xB0C0 DL-DCCH / DL-CCCH records feed a fourth: the measId -> EARFCN
    measConfig state under ``("lte_meas",)``, read by the
    MeasurementReport neighbour rows. It is updated for EVERY 0xB0C0 record,
    before the SIB1 gate, because the release / setup / handover messages that
    invalidate it carry no SIB1.
    """
    if isinstance(result, Diag0xB197):
        _cache_lte_cell_config(sib1_map, result)
        return
    if isinstance(result, Diag0xB0C0):
        _lte_meas_state_update(sib1_map, result)
        if result.sib1_tac is None:
            return
        key = (result.pci, result.earfcn)
    elif isinstance(result, Diag0xB821):
        scs_khz = _mib_scs_khz(result)
        if scs_khz is not None:
            sib1_map.setdefault(("scs", result.pci, result.arfcn), scs_khz)
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
