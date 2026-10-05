# diaggrok-provenance: re
"""GSM RR (TS 44.018) downlink CCCH/BCCH L3 message decoder.

Shared helper for DIAG codes that carry a raw GSM Radio Resource L3 block —
first consumer ``diag_0x512f.py`` (``LOG_GSM_RR_SIGNALING_MESSAGE``).
Skipped by ``parsers/__init__.py`` auto-discovery (leading underscore).

Clean-room: field layouts are taken from the public 3GPP specs (TS 44.018
§9.1 / §10.5.2, TS 24.008 §10.5.1) and every branch this module decodes was
checked bit-for-bit against stock ``tshark`` (``gsm_a_ccch``) output on the
0x512F corpus, used strictly as a black-box output oracle.

────────────────────────────────────────────────────────────────────────
Scope — decode what the corpus proves, STOP on what it doesn't
────────────────────────────────────────────────────────────────────────
Fixed-format IEs (LAI, Cell Identity, Control Channel Description, frequency
lists, Mobile Identity, Channel Description, Request Reference, …) are
decoded in full.

The *rest octets* (SI1/SI3/SI13/SI2quater/P1) are CSN.1 bitstreams: a
presence bit selects a branch, and a wrong branch width silently desynchronises
every field after it. So the CSN.1 walkers decode every branch the corpus
exercises and, on reaching a branch it does NOT exercise, **stop** and record
where in ``decode_stopped_at`` rather than guess a layout. Everything decoded
before the stop is still returned. A full walk to the padding reports
``decode_stopped_at = None``.
"""
from __future__ import annotations

from typing import Any

from diaggrok.parsers._nas_l3 import decode_lai, decode_mobile_identity
from diaggrok.parsers.uper import UperReader

# ── Message types (TS 44.018 §10.4, Table 10.4.1) — the ones this decodes ──
RR_MSG_SI13 = 0x00
RR_MSG_SI2BIS = 0x02
RR_MSG_SI2TER = 0x03
RR_MSG_SI2QUATER = 0x07
RR_MSG_SI1 = 0x19
RR_MSG_SI2 = 0x1A
RR_MSG_SI3 = 0x1B
RR_MSG_SI4 = 0x1C
RR_MSG_PAGING_REQUEST_1 = 0x21
RR_MSG_IMMEDIATE_ASSIGNMENT = 0x3F

RR_MESSAGE_NAMES: dict[int, str] = {
    0x00: "system_information_13",
    0x02: "system_information_2bis",
    0x03: "system_information_2ter",
    0x06: "system_information_5ter",
    0x07: "system_information_2quater",
    0x19: "system_information_1",
    0x1A: "system_information_2",
    0x1B: "system_information_3",
    0x1C: "system_information_4",
    0x1D: "system_information_5",
    0x1E: "system_information_6",
    0x21: "paging_request_type_1",
    0x22: "paging_request_type_2",
    0x24: "paging_request_type_3",
    0x39: "immediate_assignment_extended",
    0x3A: "immediate_assignment_reject",
    0x3F: "immediate_assignment",
}

# RR protocol discriminator (TS 24.007 §11.2.3.1.1).
PD_RR = 0x6

# CSN.1 L/H is relative to the GSM spare-padding octet 0x2B (TS 44.018 §10.5.2
# / TS 24.007 §11.1): at each bit position, H = "bit differs from 0x2B's bit".
_PADDING_OCTET = 0x2B


class _Unverified(Exception):
    """A CSN.1 branch the corpus never exercised — stop, don't guess."""


class _Csn:
    """MSB-first bit reader with CSN.1 L/H and hard end-of-buffer checks."""

    def __init__(self, data: bytes):
        self._r = UperReader(data)
        self._nbits = len(data) * 8

    @property
    def pos(self) -> int:
        return self._r.bit_pos

    def remaining(self) -> int:
        return self._nbits - self._r.bit_pos

    def bits(self, n: int, what: str = "field") -> int:
        if self._r.bit_pos + n > self._nbits:
            raise _Unverified(f"{what}: truncated")
        return self._r.read_bits(n)

    def bit(self, what: str = "flag") -> int:
        return self.bits(1, what)

    def lh(self, what: str = "L/H") -> bool:
        """Read one CSN.1 L/H bit; True means H."""
        p = self._r.bit_pos % 8
        pad = (_PADDING_OCTET >> (7 - p)) & 1
        return self.bits(1, what) != pad

    def skip(self, n: int, what: str = "skip") -> None:
        if self._r.bit_pos + n > self._nbits:
            raise _Unverified(f"{what}: truncated")
        self._r.skip_bits(n)

    def absent(self, what: str) -> None:
        """Consume a ``{0 | 1 <X>}`` bit whose '1' branch is unverified."""
        if self.bit(what):
            raise _Unverified(what)


def _run(fn, data: bytes) -> dict[str, Any]:
    """Run a CSN.1 walker; attach ``decode_stopped_at`` (None = full walk).

    After a full walk, ``padding_ok`` says whether every remaining bit is the
    0x2B spare padding. It is a tripwire, not a proof: a walk that ends early
    or late *usually* leaves non-padding bits behind or trips a stop, but a
    shift across bits that happen to equal the padding passes. (Measured: a
    2-bit P1 under-read is caught on 37/51 distinct corpus bodies, a 1-bit
    FDD under-skip on 4/6.) Field values are verified against tshark in the
    tests, not by this flag.
    """
    out: dict[str, Any] = {}
    r = _Csn(data)
    try:
        fn(r, out)
        out["decode_stopped_at"] = None
        out["padding_ok"] = not any(r.lh() for _ in range(r.remaining()))
    except _Unverified as e:
        out["decode_stopped_at"] = str(e)
        out["padding_ok"] = None
    return out


# ── Frequency lists (TS 44.018 §10.5.2.13 / .1b / .22) ─────────────────────
# Per-format W(k) bit widths, as (count, width) runs. The final run is
# truncated by the 16-octet IE size.
_RANGE_W_WIDTHS: dict[int, tuple[tuple[int, int], ...]] = {
    1024: ((1, 10), (2, 9), (4, 8), (8, 7), (1, 6)),
    512: ((1, 9), (2, 8), (4, 7), (8, 6), (2, 5)),
    256: ((1, 8), (2, 7), (4, 6), (8, 5), (6, 4)),
    128: ((1, 7), (2, 6), (4, 5), (8, 4), (13, 3)),
}
_RANGE_SUBFORMAT = {0b100: 512, 0b101: 256, 0b110: 128}
_FREQ_IE_LEN = 16


def _range_offsets(w: list[int], rng: int) -> list[int]:
    """TS 44.018 §10.5.2.13.3 tree decode: W(1..n) -> F(1..n) (stop at W=0)."""
    out: list[int] = []
    for k in range(1, len(w) + 1):
        if w[k - 1] == 0:
            break
        idx = k
        j = 1 << (idx.bit_length() - 1)
        n = w[idx - 1]
        while idx > 1:
            if 2 * idx < 3 * j:  # left child
                idx -= j // 2
                n = (n + w[idx - 1] - rng // j - 1) % (2 * rng // j - 1) + 1
            else:  # right child
                idx -= j
                n = (n + w[idx - 1] - 1) % (2 * rng // j - 1) + 1
            j //= 2
        out.append(n)
    return out


def _read_w(r: _Csn, rng: int) -> list[int]:
    w: list[int] = []
    for count, width in _RANGE_W_WIDTHS[rng]:
        for _ in range(count):
            if r.remaining() < width:
                return w
            w.append(r.bits(width))
    return w


def decode_frequency_list(ie: bytes) -> dict[str, Any] | None:
    """Decode a 16-octet frequency-list value (Cell Channel / Neighbour Cell
    Description). Returns ``{format, arfcns}``; ``orig_arfcn`` for the
    ORIG-ARFCN-based formats. Bits 6-5 of octet 1 (EXT-IND / BA-IND in
    §10.5.2.22) are the caller's to interpret.
    """
    if len(ie) < _FREQ_IE_LEN:
        return None
    b = bytes(ie[:_FREQ_IE_LEN])
    if (b[0] >> 6) == 0b00:  # bit map 0: ARFCN n (1..124) -> octet 16-(n-1)//8
        arfcns = [n for n in range(1, 125)
                  if (b[15 - (n - 1) // 8] >> ((n - 1) % 8)) & 1]
        return {"format": "bit_map_0", "arfcns": arfcns}
    if (b[0] >> 6) != 0b10:
        return {"format": f"reserved_0x{b[0] >> 6:X}", "arfcns": []}
    r = _Csn(b)
    sub = (b[0] >> 1) & 0x7
    if not (sub & 0b100):  # range 1024: F0 at bit 3 of octet 1, W(1) from bit 2
        r.skip(5)
        f0 = r.bit()
        f = _range_offsets(_read_w(r, 1024), 1024)
        return {"format": "range_1024",
                "arfcns": sorted(set(f) | ({0} if f0 else set()))}
    r.skip(7)
    orig = r.bits(10)
    if sub == 0b111:  # variable bit map: RRFCN bit k -> ORIG-ARFCN + k
        arfcns = {orig}
        k = 1
        while r.remaining():
            if r.bit():
                arfcns.add((orig + k) % 1024)
            k += 1
        return {"format": "variable_bit_map", "orig_arfcn": orig,
                "arfcns": sorted(arfcns)}
    rng = _RANGE_SUBFORMAT[sub]
    f = _range_offsets(_read_w(r, rng), rng)
    return {"format": f"range_{rng}", "orig_arfcn": orig,
            "arfcns": sorted({orig} | {(orig + x) % 1024 for x in f})}


def _neighbour_cell_description(ie: bytes) -> dict[str, Any] | None:
    """§10.5.2.22: frequency list + EXT-IND (bit 6) + BA-IND (bit 5)."""
    fl = decode_frequency_list(ie)
    if fl is None:
        return None
    fl["ext_ind"] = (ie[0] >> 5) & 1
    fl["ba_ind"] = (ie[0] >> 4) & 1
    return fl


# ── Fixed-format IEs ───────────────────────────────────────────────────────

def _rach_control(b: bytes) -> dict[str, Any]:
    """§10.5.2.29 RACH Control Parameters (3 octets)."""
    return {
        "max_retrans": (b[0] >> 6) & 0x3,
        "tx_integer": (b[0] >> 2) & 0xF,
        "cell_barr_access": (b[0] >> 1) & 1,
        "re": b[0] & 1,
        "access_control_classes": (b[1] << 8) | b[2],
    }


def _cell_selection(b: bytes) -> dict[str, Any]:
    """§10.5.2.4 Cell Selection Parameters (2 octets)."""
    return {
        "cell_reselect_hysteresis": (b[0] >> 5) & 0x7,
        "ms_txpwr_max_cch": b[0] & 0x1F,
        "acs": (b[1] >> 7) & 1,
        "neci": (b[1] >> 6) & 1,
        "rxlev_access_min": b[1] & 0x3F,
    }


def _control_channel_description(b: bytes) -> dict[str, Any]:
    """§10.5.2.11 Control Channel Description (3 octets)."""
    return {
        "mscr": (b[0] >> 7) & 1,
        "att": (b[0] >> 6) & 1,
        "bs_ag_blks_res": (b[0] >> 3) & 0x7,
        "ccch_conf": b[0] & 0x7,
        "cbq3": (b[1] >> 5) & 0x3,
        "bs_pa_mfrms": b[1] & 0x7,
        "t3212": b[2],
    }


def _cell_options_bcch(v: int) -> dict[str, Any]:
    """§10.5.2.3 Cell Options (BCCH) (1 octet)."""
    return {
        "pwrc": (v >> 6) & 1,
        "dtx": (v >> 4) & 0x3,
        "radio_link_timeout": v & 0xF,
    }


def _channel_description(b: bytes) -> dict[str, Any]:
    """§10.5.2.5 Channel Description / §10.5.2.25a Packet Channel Description
    (3 octets): channel type + TN, TSC, hopping flag, ARFCN or MAIO/HSN."""
    out: dict[str, Any] = {
        "channel_type": (b[0] >> 3) & 0x1F,
        "timeslot": b[0] & 0x7,
        "tsc": (b[1] >> 5) & 0x7,
        "hopping": bool((b[1] >> 4) & 1),
    }
    if out["hopping"]:
        out["maio"] = ((b[1] & 0xF) << 2) | (b[2] >> 6)
        out["hsn"] = b[2] & 0x3F
    else:
        out["arfcn"] = ((b[1] & 0x3) << 8) | b[2]
    return out


def _request_reference(b: bytes) -> dict[str, Any]:
    """§10.5.2.30 Request Reference (3 octets): RA + starting-time T1'/T3/T2."""
    t1p = (b[1] >> 3) & 0x1F
    t3 = ((b[1] & 0x7) << 3) | (b[2] >> 5)
    t2 = b[2] & 0x1F
    return {
        "ra": b[0], "t1_prime": t1p, "t3": t3, "t2": t2,
        # Reduced frame number (§10.5.2.38): 51*((T3-T2) mod 26) + T3 + 51*26*T1'.
        "rfn": 51 * ((t3 - t2) % 26) + t3 + 51 * 26 * t1p,
    }


def _mobile_identity(value: bytes) -> dict[str, Any] | None:
    mi = decode_mobile_identity(value)
    if mi is not None and "tmsi" in mi:
        mi["tmsi_hex"] = f"0x{mi['tmsi']:08X}"
    return mi


# ── CSN.1 rest octets ──────────────────────────────────────────────────────

def _si1_rest(r: _Csn, o: dict[str, Any]) -> None:
    """§10.5.2.32: {L | H <NCH Position : 5>} <BAND_INDICATOR : L|H>."""
    if r.lh("nch_position"):
        o["nch_position"] = r.bits(5)
    o["band_indicator"] = "pcs1900" if r.lh("band_indicator") else "dcs1800"
    if r.lh("si1_rest_additions"):
        raise _Unverified("si1_rest_additions")


def _si3_rest(r: _Csn, o: dict[str, Any]) -> None:
    """§10.5.2.34 SI3 Rest Octets."""
    if r.lh("optional_selection_parameters"):
        o["cbq"] = r.bit()
        o["cell_reselect_offset"] = r.bits(6)
        o["temporary_offset"] = r.bits(3)
        o["penalty_time"] = r.bits(5)
    if r.lh("optional_power_offset"):
        o["power_offset"] = r.bits(2)
    o["si2ter_indicator"] = r.lh()
    o["early_classmark_sending"] = r.lh()
    if r.lh("scheduling_if_and_where"):
        o["where"] = r.bits(3)
    if r.lh("gprs_indicator"):
        o["gprs_ra_colour"] = r.bits(3)
        o["si13_position"] = r.bit()
    o["3g_early_classmark_sending_restriction"] = r.lh()
    if r.lh("si2quater_indicator"):
        o["si2quater_position"] = r.bit()
    if r.lh("si21_indicator"):
        raise _Unverified("si21_indicator")


def _si13_rest(r: _Csn, o: dict[str, Any]) -> None:
    """§10.5.2.37b SI13 Rest Octets (the no-PBCCH, no-mobile-allocation form)."""
    if not r.lh("si13_contents"):
        o["si13_present"] = False
        return
    o["si13_present"] = True
    o["bcch_change_mark"] = r.bits(3)
    o["si_change_field"] = r.bits(4)
    r.absent("si13_change_mark")  # 1 -> SI13_CHANGE_MARK + GPRS Mobile Allocation
    r.absent("pbcch")             # 1 -> PBCCH Description (pre-Rel-8 only)
    o["rac"] = r.bits(8)
    o["spgc_ccch_sup"] = r.bit()
    o["priority_access_thr"] = r.bits(3)
    o["network_control_order"] = r.bits(2)
    # GPRS Cell Options (§12.24)
    co: dict[str, Any] = {
        "nmo": r.bits(2), "t3168": r.bits(3), "t3192": r.bits(3),
        "drx_timer_max": r.bits(3), "access_burst_type": r.bit(),
        "control_ack_type": r.bit(), "bs_cv_max": r.bits(4),
    }
    if r.bit("pan"):
        co["pan_dec"] = r.bits(3)
        co["pan_inc"] = r.bits(3)
        co["pan_max"] = r.bits(3)
    if r.bit("gprs_cell_options_extension"):
        ext_len = r.bits(6) + 1
        start = r.pos
        if r.bit("egprs"):
            co["egprs_supported"] = True
            co["egprs_packet_channel_request"] = r.bit()
            co["bep_period"] = r.bits(4)
        else:
            co["egprs_supported"] = False
        for name in ("pfc_feature_mode", "dtm_support",
                     "bss_paging_coordination", "ccn_active",
                     "nw_ext_utbf", "multiple_tbf_capability",
                     "ext_utbf_no_data", "dtm_enhancements_capability"):
            if r.pos - start >= ext_len:
                break
            co[name] = r.bit()
        consumed = r.pos - start
        if consumed > ext_len:
            raise _Unverified("gprs_cell_options_extension: overrun")
        r.skip(ext_len - consumed, "gprs_cell_options_extension")
    o["gprs_cell_options"] = co
    # GPRS Power Control Parameters (§12.9a)
    o["gprs_power_control"] = {
        "alpha": r.bits(4), "t_avg_w": r.bits(5), "t_avg_t": r.bits(5),
        "pc_meas_chan": r.bit(), "n_avg_i": r.bits(4),
    }
    if not r.lh("r99_additions"):
        return
    o["sgsnr"] = r.bit()
    if not r.lh("rel4_additions"):
        return
    o["si_status_ind"] = r.bit()
    if r.lh("rel6_additions"):
        raise _Unverified("rel6_additions")


def _p1_rest(r: _Csn, o: dict[str, Any]) -> None:
    """§10.5.2.23 P1 Rest Octets, up to the Packet Page Indications."""
    if r.lh("nln_pch"):
        raise _Unverified("nln_pch")
    if r.lh("priority_1"):
        o["priority_1"] = r.bits(3)
    if r.lh("priority_2"):
        o["priority_2"] = r.bits(3)
    if r.lh("group_call_information"):
        raise _Unverified("group_call_information")
    o["packet_page_indication_1"] = "gprs" if r.lh() else "rr"
    o["packet_page_indication_2"] = "gprs" if r.lh() else "rr"


# p(n) for the UTRAN FDD_CELL_INFORMATION field (TS 44.018 §9.1.54).
_FDD_CELL_INFO_BITS = (0, 10, 19, 28, 36, 44, 52, 60, 67, 74, 81, 88, 95,
                       102, 109, 116, 122)


def _si2quater_rest(r: _Csn, o: dict[str, Any]) -> None:
    """§10.5.2.33b SI2quater Rest Octets — header, 3G FDD neighbours and the
    Rel-8 Priority / E-UTRAN neighbour block."""
    o["ba_ind"] = r.bit()
    o["3g_ba_ind"] = r.bit()
    o["mp_change_mark"] = r.bit()
    o["si2quater_index"] = r.bits(4)
    o["si2quater_count"] = r.bits(4)
    for blk in ("measurement_parameters", "gprs_real_time_difference",
                "gprs_bsic", "gprs_report_priority",
                "gprs_measurement_parameters", "nc_measurement_parameters"):
        r.absent(blk)
    if r.bit("extension"):
        r.skip(r.bits(8) + 1, "extension")
    if r.bit("3g_neighbour_cell_description"):
        if r.bit("index_start_3g"):
            o["index_start_3g"] = r.bits(7)
        if r.bit("absolute_index_start_emr"):
            o["absolute_index_start_emr"] = r.bits(7)
        if r.bit("utran_fdd_description"):
            if r.bit("bandwidth_fdd"):
                o["bandwidth_fdd"] = r.bits(3)
            fdd: list[dict[str, Any]] = []
            while r.bit("repeated_utran_fdd"):
                if r.bit("fdd_arfcn_index_form"):
                    raise _Unverified("fdd_arfcn_index_form")
                uarfcn = r.bits(14)
                indic0 = r.bit()
                n_cells = r.bits(5)
                if n_cells >= len(_FDD_CELL_INFO_BITS):
                    raise _Unverified("nr_of_fdd_cells")
                r.skip(_FDD_CELL_INFO_BITS[n_cells], "fdd_cell_information")
                fdd.append({"uarfcn": uarfcn, "fdd_indic0": indic0,
                            "nr_of_fdd_cells": n_cells})
            o["utran_fdd_neighbours"] = fdd
        r.absent("utran_tdd_description")
    if r.bit("3g_measurement_parameters"):
        m: dict[str, Any] = {"qsearch_i": r.bits(4),
                             "qsearch_c_initial": r.bit()}
        if r.bit("fdd_information"):
            m["fdd_qoffset"] = r.bits(4)
            m["fdd_rep_quant"] = r.bit()
            m["fdd_multirat_reporting"] = r.bits(2)
            m["fdd_qmin"] = r.bits(3)
        r.absent("tdd_information")
        o["3g_measurement_parameters"] = m
    if r.bit("gprs_3g_measurement_parameters"):
        o["qsearch_p"] = r.bits(4)
        o["3g_search_prio"] = r.bit()
        for blk in ("gprs_3g_fdd_parameters", "gprs_3g_fdd_reporting",
                    "gprs_3g_tdd_multirat", "gprs_3g_tdd_reporting"):
            r.absent(blk)
    if not r.lh("rel5_additions"):
        return
    if r.bit("3g_additional_measurement_parameters"):
        o["fdd_qmin_offset"] = r.bits(3)
        o["fdd_rscpmin"] = r.bits(4)
    if r.bit("3g_additional_measurement_parameters_2"):
        if r.bit("fdd_reporting_threshold_2"):
            o["fdd_reporting_threshold_2"] = r.bits(6)
    if not r.lh("rel6_additions"):
        return
    o["3g_ccn_active"] = r.bit()
    if not r.lh("rel7_additions"):
        return
    r.absent("700_reporting")
    r.absent("810_reporting")
    if not r.lh("rel8_additions"):
        return
    if r.bit("priority_and_eutran_parameters"):
        _priority_and_eutran(r, o)
    r.absent("3g_csg_description")
    r.absent("eutran_csg_description")
    if r.lh("rel9_additions"):
        raise _Unverified("rel9_additions")


def _priority_and_eutran(r: _Csn, o: dict[str, Any]) -> None:
    if r.bit("serving_cell_priority_parameters"):
        o["serving_cell_priority"] = {
            "geran_priority": r.bits(3), "thresh_priority_search": r.bits(4),
            "thresh_gsm_low": r.bits(4), "h_prio": r.bits(2),
            "t_reselection": r.bits(2),
        }
    if r.bit("3g_priority_parameters"):
        p: dict[str, Any] = {"utran_start": r.bit(), "utran_stop": r.bit()}
        if r.bit("default_utran_priority_parameters"):
            p["default_utran_priority"] = r.bits(3)
            p["default_thresh_utran"] = r.bits(5)
            p["default_utran_qrxlevmin"] = r.bits(5)
        reps: list[dict[str, Any]] = []
        while r.bit("repeated_utran_priority"):
            e: dict[str, Any] = {"utran_frequency_indices": []}
            while r.bit("utran_frequency_index"):
                e["utran_frequency_indices"].append(r.bits(5))
            if r.bit("utran_priority"):
                e["utran_priority"] = r.bits(3)
            e["thresh_utran_high"] = r.bits(5)
            if r.bit("thresh_utran_low"):
                e["thresh_utran_low"] = r.bits(5)
            if r.bit("utran_qrxlevmin"):
                e["utran_qrxlevmin"] = r.bits(5)
            reps.append(e)
        p["repeated_utran_priority"] = reps
        o["3g_priority_parameters"] = p
    if not r.bit("eutran_parameters"):
        return
    eu: dict[str, Any] = {"eutran_ccn_active": r.bit(),
                          "eutran_start": r.bit(), "eutran_stop": r.bit()}
    o["eutran_parameters"] = eu
    if r.bit("eutran_measurement_parameters"):
        eu["qsearch_c_eutran_initial"] = r.bits(4)
        eu["eutran_rep_quant"] = r.bit()
        eu["eutran_multirat_reporting"] = r.bits(2)
        if not r.bit("eutran_reporting_choice"):
            raise _Unverified("eutran_reporting_threshold_form")
        r.absent("eutran_fdd_measurement_report_offset")
        r.absent("eutran_tdd_measurement_report_offset")
        eu["reporting_granularity"] = r.bit()
    if r.bit("gprs_eutran_measurement_parameters"):
        eu["qsearch_p_eutran"] = r.bits(4)
        eu["gprs_eutran_rep_quant"] = r.bit()
        eu["gprs_eutran_multirat_reporting"] = r.bits(2)
        r.absent("gprs_eutran_fdd_reporting")
        r.absent("gprs_eutran_tdd_reporting")
    groups: list[dict[str, Any]] = []
    o["eutran_neighbours"] = groups  # visible even if a later branch stops
    while r.bit("repeated_eutran_neighbour_cells"):
        g: dict[str, Any] = {"earfcns": []}
        while r.bit("eutran_neighbour_cell"):
            cell: dict[str, Any] = {"earfcn": r.bits(16)}
            if r.bit("measurement_bandwidth"):
                cell["measurement_bandwidth"] = r.bits(3)
            g["earfcns"].append(cell)
        if r.bit("eutran_priority"):
            g["eutran_priority"] = r.bits(3)
        g["thresh_eutran_high"] = r.bits(5)
        if r.bit("thresh_eutran_low"):
            g["thresh_eutran_low"] = r.bits(5)
        if r.bit("eutran_qrxlevmin"):
            g["eutran_qrxlevmin"] = r.bits(5)
        groups.append(g)
    r.absent("repeated_eutran_not_allowed_cells")
    r.absent("repeated_eutran_pcid_to_ta_mapping")


# ── Message bodies ─────────────────────────────────────────────────────────
# Each takes the IE area (octets after the message-type octet) and returns a
# dict. Out-of-bounds fixed IEs raise IndexError, which the caller turns into
# ``body_error``.

def _msg_si1(b: bytes) -> dict[str, Any]:
    return {
        "cell_channel_description": decode_frequency_list(b[0:16]),
        "rach_control": _rach_control(b[16:19]),
        "rest_octets": _run(_si1_rest, b[19:]),
    }


def _msg_si2(b: bytes) -> dict[str, Any]:
    return {
        "neighbour_cell_description": _neighbour_cell_description(b[0:16]),
        "ncc_permitted": b[16],
        "rach_control": _rach_control(b[17:20]),
    }


def _msg_si2bis(b: bytes) -> dict[str, Any]:
    return {
        "neighbour_cell_description": _neighbour_cell_description(b[0:16]),
        "rach_control": _rach_control(b[16:19]),
        "rest_octets_hex": b[19:].hex(),
    }


def _msg_si3(b: bytes) -> dict[str, Any]:
    return {
        "cell_identity": (b[0] << 8) | b[1],
        "lai": decode_lai(b[2:7]),
        "control_channel_description": _control_channel_description(b[7:10]),
        "cell_options": _cell_options_bcch(b[10]),
        "cell_selection": _cell_selection(b[11:13]),
        "rach_control": _rach_control(b[13:16]),
        "rest_octets": _run(_si3_rest, b[16:]),
    }


_IEI_CBCH_CHANNEL_DESCRIPTION = 0x64
_IEI_CBCH_MOBILE_ALLOCATION = 0x72


def _msg_si4(b: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "lai": decode_lai(b[0:5]),
        "cell_selection": _cell_selection(b[5:7]),
        "rach_control": _rach_control(b[7:10]),
    }
    pos = 10
    if pos + 4 <= len(b) and b[pos] == _IEI_CBCH_CHANNEL_DESCRIPTION:
        out["cbch_channel_description"] = _channel_description(b[pos + 1:pos + 4])
        pos += 4
        if pos + 2 <= len(b) and b[pos] == _IEI_CBCH_MOBILE_ALLOCATION:
            ln = b[pos + 1]
            out["cbch_mobile_allocation_hex"] = b[pos + 2:pos + 2 + ln].hex()
            pos += 2 + ln
    out["rest_octets_hex"] = b[pos:].hex()
    return out


def _msg_si13(b: bytes) -> dict[str, Any]:
    return {"rest_octets": _run(_si13_rest, b)}


def _msg_si2quater(b: bytes) -> dict[str, Any]:
    return {"rest_octets": _run(_si2quater_rest, b)}


_IEI_MOBILE_IDENTITY_2 = 0x17


def _msg_paging_1(b: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "page_mode": b[0] & 0x3,
        "channel_needed_1": (b[0] >> 4) & 0x3,
        "channel_needed_2": (b[0] >> 6) & 0x3,
    }
    ln = b[1]
    if 2 + ln > len(b):
        raise IndexError("mobile identity 1 overruns the block")
    ids = [_mobile_identity(b[2:2 + ln])]
    pos = 2 + ln
    if pos + 2 <= len(b) and b[pos] == _IEI_MOBILE_IDENTITY_2:
        ln2 = b[pos + 1]
        if pos + 2 + ln2 > len(b):
            raise IndexError("mobile identity 2 overruns the block")
        ids.append(_mobile_identity(b[pos + 2:pos + 2 + ln2]))
        pos += 2 + ln2
    out["mobile_identities"] = ids
    out["rest_octets"] = _run(_p1_rest, b[pos:])
    return out


_IEI_STARTING_TIME = 0x7C


def _msg_immediate_assignment(b: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "page_mode": b[0] & 0x3,
        # §10.5.2.25b Dedicated mode or TBF (high half-octet; bit 8 spare):
        # 0 = dedicated mode, 1 = uplink/two-message TBF, 3 = downlink TBF.
        "dedicated_mode_or_tbf": (b[0] >> 4) & 0x7,
        "channel_description": _channel_description(b[1:4]),
        "request_reference": _request_reference(b[4:7]),
        "timing_advance": b[7] & 0x3F,
    }
    ln = b[8]
    if 9 + ln > len(b):
        raise IndexError("mobile allocation overruns the block")
    out["mobile_allocation_hex"] = b[9:9 + ln].hex()
    pos = 9 + ln
    if pos + 3 <= len(b) and b[pos] == _IEI_STARTING_TIME:
        out["starting_time"] = {"t1_prime": (b[pos + 1] >> 3) & 0x1F,
                                "t3": ((b[pos + 1] & 0x7) << 3) | (b[pos + 2] >> 5),
                                "t2": b[pos + 2] & 0x1F}
        pos += 3
    out["rest_octets_hex"] = b[pos:].hex()
    return out


_BODY_DECODERS = {
    RR_MSG_SI1: _msg_si1,
    RR_MSG_SI2: _msg_si2,
    RR_MSG_SI2BIS: _msg_si2bis,
    RR_MSG_SI3: _msg_si3,
    RR_MSG_SI4: _msg_si4,
    RR_MSG_SI13: _msg_si13,
    RR_MSG_SI2QUATER: _msg_si2quater,
    RR_MSG_PAGING_REQUEST_1: _msg_paging_1,
    RR_MSG_IMMEDIATE_ASSIGNMENT: _msg_immediate_assignment,
}


def decode_ccch_block(block: bytes) -> dict[str, Any] | None:
    """Decode one downlink BCCH/CCCH L3 block that starts with the L2 pseudo
    length octet (§10.5.2.19). Returns ``None`` if it is not an RR message.

    Keys: ``l2_pseudo_length``, ``skip_indicator``, ``protocol_discriminator``,
    ``message_type``, ``message_name``, ``body`` (per-message dict, or None for
    a type this module does not decode) and ``body_error`` (set when a fixed IE
    overruns the block).
    """
    if len(block) < 3:
        return None
    if block[0] & 0x3 != 0x1:  # L2 pseudo length: bits 2-1 are always '01'
        return None
    pd = block[1] & 0xF
    if pd != PD_RR:
        return None
    mt = block[2]
    out: dict[str, Any] = {
        "l2_pseudo_length": block[0] >> 2,
        "skip_indicator": block[1] >> 4,
        "protocol_discriminator": pd,
        "message_type": mt,
        "message_name": RR_MESSAGE_NAMES.get(mt, f"rr_0x{mt:02X}"),
        "body": None,
        "body_error": None,
    }
    fn = _BODY_DECODERS.get(mt)
    if fn is not None:
        try:
            out["body"] = fn(bytes(block[3:]))
        except IndexError as e:
            out["body_error"] = f"truncated: {e}"
    return out
