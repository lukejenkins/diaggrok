"""0xB826 — NR5G RRC Supported CA Combos: paginated band-combination table.

Layout
------

0xB826 is not a UPER-packed UE-capability blob. It is the modem's internal RF
band-combination table, dumped as a **paginated array of C structs**, up to
100 combos per record:

    [0]     u8   version            0x07 SDX55/SDX50 · 0x09 Inseego M3100 · 0x0d SDX6x · 0x11 T99W640
    [1:4]   u24  reserved           0x000000 on every record
    [4:6]   u16  total_combos       size of the whole table
    [6:8]   u16  start_index        index of this page's first combo (0,100,200…)
    [8:10]  u16  num_combos         combos in this page (100, or the remainder)
    [10]    u8   table_kind         raw (see below)
    [11:]        num_combos × combo, then (v0x0d/v0x11) a num_combos-byte trailer

Per-version combo struct (each found by exact-closure brute force, then checked
for content):

    version  combo head  band count            entry  band field
    v0x11    29 B        (head[3] >> 3) & 0xF  9 B    u8  entry[0]
    v0x0d    13 B        (head[3] >> 3) & 0xF  8 B    u8  entry[0]
    v0x09    13 B        (head[3] >> 3) & 0xF  8 B    u8  entry[0]   (no trailer)
    v0x07     4 B        (head[0] >> 1) & 0xF  10 B   u16 entry[0:2] (n257–n261 > 255)

v0x0d / v0x11 band entry flags (entry[1], entry[2]):

    entry[1] bit 1      RAT (1 = NR, 0 = LTE)
    entry[1] bits 2-6   DL bandwidth class (1 = A, 2 = B, 3 = C, 4 = D, 5 = E)
    entry[2] bit 6      UL configured on this carrier
    everything else     exposed raw (``entry_raw``), not named

v0x07 band entries carry the band only; their RAT/class/UL bits use a different
encoding that is not resolved, so the entry is exposed raw (``rat`` /
``dl_bw_class`` / ``ul`` are None).

v0x09 (Inseego M3100): v0x0d's combo struct
without the trailer. Exact closure on 337/337 combos over the 4 distinct pages
(a 273-combo EN-DC table in 3 pages + a 64-combo NR-only table; the pair is
re-emitted byte-identically), pages summing to total_combos. head[3] bit 2 is 0
on all 337, which is what lets the degenerate (>>2, 4 B entry) twin also close;
it starts entries on non-band bytes (0x88), so the 8 B reading stands. Reading
entry[1]/entry[2] with the v0x0d flags gives one LTE UL + one NR UL on 273/273
EN-DC combos, but also "NR n4" / "NR n1" and DL-class codes 7/8/9/13, and
218/1201 entries have entry[1] bit 0 set (0x07/0x1f/0x23/0x27/0x37) with
high-entropy bytes after it. The v0x0d flag reading is therefore not adopted:
like v0x07, v0x09 exposes band = entry[0] and keeps the entry raw.

Grounding (no F3 / 0x60 in the v0x11 capture; see F3-VERDICT below):

* **Page closure.** Every table's pages close: T99W640 2800+14 = 2814 and
  2000+42 = 2042; RM520N-GL 100+94 = 194; RXM-G1 1300+44 = 1344.
* **Segment closure.** The per-version struct walk lands exactly on the end of
  the combos (plus the num_combos-byte trailer) on 55/55 v0x11, 111/111 v0x0d and
  30/30 v0x07 records. On v0x11, combo-head bytes [7:9] and [11:13] are ``24 8e``
  on 5356/5356 combos.
* **3GPP structure (v0x11 and v0x0d).** table_kind 3: 2814/2814 (v0x11) and
  1658/1658 (v0x0d) combos mix LTE and NR with exactly one LTE UL + one NR UL,
  the EN-DC rule. table_kind 4: every entry is NR (NR-CA), with 1–2 NR ULs. The
  NR-only bands n77/n78/n79/n91–n94 are never LTE-flagged. Class C/D/E appears
  only on bands that define them (LTE C on 1/2/3/7/40/41/42/46/48/66, D/E only on
  41/42/46/48; NR C only on n41/n48/n77/n78/n79), and narrow bands are A only.
* **Modem's own band list (v0x11).** The NR-flagged band set is a subset of the
  T99W640's QMI ``NR5G NSA band preference`` (all but n76), and the LTE-flagged
  set is a subset of its QMI LTE band list.

* **Whole corpus (57 captures).** Every accepted record segments exactly
  (0 left raw, 0 invariant violations): RM520N-GL, EM9291, T99W373, RXM-G1,
  RM500Q-AE, LV55, T99W175, T99W640, and the Inseego M2000. The M2000's two
  263/1063 B v0x07 records, which look like DLF misframing at first sight,
  close as complete single-page 28- and 18-combo tables. EN-DC table_kind 3: 242,198 of 242,228
  combos have one LTE UL + one NR UL. The 30 exceptions all come from one
  T99W373 firmware build. Each has an NR n1/n2 entry with
  class field 5 and no UL, so on that entry the class bits probably carry
  something else (unresolved; such an entry reports ``dl_bw_class`` "E").
  The Inseego M3100's **v0x09** (8 records) is admitted; see the v0x09
  section above and its F3-VERDICT below.

table_kind is exposed raw. Observed: 3 = EN-DC table, 4 = NR-CA table (v0x0d,
v0x11); 1 = a small mixed table on RM520N-GL (194 EN-DC + 45 NR-only combos);
5 = an NR-only table with 2 NR ULs (282 combos, v0x0d); 0 on v0x07. The combo-head bytes beyond the band count are exposed raw.

F3-VERDICT 0xB826 v0x11: F3 N/A. The only v0x11 capture (a T99W640 bring-up)
carries 0 F3 frames (0x79/0x99 top-level or 0x98-wrapped) and 0 ``0x60``
events. QCSuper and SCAT are silent (SCAT 0 mentions; QCSuper NAS-only). The decode is grounded by closure,
3GPP structure and the modem's QMI band list, as above.

F3-VERDICT 0xB826 v0x09: F3 SILENT. The only v0x09 capture (an M3100, 8
records = 4 pages emitted twice, 4.98 s apart, each burst 0.45 ms) carries
189,790 F3 frames (100% resolved) across -101 s..+101 s, and none labels the
table:

* The UE-capability sites that ground v0x07 are present, but 91 s after the
  second burst, at RRC CONNECTING -> CONNECTED: ``lte_misc.c:316/323/331``
  "RRC CAP: ... ue_cat=16" and ``LTE_RRC_CAPABILITIES_SM`` (INITIAL only, no
  capability enquiry). v0x09 is not emitted by a capability enquiry.
* An F3 file census of +-3 s around both bursts against a matched 6 s baseline
  finds no capability, band or combo print. The files seen only near the bursts
  are XO field cal, antenna tuner, ``rr_multi_sim`` counters and an Inseego
  ``qmi_nvtl`` ``GET_NR5G_SYS_INFO`` request at +6.16 s, which also fires at
  -89.9 s and +76.2 s with no 0xB826 near it.
* No capability-plane LOG code co-emits within +-200 ms (only the periodic LTE
  ML1/MAC codes). ``0x60`` is absent (outer opcodes 0x10/0x79/0x98/0x99/0x9D).
  QCSuper and SCAT produce no 0xB826 output.

The decode stands on exact page and segment closure (above). Band sets per
table: the 64-combo table uses {2, 5, 48, 66, 77, 78}, all defined NR bands; the
273-combo table adds {1, 3, 4, 7, 13, 46}. There is no M3100 band list on file
to check these against (no QMI or AT band dump for this build).

F3-VERDICT 0xB826 v0x0d: CO-EMIT (RF-driver scouting plane)
-----------------------------------------------------------

On an RM520N-GL NR capture (111 × 0xB826 v0x0d, F3 100% resolved), the
RF-driver active-scouting prints that name the CA-combo fields fire inside the
0xB826 emission window (both are products of the same NR capability-scouting
activity):

    rfm_scouting_data.c:1917  rfm_scouting_get_nr_combo_band_info: idx N carrier
        mask dl 0x.. ul 0x.. band N dl_bw_class N ul_bw_class N @@@
        ul_bw_per_cc N dl_bw_per_cc N            (×14)
    rfm_scouting_data.c:1932  … start idx 0 nr_combo_size 2 rf_combo_size 2 (×7)
    rfm_scouting_data.c:2794  rfm_scouting_get_nr5g_tx_mimo_mask: nr_band:N,
        mimo_chain_mask_nr5g[..], nr5g_sub_band[..], nr_ant_switch_path[..] (×3)

These label field semantics (band / DL and UL bandwidth class / MIMO) and give
active-combo values for cross-checks; they are not a byte-offset map. QCSuper
emits a header-only pcap for this code and SCAT does not translate it.

F3-VERDICT 0xB826 v0x07: CO-EMIT (RRC-capability plane)
-------------------------------------------------------

v0x07 is a real, deterministic report on SDX55/SDX50 silicon: the RXM-G1 emits
30 records at 15 coherent sizes (179–6881 B) ×2, byte-identical across five
independent UE-capability captures; it is also coherent on RM500Q-AE (18
records) and LV55/T99W175. A triggered UE-capability dump is driven by the
RRC-capability subsystem rather than RF scouting, so the RF-scouting prints
above do not fire (also absent on LV55 and T99W175 F3 captures). On the RXM-G1
UE-capability F3 capture (128,921 F3, 100% resolved), the RRC-capability plane
is co-temporal with the 30 v0x07 records:

    lte_rrc_cap_debug.c:813  CAP: LTE Band N/M:[ 2 4 12 66 ]   (inside the
        window — the EUTRA band-capability list; EUTRA bands feed the EN-DC
        combos 0xB826 carries)
    lte_rrc_stm.c:866        LTE_RRC_CAPABILITIES_SM state machine (×63, brackets)
    lte_misc.c:316/323/331   RRC CAP: ue_cat=16 (UE category)
    nr5g_misc.c:320          RRC CAP: use computed ue_cat (NR side, 44 ms prior)
    rfe_nr5g_txpl.c:387/585  nr_band 41 (NR band capability)

As for v0x0d, this is subsystem-attributed co-emission that labels field
semantics, not a byte map. QCSuper emits a header-only pcap and SCAT emits
GSMTAP only for adjacent RRC/NAS OTA codes, not for 0xB826.

Log name: NR5G RRC Supported CA Combos
Also known as: LOG_NR5G_RRC_SUPPORTED_CA_COMBOS
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

#: Per-version combo struct: (band-count byte offset in the combo head, its
#: shift, combo-head length, band-entry length, band-field width). See docstring.
_LAYOUTS: dict[int, tuple[int, int, int, int, int]] = {
    0x07: (0, 1, 4, 10, 2),
    0x09: (3, 3, 13, 8, 1),
    0x0d: (3, 3, 13, 8, 1),
    0x11: (3, 3, 29, 9, 1),
}
#: Versions that carry a num_combos-byte trailer after the combos.
_TRAILER = frozenset({0x0d, 0x11})
#: Versions whose entry[1]/entry[2] flags (RAT, DL class, UL) are grounded.
_FLAGS = frozenset({0x0d, 0x11})
_HDR = 11
_BW_CLASS = "?ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _band_entry(version: int, e: bytes, band_width: int) -> dict[str, Any]:
    band = unpack_from('<H', e, 0)[0] if band_width == 2 else e[0]
    if version in _FLAGS:
        cls = (e[1] >> 2) & 0x1F
        return {
            "band": band,
            "rat": "NR" if e[1] & 0x02 else "LTE",
            "dl_bw_class": _BW_CLASS[cls] if 0 < cls < len(_BW_CLASS) else None,
            "ul": bool(e[2] & 0x40),
            "entry_raw": e,
        }
    return {"band": band, "rat": None, "dl_bw_class": None, "ul": None, "entry_raw": e}


#: Sentinel: the payload ends before the header-declared structure does.
_SHORT = "short"


def _walk(version: int, data: bytes, n: int) -> tuple[list[dict[str, Any]], bytes] | str | None:
    """Segment ``n`` combos.

    Returns ``(combos, trailer)`` when the walk closes exactly on the record,
    ``_SHORT`` when the payload ends before the ``n`` declared combos (+ the
    n-byte trailer, where the version carries one) are complete, and None when
    the walk completes but leaves unexplained extra bytes.
    """
    kpos, shift, head_len, entry_len, band_width = _LAYOUTS[version]
    off, combos = _HDR, []
    for _ in range(n):
        if off + head_len > len(data):
            return _SHORT
        k = (data[off + kpos] >> shift) & 0xF
        end = off + head_len + entry_len * k
        if end > len(data):
            return _SHORT
        bands = [
            _band_entry(version, data[p:p + entry_len], band_width)
            for p in range(off + head_len, end, entry_len)
        ]
        combos.append({"num_bands": k, "head_raw": data[off:off + head_len], "bands": bands})
        off = end
    trailer = data[off:]
    want = n if version in _TRAILER else 0
    if len(trailer) < want:
        return _SHORT
    if len(trailer) != want:
        return None
    return combos, trailer


@dataclass
class Diag0xB826:
    """0xB826 — NR5G RRC Supported CA Combos, one page of the combo table."""
    log_time: int
    version: int
    payload_size: int
    total_combos: int | None
    start_index: int | None
    num_combos: int | None
    table_kind: int | None
    layout_ok: bool
    combos: list[dict[str, Any]] | None
    trailer_raw: bytes
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB826",
            "log_time": self.log_time,
            "version": self.version,
            "payload_size": self.payload_size,
            "total_combos": self.total_combos,
            "start_index": self.start_index,
            "num_combos": self.num_combos,
            "table_kind": self.table_kind,
            "layout_ok": self.layout_ok,
            "combos": self.combos,
            "trailer_raw": self.trailer_raw,
            "body_raw": self.body_raw,
        }


@register(
    0xB826,
    name="0xB826",
    description="0xB826 — NR5G RRC Supported CA Combos: paginated band-combination table (v0x07 SDX55/SDX50, v0x09 Inseego M3100, v0x0d SDX6x, v0x11 T99W640)",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room reverse engineering: exact-closure struct walk per version, checked against 3GPP EN-DC/NR-CA rules and the modems' QMI band lists. "
    "Every accepted record over 57 captures segments exactly (0 invariant violations); pages sum to total_combos. "
    "v0x0d/v0x11 entry flags (RAT, DL bandwidth class, UL) grounded by the EN-DC one-LTE-UL + one-NR-UL rule and per-band class limits. "
    "v0x09 (Inseego M3100): v0x0d's 13 B head + 8 B entries, no trailer; exact closure 337/337 combos (273-combo EN-DC table in 3 pages + 64-combo NR table); "
    "entry flags are not the v0x0d encoding (218/1201 entries with entry[1] bit0 set; 'n4'/'n1' under the v0x0d reading), so band only, rest raw. "
    "v0x07 band entries are u16 with flags left raw. "
    "F3 co-emits on the RF-scouting plane (v0x0d) and the RRC-capability plane (v0x07); it is absent on v0x11 and silent on v0x09. "
    "Truncated payloads (header < 11 B, or num_combos combos + trailer overrunning the record) return None (registry WARN); extra trailing bytes yield layout_ok=False.",
    issues=(),
    fields_identified=12,
    fields_parsed=12,
    field_invariants={"version": {"enum": [0x07, 0x09, 0x0d, 0x11]}},
)
def parse_0xb826(log_time: int, data: bytes) -> Diag0xB826 | None:
    if len(data) < 1 or data[0] not in _LAYOUTS:
        return None
    version = data[0]
    if len(data) < _HDR:
        return None  # truncated header: registry WARN, not a hollow record
    total, start, n = unpack_from('<HHH', data, 4)
    kind = data[10]
    walked = _walk(version, data, n)
    if walked == _SHORT:
        return None  # num_combos overruns the payload (truncated): registry WARN
    combos, trailer = walked if walked is not None else (None, b"")
    return Diag0xB826(
        log_time=log_time,
        version=version,
        payload_size=len(data),
        total_combos=total,
        start_index=start,
        num_combos=n,
        table_kind=kind,
        layout_ok=walked is not None,
        combos=combos,
        trailer_raw=trailer,
        body_raw=data[1:],
    )
