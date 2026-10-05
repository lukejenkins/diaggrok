"""0x1C6C — injected-event XML trace, multi-subsystem (legacy `Code1C6C`).

A **text/XML event decode**: the record carries no binary struct beyond a
zero prefix.

Record layout
-------------
Every record is::

    off 0   u32  prefix      always 0x00000000 (corpus-invariant)
    off 4   ...  ASCII text  a fragment of an injected diag event

The text is call-flow markup that modem tasks emit as a *stream* of 0x1C6C
records — one open tag, then one or more field lines, then a close tag — each
as its own record::

    record 1:  <event type="inject" mod="CM" cmd="SS" sub="0">\\n<arg name="event" value="1" />\\n
    record k:  <arg name="cell_tac" value="0" />\\n<arg name="cell_id" value="0" />\\n ...
    record n:  </event>\\n

**Not just Call-Manager / serving-system.** A full-corpus index (144K records /
98 captures) shows 0x1C6C is a multi-subsystem injected-event stream. The
emitting process is the open tag's `mod` attribute — observed: `CM`, `CM_SYS`,
`DS`, `DS_SYS`, `LTE`, `MSGR`, `QMI`, `UIM`, `ISIM`, `WMS`, `CMIAPP`, `DSNET`,
`NAS` — with 100+ distinct `(mod, cmd, sub)` event types.

Grammar (full vs terse dialect, inject vs expect category):

* **open**   — full `<event type="inject"|"expect" mod=.. cmd=.. sub=..>`;
               terse `<in ...>` (inject) / `<ex ...>` (expect). Carries the
               event identity `(mod, cmd, sub)` and the inject/expect category.
* **arg**    — input fields: `<arg name=.. value=.. />` / terse `<arg n=.. v=.. />`.
* **rv/rp**  — return value / return param inside a `<res>` block (the reply).
* **info**   — standalone metadata (`operatorMode`, `userAgent`, ...).
* **close**  — `</event>` / `</in>` / `</ex>`.

Two vendor dialects, semantics identical: **full** (`<event>`/`name=`/`value=`)
on fn980m (Telit), rm520ngl (Quectel SDX62), em9291 (Sierra), ...; **terse**
(`<in>`/`<ex>`/`n=`/`v=`) on lv55 (Wistron SDX55) and survey captures. An older
name table lists 0x1C6C as `RESERVED`.

Recognition + decode contract
-----------------------------
Layer-1 gate (version-byte-first): byte[0] must be 0x00 (the LSB of the zero
prefix); combined with the full 4-byte zero prefix + a leading `<` (after
optional ASCII whitespace) this is a strong fingerprint a foreign same-length
payload cannot meet. The whitespace tolerance is load-bearing: some terse
records start with a newline after the prefix (`byte[4]==0x0a` then `<res>`),
and a strict `data[4]=='<'` gate would drop that whole dialect. The parser
surfaces:

* `prefix`   — the u32 (always 0; preserved as ground truth, not assumed),
* `text`     — the decoded ASCII body verbatim (lossless latin-1),
* `event`    — attributes of an opening `<event>`/`<in>`/`<ex>` tag (dict),
* `category` — `"inject"` | `"expect"` | `""` (no open tag in this fragment),
* `args`     — `(name, value)` pairs from `<arg .../>` (dialect-normalized),
* `returns`  — `(name, value)` pairs from `<rv>`/`<rp>` response fields,
* `info`     — `(name, value)` pairs from `<info>` metadata fields,
* `arrays`   — indexed `<arg ... index="N"/>` elements regrouped by name,
* `plmns`    — every 3-octet `*plmn_id` array decoded as "MCC-MNC".

Cross-generation: SDX55 (rm500q/sim8202/lv55/em9190/fn980), SDX62 (em9291/
rm520ngl), MDM (inseego m2000) — same prefix+text shape. Every byte of the
record is decoded (prefix + text), with no `raw` field; the per-arg *value*
semantics are grounded only for the args listed below.

WiGLE field population
----------------------
A tally of the actual *values* of the WiGLE-relevant args across **118,317
records / 90 captures** shows the corpus carries populated serving-cell data,
but the picture is field-specific:

* **Signal is populated and real.** `irsrp` / `irsrq` (on
  **CM_SYS/SS_INFO_GENERIC/0**, not CM/SS/0) are non-zero in **1,646 / 3,806**
  occurrences, in valid cellular ranges — RSRP −106..−117 dBm, RSRQ −13..−20
  dB.
* **`cell_tac` carries real TACs** (e.g. 11544, 39178, 3328) — 315/6017
  non-zero.
* **`cell_id` and `cell_plmn` are flag-like, not WiGLE-usable identity.**
  `cell_id` only ever takes {0,1,2,4} and `cell_plmn` {0,1,-1,4} — far too
  small to be a real CID (≤268M) or PLMN (MCC/MNC) — so in this corpus these
  args behave as change/sub-indices, not the serving-cell identity tuple.
* **`gwl_irsrp` / `gwl_irsrq` are dead** (0 / 3806 non-zero): the live signal
  is on the bare `irsrp`/`irsrq` GW-LTE fields, not the `gwl_*` variants.

F3 grounding: subsystem and signal
----------------------------------
On RM520N-GL captures with fully resolved F3, two co-temporal oracles ground
the record against the firmware's own prints:

* **Subsystem — this is the CM Serving-System event stream.** The 0x1C6C
  `CM`/`CM_SYS` `SS`/`SS_INFO_GENERIC` opens fire co-temporally with the
  firmware's own CM-SS event callbacks: `ds_rmnet_meta_sm.c:8467`
  *"Processing CM SS event (0), changed_fields=… sub_id 0"* (Δ≈2 µs),
  `mmgsdi_ss_event.c:1129` *"CM SS Event, stack:… PLMN: 0x130062, Service
  Status:… Sys Mode: 0xc"*, and `tm_cm_ss_event_cb`. The "CM injected serving-
  system event" framing is F3-grounded, not inferred from tag text alone.
* **Signal — `irsrp`/`irsrq` are the LTE serving RSRP/RSRQ in dBm.** On a
  CBRS LTE capture 0x1C6C `CM_SYS/SS_INFO_GENERIC/0` reports
  `irsrp=-94, irsrq=-7`; the co-temporal F3 (Δ≈15 µs, ~0.01 % of the 157 ms
  inter-event spacing) serving RSRP is `quectel_led_modem.c:433 …rsrp = -90`,
  `quectel_signal.c:132 rsrp=…-90.7` (X/10), and the modem's own
  `+QENG:"servingcell","…","LTE",…,-90,-6,…` (RSRP −90, RSRQ −6). RAT (LTE),
  units (dBm), sign and magnitude all match; the ~4 dB / 1 dB gap is a filter/
  sample-source offset between the CM-SS event value and the LED/QENG value,
  not a scale error. `irsrp` in NR5G-SA captures is idle-zero — consistent
  (no GW-LTE serving cell), *not* a defect.

`cell_tac` is not the serving TAC under NR. On an NR5G-SA capture,
`CM_SYS/SS_INFO_GENERIC/0` carries `cell_tac=11544` (0x2D18) on all 17 opens,
but the co-temporal **serving** TAC in F3 is `0x2D6600` (2975232) —
`quectel_eng_atc.c:800 'TAC: 2D6600'`, `qpDplGetTAC: TAC=2975232`,
`+QENG:"servingcell","NR5G-SA",…,2D6600,…`. 11544 appears nowhere as a TAC in
that capture's 1.65 M F3 frames. The value is a real-magnitude TAC (39178 is
an F3-verified AT&T TAC), but under NR it is the stale LTE TAC, not the
co-temporal serving-cell TAC.

Serving identity: sys_plmn_id
-----------------------------
The serving PLMN is not `cell_tac` / `cell_plmn` but the **indexed array**
`sys_plmn_id[0..2]` (`<arg name="sys_plmn_id" value=".." index="N"/>`), gated
by `sys_id_type=1`. Its three values are the TS 24.008 §10.5.1.3 BCD octets:
19,0,98 → `13 00 62` → **310-260**. That is the same packed value F3 prints as
`mmgsdi_ss_event.c … PLMN: 0x130062`. The parser regroups indexed args into
`arrays` and decodes every 3-octet `*plmn_id` array into `plmns`.

Validation (whole corpus, plus every capture with an AT sidecar; spliced
captures excluded):

* **Decode health:** 707,649 / 707,649 records, 416 captures, 0 rejects.
* **`sys_plmn_id` → MCC-MNC, time-paired ±5 s** against the capture's own
  `+QENG` / `!LTEINFO` / `+CPSI` serving cell: **265/265 match, 0 miss**
  (239 with LTE serving, 26 with NR5G-SA serving). Three PLMNs (310-260,
  310-410, 311-480), including 3-digit MNCs. Per-capture set membership:
  591/600 across 22 captures. The 9 misses all come from one EM9291 capture
  whose AT poll reports only LTE PLMNs while the events are `sys_mode` 0/12.
  That is unresolved (ground truth incomplete), not counted as a pass.
* **In-capture F3 oracle:** `mmgsdi_ss_event.c` `CM SS Event … PLMN: 0x…`
  (same DIAG tick base, no clock offset) vs the nearest `sys_plmn_id` event:
  **52/52 consistent** across 9 capture-level checks on 4 modems / 3 vendors:
  RM520N-GL 20 (incl. 17/17 on the NR5G-SA capture), T99W373 23/23, T99W640
  4/4, M3100 4/4 (311-480). The one apparent miss is F3 `PLMN: 0x0, Sys id
  type: 0x0` (no service) ↔ the all-zero array, which is deliberately left
  undecoded. No EM9291 prints at this site in the 2 F3-armed EM9291 captures
  checked.
* **Scope: SDX62-class only.** AT ground truth exists on RM520N-GL (Quectel)
  and EM9291 (Sierra). `CM_SYS/SS_INFO_GENERIC` is never emitted on SDX55
  (LV55, FN980, RM500Q, SIM8202, EM9190, T99W175: zero events corpus-wide). On
  T99W373, T99W640 and M3100 (no AT ground truth) the arrays decode to
  310-260 / 310-410 / 311-480, all valid carrier PLMNs, and agree with the F3
  oracle above.
* **`irsrp` / `irsrq` = LTE serving RSRP/RSRQ (dBm):** 1,312 readings
  time-paired across 10 captures. Median |ΔRSRP| 1.5 dB (80 % ≤ 3 dB);
  median |ΔRSRQ| 2 dB. The >10 dB tail (5 %) is mostly cell-edge readings
  where the AT RSRQ sits at its −20 dB floor.
* **`cell_tac` = LTE serving TAC — CANDIDATE.** 239/239 time-paired matches
  when the AT serving RAT is LTE. When serving is NR it holds the stale LTE
  TAC (it never equals the NR TAC), which explains the NR5G-SA mismatch above.
  Only 2 distinct TACs are paired (3328, 39178), below the 5-value bar, so no
  claim beyond CANDIDATE.
* **`tac_5g` — not established.** 93 of 203 ground-truth-bearing events read
  as the first two NR-TAC octets, little-endian (269 ↔ `0D0100`,
  26157 ↔ `2D6600`). The other 110 are small integers or negatives. Kept raw.
* `cell_id` / `cell_plmn` stay flag-like. `CM/SS sys_id` (e.g. 6422547 =
  `0x620013`, a little-endian u24 of a PLMN) has no ground truth in 52
  events; kept raw.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# A u32 zero prefix then (after optional whitespace) a '<' — the corpus
# fingerprint. Some terse records begin with a newline after the prefix
# (byte[4]==0x0a then '<res>'), so the '<' is not always at a fixed offset.
_PREFIX = b"\x00\x00\x00\x00"

# key="value" attribute pairs (single tag's inner text).
_ATTR_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
# field-bearing elements: <arg> = input; <rv>/<rp> = return value/param (inside
# a <res> response block); <info> = standalone metadata. Terse `n`/`v` or full
# `name`/`value` attrs. All are part of the self-documenting field vocabulary.
_ARG_RE = re.compile(r"<arg\b([^>]*?)/?>")
_RET_RE = re.compile(r"<(?:rv|rp)\b([^>]*?)/?>")
_INFO_RE = re.compile(r"<info\b([^>]*?)/?>")
# an opening event element. Full: <event type="inject"|"expect" ...>; terse:
# <in ...> (inject) / <ex ...> (expect). All carry mod/cmd/sub.
_OPEN_RE = re.compile(r"<(event|in|ex)\b([^>]*?)/?>")
# inject/expect category for terse opens (full opens carry it in type=).
_TERSE_CATEGORY = {"in": "inject", "ex": "expect"}
# A C array is serialized one element per <arg>, each carrying index="N"
# (e.g. sys_plmn_id[0..2], gw_plmn_id[0..2]).
_PLMN_ARRAY_SUFFIX = "plmn_id"


@dataclass
class Diag0x1C6C:
    """0x1C6C — CM injected XML diag event fragment (legacy `Code1C6C`)."""
    log_time: int
    version: int
    prefix: int
    text: str
    event: dict[str, str]
    category: str  # "inject" | "expect" | "" (no open tag in this fragment)
    args: list[tuple[str, str]]
    returns: list[tuple[str, str]]  # <rv>/<rp> response fields
    info: list[tuple[str, str]]     # <info> standalone metadata fields
    payload_size: int
    # Indexed <arg index="N"> elements regrouped as arrays, and
    # every 3-octet *plmn_id array decoded as TS 24.008 BCD "MCC-MNC".
    arrays: dict[str, list[str]] = field(default_factory=dict)
    plmns: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1C6C",
            "log_time": self.log_time,
            "version": self.version,
            "prefix": self.prefix,
            "text": self.text,
            "event": self.event,
            "category": self.category,
            "args": [{"name": n, "value": v} for n, v in self.args],
            "returns": [{"name": n, "value": v} for n, v in self.returns],
            "info": [{"name": n, "value": v} for n, v in self.info],
            "payload_size": self.payload_size,
            "arrays": {k: list(v) for k, v in self.arrays.items()},
            "plmns": dict(self.plmns),
        }


def _parse_open(text: str) -> tuple[dict[str, str], str]:
    """Return (event-attr dict, inject/expect category) for the opening tag, or
    ({}, "") when this fragment has no open tag (a pure arg/return/close line)."""
    m = _OPEN_RE.search(text)
    if not m:
        return {}, ""
    tag = m.group(1)
    attrs = dict(_ATTR_RE.findall(m.group(2)))
    category = attrs.get("type", _TERSE_CATEGORY.get(tag, ""))
    return attrs, category


def _pairs(regex: re.Pattern[str], text: str) -> list[tuple[str, str]]:
    """Normalize `<x name=.. value=.. />` and terse `<x n=.. v=.. />` to (n, v)."""
    out: list[tuple[str, str]] = []
    for inner in regex.findall(text):
        attrs = dict(_ATTR_RE.findall(inner))
        out.append((attrs.get("name", attrs.get("n", "")),
                    attrs.get("value", attrs.get("v", ""))))
    return out


def _arrays(text: str) -> dict[str, list[str]]:
    """Regroup indexed `<arg ... index="N"/>` elements into name -> [values]
    ordered by index. Only args that carry an `index` attribute are arrays."""
    acc: dict[str, dict[int, str]] = {}
    for inner in _ARG_RE.findall(text):
        attrs = dict(_ATTR_RE.findall(inner))
        idx = attrs.get("index")
        if idx is None or not idx.isdigit():
            continue
        name = attrs.get("name", attrs.get("n", ""))
        acc.setdefault(name, {})[int(idx)] = attrs.get("value", attrs.get("v", ""))
    return {n: [d[i] for i in sorted(d)] for n, d in acc.items()}


def decode_plmn_octets(octets: list[int]) -> str | None:
    """3GPP TS 24.008 §10.5.1.3 PLMN BCD -> "MCC-MNC", or None if unset/invalid.

    oct1 = MCC2|MCC1, oct2 = MNC3|MCC3, oct3 = MNC2|MNC1 (MNC3 == 0xF for a
    two-digit MNC). All-zero octets (MCC "000") are the "no PLMN" fill.
    """
    if len(octets) != 3 or any(not 0 <= o <= 0xFF for o in octets):
        return None
    o1, o2, o3 = octets
    mcc = (o1 & 0xF, o1 >> 4, o2 & 0xF)
    mnc3, mnc1, mnc2 = o2 >> 4, o3 & 0xF, o3 >> 4
    if any(d > 9 for d in (*mcc, mnc1, mnc2)) or (mnc3 > 9 and mnc3 != 0xF):
        return None
    if mcc == (0, 0, 0):
        return None
    mnc = f"{mnc1}{mnc2}" + ("" if mnc3 == 0xF else str(mnc3))
    return "".join(map(str, mcc)) + "-" + mnc


def _plmns(arrays: dict[str, list[str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, vals in arrays.items():
        if not name.endswith(_PLMN_ARRAY_SUFFIX) or len(vals) != 3:
            continue
        try:
            plmn = decode_plmn_octets([int(v, 0) for v in vals])
        except ValueError:
            continue
        if plmn is not None:
            out[name] = plmn
    return out


# ── Ground-truth recipe — WiGLE-direct (identity + signal) ───────────────────
# 0x1C6C is a multi-subsystem injected-event XML stream; the WiGLE-bearing
# records are the Call-Manager serving-system events (mod=CM/CM_SYS, cmd=SS),
# whose <arg> fields carry cell_tac + RSRP/RSRQ (cell_tac/irsrp/irsrq are
# populated in the corpus, while cell_id / cell_plmn are flag-like {0,1,2,4} —
# not real CID/PLMN here). Target = the
# RM520N-GL (SDX62, full <event>/name=/value= dialect, single version 0x00).
# Ground the event-arg values against the Quectel LTE serving-cell AT commands.

@register(
    0x1C6C,
    name="0x1C6C",
    description="0x1C6C — injected-event XML trace (multi-subsystem), text decode",
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Reverse-engineered from corpus bytes (144K records / 98 captures): "
        "u32 zero prefix + ASCII XML fragment of an injected diag event. "
        "Decodes the text body across terse (<in>/n=/v=) and full "
        "(<event>/name=/value=) dialects; the stream is multi-subsystem "
        "(CM/CM_SYS/DS/DS_SYS/LTE/MSGR/QMI/UIM/ISIM/WMS/CMIAPP/DSNET/NAS), "
        "with inject/expect categories (full type=, terse <in>/<ex>), "
        "<rv>/<rp> response fields, <info> metadata, and a whitespace-tolerant "
        "'<' gate that accepts terse <res>/<rv> records (byte[4]==0x0a). "
        "Indexed *plmn_id arrays decode to MCC-MNC (sys_plmn_id 265/265 vs AT "
        "serving PLMN, 52/52 vs F3, SDX62-class); irsrp/irsrq are F3- and "
        "AT-grounded LTE serving RSRP/RSRQ. Cross-vendor/cross-gen: lv55 SDX55, "
        "rm500q/sim8202 SDX55, em9291/rm520ngl SDX62, fn980m Telit, em9190, "
        "inseego m2000. Open: cell_tac (CANDIDATE), tac_5g and sys_id kept raw."
    ),
    source_url="",
    ascii_kinds=("xml-event",),
    issues=(),
    primary_issue=None,  # canonical primary tracker
    fields_identified=9,
    fields_parsed=9,
    # WiGLE: the CM serving-system events carry WiGLE-required fields. Two
    # distinct event types:
    #   * CM/SS/0 (1,897 opens): identity only — cell_plmn, cell_tac, cell_id.
    #   * CM_SYS/SS_INFO_GENERIC/0 (5,434 opens): identity + SIGNAL — adds
    #     irsrp/irsrq (RSRP/RSRQ).
    # A value tally (118K records) shows they are populated: irsrp/irsrq real (1646/3806 nonzero, −106..−117 dBm /
    # −13..−20 dB) and cell_tac real (TACs 11544/39178/...). cell_id {0,1,2,4}
    # and cell_plmn {0,1,-1,4} are flag-like here (not real CID/PLMN), and
    # gwl_irsrp/gwl_irsrq are dead (always 0) — the live signal is on the bare
    # irsrp/irsrq fields. The schema-based tier rule keys on field presence.
    # F3 (see docstring): irsrp/irsrq are LTE serving RSRP/RSRQ dBm vs
    # co-temporal quectel_led_modem.c/QENG F3; subsystem confirmed via the
    # CM-SS event callbacks. Identity is grounded on the indexed
    # sys_plmn_id[0..2] array -> plmns["sys_plmn_id"] (265/265 time-paired vs
    # AT serving PLMN, SDX62-class). cell_tac = LTE serving TAC is CANDIDATE
    # (239/239, but only 2 distinct TACs); under NR5G-SA it holds the stale
    # LTE TAC, not the serving TAC.
    wigle_direct=True,
    wigle_roles=("identity", "signal"),
    field_invariants={
        "version": {"enum": [0x00]},
    },
    # Ground-truth recipe: WiGLE-direct identity+signal validation via the CM
    # serving-system XML events.
)
def parse_0x1c6c(log_time: int, data: bytes) -> Diag0x1C6C | None:
    if len(data) < 6:
        return None
    # Layer-1 gate: byte[0] is the LSB of the zero prefix. Reject before
    # decode, matching field_invariants["version"]["enum"]. Strengthened by the
    # full 4-byte zero prefix + leading-'<' fingerprint below.
    if data[0] != 0x00:
        return None
    if data[:4] != _PREFIX:
        return None
    text = data[4:].decode("latin1")
    # Whitespace-tolerant '<' gate: some terse records start with a newline
    # after the prefix (byte[4]==0x0a then '<res>'), so a strict data[4]=='<'
    # check would drop a whole dialect. Body must begin —
    # after optional ASCII whitespace — with a tag.
    if not text.lstrip().startswith("<"):
        return None
    event, category = _parse_open(text)
    arrays = _arrays(text)
    return Diag0x1C6C(
        log_time=log_time,
        version=data[0],
        prefix=unpack_from("<I", data, 0)[0],
        text=text,
        event=event,
        category=category,
        args=_pairs(_ARG_RE, text),
        returns=_pairs(_RET_RE, text),
        info=_pairs(_INFO_RE, text),
        payload_size=len(data),
        arrays=arrays,
        plmns=_plmns(arrays),
    )
