"""0x1375 — CGPS IPC data envelope (#N).

Split from `lte_misc.py` per #N tier-3 batch 17 (then misnamed "LTE
SC-FDMA Statistics" — that identity was an early-RE guess and is **wrong**;
see the identity-correction note below).

=== identity correction (2026-06-10, #N) ===

The canonical vendor name is ``LOG_CGPS_IPC_DATA_C`` (Consolidated-GPS
*inter-process-communication* data) — a GNSS-subsystem log, NOT an LTE
uplink-PHY code. A cross-generation RE pass over 251,179 records spanning
**8 Qualcomm generations** (MDM9x00 Gobi, MDM9607, MDM9x30, SDX20, SDX20v2,
SDX55, SDX62, SDX65) and **5 vendors** (Sierra, Quectel, Telit, plus the
Inseego/SIMCom families in the wider corpus) showed that every record is a
**fixed 16-byte IPC envelope** wrapping a per-message-type opaque body — not
the flat 28-byte measurement record the prior parser assumed.

The prior parser mis-modelled the envelope: it called ``u32@4`` *meas_type*
(really a per-stream id), and ``u32@12`` *measurement_accum* / "likely RSRP"
(really a per-stream monotonic **sequence counter** — which is why it showed
thousands of "unique values" and looked like noise). The 0x0101 it had
folded into ``version_config`` is the envelope's universal type-tag.

=== the header (offsets little-endian; validated on all 8 gens) ===

The v4 decode stopped at a 16-byte envelope and treated [16:] as the opaque
per-message body.  The v5 pass (2026-06-10, #N) found that the "body"
itself begins with a **universal 12-byte sub-header** — present and exact in
15,777/15,777 generation-diverse samples — so the full fixed header is
**28 bytes** and the true per-``msg_id`` payload starts at offset 28:

    [0:2]   u16   msg_id          IPC message type (dispatch). byte0 dominates
                                  (<256 for most messages); byte1 is set for a
                                  few high-id messages (e.g. 0x86xx family).
    [2:4]   u16   msg_flags       ∈ {0, 1} across every generation. Constant
                                  per msg_id for 195/236 observed msg_ids
                                  (e.g. request/response pairing 0x0001=0 /
                                  0x0047=1); mixed for the other 41.
    [4:8]   u32   stream_id       ∈ [1..22]. The key under which all three
                                  per-stream counters are monotonic
                                  (0 violations / 251K recs).
    [8:10]  u16   substream_id    ∈ [0..26].  msg_id 0x0009 (zero-payload,
                                  periodic, fires on every stream) always has
                                  substream_id == stream_id — the shape of a
                                  timer/heartbeat self-message.
    [10:12] u16   marker          == 0x0101 in 100% of records, every gen,
                                  every size. Cross-message invariant #N —
                                  parse-gate (#N hardening).
    [12:16] u32   seq             per-stream monotonic COARSE counter: runs of
                                  consecutive same-stream records share one
                                  value, then it ticks (a transaction/batch
                                  counter, not per-message).  Its global sum
                                  is `global_seq` — see below.
    [16:20] u32   stream_msg_seq  per-stream monotonic FINE counter: +1 per
                                  consecutive logged record within the stream
                                  (verified on complete near-boot prefixes,
                                  e.g. EG25-G stream 1: 946..970 with zero
                                  gaps across 25 records of mixed msg_ids).
                                  Keyed by stream_id: 0 violations; keyed by
                                  (chip, msg_id) alone: 565 violations — the
                                  counter belongs to the stream, not the
                                  message type.
    [20:24] u32   global_seq      GLOBAL monotonic counter (0 decreases across
                                  every capture and generation, all msg_ids
                                  interleaved).  NOT a timestamp: per-capture
                                  "ms" ratios are incoherent (0.09..0.23).
                                  Identity: ≈ Σ over streams of `seq` — on the
                                  near-boot EG25-G capture the residual
                                  `global_seq − Σ last-seen seq` is EXACTLY
                                  constant (6268) across 1,412 consecutive
                                  tail records, and the residual is ≥ 0 on all
                                  15,777 samples / 8 gens (stale/unobserved
                                  streams only underestimate — any negative
                                  would falsify; none observed).
    [24:28] u32   payload_len     == len(record) − 28 in 15,777/15,777
                                  samples across all 8 generations and all
                                  236 observed msg_ids.  Cross-message
                                  invariant #N — parse-gate (v5).  (The v4
                                  "no universal body length field" finding
                                  tested `len(body)` against raw u32s without
                                  the +12 sub-header offset — wrong relation.)
    [28:N]  bytes payload         the actual per-``msg_id`` IPC message
                                  payload.  msg_id 0x0009 has payload_len==0
                                  (pure signal).  msg_id 0x00ec: payload[0] is
                                  a u8 element count with 192-byte stride
                                  (len = base + 192*count).  Per-msg_id
                                  payload decode is the still-open tail of
                                  #N / umbrella #N.

With the sub-header decoded, the dominant 28-byte size class (2.94M records,
~21% of the 13.9M-record corpus) is **fully decoded** — every byte named.

=== v6 (2026-06-10, #N): per-msg_id payload taxonomy ===

The "~50 message types carry a payload" tail was stratified per ``msg_id``
over the 15,777-sample / 8-generation walk artifact.  Two structural facts
emerged and are now encoded in ``_MSG_PAYLOAD`` (advisory — never a parse
gate; the marker + payload_len invariants remain the only hard gates):

1. **``substream_id`` is a per-``msg_id`` sub-dispatch key.**  Many message
   types that look "variable" at the ``msg_id`` level are actually several
   clean per-``substream_id`` shapes (e.g. ``0x0048``: sub1 → 2216-byte
   payload, sub5 → 4520-byte; ``0x001f``: sub1 → 88, sub6 → empty, sub8 →
   136).  This corrects the naive "length is the discriminator" reading.

2. **Two message types are genuine count-prefixed arrays** whose element
   count is a STORED field (not inferred from length):
     - ``0x00ec``: ``element_count = payload[0]`` (u8), 192-byte stride,
       536-byte base.  Exact on 443/443 samples, SDX62 + SDX65; counts 0..7+.
     - ``0x00c7``: ``element_count = payload[0]`` (u8), 144-byte stride,
       560-byte base.  Exact on 120/120 samples (SDX55 only — medium
       confidence pending a second generation).
   For these, v6 decodes ``element_count`` / ``element_stride`` and validates
   the geometry (``array_ok``: payload_len == base + stride*count).

   NB: ``0x0048`` looks array-shaped (4520 == 2216 + 144*16) but is a
   **two-cluster sub-dispatch coincidence**, not an array — only two payload
   sizes exist, split cleanly by ``substream_id``, so any 0/16-valued field
   yields a spurious 2-point fit.  It is classified ``sub_fixed``, not array.
   (This is the "version/dispatch is primary, length is secondary" trap.)

3. **``0x0078`` stream-1 is a fixed-capacity per-SV GNSS measurement array**
   (``sv_array``): a 64-byte header + **36 fixed slots** (zero-padded,
   front-contiguous) + a 4-byte trailer (const ``u32 == 6``).  The STORED
   ``u8`` at payload offset 39 is the count of VALID (non-empty) SV slots —
   it equals the number of non-zero ``sv_id`` slots in **156/156** records
   across 6 generations.  Slot stride is generation-fixed: 40 bytes on the
   SDX gens (1508-byte payload), 36 on MDM9x30 (1364-byte).  This is a
   FIXED-capacity array (payload size is constant per gen; the count says
   how many slots are populated) — distinct from the variable-length
   ``base + stride*count`` form above.  v6 decodes ``element_count`` (=valid
   SVs) + ``element_stride`` and validates the geometry.  (The per-slot
   element layout — ``sv_id`` + constellation + measurement floats — is
   GNSS-semantic and left for ground-truth-referenced follow-up.)

   Relatedly, ``0x0001`` sub-5 carries a **length-prefixed ``$PQME`` ASCII
   string**: a stored ``u32`` at payload offset 12 is the NUL-terminated
   string's byte length, the string itself at offset 16.  That is a
   length-prefix, NOT a ``base+stride*count`` array — so ``0x0001`` stays
   ``variable`` (the string slice is left to a follow-up; recorded here so a
   future reader doesn't mistake the u32 for an element count).

Every record now carries ``msg_kind`` (the taxonomy class for its ``msg_id``,
or ``"unknown"`` for an unrecognized one).  The 43 highest-volume payload-
bearing ``msg_id``s plus the 2 pure-signal ones (~88% of all 0x1375 records)
are classified; the per-element *semantics* inside array/fixed payloads stay
opaque (GNSS-domain IPC bodies; naming them needs co-captured NMEA/AT ground
truth, not offline bytes).

=== v7 (2026-06-10, #N): 0x0078 stream-1 per-SV GNSS measurement decode ===

The ``0x0078`` ``sv_array`` (v6) is the CGPS per-SV **carrier-phase / Doppler
measurement report**.  Each record is **one constellation's measurement
epoch** (constellations interleaved as separate records).  Reverse-engineered
against co-captured NMEA ``$GxGSV`` + the LG290P RINEX reference (same antenna
via passive splitter), cross-validated on 6 QCA generations (MDM9x30 + the 5
SDX gens) / 3,505 records — see ``_decode_0x0078_sv_report``.

64-byte epoch header (offsets payload-relative): ``[39]`` u8 valid-SV count,
``[40]`` u16 native week number (GPS 2419 / BeiDou 1060 / Galileo 1392; 0 for
GLONASS), ``[48]`` u32 epoch time-of-week ms (per-constellation scale —
GPS→BeiDou offset is exactly 14000 ms), ``[52]`` u32 constellation enum
(1=GPS, 3=GLONASS, 4=BeiDou, 5=Galileo).

Per-SV slot (SDX stride 40; MDM9x30 stride 36 drops the slot @4 word, so
fields after @2 sit 4 bytes earlier):
  @0  u16  sv_id            GPS 1-32 / GLONASS 65-96 / BeiDou 201-264 / Gal 265+
  @2  u16  signal_ch (hi byte, {0,1,2}) + glonass_fcn (lo byte, signed i8
           -7..+6, GLONASS only — matches the published OSN→FCN table 23/23)
  @8  f32  carrier_phase    fractional phase accumulator in [0,1); proven via
           d(phase)/d(meas_tow) = -range_rate/c on every generation
  @12 u32  meas_tow_ms      per-SV measurement time-of-week (ms); within ~20 ms
           of the epoch header tow; advances 1000 ms / real second
  @20 f32  range_rate_mps   LOS satellite radial velocity (m/s, +=receding) —
           the unscaled Doppler observable.  **Validated r=-1.000000 vs the
           LG290P RINEX D1C Doppler** (D1C = -5.2552·v ≈ -v/λ_L1).
  @36 f32  el_weight        cos(elevation) measurement weight (≈0.0042 +
           0.1845·cos(el), fit r=0.9998 vs GSV elevation); SDX stride only.
The @4/@16/@24/@28/@32 slot words are reserved / GLONASS-conditional and left
undecoded (mostly zero; no ground-truth match).  This is the first semantic
(named-physical-quantity, ground-truth-cross-checked) decode of a 0x1375
payload body.

Why this code still can't close (#N closure rule): the per-``msg_id`` payload
bodies of the OTHER message types remain structurally framed but not
semantically decoded — that per-``msg_id`` field naming is the open tail.

=== names-block:start (auto-generated by tools/inject_names_block_parsers.py) ===

Names by source (from sources/DIAG_LOG_INDEX.yaml):
    canonical: LOG_CGPS_IPC_DATA_C
        source: qualcomm_diag_log_codes_h (authority: vendor_official)
    aliases:
        LOG_HDR_DOS_MO_DOS_STATUS
            source: qxdm_3_12_714_2017_diag_log_codes
        LOG_INTERNAL_CGPS_IPC_DATA
            source: qxdm_3_12_714_2017_diag_log_codes
        RESERVED
            source: qxdm_itemtype_list_zukgit_2025_04_03

Source-precedence (#N): vendor_official > observation >
community (specification) > community (reference).
=== names-block:end ===
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# Universal CGPS-IPC envelope type-tag at offsets 10..11.  Present in 100% of
# records across all 8 QCA generations (251,179 records, 2026-06-10 #N
# cross-gen pass; corroborates the earlier 2026-04-23 543K-record SDX55+SDX62
# finding).  Used as the parse-gate: any record >= 12B that doesn't carry it
# is a foreign payload and is rejected.
_MARKER_0101 = b"\x01\x01"

# Smallest record we can read every envelope field from, and the full fixed
# header (16B envelope + 12B sub-header).  In practice every observed record
# is >= 28B (corpus size_min == 28 on every sidecar), so the full header is
# always present; the graceful sub-28 paths below exist only to keep
# parse-rate at 100% if a runt ever appears.
_FULL_ENVELOPE = 16
_FULL_HEADER = 28

# Per-msg_id payload taxonomy (#N v6).  Built from the 15,777-sample /
# 8-generation walk artifact, covering the 43 highest-volume payload-bearing
# msg_ids + the 2 pure-signal ones (~88% of all 0x1375 records).  ADVISORY
# ONLY — looked up to set `msg_kind`; it never gates the parse (a wrong entry
# can mislabel `msg_kind`, never break the 100% parse rate).  Entry forms:
#   ("signal",)                    payload always empty for this msg_id
#   ("fixed", size)                single fixed nonzero payload size
#   ("opt_fixed", size)            either empty or that one fixed size
#   ("sub_fixed", {sub: size})     payload size determined by substream_id
#   ("array", coff, cw, stride, base)  VARIABLE-LENGTH count-prefixed array:
#                                  a STORED count at payload[coff:coff+cw] (LE)
#                                  with len(payload) == base + stride*count.
#   ("sv_array", coff, header, capacity, trailer, {paysize: stride})
#                                  FIXED-CAPACITY array: `capacity` slots of
#                                  `stride` bytes (zero-padded, front-contiguous)
#                                  between a `header`-byte prefix and a
#                                  `trailer`-byte suffix; the STORED u8 at
#                                  payload[coff] is the count of VALID
#                                  (non-empty) slots.  Stride is keyed by the
#                                  (generation-fixed) payload size.
# msg_ids absent here are left msg_kind="unknown" (payload stays opaque).
_MSG_PAYLOAD: dict[int, tuple] = {
    0x00de: ("opt_fixed", 48),
    0x0033: ("opt_fixed", 4),
    0x86a9: ("fixed", 1),
    0x0008: ("opt_fixed", 1392),
    0x0047: ("variable",),
    0x86ff: ("fixed", 16),
    0x00c9: ("sub_fixed", {1: 32, 6: 200}),
    0x8709: ("fixed", 248),
    0x8760: ("fixed", 328),
    0x0001: ("variable",),
    0x00e1: ("opt_fixed", 2),
    0x86a2: ("variable",),
    0x003a: ("variable",),
    0x0058: ("fixed", 6),
    0x86a1: ("variable",),
    0x86c4: ("fixed", 80),
    0x86ba: ("variable",),
    0x86c5: ("fixed", 136),
    0x008a: ("fixed", 1),
    0x0014: ("opt_fixed", 208),
    0x0000: ("variable",),
    0x007c: ("opt_fixed", 4520),
    0x005a: ("variable",),
    0x86c7: ("fixed", 24),
    0x86b7: ("fixed", 8),
    0x871a: ("fixed", 16),
    0x00ec: ("array", 0, 1, 192, 536),
    # 0x0078 stream-1: per-SV GNSS measurement array — 64B header, 36-slot
    # fixed capacity, 4B trailer (const u32==6); valid-SV count is the u8 at
    # payload offset 39.  stride 40 (SDX gens, 1508B) / 36 (MDM9x30, 1364B).
    # Verified 156/156 records across 6 gens (stored count == #non-zero slots).
    # The stream-5 168B variant is a different shape (element_count left None).
    0x0078: ("sv_array", 39, 64, 36, 4, {1508: 40, 1364: 36}),
    0x0017: ("sub_fixed", {2: 4, 14: 1}),
    0x001f: ("sub_fixed", {1: 88, 8: 136}),
    0x0031: ("fixed", 24),
    0x00c7: ("array", 0, 1, 144, 560),
    0x0053: ("variable",),
    0x004d: ("variable",),
    0x0025: ("variable",),
    0x0039: ("fixed", 1),
    0x001e: ("sub_fixed", {1: 64, 6: 32, 8: 1}),
    0x0009: ("opt_fixed", 744),
    0x0048: ("sub_fixed", {1: 2216, 5: 4520}),
    0x86a3: ("fixed", 2),
    0x003c: ("variable",),
    0x0093: ("sub_fixed", {1: 16, 2: 56}),
    0x0027: ("sub_fixed", {1: 1, 5: 2224}),
    0x008f: ("signal",),
    0x0435: ("signal",),
}

# === 0x0078 stream-1 per-SV measurement decode (#N v7) ===================
#
# 0x0078 stream-1 is the CGPS per-SV carrier-phase/Doppler MEASUREMENT report
# (one record == one constellation's measurement epoch; constellations are
# interleaved as separate records).  The 64-byte header + 36-slot layout was
# reverse-engineered against co-captured NMEA $GxGSV + the LG290P RINEX
# reference (same antenna via passive splitter), cross-validated on 6 QCA gens
# (MDM9x30 + the 5 SDX gens) / 3,505 records.  Ground-truth anchors:
#   - slot range_rate_mps vs LG290P RINEX D1C Doppler: D1C = -5.2552*v,
#     r = -1.000000 (theoretical -1/lambda_L1 = -5.2550) -> range-rate in m/s.
#   - slot carrier_phase: d(phase)/d(meas_tow) = -range_rate/c on every gen.
#   - header gnss_tow_ms vs RINEX GPS ToW: sub-second; GPS->BeiDou ToW offset
#     exactly 14000 ms; native week numbers (GPS 2419, BeiDou 1060, Gal 1392).
# Header field offsets (payload-relative; identical on both strides):
_X0078_HDR = {
    "sv_count": 39,        # u8  — valid-SV count (== the sv_array element count)
    "week": 40,            # u16 — native constellation week number (0 for GLONASS)
    "gnss_tow_ms": 48,     # u32 — epoch time-of-week in ms (per-constellation scale)
    "constellation": 52,   # u32 — system enum (see _X0078_CONST)
}
_X0078_CONST = {1: "GPS", 3: "GLONASS", 4: "BeiDou", 5: "Galileo"}
# Per-SV slot field offsets WITHIN a slot, keyed by stride.  MDM9x30 (stride 36)
# drops the SDX slot's @4 word, so every field after @2 sits 4 bytes earlier.
# el_weight is only decoded on the SDX stride (40) where it is the confirmed
# cos(elevation) measurement weight; the MDM9x30 trailing field is ambiguous.
_X0078_SLOT = {
    40: {"carrier_phase": 8, "meas_tow_ms": 12, "range_rate_mps": 20, "el_weight": 36},
    36: {"carrier_phase": 4, "meas_tow_ms": 8,  "range_rate_mps": 16},
}


def _decode_0x0078_sv_report(payload: bytes, stride: int) -> dict[str, Any]:
    """Decode a 0x0078 stream-1 per-constellation measurement epoch.

    Returns {constellation, week, gnss_tow_ms, sv_count, sv:[...]} where each
    sv entry carries the ground-truth-validated per-SV observables.  Semantic
    fields (sv_id, glonass_fcn, range_rate_mps, meas_tow_ms) are cross-checked
    against RINEX/NMEA; carrier_phase / el_weight / signal_ch are structural
    (wire role known, exact unit/modulus pending).
    """
    cenum = unpack_from("<I", payload, _X0078_HDR["constellation"])[0]
    constellation = _X0078_CONST.get(cenum, f"enum{cenum}")
    is_glo = constellation == "GLONASS"
    fm = _X0078_SLOT[stride]
    svs: list[dict[str, Any]] = []
    for i in range(36):
        base = 64 + i * stride
        sv_id = unpack_from("<H", payload, base)[0]
        if sv_id == 0:
            continue  # empty (zero-padded) slot
        sysw = unpack_from("<H", payload, base + 2)[0]
        lo = sysw & 0xFF
        entry: dict[str, Any] = {
            "sv_id": sv_id,
            "signal_ch": sysw >> 8,                         # per-SV channel selector {0,1,2}
            "glonass_fcn": (lo - 256 if lo >= 128 else lo) if is_glo else None,  # signed FCN -7..+6
            "carrier_phase": unpack_from("<f", payload, base + fm["carrier_phase"])[0],
            "meas_tow_ms": unpack_from("<I", payload, base + fm["meas_tow_ms"])[0],
            "range_rate_mps": unpack_from("<f", payload, base + fm["range_rate_mps"])[0],
        }
        if "el_weight" in fm:
            entry["el_weight"] = unpack_from("<f", payload, base + fm["el_weight"])[0]
        svs.append(entry)
    return {
        "constellation": constellation,
        "week": unpack_from("<H", payload, _X0078_HDR["week"])[0],
        "gnss_tow_ms": unpack_from("<I", payload, _X0078_HDR["gnss_tow_ms"])[0],
        "sv_count": payload[_X0078_HDR["sv_count"]],
        "sv": svs,
    }


# ──────────────────────────────────────────────────────────────────────────
# Ground-truth capture recipes (#N framework / #N lane 0x1375, #N).
#
# ⛔ IDENTITY DRIVES THE SUBSYSTEM (ground-truth-recipes.md §"Authoring", #N).
# The issue #N matrix still labels 0x1375 "LTE uplink PHY statistics" — that
# is the STALE docstring title (an early-RE guess; see the identity-correction
# note at the top of this module). The vendor-OFFICIAL name is
# LOG_CGPS_IPC_DATA_C (Consolidated-GPS inter-process-communication data), a
# GNSS-subsystem log. Per the source-precedence rule (vendor_official >
# observation > community), the name OUTRANKS the title and decides the
# subsystem: these recipes ground against the **GNSS** AT/QMI vocabulary
# (AT+QGPS*/AT$GPSP/AT!GPS*/AT+CGPS/QMI_LOC), NOT LTE AT#RFSTS/PUSCH — grounding
# a CGPS code to LTE would be the exact "confident-wrong mapping" the doc warns
# about (the 0x13CE "LTE status"→LOG_CGPS_FREQ_EST precedent). So the sibling
# template here is the GNSS lane 0x14D8, NOT the LTE 0xB11x lanes.
#
# HONEST GROUNDING — the decoded fields are an IPC ENVELOPE, not measurements.
# 0x1375's decoded header is pure CGPS-IPC bookkeeping: msg_id (a dispatcher),
# stream_id/substream_id, the monotonic seq/stream_msg_seq/global_seq counters,
# the constant 0x0101 marker (a parse-gate), and payload_len (== len−28,
# structural). NO AT/QMI/NMEA command returns any of these by value — so this is
# the 0xB114 situation (no direct command → ground by CORRELATION / emission,
# never value-equality), transplanted into the GNSS subsystem. We therefore
# ground two falsifiable, per-modem-runnable things:
#   • msg_id  — the IPC dispatch type. A subset of msg_ids carry $PQME*/$PQPE1
#               proprietary ME-engine GNSS sentences in their (undecoded, #N)
#               payload, so msg_id co-varies with GNSS-engine activity. Ground by
#               EMISSION: enable the engine (the modem-specific GNSS-on trigger)
#               and 0x1375 IPC flows alongside the engine-state query + standard
#               NMEA; it should quiesce when the engine is off.
#   • payload_len — the 28-byte CGPS-IPC envelope STRUCTURAL fit. The per-modem
#               validation (#N core truth) is: does THIS firmware's 0x1375
#               stream fit the cross-gen 28-byte envelope at ~100% parse-rate?
#               A new firmware that shipped a different sub-header would fail the
#               payload_len==len−28 gate — this is the per-modem guard against
#               the size-invariance≠format-invariance trap (#N cross-gen RE).
#
# VERSION KEY (nominal). 0x1375 has NO version byte — byte-0 is the low byte of
# msg_id (a dispatcher), explicitly NOT a layout version (see field_invariants
# below: there is no `version` enum to gate, only the two cross-message
# invariants). The envelope format is uniform across all 8 Qualcomm generations
# (MDM9x00..SDX65). So every recipe is keyed at the NOMINAL version=1 — a
# placeholder for "the single observed CGPS-IPC envelope format", mirroring the
# single-version GNSS lane 0x14D8, NOT a decoded byte-0 value. (The display
# "v0x01" in --by-modem is this nominal key, not an emitted version byte.)
#
# KEYED, not consolidated. Coverage is counted per recipe_key = (version, make,
# model, firmware); listing a modem in another recipe's emitting_modems does NOT
# satisfy its cell (#N definition of done). So 0x1375 carries ONE GroundTruth
# PER emitting modem. The emitter set was taken from the corpus index
# (data/diag/corpus_index.json, 2026-06-10), which shows **24** inventory modems
# emitting 0x1375 — the 23 in the #N matrix PLUS sierra/em7455, a newly-
# observed emitter (the issue footer sanctions appending such cells). The 2
# corpus modems that do NOT emit it (casasystems/cfw3212, quectel/rg650vna)
# carry no recipe here.
#
# Authoring is OFFLINE — every field is status="hypothesis", hw_run_performed=
# False (no modem in hand, no capture taken; a later hardware run flips
# hw_run_performed + promotes the statuses).
#
# test_mode="triggered" is the NOMINAL classification (matches the GNSS sibling
# 0x14D8): enabling the GNSS engine is the most actionable thing a neighbour can
# DO to exercise the CGPS-IPC bus, and is a reasonable emission hypothesis. But
# it is UNVERIFIED and possibly wrong in one direction: the corpus shows 0x1375
# at a steady ~58s background cadence (corpus_index cadence_p50_ms) and present
# in wardriving captures — so emission may NOT be strictly gated by a user GNSS
# session (wardrives often run GNSS for geo-tagging, so this is consistent with
# "triggered" too, but does not prove it). The decisive test is an engine-OFF
# capture: if 0x1375 still flows, reclassify to subtractive. NOTE for that
# reclassification: there is **no single non-0x1xxx canary** that covers all 24
# emitters — the broadest LTE controls (0xB113/0xB114/0xB115) reach only 22/24
# (foxconn/t99w640 + sierra/em7455 lack the LTE ML1 family / have only a sparse
# capture), so a subtractive version would need PER-MODEM canaries, not one
# shared code.

# (slug, make, model, representative-firmware-build, gnss-dialect)


# ── Hardware-validation runs (#N per-modem promotion) ──────────────────────
# Each entry promotes ONE modem's recipe from the authored hypothesis to a
# hardware-validated outcome. Keyed by slug; only listed modems flip
# hw_run_performed=True and get their field statuses promoted. Measured evidence
# is kept in-source (the #N auditability rule) on both the recipe `notes` and
# this block.
#
# <redacted-ref> <redacted-ref>-06-11 on host <redacted-host> (Foxconn T99W640 / Dell
# DW5934e, SDX72, PCIe-MHI via the OOT pcie_mhi driver). The T99W640 is AT-mute
# (firmware-internal DUN silence — re-confirmed empirically this session: writes
# to /dev/mhi_DUN succeed, ATI/AT+CGMM/AT all return zero bytes), so ground truth
# is QMI — the framework-sanctioned non-AT source for modems with no vendor
# serving/GNSS AT command (#N/#N). The GNSS engine auto-runs (QMI_LOC
# operation-mode=standalone across 9 timestamped snapshots; the sibling GNSS
# ME-state code 0x14D8 co-fires 4284 recs), so the CGPS-IPC bus is active and
# 0x1375 flows. No sky fix indoors (QMI_LOC SV-info empty), so the engine never
# left acquisition — see the per-field partial rationale below.
#
# Owned capture (this session): <redacted-capture-path>
#   <redacted-pii>/diag_main.hdlc
#   (mask 0x1375+0x14D8, 100s, /dev/mhi_DIAG). 0x1375 = 1113 records:
#   • marker==0x0101      : 1113/1113 = 100.00%  → structural parse-gate holds
#   • payload_len==len−28 : 1113/1113 = 100.00%  → 28B envelope fits this FW
#   • msg_id (7 distinct) : 0xE7×324 0x01×260 0x47×208 0xC9×208 0x09×73(heartbeat)
#       0x07×32 0x17D4×8 — byte0-dominant dispatch shape + the 0x0009 zero-payload
#       heartbeat + one byte1-set high-id (0x17D4) ⇒ msg_id behaves as the IPC
#       DISPATCHER as hypothesised (not a counter, not a version byte).
# payload_len → VERIFIED (100% per-modem envelope structural fit, the #N gate).
# msg_id → PARTIAL: emission-while-engine-active + the dispatcher shape are
#   confirmed, but the DECISIVE engine-OFF negative control was NOT run (the GNSS
#   engine auto-runs; no clean engine-off window was available this session), so
#   the triggered-vs-subtractive gating and the "which msg_ids carry the $PQME
#   payload" question remain open. Honest = partial.
_X1375_HW_RUNS: dict[str, dict[str, Any]] = {
    "t99w640": {
        "firmware": "FDE2.F0.0.0.1.2.TO.001 020",
        "status": {"msg_id": "partial", "payload_len": "verified"},
        "evidence": (
            " ── HW-VALIDATED 2026-06-11 (<redacted-ref>, host <redacted-host>, PCIe-MHI, "
            "QMI ground truth — modem is AT-mute). Owned capture diag_main.hdlc "
            "<redacted-capture-path> mask "
            "0x1375+0x14D8, 100s, /dev/mhi_DIAG). 0x1375=1113 recs: marker==0x0101 "
            "1113/1113 (100%) + payload_len==len−28 1113/1113 (100%) → payload_len "
            "VERIFIED (28B CGPS-IPC envelope fits FW FDE2.F0.0.0.1.2.TO.001 020). "
            "msg_id 7 distinct, byte0-dominant dispatch shape + 0x0009 heartbeat + "
            "byte1-set 0x17D4 ⇒ dispatcher confirmed; GNSS engine active (QMI_LOC "
            "op-mode=standalone ×9 + sibling 0x14D8 ME-state co-fire 4284 recs) but "
            "no engine-OFF control and no sky fix (QMI SV-info empty, indoor) → "
            "msg_id PARTIAL (gating + $PQME-carrying msg_ids still open)."
        ),
    },
    "em7455": {
        "firmware": "SWI9X30C_02.24.03.00",
        "status": {"msg_id": "verified", "payload_len": "verified"},
        "evidence": (
            " ── HW-VALIDATED 2026-06-10 (<redacted-ref>, host <redacted-host>, Sierra "
            "EM7455, MDM9230 — the M.2 "
            "twin of the MC7455; GNSS antenna on the LG290P reference splitter, "
            "LIVE 3D FIX HEPE 12.2 m, 21/21 SVs GPS+GLONASS — stronger than the "
            "t99w640 indoor/no-fix run). Owned engine-ON capture em7455.dlf "
            "<redacted-capture-path>"
            "gnss_comparison_2026-06-10/, narrow mask 0x1375+0x1476+0x1477+0x147C+"
            "0x1480+0x1526+0x158C+0x14D8 via capture_dlf_from_diag — NOT diaggulp "
            "full-mask, which wedges this MDM9230's shared DIAG/AT task; 120 s, "
            "if00). 0x1375 = 37,766 recs: marker==0x0101 37766/37766 (100.00%) + "
            "payload_len==len−28 37766/37766 (100.00%) → payload_len VERIFIED (28B "
            "CGPS-IPC envelope fits SWI9X30C_02.24.03.00); msg_id 58 distinct, "
            "byte0-dominant dispatch shape (dominant 0x58 ×17424) ⇒ dispatcher. "
            "── DECISIVE engine-OFF NEGATIVE CONTROL (the test t99w640 lacked): "
            "AT!GPSEND → em7455_engineoff.dlf (25 s) → 0x1375 = 113 recs = 4.5/s, "
            "only 6 distinct msg_ids {0x01,0x09,0x3c,0x44,0x47,0x64}; vs engine-ON "
            "314.7/s, 58 msg_ids. 52/58 msg_ids fire ONLY with the engine on; the "
            "0x1375 flow COLLAPSES ~70× when the engine stops, leaving a stable "
            "6-id residual ⇒ msg_id is the GNSS-engine-GATED CGPS-IPC dispatcher "
            "(triggered, not free-running background IPC); the 6 residual ids are "
            "the background heartbeat/control bus. → msg_id VERIFIED (dispatcher "
            "identity + engine gating decisively grounded). The per-msg_id $PQME "
            "payload taxonomy remains the separate #N work."
        ),
    },
    "rm520ngl": {
        "firmware": "RM520NGLAAR03A03M4G",
        "status": {"msg_id": "verified", "payload_len": "verified"},
        "evidence": (
            " ── HW-VALIDATED 2026-06-11 (<redacted-ref>, host t480, Quectel "
            "RM520N-GL @ RM520NGLAAR03A03M4G_A0.303, SDX62 "
            "Snapdragon X62 — the 3rd chipset family for this code after MDM9230 "
            "and SDX72; 4-port USB composition 2c7c:0801 if00-if03, live 3D fix "
            "41.215,-111.936 HDOP 0.9, 7-9 SVs GPS+GLONASS+Galileo+Beidou). Owned "
            "engine-ON capture gnss.dlf (narrow mask 0x1375+0x147C+0x14A6+0x14D8+"
            "0x1480 via capture_dlf_from_diag --spc auto — NOT diaggulp; 118 s, "
            "if00). 0x1375 = 26,519 recs: marker==0x0101 26519/26519 (100.00%) + "
            "payload_len==len−28 26519/26519 (100.00%) → payload_len VERIFIED (28B "
            "CGPS-IPC envelope fits RM520NGLAAR03A03M4G); msg_id 58 distinct, "
            "byte0-dominant dispatch shape (dominant 222 & 51 ×5879 each) ⇒ "
            "dispatcher. ── DECISIVE engine-OFF NEGATIVE CONTROL (matching the "
            "EM7455 sibling): AT+QGPSEND → gnss_engineoff.dlf (25 s) → 0x1375 = 61 "
            "recs = 2.44/s, only 6 distinct msg_ids {1,71,100,201,202,212}; vs "
            "engine-ON 224.7/s, 58 msg_ids. 52/58 msg_ids fire ONLY with the engine "
            "on; the 0x1375 flow COLLAPSES ~92x when the engine stops, leaving a "
            "stable 6-id residual ⇒ msg_id is the GNSS-engine-GATED CGPS-IPC "
            "dispatcher. This SDX62 result REPLICATES the EM7455 MDM9230 sibling "
            "near-exactly (58 msg_ids ON / 6 residual OFF / 52-of-58 gated on both) "
            "→ the dispatcher gating is firmware-independent. → msg_id VERIFIED. "
            "Per-msg_id $PQME payload taxonomy remains the separate #N work."
        ),
    },
    "lm960": {
        "firmware": "32.01.150",
        "status": {"msg_id": "verified", "payload_len": "verified"},
        "evidence": (
            " ── HW-VALIDATED 2026-06-25 (<redacted-ref>, host <redacted-host>, Telit "
            "LM960A18 @ 32.01.150 = TMUS slot 4 of the single "
            "32.01.1X0 firmware, Qualcomm SDX20 — the 5th and OLDEST chipset family "
            "for this code after SDX72 / MDM9230 / SDX62 / SDX55; if00 USB-serial "
            "DIAG, no SPC needed, --enable-oemdre, marginal 2D fix). Owned engine-ON "
            "dual-mask DIAG+F3 capture cap_on.hdlc (diaggulp --ext-msg-f3, 101.9s, "
            "if00). 0x1375 = 16,996 recs = 166.6/s: marker==0x0101 16996/16996 "
            "(100.00%) + payload_len==len−28 16996/16996 (100.00%) → payload_len "
            "VERIFIED (28B CGPS-IPC envelope fits 32.01.1X0); msg_id 59 distinct, "
            "byte0-dominant dispatch shape (+ byte1-set high ids 0x86A9 ×2042 / "
            "0x86B7 / 0x86A2). ── DECISIVE engine-OFF NEGATIVE CONTROL (matching the "
            "EM7455/RM520N-GL/RM500Q siblings): AT$GPSP=0 → cap_off.hdlc (34.7s) → "
            "0x1375 = 17 recs = 0.49/s, only 7 distinct msg_ids {1,9,54,60,71,148,"
            "201}; vs engine-ON 166.6/s, 59 msg_ids. 52/59 msg_ids fire ONLY with the "
            "engine on; the 0x1375 flow COLLAPSES ~340× when the engine stops, "
            "leaving a stable 7-id residual (overlaps the RM520N-GL {1,71,201} "
            "heartbeat set) ⇒ msg_id is the GNSS-engine-GATED CGPS-IPC dispatcher. "
            "This SDX20 result REPLICATES the MDM9230/SDX62/SDX55 collapse pattern on "
            "a 5th, oldest chipset family → the dispatcher gating is "
            "firmware-independent. F3 cross-check (qdb GUID 2f5667ef, slot 1 shared-DSP, 100% "
            "qsr4 resolution): GNSS subsystem dominates the F3 (gm_core.c, mc_peak.c, "
            "pp_columnpeaks_uimage.c, mc_gnssmeasreport.c) confirming CGPS/GNSS "
            "context — no mis-attribution. → msg_id VERIFIED. Per-msg_id $PQME "
            "payload taxonomy remains the separate #N work."
        ),
    },
    "rm500q": {
        "firmware": "<redacted-firmware>",
        "status": {"msg_id": "verified", "payload_len": "verified"},
        "evidence": (
            " ── HW-VALIDATED 2026-06-19 (<redacted-ref>, host <redacted-host>, Quectel "
            "RM500Q-AE @ <redacted-firmware>, SDX55 "
            "Snapdragon X55 — the 4th chipset family for this code after SDX72 / "
            "MDM9230 / SDX62; live 3D fix 41.215,-111.936 HDOP 0.7, 20 SVs). Owned "
            "engine-ON dual-mask DIAG+F3 capture cap.hdlc (diaggulp --ext-msg-f3, "
            "244.7s, if00, CRC 1993558/1993558 OK). 0x1375 = 64,742 recs = 264.6/s: "
            "marker==0x0101 64742/64742 (100.00%) + payload_len==len−28 64742/64742 "
            "(100.00%) → payload_len VERIFIED (28B CGPS-IPC envelope fits "
            "<redacted-firmware>); msg_id 75 distinct, byte0-dominant dispatch "
            "shape (+ byte1-set high ids 0x8709/0x86BA). ── DECISIVE engine-OFF "
            "NEGATIVE CONTROL (matching the EM7455/RM520N-GL siblings): AT+QGPSEND "
            "→ engineoff.hdlc (29.7s) → 0x1375 = 166 recs = 5.6/s, only 26 distinct "
            "msg_ids; vs engine-ON 264.6/s, 75 msg_ids. The 0x1375 flow COLLAPSES "
            "~47x when the engine stops ⇒ msg_id is the GNSS-engine-GATED CGPS-IPC "
            "dispatcher (triggered, not free-running). This SDX55 result REPLICATES "
            "the MDM9230/SDX62 collapse pattern on a 4th chipset family → the "
            "dispatcher gating is firmware-independent. → msg_id VERIFIED. "
            "Per-msg_id $PQME payload taxonomy remains the separate #N work."
        ),
    },
}


@dataclass
class Diag0x1375:
    """CGPS IPC data record (0x1375 / ``LOG_CGPS_IPC_DATA_C``).

    The fixed 28-byte header (16B IPC envelope + 12B sub-header) is decoded
    into named fields; ``payload`` is the per-message-type payload starting
    at offset 28 (opaque — its decode is per-``msg_id`` and tracked on
    #N).  See module docstring for full field provenance.
    """

    log_time: int
    msg_id: int          # [0:2]  u16 — IPC message type (dispatch)
    msg_flags: int       # [2:4]  u16 — binary flag, ∈ {0,1}
    stream_id: int       # [4:8]  u32 — per-stream id (all counters monotonic within)
    substream_id: int    # [8:10] u16 — secondary stream id
    marker: int          # [10:12] u16 — == 0x0101
    seq: int             # [12:16] u32 — per-stream coarse (transaction) counter
    marker_0101_ok: bool # True iff marker == 0x0101 (or payload < 12B)
    has_seq: bool        # True iff payload >= 16B (full envelope present)
    stream_msg_seq: int  # [16:20] u32 — per-stream fine counter (+1 per record)
    global_seq: int      # [20:24] u32 — global counter ≈ Σ streams' seq
    payload_len: int     # [24:28] u32 — == len(record) − 28 (gated)
    payload_len_ok: bool # True iff payload_len matches (or record < 28B)
    has_subheader: bool  # True iff payload >= 28B (full header present)
    payload: bytes       # [28:]  per-message IPC payload (undecoded; per-msg_id)
    payload_size: int
    # v6 (#N): per-msg_id payload taxonomy (advisory; from _MSG_PAYLOAD)
    msg_kind: str        # "signal"/"fixed"/"opt_fixed"/"sub_fixed"/"array"/
                         # "sv_array"/"variable"/"unknown" — class of payload
    element_count: int | None    # array/sv_array — STORED count (elements, or
                                 # for sv_array the # of VALID slots)
    element_stride: int | None   # array/sv_array — bytes per element/slot
    array_ok: bool | None        # array/sv_array — stored count + geometry validate
    # v7 (#N): decoded 0x0078 stream-1 per-SV measurement epoch (else None)
    sv_report: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "Diag0x1375",
            "log_time": self.log_time,
            "msg_id": self.msg_id,
            "msg_flags": self.msg_flags,
            "stream_id": self.stream_id,
            "substream_id": self.substream_id,
            "marker": self.marker,
            "marker_0101_ok": self.marker_0101_ok,
            "payload_len_ok": self.payload_len_ok,
            "payload_size": self.payload_size,
            "msg_kind": self.msg_kind,
        }
        if self.has_seq:
            d["seq"] = self.seq
        if self.has_subheader:
            d["stream_msg_seq"] = self.stream_msg_seq
            d["global_seq"] = self.global_seq
            d["payload_len"] = self.payload_len
            if self.msg_kind in ("array", "sv_array") and self.element_count is not None:
                # decoded array geometry (count is a stored field, validated).
                # For "array" element_count is the element count; for
                # "sv_array" it is the count of VALID (non-empty) slots.
                d["element_count"] = self.element_count
                d["element_stride"] = self.element_stride
                d["array_ok"] = self.array_ok
            if self.sv_report is not None:
                # decoded 0x0078 stream-1 per-SV measurement epoch (v7)
                d["sv_report"] = self.sv_report
            elif self.payload:
                # payload is per-message and (beyond the array count) undecoded
                # — preserve as hex for downstream per-msg_id RE.  Suppressed
                # when sv_report is present (the decode supersedes the ~3 KB
                # raw hex; the reserved slot words are re-derivable from capture).
                d["payload_hex"] = self.payload.hex()
        return d


@register(0x1375,
    name="0x1375",
    description="CGPS IPC data record (LOG_CGPS_IPC_DATA_C) — 28B header + per-msg_id payload; v6 per-msg_id taxonomy (msg_kind) + array decode; v7 0x0078 stream-1 per-SV GNSS measurement decode (range-rate/carrier-phase/ToW, RINEX-validated); cross-gen MDM9x00..SDX65",
    version=13, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="v13 (2026-06-25, <redacted-ref> #N/#N, <redacted-host>): 5th per-modem HW validation — Telit LM960A18 @ 32.01.150 (Qualcomm SDX20, the OLDEST chipset family, marginal 2D fix): payload_len VERIFIED (16996/16996=100%) AND msg_id VERIFIED via engine-OFF control (0x1375 collapses ~340x, 166.6→0.49 rec/s, 59→7 msg_ids, 52/59 gated) — replicates the MDM9230/SDX62/SDX55/SDX72 engine-gated dispatcher on a 5th chipset family, F3-confirmed GNSS context (qdb 2f5667ef). v12 (2026-06-19, <redacted-ref> #N/#N, <redacted-host>): 4th per-modem HW validation — Quectel RM500Q-AE @ <redacted-firmware> (SDX55, live 3D fix): payload_len VERIFIED (64742/64742=100%) AND msg_id VERIFIED via engine-OFF control (0x1375 collapses ~47x, 264.6→5.6 rec/s, 75→26 msg_ids) — replicates the MDM9230/SDX62/SDX72 engine-gated dispatcher on a 4th chipset family. v11 (2026-06-11, <redacted-ref> #N): declared version_less=True — byte-0 is the low byte of msg_id (a dispatcher), RE-proven NOT a version across 8 generations / 251K records; the 0x0101 marker + payload_len==len−28 gates already reject foreign payloads, so no version axis exists. v10: 8-generation cross-validation 2026-06-10 (MDM9x00/9607/9x30/SDX20/SDX20v2/SDX55/SDX62/SDX65, 251K records); v5 universal 12B sub-header + envelope seq-monotonicity + #N marker hardening; v6 per-msg_id payload taxonomy (substream_id sub-dispatch; var-len arrays 0x00ec/0x00c7; 0x0078 fixed-capacity SV array; ~88% classified); v7 0x0078 stream-1 per-SV measurement decode — sv_id/glonass_fcn/carrier_phase/meas_tow_ms/range_rate_mps + per-constellation epoch header (constellation/week/gnss_tow_ms), ground-truth-validated against co-captured NMEA GSV + LG290P RINEX (range_rate vs D1C Doppler r=-1.000000) on 6 gens / 3505 records; v8 first per-modem HW validation (#N) — Foxconn T99W640 @ FDE2.F0.0.0.1.2.TO.001 020 (<redacted-ref> 2026-06-11, QMI ground truth on the AT-mute PCIe-MHI unit): payload_len VERIFIED (envelope structural fit 1113/1113=100%), msg_id PARTIAL (dispatcher shape + emission-while-engine-active confirmed; engine-OFF control not run); v9 second per-modem HW validation (#N) — Sierra EM7455 @ SWI9X30C_02.24.03.00 (MDM9230, <redacted-ref> 2026-06-10, live 3D fix on LG290P splitter): payload_len VERIFIED (37766/37766=100%) AND msg_id VERIFIED via the DECISIVE engine-OFF negative control t99w640 lacked — 0x1375 flow collapses ~70x (314.7→4.5 rec/s) and 52/58 msg_ids vanish when the GNSS engine stops, confirming the engine-gated CGPS-IPC dispatcher; v10 third per-modem HW validation (#N) — Quectel RM520N-GL @ RM520NGLAAR03A03M4G (SDX62, <redacted-ref> 2026-06-11, live 3D fix): payload_len VERIFIED (26519/26519=100%) AND msg_id VERIFIED via engine-OFF control (flow collapses ~92x, 224.7→2.44 rec/s, 52/58 msg_ids vanish) — REPLICATES the EM7455 MDM9230 result (58/6/52 on both), proving the dispatcher gating is firmware-independent across 3 chipset families",
    issues=(),
    primary_issue=None,
    fields_identified=9, fields_parsed=9,
    field_invariants={
        # The two cross-message universal invariants (layer-2 backstop; the
        # parser body also hard-rejects on both — layer-1).  byte 0 is NOT a
        # version (it's the low byte of msg_id, a dispatcher), so there is no
        # `version` enum to gate — see module docstring + #N audit thread.
        "marker_0101_ok": {"enum": [True]},
        "payload_len_ok": {"enum": [True]},
    },
    # A subset of msg_id values carry $PQME* proprietary ME-engine GNSS
    # sentences ($PQME1..5 + $PQPE1, '$P…*XX' checksum form) and the GNSS
    # config path `/nv/item_files/gps/cgps/me/gnss_config` inside the IPC
    # body — entirely consistent with this being a CGPS (GNSS) IPC container.
    # Empirically genuine ASCII (complete, checksummed, high-recurrence;
    # same $PQME family as 0x1C7C). Cross-vendor: Quectel (#N slice 3) +
    # Sierra EM9190 SDX55 / MC7455 MDM9x30 + Inseego M2000 MDM9627 (slice 5);
    # config-token clean+recurring on Sierra EM7565 SWI9X50C (slice 10). NOT
    # PII. The 2026-06-10 identity correction (LTE→CGPS) is consistent with —
    # and partly explained by — this GNSS ASCII.
    ascii_kinds=("nmea", "config-token"),
    # byte-0 is the low byte of msg_id (a dispatcher), NOT a DIAG version —
    # RE-proven across 8 generations / 251K records (module docstring + the
    # field_invariants comment above). The real parse-gates are the 0x0101
    # marker (data[10:12]) and payload_len == len−28, both hard-rejected in the
    # body. No version axis exists; version_less=True clears 0x1375 off #N.
    version_less=True,
    )
def parse_0x1375(log_time: int, data: bytes) -> Diag0x1375 | None:
    n = len(data)
    if n < 8:
        return None

    # Layer-1 universal-invariant gate (#N, #N): when the payload is long
    # enough to carry the envelope type-tag, validate it BEFORE decoding.
    marker = 0
    marker_ok = True
    if n >= 12:
        marker = unpack_from("<H", data, 10)[0]
        if data[10:12] != _MARKER_0101:
            return None

    # Layer-1 universal-invariant gate #N (v5, #N): when the payload is long
    # enough to carry the full 28-byte header, the sub-header's payload_len
    # field must equal len(record) − 28 — exact in 15,777/15,777 generation-
    # diverse samples across all 8 QCA gens and all 236 observed msg_ids.
    has_subheader = n >= _FULL_HEADER
    stream_msg_seq = global_seq = payload_len = 0
    payload = b""
    if has_subheader:
        payload_len = unpack_from("<I", data, 24)[0]
        if payload_len != n - _FULL_HEADER:
            return None
        stream_msg_seq = unpack_from("<I", data, 16)[0]
        global_seq = unpack_from("<I", data, 20)[0]
        payload = bytes(data[_FULL_HEADER:])

    msg_id = unpack_from("<H", data, 0)[0]
    msg_flags = unpack_from("<H", data, 2)[0]
    stream_id = unpack_from("<I", data, 4)[0]
    substream_id = unpack_from("<H", data, 8)[0] if n >= 10 else 0

    has_seq = n >= _FULL_ENVELOPE
    seq = unpack_from("<I", data, 12)[0] if has_seq else 0

    # v6 (#N): per-msg_id payload taxonomy (advisory — no gating).  Look up
    # the msg_id's structural class; for the two count-prefixed array types
    # decode the STORED element count and validate the array geometry.
    msg_kind = "unknown"
    element_count = element_stride = None
    array_ok = None
    sv_report = None
    spec = _MSG_PAYLOAD.get(msg_id)
    if spec is not None:
        msg_kind = spec[0]
        if msg_kind == "array" and has_subheader:
            _, coff, cw, stride, base = spec
            if coff + cw <= len(payload):
                cnt = (payload[coff] if cw == 1
                       else int.from_bytes(payload[coff:coff + cw], "little"))
                element_count = cnt
                element_stride = stride
                array_ok = (len(payload) == base + stride * cnt)
        elif msg_kind == "sv_array" and has_subheader:
            _, coff, header, capacity, trailer, strides = spec
            psize = len(payload)
            stride = strides.get(psize)
            if stride is not None and coff < psize:
                cnt = payload[coff]  # valid (non-empty) slot count, u8
                element_count = cnt
                element_stride = stride
                array_ok = (psize == header + stride * capacity + trailer
                            and 0 <= cnt <= capacity)
                # v7: 0x0078 stream-1 carries a decodable per-SV measurement
                # epoch.  Decode it when the geometry validates.
                if array_ok and msg_id == 0x0078 and stream_id == 1:
                    sv_report = _decode_0x0078_sv_report(payload, stride)

    return Diag0x1375(
        log_time=log_time,
        msg_id=msg_id,
        msg_flags=msg_flags,
        stream_id=stream_id,
        substream_id=substream_id,
        marker=marker,
        seq=seq,
        marker_0101_ok=marker_ok,
        has_seq=has_seq,
        stream_msg_seq=stream_msg_seq,
        global_seq=global_seq,
        payload_len=payload_len,
        payload_len_ok=True,
        has_subheader=has_subheader,
        payload=payload,
        payload_size=n,
        msg_kind=msg_kind,
        element_count=element_count,
        element_stride=element_stride,
        array_ok=array_ok,
        sv_report=sv_report,
    )
