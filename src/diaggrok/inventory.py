# diaggrok-provenance: re
"""Per-``(log_code, version)`` parse-coverage census.

A ``(log_code, byte-0)`` key is the CAPTURE-TIME analogue of the version
invariant the parsers enforce at PARSE time. A fixed payload size says nothing
about format stability, because firmware can ship a new struct layout under a
new version byte at the same byte count. The parser-level answer is ``field_invariants``; this is
the fleet-level one -- it makes a firmware emitting an undecoded
``(code, version)`` VISIBLE, instead of leaving it to be noticed by a mis-parse downstream.

The two-tier bound exists for that key's one false premise: byte-0 is the version
only for the version-gated codes. On other codes it is a DATA field, so the cap
is a decoder fact about which codes carry a version there -- not a buffer size.

What is NOT here: the ``diag_inventory`` wire record. Rendering, hex
formatting, rounding, JSON field order and the line-length bounds are the
consumer's business, and they are expressed over :meth:`DiagInventory.snapshot`.
That is the seam -- ``snapshot()`` returns plain data with codes as integers and
timestamps as raw floats, so this census does not know a wire exists.
"""
from __future__ import annotations

#: The log codes a decoded record can produce a downstream observation for: the
#: five cell-measurement/identity codes :mod:`diaggrok.observation` maps, plus the
#: two GNSS codes :mod:`diaggrok.gnss_gate` gates. Used ONLY to gate the census's
#: ``silent`` finding; it is not a filter on what gets parsed or counted.
#:
#: 0x14D8 is in this set and is EXPECTED to be permanently ``silent``. Its
#: lat/lon/alt are hardcoded 0.0 in the reference parser, so it parses 100%
#: and emits 0% -- 53 records on an RM520N-GL capture. That is the flag
#: working, not a bug in it: 0x14D8 is a "backup" position source in the
#: mask and contributes nothing, which is precisely the
#: state a census should make visible rather than average away into ``decoded``.
EMIT_CONTRACT_CODES = frozenset({0xB192, 0xB193, 0xB195, 0xB0C0, 0xB97F,
                                 0x1476, 0x14D8})

#: The subset of :data:`EMIT_CONTRACT_CODES` that CANNOT emit -- not "did not on
#: this capture", but structurally, for any capture on any modem.
#:
#: This exists because ``silent`` has two consumers with opposite needs. The
#: census wants 0x14D8 listed: a code in the mask that contributes nothing is
#: precisely what a census should make visible (see the note on
#: ``EMIT_CONTRACT_CODES`` above). But a consumer that uses the same list as an
#: ALARM predicate -- escalating a log line from INFO to ERROR whenever it is
#: non-empty -- would alarm forever: 0x14D8's lat/lon/alt are hardcoded 0.0
#: (bytes [+20..+43] are unbound carryover the parser does not unpack), so the
#: validity gate rejects every record and the key is silent on every healthy
#: source.
#:
#: Measured, not reasoned: on a healthy two-source server (RM520N-GL +
#: RM500Q-AE, both ``FLOWING`` at 780/433 observations) an alarm keyed on
#: ``silent`` emitted **26 ERROR lines and 0 INFO lines**, and on the RM500Q-AE
#: the only silent key was 0x14D8 -- an alarm whose entire content was the one
#: key that can never be anything else.
#:
#: So there is a second, narrower set rather than a change to the first:
#: ``silent`` stays complete for the census, ``silent_actionable`` drops the
#: structural members for the alarm -- two findings kept apart rather than one
#: suppressed.
#:
#: A code belongs here only when NO capture could make it emit. "Silent on
#: this bench", "silent without an antenna", or "silent until a parser change
#: lands" are all real ``silent_actionable`` findings and must stay in the
#: alarm.
NEVER_EMITS_CODES = frozenset({0x14D8})


class DiagInventory:
    """Per-``(log_code, version)`` observability for a DIAG capture.

    ``version`` is the DIAG payload's byte-0 version field -- the SAME key
    diaggrok dispatches on (a new firmware can ship a new struct layout under a
    new version byte at the same size; surfacing unseen ``(code, version)`` pairs
    is how a user notices a firmware emitting something the parsers do not
    yet handle -- the capture-time analogue of the byte-0 version invariants the
    parsers enforce at parse time).

    The ``decoded`` vs ``dropped`` split is why this lives beside the parsers
    and not in a capture relay: only the parser knows whether a recognized
    LOG_F record actually produced a result. A key that has been dropped but
    never decoded is flagged ``new`` -- the fleet's early warning.

    ``decoded`` MEANS PARSED, NOT USEFUL -- hence the third counter,
    ``emitted``. A record can parse cleanly and produce nothing
    downstream, and the gap is not marginal:

    * ``0x14D8`` parses on every record and emits a ``gps_fix`` on NONE of them
      -- its lat/lon/alt are hardcoded 0.0 in the reference parser (bytes
      [+20..+43] are unbound carryover), so the validity gate rejects
      every one. On an RM520N-GL capture that is 53 records at 100%
      ``decoded`` and 0% yield.
    * ``0x1476`` parses on every record and emits only when the fix clears the
      plausibility + vendor-placeholder gate.
    * ``0xB0C0`` parses on every RRC record and emits an identity only for the
      SIB1-bearing ones; ``0xB192`` emits nothing for a record with no id=27
      response subpacket.

    So a census with only ``decoded`` answers "did the parser understand this?"
    while the question this census exists to answer is **"is data flowing?"** --
    and on the GNSS codes those two answers differ by a factor of four.
    ``emitted`` closes that: a key with ``decoded`` high and ``emitted`` zero is
    a parser that understands a record type which contributes nothing, which is
    either a gate doing its job or a decode that has quietly stopped paying for
    itself. Both are worth seeing; neither is visible from ``decoded`` alone.

    Bounded keyset, TWO-TIER (saturate + report, never grow unboundedly on a
    hostile/novel stream, mirroring ``diag_stats``' bounded-ring discipline):

    - ``max_codes`` bounds distinct log CODES. The first version of every new code
      is admitted until this cap, so code coverage is independent of arrival
      order -- a target code (0xB97F) is never starved by codes seen earlier.
    - ``max_versions_per_code`` bounds versions WITHIN a code. This is the guard
      for the (code, byte-0) key's one false premise: byte-0 is the version only
      for the version-gated codes the census exists for (0xB193/0xB821/...). For
      other codes byte-0 can be a DATA field (e.g. 0x117E, a counter that spans
      0..255), which without this cap fragments one code into up to 256 spurious
      keys and, under a flat global cap, evicts genuine target codes -- observed
      on a real full-spectrum replay (512 keys / 41k overflow, NR codes lost).
      A real version field never spans dozens of values in one session, so a
      small per-code cap keeps every true version and drops only the junk.

    Under a live wardrive mask a source subscribes only ~6 target codes, so
    neither cap is ever approached; the caps matter for a full-mask / replay run.

    ``snapshot()`` is the seam to any consumer that renders this: plain data,
    integer codes, raw timestamps. See the module docstring.
    """
    def __init__(self, max_codes: int = 512, max_versions_per_code: int = 16):
        self.max_codes = max_codes
        self.max_versions_per_code = max_versions_per_code
        # (code, version) -> {"count", "decoded", "dropped", "enrich_failed", "last"}
        self.keys: dict[tuple[int, int], dict] = {}
        # code -> number of distinct versions admitted for it (for the per-code cap)
        self.code_versions: dict[int, int] = {}
        self.overflow = 0

    def record(self, code: int, version: int, decoded: bool, now: float,
               emitted: int = 0, enrich_failed: bool = False) -> None:
        """Tally one record. `emitted` is how many downstream records it actually
        produced (observations, or 1 for a gps_fix) -- see the class docstring
        for why that is not the same question as `decoded`. It defaults to 0 so a
        caller that does not know the yield still gets a correct count/decoded
        tally rather than a wrong emitted one.

        `enrich_failed` is a FOURTH counter and deliberately not a fold into
        `dropped`. A record that parsed and then raised while being
        enriched is `decoded=True` -- the parser understood it. Counting that as
        `dropped` would report an ENRICHMENT defect as a DECODE gap and point
        at the parser, which is the wrong layer."""
        k = (code, version)
        e = self.keys.get(k)
        if e is None:
            seen = self.code_versions.get(code)
            if seen is None:
                # A new code: admit unless we are at the distinct-code ceiling.
                if len(self.code_versions) >= self.max_codes:
                    self.overflow += 1
                    return
                self.code_versions[code] = 1
            else:
                # An existing code, new version: admit unless this code has
                # already contributed its version budget (byte-0-as-data guard).
                if seen >= self.max_versions_per_code:
                    self.overflow += 1
                    return
                self.code_versions[code] = seen + 1
            e = {"count": 0, "decoded": 0, "dropped": 0, "emitted": 0,
                 "enrich_failed": 0, "first": now, "last": now}
            self.keys[k] = e
        e["count"] += 1
        e["last"] = now
        if decoded:
            e["decoded"] += 1
        else:
            e["dropped"] += 1
        e["emitted"] += emitted
        if enrich_failed:
            e["enrich_failed"] += 1

    def unrecognized(self) -> list[tuple[int, int]]:
        """(code, version) keys seen but never decoded -- an unparsed firmware
        message type/version. Sorted for a stable status line."""
        return sorted(k for k, e in self.keys.items()
                      if e["decoded"] == 0 and e["dropped"] > 0)

    def silent(self) -> list[tuple[int, int]]:
        """(code, version) keys the emit contract DEPENDS on that parsed fine and
        produced nothing -- "is data flowing?" answered in the negative.

        A top-level list rather than only a per-key boolean, so it is symmetric
        with ``unrecognized()``: a relay can test one cheap substring rather than
        walking the key table, and the status one-liner can name the offenders. The
        two lists are DIFFERENT findings and both are needed -- an unrecognized key
        is new firmware the parsers do not handle yet (expected, on a new part),
        whereas a silent key is a code a consumer depends on going quiet, which on a
        live source is indistinguishable from "no cells in range".

        Gated to ``EMIT_CONTRACT_CODES``. Ungated it fires on nearly every key (a
        wardriving capture is mostly codes diaggrok parses and the consumer does
        not use: 4,250 of 4,257 records "decoded", 20 emitted), and a flag that is
        always on is not a signal.
        """
        return sorted(k for k, e in self.keys.items()
                      if k[0] in EMIT_CONTRACT_CODES
                      and e["decoded"] > 0 and e["emitted"] == 0)

    def silent_actionable(self) -> list[tuple[int, int]]:
        """``silent()`` minus the keys whose code can never emit.

        The list an ALARM should key on. ``silent()`` answers "what is not
        contributing?", which is a census question and correctly includes
        0x14D8; this answers "what is not contributing that COULD be?", which is
        the alarm question, and is empty on a healthy source.

        The two must stay separate rather than one replacing the other. Drop
        0x14D8 from ``silent()`` and the census loses a state it exists to
        show; escalate on ``silent()`` and the alarm is on permanently. See
        :data:`NEVER_EMITS_CODES` for the measurement.
        """
        return [k for k in self.silent() if k[0] not in NEVER_EMITS_CODES]

    def enrich_failed(self) -> list[tuple[int, int]]:
        """(code, version) keys that PARSED and then raised during enrichment --
        SIB1 learn, GNSS write, or observation build.

        Kept separate from ``unrecognized()`` on purpose. An unrecognized key is
        a diaggrok gap: new firmware the parsers do not handle yet, and the fix
        is a parser. An enrich-failed key is a defect in the consumer's mapping
        layer on a record diaggrok understood perfectly -- a None reaching
        arithmetic, an absent dict key, an out-of-range SIB1 index. Same
        symptom, different layer, so folding them would point at the wrong
        one. Uncounted, this class of failure raises out of the consumer and
        reads as "no cells in range"."""
        return sorted(k for k, e in self.keys.items() if e["enrich_failed"] > 0)

    def snapshot(self) -> dict:
        """The census as PLAIN DATA -- the seam between counting and rendering.

        Nothing here is formatted for a consumer. ``code`` is an ``int``, not
        ``"0xB193"``; ``first``/``last`` are raw epoch floats, not rounded for a
        display; there is no ``type``, no ``status`` line and no table. A renderer
        (the Kismet ``diag_inventory`` line, an analysis notebook, a future web
        panel) builds its own shape from this. The moment a ``0x``-prefixed string
        appears in this return value, the wire has leaked back into the census.

        The ``*_total`` counts ride alongside the three lists deliberately. A
        consumer that bounds the lists for a fixed-size pipe must still be
        able to report the true length, and a count that exists only when the
        array is short is a count a reader can be written against and then
        silently lose at scale.
        """
        unrec = self.unrecognized()
        silent = self.silent()
        silent_actionable = self.silent_actionable()
        enriched = self.enrich_failed()
        keys = []
        for (code, ver), e in sorted(self.keys.items()):
            # Per-key rate: lifetime average over the observed window
            # for this (code,version) -- count / (last-first). A single-observation
            # key has zero span (no interval elapsed), so its rate is 0.0 rather
            # than an undefined divide. This is the census-table analogue of a
            # windowed obs/sec readout, which uses a rolling ring; a full ring per
            # key (up to max_codes*max_versions keys) would be far heavier than
            # the lifetime average a census needs.
            span = e["last"] - e["first"]
            rate = round(e["count"] / span, 4) if span > 0 else 0.0
            keys.append({
                "code": code,
                "ver": ver,
                "count": e["count"],
                "decoded": e["decoded"],
                "dropped": e["dropped"],
                "emitted": e["emitted"],
                # Parsed, then raised while being enriched. A
                # FOURTH counter, not a fold into `dropped` -- see record().
                "enrich_failed": e["enrich_failed"],
                "first": e["first"],
                "last": e["last"],
                "rate": rate,
                "new": e["decoded"] == 0 and e["dropped"] > 0,
                # Parsed fine, contributed nothing -- but ONLY flagged for codes
                # the emit contract expects output from. Without that gate the
                # flag fires on almost every key (a wardriving capture is mostly
                # codes the parsers handle and no consumer wants: on an
                # RM520N-GL capture, 4,250 of 4,257 records are "decoded"
                # and 20 are emitted), and a flag that is always on is not a
                # signal. Gated, it means what "is data flowing?" needs: a code
                # a consumer DEPENDS on, understood by the parser, yielding zero.
                "silent": (code in EMIT_CONTRACT_CODES
                           and e["decoded"] > 0 and e["emitted"] == 0),
            })
        return {
            "distinct": len(self.keys),
            "overflow": self.overflow,
            "unrecognized": unrec,
            "silent": silent,
            # The alarm's list, beside -- not replacing -- the census's.
            # `silent`/`silent_total` keep their meaning; a consumer that
            # ESCALATES should read these instead, falling back to
            # `silent_total` when talking to an older producer.
            "silent_actionable": silent_actionable,
            "enrich_failed": enriched,
            "unrecognized_total": len(unrec),
            "silent_total": len(silent),
            "silent_actionable_total": len(silent_actionable),
            "enrich_failed_total": len(enriched),
            "keys": keys,
        }
