"""0x1350 — LTE Meas 1350 (v=0x05 97B fixed; v=0x06 variable).

Two on-wire formats share this log code, discriminated by byte [0]:

**v=0x05** — fixed 97B, 8 × s16-triplet entries. Validated across
generations on MDM9607 (EG25-G), MDM9x50 (EM7511), SDX20 (LM960), SDX20V2
(EG18-NA) and SDX55 (FN980m + FN980 + EM7511 edge cases). The size is 97B
everywhere (a 14B observation is a truncated record).

Layout:
  [ 0]    version         u8  = 0x05 const
  [ 1]    const_0d        u8  = 0x0D const (family magic — cf. 0x137A/0x1378)
  [ 2-28] reserved_pre    27B = 0x00... (all-zero across 14,151 records /
                               245 captures)
  [ 29]   entry_count     u8  = 0x08 const (drives entries[] length)
  [30-34] reserved_mid     5B = 0x00... (all-zero, same walk)
  [35-96] entries[8]     62B = 8 × 8-byte slots; last slot's trailing
                               padding is elided so the final slot is 6B.

Each 8-byte entry is:
  val_a_s16 (s16 LE), val_b_s16 (s16 LE), val_c_s16 (s16 LE), pad (2B = 0x0000)

Field semantics (v=0x05):
  val_a = the tcxomgr **AFC rotator** value ("Rot") — the oscillator
         frequency-rotation term the VCTCXO/AFC loop drives. **F3-GROUNDED**:
         on an EM7565 (MDM9x50) capture, per-record median(val_a) matches the
         co-temporal tcxomgr rotator ``Rot`` (s32) within ±6 on
         **232/265 records (88%)**, mean diff -0.30 — and is corroborated
         independently by ``lte_ml1_afc_stm.c:5245 "AFC reporting RGS,
         tcxomgr:%d/%d"`` (val_a ≈ -1927 co-temporal with tcxomgr:0/1929).
         Cross-generation confirmation on an LM960 capture (**SDX20**, 317
         records): **316/317 (100%)** within ±6, mean +1.21, stdev 1.59.
         Matched by F3 format-string content (line numbers differ per build).
         val_a is an AFC frequency offset, NOT an EARFCN delta. This ties the
         whole record to its canonical name LOG_TCXOMGR_AFC_DATA_C at the
         field level.
  val_b takes two distinct magnitudes per record pair (~ tens vs ~ 1250;
         dominant 100 on the EM7565) — likely two sub-measurements per
         logical cell; F3-SILENT (no co-temporal tcxomgr field matches),
         unresolved.
  val_c = LTE serving-cell RSRP in dBm (identity scale) — CONFIRMED via AT
         correlation on RM520N-GL/SDX62, EG25-G/MDM9207, LV55/SDX55.
         F3-NEUTRAL: the AFC subsystem F3 carries no RSRP print, so F3 neither
         confirms nor refutes it — the per-path RSRP the AFC loop consumes to
         gate its corrections, consistent with val_a=Rot living in the same
         entry (each entry = one RX path's AFC state).

**v=0x06** — variable length, observed on the Netgear AirCard 791L (Sierra
MDM9x35) and decoded from 2,392 records across two drive captures. The
alias `LOG_VCTCXO_MANAGER_AUTOMATIC_FREQUENCY_CONTROL_VERSION_6` matches:
this is the "VERSION_6" arm of the VCTCXO/AFC log.

Size model (100% of 2,392 records): ``len == 35 + 8*n_entries + 10`` —
a 35B header (sharing v=0x05's [30:35] reserved_mid), n_entries × 8B
entry slots, and a 10B trailer. Observed n_entries 1..8 (sizes 53..109,
+8B stride == one entry). The parser accepts ONLY those eight sizes, plus
v=0x05 at exactly 97B with entry_count 8. Any other (version, size, count)
returns None so the registry's WARN reports it.
Layout:
  [ 0]     version    u8  = 0x06 const
  [ 1]     const_06   u8  = 0x06 const
  [ 2]                 = 0x00 const
  [ 3:10]  hdr_var7   7B  — per-record varying (counter/timestamp-like;
                            [9] ∈ {0x3d,0x3e})
  [10:13]              = 0x00 const ×3
  [13]     const_03   u8  = 0x03 const
  [14]     flag14     u8  ∈ {0x00,0x01}
  [15:17]              = 0x00 const ×2
  [17:25]  hdr_slot   8B  — entry-shaped (4 × s16 LE); per-record varying,
                            likely a reference/serving measurement slot
  [25:29]  marker     4B  = 5a 01 1e 00 const (format discriminant)
  [29]     n_entries  u8  ∈ 1..8 (drives entries[] length)
  [30:35]  reserved_mid 5B = 0x00 const (same offset/role as v=0x05)
  [35:35+8N] entries[N] — 8B each, decoded as 4 × s16 LE (w0,w1,w2,w3)
  [.. +10] trailer    10B — often zero; leading 8B are entry-shaped

Each v=0x06 entry (4 × s16 LE, observed ranges over 18,543 entries):
  w0  signed wide  (-23096..+22688) — AFC-frequency-error-shaped
  w1  small count/index (0..10; dominant 2; [3] hi-byte always 0)
  w2  small positive (0..380)
  w3  mostly zero (nonzero 8.2%); wide signed when populated

v=0x05 vs v=0x06 is a RADIO-STATE selector, NOT a firmware version. A live
A/B on the AirCard 791L itself: a 60s DIAG capture of the *same* unit +
firmware while stably camped on LTE B4 (EARFCN 2050, PCI 221,
val_c ≈ -97..-99 dBm) emitted 13 × v=0x05 and **zero v=0x06**, whereas the
CDMA-search drive capture was ~100% v=0x06. So the firmware emits the fixed
8-entry v=0x05 in the steady frequency-locked LTE-serving state and the
variable-entry v=0x06 during CDMA-1x search / (re)acquisition. This fits the
VCTCXO/AFC name: AFC reports differently while pulling in frequency
(acquisition) than when locked. It also explains why the v=0x06 measurement
slots are largely unpopulated in the drive captures — during CDMA search there
is no stable serving cell to measure.

v=0x06 field semantics are NOT confirmed: grounding them needs a capture
taken *while the modem is in CDMA-search/acquisition state*, not a steady LTE
camp; neither drive capture's F3 (RF-driver / CDMA-searcher chatter) labels
these fields. Downstream consumers should treat the v=0x06 w-fields as opaque
s16. Cf. the sibling AFC log 0x13D1 `XoFreqEst13D1`, which has the
identical variable-entry shape (``size == 412 + 10*ec``).

F3-VERDICT 0x1350 v0x05: GROUND. Across every F3-bearing capture,
``median(entries[].val_a)`` vs the ``tcxomgr_data.c`` Rot interpolated to the
record time: 195/224 joined captures at median |Δ| ≤ 25 (Rot levels about
−4,200 … +650 across devices); trend ρ > 0.5 on 150/172, median 0.90.
Outliers are a Rot printed for another ``system:`` client, boot /
GNSS-restart transients, and fast drift.
F3-VERDICT 0x1350 v0x06: INCONCLUSIVE: both F3-bearing AirCard 791L captures
print no tcxomgr Rot; their co-temporal F3 is CDMA-searcher chatter with no
field value above a shuffled baseline.

Log name: LOG_TCXOMGR_AFC_DATA_C
Also known as: LOG_DMB_TUNE_DONE_SUCCESS, LOG_VCTCXO_MANAGER_AUTOMATIC_FREQUENCY_CONTROL, LOG_VCTCXO_MANAGER_AUTOMATIC_FREQUENCY_CONTROL_VERSION_6
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


@dataclass
class LteMeas1350Entry:
    """Single 8-byte entry from 0x1350 — 3 × s16 LE + 2B padding."""
    val_a: int  # tcxomgr AFC rotator ("Rot") — F3-grounded
    val_b: int  # two sub-measurement magnitudes; F3-silent, unresolved
    val_c: int  # LTE serving RSRP in dBm (AT-grounded; F3-neutral)

    def to_dict(self) -> dict[str, Any]:
        return {'val_a': self.val_a, 'val_b': self.val_b, 'val_c': self.val_c}


@dataclass
class Diag0x1350:
    """LTE measurement (0x1350) — 97B fixed, 8 × 3-s16 entries."""
    log_time: int
    version: int
    const_0d: int
    entry_count: int
    entries: list[LteMeas1350Entry]
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1350',
            'log_time': self.log_time,
            'version': self.version,
            'const_0d': self.const_0d,
            'entry_count': self.entry_count,
            'entries': [e.to_dict() for e in self.entries],
            'payload_size': self.payload_size,
        }


@dataclass
class LteMeas1350V6Entry:
    """Single 8-byte v=0x06 entry — 4 × s16 LE (semantics unconfirmed)."""
    w0: int  # signed wide — AFC-frequency-error-shaped
    w1: int  # small count/index (0..10)
    w2: int  # small positive (0..380)
    w3: int  # mostly zero; wide signed when populated

    def to_dict(self) -> dict[str, Any]:
        return {'w0': self.w0, 'w1': self.w1, 'w2': self.w2, 'w3': self.w3}


@dataclass
class Diag0x1350V6:
    """LTE Meas 1350 v=0x06 — variable-length VCTCXO/AFC record.

    Field names deliberately avoid the v=0x05-only invariant keys
    (``const_0d``, ``entry_count``) so the shared registry ``field_invariants``
    (which match by dict-key name) apply those strictly to v=0x05. ``version``
    and ``payload_size`` are shared: the ``payload_size`` enum is the union of
    both versions' attested sizes, and the executable gate couples each
    size to its version.
    """
    log_time: int
    version: int          # byte [0] = 0x06
    const_06: int         # byte [1] = 0x06
    flag14: int           # byte [14] ∈ {0,1}
    hdr_var7: bytes       # [3:10] per-record varying header region
    hdr_slot: LteMeas1350V6Entry  # [17:25] entry-shaped reference slot
    n_entries: int        # byte [29] ∈ 1..8
    entries: list[LteMeas1350V6Entry]  # [35:35+8N]
    trailer: bytes        # trailing 10B
    consts_ok: bool       # all corpus-verified const bytes hold
    payload_size: int     # total payload length == 35 + 8*n_entries + 10

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1350V6',
            'log_time': self.log_time,
            'version': self.version,
            'const_06': self.const_06,
            'flag14': self.flag14,
            'hdr_var7': self.hdr_var7.hex(),
            'hdr_slot': self.hdr_slot.to_dict(),
            'n_entries': self.n_entries,
            'entries': [e.to_dict() for e in self.entries],
            'trailer': self.trailer.hex(),
            'consts_ok': self.consts_ok,
            'payload_size': self.payload_size,
        }


# v=0x06 format discriminant marker at [25:29] (corpus-invariant, 2,392 recs).
_V6_MARKER = b'\x5a\x01\x1e\x00'
_V6_HEADER = 35   # bytes before the entries region
_V6_ENTRY = 8     # bytes per entry
_V6_TRAILER = 10  # trailing bytes after the entries region

# Attested (version -> size) coupling (1,793 scanned captures). Every record
# falls on one of these pairs and none crosses:
#   v=0x05  97 B, entry_count == 8                 69,758 records, 15+ chipsets
#   v=0x06  35 + 8n + 10 B, n_entries n in 1..8     2,392 records, MDM9x35 AC791L
# Anything else returns None so it reaches the registry's WARN and the
# unhandled tally. A new size or count is new silicon or a misframe, and it must
# be investigated, not truncated or guessed at.
_V05_SIZE = 97
_V05_ENTRY_COUNT = 8
_V6_SIZE_BY_N = {n: _V6_HEADER + _V6_ENTRY * n + _V6_TRAILER for n in range(1, 9)}
_1350_SIZES_OBSERVED = sorted({_V05_SIZE, *_V6_SIZE_BY_N.values()})


# ---------------------------------------------------------------------------
# Field grounding summary — v=0x05
# ---------------------------------------------------------------------------
# The canonical name LOG_TCXOMGR_AFC_DATA_C (TCXO-manager Automatic Frequency
# Control) is grounded at the field level, not just the subsystem level: this
# is an AFC data log that ALSO embeds a per-RX-path signal metric. F3 (EM7565
# capture) shows per-record median(val_a) == the co-temporal tcxomgr rotator
# ``Rot`` (``tcxomgr_data.c:2574`` s32) within ±6 on 232/265 records (88%,
# mean diff -0.30), corroborated by ``lte_ml1_afc_stm.c:5245 "AFC reporting
# RGS, tcxomgr:%d/%d"``. So val_a is the AFC frequency-rotation term, NOT an
# EARFCN-delta. val_c is AT-grounded RSRP (driven by varying RF on three
# chipset families) and F3-neutral (the AFC subsystem emits no RSRP print),
# consistent with each entry being one RX path's AFC state (rotator + the
# signal metric that gates its corrections).

@register(0x1350,
    name="0x1350",
    description="LTE measurement (0x1350) — 97B fixed, 8 × s16 triplet entries",
    version=8, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Cross-generation decode from MDM9607 + MDM9x50 + SDX20 + SDX20V2 + "
        "SDX55. v=0x05 (97 B, 69,758 records): reserved_pre [2:28] and "
        "reserved_mid [30:34] all-zero over 14,151 records / 245 captures / 8 "
        "chipsets; const_0d [1]=0x0d and entry_count [29]=0x08 invariant "
        "(layer-2 field_invariants); entry 2B pad bytes zero. entries.val_c = "
        "serving RSRP (dBm, identity scale), verified against AT/JSON-RPC "
        "serving RSRP while RF varied on RM520N-GL (SDX62), EG25-G (MDM9207, "
        "reselection sweep -110..-117 dBm) and LV55 (SDX55, 100% multi-value "
        "containment). entries.val_a = tcxomgr AFC rotator, F3-grounded (88% "
        "within ±6 on MDM9x50, 316/317 on SDX20). v=0x06: variable-length "
        "VCTCXO/AFC record from the AirCard 791L (MDM9x35); size model "
        "len==35+8*n_entries+10 on 2,392 records; structural decode only (F3 "
        "does not label the fields). The parser gates on exact (version -> "
        "size) coupling: v=0x05 len == 97 and entry_count == 8, v=0x06 "
        "n_entries in 1..8; anything else returns None so the registry WARN "
        "fires."
    ),
    issues=(),
    fields_identified=6, fields_parsed=6,
    field_invariants={
        # version gates BOTH formats (0x05 fixed-97B, 0x06 variable). A record
        # carrying any other byte-0 is rejected in the parser body.
        "version": {"enum": [0x05, 0x06]},
        # Union of both versions' attested sizes. The parser body
        # couples each size to its version, so this enum is not the gate.
        "payload_size": {"enum": _1350_SIZES_OBSERVED},
        # The remaining invariants are v=0x05-only: the v=0x06 struct
        # (Diag0x1350V6) emits `n_entries` and no `const_0d`, so these keys
        # are absent from v6 dicts and the checker skips them (registry.py
        # match-by-key). They stay strict for v=0x05.
        "const_0d": {"enum": [0x0D]},
        "entry_count": {"enum": [0x08]},
    },
    )
def parse_0x1350(log_time: int, data: bytes) -> Diag0x1350 | Diag0x1350V6 | None:
    if not data:
        return None
    version = data[0]
    # Layer-1 version gate: reject any byte-0 outside the declared
    # {0x05, 0x06} enum up front, in the canonical reject-first form a static
    # version-gate audit recognizes. The per-version branches below would also
    # return None for other bytes; this makes the guarantee explicit.
    if version not in (0x05, 0x06):
        return None
    if version == 0x05:
        return _parse_v05(log_time, data)
    if version == 0x06:
        return _parse_v06(log_time, data)
    return None


def _parse_v05(log_time: int, data: bytes) -> Diag0x1350 | None:
    # Exact size + count: a longer record or another count is an unobserved
    # layout. Reject it loudly rather than decode the first 97 bytes.
    if len(data) != _V05_SIZE:
        return None
    entry_count = data[29]
    if entry_count != _V05_ENTRY_COUNT:
        return None
    version = data[0]
    const_0d = data[1]
    # Each entry is 3×s16 LE on an 8 B stride; the final entry is truncated to
    # 6 B (no trailing pad), so 35 + 7*8 + 6 == 97.
    entries = [LteMeas1350Entry(*unpack_from('<hhh', data, 35 + i * 8))
               for i in range(entry_count)]
    return Diag0x1350(
        log_time=log_time, version=version, const_0d=const_0d,
        entry_count=entry_count, entries=entries,
        payload_size=len(data),
    )


def _read_v6_entry(data: bytes, off: int) -> LteMeas1350V6Entry:
    w0, w1, w2, w3 = unpack_from('<hhhh', data, off)
    return LteMeas1350V6Entry(w0=w0, w1=w1, w2=w2, w3=w3)


def _parse_v06(log_time: int, data: bytes) -> Diag0x1350V6 | None:
    if len(data) < _V6_HEADER + _V6_TRAILER:
        return None
    n_entries = data[29]
    # Size model is the format discriminant: len == 35 + 8*n_entries + 10, for
    # the attested n_entries 1..8 only. n=0 or n>8 fits the model but
    # has never been seen, so it is rejected loudly, not decoded.
    if len(data) != _V6_SIZE_BY_N.get(n_entries):
        return None
    # Marker [25:29] is the corpus-invariant format magic — reject mismatches
    # rather than mis-decode a same-sized record from another format.
    if data[25:29] != _V6_MARKER:
        return None
    entries = [_read_v6_entry(data, _V6_HEADER + i * _V6_ENTRY)
               for i in range(n_entries)]
    trailer = data[_V6_HEADER + _V6_ENTRY * n_entries:]
    # Observational: verify the corpus-verified const bytes still hold (soft
    # flag, not a hard reject — a drift here is worth surfacing, not dropping).
    consts_ok = (
        data[1] == 0x06 and data[2] == 0x00 and
        data[10:13] == b'\x00\x00\x00' and data[13] == 0x03 and
        data[15:17] == b'\x00\x00' and data[30:35] == b'\x00' * 5
    )
    return Diag0x1350V6(
        log_time=log_time, version=data[0], const_06=data[1], flag14=data[14],
        hdr_var7=data[3:10], hdr_slot=_read_v6_entry(data, 17),
        n_entries=n_entries, entries=entries, trailer=trailer,
        consts_ok=consts_ok, payload_size=len(data),
    )
