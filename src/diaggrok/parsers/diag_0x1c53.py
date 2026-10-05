"""NR5G ML1 0x1C53 — boot-only 28B fixed record.

4 records per boot. Record 0 is a header (record_kind byte 9 = 0x00),
records 1-3 are indexed entries (byte 9 = 0x01, byte 11 ∈ {1, 2, 3}).
The 3 entries likely correspond to 3 NR5G bands / chains that NR5G ML1
tracks even when no 5G registration is present (unverified; they are not
a subscriber count — see below).

Bytes 1-4 are a ~1 ms **timetick** (u32 LE), not an opaque handle — see
below. The older name ``boot_handle`` survives as a deprecated alias.

Cross-vendor scope: the code is ABSENT on Sierra EM9190 SDX55 (despite a
reboot in scope; sibling 0x19A9 fires there), absent on Telit LM960 SDX24
reboots, and absent on 3 Quectel RM520N-GL SDX62 runtime captures (no
reboot in scope); emission is so far specific to Telit FN980 firmware.

Discovery context shared with 0x19A9 (``diag_0x19a9.py``) and 0x19EC
(``diag_0x19ec.py``) — all three emerged from the same FN980 SDX55
edge-case captures.

Layout::

    +0x00  1B   version           u8, always 0x01
    +0x01  4B   timetick          u32 LE, ~1 ms tick (``boot_handle`` is a
                                   deprecated alias)
    +0x05  4B   (zero)            all-zero across the 8 corpus records
    +0x09  1B   record_kind       u8, 0=header / 1=entry
    +0x0A  1B   const_0x02_0a     u8, constant 0x02 (``subscriber_count`` is a
                                   deprecated alias; not a count)
    +0x0B  1B   entry_index       u8, 0=header / 1..3=entries
    +0x0C  ...  entry payload / header 0x01+5×0xFF marker

Field grounding (sibling 0x19A9 precedent)
==========================================
Sibling 0x19A9 (same FN980 firmware, same discovery captures) has its
byte[1:5] F3-confirmed as a ~1 ms timetick, and its "subscriber count"
reading ruled out by F3. The same questions apply here.

**No F3 source exists for 0x1C53.** Its only two bearing captures (full
reboot, and boot + GNSS, both post-reset) carry ZERO decodable F3: bare
``0x79``/``0x99``/``0x92`` = 0, and the thousands of ``0x98`` multi-radio
envelopes wrap 0 inner F3. The F3 extractor returns 0 records on both; the
same extractor reads 632,497 records on a SIM8202G-M2 control, so the zero
is a measurement, not a tooling miss. 0x1C53 is FN980-firmware-EXCLUSIVE,
so no other capture can supply F3.

**timetick (u32 @1), grounded against the capture's own clock.** Across
BOTH independent boots the header→entry-burst gap is exactly 62464 ticks of
the diag inner ``log_time`` timebase for exactly +1 in byte[1:] — i.e.
byte[1:] is a linear function of the diag clock, not a handle. At the SDX55
inner-tick rate (~17.24 ns) that is ≈1.08 ms; at the outer ts64 rate
(19.07 ns) ≈1.19 ms — either way ≈1 timetick unit ≈ 1 ms, matching 0x19A9's
F3-confirmed ~1 ms tick. Absolute values (~42051 / ~41702) ≈ boot uptime in
ms. The field is u32 to mirror 0x19A9 (bytes[3:5] are zero at the ~42 s
uptime observed).

**const_0x02_0a is not a subscriber count.** byte[10] is constant 0x02
across all 8 records (header AND entries, both boots). Two independent
reasons the "subscriber count" reading fails: (a) its only cross-code
support was a "baseband counts subscribers per layer" hypothesis for 0x19A9,
which F3 rules out; (b) it is self-inconsistent — a count of the 3 entries
(entry_index 1/2/3) would read 3, not 2. Hence the claim-free name
``const_0x02_0a``; ``subscriber_count`` is kept as a deprecated alias and
the invariant is enum[2].

Open (would need FN980 modem-image disassembly): confirm the u32 width
directly (no capture exceeds 65.5 s uptime, so the high bytes are never
exercised), and name what const_0x02_0a and the 3 entries actually encode.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


NR5G_ML1_1C53_SIZE = 28


# --- Validation notes ------------------------------------------------------
# This code is FN980-firmware-EXCLUSIVE in the corpus (absent on Sierra
# EM9190 SDX55, Telit LM960 SDX24, Quectel RM520N-GL SDX62) and BOOT-ONLY: a
# 4-record burst per post-reset (1 header + 3 indexed entries). A reboot is
# therefore the only trigger. The 3 entries are hypothesised to be 3 NR5G
# bands / chains ML1 tracks even with no 5G registration.
# byte 9 record-kind values
_KIND_HEADER = 0
_KIND_ENTRY = 1


@dataclass
class Diag0x1C53:
    """NR5G ML1 0x1C53 — boot-only 28B fixed record.

    Two record kinds within a 4-record-per-boot burst:
      - record 0: header (kind=0), trailing 0x01 + 5 × 0xFF marker
      - records 1-3: entries (kind=1), indexed 1/2/3 at byte 11

    ``boot_handle`` / ``subscriber_count`` are deprecated aliases kept for
    schema compatibility.
    """

    log_time: int
    version: int           # u8 @ 0 — on-wire version, always 0x01
    timetick: int          # u32 LE @ 1 — ~1 ms boot timetick
    record_kind: int       # u8 @ 9 — 0=header, 1=entry
    const_0x02_0a: int     # u8 @ 10 — constant 0x02 (not a subscriber count)
    entry_index: int       # u8 @ 11 — 0 for header; 1..3 for entries
    raw_payload: bytes

    @property
    def boot_handle(self) -> int:
        """Deprecated alias for :attr:`timetick`."""
        return self.timetick

    @property
    def subscriber_count(self) -> int:
        """Deprecated alias for :attr:`const_0x02_0a` (not a subscriber count)."""
        return self.const_0x02_0a

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1C53",
            "log_time": self.log_time,
            "version": self.version,
            "timetick": self.timetick,
            "boot_handle": self.timetick,           # deprecated alias
            "record_kind": self.record_kind,
            "const_0x02_0a": self.const_0x02_0a,
            "subscriber_count": self.const_0x02_0a,  # deprecated alias
            "entry_index": self.entry_index,
            "raw_payload": self.raw_payload.hex(),
        }


@register(0x1C53,
    name="0x1C53",
    description="NR5G ML1 boot-only 28B fixed record (Telit FN980 SDX55, 1 header + 3 indexed entries per post-reset; byte[1:5] is a ~1 ms timetick)",
    version=2, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="FN980 SDX55 edge-case captures (2 captures × 4 records, one boot each); the code is absent on Sierra EM9190 SDX55 (despite a reboot in scope; sibling 0x19A9 fires there), on Telit LM960 SDX24 reboots, and on Quectel RM520N-GL SDX62 runtime captures, so emission is so far FN980-firmware-specific. No F3 exists for 0x1C53 (both bearing captures decode 0 F3 frames; the extractor reads positive on a SIM8202G control), so fields are grounded against the capture's own diag clock: byte[1:5] increments +1 per 62464 inner-log_time ticks (~1 ms) identically across both boots -> timetick (u32; boot_handle kept as a deprecated alias), mirroring 0x19A9. byte[10] is constant 0x02 -> const_0x02_0a (subscriber_count kept as a deprecated alias): not a count (2 != the 3 entries a count would give, and the 0x19A9 cross-code support is ruled out by F3).",

    issues=(),
    primary_issue=None,
    fields_identified=6, fields_parsed=5,
    field_invariants={
        "version": {"enum": [1]},
        "record_kind": {"enum": [_KIND_HEADER, _KIND_ENTRY]},
        "const_0x02_0a": {"enum": [2]},
        "entry_index": {"range": (0, 0xFF)},
    },
    )
def parse_0x1c53(log_time: int, data: bytes) -> Diag0x1C53 | None:
    if len(data) != NR5G_ML1_1C53_SIZE:
        return None
    if data[0] != 1:
        return None
    return Diag0x1C53(
        log_time=log_time,
        version=data[0],
        timetick=unpack_from("<I", data, 1)[0],
        record_kind=data[9],
        const_0x02_0a=data[10],
        entry_index=data[11],
        raw_payload=bytes(data),
    )
