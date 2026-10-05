"""0x1D36 — IPA WAN bearer-stats snapshot at bearer deregistration.

The 144 B payload is not mostly zero: on a single chipset in idle mode it
can look that way, but across four chipset families it carries a populated
counter block.

Corpus (sampled walk, 649 unique records; manifest 855 records / 41
captures, all v0x00 / 144 B): RM520N-GL SDX62 (two firmware builds), Inseego
M3100, Sierra EM9291, Foxconn T99W373/T99W640. The first 28 of 41
code-bearing captures were walked in full, plus both EM9291 captures (the only
unsampled chipset family); the remaining 11 are RM520N-GL/M3100 captures whose
families the sample already covers. The version + size gate holds
corpus-wide.

Layout (little-endian; every byte also stays exposed raw in ``body_raw``)::

    +0   u8   version        == 0x00 (gated)
    +4   u32  config_word    == 4 on all 649 sampled records, all 4 families
    +8   u8   valid_mask     field-presence bitmask (see below)
    +8   u32  status_word    raw; bytes +9..+11 carry further flag bits
    +12  u32  word_12        raw; bit 31 toggles per record (RM520N/EM9291)
    +16  u8   stream_id      CANDIDATE counter-set/instance id
    +17  u8   bearer_uid     IPA WAN bearer uid — F3-GROUNDED
    +20  u64  pkts_0         packet counter, slot 0 (mask bit 1)
    +28  u64  pkts_1         packet counter, slot 1 (mask bit 2)
    +36  u64  bytes_0        byte counter,   slot 0 (mask bit 3)
    +44  u64  bytes_1        byte counter,   slot 1 (mask bit 4)
    +52..+143                raw (zero on RM520N/EM9291; M3100 fills +68..+143
                             with pointer-shaped 0xC832xxxx/0xE00Cxxxx words)

**valid_mask (byte +8) ⇔ counter slots — structural, measured.** Bit N
(N=1..4) gates the u64 at ``+20 + 8*(N-1)``: across 649 records, 0 records
carry a non-zero counter whose bit is clear (all 2,222 non-zero
slot-values have their bit set: 571/540/571/540 on slots +20/+28/+36/+44). EM9291
emits single-bit records (mask 0x02/0x04/0x08/0x10) that populate exactly one
slot. Bits 0, 5, 6, 7 are unmapped (M3100 emits 0x7F; RM520N 0x1E).

**bearer_uid (byte +17) — F3-grounded.** On an RM520N-GL build with fully
resolved F3, every 0x1D36 record is bracketed by the IPA WAN driver's
own prints for the same bearer: ``ipa_wan.c:2255 "WAN get Bearer stats: …
uid = N"`` 363–719 ticks BEFORE, and ``ipa_wan.c:1184 "WAN DS Bearer
Deregister : … uid = N"`` 227–633 ticks AFTER, with ``N == byte +17`` on
7/7 records across 2 captures (a data-connection capture: uids
21,21,20,20,22; an NR capture: uids 24,25). Coincidence baseline: P(an
ipa_wan:2255 print within 1000 ticks before a random timestamp) < 1e-5
over the connection capture (313 prints / 1.5e11 ticks). Byte +17 is not a
sequence counter; it only looks monotonic because bearer uids are
allocated incrementally. The code is therefore a final-stats dump emitted
at bearer deregistration by the data-services (``ds_*`` / ``ipa_wan``)
subsystem, not an NR5G ML1 log.

**pkts/bytes pairing — measured, direction CANDIDATE.** On every record
where both halves of a pair are non-zero, bytes/pkts falls inside IP packet
sizes: slot 0 42–368 B/pkt (n=569), slot 1 48–1425 B/pkt (n=539). The
connection capture's uid-21 record's ``pkts_1 == 20`` equals the co-temporal
``ipa_wan.c:2255 "stats ipv4 = 20"`` (n=1, so corroborating, not
grounding). Slot 1 reaching MTU-sized 1425 B/pkt on a bulk transfer
(3,654 pkts / 5,206,128 B) while slot 0 stays ACK-sized (66 B/pkt) makes
slot 1 the CANDIDATE downlink and slot 0 the CANDIDATE uplink — named
neutrally (``_0``/``_1``) until an oracle labels the direction.

**stream_id (byte +16) — CANDIDATE.** Keys distinct counter sets for one
bearer: the connection capture's uid-21 bearer emits a 0x21 record and a 0x40 record
with different counters; EM9291 emits 0x10..0x60 with stable per-id counters.
No oracle labels it.

Oracles: F3 as above. ``0x60`` events: ABSENT — the F3-bearing captures are
``.dlf`` (demuxed LOG records; structurally cannot carry an outer ``0x60``
frame). QCSuper / SCAT / rayhunter: none of them decodes 0x1D36.

Size invariance is not format invariance: a v != 0x00 emission at the
same 144 B size MUST be rejected, not mis-parsed.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_1D36_VERSION_OBSERVED = 0x00
_1D36_PAYLOAD_SIZE_OBSERVED = 144
# valid_mask bit N (N=1..4) gates the u64 counter at +20 + 8*(N-1).
_1D36_COUNTER_OFFSETS = (20, 28, 36, 44)


@dataclass
class Diag0x1D36:
    """0x1D36 — IPA WAN bearer-stats snapshot at bearer deregistration."""
    log_time: int
    version: int
    config_word: int
    valid_mask: int
    status_word: int
    word_12: int
    stream_id: int
    bearer_uid: int
    pkts_0: int
    pkts_1: int
    bytes_0: int
    bytes_1: int
    counters_valid: tuple[bool, bool, bool, bool]
    data_density: float
    payload_size: int
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1D36",
            "log_time": self.log_time,
            "version": self.version,
            "config_word": self.config_word,
            "valid_mask": self.valid_mask,
            "status_word": self.status_word,
            "word_12": self.word_12,
            "stream_id": self.stream_id,
            "bearer_uid": self.bearer_uid,
            "pkts_0": self.pkts_0,
            "pkts_1": self.pkts_1,
            "bytes_0": self.bytes_0,
            "bytes_1": self.bytes_1,
            "counters_valid": list(self.counters_valid),
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }


@register(
    0x1D36,
    name="0x1D36",
    description="0x1D36 — IPA WAN bearer-stats snapshot at bearer deregistration: bearer_uid (F3-grounded, ipa_wan.c) + valid-mask-gated u64 pkts/bytes counters",
    version=2,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "4-chipset corpus (RM520N-GL SDX62, Inseego M3100, Sierra EM9291, "
        "Foxconn T99W373/T99W640; 649 sampled records). bearer_uid F3-grounded "
        "7/7 against ipa_wan.c:2255/1184 uid prints on RM520N-GL; valid_mask bit<->counter-slot rule 0 violations / 649."
    ),
    source_url="",
    issues=(),
    fields_identified=11,
    fields_parsed=11,
    field_invariants={
        "version": {"enum": [_1D36_VERSION_OBSERVED]},
        "payload_size": {"enum": [_1D36_PAYLOAD_SIZE_OBSERVED]},
    },
)
def parse_0x1d36(log_time: int, data: bytes) -> Diag0x1D36 | None:
    if len(data) != _1D36_PAYLOAD_SIZE_OBSERVED:
        return None
    version = data[0]
    if version != _1D36_VERSION_OBSERVED:
        return None
    config_word = unpack_from('<I', data, 4)[0]
    status_word, word_12 = unpack_from('<II', data, 8)
    valid_mask = data[8]
    pkts_0, pkts_1, bytes_0, bytes_1 = (
        unpack_from('<Q', data, off)[0] for off in _1D36_COUNTER_OFFSETS
    )
    nonzero = sum(1 for b in data[2:] if b != 0)
    density = round(nonzero / (len(data) - 2), 2)
    return Diag0x1D36(
        log_time=log_time,
        version=version,
        config_word=config_word,
        valid_mask=valid_mask,
        status_word=status_word,
        word_12=word_12,
        stream_id=data[16],
        bearer_uid=data[17],
        pkts_0=pkts_0,
        pkts_1=pkts_1,
        bytes_0=bytes_0,
        bytes_1=bytes_1,
        counters_valid=tuple(bool(valid_mask >> n & 1) for n in range(1, 5)),
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
