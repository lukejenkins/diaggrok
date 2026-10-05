"""NR5G ML1 measurement-occasion database parser (0xB8CB).

Both on-wire versions carry one nested-TLV container of per-occasion
entries, each stamped with an NR SFN/slot word and 24-bit USTMR (19.2 MHz)
timestamps. Neither version carries cell identity or signal level: this
code is not a per-cell RSRP/RSRQ/SINR table (see "No per-cell identity or
signal" below).

Header (version-dependent, then the TLV container):

    v0x02 (SDX55 / SDX65 — RM500Q, EM9190, RXM-G1, M2000, FN980, LV55, SIM8202):
        [0:4]   u32  header_word = 0x00000002  (byte0 = version)
        [4:]    TLV container (type 0xFC)
    v0x00 (SDX62 — RM520N-GL, Inseego M3100):
        [0:4]   u32  header_word = 0x00020000  (byte0 = 0, byte2 = 0x02)
        [4:8]   u32  header_word1 — per-record; differs between the 0xB8CB
                     and 0xB8C5 records of the same instant; raw
        [8:12]  u32  header_word2 — small value; 1 on RM520N-GL, but
                     {1,2,3,4,22,23,373,374} on the M3100, so not a
                     constant; raw
        [12:]   TLV container (type 0xFC)

TLV header (4 bytes, little-endian u32 bitfield):

    bits  0..7   type   (0xFC container · 0x06/0x08/0x09 entry · 0xFE marker)
    bits  8..19  len    total TLV length INCLUDING this header
    bits 20..31  tag    small per-TLV qualifier

The record is exactly one 0xFC container spanning the rest of the payload
(byte 4 is the container type 0xFC and bytes 5..6 its length; this is not
a ``config_id`` field). Its children are a flat run of entries interleaved
with 4-byte 0xFE markers (0xFE tag 0xB after a 0x08 entry, 0x7 after a
0x06 entry, 0x1/0xA closing the record). The 16-byte idle sentinel
``02000000 fc0c0000 fe041000 fe041000`` is a container holding just two
markers.

Entry body (offsets relative to the end of the 4-byte TLV header):

    +0   u32  entry_rev    per-(version,type) constant (v0x02: 3 for 0x06/
                           0x08, 2 for 0x09; v0x00: 0 for 0x08/0x09, 0x10 for
                           0x06). The first entry's entry_rev sits at payload
                           offset 12, where its {2,3} values can be mistaken
                           for a component-carrier count; F3 rules that out.
    +4   u32  timing word  bits 0..4  timing_lo5 ({2,3,0} — raw)
                           bits 5..9  slot  (0..19 — 30 kHz SCS, μ=1)
                           bits 10..19 sfn  (0..1023)
                           bits 20..31 timing_hi (0 on SDX55; 0/0x20 SDX62)
    +8   u32  word_08      small enum per entry kind — raw
    +12  u32  word_12      mask-like — raw
    +16  u32  word_16      mask-like — raw
  type 0x08 (len 44) / 0x09 (len 40):
    +20  u32  ustmr_a  ┐ 24-bit USTMR timestamps (19.2 MHz, wrap 0.874 s);
    +24  u32  ustmr_b  │ a ≤ b always, b ≤ c on 99.9 % (mod 2^24); all
    +28  u32  ustmr_c  ┘ within ~1 slot of the entry's sfn/slot
    +32  u32  word_32      raw (0 or k*0x1E000 + 0x10/0x90 — raw)
    +36  u32  word_36      type 0x08 only — raw (word_32 + 5, or 0xFFFFFFFF)
  type 0x06 (len 28):
    +12..+23  word_12 / word_16 / word_20 raw (mask-like, no timestamps)

Grounding (F3-grounded on v0x02 and v0x00):

* USTMR clock: across 6,260 dense RXM-G1 records from an F3-enabled
  capture, unwrapped ustmr_a regresses against the DIAG log timestamp at
  19,199,987 Hz (−0.7 ppm from 19.2 MHz) with sub-ms residuals; all three
  timestamps sit within ~0.7 ms of the record's own log time.
* SFN/slot: the slot bits take exactly the 20 values 0..19 (never 20..31)
  on SDX55 and SDX62. Consecutive same-type entries advance their USTMR by
  9,600 ticks (0.5 ms) per slot step: 93.4 % within ±0.5 slot on ustmr_b
  (RXM-G1, n=84,956); 95.7 % / 93.3 % on ustmr_c (RM520N-GL / M3100
  v0x00), all within ±1 slot.
* v0x00 clock: the same 24-bit counters advance at 19.26 MHz (RM520N-GL)
  and 19.23 MHz (M3100) over short consecutive-record pairs, i.e. 19.2 MHz
  within the ±0.7 ms log-time jitter.
* TLV tree, corpus-wide (all 165 captures carrying the code, decoded with
  this parser via ``diaggrok.parse``): v0x02 2,454,292 / 2,454,386 parse
  (155 captures), v0x00 162,005 / 162,006 (9 captures). Rejects:
  20 records of a 2,056 B form whose top TLV is 0xFD (not 0xFC) on 6
  RM500Q captures, with an entry body following the 4-byte header (likely
  a buffer-capped spill; returned as None, layout not yet decoded); 75
  container/payload length mismatches from a merged multi-modem UDP stress
  capture (misframes, including the code's only byte0=0x10 record); 1
  truncated 239 B M2000 frame. slot ∈ 0..19 and USTMR < 2^24 hold on every
  one of the 8.77 M timed entries but one. One 992-record EM9190 capture
  could not be replayed and is not counted.
* No per-cell identity or signal: no v0x02 record of the RXM-G1 capture
  carries the F3-witnessed serving PCI 596 or NR-ARFCN 521310 (2
  coincidental u16 hits in 11,335 records). The continuously varying
  fields are timing only, so the code is not ``wigle_direct`` (cf. 0x1C64).
* F3 — SFN grounded by time-join: the firmware's own ``nrfw_iu_cfg.c``
  print "cmd id = N, sfn = M" (plaintext 0x79) is matched by an entry
  ``sfn`` of a 0xB8CB record logged within ±20 ms of it:
    RXM-G1   v0x02  :4423   50/50   exact (null sfn+37: 0/50)
    RM500Q-AE v0x02 :4423  904/924  exact (null: 0/924)
    RM520N-GL v0x00 :5014  238/244  exact (null: 0/244; t+3.7 s: 0/128)
  This is the same print site 0xB8C5's SFN is grounded on; its subframe
  bits [6:10] are this code's slot bits [6:10] (slot = 2·subframe + bit 5
  at 30 kHz SCS). Beyond SFN, F3 is silent: a join of every ≥17-bit word
  against all F3 args (RXM-G1 and RM520N-GL message databases) finds only
  coincidental MCPM/VADC/SQP hits.
* 0x60 events: none in the RXM-G1 capture; present on RM520N-GL (v0x00)
  and RM500Q (v0x02) but silent (chance-rate payload-window joins; the
  constant LTE EARFCN 66786 in ids 3266/2568/3251 collides with one timing
  word). Open-source decoders: QCSuper emits RRC/NAS GSMTAP only; SCAT
  decodes 0xB97F ("NR ML1 Meas Packet") but emits nothing for 0xB8CB.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_NR5G_ML1_MEAS_DB = 0xB8CB

TLV_CONTAINER = 0xFC
TLV_MARKER = 0xFE
# entry type → body words that are USTMR timestamps
_USTMR_TYPES = (0x08, 0x09)


def _tlv_header(data: bytes, off: int) -> tuple[int, int, int]:
    """Return (type, len, tag) of the 4-byte TLV header at ``off``."""
    w = unpack_from("<I", data, off)[0]
    return w & 0xFF, (w >> 8) & 0xFFF, w >> 20


@dataclass
class Nr5gMeasDbEntry:
    """One child TLV of the 0xB8CB container (entry or 0xFE marker)."""

    tlv_type: int
    tlv_len: int
    tlv_tag: int
    entry_rev: int | None = None
    timing_word: int | None = None
    sfn: int | None = None
    slot: int | None = None
    timing_lo5: int | None = None
    timing_hi: int | None = None
    # USTMR (19.2 MHz, 24-bit) — types 0x08 / 0x09 only
    ustmr_a: int | None = None
    ustmr_b: int | None = None
    ustmr_c: int | None = None
    # remaining body u32s, raw, keyed by body offset
    raw_words: dict[int, int] = field(default_factory=dict)
    raw_tail: bytes = b""  # body bytes past the last whole u32 (unknown type)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tlv_type": self.tlv_type,
            "tlv_len": self.tlv_len,
            "tlv_tag": self.tlv_tag,
        }
        if self.entry_rev is not None:
            d.update({
                "entry_rev": self.entry_rev,
                "timing_word": self.timing_word,
                "sfn": self.sfn,
                "slot": self.slot,
                "timing_lo5": self.timing_lo5,
                "timing_hi": self.timing_hi,
            })
        if self.ustmr_a is not None:
            d.update({
                "ustmr_a": self.ustmr_a,
                "ustmr_b": self.ustmr_b,
                "ustmr_c": self.ustmr_c,
            })
        for k, v in self.raw_words.items():
            d[f"word_{k:02d}"] = v
        if self.raw_tail:
            d["raw_tail"] = self.raw_tail.hex()
        return d


@dataclass
class Diag0xB8CB:
    """NR5G ML1 measurement-occasion database (0xB8CB), v0x02 or v0x00."""

    log_time: int
    version: int
    header_word: int
    header_word1: int | None  # v0x00 only, raw
    header_word2: int | None  # v0x00 only, raw (not constant)
    container_len: int
    container_tag: int
    payload_size: int
    num_entries: int  # non-marker children (types 0x06/0x08/0x09/…)
    num_markers: int  # 0xFE children
    entries: list[Nr5gMeasDbEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "Diag0xB8CB",
            "log_time": self.log_time,
            "version": self.version,
            "header_word": self.header_word,
            "container_len": self.container_len,
            "container_tag": self.container_tag,
            "payload_size": self.payload_size,
            "num_entries": self.num_entries,
            "num_markers": self.num_markers,
        }
        if self.header_word1 is not None:
            d["header_word1"] = self.header_word1
            d["header_word2"] = self.header_word2
        if self.entries:
            d["entries"] = [e.to_dict() for e in self.entries]
        return d


def _decode_child(data: bytes, off: int, t: int, ln: int, tag: int) -> Nr5gMeasDbEntry:
    e = Nr5gMeasDbEntry(tlv_type=t, tlv_len=ln, tlv_tag=tag)
    body = off + 4
    end = off + ln
    if t == TLV_MARKER or ln < 12:
        if end > body:
            e.raw_tail = bytes(data[body:end])
        return e
    e.entry_rev = unpack_from("<I", data, body)[0]
    w = unpack_from("<I", data, body + 4)[0]
    e.timing_word = w
    e.timing_lo5 = w & 0x1F
    e.slot = (w >> 5) & 0x1F
    e.sfn = (w >> 10) & 0x3FF
    e.timing_hi = w >> 20
    k = 8
    while body + k + 4 <= end:
        v = unpack_from("<I", data, body + k)[0]
        if t in _USTMR_TYPES and k == 20:
            e.ustmr_a = v
        elif t in _USTMR_TYPES and k == 24:
            e.ustmr_b = v
        elif t in _USTMR_TYPES and k == 28:
            e.ustmr_c = v
        else:
            e.raw_words[k] = v
        k += 4
    if body + k < end:
        e.raw_tail = bytes(data[body + k:end])
    return e


@register(LOG_NR5G_ML1_MEAS_DB,
    name="0xB8CB",
    wigle_direct=False,
    wigle_roles=("rat-context",),
    description=(
        "NR5G ML1 measurement-occasion DB — nested TLV (0xFC container of "
        "0x06/0x08/0x09 entries + 0xFE markers), per-entry SFN/slot + 24-bit "
        "USTMR 19.2 MHz timestamps; v0x02 (SDX55/65) + v0x00 (SDX62)"
    ),
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Decoded from SDX55 (RM500Q) captures and a corpus-wide walk of "
        "v0x02 and the SDX62 v0x00 variant: both versions are one nested-TLV "
        "container. USTMR timestamps regress at 19.2 MHz against DIAG log "
        "time and SFN/slot advance at 9,600 ticks/slot on RXM-G1 (v0x02) and "
        "RM520N-GL/M3100 (v0x00); entry SFN matches the firmware's F3 SFN "
        "print. Non-timing entry words remain raw."
    ),
    source_url="",
    supported_versions=(0x00, 0x02),
    field_invariants={
        "version": {"enum": [0x00, 0x02]},
        "header_word": {"enum": [0x00000002, 0x00020000]},
    },
    issues=(),
    primary_issue=None,
    fields_identified=16,
    fields_parsed=16,
)
def parse_0xb8cb(log_time: int, data: bytes) -> Diag0xB8CB | None:
    """Parse 0xB8CB — both versions into one TLV-tree decode.

    Returns None when the header is not a known version or the payload is
    not exactly one well-formed 0xFC container (malformed / misframed).
    """
    if len(data) < 8:
        return None
    if data[0] not in (0x00, 0x02):  # Layer-1 version gate
        return None
    version = data[0]
    header_word = unpack_from("<I", data, 0)[0]
    if version == 0x02:
        start = 4
        header_word1 = header_word2 = None
    elif version == 0x00:
        if len(data) < 16:
            return None
        start = 12
        header_word1 = unpack_from("<I", data, 4)[0]
        header_word2 = unpack_from("<I", data, 8)[0]
    else:
        return None

    t, ln, ctag = _tlv_header(data, start)
    if t != TLV_CONTAINER or ln != len(data) - start:
        return None

    entries: list[Nr5gMeasDbEntry] = []
    off = start + 4
    end = start + ln
    while off < end:
        if end - off < 4:
            return None
        ct, cl, cg = _tlv_header(data, off)
        if cl < 4 or off + cl > end:
            return None
        entries.append(_decode_child(data, off, ct, cl, cg))
        off += cl

    n_markers = sum(1 for e in entries if e.tlv_type == TLV_MARKER)
    return Diag0xB8CB(
        log_time=log_time,
        version=version,
        header_word=header_word,
        header_word1=header_word1,
        header_word2=header_word2,
        container_len=ln,
        container_tag=ctag,
        payload_size=len(data),
        num_entries=len(entries) - n_markers,
        num_markers=n_markers,
        entries=entries,
    )
