"""NR5G ML1 Meas 0xB8B5 — chipset-divergent structural decode.

The log name is ``LOG_NR5G_MAC_TX_PWR_DIST_STATS_LOG``. The framing is
documented (version, size class, field offsets) and the per-carrier NR band is
F3-grounded; the remaining slot fields are surfaced as named raw u32 fields
because their meaning is not yet known.

Size classes are discriminated by the ``version`` u32 at ``[0:4]`` AND the
payload length (a 638-record / 48-capture walk established the original three;
more forms are listed below):

  * **SDX62 v3, 28B** (``version == 0x00030000``) — the populated record
    (RM520N-GL / EM9291 SDX62). field_a/field_b/field_c/field_d carry
    measurement state; most are zero when idle, populated under load.
  * **SDX62 v3 header-only, 12B** (``version == 0x00030000``, len 12) — the
    zero-entry form of the same version: ``version + field_a + tail`` only.
    Appears ~1/scenario at session start (158 records corpus-wide). Not a
    distinct version — byte0 is 0x00 for all classes because the version is
    a little-endian u32 (= 0x00030000 here).
  * **SDX55 v2, 98B** (``version == 0x00020000``) — mostly-zero TLV shell
    with a monotonic counter (EM9190 SDX55).

=== v3 entry layout, minor revision and 90B shell ===

  * **The 12B / 28B / 44B classes are one layout.** byte[8] (the low byte of
    ``field_b``) is an entry count and ``len == 12 + 16 * byte[8]``: a 12-byte
    header (version, field_a, field_b) then ``count`` 16-byte entries of
    ``field_d u32, field_c u32, tail 8B``. 12B = 0 entries (the "header-only"
    form, byte[8]=0x00), 28B = 1 entry, 44B = 2 entries (Foxconn T99W373 SDX35
    and T99W640 SDX7x). The gate cross-checks the count against the wire, so a
    crossed pair is a rejected misframe, not a mis-parse. ``entries`` carries
    every entry; ``field_d`` / ``field_c`` / ``tail`` are entry 0.
  * **``version == 0x00030001``** (byte[0]=0x01, subversion still 0x03) — the
    same entry layout on the Foxconn T99W640 bring-up capture (28B + 44B).
  * **90B TLV shell** at ``version == 0x00030000`` (Inseego M3100; RM520N-GL
    under QSH throughput) — the SDX55 98B shell with 8 fewer bytes before the
    marker: marker u8 @7 (0x01), tlv_header u32 @8 (tag 0x0001 + len
    {0x4c,0x28}; 0 idle), counter u32 @12 (monotonic), counter2 u16 @18
    (monotonic), rest zero. Not a 12+16n size, so it cannot collide with the
    entry rule.

Anything else returns None, so the registry WARN and tally fire: the code
fails loudly on an unexpected size rather than dropping it silently or forcing
it into a layout it does not match.

=== The NR band, F3-grounded per u32 version ===

Each v3 entry's ``field_d`` is the **NR operating band minus one**, and both
shells carry the same index in ``tlv_header``'s high u16 (low u16 = 0x0001; the
whole word is 0 when idle). Surfaced as the DERIVED ``nr_band`` (per entry, and
entry 0 / the shell at top level); the raw fields are unchanged. An all-zero
16-byte entry is an empty carrier slot (``nr_band`` None), not band n1.

  * **F3 (labeled).** ``rfe_nr5g_txpl.c`` ``rfi_nr5g_tx_convert_ota_ns: cc_idx
    %d valid flag %d with nr_band %d`` fires ~1 ms before the record; entry i ==
    cc_idx i. T99W373 (v3 28B + 44B): 26/26 entries (24 equal the current cc
    band, 2 at a band change equal the outgoing one — the stats close on the
    old carrier). FT980M SDX55 (v2 98B): 2/2 (n77).
  * **0xB825 RRC config band list** (its parser is F3/QCSuper-grounded), full
    1,858-record / 88-capture walk: every populated entry or shell is in the
    nearest B825 band set — 986 the previous one, 9 the next (the record leads
    the RRC snapshot at a band change). Bands seen: n5/n25/n41/n66/n71/n77.
  * **v0x00030001** (T99W640 bring-up, a log-only DLF: F3 and 0x60 absent): 11
    records, bands n25/n41 — the capture's own 0xB825 and QCSuper NR-RRC
    (NR-ARFCN 521310/501390 = n41, 387170 = n25) agree.
  * The 2-entry records are NR UL CA: n71 PCell + n41 SCell on T99W373.

``field_a`` / ``field_b`` (bytes 9-11) / ``field_c`` / ``tail`` and the shell
counters are unlabeled by F3 and 0x60 — raw.

Layer-2 invariants: none of the per-field values is constant corpus-wide.

  * ``field_d`` (``[12:16]``) takes 7 values corpus-wide —
    0x28/0x41/0x00/0x4c/0x04/0x46/0x18 — with intra-capture variance (it is the
    band index above).
  * the 8-byte tail ``[20:28]`` is not all-zero on active captures (byte 26 is
    a small varying int 0x00..0x0c) — preserved raw as ``tail``.
  * the v2 ``tlv_header`` (and the marker word) is all-zero on idle v2
    records — state-dependent, not invariant.

So the only hard layer-2 invariants are the structural anchors: ``version``,
``subversion`` and ``payload_size`` (the observed sizes). All other fields are
surfaced for downstream semantic work but not asserted as value-invariant.

Log name: LOG_NR5G_MAC_TX_PWR_DIST_STATS_LOG
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


_B8B5_PKT_VER_SDX62 = 0x00030000  # v3 entry layout (12+16n B) + 90B TLV shell
# v3 minor revision (byte[0]=0x01): same 12+16n entry layout, observed on the
# Foxconn T99W640 (SDX7x) bring-up capture at 28B and 44B.
_B8B5_PKT_VER_SDX62_R1 = 0x00030001
_B8B5_PKT_VER_SDX55 = 0x00020000  # 98B layout (SDX55 EM9190 v2)
# Convention-correct NR5G subversion (byte[2]) = version >> 16. Declared as its
# own value-invariant; coupled to the u32 version enum above by construction.
_B8B5_SUBVER_SDX62 = 0x03          # byte[2] for the SDX62 v3 family
_B8B5_SUBVER_SDX55 = 0x02          # byte[2] for the SDX55 v2 family
_B8B5_SIZE_SDX62 = 28             # SDX62 v3 populated record
_B8B5_SIZE_SDX62_HDR = 12         # SDX62 v3 header-only / truncated record
_B8B5_SIZE_SDX55 = 98             # SDX55 v2 record
# v3 entry layout: 12-byte header (version, field_a, field_b whose low byte is
# the entry count) + count * 16-byte entries — so len == 12 + 16*byte[8].
_B8B5_V3_HDR = 12
_B8B5_V3_ENTRY = 16
_B8B5_SIZE_V3_2ENTRY = 44         # 2-entry form (T99W373 SDX35, T99W640 SDX7x)
_B8B5_SIZE_SHELL = 90             # v3 TLV-shell form (Inseego M3100, RM520N-GL)
_B8B5_V3_VERSIONS = (_B8B5_PKT_VER_SDX62, _B8B5_PKT_VER_SDX62_R1)


def _shell_nr_band(tlv_header: int) -> int | None:
    """NR band from a shell's tlv_header: high u16 = band - 1, low u16 = 0x0001;
    0 = idle (no carrier). F3-grounded on the SDX55 98B form."""
    return (tlv_header >> 16) + 1 if tlv_header else None


@dataclass
class Diag0xB8B5:
    """NR5G ML1 Meas 0xB8B5 — structural decode, chipset-divergent.

    Header convention (all variants): byte[0]=version=0x00 (const), byte[2]=
    subversion (0x03 SDX62 / 0x02 SDX55). The u32 read at [0:4] == subversion
    << 16 and is what this parser gates on (a stronger check than byte[2] alone
    — it also pins bytes 0/1/3 to zero). subversion is surfaced separately to
    match the 0xB971 convention.

    SDX62 v3 populated variant (28B, version=0x00030000):
      [0:4]   version u32 (0x00030000; == subversion<<16, subversion=byte[2]=0x03)
      [4:8]   field_a u32 (byte[7]=0x01 anchor; freely varying body)
      [8:12]  field_b u32 (byte[8]=0x01 anchor; u8 tag + u24 value)
      [12:16] field_d u32 (NR band - 1; 7 values with intra-capture
              variance: {0,4,24,40,65,70,76})
      [16:20] field_c u32 (measurement magnitude candidate)
      [20:28] tail 8 bytes raw (not reserved-zero on active captures;
              byte 26 is a small varying int)

    SDX62 v3 header-only variant (12B, version=0x00030000):
      [0:4]   version u32 (0x00030000)
      [4:8]   field_a u32 (byte[7]=0x01 anchor — same offset/role as 28B)
      [8:12]  tail 4 bytes raw (byte[8]=0x00; small field). is_header_only=True.

    SDX55 v2 variant (98B, version=0x00020000) — on-wire layout locked
    against 35 real EM9190 v2 records across 6 captures (every record has
    marker@15==0x01):
      [0:4]   version u32 (0x00020000)
      [4:15]  11 bytes reserved (all-zero corpus-wide)
      [15]    marker u8 (constant 0x01 across every observed v2 record)
      [16:20] tlv_header u32 (tag=0x0001 + len∈{0x004c,0x0028,0x0046}; 0 idle)
      [20:24] counter u32 (free-running, monotonic within a capture; 0 idle)
      [24:98] 74 bytes reserved (all-zero corpus-wide; incl. the 70B TLV body)

    Reading these one word late (tlv_header@20 / counter@24) lands on the
    reserved-zero word @24 instead of the counter; the fixtures are real
    byte-for-byte EM9190 records, so the offsets above are pinned.
    """

    log_time: int
    version: int
    # Convention-correct NR5G log-header subversion (byte[2]) — 0x03 (SDX62 v3)
    # or 0x02 (SDX55 v2). This is the field that actually discriminates the
    # chipset family; the u32 `version` above == (subversion << 16). byte[0] is
    # the log-header "version" byte and is a constant 0x00 across all classes,
    # so it does not identify a new version. Surfaced explicitly to match the
    # 0xB971 convention (version@0 + subversion@2) and declared as its own
    # field_invariant (enum {0x02, 0x03}); enforced at Layer-2 by
    # check_invariants and at Layer-1 by the coupled u32 `version` gate.
    subversion: int
    payload_size: int
    # SDX62 v3 fields (None on SDX55). On the 12B header-only variant only
    # field_a + tail are populated and is_header_only is True.
    field_a: int | None = None
    field_b: int | None = None
    field_c: int | None = None
    field_d: int | None = None
    tail: bytes | None = None
    is_header_only: bool = False
    # v3 entry model: entry_count == byte[8]; entries holds
    # every 16-byte entry as {field_d, field_c, tail(hex)}. field_d / field_c /
    # tail above are entry 0 (same meaning as on the 28B form). None on the
    # SDX55 v2 and 90B shell forms.
    entry_count: int | None = None
    entries: list[dict[str, Any]] | None = None
    # 90B TLV-shell form (v3): marker/tlv_header/counter below are reused at
    # shell offsets 7/8/12, plus a second monotonic u16 counter @18.
    is_tlv_shell: bool = False
    counter2: int | None = None
    # NR operating band, DERIVED. Entry forms: entry 0's band (each
    # entry carries its own `nr_band` = field_d + 1). Shells: tlv_header's high
    # u16 + 1. None for an empty slot / idle shell / header-only record.
    nr_band: int | None = None
    # SDX55 v2 fields (None on SDX62). Corpus-locked on-wire offsets:
    # marker u8 @15, tlv_header u32 @16, counter u32 @20.
    marker: int | None = None       # u8 @15 (constant 0x01 across the v2 corpus)
    tlv_header: int | None = None    # u32 @16 (tag 0x0001 + len; 0 on idle)
    counter: int | None = None       # u32 @20 (free-running monotonic; 0 on idle)
    # v2-only: True when the v2 reserved/TLV-body bytes are all zero.
    # Informational (state-dependent), NOT a hard layer-2 invariant.
    reserved_all_zero: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB8B5",
            "log_time": self.log_time,
            "version": self.version,
            "subversion": self.subversion,
            "payload_size": self.payload_size,
            "field_a": self.field_a,
            "field_b": self.field_b,
            "field_c": self.field_c,
            "field_d": self.field_d,
            "tail": self.tail.hex() if self.tail is not None else None,
            "is_header_only": self.is_header_only,
            "entry_count": self.entry_count,
            "entries": self.entries,
            "is_tlv_shell": self.is_tlv_shell,
            "counter2": self.counter2,
            "nr_band": self.nr_band,
            "marker": self.marker,
            "tlv_header": self.tlv_header,
            "counter": self.counter,
            "reserved_all_zero": self.reserved_all_zero,
        }


@register(
    0xB8B5,
    name="0xB8B5",
    # The version is the u32 at [0:4] (0x00020000 / 0x00030000 / 0x00030001),
    # not byte 0 — with the registry default "u8" the loud-version check could
    # not project the declared enum onto the payload.
    version_field="u32le",
    description=(
        "NR5G MAC Tx-power dist stats — per-carrier NR band (F3-grounded) + "
        "raw stats; v3 self-describing 12+16n B entries (+ v0x00030001), 90B "
        "TLV shell, SDX55 v2 98B"
    ),
    version=7,
    author="Claude Code",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Structural decode across four forms keyed by the u32 version and length: "
        "v3 (0x00030000 / 0x00030001) self-describing entries, len == 12 + "
        "16*byte[8] (12/28/44B = 0/1/2 entries; RM520N-GL, EM9291, T99W373, "
        "T99W640); a 90B v3 TLV shell (Inseego M3100, RM520N-GL under QSH) = "
        "the SDX55 98B shell minus 8 leading bytes (marker@7, tlv_header@8, "
        "counter@12, counter2 u16@18); and the SDX55 v2 98B shell (marker u8 "
        "@15, tlv_header u32 @16, counter u32 @20), locked against 35 real "
        "EM9190 records. Any other size returns None (registry WARN). "
        "DERIVED nr_band: each v3 entry's field_d is the NR band - 1 and the "
        "shells carry it in tlv_header's high u16 (low u16 0x0001; 0 idle). F3 "
        "rfe_nr5g_txpl.c 'cc_idx %d ... nr_band %d' (entry i == cc_idx i): "
        "T99W373 26/26, FT980M 2/2; the 0xB825 band list agrees on every "
        "populated record of the 1,858-record / 88-capture corpus; v0x00030001 "
        "(T99W640, log-only DLF) agrees with its own 0xB825 and QCSuper "
        "NR-ARFCNs. An all-zero entry is an empty slot (None). The NR5G "
        "subversion (byte[2]) is surfaced as its own field (0x03 v3 / 0x02 v2; "
        "u32 version == subversion << 16), matching 0xB971. Per-field value "
        "enums do not hold corpus-wide (638-record walk), so only version, "
        "subversion and payload_size are invariants. field_a/field_b/field_c/"
        "tail and the shell counters are unlabeled by F3 and stay raw."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=15,
    fields_parsed=15,
    field_invariants={
        # Structural anchors only: per-field value enums (field_d, tail,
        # tlv_header, reserved_all_zero) do not hold corpus-wide (see the
        # module docstring).
        #
        # `version` (u32 @0) is the Layer-1 gate: its enum simultaneously pins
        # bytes 0/1/3 to 0x00 AND byte[2] to the family. `subversion` (u8 @2) is
        # the convention-correct NR5G subversion the u32 actually carries
        # (version == subversion << 16); it is declared as its own value-
        # invariant and enforced at Layer-2 by check_invariants (the standard
        # path for non-version fields). The two are 100%-coupled by construction,
        # so an off-enum subversion is ALSO rejected at Layer-1 by the version
        # gate (see test_unknown_version_returns_none, which feeds byte[2]=0x04).
        "version": {
            "enum": [_B8B5_PKT_VER_SDX62, _B8B5_PKT_VER_SDX62_R1, _B8B5_PKT_VER_SDX55]
        },
        "subversion": {"enum": [_B8B5_SUBVER_SDX62, _B8B5_SUBVER_SDX55]},
        # Observed sizes (reporting only — the executable gate is the
        # self-describing 12+16*byte[8] rule plus the 90/98 shell literals, so a
        # future 3-entry 60B record parses and is flagged here, not dropped).
        "payload_size": {
            "enum": [
                _B8B5_SIZE_SDX62_HDR,
                _B8B5_SIZE_SDX62,
                _B8B5_SIZE_V3_2ENTRY,
                _B8B5_SIZE_SHELL,
                _B8B5_SIZE_SDX55,
            ]
        },
    },
)
def parse_0xb8b5(
    log_time: int, data: bytes
) -> Diag0xB8B5 | None:
    if len(data) < 4:
        return None
    version = unpack_from("<I", data, 0)[0]
    # Layer-1 version allowlist (mirrors the dispatch below) so the
    # canonical `version` enum has a ratchet-visible rejection.
    if version not in (*_B8B5_V3_VERSIONS, _B8B5_PKT_VER_SDX55):
        return None
    if version == _B8B5_PKT_VER_SDX62 and len(data) == _B8B5_SIZE_SHELL:
        # 90B TLV shell: the SDX55 v2 98B shell with 8 fewer
        # bytes before the marker — marker@7, tlv_header@8, counter@12,
        # counter2 u16@18; [4:7] + [16:18] + [20:90] reserved (zero corpus-wide).
        reserved_all_zero = (
            not any(data[4:7]) and not any(data[16:18]) and not any(data[20:90])
        )
        return Diag0xB8B5(
            log_time=log_time,
            version=version,
            subversion=data[2],
            payload_size=len(data),
            marker=data[7],
            tlv_header=unpack_from("<I", data, 8)[0],
            counter=unpack_from("<I", data, 12)[0],
            counter2=unpack_from("<H", data, 18)[0],
            reserved_all_zero=reserved_all_zero,
            is_tlv_shell=True,
            nr_band=_shell_nr_band(unpack_from("<I", data, 8)[0]),
        )
    if version in _B8B5_V3_VERSIONS:
        # Self-describing entry model: byte[8] (low byte of field_b) is the
        # entry count and len == 12 + 16*count. The 12B header-only, 28B
        # populated and 44B two-entry forms are 0/1/2 entries of one layout. A
        # count that disagrees with the length is a misframe: return None so
        # the registry WARN and tally fire (the log code fails loudly instead
        # of mis-parsing or silently dropping).
        if len(data) < _B8B5_V3_HDR:
            return None
        count = data[8]
        if len(data) != _B8B5_V3_HDR + _B8B5_V3_ENTRY * count:
            return None
        field_a = unpack_from("<I", data, 4)[0]
        if count == 0:
            # Header-only: version + field_a + 4B tail (field_b not surfaced, so
            # the output matches the Kaitai description byte-for-byte).
            return Diag0xB8B5(
                log_time=log_time,
                version=version,
                subversion=data[2],
                payload_size=len(data),
                field_a=field_a,
                tail=bytes(data[8:12]),
                is_header_only=True,
                entry_count=0,
                entries=[],
            )
        entries = []
        for i in range(count):
            off = _B8B5_V3_HDR + _B8B5_V3_ENTRY * i
            field_d = unpack_from("<I", data, off)[0]
            entries.append({
                "field_d": field_d,
                "field_c": unpack_from("<I", data, off + 4)[0],
                "tail": bytes(data[off + 8:off + 16]).hex(),
                # field_d is the NR band - 1 (F3 cc_idx i == entry i).
                # An all-zero entry is an empty carrier slot, not band n1.
                "nr_band": (field_d + 1) if any(data[off:off + 16]) else None,
            })
        return Diag0xB8B5(
            log_time=log_time,
            version=version,
            subversion=data[2],
            payload_size=len(data),
            field_a=field_a,
            field_b=unpack_from("<I", data, 8)[0],
            field_d=entries[0]["field_d"],
            field_c=entries[0]["field_c"],
            tail=bytes(data[20:28]),
            entry_count=count,
            entries=entries,
            nr_band=entries[0]["nr_band"],
        )
    if version == _B8B5_PKT_VER_SDX55:
        if len(data) != _B8B5_SIZE_SDX55:
            return None
        # Reserved regions (everything OUTSIDE marker@15 / tlv_header@16 /
        # counter@20): [4:15] (11B) + [24:98] (74B, incl. the 70B TLV body).
        # Informational only — NOT a hard invariant (the TLV body may populate
        # under a measurement-carrying state not yet captured). marker@15 is
        # excluded from the reserved span.
        reserved_all_zero = (
            all(b == 0 for b in data[4:15])
            and all(b == 0 for b in data[24:98])
        )
        # On-wire offsets locked against 35 real EM9190 v2 records.
        return Diag0xB8B5(
            log_time=log_time,
            version=version,
            subversion=data[2],
            payload_size=len(data),
            marker=data[15],
            tlv_header=unpack_from("<I", data, 16)[0],
            counter=unpack_from("<I", data, 20)[0],
            reserved_all_zero=reserved_all_zero,
            nr_band=_shell_nr_band(unpack_from("<I", data, 16)[0]),
        )

    # Unreachable (version allowlist above), but keep the explicit refusal:
    # a future v4+ firmware drop surfaces as a corpus-sweep parse-rate drop.
    return None
