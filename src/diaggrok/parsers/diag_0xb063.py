"""0xB063 — LTE MAC DL Transport Block (LOG_LTE_MAC_DL_TRANSPORT_BLOCK): per-TB RNTI type, HARQ id, SFN/subframe, TBS, MAC subheaders.

The body is the MAC downlink transport block log, one sample per received TB.

### Layout (body decoded on all three wire versions)

**v0x01** (MDM9200 MC7700 → SDX20/MDM9250/SDX24 LM960 / EM7565 / EM120R / EG25-G …):
the classic LTE-MAC subpacket container.

    @0   u8   version            0x01
    @1   u8   num_subpackets
    @2   2B   hdr_raw            raw
    per subpacket:
    +0   u8   subpacket_id       0x07 (DL transport block)
    +1   u8   subpacket_version  1 (MC7700), 2, 4
    +2   u16  subpacket_size     includes this 4-byte header
    +4   u8   num_samples
    then num_samples packed samples, then 0..3 alignment bytes to the subpacket end.

    sample, subpacket_version 2 (12 B + mac_hdr):
      u16 timing (sfn bits 4-15, subframe bits 0-3), u8 rnti_type, u8 harq_id,
      u16 pmch_id, u16 tbs, u8 rlc_pdus, u16 padding_bytes, u8 mac_hdr_len,
      mac_hdr_len bytes of the TB head (mac_hdr)
    subpacket_version 4: u8 sub_id_raw, u8 cell_id_raw, then the v2 sample.
    subpacket_version 1 (10 B + mac_hdr): u8 harq_id, u8 rnti_type, u16 timing,
      u16 tbs, 3B v1_reserved_raw, u8 mac_hdr_len, mac_hdr

    rnti_type: 0 C-RNTI, 2 P-RNTI, 3 RA-RNTI, 4 TC-RNTI, 5 SI-RNTI (others raw).
    For a transparent-MAC TB (P-/SI-/RA-RNTI) mac_hdr is the TB, but only its
    head is logged: at most 32 B (15 B on the MC7700 and some MDM9x07 builds).
    mac_hdr_len < tbs means mac_hdr is a head, not the whole TB (corpus:
    3,899 sp07.v2 + 946 sp07.v4 samples at 32 B, 71 at 15 B; each such head is
    the first bytes of the 0xB0C0 PDU). For a C-/TC-RNTI TB it is the MAC
    subheader block (+ any CE bytes).

**v0x32** (SDX55/SDX6x RM520N-GL / M3100 / EM9291 …) and **v0x31** (SDX55
RM500Q / LV55 / FN980 / M2000 / T99W175): a flat TB-entry list.

    v0x32: @0 u8 version, @1 3B hdr_raw, @4 u32 num_entries, entries @8
    v0x31: @0 u8 version, @1 3B hdr_raw, @4 u16 num_entries, @6 u16 hdr_word6_raw,
           @8 532B cell_stats_raw (19 x 28 B slots, slots 0-2 populated; raw), entries @540

    entry (16 B + elements):
      u32 tbs                    TB size, bytes
      u32 word4_raw              raw (0 on every Msg4)
      u32 timing                 sfn bits 0-9, subframe bits 10-13, timing_hi_raw bits 14+
      u8  harq_id (bits 4-7) | h0_lo_raw (bits 0-3)
      u8  num_elements
      u8  h2_raw, u8 h3_raw      raw (h3 is 0 or uninitialised: low nibble always 0)
    element (12 B [+ RLC extension]):
      u32 LE word: bit 0 is_mac_ce, bits 1-5 lcid, bits 7-22 length (MAC SDU / CE
      length L), byte 3 = first CE payload byte (CE) / b3_raw (SDU)
      MAC CE: ce_payload = bytes 3 .. 3+L (L <= 9; UE Contention Resolution
      Identity = 6 B, Timing Advance Command = 1 B)
      SDU: bytes 4-11 el_raw; byte 8 != 0 => an RLC extension follows: n = byte9
      item words, then T trailer words, 4*n + 4*T B (rlc_ext_raw, raw). The
      primary rule allows T in [n, 2n]; a relaxed fallback allows T in
      [1, min(3, 2n)] (see below).
    Unused element / header bytes are often uninitialised firmware memory; they
    are exposed raw, never named.

The RLC extension length is not fully predictable from any one field (a bit-6
flag in the group header predicts the extra word most, not all, of the time), so
entries are framed by constraint: every entry header must be valid (subframe
< 10, <= 16 elements, low nibble of h3 0) and the record must end exactly. The
strict pass also requires h3 == 0. A record with more than one valid framing
takes the one with the fewest extra words and sets `framing_ambiguous`.

**Relaxed fallback, v6**. Only when neither primary pass frames the
record, two more passes allow T in [1, min(3, 2n)] and require every entry's
harq_id < 8; such a record sets `framing_relaxed`. Orbic R500L5 (SDX55, V2.0.3.9
and V2.0.4.3) v0x31 and RG650V-NA (SDX72) v0x32 log n = 3..5 item words with
only 2..3 trailer words (T < n), which the primary rule cannot frame; the census
counted 111 v0x31 + 11 v0x32 such drops. Sample (84 captures, 14,387 records):
24 drop -> parse, all unambiguous, 14,363 unchanged, 0 regressions; on the 536
rescued entries sum(element L) <= tbs 536/536 (primary-framed control
43,672/43,679). The harq guard rejects a byte-count-only fit on one RG650V-NA
record (harq 13, L 3,184 > tbs 44) that the relaxed range alone accepted.

A record with no valid framing still returns None. Every drop WARNs with its
reason (1st, 10th, 100th ... per (version, len, reason)), naming the furthest
entry a partial framing reached, or the search cap; a v0x01 subpacket or sample
that overruns the record / its subpacket is a named drop, and a v0x01 subpacket
with an unknown id / version is kept raw in align_raw but WARNed.

### Grounding

* **v0x01, F3 + RRC OTA, EM7455 MDM9x30 all-diag+F3:** all 69 records are
  P-RNTI TBs and pair 1:1, in order, with the 69 F3 `lte_rrc_stm.c:535
  (MAC -> LTE_RRC_MH_SM) LTE_MAC_RRC_PCCH_DL_DATA_IND` prints and the 69 0xB0C0
  PCCH messages; mac_hdr is byte-identical to the PCCH PDU 69/69. The record
  trails both by ~29 ms (batched log flush).
* **v0x01, black-box:** SCAT MAC-LTE frames byte-join 9/9 on an EG18-NA
  (timing word == SCAT's sfn<<4|sf tag, mac_hdr == PDU, rnti_type 2 -> P-RNTI)
  and 6/6 SI-RNTI frames on an EM7565 (rnti_type 5 -> SI-RNTI).
* **v0x01 rnti_type 0/3/4, in-capture, EM7565 F3 capture:** the RA-RNTI TB is
  the MAC RAR (RAPID == 0xB167 preamble_index, TC-RNTI == 0xB168 tc_rnti, timing
  == 0xB168 RAR sfn/subframe); the TC-RNTI TB carries a Contention Resolution CE
  equal to the 0xB0C0 UL-CCCH Msg3; C-RNTI TBs carry an LCID-1 subheader whose L
  == DL-DCCH length + 7 (PDCP+MAC-I+RLC) at the same sfn/subframe, and
  tbs - L - 3 == padding_bytes.
* **v0x01 framing:** 74 captures / 34 model groups: every subpacket walks with
  0..3 alignment bytes left, multi-sample (up to 23) included.
* **v0x01 per subpacket layout:** each sample layout grounded on its own
  records.
  F3 1:1, P-RNTI sample <-> MAC->RRC paging hand-off print, record after print
  by 0-51 ms: sp07.v1 MC7700 12/12 (`lte_rrc_paging.c:934 Received paging
  dlm`; that build has no PCCH_DL_DATA_IND print); sp07.v2 EG25-G 103/103
  (`lte_rrc_stm.c:537` PCCH_DL_DATA_IND and `lte_rrc_paging.c:1037`, 103 each);
  sp07.v4 EM160R-GL 117/117 (`lte_rrc_stm.c:852`), LM960A18 318/318
  (`lte_rrc_stm.c:683`, + TC-RNTI Msg4 1/1 CCCH_DL_DATA_IND), EM060K-GL 135/135
  (`lte_rrc_stm.c:648` + `lte_rrc_paging.c:1211`, + Msg4 2/2). The timing word:
  sfn*10+subframe == the `pag_sf` arg of ML1's `lte_ml1_common_paging_drx.c`
  "Next Pag Occ" print in the 3 s before the record on sp07.v1 12/12, sp07.v2
  103/103, sp07.v4 302/302 (LM960A18) and 129/135 (EM060K-GL); the same
  subframe + 10 matches pag_sf 0 times (control). SCAT MAC-LTE (timing tag +
  bytes): sp07.v2 92/92, sp07.v4 167/167 DL frames with the RNTI type agreeing
  on P/RA/C(TC)/SI; SCAT emits no MAC frame on the MC7700 (sp07.v1).
  0xB0C0 content join, 338 bearing captures, head-aware: P-RNTI == PCCH
  sp07.v1 409/409, sp07.v2 6,200/6,207, sp07.v4 7,307/7,475; SI-RNTI == BCCH
  sp07.v2 6,114/6,121, sp07.v4 1,630/1,875; TC-RNTI CRI == Msg3 sp07.v2
  102/106, sp07.v4 61/69; CCCH L == DL-CCCH length 15/15, 12/13. The sp07.v4
  P/SI misses are not characterised.
* **v0x32, F3 + RRC OTA, RM520N-GL SDX62 survey (46 RACHs):** exactly 46 entries
  carry an LCID-28 Contention Resolution CE; ce_payload == the 0xB0C0 UL-CCCH
  Msg3 head 46/46, the LCID-0 element length == the 0xB0C0 DL-CCCH length 46/46,
  entry sfn/subframe == the DL-CCCH's 46/46, and each pairs 1:1 with F3
  `lte_rrc_stm.c:837 (MAC -> LTE_RRC_MH_SM) LTE_MAC_RRC_CCCH_DL_DATA_IND`
  (record 3.1-4.1 ms after the print). tbs == 32 + 7 + 2 on the 41 B Msg4s.
* **v0x31, same test, LV55 SDX55 F3 capture:** 2/2 on every check, F3
  `lte_rrc_stm.c:866 LTE_MAC_RRC_CCCH_DL_DATA_IND` 3.9-4.4 ms before.
* **v0x32, black-box:** SCAT rebuilds a MAC subheader block per entry; on 62,660
  entries (1,541 RM520N-GL records anchored by the SCAT sfn<<4|sf tags) the
  data elements' (lcid, length) list equals SCAT's 57,539/57,540, and the CE LCID
  set 57,510/57,540.
* **All bearing captures (346 captures, 23,608 records):** 0 rejected,
  0 invariant violations. v0x01 14,013 records, every subpacket walks (sver
  1/2/4: 381/4,915/8,717); rnti_type in {0,2,3,4,5}; P-RNTI TB bytes found in a
  nearby 0xB0C0 PCCH 9,317/10,422, SI-RNTI in BCCH 2,969/3,143. v0x31 896
  records: 887 framed, 6 ambiguous, 3 raw; Msg4 CRI == Msg3 98/100, CCCH L ==
  DL-CCCH length 98/100. v0x32 8,699 records (236,544 entries): 8,644 framed,
  44 ambiguous, 11 raw; CRI == Msg3 193/206, CCCH L == DL-CCCH length 201/206
  (misses: Msg3 / DL-CCCH not logged near that RACH).
* **harq_id (v0x31/v0x32):** values 0-7 uniform; a process is reused after
  exactly 8 subframes (the FDD HARQ RTT) on 44,121 of the reuse events.

Log name: LOG_DL_TRANSPORT_BLOCK
Also known as: LOG_LTE_MAC_DL_TRANSPORT_BLOCK, LTE MAC DL Transport Block
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_B063_VERSIONS_OBSERVED = (0x01, 0x31, 0x32)

logger = logging.getLogger(__name__)
_LAYOUT_ALARMS: Counter = Counter()


def _layout_alarm(data: bytes, why: str) -> None:
    """WARN on a dropped or partly-walked record, naming its form and the reason.

    The registry's own WARN fires once per (code, version), so a new size or a
    framing failure inside an already-seen version would otherwise go unreported
    . Logs the 1st, 10th, 100th, ... per (version, len, reason).
    """
    key = (data[0] if data else None, len(data), why)
    _LAYOUT_ALARMS[key] += 1
    n = _LAYOUT_ALARMS[key]
    if str(n).rstrip("0") != "1":
        return
    logger.warning(
        "diaggrok 0xB063 layout issue #%d: version=0x%02X len=%d head=%s — %s "
        "", n, data[0] if data else 0, len(data),
        bytes(data[:8]).hex(), why,
    )


class _StateCapExceeded(Exception):
    """The constraint framer hit _MAX_STATES before finishing."""

#: v0x01 sample rnti_type (grounded: see module docstring). 1 is unobserved.
RNTI_TYPES = {0: "C-RNTI", 2: "P-RNTI", 3: "RA-RNTI", 4: "TC-RNTI", 5: "SI-RNTI"}

#: TS 36.321 Table 6.2.1-1 DL-SCH LCIDs (1-10 are logical channels).
DL_LCID_NAMES = {
    0: "CCCH",
    27: "Activation/Deactivation",
    28: "UE Contention Resolution Identity",
    29: "Timing Advance Command",
    30: "DRX Command",
    31: "Padding",
}

_V31_ENTRIES_OFF = 540
_ENTRY_HDR = 16
_ELEMENT = 12
_MAX_STATES = 200_000


def _lcid_name(lcid: int) -> str | None:
    if 1 <= lcid <= 10:
        return f"LCH{lcid}"
    return DL_LCID_NAMES.get(lcid)


@dataclass
class Diag0xB063:
    """0xB063 — LTE MAC DL transport block log."""
    log_time: int
    version: int
    hdr_raw: bytes
    num_subpackets: int | None
    subpackets: list[dict[str, Any]] = field(default_factory=list)
    num_entries: int | None = None
    entries: list[dict[str, Any]] = field(default_factory=list)
    hdr_word6_raw: int | None = None
    cell_stats_raw: bytes = b""
    framing_ambiguous: bool = False
    framing_relaxed: bool = False
    unparsed_raw: bytes = b""
    payload_size: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB063",
            "log_time": self.log_time,
            "version": self.version,
            "hdr_raw": self.hdr_raw,
            "num_subpackets": self.num_subpackets,
            "subpackets": self.subpackets,
            "num_entries": self.num_entries,
            "entries": self.entries,
            "hdr_word6_raw": self.hdr_word6_raw,
            "cell_stats_raw": self.cell_stats_raw,
            "framing_ambiguous": self.framing_ambiguous,
            "framing_relaxed": self.framing_relaxed,
            "unparsed_raw": self.unparsed_raw,
            "payload_size": self.payload_size,
        }


# --- v0x01: subpacket container --------------------------------------------

def _v01_sample(body: bytes, o: int, sver: int) -> tuple[dict[str, Any], int] | None:
    s: dict[str, Any] = {}
    if sver == 1:
        if o + 10 > len(body):
            return None
        s["harq_id"], rnti_type = body[o], body[o + 1]
        timing, tbs = unpack_from("<HH", body, o + 2)
        s["v1_reserved_raw"] = bytes(body[o + 6:o + 9])
        hl = body[o + 9]
        o += 10
    else:
        if sver >= 4:
            if o + 2 > len(body):
                return None
            s["sub_id_raw"], s["cell_id_raw"] = body[o], body[o + 1]
            o += 2
        if o + 12 > len(body):
            return None
        timing = unpack_from("<H", body, o)[0]
        rnti_type, s["harq_id"] = body[o + 2], body[o + 3]
        s["pmch_id"], tbs = unpack_from("<HH", body, o + 4)
        s["rlc_pdus"] = body[o + 8]
        s["padding_bytes"] = unpack_from("<H", body, o + 9)[0]
        hl = body[o + 11]
        o += 12
    if o + hl > len(body):
        return None
    s.update(
        sfn=timing >> 4,
        subframe=timing & 0xF,
        rnti_type=rnti_type,
        rnti_type_name=RNTI_TYPES.get(rnti_type),
        tbs=tbs,
        mac_hdr_len=hl,
        mac_hdr=bytes(body[o:o + hl]),
    )
    return s, o + hl


def _parse_v01(data: bytes) -> tuple[list[dict[str, Any]], int] | str:
    """Walk the declared subpackets; a reason string when any declared
    subpacket or sample does not fit (truncated -> loud drop, never a silently
    short list). An unknown subpacket id / version is kept (raw in align_raw)
    but WARNed, so a new sample layout is not silently swallowed."""
    subs: list[dict[str, Any]] = []
    off = 4
    for i in range(data[1]):
        if off + 4 > len(data):
            return (f"v0x01 subpacket {i}/{data[1]} header @{off} overruns "
                    f"the {len(data)} B record")
        sid, sver = data[off], data[off + 1]
        ssz = unpack_from("<H", data, off + 2)[0]
        if ssz < 5 or off + ssz > len(data):
            return (f"v0x01 subpacket {i}/{data[1]} (id 0x{sid:02X} v{sver}) "
                    f"size {ssz} @{off} is < 5 or overruns the {len(data)} B record")
        body = data[off + 4:off + ssz]
        sp: dict[str, Any] = {
            "subpacket_id": sid,
            "subpacket_version": sver,
            "subpacket_size": ssz,
            "num_samples": body[0],
            "samples": [],
            "align_raw": b"",
        }
        o = 1
        if sid == 0x07 and sver in (1, 2, 4):
            for j in range(body[0]):
                r = _v01_sample(body, o, sver)
                if r is None:
                    return (f"v0x01 subpacket {i} (id 0x07 v{sver}) sample "
                            f"{j}/{body[0]} @{o} overruns its {ssz} B subpacket")
                sp["samples"].append(r[0])
                o = r[1]
        else:
            _layout_alarm(data, f"v0x01 subpacket {i} id 0x{sid:02X} v{sver} "
                                f"({ssz} B) is not a known sample layout; kept "
                                f"raw in align_raw")
        sp["align_raw"] = bytes(body[o:])
        subs.append(sp)
        off += ssz
    return subs, off


# --- v0x31 / v0x32: TB entry list --------------------------------------------

def _entry_hdr_ok(data: bytes, o: int, strict: bool, relaxed: bool = False) -> bool:
    if o + _ENTRY_HDR > len(data):
        return False
    timing = unpack_from("<I", data, o + 8)[0]
    h3 = data[o + 15]
    # The relaxed fallback is less trusted, so it also needs harq_id < 8 (the
    # FDD HARQ process range): it keeps the fallback from accepting a framing
    # that only fits the byte count; one RG650V-NA record did.
    return (((timing >> 10) & 0xF) < 10 and data[o + 13] <= 16
            and (h3 == 0 if strict else (h3 & 0x0F) == 0)
            and (not relaxed or data[o + 12] >> 4 < 8))


def _ext_choices(data: bytes, o: int, relaxed: bool = False) -> tuple[int, ...]:
    """RLC extension lengths allowed after the element at `o` (0 = none).

    The extension is n = byte9 item words then T trailer words (4·n + 4·T B).
    The primary rule allows T in [n, 2n]. The relaxed fallback allows
    T in [1, min(3, 2n)]: Orbic R500L5 (SDX55) v0x31 and RG650V-NA (SDX72)
    v0x32 log n = 3..5 item words with only 2..3 trailer words, which the
    primary rule cannot frame. T = 1..3 is every trailer the corpus attests.
    """
    e = data[o:o + _ELEMENT]
    if e[0] & 1 or not e[8]:
        return (0,)
    n = e[9]
    if relaxed:
        return tuple(4 * n + 4 * t for t in range(1, min(3, 2 * n) + 1))
    return tuple(8 * n + 4 * j for j in range(n + 1))


def _frame(data: bytes, base: int, n: int, strict: bool, diag: dict | None = None,
           relaxed: bool = False):
    """Constraint-frame n entries from `base` to the exact end of `data`.

    Returns (entries, ambiguous): entries = [(entry_off, [(el_off, ext_len), ...])].
    With no framing, `diag['deepest']` (when given) is the furthest
    (entry_idx, offset) any partial framing reached, for the drop WARN.
    Raises _StateCapExceeded past _MAX_STATES.
    Iterative memoised DP over (offset, entry_idx, elements_left); every
    transition advances the offset or the entry index, so it terminates.
    """
    end = len(data)
    memo: dict[tuple[int, int, int], int] = {}  # state -> number of completions (capped 2)

    def succ(state):
        o, k, m = state
        if m < 0:  # expecting the header of entry k
            if k == n:
                return []
            if not _entry_hdr_ok(data, o, strict, relaxed):
                return []
            return [(o + _ENTRY_HDR, k, data[o + 13])]
        if m == 0:
            return [(o, k + 1, -1)]
        if o + _ELEMENT > end:
            return []
        return [(o + _ELEMENT + x, k, m - 1) for x in _ext_choices(data, o, relaxed)]

    def is_final(state):
        o, k, m = state
        return m < 0 and k == n and o == end

    start = (base, 0, -1)
    stack = [start]
    while stack:
        if len(memo) > _MAX_STATES:  # pathological record: give up (named drop)
            raise _StateCapExceeded
        st = stack[-1]
        if st in memo:
            stack.pop()
            continue
        nxt = [s for s in succ(st) if s[0] <= end]
        pending = [s for s in nxt if s not in memo]
        if pending:
            stack.extend(pending)
            continue
        stack.pop()
        memo[st] = 1 if is_final(st) else min(2, sum(memo[s] for s in nxt))
    if memo.get(start, 0) == 0:
        if diag is not None:
            diag["deepest"] = max(((k, o) for o, k, _ in memo), default=(0, base))
        return None, False
    # Walk the first solution (succ order = fewest extra words first).
    entries: list[tuple[int, list[tuple[int, int]]]] = []
    st = start
    while not is_final(st):
        o, k, m = st
        for s in succ(st):
            if s[0] <= end and memo.get(s, 0):
                if m < 0:
                    entries.append((o, []))
                elif m > 0:
                    entries[-1][1].append((o, s[0] - o - _ELEMENT))
                st = s
                break
    return entries, memo[start] > 1


def _element(data: bytes, o: int, ext: int) -> dict[str, Any]:
    e = data[o:o + _ELEMENT]
    word = unpack_from("<I", e, 0)[0]
    is_ce = bool(e[0] & 1)
    lcid = (e[0] >> 1) & 0x1F
    length = (word >> 7) & 0xFFFF
    el: dict[str, Any] = {
        "is_mac_ce": is_ce,
        "lcid": lcid,
        "lcid_name": _lcid_name(lcid),
        "length": length,
        "word_raw": word,
    }
    if is_ce:
        el["ce_payload"] = bytes(e[3:3 + min(length, 9)])
        el["el_raw"] = bytes(e[3 + min(length, 9):])
    else:
        el["b3_raw"] = e[3]
        el["el_raw"] = bytes(e[4:])
        el["rlc_desc_count"] = e[9] if e[8] else 0
        el["rlc_ext_raw"] = bytes(data[o + _ELEMENT:o + _ELEMENT + ext])
    return el


def _parse_entries(data: bytes, base: int, n: int):
    """A reason string when no framing of the declared n entries ends exactly
    at the record end (a truncated / unframeable entry list is a loud drop)."""
    diag: dict[str, Any] = {}
    capped = False
    # The relaxed passes run only when the primary rule frames nothing, so a
    # record the primary rule frames is decoded exactly as before.
    for relaxed, strict in ((False, True), (False, False), (True, True), (True, False)):
        try:
            framed, amb = _frame(data, base, n, strict, diag, relaxed)
        except _StateCapExceeded:
            capped = True
            continue
        if framed is not None:
            break
    else:
        if capped:
            return (f"v0x{data[0]:02X} entry framing of {n} entries gave up "
                    f"after {_MAX_STATES} states")
        k, o = diag.get("deepest", (0, base))
        return (f"v0x{data[0]:02X} no framing of {n} declared entries ends at "
                f"the record end; furthest partial framing reached entry {k} "
                f"@{o} of {len(data)} B")
    out = []
    for eo, els in framed:
        tbs, word4, timing = unpack_from("<III", data, eo)
        h = data[eo + 12:eo + 16]
        out.append({
            "tbs": tbs,
            "word4_raw": word4,
            "sfn": timing & 0x3FF,
            "subframe": (timing >> 10) & 0xF,
            "timing_hi_raw": timing >> 14,
            "harq_id": h[0] >> 4,
            "h0_lo_raw": h[0] & 0xF,
            "num_elements": h[1],
            "h2_raw": h[2],
            "h3_raw": h[3],
            "elements": [_element(data, o, x) for o, x in els],
        })
    return out, amb, relaxed


@register(
    0xB063,
    name="0xB063",
    description="0xB063 — LTE MAC DL Transport Block: per-TB RNTI type, HARQ id, SFN/subframe, TBS, MAC subheader LCID/length, MAC CEs (contention resolution, TA), v0x01 TB head bytes",
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. v0x01 = LTE-MAC subpacket "
        "container (subpacket 0x07 v1/v2/v4; samples: timing sfn<<4|sf, rnti_type "
        "0 C/2 P/3 RA/4 TC/5 SI, harq_id, pmch_id, tbs, rlc_pdus, padding_bytes, TB "
        "head bytes). v0x31/v0x32 = TB entry list (tbs, sfn/subframe bits 0-9/10-13, "
        "harq_id, elements: is_mac_ce, lcid, length bits 7-22, CE payload; RLC "
        "extension raw, constraint-framed). Grounding: EM7455 v0x01 F3 "
        "LTE_MAC_RRC_PCCH_DL_DATA_IND 69/69 + 0xB0C0 PCCH byte-join 69/69; SCAT "
        "MAC-LTE 9/9 (EG18-NA) + SI 6/6 (EM7565); RM520N-GL v0x32 46 Msg4s: CRI == "
        "Msg3 46/46, CCCH L == DL-CCCH len 46/46, F3 LTE_MAC_RRC_CCCH_DL_DATA_IND "
        "1:1; LV55 v0x31 2/2; SCAT (lcid, L) 57,539/57,540 entries. RLC "
        "extension = n item words + T trailer words; primary T in [n, 2n], "
        "relaxed fallback T in [1, min(3, 2n)] with harq_id < 8 (R500L5 v0x31, "
        "RG650V-NA v0x32; framing_relaxed). Truncated payloads return None with "
        "a reason-carrying WARN rather than a silently short record: a v0x01 "
        "subpacket whose subpacket_size overruns the record, a sample "
        "overrunning its subpacket, or a v0x31/v0x32 entry list with no framing "
        "that ends at the record end."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=13,
    fields_parsed=13,
    field_invariants={
        "version": {"enum": [0x01, 0x31, 0x32]},
        # v0x01's body layout is picked PER SUBPACKET: the DL-TB
        # subpacket 0x07 carries its own version, and v1 (10 B sample) / v2
        # (12 B) / v4 (+2 B sub_id/cell_id prefix) are three sample layouts.
        # Corpus-attested (346 captures): sver 1/2/4 = 381/4,915/8,717 records.
        "subpackets[].subpacket_id": {"enum": [0x07]},
        "subpackets[].subpacket_version": {"enum": [1, 2, 4]},
    },
    # F3-sweep layout axis (list form): the unit of F3 work is
    # (0xB063, v0x01, sp07.vN). v0x31/v0x32 carry no subpacket list.
    layout_axes={"sp": "subpackets[subpacket_id].subpacket_version"},
)
def parse_0xb063(log_time: int, data: bytes) -> Diag0xB063 | None:
    if len(data) < 4:
        _layout_alarm(data, "payload shorter than the 4 B header")
        return None
    version = data[0]
    if version not in _B063_VERSIONS_OBSERVED:
        _layout_alarm(data, "unknown version (known: 0x01, 0x31, 0x32)")
        return None
    rec = Diag0xB063(
        log_time=log_time,
        version=version,
        hdr_raw=bytes(data[1:4] if version != 0x01 else data[2:4]),
        num_subpackets=None,
        payload_size=len(data),
    )
    if version == 0x01:
        rec.num_subpackets = data[1]
        walked = _parse_v01(data)
        if isinstance(walked, str):
            _layout_alarm(data, walked)
            return None
        rec.subpackets, used = walked
        rec.unparsed_raw = bytes(data[used:])
        return rec
    if version == 0x32:
        if len(data) < 8:
            _layout_alarm(data, "v0x32 shorter than its 8 B header")
            return None
        n, base = unpack_from("<I", data, 4)[0], 8
    else:
        if len(data) < _V31_ENTRIES_OFF:
            _layout_alarm(data, f"v0x31 shorter than its {_V31_ENTRIES_OFF} B "
                                f"header + cell_stats block")
            return None
        n, rec.hdr_word6_raw = unpack_from("<HH", data, 4)
        rec.cell_stats_raw = bytes(data[8:_V31_ENTRIES_OFF])
        base = _V31_ENTRIES_OFF
    rec.num_entries = n
    parsed = _parse_entries(data, base, n)
    if isinstance(parsed, str):
        _layout_alarm(data, parsed)
        return None
    rec.entries, rec.framing_ambiguous, rec.framing_relaxed = parsed
    return rec
