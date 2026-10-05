"""0x1855 — IPA hardware FILTER-rule table dump. NOT GNSS.

Despite a circulating "GNSS ME GPS L1C measurement report" label (no name
source gives it), every per-SV hypothesis fails against this code. The body
is a dump of the modem's **IPA (IP Accelerator) hardware filter-rule
tables** — the packet classifiers
that divert control traffic (DHCP, DNS, DHCPv6, TCP SYN/FIN/RST, ICMP/ICMPv6,
pure TCP ACKs) off the hardware fast path. Sibling 0x1856 dumps the
matching **routing**-rule tables; 0x1853 is ``LOG_DATA_MODEM_IPA_SIO_CONFIG``
and 0x184F ``Data Modem IPA Stats`` in the same numbering block.

## When it fires

1. **On a DIAG log-mask change** — a 0x1855 + 0x1856 burst (plus 0x1851/0x1852
   on some builds) follows within 0.1 ms of ``uim_sigs.c "UIM - Received Diag
   log mask change indication"`` / ``mplm.c "MPLM Log Mask Change Received!"``
   (Compal RXM-G1 v0x03, RM520N-GL v0x03/v0x04, MDM9655 v0x02, T99W640 v0x06).
   A log-on-subscribe snapshot.
2. **On every IPA table commit** — on the MDM9655 (v0x02) PDN bring-up capture
   ``ipa_ipfltr.c:11369 IPA_IPFLTRI_FLTR_TBL_TYPE_DL_IPV4`` /
   ``ipa_ipfltr.c:11469 IPA_IPFLTRI_FLTR_TBL_TYPE_DL_IPV6`` precede fresh 0x1855
   records by ~10 us, and ``ipa_ipfltr.c:12017 IPA_IPFLTRI_RTNG_TBL_TYPE_DL``
   precedes a burst carrying 0x1856; the decoded rule count of one table grows
   6 -> 9 -> 11 -> 12 -> 13 across successive snapshots as filters are
   installed. RM520N-GL v0x04 shows ``ipa_acc_dpl.c`` / ``ipa_ctl_clk.c
   "IPA_DBG: DL producer pipe started"`` 0.1-0.5 ms after its burst.

So the records are live filter-table snapshots. The body is byte-identical
across two PocketSDR-paired runs with disjoint L1C PRN sets because the same
control-plane rules are installed at the same point of bring-up.
Oracle verdicts: F3 — LABELED (the firmware names the tables it is emitting:
``FLTR_TBL_TYPE_DL_IPV4/IPV6``, ``RTNG_TBL_TYPE_DL``, file ``ipa_ipfltr.c``)
plus the log-mask trigger; ``0x60`` events — silent (nearest are unrelated
``root_pd`` service-registry events 16 ms earlier); qcsuper + SCAT — silent
(code not in their tables); AT ``+CGPADDR`` — the /128 IPv6 destination rule
equals the PDP IPv6 address in 2/2 paired T99W175 captures.

## Record header — see ``_ipa_rules.decode_dump``

``version`` >= 0x02: 16 bytes — ``version:u8, timetick:u24, dump_word:u32,
table_id:u8, table_sub:u8, table_word:u16, body_len:u16, pad14:u16``.
``version`` 0x01: 12 bytes — ``version, timetick, dump_word, table_id:u8,
table_sub:u8, body_len:u16``.

* ``version`` is a record-format byte that changes with the **firmware
  build**, not strictly the chipset: one RM520N-GL emits 0x04 on one
  firmware build and 0x03 on another. It still tracks platform era loosely
  (0x01 MDM9x30-9x40, 0x02 MDM9250/9655/SDX20, 0x03 SDX55, 0x04 SDX62/65,
  0x06 SDX72), so it can look like a chipset-generation byte.
* ``timetick`` is NOT a boot-session id: it
  advances between bursts within one boot and is shared with 0x1851/0x1852
  and 0x1856 in the same burst. Its rate against DIAG timestamps is
  1.02400/ms on MDM9x40/MDM9250/SDX20 (32.768 kHz sclk >> 5) and
  1.1719/ms on SDX55/62/65/72 (19.2 MHz QTimer >> 14) — a truncated system
  timer stamping the dump. It matches across codes only because they are
  dumped in the same burst.
* ``table_sub`` is the **IP family** on this code: every 0x1855 table with
  ``table_sub == 0`` holds only IPv4 matches (version-nibble 4, ICMP proto 1,
  IPv4 address offsets) and every ``table_sub == 1`` table only IPv6 matches
  (version-nibble 6, ICMPv6 proto 58, meq128 at the IPv6 destination offset
  24) — zero cross-family rules in the corpus walk. ``ip_family`` exposes it.
* ``body_len`` equals the body length on every corpus record, all versions.
* ``dump_word`` is constant within a burst and takes
  {0..6, 251} across boots — not reserved, semantics unknown, raw.

## Body — IPA rules

A sequence of IPA hardware rules, walked by ``_ipa_rules.walk_rules`` (IPA v3+
layout for ``version`` >= 0x02, IPA v2 layout for 0x01). Each rule is
``{'offset', 'en_rule', 'word2', 'word4', 'word6', 'equations'}``; the
``equations`` dict carries the decoded match operands (``protocol``,
``meq32_0`` {offset, mask, value}, ``ihl_range16_0`` {offset, low, high},
``meq128_0`` {offset, mask, value hex}, ``metadata``, ``is_frag``, …). Zero
8-byte words separate tables; some tables end in a 0xDEADC0FE fill word
(``trailer_magic``).

Examples from the corpus (``version`` 0x03, Compal RXM-G1): proto 17 +
range16 @L4+2 67..67 (DHCP server port); proto 17 + meq32 @16
0xFFFFFFE0/0xC0000000 + range16 53..53 (DNS to 192.0.0.0/27); proto 6 +
ihl_meq32 @12 0x00020000 (TCP SYN); proto 58 + ihl_meq32 0xFF000000/0x86000000
(ICMPv6 Router Advertisement); meq32 @0 0xF0000000/0x40000000 (any IPv4).

``meq128`` rules at offset 24 match an IPv6 **destination address** — on a
live modem that is the UE's own address. It is decoded in full; test fixtures
use 0xFF sentinels rather than a real captured value.

## Rule header — ``rule['header']``

``word2``/``word4``/``word6`` stay exposed raw, and each rule also carries a
decoded ``header``: ``rt_tbl_idx``, ``action``, ``priority``, ``rule_id`` and a
position-named flag (``w2_bit10`` or ``prio_bit9``). There are two IPA v3+
header layouts, and the ``version`` byte does NOT pick between them: SDX55
builds use layout A at version 0x03, while an RM520N-GL build, Inseego M3100
and a T99W175 build use layout B at the same 0x03. ``header_layout`` is detected per
record (layout A filter rules have ``word6`` bit 9 set, since the rule id is
``0x200 | priority``; layout B never sets it). On the corpus, 11,671 records
fall into one layout each (zero mixed) with zero ``header_residual`` bits, and
``header_residual_ok`` is pinned so a new split is surfaced, not mis-read.
The split is grounded by a cross-generation Rosetta stone. The same
14-rule control-plane table on an SDX55 layout-A build (LV55) and an SDX65
layout-B build (EM9291) aligns rule-for-rule, and ``rt_tbl_idx`` (3, 4, 2, 5)
and ``action`` (0 / 3) match on every aligned rule. ``rule_id`` is unique and
increasing in every table. Full bit tables and evidence: ``_ipa_rules``. The
``rt_tbl_idx`` / ``action`` names are IPA terminology (CANDIDATE meaning; the
bit positions are grounded).

``table_id`` is F3-labelled on MDM9655 (v0x02): a lone
``FLTR_TBL_TYPE_DL_IPV4/IPV6`` print is followed by exactly table_id 2 (sub
0/1) + table_id 0 (sub 1), 8/8. table_id 1 (the DHCP/DNS/SYN control table)
and 3 have no lone label there. ``pad14`` is uninitialised padding (byte-
identical bodies carry up to 165 different values). ``dump_word`` and
``table_word`` are named raw: constant per burst / per (build, table), with
their meaning still open.

## Corpus (every capture < 50 MB with a sidecar, 464 of 643 — ~55% of indexed records)

Every 0x1855 record walks to exactly ``body_len`` with zero desyncs:
9,892 records at versions 0x02/0x03/0x04/0x06 and 80 at 0x01,
57,192 rules decoded. ``walk_status`` is pinned to ``'exact'`` so a future
layout drift is surfaced by ``check_invariants``, not silently mis-walked.

Log name: LOG_EVENTS_DS_GSM_HANDOVER_END
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_IPA_FLT_RULE_TABLE_DUMP
from diaggrok.parsers._ipa_rules import SUPPORTED_VERSIONS, decode_dump
from diaggrok.registry import register

_IP_FAMILY = {0: 'ipv4', 1: 'ipv6'}


@dataclass
class Diag0x1855:
    """IPA filter-rule table dump (0x1855)."""

    log_time: int
    version: int
    timetick: int
    dump_word: int
    table_id: int
    table_sub: int
    table_word: int | None
    body_len: int
    body_len_ok: bool
    pad14: int | None
    header_len: int
    rule_generation: str
    rule_count: int
    header_layout: str | None
    header_residual_ok: bool
    walk_status: str
    trailer_magic: bool
    payload_size: int
    config_word: int | None        # u32 view of [8:12] (v >= 0x02), kept for continuity
    rules: list[dict[str, Any]] = field(default_factory=list)
    raw: bytes = b''

    @property
    def ip_family(self) -> str:
        return _IP_FAMILY.get(self.table_sub, f'unknown_{self.table_sub}')

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1855',
            'log_time': self.log_time,
            'version': self.version,
            'timetick': self.timetick,
            'dump_word': self.dump_word,
            'table_id': self.table_id,
            'table_sub': self.table_sub,
            'ip_family': self.ip_family,
            'table_word': self.table_word,
            'body_len': self.body_len,
            'body_len_ok': self.body_len_ok,
            'pad14': self.pad14,
            'header_len': self.header_len,
            'config_word': self.config_word,
            'payload_size': self.payload_size,
            'rule_generation': self.rule_generation,
            'rule_count': self.rule_count,
            'header_layout': self.header_layout,
            'header_residual_ok': self.header_residual_ok,
            'walk_status': self.walk_status,
            'trailer_magic': self.trailer_magic,
            'rules': self.rules,
        }


@register(
    LOG_IPA_FLT_RULE_TABLE_DUMP,
    name="0x1855",
    description=(
        "IPA hardware filter-rule table dump (log-mask-change triggered) — "
        "IPv4/IPv6 packet classifiers, fully walked"
    ),
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "IPA filter-rule table dump, NOT GNSS. Body walked as IPA HW rules "
        "(en_rule equation bitmap + extra/rest operand areas; IPA v2 layout "
        "for version 0x01) — every corpus record consumes exactly body_len. "
        "F3: fires <0.1 ms after 'Diag log mask change' (uim_sigs.c / mplm.c) "
        "and on each table commit (ipa_ipfltr.c FLTR_TBL_TYPE_DL_IPV4/IPV6). "
        "meq128@24 = AT+CGPADDR IPv6 in 2/2 paired captures. table_sub = IP family (zero cross-family rules). The u24 "
        "at [1:4] is a truncated system timer (1.024 kHz sclk / 1.171875 kHz "
        "QTimer), not a session tag. Rule-header words split into "
        "rt_tbl_idx/action/priority/rule_id per header layout A/B, detected "
        "per record (version 0x03 carries both); cross-generation rule-for-rule "
        "alignment SDX55<->SDX65, 0 residual bits on 16,894 records; table_id "
        "F3-labelled (FLTR_TBL_TYPE_DL -> table_id 2/0). A declared body_len "
        "that overruns the payload returns None. dump_word / table_word "
        "semantics remain open."
    ),
    source_url="",
    # 13 header fields + per-rule en_rule/equations + dump_word/table_word/
    # pad14 (named; pad14 grounded as padding, the other two semantics open)
    # + the rule-header split (rt_tbl_idx, action, priority, rule_id,
    # w2_bit10, prio_bit9) that replaces the opaque word2/4/6.
    fields_parsed=23,
    fields_identified=23,
    field_invariants={
        "version": {"enum": list(SUPPORTED_VERSIONS)},
        "walk_status": {"enum": ["exact"]},
        "body_len_ok": {"enum": [True]},
        "header_layout": {"enum": [None, "ipa_v2", "A", "B"]},
        "header_residual_ok": {"enum": [True]},
    },
    issues=(),
    primary_issue=None,
)
def parse_0x1855(log_time: int, data: bytes) -> Diag0x1855 | None:
    """Parse an 0x1855 IPA filter-rule table dump."""
    d = decode_dump(data, v1_len_at=10)
    if d is None:
        return None
    return Diag0x1855(
        log_time=log_time,
        version=d['version'],
        timetick=d['timetick'],
        dump_word=d['dump_word'],
        table_id=d['table_id'],
        table_sub=d['table_sub'],
        table_word=d['table_word'],
        body_len=d['body_len'],
        body_len_ok=d['body_len_ok'],
        pad14=d['pad14'],
        header_len=d['header_len'],
        rule_generation=d['rule_generation'],
        rule_count=d['rule_count'],
        header_layout=d['header_layout'],
        header_residual_ok=d['header_residual_ok'],
        walk_status=d['walk_status'],
        trailer_magic=d['trailer_magic'],
        payload_size=len(data),
        config_word=unpack_from('<I', data, 8)[0] if d['header_len'] == 16 else None,
        rules=d['rules'],
        raw=bytes(data),
    )
