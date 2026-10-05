"""0x1856 — IPA hardware ROUTING-rule table dump. NOT GNSS.

Despite a circulating "GNSS ME BeiDou B1C measurement report" label (no name
source gives it; the BeiDou B1C measurement code is 0x1CC6
``LOG_GNSS_BDS_B1C_MEASUREMENT_REPORT``), the body is a dump of the modem's
**IPA (IP Accelerator) routing-rule tables**, the companion of the
filter-rule tables in 0x1855. See ``diag_0x1855`` for the trigger (a
DIAG log-mask change — F3 ``uim_sigs.c`` / ``mplm.c``), the oracle verdicts,
and the shared record header, all of which apply here unchanged; the header
and the rule walker live in ``_ipa_rules``. The F3 label for this code is
``ipa_ipfltr.c:12017 IPA_IPFLTRI_RTNG_TBL_TYPE_DL`` (MDM9655 v0x02), printed
immediately before a table-commit burst that carries 0x1856.

## What differs from 0x1855

* ``table_sub`` is NOT an IP family here: it takes {0, 1, 2}, and
  ``table_sub == 0`` tables carry both version-nibble-4 and version-nibble-6
  matches. Exposed raw. (``2`` would fit the IPA ``ipa_ip_type`` enum's MAX,
  but that is not established.)
* Each rule carries a decoded ``header``: ``pipe``
  (``word2 & 0x1F``, values 8..31, which is IPA endpoint-sized; CANDIDATE
  destination pipe), ``priority``, ``rule_id`` (equal to ``priority`` on every
  corpus rule), ``hdr_index`` + ``hdr_flag``, and the position-named bits
  ``w4_bit15`` / ``u_bit30``. The split is per ``header_layout``: in layout A
  the header index sits in ``word2`` bits 6-15, and in layout B it moves to
  ``(word4 | word6 << 16)`` bits 20-29. The version byte does not pick the
  layout (0x03 carries both). The rules align across generations: LV55 (SDX55,
  A) pipe-0x15 ``word2 = 0x0195`` (index 6) matches RM520N/M3100 (SDX62, B)
  pipe-0x15 ``u >> 20 = 0x006``, and LV55 ``0x8213``/``0x8214`` (index 8 +
  flag) match M3100 ``0x20d``/``0x20e`` (index 13/14 + flag). 5,223 records,
  zero residual bits, zero mixed layouts. Bit tables: ``_ipa_rules``.
* ``table_id`` is F3-labelled on MDM9655 (v0x02). A lone
  ``RTNG_TBL_TYPE_UL_WWAN`` print is followed by exactly table_id 3 (sub
  0/1), 2/2, and ``RTNG_TBL_TYPE_DL`` by table_id 0 (sub 2). The content
  agrees across every chipset: table 3 routes on the IP version nibble, and
  table 0 on metadata (mux id).
* Rules here are mostly single-equation (IP version nibble, metadata/mux-id
  compare, ICMPv6), with zero-padded gaps between small per-destination tables.
* ``version`` 0x01 (12-byte header) carries the body length as a u8 at [9]
  (0x1855 uses u16 at [10] with the IP family at [9]); bytes [10:12] are
  exposed as ``table_word`` (0 on every corpus record).
* Several tables end in the 0xDEADC0FE fill word (``trailer_magic``).

## Corpus (every capture < 50 MB with a sidecar, 464 of 643 — ~36% of indexed records)

Every 0x1856 record walks to exactly ``body_len``: 4,601 records at
versions 0x02/0x03/0x04/0x06 and 36 at 0x01, 19,702 rules decoded.
``walk_status`` is pinned to ``'exact'``.

The recurring ``20 00 15 00`` byte runs are not per-SV slots: they are IPA
routing rules matching IP version 4/6, and the body is static across boots.

Log name: LOG_EVENTS_DS_GSM_RESELECT_START
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_IPA_RT_RULE_TABLE_DUMP
from diaggrok.parsers._ipa_rules import SUPPORTED_VERSIONS, decode_dump
from diaggrok.registry import register


@dataclass
class Diag0x1856:
    """IPA routing-rule table dump (0x1856)."""

    log_time: int
    version: int
    timetick: int
    dump_word: int
    table_id: int
    table_sub: int | None
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
    flags_8: int | None            # u32 view of [8:12] (v >= 0x02), kept for continuity
    rules: list[dict[str, Any]] = field(default_factory=list)
    raw: bytes = b''

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1856',
            'log_time': self.log_time,
            'version': self.version,
            'timetick': self.timetick,
            'dump_word': self.dump_word,
            'table_id': self.table_id,
            'table_sub': self.table_sub,
            'table_word': self.table_word,
            'body_len': self.body_len,
            'body_len_ok': self.body_len_ok,
            'pad14': self.pad14,
            'header_len': self.header_len,
            'flags_8': self.flags_8,
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
    LOG_IPA_RT_RULE_TABLE_DUMP,
    name="0x1856",
    description=(
        "IPA hardware routing-rule table dump (log-mask-change triggered) — "
        "companion of 0x1855, fully walked"
    ),
    version=8,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "IPA routing-rule table dump, NOT GNSS (BeiDou B1C lives in 0x1CC6). "
        "Body walked as IPA HW rules — every corpus record consumes exactly "
        "body_len. Shares the 0x1855 header, trigger (DIAG log-mask change, "
        "F3 uim_sigs.c/mplm.c) and timetick. Rule-header words split into "
        "pipe/priority/rule_id/hdr_index/hdr_flag per header layout A/B, "
        "detected per record; cross-generation alignment SDX55<->SDX62, 0 "
        "residual bits; table_id F3-labelled (RTNG_TBL_TYPE_UL_WWAN -> 3, "
        "RTNG_TBL_TYPE_DL -> 0). A declared body_len that overruns the "
        "payload returns None. table_sub and the pipe meaning stay CANDIDATE."
    ),
    source_url="",
    # 13 header fields + per-rule en_rule/equations, table_sub (raw: not an IP
    # family here) + dump_word/table_word/pad14 (named; pad14 grounded as
    # padding) + the rule-header split (pipe, hdr_index, hdr_flag, priority,
    # rule_id, w4_bit15, u_bit30) that replaces the opaque word2/4/6.
    fields_parsed=24,
    fields_identified=24,
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
def parse_0x1856(log_time: int, data: bytes) -> Diag0x1856 | None:
    """Parse an 0x1856 IPA routing-rule table dump."""
    d = decode_dump(data, v1_len_at=9, routing=True)
    if d is None:
        return None
    return Diag0x1856(
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
        flags_8=unpack_from('<I', data, 8)[0] if d['header_len'] == 16 else None,
        rules=d['rules'],
        raw=bytes(data),
    )
