# diaggrok-provenance: re
"""IPA hardware filter/routing rule walker — shared by 0x1855 / 0x1856.

0x1855 and 0x1856 dump tables of IPA (IP Accelerator) hardware rules. A rule
is a header word whose low 16 bits are ``en_rule`` — a bitmap of which match
*equations* the rule uses — followed by the equation operands. The body of a
rule is fully determined by ``en_rule``, which is what makes a table walkable
without knowing what the rule *does*.

Two on-wire rule generations are attested across the captures walked:

* **IPA v3+ layout** (record ``version`` >= 0x02, 16-byte record header):
  8-byte rule header ``<u16 en_rule, u16 word2, u16 word4, u16 word6>``, then
  an "extra" area of one byte per offset/u8-valued equation (0, 8 or 16 bytes),
  then a "rest" area of mask/value operands, padded to 8 bytes.
* **IPA v2 layout** (record ``version`` == 0x01, 12-byte record header):
  4-byte rule header ``<u16 en_rule, u16 word2>``, then each equation's
  operands in bit order, each padded to 4 bytes.

The two generations assign ``en_rule`` bits differently (tables below).
Equation names (``meq32``, ``ihl_range16``, …) follow the terminology of the
public Linux IPA driver; no code is derived from it — every bit position and
operand size here was confirmed against corpus bytes (the walk below).

Grounding (structural — the black-box oracles are silent on both codes): the
walker consumes every corpus record's body to *exactly* the firmware-declared
body length with only zero bytes between tables (464 captures / 450 bearing: 0x1855 9,892 records at v0x02-v0x06 + 80 at v0x01, 57,192 rules;
0x1856 4,601 + 36, 19,702 rules; zero desyncs). The operands decode to
recognisable packet classifiers — UDP dport 67/53/547, TCP SYN/FIN/RST flag
masks, ICMPv6 type 134/128/129, IPv4/IPv6 version-nibble matches, an IPv4
total-length == 40 pure-ACK match, the IPv6 destination address at L3 offset
24 — which is what an IPA filter/routing table holds.

Rule-header words — ``word2``/``word4``/``word6`` stay
exposed raw, and ``split_rule_headers`` adds a decoded per-rule ``header``
dict. Two IPA v3+ header layouts exist and the record ``version`` byte does
NOT select between them: SDX55 builds emit layout A at version 0x03, and
RM520N-GL / Inseego M3100 / T99W175 (SDX62-class) builds emit layout B
at the same 0x03. The layout is therefore detected per record from the words
themselves (``header_layout``). With ``u = word4 | word6 << 16``:

* **layout A** (MDM9x50/SDX20 v0x02, SDX55 v0x03) — filter: ``word2`` =
  ``action:5 | rt_tbl_idx:5 | w2_bit10:1``, ``priority = word4 & 0x3FF``,
  ``rule_id = word6 & 0x3FF`` (always ``0x200 | priority`` in the corpus, so
  ``word6`` bit 9 is set on every layout-A filter rule — the discriminator).
  Routing: ``word2`` = ``pipe:5 | 0:1 | hdr_index:9 | hdr_flag:1``,
  ``priority = word4 & 0x3FF``, ``rule_id = word6 & 0x3FF`` (equal to each
  other on every rule), ``w4_bit15``.
* **layout B** (SDX62/65/72 v0x03/v0x04/v0x06) — filter: ``rt_tbl_idx =
  word2`` (bits 5-15 always 0), ``priority = u & 0xFF``, ``prio_bit9``,
  ``rule_id = (u >> 10) & 0x3FF`` (base 0x200 or 0x300 by build),
  ``action = (u >> 20) & 3``. Routing: ``pipe = word2 & 0x1F``, ``priority =
  u & 0x3FF``, ``rule_id = (u >> 10) & 0x3FF``, ``hdr_index = (u >> 20) &
  0x1FF``, ``hdr_flag`` (bit 29), ``u_bit30``.
* **IPA v2** (``version`` 0x01) — the 16-bit ``word2`` has the layout-A
  ``word2`` split (filter action / rt_tbl_idx / w2_bit10; routing pipe); there
  is no priority / rule-id word.

Grounding — 16,894 corpus records (every bearing capture < 100 MB, 532
captures), zero ``header_residual`` bits set, zero mixed-layout records:

* **Cross-generation Rosetta stone.** The same control-plane filter table
  (table_id 1, 14 rules) on an SDX55 layout-A build (LV55) and an SDX65
  layout-B build (EM9291) aligns rule-for-rule by ``en_rule`` + operands: the
  layout-A ``(word2 >> 5) & 0x1F`` (3, 4, 2, 5) equals the layout-B ``word2``
  (3, 4, 2, 5) on every aligned rule, and the layout-A ``word2 & 0x1F`` action
  (0 / 3) equals the layout-B ``(u >> 20) & 3`` (0 / 3). Routing ``hdr_index``
  aligns the same way: LV55 pipe-0x15 rule ``word2 = 0x0195`` (index 6) vs
  RM520N/M3100 pipe-0x15 ``u >> 20 = 0x006``; LV55 pipe-0x13/0x14 ``0x8213`` /
  ``0x8214`` (index 8, flag) vs M3100 ``0x20d`` / ``0x20e`` (index 13/14, flag).
* **rule_id** is unique within every filter table (8,463 layout-A + 2,069
  layout-B tables) and strictly increasing in walk order; layout-A filter
  ``priority`` is strictly increasing in walk order in every table. Layout-B
  ``priority`` equals ``rule_id & 0xFF`` on all 12,940 rules (bit 8 never set);
  routing ``priority == rule_id`` on every rule of both layouts (routing ids
  repeat within some layout-A tables, so they are not unique there).
* The routing ``pipe`` values (8..31) are IPA endpoint-sized small integers,
  and ``rt_tbl_idx``/``action`` names follow IPA terminology — those two
  readings are CANDIDATE (structure grounded; the meaning is by analogy).
  ``w2_bit10``, ``prio_bit9``, ``w4_bit15``, ``u_bit30`` are single bits whose
  meaning is unknown and are named by position.

meq32 masks/values are the u32 as written by the firmware (little-endian on the
wire) and compare the BIG-endian packet word at ``offset``: mask 0xF0000000 /
value 0x40000000 at offset 0 is "IP version nibble == 4". IPA v3+ meq128
operands follow the same convention (a little-endian u128) and are returned in
network byte order with the masked ``address`` and ``prefix_len`` (see
``_meq128``); IPA v2 meq128 operands are returned as wire-order hex (none occur
in the corpus to pin their order).
"""
from __future__ import annotations

import ipaddress
from struct import error as StructError, unpack_from
from typing import Any

# 0xDEADC0FE — a fill/terminator word seen as the final 4 bytes of some tables.
TRAILER_MAGIC = b'\xfe\xc0\xad\xde'

# IPA v3+ en_rule bit -> equation name (the order the operands are written in
# is the same as the bit order within each group, see _parse_rule_v3).
V3_EQUATIONS = (
    'tos', 'protocol', 'tc', 'meq128_0', 'meq128_1', 'meq32_0', 'meq32_1',
    'ihl_meq32_0', 'ihl_meq32_1', 'metadata', 'ihl_range16_0',
    'ihl_range16_1', 'ihl_eq32', 'ihl_eq16', 'fl_eq', 'is_frag',
)
# en_rule bits that consume one byte of the v3 "extra" area.
_V3_EXTRA_BITS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13)

# IPA v2 en_rule bit -> (equation name, padded operand bytes).
V2_EQUATIONS = (
    ('tos', 4), ('protocol', 4), ('meq32_0', 12), ('meq32_1', 12),
    ('ihl_range16_0', 8), ('ihl_range16_1', 8), ('ihl_eq16', 4),
    ('ihl_eq32', 8), ('ihl_meq32_0', 12), ('meq128_0', 36), ('meq128_1', 36),
    ('tc', 4), ('fl_eq', 4), ('ihl_meq32_1', 12), ('metadata', 8),
    ('is_frag', 0),
)


class RuleWalkError(ValueError):
    """A rule header whose operands do not fit the table."""


def _meq128(offset: int, mask_wire: bytes, value_wire: bytes) -> dict[str, Any]:
    """A 128-bit masked compare, returned in network byte order.

    The firmware stores each 16-byte operand as a little-endian u128 of the
    big-endian packet field (the same convention as meq32), so reversing the
    bytes yields network order: a /64 source-prefix rule reads mask
    ``ffff:ffff:ffff:ffff::`` and its value the prefix. At IPv6 header offset
    8 (source) or 24 (destination) the value is an IPv6 address — the UE's own
    on a live modem (PII: decoded in full, never committed from a real capture).
    """
    mask = int.from_bytes(mask_wire, 'little')
    value = int.from_bytes(value_wire, 'little')
    ones = bin(mask).count('1')
    contiguous = mask == ((1 << 128) - 1) ^ ((1 << (128 - ones)) - 1)
    return {
        'offset': offset,
        'mask': f'{mask:032x}',
        'value': f'{value:032x}',
        'address': str(ipaddress.IPv6Address(value & mask)),
        'prefix_len': ones if contiguous else None,
    }


def _parse_rule_v3(b: bytes, o: int) -> tuple[dict[str, Any], int]:
    en, w2, w4, w6 = unpack_from('<HHHH', b, o)
    n_extra = sum(1 for i in _V3_EXTRA_BITS if en >> i & 1)
    if n_extra > 13:
        raise RuleWalkError(f'{n_extra} extra bytes')
    extra_len = 0 if n_extra == 0 else (8 if n_extra <= 8 else 16)
    extra = b[o + 8:o + 8 + extra_len]
    p = o + 8 + extra_len
    xi = 0
    eq: dict[str, Any] = {}

    def take() -> int:
        nonlocal xi
        v = extra[xi]
        xi += 1
        return v

    for bit, name in ((0, 'tos'), (1, 'protocol'), (2, 'tc')):
        if en >> bit & 1:
            eq[name] = take()
    for bit in (3, 4):                       # meq128: mask/value interleaved per 8 bytes
        if en >> bit & 1:
            off = take()
            m = b[p:p + 8] + b[p + 16:p + 24]
            v = b[p + 8:p + 16] + b[p + 24:p + 32]
            p += 32
            eq[V3_EQUATIONS[bit]] = _meq128(off, m, v)
    for bit in (5, 6, 7, 8):                 # meq32 / ihl_meq32: u32 mask, u32 value
        if en >> bit & 1:
            off = take()
            m, v = unpack_from('<II', b, p)
            p += 8
            eq[V3_EQUATIONS[bit]] = {'offset': off, 'mask': m, 'value': v}
    if en >> 9 & 1:
        m, v = unpack_from('<II', b, p)
        p += 8
        eq['metadata'] = {'mask': m, 'value': v}
    for bit in (10, 11):                     # range16: high then low
        if en >> bit & 1:
            off = take()
            hi, lo = unpack_from('<HH', b, p)
            p += 4
            eq[V3_EQUATIONS[bit]] = {'offset': off, 'low': lo, 'high': hi}
    if en >> 12 & 1:
        off = take()
        eq['ihl_eq32'] = {'offset': off, 'value': unpack_from('<I', b, p)[0]}
        p += 4
    if en >> 13 & 1:
        off = take()
        eq['ihl_eq16'] = {'offset': off, 'value': unpack_from('<H', b, p)[0]}
        p += 4
    if en >> 14 & 1:
        eq['fl_eq'] = unpack_from('<I', b, p)[0] & 0xFFFFF
        p += 4
    if en >> 15 & 1:
        eq['is_frag'] = True
    if any(extra[xi:]):
        raise RuleWalkError('non-zero unused extra bytes')
    p = o + ((p - o + 7) // 8) * 8
    rule = {'offset': o, 'en_rule': en, 'word2': w2, 'word4': w4, 'word6': w6,
            'equations': eq}
    return rule, p


def _parse_rule_v2(b: bytes, o: int) -> tuple[dict[str, Any], int]:
    en, w2 = unpack_from('<HH', b, o)
    p = o + 4
    eq: dict[str, Any] = {}
    for bit, (name, size) in enumerate(V2_EQUATIONS):
        if not en >> bit & 1:
            continue
        f = b[p:p + size]
        if len(f) < size:
            raise RuleWalkError(f'{name} operands overrun')
        if name in ('tos', 'protocol', 'tc'):
            eq[name] = f[0]
        elif name in ('meq32_0', 'meq32_1', 'ihl_meq32_0', 'ihl_meq32_1'):
            m, v = unpack_from('<II', f, 1)
            eq[name] = {'offset': f[0], 'mask': m, 'value': v}
        elif name in ('ihl_range16_0', 'ihl_range16_1'):
            # High bound first, as in v3: the EP06A v0x01 unequal-bound rules
            # read (61440, 32768) and (100, 40) in wire order.
            hi, lo = unpack_from('<HH', f, 1)
            eq[name] = {'offset': f[0], 'low': lo, 'high': hi}
        elif name == 'ihl_eq16':
            eq[name] = {'offset': f[0], 'value': unpack_from('<H', f, 1)[0]}
        elif name == 'ihl_eq32':
            eq[name] = {'offset': f[0], 'value': unpack_from('<I', f, 1)[0]}
        elif name in ('meq128_0', 'meq128_1'):
            eq[name] = {'offset': f[0], 'mask': f[1:17].hex(), 'value': f[17:33].hex()}
        elif name == 'fl_eq':
            eq[name] = unpack_from('<I', f, 0)[0] & 0xFFFFF
        elif name == 'metadata':
            m, v = unpack_from('<II', f, 0)
            eq[name] = {'mask': m, 'value': v}
        elif name == 'is_frag':
            eq[name] = True
        p += size
    return {'offset': o, 'en_rule': en, 'word2': w2, 'equations': eq}, p


def walk_rules(body: bytes, *, v2: bool) -> tuple[list[dict[str, Any]], str, bool]:
    """Walk an IPA rule-table dump.

    Returns ``(rules, status, trailer_magic)``. ``status`` is ``'exact'`` when
    the walk consumed the body with only zero padding between rules/tables
    (and at most a trailing 0xDEADC0FE word), else a diagnostic string naming
    the offset where it desynced. A non-``'exact'`` status on a real record
    means the rule layout drifted — the parser's ``walk_status`` invariant
    surfaces it.
    """
    word = 4 if v2 else 8
    parse = _parse_rule_v2 if v2 else _parse_rule_v3
    rules: list[dict[str, Any]] = []
    n = len(body)
    o = 0
    while o + word <= n:
        if body[o:o + word] == bytes(word):
            o += word
            continue
        if n - o == 4 and body[o:] == TRAILER_MAGIC:
            break
        try:
            rule, p = parse(body, o)
        except (RuleWalkError, IndexError, StructError) as exc:
            return rules, f'desync@{o}: {exc}', False
        if p > n:
            return rules, f'overrun@{o}', False
        rules.append(rule)
        o = p
    tail = body[o:]
    if tail == TRAILER_MAGIC:
        return rules, 'exact', True
    if not any(tail):
        return rules, 'exact', False
    return rules, f'tail@{o}', False


def _filter_layout(rules: list[dict[str, Any]]) -> str:
    a = [bool(r['word6'] & 0x200) for r in rules]
    return 'A' if all(a) else ('B' if not any(a) else 'mixed')


def _routing_layout(rules: list[dict[str, Any]]) -> str:
    # Layout A keeps priority and rule_id in separate words (equal values);
    # layout B packs both counters into word4, so a nonzero rule_id shows up
    # as word4 >> 10 == priority & 0x3F. A table whose ids are all 0 decodes
    # identically under either layout.
    a = all((r['word4'] & 0x3FF) == (r['word6'] & 0x3FF) for r in rules)
    b = any((r['word4'] >> 10) and (r['word4'] >> 10) == (r['word4'] & 0x3F)
            for r in rules)
    if a and not b:
        return 'A'
    if b and not a:
        return 'B'
    return 'mixed'


def _filter_header(r: dict[str, Any], layout: str) -> tuple[dict[str, Any], int]:
    w2 = r['word2']
    if layout in ('v2', 'A'):
        h = {'action': w2 & 0x1F, 'rt_tbl_idx': (w2 >> 5) & 0x1F,
             'w2_bit10': (w2 >> 10) & 1}
        residual = w2 >> 11
        if layout == 'A':
            h['priority'] = r['word4'] & 0x3FF
            h['rule_id'] = r['word6'] & 0x3FF
            residual |= (r['word4'] >> 10) | (r['word6'] >> 10)
        return h, residual
    u = r['word4'] | r['word6'] << 16
    h = {'rt_tbl_idx': w2 & 0x1F, 'action': (u >> 20) & 3, 'priority': u & 0xFF,
         'prio_bit9': (u >> 9) & 1, 'rule_id': (u >> 10) & 0x3FF}
    return h, (w2 >> 5) | ((u >> 8) & 1) | (u >> 22)


def _routing_header(r: dict[str, Any], layout: str) -> tuple[dict[str, Any], int]:
    w2 = r['word2']
    if layout == 'v2':
        return {'pipe': w2 & 0x1F}, w2 >> 5
    if layout == 'A':
        h = {'pipe': w2 & 0x1F, 'hdr_index': (w2 >> 6) & 0x1FF, 'hdr_flag': w2 >> 15,
             'priority': r['word4'] & 0x3FF, 'rule_id': r['word6'] & 0x3FF,
             'w4_bit15': r['word4'] >> 15}
        return h, ((w2 >> 5) & 1) | ((r['word4'] >> 10) & 0x1F) | (r['word6'] >> 10)
    u = r['word4'] | r['word6'] << 16
    h = {'pipe': w2 & 0x1F, 'priority': u & 0x3FF, 'rule_id': (u >> 10) & 0x3FF,
         'hdr_index': (u >> 20) & 0x1FF, 'hdr_flag': (u >> 29) & 1,
         'u_bit30': (u >> 30) & 1}
    return h, (w2 >> 5) | (u >> 31)


def split_rule_headers(rules: list[dict[str, Any]], *, routing: bool,
                       v2: bool) -> tuple[str | None, bool]:
    """Attach a decoded ``header`` dict to every rule (see module docstring).

    Returns ``(header_layout, residual_ok)``: the layout is ``'ipa_v2'``,
    ``'A'``, ``'B'``, ``'mixed'`` (rules disagree — never seen in the corpus;
    the rules are then left without ``header``) or None for an empty table.
    ``residual_ok`` is False when any header bit outside the decoded fields is
    set — a layout the corpus has not shown, surfaced by the parser invariant.
    """
    if not rules:
        return None, True
    if v2:
        layout = 'v2'
    else:
        layout = _routing_layout(rules) if routing else _filter_layout(rules)
        if layout == 'mixed':
            return 'mixed', True
    split = _routing_header if routing else _filter_header
    ok = True
    for r in rules:
        r['header'], residual = split(r, layout)
        ok = ok and residual == 0
    return ('ipa_v2' if v2 else layout), ok


# Record-header versions attested on both codes. 0x01 = 12-byte header +
# IPA v2 rules; 0x02..0x06 = 16-byte header + IPA v3+ rules. 0x05 has not been
# seen on either code.
SUPPORTED_VERSIONS = (0x01, 0x02, 0x03, 0x04, 0x06)


def decode_dump(data: bytes, *, v1_len_at: int,
                routing: bool = False) -> dict[str, Any] | None:
    """Decode the record header shared by 0x1855/0x1856 and walk the rules.

    Header (little-endian), version >= 0x02 — 16 bytes:
      [0]      u8   version (record-format byte; varies by firmware build,
                    NOT by chipset: one RM520N-GL emits 0x03 on one build and
                    0x04 on another)
      [1:4]    u24  timetick — truncated free-running system timer, shared by
                    every record of one dump burst and by sibling codes
                    0x1851/0x1852 in the same burst; advances between bursts
                    at 1.024 kHz (32.768 kHz sclk >> 5) on MDM9x40/MDM9250/
                    SDX20 and 1.171875 kHz (19.2 MHz QTimer >> 14) on
                    SDX55/62/65/72
      [4:8]    u32  dump_word — constant within a burst, varies per boot
                    ({0..6, 251} observed); changes inside a capture in 6 of
                    532 captures, always to 0. Semantics unknown, raw
      [8]      u8   table_id (0..3). F3-labelled on MDM9655 (v0x02), where a
                    lone ipa_ipfltr.c table-type print is followed only by
                    these records: FLTR_TBL_TYPE_DL_IPV4/IPV6 -> 0x1855
                    table_id 2 (sub 0/1) + 0 (sub 1), 8/8; RTNG_TBL_TYPE_UL_WWAN
                    -> 0x1856 table_id 3 (sub 0/1), 2/2; RTNG_TBL_TYPE_DL ->
                    0x1856 table_id 0 (sub 2). 0x1855 table_id 1/3 carry no
                    lone F3 label in that capture.
      [9]      u8   table_sub (0x1855: IP family 0=IPv4 / 1=IPv6)
      [10:12]  u16  table_word — constant per (build, code, table_id) in 237
                    of 240 corpus groups (the 3 exceptions are a directory
                    holding two builds); semantics unknown, raw
      [12:14]  u16  body_len == len(data) - 16
      [14:16]  u16  pad14 — uninitialised padding: 250 of 654 byte-identical
                    bodies carry more than one pad14 value (up to 165 distinct
                    values for one body), so it is independent of the content
    version 0x01 — 12 bytes: [0..8] as above, [8] table_id, then the body
    length at ``v1_len_at`` (0x1855: u16@10 with table_sub at [9];
    0x1856: u8@9).

    ``routing`` selects the routing-rule (0x1856) rather than the filter-rule
    (0x1855) rule-header split; see ``split_rule_headers``.

    Returns None for a payload too short for its header, an unknown version,
    or a declared ``body_len`` that overruns the payload (a truncated record:
    it declines loudly via the registry WARN instead of walking a short
    body). A payload LONGER than ``body_len`` still decodes, with
    ``body_len_ok`` False.
    """
    if not data or data[0] not in SUPPORTED_VERSIONS:
        return None
    v1 = data[0] == 0x01
    hdr_len = 12 if v1 else 16
    if len(data) < hdr_len:
        return None
    out: dict[str, Any] = {
        'version': data[0],
        'timetick': int.from_bytes(data[1:4], 'little'),
        'dump_word': unpack_from('<I', data, 4)[0],
        'table_id': data[8],
        'header_len': hdr_len,
    }
    if v1:
        if v1_len_at == 10:
            out['table_sub'] = data[9]
            out['table_word'] = None
            body_len = unpack_from('<H', data, 10)[0]
        else:
            out['table_sub'] = None
            body_len = data[9]
            out['table_word'] = unpack_from('<H', data, 10)[0]
        out['pad14'] = None
    else:
        out['table_sub'] = data[9]
        out['table_word'] = unpack_from('<H', data, 10)[0]
        body_len = unpack_from('<H', data, 12)[0]
        out['pad14'] = unpack_from('<H', data, 14)[0]
    if body_len > len(data) - hdr_len:
        return None  # declared body overruns the payload: truncated
    out['body_len'] = body_len
    out['body_len_ok'] = body_len == len(data) - hdr_len
    rules, status, trailer = walk_rules(bytes(data[hdr_len:]), v2=v1)
    out['rule_generation'] = 'ipa_v2' if v1 else 'ipa_v3'
    out['rules'] = rules
    out['rule_count'] = len(rules)
    out['header_layout'], out['header_residual_ok'] = split_rule_headers(
        rules, routing=routing, v2=v1)
    out['walk_status'] = status
    out['trailer_magic'] = trailer
    return out
