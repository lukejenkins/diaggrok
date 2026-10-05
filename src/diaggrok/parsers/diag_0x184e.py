"""0x184E — LOG_CALL_MANAGER_SERVING_SYSTEM_MSIM_EVENT (CM SS MSIM event).

**Not GNSS.** Despite sitting in a GNSS-heavy code range (a "GNSS ME BeiDou
B2b" label circulates for it without any source), 0x184E is
``LOG_CALL_MANAGER_SERVING_SYSTEM_MSIM_EVENT`` ("Call Manager Serving System
MSIM Event", from a community log-name table), the multi-SIM sibling of
0x134F ``LOG_CM_SS_EVENT_C``. The observations rule out a GNSS reading — it
fires with BeiDou disabled (``gnssconfig=6``), on GPS+GLONASS-only MC7455
silicon, with no antenna, near-constant ~periodic frames — because it is a
Call-Manager serving-system snapshot, one record per CM SS event delivered to
the ATCoP MSIM callback.

## F3 + 0x60 grounding

Every version is grounded on its own records against co-emitted firmware
prints (ordinal / nearest-tick pairing):

| ver | capture (chipset, size) | oracle | result |
|---|---|---|---|
| 0x05 | RM520N-GL SDX62 1141 B, AT-correlation capture | ``dsatcmif_ex.c`` ``In cmif_ss_event_msim_cb_func: event %d CM Subs ID %d number of stack %d`` | **519/519** records paired, event/asubs_id/number_of_stacks equal 519/519 |
| 0x05 | same | ``stack_id = %d, rssi = %d, rssi2, rscp, bit_err_rate, ecio …`` | 519 prints = 519 event-1 records; rssi 125 / ecio 5 / rssi2 −125 / rscp −125 byte-equal |
| 0x05 | same | ``CTCC_PROC_IsNR5G serving PLMN 310260`` (519×) | stack PLMN ``13 00 62`` = 310-260 |
| 0x02 | FN980 SDX55 1946 B, mmW camp | cmif_ss_event_msim_cb_func | **178/178** incl. both event-0 records |
| 0x02 | RM500Q SDX55 1934 B, AT-correlation capture | ``stack_id = %d, rssi = %d …`` | 144 prints = 144 event-1 records |
| 0x01 | LM960 SDX20 1883 B, correlation capture | cmif_ss_event_msim_cb_func | **183/183** event (95×0 / 88×1) |
| 0x01 | same | ``cmss.c`` ``=CM= CMSS Change … new sys_mode %d, srv_status %d`` | sys_mode+srv_status **183/183** (mode 0/9, srv 0/1) |
| 0x01 | same | ``cmss.c`` ``stack %d: ss_info_ptr->changed_fields %d, …changed_fields2 %d`` | **147/183** exact (misses: RSSI events carry 0 where CM's pre-print has 0x1f80) |
| 0x01 | same | ``0x60 EVENT_CM_DS_SYSTEM_MODE`` (payload[1]) | = sys_mode **24/24** |
| 0x01 | same | ``0x60 EVENT_CM_SERVICE_CONFIRMED`` (payload[1:4]) | = ``plmn_268`` **12/12** incl. a 310-260 ↔ 310-410 switch |
| 0x01 | EG25-G MDM9x07 1871 B, cold start | ``[chris]cmif_ss_event_msim_cb_func`` + ``CM_SS_EVENT_SRV_CHANGED ind %d`` | 121/121; the 2 SRV_CHANGED prints = the 2 event-0 records |
| 0x01 | same | ``NET_NOTE: srv:SYS_SRV_STATUS_LIMITED, domain:SYS_SRV_DOMAIN_NO_SRV, sys_mode:SYS_SYS_MODE_LTE`` | srv_status 1 / srv_domain 0 / sys_mode 9 |

Black-box oracle (qcsuper/SCAT): **absent** — neither decodes 0x184E.

Structural invariants measured on the same 1,165 records (5 captures, 3 versions):
event 1 ⇒ ``signal_changed_fields`` ≠ 0 and both changed-field masks = 0
(1,346/1,346 incl. sets not listed); event 0 ⇒ ``signal_changed_fields`` = 0;
``rssi2 == −rssi`` 1,165/1,165.

## Layout

    [0]      u8   version            0x01 / 0x02 / 0x05
    [1..5)   u32  event              cm_ss_event: 0 = CM_SS_EVENT_SRV_CHANGED,
                                     1 = RSSI report (see EVENT_NAMES); 12, 24 seen raw
    [5..9)   u32  asubs_id           CM subscription id
    [9]      u8   number_of_stacks

    v0x01: [10 .. 10+2×750)  stack[0], stack[1]    then subs_block (361 / 373 B)
    v0x02: [10 .. 10+2×754)  stack[0], stack[1]    then subs_block (416 / 428 B)
    v0x05: [10 .. 387)       subs_block (377 B)    then stack[0] (754 B) — 1141 B exact

The v0x01/0x02 subs_block has no length field; the parser accepts only the
attested sizes (v1 361/373, v2 416/428) or anything longer than them, and
returns None for a shorter unattested block (a truncated record).

v0x01/0x02 always emit two stack slots (stack[1] is zero/default when
``number_of_stacks`` = 1); v0x05 emits one. The v0x05 377-B prefix matches the
v0x01/0x02 trailing block (``0x0b`` at +0x12, a counter-like u32 at +0x08), so
it is the same subscription-level block moved ahead of the stack. Stack offsets
proven by three anchors that shift together: PLMN at stack+0x3a / +0x268 and
the signal block at +650 (v0x05 = v0x01/0x02 + 377 for all three). The v0x02
stack is 4 B longer than v0x01 somewhere after +650. The ``_compact`` sizes
(1871 vs 1883, 1934 vs 1946) differ only in the subs_block length.

Per stack (offsets relative to the stack start):

    +0x000 u64  changed_fields           F3 cmss.c:6927 (low 32 bits printed)
    +0x008 u64  changed_fields2          F3 cmss.c:6927
    +0x010 u32  signal_changed_fields    non-zero exactly on RSSI events
    +0x014 u32  u32_014                  raw
    +0x018 u8   is_operational           1 on the active stack, 0 on the idle slot
    +0x019 u32  srv_status               sys_srv_status (0 NO_SRV, 1 LIMITED, 2 SRV) — F3 183/183
    +0x01d u32  u32_01d                  raw (0/2/3 observed; not true_srv_status)
    +0x021 u32  srv_domain               sys_srv_domain — F3 NET_NOTE (CANDIDATE on 1 value)
    +0x025 u32  srv_capability           sys_srv_domain — CANDIDATE (PS_ONLY on NR5G SA)
    +0x029 u32  sys_mode                 sys_sys_mode (0 NO_SRV, 9 LTE, 12 NR5G) — F3 183/183, 0x60 24/24
    +0x02d u32  u32_02d                  raw (0xff / 0x1ff mask-shaped)
    +0x03a 3B   plmn_03a                 TS 24.008 TBCD PLMN; populated once registered
    +0x268 3B   plmn_268                 TBCD PLMN = EVENT_CM_SERVICE_CONFIRMED PLMN 12/12
    +0x28a u16  rssi                     = F3 rssi (125 = none)
    +0x28c u16  ecio                     = F3 ecio
    +0x297 s16  rssi2                    = F3 rssi2 (always −rssi)
    +0x299 s16  rscp                     = F3 rscp
    +0x2e1 s16  s16_2e1   (v0x02/0x05)   CANDIDATE filtered RSRP dBm: within ±2 dB of the co-emitted
                                         NR5G serving RSRP (mode Δ 0/−1, 519 records) but sticky
    +0x2e3 s16  s16_2e3   (v0x02/0x05)   CANDIDATE ≈10×SINR (tracks +QENG SINR; Pearson 0.63 vs RSRP)

Everything else in a stack and the whole subs_block stays raw (``raw``). Parts
are CM stack residue, not data: a v0x05 subs_block region at +0x3f0 carries
nibble-shifted ASCII fragments (``…rfw…cmd…pro…sys.c``) that change every
record — do not name bytes there.

Enum names used for ``event_name`` are the firmware's own strings where F3
printed them (``CM_SS_EVENT_SRV_CHANGED``); event 1 is labeled
``CM_SS_EVENT_RSSI`` because the ATCoP RSSI-report print fires once per
event-1 record (144/144, 519/519) and only event-1 records carry a signal
changed-mask. Other event values are emitted raw.

Log name: LOG_CALL_MANAGER_SERVING_SYSTEM_MSIM_EVENT
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_CM_SS_MSIM_EVENT
from diaggrok.registry import register

HEADER_LEN = 10
# version → (stack stride, stack slots emitted, subs_block leads the stacks)
_LAYOUT = {
    0x01: (750, 2, False),
    0x02: (754, 2, False),
    0x05: (754, 1, True),
}
V5_SUBS_BLOCK_LEN = 377
# v0x01/0x02 put the subscription block LAST and it carries no length field, so
# the payload's end is the only delimiter. Attested trailing-block sizes per
# version: a block that is shorter than the longest attested size and is
# not itself an attested size cannot be told apart from a truncated record, so
# it returns None (registry WARN). A block longer than every attested size is
# still accepted (size_variant 'unknown') — that is a longer record, not a cut one.
_TRAILING_SUBS_LENS = {
    0x01: (361, 373),
    0x02: (416, 428),
}

EVENT_NAMES = {
    0: 'CM_SS_EVENT_SRV_CHANGED',
    1: 'CM_SS_EVENT_RSSI',
}
SRV_STATUS_NAMES = {0: 'NO_SRV', 1: 'LIMITED', 2: 'SRV', 3: 'LIMITED_REGIONAL', 4: 'PWR_SAVE'}
SYS_MODE_NAMES = {0: 'NO_SRV', 3: 'GSM', 5: 'WCDMA', 9: 'LTE', 11: 'TDS', 12: 'NR5G'}


def _classify_variant(version: int, payload_size: int) -> str:
    """Name the observed (version, size) profile; the layout itself is keyed on version."""
    return {
        (0x01, 1883): 'v1_1883',
        (0x01, 1871): 'v1_1871',
        (0x02, 1946): 'v2_1946',
        (0x02, 1934): 'v2_1934',
        (0x05, 1141): 'v5_1141',
    }.get((version, payload_size), 'unknown')


def _plmn(b3: bytes) -> str | None:
    """TS 24.008 TBCD PLMN → 'MCC-MNC', or None when unset (all-zero)."""
    if b3 == b'\x00\x00\x00':
        return None
    mcc = f"{b3[0] & 0xF}{b3[0] >> 4}{b3[1] & 0xF}"
    mnc3 = b3[1] >> 4
    mnc = f"{b3[2] & 0xF}{b3[2] >> 4}" + ('' if mnc3 == 0xF else f"{mnc3}")
    return f"{mcc}-{mnc}"


@dataclass
class CmSsStack:
    """One per-stack block of the CM SS MSIM event."""
    changed_fields: int
    changed_fields2: int
    signal_changed_fields: int
    u32_014: int
    is_operational: int
    srv_status: int
    u32_01d: int
    srv_domain: int
    srv_capability: int
    sys_mode: int
    u32_02d: int
    plmn_03a: str | None
    plmn_268: str | None
    rssi: int
    ecio: int
    rssi2: int
    rscp: int
    s16_2e1: int | None      # v0x02/0x05 only — CANDIDATE RSRP dBm
    s16_2e3: int | None      # v0x02/0x05 only — CANDIDATE ≈10×SINR

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d['changed_fields'] = f"0x{self.changed_fields:016x}"
        d['changed_fields2'] = f"0x{self.changed_fields2:016x}"
        d['signal_changed_fields'] = f"0x{self.signal_changed_fields:08x}"
        d['srv_status_name'] = SRV_STATUS_NAMES.get(self.srv_status)
        d['sys_mode_name'] = SYS_MODE_NAMES.get(self.sys_mode)
        return d


def _parse_stack(data: bytes, o: int, version: int) -> CmSsStack:
    s = o
    return CmSsStack(
        changed_fields=unpack_from('<Q', data, s)[0],
        changed_fields2=unpack_from('<Q', data, s + 0x08)[0],
        signal_changed_fields=unpack_from('<I', data, s + 0x10)[0],
        u32_014=unpack_from('<I', data, s + 0x14)[0],
        is_operational=data[s + 0x18],
        srv_status=unpack_from('<I', data, s + 0x19)[0],
        u32_01d=unpack_from('<I', data, s + 0x1d)[0],
        srv_domain=unpack_from('<I', data, s + 0x21)[0],
        srv_capability=unpack_from('<I', data, s + 0x25)[0],
        sys_mode=unpack_from('<I', data, s + 0x29)[0],
        u32_02d=unpack_from('<I', data, s + 0x2d)[0],
        plmn_03a=_plmn(bytes(data[s + 0x3a:s + 0x3d])),
        plmn_268=_plmn(bytes(data[s + 0x268:s + 0x26b])),
        rssi=unpack_from('<H', data, s + 0x28a)[0],
        ecio=unpack_from('<H', data, s + 0x28c)[0],
        rssi2=unpack_from('<h', data, s + 0x297)[0],
        rscp=unpack_from('<h', data, s + 0x299)[0],
        s16_2e1=None if version == 0x01 else unpack_from('<h', data, s + 0x2e1)[0],
        s16_2e3=None if version == 0x01 else unpack_from('<h', data, s + 0x2e3)[0],
    )


@dataclass
class Diag0x184E:
    """CM Serving-System MSIM event (0x184E) — header + per-stack serving state."""
    log_time: int
    version: int
    event: int
    asubs_id: int
    number_of_stacks: int
    stacks: list[CmSsStack]
    subs_block: bytes
    payload_size: int
    size_variant: str
    raw: bytes

    @property
    def event_name(self) -> str | None:
        return EVENT_NAMES.get(self.event)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x184E',
            'log_time': self.log_time,
            'version': self.version,
            'event': self.event,
            'event_name': self.event_name,
            'asubs_id': self.asubs_id,
            'number_of_stacks': self.number_of_stacks,
            'stacks': [s.to_dict() for s in self.stacks],
            'subs_block_len': len(self.subs_block),
            'payload_size': self.payload_size,
            'size_variant': self.size_variant,
        }


@register(
    LOG_CM_SS_MSIM_EVENT,
    name="0x184E",
    description=(
        "LOG_CALL_MANAGER_SERVING_SYSTEM_MSIM_EVENT — CM serving-system MSIM event: "
        "event / asubs_id / stack count + per-stack changed masks, srv_status, "
        "srv_domain, sys_mode, PLMNs, RSSI block (F3-grounded v1/v2/v5)"
    ),
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "0x184E is the Call-Manager serving-system MSIM event (the only sourced name), "
        "not GNSS. F3-grounded per version: v0x05 "
        "RM520N 519/519 records = dsatcmif cmif_ss_event_msim_cb_func (event/asubs_id/"
        "number_of_stacks equal); v0x02 FN980 178/178, RM500Q 144 RSSI prints = 144 event-1 "
        "records; v0x01 LM960 183/183 event and sys_mode+srv_status 183/183 vs cmss.c, "
        "changed_fields/changed_fields2 147/183 vs cmss.c:6927, 0x60 EVENT_CM_DS_SYSTEM_MODE "
        "24/24 and EVENT_CM_SERVICE_CONFIRMED PLMN 12/12; EG25-G 121/121 + "
        "CM_SS_EVENT_SRV_CHANGED 2/2. Layout: 10-B header, 750-B (v1) / 754-B (v2, v5) stack "
        "blocks — two slots then the subscription block on v1/v2, subscription block (377 B) "
        "then one slot on v5; 5 size variants. The v0x01/0x02 trailing subs_block has no "
        "length field; a block shorter than the longest attested size (v1 361/373, v2 "
        "416/428) that is not itself attested returns None."
    ),
    source_url="",
    # Named fields: header 4 (version, event, asubs_id, number_of_stacks) + 19 per-stack
    # (changed_fields, changed_fields2, signal_changed_fields, u32_014, is_operational,
    # srv_status, u32_01d, srv_domain, srv_capability, sys_mode, u32_02d, plmn_03a,
    # plmn_268, rssi, ecio, rssi2, rscp, s16_2e1, s16_2e3) + subs_block = 24. The
    # raw-typed u32_014 / u32_01d / u32_02d / s16_* and the opaque subs_block are all
    # exposed; stack bytes outside these offsets are stack residue / unmodeled and
    # are not counted as identified fields.
    fields_parsed=24,
    fields_identified=24,
    field_invariants={
        "version": {"enum": [0x01, 0x02, 0x05]},
        "number_of_stacks": {"range": (0, 2)},
    },
    issues=(),
    primary_issue=None,
)
def parse_0x184e(log_time: int, data: bytes) -> Diag0x184E | None:
    """Parse LOG_CALL_MANAGER_SERVING_SYSTEM_MSIM_EVENT (0x184E)."""
    if len(data) < HEADER_LEN:
        return None
    version = data[0]
    layout = _LAYOUT.get(version)
    if layout is None:
        return None
    stride, slots, subs_first = layout
    n = len(data)
    stacks_start = HEADER_LEN + (V5_SUBS_BLOCK_LEN if subs_first else 0)
    stacks_end = stacks_start + slots * stride
    if n < stacks_end:
        return None
    if subs_first:
        subs_block = bytes(data[HEADER_LEN:stacks_start])
    else:
        subs_block = bytes(data[stacks_end:])
        known = _TRAILING_SUBS_LENS[version]
        if len(subs_block) not in known and len(subs_block) < max(known):
            return None  # truncated (or unattested shorter) trailing block
    return Diag0x184E(
        log_time=log_time,
        version=version,
        event=unpack_from('<I', data, 1)[0],
        asubs_id=unpack_from('<I', data, 5)[0],
        number_of_stacks=data[9],
        stacks=[_parse_stack(data, stacks_start + i * stride, version) for i in range(slots)],
        subs_block=subs_block,
        payload_size=n,
        size_variant=_classify_variant(version, n),
        raw=bytes(data),
    )
