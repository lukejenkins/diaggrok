"""0xB0EE — LTE NAS EMM state (EMM state / substate, serving PLMN, GUTI).

Emitted on every EMM state or substate change: the TS 24.301 §5.1.3 EMM
state machine position plus the registered PLMN and the UE's current GUTI.

Layout (v0x02, the sole version; fixed 19 B; 7,267 records / 336 captures /
16 chipset families MDM9207 → SDX72)::

    [0]      u8    version          0x02 (Layer-1 gated)
    [1]      u8    emm_state        see _EMM_STATE_NAMES
    [2:4]    u16   emm_substate     LE; state-dependent enum, surfaced raw
                                    (byte [3] is 0x00 on every sampled record)
    [4:7]    3B    plmn             TS 24.008 §10.5.1.3 TBCD; ff ff ff = none
    [7]      u8    guti_valid       0 / 1
    [8]      u8    guti_ue_id_type  6 (GUTI, TS 24.301 §9.9.3.12) when valid,
                                    0xFF fill otherwise
    [9:12]   3B    guti_plmn        TBCD, wire order
    [12:14]  u16   mme_group_id     LITTLE-endian (wire GUTI is big-endian)
    [14]     u8    mme_code
    [15:19]  u32   m_tmsi           LITTLE-endian (wire GUTI is big-endian)

When ``guti_valid == 0`` bytes [8:19] are 0xFF fill and the GUTI fields are
``None``. The GUTI survives deregistration (it is kept in the USIM), so a
DEREGISTERED record may still carry ``guti_valid == 1``.

Grounding (three chipsets, two PLMNs):
  * GUTI — the NAS OTA EPS-mobile-identity IE carries the same GUTI in wire
    (big-endian) order: RM500Q-AE (SDX55) Attach Accept in 0xB0EC
    (``50 0b f6 <plmn> <mmegi BE> <mmec> <m-tmsi BE>``) equals the
    0xB0EE record that follows it, and the earlier TAU Request in 0xB0ED
    equals the 0xB0EE records before it. LV55 (SDX55) Detach Request in
    0xB0ED equals the 0xB0EE record emitted just before it. 4/4: PLMN
    byte-exact, MMEGI and M-TMSI exact once byte-swapped, MMEC exact. This
    is what pins the little-endian storage of mme_group_id / m_tmsi.
  * plmn — F3 ``emm_update_lib.c:1708`` "Attach Request, PLMN [%X %X %X]"
    prints the raw octets ``13 0 62``, equal to [4:7] of the adjacent record.
  * emm_state — F3 ``emm_esm_handler.c:2434`` "=EMM= emm_state %d" prints 2
    twice, both inside the window where 0xB0EE reads state 2 (between the
    Attach Request and Attach Accept). 0x60 ``EVENT_NAS_ATTACH`` (2556) is
    co-emitted with the entry into state 2 and with the 2 → 3 transition.
    OTA sequencing names the rest: 6 is logged immediately before an
    outgoing Detach Request; 1 follows the detach and precedes the next
    Attach Request; 3 follows Attach Accept / Complete; 5 is logged
    immediately before an outgoing Service Request.
    0 and 4 were not seen transitioning; they are named by elimination
    against the TS 24.301 state list and flagged as candidates.
  * emm_substate — no oracle labels it; surfaced raw (values 0–7 seen).
  * Black-box A/B: qcsuper + tshark on an EM7511 (MDM9x50) capture decode
    the Detach Request from RRC ULInformationTransfer (an independent path,
    not this code). Its GUTI IE and the RRCConnectionRequest s-TMSI
    (MMEC + M-TMSI) equal the GUTI of all 3 0xB0EE records in that capture,
    the first being state 6 just before the Detach Request. Neither tool
    decodes 0xB0EE itself.

The PLMN / GUTI are decoded in full; fixtures use a sentinel M-TMSI, never a
captured one.

Log name: LOG_LTE_NAS_EMM_STATE_LOG_C
Also known as: LTE NAS EMM State
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.parsers._nas_l3 import _decode_plmn_tbcd
from diaggrok.registry import register

_B0EE_VERSION_OBSERVED = 0x02
_B0EE_PAYLOAD_SIZE_OBSERVED = 19
_EPS_ID_TYPE_GUTI = 0x6

# Grounded values: see the module docstring. "(candidate)" = named by
# elimination, never observed in a grounded transition.
_EMM_STATE_NAMES = {
    0: "EMM_NULL (candidate)",
    1: "EMM_DEREGISTERED",
    2: "EMM_REGISTERED_INITIATED",
    3: "EMM_REGISTERED",
    4: "EMM_TRACKING_AREA_UPDATING_INITIATED (candidate)",
    5: "EMM_SERVICE_REQUEST_INITIATED",
    6: "EMM_DEREGISTERED_INITIATED",
}


def _plmn(b3: bytes) -> dict[str, str] | None:
    """TBCD PLMN, or None for the 0xFF fill / a non-BCD MCC."""
    if b3 == b"\xff\xff\xff":
        return None
    if any(n > 9 for n in (b3[0] & 0xF, b3[0] >> 4, b3[1] & 0xF)):
        return None
    return _decode_plmn_tbcd(b3)


@dataclass
class Diag0xB0EE:
    """0xB0EE — LTE NAS EMM state."""
    log_time: int
    version: int
    emm_state: int
    emm_state_name: str
    emm_substate: int
    plmn_raw: bytes
    plmn: dict[str, str] | None
    guti_valid: int
    guti_ue_id_type: int
    guti_plmn: dict[str, str] | None
    mme_group_id: int | None
    mme_code: int | None
    m_tmsi: int | None
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB0EE",
            "log_time": self.log_time,
            "version": self.version,
            "emm_state": self.emm_state,
            "emm_state_name": self.emm_state_name,
            "emm_substate": self.emm_substate,
            "plmn_hex": self.plmn_raw.hex(),
            "plmn": self.plmn,
            "guti_valid": self.guti_valid,
            "guti_ue_id_type": self.guti_ue_id_type,
            "guti_plmn": self.guti_plmn,
            "mme_group_id": self.mme_group_id,
            "mme_code": self.mme_code,
            "m_tmsi": self.m_tmsi,
            "payload_size": self.payload_size,
        }


@register(
    0xB0EE, domain="nas",
    name="0xB0EE",
    description=(
        "LTE NAS EMM state — EMM state (named, F3/OTA-grounded) and raw "
        "substate, registered PLMN, and the UE GUTI (PLMN / MMEGI / MMEC / "
        "M-TMSI, grounded 4/4 against the NAS OTA EPS-mobile-identity IE)"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Full 19 B body decoded. GUTI == the "
        "0xB0EC Attach Accept / 0xB0ED TAU + Detach Request EPS mobile "
        "identity, 4/4 on RM500Q-AE (SDX55, 310-260) and LV55 (SDX55, "
        "311-480), with MMEGI/M-TMSI stored little-endian; black-box A/B "
        "3/3 on EM7511 (MDM9x50): qcsuper's RRC-carried Detach Request GUTI "
        "and s-TMSI equal it. plmn == F3 "
        "emm_update_lib.c:1708 Attach Request PLMN octets; emm_state 2 == F3 "
        "emm_esm_handler.c:2434 (2/2) + EVENT_NAS_ATTACH co-emission; states "
        "1/3/5/6 named from OTA sequencing; 0/4 are candidates by elimination. "
        "Substate raw. Version and payload size are gated (v0x02, 19 B)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Wire fields: version, emm_state, emm_substate, plmn, guti_valid,
    # guti_ue_id_type, guti_plmn, mme_group_id, mme_code, m_tmsi.
    fields_identified=10,
    fields_parsed=10,
    field_invariants={
        "version": {"enum": [_B0EE_VERSION_OBSERVED]},
        "payload_size": {"enum": [_B0EE_PAYLOAD_SIZE_OBSERVED]},
    },
)
def parse_0xb0ee(log_time: int, data: bytes) -> Diag0xB0EE | None:
    if len(data) != _B0EE_PAYLOAD_SIZE_OBSERVED:
        return None
    version = data[0]
    if version != _B0EE_VERSION_OBSERVED:
        return None
    emm_state = data[1]
    guti_valid = data[7]
    guti_ue_id_type = data[8]
    has_guti = guti_valid == 1 and guti_ue_id_type == _EPS_ID_TYPE_GUTI
    return Diag0xB0EE(
        log_time=log_time,
        version=version,
        emm_state=emm_state,
        emm_state_name=_EMM_STATE_NAMES.get(emm_state, f"UNKNOWN_{emm_state}"),
        emm_substate=unpack_from("<H", data, 2)[0],
        plmn_raw=bytes(data[4:7]),
        plmn=_plmn(data[4:7]),
        guti_valid=guti_valid,
        guti_ue_id_type=guti_ue_id_type,
        guti_plmn=_plmn(data[9:12]) if has_guti else None,
        mme_group_id=unpack_from("<H", data, 12)[0] if has_guti else None,
        mme_code=data[14] if has_guti else None,
        m_tmsi=unpack_from("<I", data, 15)[0] if has_guti else None,
        payload_size=len(data),
    )
