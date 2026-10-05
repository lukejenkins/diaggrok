"""0xB061 — LTE MAC RACH Trigger (LOG_LTE_MAC_RACH_TRIGGER).

ID-only naming: registry name "0xB061", class `Diag0xB061`.

=== Full decode, all four on-wire layouts ===

Offsets 4-7 are a **subpacket header**, not a u32 config word. The record is
the same subpacket container as its 0xB062 (RACH Attempt) sibling, carrying
two subpackets — the cell's RACH configuration and the reason this RACH was
triggered:

    [0]    u8   version          (== 0x01; outer DIAG log version, L1-gated)
    [1]    u8   num_subpackets    (== 0x02 on every observed record)
    [2:4]  u16  hdr_counter       (per-capture instance marker, as on 0xB062)
    then num_subpackets × { u8 id, u8 version, u16 length (INCLUSIVE of this
    4-byte header), body } — the lengths tile the payload exactly on every
    observed record.

Subpacket 0x03 (RACH config) / 0x05 (RACH reason) version pairs, each a fixed
record size ("size invariance != format invariance": byte 0 is 0x01 on all):

    cfg v0x02 + rsn v0x01  →  52 B  MDM9x07/9x30 (EG25-G, EG95, MC7455, …)
    cfg v0x04 + rsn v0x02  →  60 B  MDM9x50 / SDX55 / SDX12 (EM7511, LV55,
                                    T99W175, Inseego M2000, FM101, …)
    cfg v0x08 + rsn v0x02  →  60 B  SDX55 / SDX62 (FN980, M3100, RM520N, …)
    cfg v0x09 + rsn v0x05  →  52 B  SDX6x (RM520N-GL, EM9291)

RACH config body (offsets relative to the subpacket body). v0x04/0x08/0x09
prefix the v0x02 grammar with 3 bytes (`cfg_prefix`: u8 0x00|0x01, then
`01 00`, raw); v0x09 drops `p_max`; trailers are exposed raw:

    s16  preamble_initial_power_dbm      preambleInitialReceivedTargetPower
    u8   power_ramping_step_db           powerRampingStep
    u8   ra_preambles_group_a            sizeOfRA-PreamblesGroupA
    u8   num_ra_preambles                numberOfRA-Preambles
    u8   preamble_trans_max              preambleTransMax
    u16  contention_resolution_timer_ms  mac-ContentionResolutionTimer
    u16  message_size_group_a            messageSizeGroupA (CANDIDATE units)
    u8   message_power_offset_group_b    raw enum (CANDIDATE)
    s16  p_max_dbm                       (absent in v0x09)
    s16  delta_preamble_msg3_db          deltaPreambleMsg3 × 2 dB
    u8   prach_config_index              prach-ConfigIndex
    u8   zero_correlation_zone_config    zeroCorrelationZoneConfig
    u16  root_sequence_index             rootSequenceIndex
    u8   prach_freq_offset               prach-FreqOffset
    u8   high_speed_flag                 highSpeedFlag (CANDIDATE: only 0 seen)
    u8   max_harq_msg3_tx                maxHARQ-Msg3Tx
    u8   ra_response_window_sf           ra-ResponseWindowSize

GROUNDING — the cell's own SIB2 (0xB0C0 BCCH-DL-SCH, UPER-decoded offline with
pycrate as an oracle only) for the serving cell agrees with EVERY named field
above, value for value, on all four layouts: EG25-G (cfg v0x02, PCI 381),
LV55 (v0x04, PCI 1), RM520N-GL (v0x08, PCI 236, 2 records) and EM9291 (v0x09,
PCI 473) — incl. -110/-118 dBm, n44/n52/n64, root 40/170/418/470,
prach-ConfigIndex 3/5/20/21, zczc 12/13/14, freq offset 3/4 — on every record
whose cell's SIB2 was in the capture. `delta_preamble_msg3_db` reads 12 where
SIB2 carries deltaPreambleMsg3 = 6 (TS 36.213: Δ = value × 2 dB). `p_max_dbm`
reads 23 where SIB1 p-Max is 23 *and* where SIB1 omits p-Max (LV55), so it is
the UE's effective P_max, not the SIB1 IE; 127 (11 cfg-v0x08 records) is
presumably a "not configured" value — exposed raw. `ra_preambles_group_a <=
num_ra_preambles` on every record (44/52 alongside message_size_group_a 7 ⇒ a
group-B cell), which fixes the order of the two. A record emitted before SIB2
is acquired carries an ALL-ZERO config body (`rach_config_valid` False).

RACH reason body (v0x02/v0x05 prefix 2 raw bytes, `rsn_prefix`; v0x05 drops
`ra_group`):

    u8   rach_reason        F3 "Start Access Request for reason=N"
    6 B  msg3_ccch_sdu      the Msg3 UL-CCCH SDU (an RRCConnectionRequest)
    u8   co_ra              F3 rach_procedure_init "co_ra=" (contention-based)
    u8   rsn_field_1        raw (0 or 0x34 observed; unidentified)
    u8   ra_preamble_id     F3 "RAID=" (255 ⇒ none assigned / UE-selected)
    u8   msg3_size          F3 "msg3_len=" (bytes; 6 ⇔ CCCH SDU present)
    u8   ra_group           F3 rach_procedure_init "ra_gp=" (v0x01/v0x02 only)
    u8   dl_pathloss_db     F3 lte_ml1_prach.c "dl_pathloss="
    u16  time_u16           raw; monotonically increasing across records of
                            one session — a timer/counter, units unknown
    rest rsn_trailer        raw

GROUNDING —
  * F3 (Telit LM960A18, MDM9x50, cfg v0x04, plaintext): each of 6 records in
    a SIM-attach capture is co-emitted with
    `lte_mac_ctrl.c:2206 Start Access Request for reason=0, RAID=255`
    (rach_reason 0, ra_preamble_id 255 — 6/6), `lte_mac_rach.c:550
    rach_procedure_init … co_ra=1,ra_gp=0` (co_ra 1, ra_group 0 — 6/6),
    `lte_mac_rach.c:1060 … msg3_len=6` (msg3_size 6), and
    `lte_ml1_prach.c:3189 ULM PRACH : … dl_pathloss=N`: B061 106/117/106/106
    vs F3 106/117/106/106, and 118/106 vs F3 120/105 (the ML1 print is taken
    at PRACH Tx, a few ms after the trigger).
  * In-capture RRC: `msg3_ccch_sdu` equals, byte for byte, the UL-CCCH
    RRCConnectionRequest PDU logged in 0xB0C0 on every reason-0 record checked
    (7/7 across MC7455, EG25-G, LV55, FN980, EM9291, FM101), at the same tick
    (MDM9x07) or 1-2 ms after it (SDX).
  * `rach_reason` values: 0 (CCCH Msg3, random preamble — connection
    establishment, grounded above), 2 (random preamble, msg3_size 0) and 4
    (dedicated preamble 59 / 0, msg3_size 0, same PCI — PDCCH-order-like).
    Only 0's meaning is grounded; the enum is exposed as an int.

`msg3_ccch_sdu` is additionally decoded as RRCConnectionRequest-r8 (TS 36.331,
UPER) when msg3_size == 6 and the first two bits are `01`: ue_identity_type
("s-TMSI" | "randomValue"), mmec / m_tmsi (s-TMSI) or random_value, and
establishment_cause. The bit layout was checked against pycrate's UL-CCCH
decode on 5 captured PDUs (offline oracle; no runtime dependency). The S-TMSI
is an identifier and is decoded in full; fixtures carry a 0xFF…/0xFFFFFFFF
sentinel, never a captured value.

`dl_pathloss_db` is F3-grounded on rsn v0x02 only (LM960); on v0x01/v0x05 it
is a structural transfer (same byte after ra_group / msg3_size), range-checked
only: [75, 178] across all captures, with the MC7455 v0x01 records at the
160-170 top.

Checked against 517 records / 112 captures: 517 parse, 0 rejects, 0 invariant
violations, 0 undecoded subpackets. rach_reason 0 ⇔ msg3_size 6 (437/437), and all 437 decode
as a valid RRCConnectionRequest; ra_preambles_group_a <= num_ra_preambles and
root_sequence_index <= 837 on every record. SCAT has no MAC-RACH decoder, but
its RRC decode of the same Msg3 PDU (MC7455) agrees with ours on identity type,
the 40-bit value and establishmentCause.

Log name: LOG_LTE_MAC_RACH_TRIGGER
Also known as: LOG_MAC_RACH_TRIGGER, LTE MAC Rach Trigger
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# byte-0 is the DIAG log version; invariant 0x01 across both observed
# payload sizes. Size is NOT invariant, so no payload_size invariant.
_B061_VERSION_OBSERVED = 0x01
_SP_RACH_CONFIG = 0x03
_SP_RACH_REASON = 0x05

# RACH-config subpacket version -> (prefix bytes before the v0x02 grammar, has p_max)
_CFG_LAYOUT = {0x02: (0, True), 0x04: (3, True), 0x08: (3, True), 0x09: (3, False)}
# RACH-reason subpacket version -> (prefix bytes, has ra_group)
_RSN_LAYOUT = {0x01: (0, True), 0x02: (2, True), 0x05: (2, False)}

_RA_PREAMBLE_NONE = 0xFF
_CCCH_SDU_LEN = 6

# TS 36.331 EstablishmentCause (3 bits, no extension marker).
ESTABLISHMENT_CAUSES = {
    0: "emergency",
    1: "highPriorityAccess",
    2: "mt-Access",
    3: "mo-Signalling",
    4: "mo-Data",
    5: "delayTolerantAccess-v1020",
    6: "mo-VoiceCall-v1280",
    7: "spare1",
}


@dataclass
class Diag0xB061:
    """0xB061 — LTE MAC RACH Trigger (RACH config + RACH reason subpackets)."""
    log_time: int
    version: int
    num_subpackets: int
    hdr_counter: int
    # ── RACH config subpacket (id 0x03) ──
    cfg_version: int | None
    rach_config_valid: bool | None
    preamble_initial_power_dbm: int | None
    power_ramping_step_db: int | None
    ra_preambles_group_a: int | None
    num_ra_preambles: int | None
    preamble_trans_max: int | None
    contention_resolution_timer_ms: int | None
    message_size_group_a: int | None
    message_power_offset_group_b: int | None
    p_max_dbm: int | None
    delta_preamble_msg3_db: int | None
    prach_config_index: int | None
    zero_correlation_zone_config: int | None
    root_sequence_index: int | None
    prach_freq_offset: int | None
    high_speed_flag: int | None
    max_harq_msg3_tx: int | None
    ra_response_window_sf: int | None
    cfg_prefix: bytes | None
    cfg_trailer: bytes | None
    # ── RACH reason subpacket (id 0x05) ──
    rsn_version: int | None
    rach_reason: int | None
    msg3_ccch_sdu: bytes | None
    co_ra: int | None
    rsn_field_1: int | None
    ra_preamble_id: int | None
    msg3_size: int | None
    ra_group: int | None
    dl_pathloss_db: int | None
    time_u16: int | None
    rsn_prefix: bytes | None
    rsn_trailer: bytes | None
    # ── Msg3 RRCConnectionRequest decode (only when msg3_size == 6) ──
    ue_identity_type: str | None
    mmec: int | None
    m_tmsi: int | None
    random_value: int | None
    establishment_cause: int | None
    establishment_cause_name: str | None
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB061",
            "log_time": self.log_time,
            "version": self.version,
            "num_subpackets": self.num_subpackets,
            "hdr_counter": self.hdr_counter,
            "cfg_version": self.cfg_version,
            "rach_config_valid": self.rach_config_valid,
            "preamble_initial_power_dbm": self.preamble_initial_power_dbm,
            "power_ramping_step_db": self.power_ramping_step_db,
            "ra_preambles_group_a": self.ra_preambles_group_a,
            "num_ra_preambles": self.num_ra_preambles,
            "preamble_trans_max": self.preamble_trans_max,
            "contention_resolution_timer_ms": self.contention_resolution_timer_ms,
            "message_size_group_a": self.message_size_group_a,
            "message_power_offset_group_b": self.message_power_offset_group_b,
            "p_max_dbm": self.p_max_dbm,
            "delta_preamble_msg3_db": self.delta_preamble_msg3_db,
            "prach_config_index": self.prach_config_index,
            "zero_correlation_zone_config": self.zero_correlation_zone_config,
            "root_sequence_index": self.root_sequence_index,
            "prach_freq_offset": self.prach_freq_offset,
            "high_speed_flag": self.high_speed_flag,
            "max_harq_msg3_tx": self.max_harq_msg3_tx,
            "ra_response_window_sf": self.ra_response_window_sf,
            "cfg_prefix": self.cfg_prefix,
            "cfg_trailer": self.cfg_trailer,
            "rsn_version": self.rsn_version,
            "rach_reason": self.rach_reason,
            "msg3_ccch_sdu": self.msg3_ccch_sdu,
            "co_ra": self.co_ra,
            "rsn_field_1": self.rsn_field_1,
            "ra_preamble_id": self.ra_preamble_id,
            "msg3_size": self.msg3_size,
            "ra_group": self.ra_group,
            "dl_pathloss_db": self.dl_pathloss_db,
            "time_u16": self.time_u16,
            "rsn_prefix": self.rsn_prefix,
            "rsn_trailer": self.rsn_trailer,
            "ue_identity_type": self.ue_identity_type,
            "mmec": self.mmec,
            "m_tmsi": self.m_tmsi,
            "random_value": self.random_value,
            "establishment_cause": self.establishment_cause,
            "establishment_cause_name": self.establishment_cause_name,
            "payload_size": self.payload_size,
        }


_CFG_FIELDS = (
    "preamble_initial_power_dbm", "power_ramping_step_db", "ra_preambles_group_a",
    "num_ra_preambles", "preamble_trans_max", "contention_resolution_timer_ms",
    "message_size_group_a", "message_power_offset_group_b", "p_max_dbm",
    "delta_preamble_msg3_db", "prach_config_index", "zero_correlation_zone_config",
    "root_sequence_index", "prach_freq_offset", "high_speed_flag",
    "max_harq_msg3_tx", "ra_response_window_sf", "cfg_prefix", "cfg_trailer",
)
_RSN_FIELDS = (
    "rach_reason", "msg3_ccch_sdu", "co_ra", "rsn_field_1", "ra_preamble_id",
    "msg3_size", "ra_group", "dl_pathloss_db", "time_u16", "rsn_prefix", "rsn_trailer",
)
_RRC_FIELDS = (
    "ue_identity_type", "mmec", "m_tmsi", "random_value",
    "establishment_cause", "establishment_cause_name",
)


def _decode_rach_config(body: bytes, sp_version: int) -> dict[str, Any] | None:
    layout = _CFG_LAYOUT.get(sp_version)
    if layout is None:
        return None
    prefix_len, has_pmax = layout
    if len(body) < prefix_len + (23 if has_pmax else 21):
        return None
    o = prefix_len
    f: dict[str, Any] = {"cfg_prefix": body[:prefix_len]}
    f["preamble_initial_power_dbm"] = unpack_from("<h", body, o)[0]
    f["power_ramping_step_db"] = body[o + 2]
    f["ra_preambles_group_a"] = body[o + 3]
    f["num_ra_preambles"] = body[o + 4]
    f["preamble_trans_max"] = body[o + 5]
    f["contention_resolution_timer_ms"], f["message_size_group_a"] = unpack_from("<HH", body, o + 6)
    f["message_power_offset_group_b"] = body[o + 10]
    o += 11
    if has_pmax:
        f["p_max_dbm"] = unpack_from("<h", body, o)[0]
        o += 2
    else:
        f["p_max_dbm"] = None
    f["delta_preamble_msg3_db"] = unpack_from("<h", body, o)[0]
    f["prach_config_index"] = body[o + 2]
    f["zero_correlation_zone_config"] = body[o + 3]
    f["root_sequence_index"] = unpack_from("<H", body, o + 4)[0]
    f["prach_freq_offset"] = body[o + 6]
    f["high_speed_flag"] = body[o + 7]
    f["max_harq_msg3_tx"] = body[o + 8]
    f["ra_response_window_sf"] = body[o + 9]
    f["cfg_trailer"] = body[o + 10:]
    return f


def _decode_rach_reason(body: bytes, sp_version: int) -> dict[str, Any] | None:
    layout = _RSN_LAYOUT.get(sp_version)
    if layout is None:
        return None
    prefix_len, has_group = layout
    o = prefix_len
    if len(body) < o + 14 + (1 if has_group else 0):
        return None
    f: dict[str, Any] = {"rsn_prefix": body[:prefix_len]}
    f["rach_reason"] = body[o]
    f["msg3_ccch_sdu"] = body[o + 1:o + 7]
    f["co_ra"] = body[o + 7]
    f["rsn_field_1"] = body[o + 8]
    f["ra_preamble_id"] = body[o + 9]
    f["msg3_size"] = body[o + 10]
    o += 11
    if has_group:
        f["ra_group"] = body[o]
        o += 1
    else:
        f["ra_group"] = None
    f["dl_pathloss_db"] = body[o]
    f["time_u16"] = unpack_from("<H", body, o + 1)[0]
    f["rsn_trailer"] = body[o + 3:]
    return f


def _decode_rrc_connection_request(sdu: bytes) -> dict[str, Any] | None:
    """UL-CCCH RRCConnectionRequest-r8 (TS 36.331), 48-bit UPER.

    Bits (MSB first): c1 choice 0, rrcConnectionRequest 1, criticalExtensions
    r8 0, InitialUE-Identity choice (0 s-TMSI / 1 randomValue), 40-bit
    identity, 3-bit establishmentCause, 1 spare bit.
    """
    if len(sdu) != _CCCH_SDU_LEN:
        return None
    v = int.from_bytes(sdu, "big")
    if (v >> 45) != 0b010:  # c1 / rrcConnectionRequest / r8
        return None
    identity = (v >> 4) & 0xFF_FFFF_FFFF
    cause = (v >> 1) & 0x7
    f: dict[str, Any] = {
        "mmec": None, "m_tmsi": None, "random_value": None,
        "establishment_cause": cause,
        "establishment_cause_name": ESTABLISHMENT_CAUSES[cause],
    }
    if (v >> 44) & 1:
        f["ue_identity_type"] = "randomValue"
        f["random_value"] = identity
    else:
        f["ue_identity_type"] = "s-TMSI"
        f["mmec"] = identity >> 32
        f["m_tmsi"] = identity & 0xFFFF_FFFF
    return f


@register(
    0xB061,
    name="0xB061",
    description=(
        "0xB061 — LTE MAC RACH Trigger: SIB2 RACH/PRACH config subpacket + RACH "
        "reason subpacket (reason, RAID, Msg3 CCCH SDU / RRCConnectionRequest, pathloss)"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Reverse-engineered from DLF/HDLC captures. Container is the "
        "0xB062 subpacket envelope with two subpackets (0x03 RACH config v0x02/"
        "0x04/0x08/0x09; 0x05 RACH reason v0x01/0x02/0x05). Config fields "
        "grounded value-for-value against the serving cell's SIB2 in 0xB0C0 "
        "(pycrate as an offline oracle) on MDM9x07, SDX55 and SDX6x. Reason "
        "fields grounded against co-emitted LM960 F3 (lte_mac_ctrl.c:2206 "
        "reason/RAID, lte_mac_rach.c:550 co_ra/ra_gp, lte_mac_rach.c:1060 "
        "msg3_len, lte_ml1_prach.c:3189 dl_pathloss); the Msg3 SDU equals the "
        "UL-CCCH RRCConnectionRequest PDU in 0xB0C0 byte for byte."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=35,
    fields_parsed=35,
    field_invariants={
        "version": {"enum": [_B061_VERSION_OBSERVED]},
    },
)
def parse_0xb061(log_time: int, data: bytes) -> Diag0xB061 | None:
    if len(data) < 4:
        return None
    version = data[0]
    if version != _B061_VERSION_OBSERVED:
        return None
    num_subpackets = data[1]
    hdr_counter = unpack_from("<H", data, 2)[0]

    # Walk the subpackets; their inclusive lengths must tile the payload.
    subpackets: dict[int, tuple[int, bytes]] = {}
    off = 4
    for _ in range(num_subpackets):
        if off + 4 > len(data):
            return None
        sp_id, sp_ver = data[off], data[off + 1]
        sp_len = unpack_from("<H", data, off + 2)[0]
        if sp_len < 4 or off + sp_len > len(data):
            return None
        subpackets.setdefault(sp_id, (sp_ver, data[off + 4:off + sp_len]))
        off += sp_len
    if off != len(data):
        return None

    fields: dict[str, Any] = dict.fromkeys(_CFG_FIELDS + _RSN_FIELDS + _RRC_FIELDS)
    cfg_version = rsn_version = None
    rach_config_valid: bool | None = None

    if _SP_RACH_CONFIG in subpackets:
        cfg_version, body = subpackets[_SP_RACH_CONFIG]
        cfg = _decode_rach_config(body, cfg_version)
        if cfg is not None:
            fields.update(cfg)
            # Emitted before SIB2 is acquired, the whole config body is zero.
            rach_config_valid = cfg["num_ra_preambles"] != 0

    if _SP_RACH_REASON in subpackets:
        rsn_version, body = subpackets[_SP_RACH_REASON]
        rsn = _decode_rach_reason(body, rsn_version)
        if rsn is not None:
            fields.update(rsn)
            if rsn["msg3_size"] == _CCCH_SDU_LEN:
                rrc = _decode_rrc_connection_request(rsn["msg3_ccch_sdu"])
                if rrc is not None:
                    fields.update(rrc)

    return Diag0xB061(
        log_time=log_time,
        version=version,
        num_subpackets=num_subpackets,
        hdr_counter=hdr_counter,
        cfg_version=cfg_version,
        rach_config_valid=rach_config_valid,
        rsn_version=rsn_version,
        payload_size=len(data),
        **fields,
    )
