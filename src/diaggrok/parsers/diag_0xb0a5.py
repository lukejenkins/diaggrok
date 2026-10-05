"""0xB0A5 — LOG_LTE_PDCP_DL_SRB_INTEGRITY_DATA_PDU (LTE PDCP DL SRB integrity).

Downlink twin of 0xB0B5: one record per batch of downlink SRB PDUs that
went through PDCP integrity verification. It carries the AS security context
(both 128-bit RRC keys and both algorithm ids), then one entry per PDU with
the PDCP COUNT, the MAC-I and the logged PDCP PDU bytes (header + DL-DCCH RRC
message + MAC-I).

Only version 0x01 has been observed. It is the standard DIAG sub-packet framing, with
sub-packet id 0xC6 and sub-packet version 0x01 (MDM9x07 / 9x30 / 9x50 /
SDX20) or 0x28 (SDX55 / SDX62 / SDX65)::

    [0] u8 version 0x01  [1] u8 num_sub_packets (1)  [2:4] u16 wrapper_reserved
    [4] u8 subpkt_id 0xC6  [5] u8 subpkt_version  [6:8] u16 subpkt_size (= len - 4)
    [8:24]   srb_cipher_key      K_RRCenc (CANDIDATE: by elimination)
    [24:40]  srb_integrity_key   K_RRCint (GROUNDED: EIA2 CMAC reproduces MAC-I)
    [40] u8 srb_cipher_algo      33.401 EEA id (CANDIDATE) | 7 = null or not reported
    [41] u8 srb_integrity_algo   33.401 EIA id (2 GROUNDED) | 7 = null or not reported
    [42:44] u16 num_pdus
    per PDU (20-byte header, PDU padded to 4 bytes):
      +0  u8  rb_cfg_idx    33 = SRB1, 34 = SRB2 (0 on SDX55 sub-ver 0x28)
      +1  u8  flags         raw (0x40/0x42 sub-ver 0x01; 0x80/0x84 sub-ver 0x28)
      +2  u16 pdu_size
      +4  u16 logged_bytes
      +6  u16 sfn_subfn     sfn << 4 | subframe
      +8  u32 count         PDCP COUNT
      +12 u32 mac_i         MAC-I (the PDU's trailing 4 bytes, big-endian)
      +16 u32 mac_i_2       a second MAC-I word (equal to mac_i on every record)
      +20 PDCP PDU[logged_bytes]

GROUNDING (no real key, MAC or PDU value is reproduced here beyond the
synthetic test fixtures):

1. F3 ``mutils_security.c`` (QSR4). Each integrity check prints ``:188``
   "integrity_maci function Direction = %d Bearer = 0x%0x Count= 0x%0x" and
   then ``:627`` "MAC-I computation successful: MAC-I[0x%x]". Joined on exact
   MAC-I: RM520N-GL SDX62 (sub-ver 0x28) 11/11, Direction=1, COUNT equal,
   F3 Bearer = rb_cfg_idx - 33 (SRB1 -> 0, SRB2 -> 1; 33.401 BEARER = RB
   identity - 1). PDUs with mac_i == 0 (before SecurityModeCommand) have no
   F3 integrity call.
2. Cryptographic: 128-EIA2 (AES-CMAC over COUNT || BEARER || DIRECTION=1 ||
   PDU-without-MAC-I) keyed with the 16 bytes at +24 reproduces mac_i on 311
   PDUs across all captures (EG25-G, EM7511, LM960, LV55, M2000, MC7411,
   MC7455, RM500Q, both sub-packet versions); the key at +8 never does. With
   rb_cfg_idx logged, the verifying BEARER is rb_cfg_idx - 33 on every PDU.
   On SDX55 sub-ver 0x28 (rb_cfg_idx 0) the CMAC still recovers the bearer
   (0 or 1).
3. All captures (1,967 records / 110 capture groups): 1,967 parse, 0
   rejected. mac_i_2 == mac_i, sfn < 1024 and subframe < 10, and the PDU's
   first octet low 5 bits == count & 31 (SRB PDCP SN) on every record; the
   PDU's last 4 bytes equal mac_i on every fully logged PDU (1,964/1,964).
   num_pdus is 1. rb 34 carries only dlInformationTransfer (SRB2 = NAS).
4. Algo id 7 is the firmware's NULL-algorithm code: on EM7565 (9x50) and
   LM960 (SDX20) F3 ``cipher function Algo = 7`` is always followed by
   "Null Security algorithm... Input msg is the same as ciphered out msg",
   and the integrity call prints Algo = 1, matching records logged
   (cipher 7, integrity 1) = null ciphering + EIA1. But RM520N-GL / EM9291
   log 7/7 (usually with zeroed keys) while the same RM520N capture's F3
   prints integrity Algo = 2 on all 227 calls and the MAC-Is verify, so on
   SDX62/65 a 7 is a placeholder, not the algorithm in use. Hence the name
   ``null_or_not_reported``. When an algo byte is 7, the logged keys are not
   the active context (58 keyed DL PDUs logged 7/7 never verify under EIA2).
   EIA1 (SNOW 3G) is not cryptographically checked here.
5. Sub-packet version 0x01 (EM7565 9x50): F3 MAC-I join 2/2, Direction 1,
   COUNT equal, rb 33 -> Bearer 0, F3 integrity Algo = 1. Black-box SCAT on
   an EG25-G capture emits 4/6 of these RRC bodies byte-exact; the 2 it lacks
   share no prefix with any SCAT frame (SCAT's framer drops them), 0 conflict.

Any other version byte, a sub-packet id other than 0xC6, or a PDU table that
overruns the record returns ``None``.

Log name: LOG_LTE_PDCP_DL_SRB_INTEGRITY_DATA_PDU
Also known as: LTE PDCP DL SRB Integrity Data PDU
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_B0A5_VERSION_OBSERVED = 0x01
_SUBPKT_ID_DL_SRB_INTEGRITY = 0xC6
_ALGO_NOT_REPORTED = 7
_EEA_NAMES = {0: "EEA0", 1: "128-EEA1", 2: "128-EEA2", 3: "128-EEA3"}
_EIA_NAMES = {0: "EIA0", 1: "128-EIA1", 2: "128-EIA2", 3: "128-EIA3"}
_BODY = 8
_ENTRY_HDR = 20


def _algo_name(value: int, names: dict[int, str]) -> str:
    if value == _ALGO_NOT_REPORTED:
        return "null_or_not_reported"
    return names.get(value, f"unknown_{value}")


@dataclass
class Diag0xB0A5:
    """0xB0A5 — LTE PDCP DL SRB integrity data PDUs."""
    log_time: int
    version: int
    payload_size: int
    num_sub_packets: int
    wrapper_reserved: int
    subpkt_id: int
    subpkt_version: int
    subpkt_size: int
    srb_cipher_key: str
    srb_integrity_key: str
    keys_logged: bool
    srb_cipher_algo: int
    srb_cipher_algo_name: str
    srb_integrity_algo: int
    srb_integrity_algo_name: str
    num_pdus: int
    pdus: list[dict[str, Any]] = field(default_factory=list)
    trailing_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB0A5",
            "log_time": self.log_time,
            "version": self.version,
            "payload_size": self.payload_size,
            "num_sub_packets": self.num_sub_packets,
            "wrapper_reserved": self.wrapper_reserved,
            "subpkt_id": self.subpkt_id,
            "subpkt_version": self.subpkt_version,
            "subpkt_size": self.subpkt_size,
            "srb_cipher_key": self.srb_cipher_key,
            "srb_integrity_key": self.srb_integrity_key,
            "keys_logged": self.keys_logged,
            "srb_cipher_algo": self.srb_cipher_algo,
            "srb_cipher_algo_name": self.srb_cipher_algo_name,
            "srb_integrity_algo": self.srb_integrity_algo,
            "srb_integrity_algo_name": self.srb_integrity_algo_name,
            "num_pdus": self.num_pdus,
            "pdus": self.pdus,
            "trailing_bytes": self.trailing_bytes,
        }


@register(
    0xB0A5,
    name="0xB0A5",
    description=(
        "LTE PDCP DL SRB integrity data PDUs: K_RRCenc/K_RRCint, EEA/EIA ids, "
        "and per PDU the rb_cfg_idx, SFN/subframe, COUNT, MAC-I and PDCP PDU bytes"
    ),
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. Body decode (sub-packet 0xC6, sub-ver 0x01/0x28, "
        "20-byte PDU entry header). MAC-I/COUNT grounded against F3 "
        "mutils_security.c:188 (Direction=1)/:627; 128-EIA2 CMAC with the key "
        "at +24 reproduces MAC-I on 311 PDUs. Algo id 7 = null or not "
        "reported. 1,967/1,967 captured records parse. Cipher algo CANDIDATE. "
        "Byte 0 (version) is gated to 0x01. A payload shorter than 4 + "
        "subpkt_size (the declared sub-packet) returns None (registry WARN)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=19,
    fields_parsed=19,
    field_invariants={
        "version": {"enum": [_B0A5_VERSION_OBSERVED]},
        "subpkt_id": {"enum": [_SUBPKT_ID_DL_SRB_INTEGRITY]},
    },
)
def parse_0xb0a5(log_time: int, data: bytes) -> Diag0xB0A5 | None:
    if len(data) < _BODY + 36 or data[0] != _B0A5_VERSION_OBSERVED:
        return None
    if data[4] != _SUBPKT_ID_DL_SRB_INTEGRITY:
        return None
    # The sub-packet spans [4:4+subpkt_size]; a payload that cannot hold
    # the declared size is truncated -> loud None (registry WARN).
    if 4 + unpack_from("<H", data, 6)[0] > len(data):
        return None
    cipher_key = data[_BODY:_BODY + 16]
    integ_key = data[_BODY + 16:_BODY + 32]
    calg, ialg = data[_BODY + 32], data[_BODY + 33]
    num_pdus = unpack_from("<H", data, _BODY + 34)[0]

    pdus: list[dict[str, Any]] = []
    off = _BODY + 36
    for _ in range(num_pdus):
        if off + _ENTRY_HDR > len(data):
            return None
        rb, flags, pdu_size, logged, sfn_subfn, count, mac_i, mac_i_2 = unpack_from(
            "<BBHHHIII", data, off)
        off += _ENTRY_HDR
        if off + logged > len(data):
            return None
        pdu = data[off:off + logged]
        off += (logged + 3) & ~3
        pdus.append({
            "rb_cfg_idx": rb,
            "srb_id": rb - 32 if rb in (33, 34) else None,
            "flags": flags,
            "pdu_size": pdu_size,
            "logged_bytes": logged,
            "truncated": logged < pdu_size,
            "sfn": sfn_subfn >> 4,
            "subframe": sfn_subfn & 0xF,
            "count": count,
            "mac_i": mac_i,
            "mac_i_2": mac_i_2,
            "pdcp_sn": pdu[0] & 0x1F if pdu else None,
            "pdu_hex": pdu.hex(),
        })

    return Diag0xB0A5(
        log_time=log_time,
        version=data[0],
        payload_size=len(data),
        num_sub_packets=data[1],
        wrapper_reserved=unpack_from("<H", data, 2)[0],
        subpkt_id=data[4],
        subpkt_version=data[5],
        subpkt_size=unpack_from("<H", data, 6)[0],
        srb_cipher_key=cipher_key.hex(),
        srb_integrity_key=integ_key.hex(),
        keys_logged=any(cipher_key) or any(integ_key),
        srb_cipher_algo=calg,
        srb_cipher_algo_name=_algo_name(calg, _EEA_NAMES),
        srb_integrity_algo=ialg,
        srb_integrity_algo_name=_algo_name(ialg, _EIA_NAMES),
        num_pdus=num_pdus,
        pdus=pdus,
        trailing_bytes=len(data) - off if off <= len(data) else 0,
    )
