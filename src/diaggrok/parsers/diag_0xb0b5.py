"""0xB0B5 — LOG_LTE_PDCP_UL_SRB_INTEGRITY_DATA_PDU (LTE PDCP UL SRB integrity).

One record per batch of uplink SRB PDUs that went through PDCP integrity
protection: the AS security context (both 128-bit RRC keys, both algorithm
ids) followed by one entry per PDU carrying the PDCP COUNT, the computed
MAC-I and the logged PDCP PDU bytes (header + UL-DCCH RRC message + MAC-I).

Two on-wire framings, one per version byte:

======  =================================  =====================================
ver     silicon (observed)                 framing
======  =================================  =====================================
0x01    MDM9207 / 9x30 / 9x50 / SDX20 /    4 B wrapper + one DIAG sub-packet
        SDX50M / SDX55 (EG25-G, MC7455,    (id 0xC7, sub-packet version 0x01 or
        EM7565, LM960, MC7411, RM500Q,     0x28, u16 size = record length - 4),
        LV55, m2000, FT980m)               PDU entry header 8 B
0x38    SDX62 / SDX65 / m3100 (RM520N-GL,  flat: 1 B version + 3 B reserved,
        EM9291, m3100)                     PDU entry header 10 B
======  =================================  =====================================

Layout (``B`` = 8 for v0x01, 4 for v0x38)::

    v0x01: [0] u8 version  [1] u8 num_sub_packets (1)  [2:4] u16 wrapper_reserved
           [4] u8 subpkt_id (0xC7)  [5] u8 subpkt_version  [6:8] u16 subpkt_size
    v0x38: [0] u8 version  [1:4] reserved (0 on every record)

    [B+0 :B+16]  srb_cipher_key      K_RRCenc (CANDIDATE: by elimination)
    [B+16:B+32]  srb_integrity_key   K_RRCint (GROUNDED: EIA2 CMAC reproduces MAC-I)
    [B+32]       u8 srb_cipher_algo      33.401 EEA id (CANDIDATE) | 7 = null or not reported
    [B+33]       u8 srb_integrity_algo   33.401 EIA id (2 GROUNDED) | 7 = null or not reported
    [B+34:B+36]  u16 num_pdus
    per PDU:
      u16 pdu_word       bits 0-5 rb_cfg_idx (33 = SRB1, 34 = SRB2), bits 6-15 raw
      u16 pdu_size       full PDCP PDU length
      u16 logged_bytes   bytes logged (< pdu_size when truncated, e.g. UE capability)
      entry_reserved     v0x01 2 B (0x4000) / v0x38 4 B (0x00000100), raw
      u32 count          PDCP COUNT (HFN << 5 | SN for SRBs)
      u32 mac_i          computed MAC-I; the PDU's trailing 4 bytes big-endian
      logged_bytes       PDCP PDU (SN octet, RRC UL-DCCH message, MAC-I)
    v0x01 pads the record to a 4-byte boundary; v0x38 does not.

GROUNDING (no real key, MAC or PDU value is reproduced here; the test
fixtures are synthetic):

1. F3 ``mutils_security.c`` (QSR4, build-matched qdb). Every integrity
   computation prints ``:188`` "integrity_maci function Direction = %d
   Bearer = 0x%0x Count= 0x%0x" then ``:627`` "MAC-I computation successful:
   MAC-I[0x%x]". Joining each 0xB0B5 PDU (direction 0 = UL) on COUNT,
   nearest preceding triple: v0x01 RM500Q-AE SDX55 24/24 exact MAC-I, 0
   disagree (1 PDU with no F3 print); v0x38 RM520N-GL SDX62 15/15 exact, plus
   one 21 ms-stale join onto a NAS integrity call (NAS also prints bearer 0;
   the PDU's own print was dropped). F3 ``Bearer`` equals rb_cfg_idx - 33 on
   every match (SRB1 -> 0, SRB2 -> 1; 33.401 BEARER = RB identity - 1), so
   rb_cfg_idx is grounded. PDUs with mac_i == 0 (before SecurityModeCommand,
   e.g. RRCConnectionSetupComplete) have no F3 integrity call, as expected.
2. Cryptographic: 128-EIA2 (AES-CMAC over COUNT || BEARER || DIRECTION=0 ||
   PDU-without-MAC-I) keyed with the 16 bytes at B+16 reproduces mac_i on
   v0x01 (RM500Q sub-ver 0x28, EG25-G sub-ver 0x01) and v0x38 (m3100); the
   key at B+0 never does. That fixes key order and integrity algo 2 = EIA2.
3. All captures (2,368 records / 81 capture groups): 2,368 parse,
   0 rejected. The PDU's last 4 bytes, read big-endian, equal mac_i on every
   fully logged PDU (v0x01 627/627, v0x38 1,498/1,498); the PDU's first octet
   low 5 bits equal count & 31 (the SRB PDCP SN) on every PDU; num_pdus is 1;
   rb_cfg_idx is 33 or 34 on every PDU, and rb 34 carries only
   ulInformationTransfer (SRB2 = NAS). entry_reserved is constant per version.
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
5. Sub-packet version 0x01 (EM7565 9x50, an F3-bearing capture):
   F3 MAC-I join 3/3 (Direction 0, COUNT equal, Bearer = rb_cfg_idx - 33),
   and the UL-only print ``"UL SRB RB Cfg idx = %d Calculated MAC-I = 0x%x"``
   names rb_cfg_idx 33 / 34 for the matching MAC-I 4/4.
6. Black-box SCAT decodes v0x01 sub-version 0x01 and refuses sub-version 40
   and v0x38 ("Unknown ... packet version 38"); it is not used as a field
   oracle here.

The cipher algo (EEA) has no in-capture oracle: F3 ``:715`` "cipher
function Algo" fires a handful of times per session (NAS ciphering, not per
RRC PDU) and does not match the record byte. It stays CANDIDATE.
``pdu_word`` bits 6-15 (0x80 / 0x40 / 0x84 high-byte patterns) and
``entry_reserved`` are surfaced raw.

Any other version byte, a v0x01 sub-packet id other than 0xC7, or a PDU
table that overruns the record returns ``None``.

Log name: LTE PDCP DL SRB Integrity Data PDU
Also known as: LOG_LTE_PDCP_UL_SRB_INTEGRITY_DATA_PDU, LTE PDCP UL SRB Integrity Data PDU
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_V1 = 0x01
_V38 = 0x38
_SUBPKT_ID_SRB_INTEGRITY = 0xC7
_ALGO_NOT_REPORTED = 7
# 33.401 Annex B: 3-bit algorithm identifiers
_EEA_NAMES = {0: "EEA0", 1: "128-EEA1", 2: "128-EEA2", 3: "128-EEA3"}
_EIA_NAMES = {0: "EIA0", 1: "128-EIA1", 2: "128-EIA2", 3: "128-EIA3"}
# version -> (body offset, per-PDU entry header bytes before count)
_LAYOUT = {_V1: (8, 8), _V38: (4, 10)}


def _algo_name(value: int, names: dict[int, str]) -> str:
    if value == _ALGO_NOT_REPORTED:
        return "null_or_not_reported"
    return names.get(value, f"unknown_{value}")


@dataclass
class Diag0xB0B5:
    """0xB0B5 — LTE PDCP UL SRB integrity data PDUs."""
    log_time: int
    version: int
    payload_size: int
    num_sub_packets: int | None      # v0x01 wrapper only
    wrapper_reserved: int | None     # v0x01 u16@2 (varies), raw
    subpkt_id: int | None            # v0x01: 0xC7
    subpkt_version: int | None       # v0x01: 0x01 | 0x28
    subpkt_size: int | None
    header_reserved: int | None      # v0x38 bytes 1-3, raw
    srb_cipher_key: str              # hex, K_RRCenc (CANDIDATE)
    srb_integrity_key: str           # hex, K_RRCint
    keys_logged: bool                # False when firmware zeroes the keys
    srb_cipher_algo: int
    srb_cipher_algo_name: str
    srb_integrity_algo: int
    srb_integrity_algo_name: str
    num_pdus: int
    pdus: list[dict[str, Any]] = field(default_factory=list)
    trailing_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB0B5",
            "log_time": self.log_time,
            "version": self.version,
            "payload_size": self.payload_size,
            "num_sub_packets": self.num_sub_packets,
            "wrapper_reserved": self.wrapper_reserved,
            "subpkt_id": self.subpkt_id,
            "subpkt_version": self.subpkt_version,
            "subpkt_size": self.subpkt_size,
            "header_reserved": self.header_reserved,
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
    0xB0B5,
    name="0xB0B5",
    description=(
        "LTE PDCP UL SRB integrity data PDUs: K_RRCenc/K_RRCint, EEA/EIA ids, "
        "and per PDU the rb_cfg_idx, COUNT, MAC-I and logged PDCP PDU bytes"
    ),
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. Body decode of both framings (v0x01 "
        "sub-packet 0xC7, v0x38 flat). MAC-I grounded 1:1 against F3 "
        "mutils_security.c:188/:627 (RM500Q v0x01 24/24, RM520N v0x38 15/15) "
        "and reproduced by 128-EIA2 AES-CMAC with the key at body+16 (v0x01 + "
        "v0x38); F3 Bearer = rb_cfg_idx - 33. Algo id 7 = not reported (F3 "
        ":186 prints Algo=2 on the same capture). 2,368/2,368 captured "
        "records parse. Cipher algo CANDIDATE. Byte 0 (version) is gated to "
        "{0x01, 0x38}. A v0x01 payload shorter than 4 + subpkt_size (the "
        "declared sub-packet) returns None (registry WARN)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=18,
    fields_parsed=18,
    field_invariants={
        "version": {"enum": [_V1, _V38]},
        "subpkt_id": {"enum": [_SUBPKT_ID_SRB_INTEGRITY, None]},
    },
)
def parse_0xb0b5(log_time: int, data: bytes) -> Diag0xB0B5 | None:
    if len(data) < 1 or data[0] not in _LAYOUT:
        return None
    version = data[0]
    base, entry_hdr = _LAYOUT[version]
    if len(data) < base + 36:
        return None

    num_sub = wrap_res = sp_id = sp_ver = sp_size = hdr_res = None
    if version == _V1:
        num_sub = data[1]
        wrap_res = unpack_from("<H", data, 2)[0]
        sp_id, sp_ver = data[4], data[5]
        sp_size = unpack_from("<H", data, 6)[0]
        if sp_id != _SUBPKT_ID_SRB_INTEGRITY:
            return None
        # The sub-packet spans [4:4+subpkt_size]; a payload that cannot
        # hold the declared size is truncated -> loud None (registry WARN).
        if 4 + sp_size > len(data):
            return None
    else:
        hdr_res = int.from_bytes(data[1:4], "little")

    cipher_key = data[base:base + 16]
    integ_key = data[base + 16:base + 32]
    calg, ialg = data[base + 32], data[base + 33]
    num_pdus = unpack_from("<H", data, base + 34)[0]

    pdus: list[dict[str, Any]] = []
    off = base + 36
    for _ in range(num_pdus):
        if off + entry_hdr + 8 > len(data):
            return None
        word, pdu_size, logged = unpack_from("<HHH", data, off)
        entry_res = int.from_bytes(data[off + 6:off + entry_hdr], "little")
        off += entry_hdr
        count, mac_i = unpack_from("<II", data, off)
        off += 8
        if off + logged > len(data):
            return None
        pdu = data[off:off + logged]
        off += logged
        rb_cfg_idx = word & 0x3F
        pdus.append({
            "pdu_word": word,
            "rb_cfg_idx": rb_cfg_idx,
            "srb_id": rb_cfg_idx - 32 if rb_cfg_idx in (33, 34) else None,
            "pdu_word_upper": word >> 6,
            "pdu_size": pdu_size,
            "logged_bytes": logged,
            "truncated": logged < pdu_size,
            "entry_reserved": entry_res,
            "count": count,
            "mac_i": mac_i,
            "pdcp_sn": pdu[0] & 0x1F if pdu else None,
            "pdu_hex": pdu.hex(),
        })

    return Diag0xB0B5(
        log_time=log_time,
        version=version,
        payload_size=len(data),
        num_sub_packets=num_sub,
        wrapper_reserved=wrap_res,
        subpkt_id=sp_id,
        subpkt_version=sp_ver,
        subpkt_size=sp_size,
        header_reserved=hdr_res,
        srb_cipher_key=cipher_key.hex(),
        srb_integrity_key=integ_key.hex(),
        keys_logged=any(cipher_key) or any(integ_key),
        srb_cipher_algo=calg,
        srb_cipher_algo_name=_algo_name(calg, _EEA_NAMES),
        srb_integrity_algo=ialg,
        srb_integrity_algo_name=_algo_name(ialg, _EIA_NAMES),
        num_pdus=num_pdus,
        pdus=pdus,
        trailing_bytes=len(data) - off,
    )
