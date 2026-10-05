"""0xB0EA — LTE NAS EMM security-protected incoming (DL) message envelope.

The downlink NAS message **as received**, before integrity check and
deciphering: the TS 24.301 §9.1 security-protected envelope behind the same
4-byte DIAG wrapper as the plain-OTA siblings (``_lte_nas_ota_helpers.py``).
Once the UE verifies and deciphers it, the inner plain message is logged
again in 0xB0EC (EMM inner) or 0xB0E2 (ESM inner).

Layout (v0x01, the sole version; 300/300 records, 62 captures, 9 chipsets
MDM9207 → SDX65)::

    [0]     u8   version        0x01 (Layer-1 gated)
    [1]     u8   rrc_rel        } DIAG wrapper, 09 05 00 on every record
    [2]     u8   rrc_ver_major  } (same bytes as 0xB0EC/0xB0ED)
    [3]     u8   rrc_ver_minor  }
    [4]     u8   sec_hdr_type(hi nibble) | prot_disc(lo nibble)
                   prot_disc = 7 (EMM) on 300/300; sec_hdr_type ∈ {2, 3}
                   observed (0x27 ×257, 0x37 ×43), 1..4 legal (§9.3.1)
    [5:9]   u32  mac            NAS message authentication code, big-endian
    [9]     u8   seq_num        NAS sequence number (low byte of DL NAS COUNT)
    [10:]   bytes inner_nas     the protected NAS message

F3 grounding:
  * ``mac`` — equals, 32 bits exact, the MAC-I that ``mutils_security.c:627``
    prints as "MAC-I computation successful: MAC-I[0x%x]" for the DL NAS
    integrity check (``:608`` "MAC-I rxd" prints the same wire bytes read
    little-endian). 6/6 records on RM520N-GL (SDX62) + RM500Q-AE (SDX55).
  * ``seq_num`` — equals the Count in the adjacent ``mutils_security.c:188``
    "integrity_maci function Direction = 1 Bearer = 0x0 Count= 0x%0x"
    (Direction 1 = downlink, Bearer 0 = NAS per TS 33.401). 6/6.
  * Black-box A/B: tshark on the qcsuper pcap of an RM520N-GL capture (NAS
    carried in RRC DLInformationTransfer, i.e. NOT decoded from this code)
    shows the same (sec_hdr_type, MAC, SQN) triples as this code's records.
  * ``inner_nas`` — for sec_hdr_type 3 (integrity protected with new EPS
    context: the Security Mode Command) the inner bytes are plaintext
    ``07 5D …`` and equal the following 0xB0EC record's NAS PDU byte-for-
    byte. For sec_hdr_type 2/4 the inner bytes are ciphertext (length equals
    the plaintext logged in 0xB0EC/0xB0E2); they are surfaced raw, and
    decoded only when the header says they are not ciphered.

Log name: LOG_LTE_NAS_EMM_SEC_INCOMING_MSG_LOG_C
Also known as: LOG_LTE_NAS_EMM_OTA_INCOMING_MESSAGE, LOG_OTA_INCOMING_MESSAGE, LOG_LTE_NAS_EMM_SECURITY_PROTECTED_INCOMING_MSG
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.parsers._lte_nas_ota_helpers import (
    _PROT_DISC_NAMES,
    _SEC_HDR_TYPE_NAMES,
    _parse_nas_ota,
)
from diaggrok.registry import register

_B0EA_VERSION_OBSERVED = 0x01
_WRAPPER_SIZE = 4           # version, rrc_rel, rrc_ver_major, rrc_ver_minor
_SEC_ENVELOPE_SIZE = 6      # sec_hdr|pd, MAC(4), SQN
_MIN_SIZE = _WRAPPER_SIZE + _SEC_ENVELOPE_SIZE + 1   # at least one inner byte

# TS 24.301 §9.3.1: security header types that carry the MAC+SQN envelope,
# and the subset whose inner message is NOT ciphered.
_PROTECTED_SEC_HDR_TYPES = (1, 2, 3, 4)
_INTEGRITY_ONLY_SEC_HDR_TYPES = (1, 3)


@dataclass
class Diag0xB0EA:
    """0xB0EA — LTE NAS EMM security-protected incoming message."""
    log_time: int
    version: int
    rrc_rel: int
    rrc_ver_major: int
    rrc_ver_minor: int
    prot_disc: int
    prot_disc_name: str
    sec_hdr_type: int
    sec_hdr_type_name: str
    mac: int
    seq_num: int
    is_ciphered: bool
    inner_nas: bytes
    # Plain decode of the inner NAS message (msg_type, emm_body, …) via the
    # shared plain-OTA decoder; only when sec_hdr_type says it is not ciphered.
    inner: dict[str, Any] | None
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB0EA",
            "log_time": self.log_time,
            "version": self.version,
            "rrc_rel": self.rrc_rel,
            "rrc_ver_major": self.rrc_ver_major,
            "rrc_ver_minor": self.rrc_ver_minor,
            "prot_disc": self.prot_disc,
            "prot_disc_name": self.prot_disc_name,
            "sec_hdr_type": self.sec_hdr_type,
            "sec_hdr_type_name": self.sec_hdr_type_name,
            "mac": self.mac,
            "seq_num": self.seq_num,
            "is_ciphered": self.is_ciphered,
            "inner_nas_hex": self.inner_nas.hex(),
            "inner": self.inner,
            "payload_size": self.payload_size,
        }


@register(
    0xB0EA, domain="nas",
    name="0xB0EA",
    description=(
        "LTE NAS EMM security-protected incoming message — DIAG wrapper, "
        "sec_hdr_type / prot_disc, NAS MAC + sequence number (F3-grounded "
        "vs mutils_security.c DL integrity check), inner NAS message (plain "
        "decode for integrity-only headers, e.g. the Security Mode Command; "
        "ciphertext surfaced raw otherwise)"
    ),
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Body decoded as the TS 24.301 §9.1 "
        "security-protected NAS envelope behind the plain-OTA DIAG wrapper. "
        "Captures: 300 records / 62 captures / 9 chipsets, byte[0:4]=01 09 05 00 "
        "and prot_disc=7 on every record, sec_hdr_type {2,3}. F3-grounded on "
        "RM520N-GL (SDX62) and RM500Q-AE (SDX55): mac == mutils_security.c:627 "
        "computed MAC-I (32-bit exact), seq_num == :188 DL Bearer-0 Count, 6/6. "
        "qcsuper/tshark A/B (RRC-carried NAS) agrees on sec_hdr/MAC/SQN. "
        "sec_hdr_type 3 inner == the following 0xB0EC Security Mode Command "
        "byte-for-byte. For integrity-only headers (1/3) the plaintext inner "
        "message is structure-checked by the shared _parse_nas_ota (TS 24.301 "
        "mandatory + known optional IEs); an inner message whose declared "
        "lengths overrun the record returns None (registry WARN). Ciphered "
        "inners (2/4) carry no length and cannot be checked."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Wire fields: version, rrc_rel, rrc_ver_major, rrc_ver_minor, prot_disc,
    # sec_hdr_type, mac, seq_num, inner_nas. The `inner` plain decode is a
    # derivation of inner_nas, not a wire field.
    fields_identified=9,
    fields_parsed=9,
    field_invariants={
        "version": {"enum": [_B0EA_VERSION_OBSERVED]},
        "prot_disc": {"enum": [7]},
        "sec_hdr_type": {"enum": list(_PROTECTED_SEC_HDR_TYPES)},
    },
)
def parse_0xb0ea(log_time: int, data: bytes) -> Diag0xB0EA | None:
    if len(data) < _MIN_SIZE:
        return None
    version = data[0]
    if version != _B0EA_VERSION_OBSERVED:
        return None
    hdr = data[_WRAPPER_SIZE]
    prot_disc = hdr & 0x0F
    sec_hdr_type = (hdr >> 4) & 0x0F
    # Only EMM carries a security header, and only types 1..4 carry the
    # MAC+SQN envelope. Anything else is not this layout.
    if prot_disc != 7 or sec_hdr_type not in _PROTECTED_SEC_HDR_TYPES:
        return None
    mac = unpack_from(">I", data, _WRAPPER_SIZE + 1)[0]
    seq_num = data[_WRAPPER_SIZE + 5]
    inner_nas = data[_WRAPPER_SIZE + _SEC_ENVELOPE_SIZE:]
    is_ciphered = sec_hdr_type not in _INTEGRITY_ONLY_SEC_HDR_TYPES

    inner: dict[str, Any] | None = None
    if not is_ciphered:
        plain = _parse_nas_ota(
            log_time,
            data[:_WRAPPER_SIZE] + inner_nas,
            log_code=0xB0EA,
            is_uplink=False,
            type_name="Diag0xB0EA.inner",
        )
        # The integrity-only inner message is plaintext, so its own
        # structure is checked by the shared decoder; None there means the
        # record cannot hold what the message declares (truncated) -> loud None.
        if plain is None:
            return None
        inner = {
            k: v for k, v in plain.to_dict().items()
            if k not in ("type", "log_time", "log_code", "is_uplink",
                         "version", "rrc_rel", "rrc_ver_major",
                         "rrc_ver_minor", "payload_size")
        }

    return Diag0xB0EA(
        log_time=log_time,
        version=version,
        rrc_rel=data[1],
        rrc_ver_major=data[2],
        rrc_ver_minor=data[3],
        prot_disc=prot_disc,
        prot_disc_name=_PROT_DISC_NAMES.get(prot_disc, f"0x{prot_disc:X}"),
        sec_hdr_type=sec_hdr_type,
        sec_hdr_type_name=_SEC_HDR_TYPE_NAMES.get(sec_hdr_type, f"0x{sec_hdr_type:X}"),
        mac=mac,
        seq_num=seq_num,
        is_ciphered=is_ciphered,
        inner_nas=inner_nas,
        inner=inner,
        payload_size=len(data),
    )
