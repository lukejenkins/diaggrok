"""LTE NAS ESM security-protected OTA outgoing message (0xB0E1).

Canonical name ``LOG_LTE_NAS_ESM_OTA_OUTGOING_MESSAGE``; the alias
``LOG_LTE_NAS_ESM_SECURITY_PROTECTED_OUTGOING_MSG`` (listed below) is the
accurate one. Layout (F3-grounded)::

    [0:4]  version, rrc_rel, rrc_ver_major, rrc_ver_minor   (DIAG NAS ext header)
    [4]    sec_hdr_type << 4 | prot_disc   (0x27: integrity+ciphered | EMM PD)
    [5:9]  nas_mac   (u32 BE NAS message authentication code)
    [9]    nas_seq   (UL NAS sequence number)
    [10:]  inner_pdu (the ESM message; ciphered unless the network chose EEA0)

``nas_pdu`` is the whole protected NAS PDU ``data[4:]``. That is what GSMTAP
frames, with the security-header sub-type, so stock nas-eps dissects the MAC,
the SQN and (under EEA0) the inner message.

=== Variable length ===

The record is variable length ("size invariance ≠ format invariance");
across 55 records / 9 captures:

  | size | records | note                                              |
  |-----:|--------:|---------------------------------------------------|
  | 65 B |      46 | **dominant (84%)** — opaque/high-entropy NAS PDU  |
  | 33 B |       7 | short ESM msg (incl. the LV55 plaintext-APN form) |
  | 13 B |       1 | shortest observed                                 |
  | 86 B |       1 | longest observed PDU                              |

Do not assume a fixed 33 B size: a fixed slice would truncate 32 B of NAS PDU
on every 65 B record. ``byte[9]`` is not constant: it takes 40+ values across
the 65 B records (it is the NAS SQN, see below).

Plaintext APN: the 33 B LV55 SDX55 records carry a plaintext APN in **3GPP
DNS-label encoding** (TS 23.003) inside an ESM Access-Point-Name IE::

    01 09 05 00 27 | 60 04 5b 33 | 01 | 02 1a da 28 12 | 04 'fast' 08 't-mobile' 03 'com'
    └─ header[0:5] ┘ └seq[5:9] ┘ └── ESM NAS PDU [9:] ─────────────────────────────────┘
                                          28 = APN IEI, 12 = len 18 ──┘└─ DNS-label APN ─┘

The APN is readable because that network chose null ciphering (EEA0), not
because the message type is unprotected (see the F3 grounding below).

=== F3 grounding of v0x01 ===

0xB0E1 is the security-protected outer of an outgoing ESM message
(``LOG_LTE_NAS_ESM_SECURITY_PROTECTED_OUTGOING_MSG``). In TS 24.301 §9.1
terms the bytes after the DIAG header are::

    [4] 0x27 = sec_hdr_type 2 | PD 7   (``sec_hdr_type`` / ``prot_disc``)
    [5:9] NAS-MAC                      (``nas_mac``)
    [9] NAS SQN                        (``nas_seq``)
    [10:] inner ESM message, ciphered unless the network chose EEA0

On 15/15 F3-labelled records over 9 captures (EM7565 ×2, EM120R, LM960 ×2,
RM520N-GL ×2, FT980m, RM500Q), each 0xB0E1 sits on the same DIAG tick as a
plain 0xB0E3 of the same message. It is exactly 6 octets longer, and F3 prints
"NAS message is security protected" plus "msg_id = <that 0xB0E3 msg_type>". The
inner equals the 0xB0E3 PDU byte-for-byte exactly where the co-captured
Security Mode Command picked EEA0 (``5d 01``: EM7565 x2, LM960) and is
high-entropy under EEA2 (``5d 22``: EM120R, RM520N-GL x2, FT980m, RM500Q), 8/8
captures that hold both. So the readable LV55 APN came from a null-ciphered network, not from
an unprotected message type. The SQN steps 6, 7, 8, 9 across consecutive UL
messages on LM960. GSMTAP frames ``data[4:]`` as a security-header NAS PDU,
not ``data[9:]`` as a plain one.

Header [0:5] = (version=1, rrc_rel=9, rrc_ver_major=5, rrc_ver_minor=0,
byte[4]=0x27), constant across all 3 chipsets / 4 sizes (the major/minor
order follows a vendor decoder's rendered output).

Log name: LOG_LTE_NAS_ESM_OTA_OUTGOING_MESSAGE
Also known as: LOG_OTA_OUTGOING_MESSAGE, LOG_LTE_NAS_ESM_SECURITY_PROTECTED_OUTGOING_MSG
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.codes import LOG_LTE_NAS_ESM_B0E1
from diaggrok.parsers._lte_nas_ota_helpers import (
    SEC_PROTECTED_OVERHEAD,
    _SEC_HDR_TYPE_NAMES,
    split_sec_protected,
)
from diaggrok.registry import register

# DIAG header(4) + security header(6) + a 3-octet ESM header (EBI|PD, PTI, type,
# TS 24.301 §8.3). The observed minimum is 13. A shorter record cannot hold an ESM
# message, so it is rejected loudly rather than decoded short.
_B0E1_MIN_SIZE = 4 + SEC_PROTECTED_OVERHEAD + 3
_B0E1_VERSION_OBSERVED = 0x01  # byte [0] = DIAG NAS extended-header version
# byte [4] is 0x27 on every observed record: ESM is sent only after Security Mode,
# so it is always integrity protected and ciphered (sec_hdr_type 2) under the
# EMM PD 7. Any other octet is rejected loudly, never mis-parsed.
_B0E1_SEC_HDR_TYPE = 2
_B0E1_PROT_DISC = 7


@dataclass
class Diag0xB0E1:
    """LTE NAS ESM security-protected OTA outgoing message (0xB0E1)."""
    log_time: int
    version: int          # [0]  = 0x01 — DIAG NAS extended-header version
    rrc_rel: int          # [1]  = 0x09
    rrc_ver_major: int    # [2]  = 0x05
    rrc_ver_minor: int    # [3]  = 0x00
    sec_hdr_type: int     # [4] high nibble = 2 (integrity protected and ciphered)
    prot_disc: int        # [4] low nibble  = 7 (EMM: the security header is EMM's)
    nas_mac: int          # [5:9] u32 BE NAS-MAC
    nas_seq: int          # [9]   UL NAS sequence number
    nas_pdu: bytes        # [4:]  whole security-protected NAS PDU (GSMTAP payload)
    inner_pdu: bytes      # [10:] inner ESM message, ciphered unless EEA0
    apn: str | None       # DNS-label APN, only when the inner message is readable
    payload_size: int
    is_uplink: bool = True  # outgoing (F3 send path)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0xB0E1',
            'log_time': self.log_time,
            'version': self.version,
            'rrc_rel': self.rrc_rel,
            'rrc_ver_major': self.rrc_ver_major,
            'rrc_ver_minor': self.rrc_ver_minor,
            'sec_hdr_type': self.sec_hdr_type,
            'sec_hdr_type_name': _SEC_HDR_TYPE_NAMES.get(self.sec_hdr_type, f"0x{self.sec_hdr_type:X}"),
            'prot_disc': self.prot_disc,
            'nas_mac': self.nas_mac,
            'nas_seq': self.nas_seq,
            'nas_pdu_hex': self.nas_pdu.hex(),
            'inner_pdu_hex': self.inner_pdu.hex(),
            'apn': self.apn,
            'is_uplink': self.is_uplink,
            'payload_size': self.payload_size,
        }


def _decode_apn_labels(pdu: bytes) -> str | None:
    """Decode a 3GPP APN (TS 23.003 DNS-label form) embedded in the NAS PDU.

    Scans every offset for a run of length-prefixed labels — ``L b₀..b_{L-1}``
    with ``1 <= L <= 63`` and all label bytes printable ASCII — joined by dots.
    Returns the first run that yields >= 2 labels and contains a dot (so a
    lone random length byte followed by printable junk can't masquerade as an
    APN).  Returns None for opaque / non-APN PDUs.
    """
    best: str | None = None
    n = len(pdu)
    for start in range(n):
        labels: list[str] = []
        i = start
        while i < n:
            length = pdu[i]
            if not (1 <= length <= 63) or i + 1 + length > n:
                break
            chunk = pdu[i + 1 : i + 1 + length]
            if not all(0x21 <= b <= 0x7E for b in chunk):
                break
            labels.append(chunk.decode('ascii'))
            i += 1 + length
        if len(labels) >= 2:
            candidate = '.'.join(labels)
            if best is None or len(candidate) > len(best):
                best = candidate
    return best


@register(
    LOG_LTE_NAS_ESM_B0E1, domain="nas",
    name="0xB0E1",
    description="LTE NAS ESM security-protected OTA outgoing message — sec hdr | MAC | SQN | inner ESM",
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from EM7511 MDM9650, checked across 55 records / 9 "
        "captures (variable length, plaintext APN under EEA0), with a byte-0 "
        "version gate. The TS 24.301 §9.1 security-protected layout is "
        "F3-grounded: [4] = sec_hdr_type 2 | PD 7, [5:9] NAS-MAC, [9] NAS "
        "SQN, [10:] inner ESM. Each record is the same-tick protected outer of a "
        "0xB0E3 message, 6 octets longer (15/15 F3-labelled, 9 captures, "
        "SDX20..SDX62). nas_pdu is data[4:] so GSMTAP frames a "
        "security-header nas-eps PDU; stock tshark then dissects MAC/SQN and, "
        "under EEA0, the inner message."
    ),
    issues=(),
    primary_issue=None,
    ascii_kinds=("config-token",),  # plaintext APN in DNS-label form (fast.t-mobile.com) under EEA0; LV55 SDX55
    fields_identified=11,
    fields_parsed=11,
    field_invariants={
        "version": {"enum": [_B0E1_VERSION_OBSERVED]},
        "sec_hdr_type": {"enum": [_B0E1_SEC_HDR_TYPE]},
        "prot_disc": {"enum": [_B0E1_PROT_DISC]},
    },
)
def parse_0xb0e1(log_time: int, data: bytes) -> Diag0xB0E1 | None:
    if len(data) < _B0E1_MIN_SIZE:
        return None
    # Byte-0 version gate (the NAS ext-header version).
    if data[0] != _B0E1_VERSION_OBSERVED:
        return None
    split = split_sec_protected(bytes(data[4:]))
    if split is None:
        return None
    sec_hdr_type, prot_disc, nas_mac, nas_seq, inner = split
    if sec_hdr_type != _B0E1_SEC_HDR_TYPE or prot_disc != _B0E1_PROT_DISC:
        return None
    return Diag0xB0E1(
        log_time=log_time,
        version=data[0],
        rrc_rel=data[1],
        rrc_ver_major=data[2],
        rrc_ver_minor=data[3],
        sec_hdr_type=sec_hdr_type,
        prot_disc=prot_disc,
        nas_mac=nas_mac,
        nas_seq=nas_seq,
        nas_pdu=bytes(data[4:]),
        inner_pdu=inner,
        apn=_decode_apn_labels(inner),
        payload_size=len(data),
    )
