"""0xB0EB — LTE NAS EMM security-protected outgoing (UL) message envelope.

The uplink twin of 0xB0EA: the NAS message the UE sends, **as transmitted**,
after integrity protection (and ciphering, when the header says so) — the
TS 24.301 §9.1 security-protected envelope behind the same 4-byte DIAG wrapper
as the plain-OTA siblings (``_lte_nas_ota_helpers.py``). The plaintext of the
same message is logged in 0xB0ED (EMM outgoing) / 0xB0E3 (ESM outgoing).

Layout (v0x01, the sole version; 351/351 records, 57 captures, MDM9207 →
SDX65)::

    [0]     u8   version        0x01 (Layer-1 gated)
    [1]     u8   rrc_rel        } DIAG wrapper, 09 05 00 on every record
    [2]     u8   rrc_ver_major  } (same bytes as 0xB0EA/0xB0EC/0xB0ED)
    [3]     u8   rrc_ver_minor  }
    [4]     u8   sec_hdr_type(hi nibble) | prot_disc(lo nibble)
                   prot_disc = 7 (EMM) on every populated record;
                   sec_hdr_type ∈ {1 ×157, 2 ×104, 4 ×47} observed
    [5:9]   u32  mac            NAS message authentication code, big-endian
    [9]     u8   seq_num        NAS sequence number (low byte of UL NAS COUNT)
    [10:]   bytes inner_nas     the protected NAS message

The UL header mix differs from the DL one: sec_hdr_type 1 (integrity only) is
the most common, because a UE that holds a cached EPS security context
integrity-protects its initial messages (Attach / TAU / Detach Request,
Identity / Authentication Response) without ciphering them (TS 24.301
§4.4.4.2); sec_hdr_type 4 is the Security Mode Complete (first message under
the new context, ciphered); 2 is everything after it.

**Empty record.** 43 of 351 records are 12 B with an all-zero body after
the wrapper (``01 09 05 00`` + 8 × ``00``). It carries no envelope. It is surfaced as ``empty_body=True`` with the envelope
fields ``None`` rather than rejected, so the parser accepts every observed
record.

F3 grounding:
  * ``mac`` — equals, 32 bits exact, the MAC-I that ``mutils_security.c:627``
    prints as "MAC-I computation successful: MAC-I[0x%x]" for the UL NAS
    integrity computation. 11/11 records that have a UL print in their
    capture's F3 extract: RM520N-GL (SDX62) ×3 captures (10) and LV55 (SDX55)
    (1), covering sec_hdr_type 1, 2 and 4. 0 mismatches.
  * ``seq_num`` — equals the low byte of the Count in the preceding
    ``mutils_security.c:188`` "integrity_maci function Direction = 0 …
    Count= 0x%0x" (Direction 0 = uplink). 11/11, including LV55 Count 0x10a
    → seq_num 0x0a (the overflow counter is not on the wire).
    The ``Bearer`` printed alongside is NOT a NAS/AS discriminator: initial
    messages (Attach / TAU Request) print ``Bearer = 0x1`` and SRB1 PDCP
    checks also print ``Bearer = 0x0``; the join is by exact MAC equality.
  * Black-box A/B: tshark on the qcsuper pcap of an RM520N-GL
    capture (NAS carried in RRC UL_DCCH, i.e. NOT decoded from this code)
    gives the same (sec_hdr_type, MAC, SQN) triples for all 5 of this code's
    records it carries.
  * ``inner_nas`` — for sec_hdr_type 1 the inner bytes are plaintext
    (``07 41`` Attach Request, ``07 45`` Detach Request, ``07 48`` TAU
    Request, ``07 53`` Authentication Response, ``07 56`` Identity
    Response) and are decoded via the shared plain-OTA decoder. For 2/4 they
    are ciphertext and surfaced raw.

Log name: LOG_LTE_NAS_EMM_SEC_OUTGOING_MSG_LOG_C
Also known as: LOG_LTE_NAS_EMM_OTA_OUTGOING_MESSAGE, LOG_OTA_OUTGOING_MESSAGE, LOG_LTE_NAS_EMM_SECURITY_PROTECTED_OUTGOING_MSG
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

_B0EB_VERSION_OBSERVED = 0x01
_WRAPPER_SIZE = 4           # version, rrc_rel, rrc_ver_major, rrc_ver_minor
_SEC_ENVELOPE_SIZE = 6      # sec_hdr|pd, MAC(4), SQN
_MIN_SIZE = _WRAPPER_SIZE + _SEC_ENVELOPE_SIZE + 1   # at least one inner byte
# The degenerate all-zero record: wrapper + 8 zero bytes (12 B on the wire).
_EMPTY_BODY = bytes(_SEC_ENVELOPE_SIZE + 2)

# TS 24.301 §9.3.1: security header types that carry the MAC+SQN envelope,
# and the subset whose inner message is NOT ciphered.
_PROTECTED_SEC_HDR_TYPES = (1, 2, 3, 4)
_INTEGRITY_ONLY_SEC_HDR_TYPES = (1, 3)


@dataclass
class Diag0xB0EB:
    """0xB0EB — LTE NAS EMM security-protected outgoing message."""
    log_time: int
    version: int
    rrc_rel: int
    rrc_ver_major: int
    rrc_ver_minor: int
    # True for the all-zero 12 B record; every envelope field below is then None.
    empty_body: bool
    prot_disc: int | None
    prot_disc_name: str | None
    sec_hdr_type: int | None
    sec_hdr_type_name: str | None
    mac: int | None
    seq_num: int | None
    is_ciphered: bool | None
    inner_nas: bytes
    # Plain decode of the inner NAS message (msg_type, emm_body, …) via the
    # shared plain-OTA decoder; only when sec_hdr_type says it is not ciphered.
    inner: dict[str, Any] | None
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB0EB",
            "log_time": self.log_time,
            "version": self.version,
            "rrc_rel": self.rrc_rel,
            "rrc_ver_major": self.rrc_ver_major,
            "rrc_ver_minor": self.rrc_ver_minor,
            "empty_body": self.empty_body,
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
    0xB0EB, domain="nas",
    name="0xB0EB",
    description=(
        "LTE NAS EMM security-protected outgoing message — DIAG wrapper, "
        "sec_hdr_type / prot_disc, NAS MAC + sequence number (F3-grounded "
        "vs mutils_security.c UL integrity computation), inner NAS message "
        "(plain decode for integrity-only headers, e.g. Attach / TAU / "
        "Authentication Response; ciphertext surfaced raw otherwise)"
    ),
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Body decoded as the TS 24.301 §9.1 "
        "security-protected NAS envelope behind the plain-OTA DIAG wrapper "
        "(UL twin of 0xB0EA). Captures: 351 records / 57 captures, "
        "byte[0:4]=01 09 05 00 on every record, byte[4] ∈ {0x17, 0x27, 0x47} "
        "plus 43 all-zero 12 B empty records; 351/351 parse, 0 invariant "
        "violations. F3-grounded on RM520N-GL (SDX62, 3 captures) and LV55 (SDX55): mac == mutils_security.c:627 MAC-I "
        "(32-bit exact), seq_num == low byte of :188 Direction-0 Count, 11/11 "
        "across sec_hdr_type 1/2/4. qcsuper/tshark A/B (RRC-carried NAS) "
        "agrees on sec_hdr/MAC/SQN 5/5. For integrity-only headers (1/3) the "
        "plaintext inner message is structure-checked by the shared "
        "_parse_nas_ota (TS 24.301 mandatory + known optional IEs); an inner "
        "message whose declared lengths overrun the record returns None "
        "(registry WARN). Ciphered inners (2/4) carry no length and cannot be "
        "checked."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # Wire fields: version, rrc_rel, rrc_ver_major, rrc_ver_minor, prot_disc,
    # sec_hdr_type, mac, seq_num, inner_nas. `empty_body`, `is_ciphered` and
    # the `inner` plain decode are derivations, not wire fields.
    fields_identified=9,
    fields_parsed=9,
    field_invariants={
        "version": {"enum": [_B0EB_VERSION_OBSERVED]},
        "prot_disc": {"enum": [7]},
        "sec_hdr_type": {"enum": list(_PROTECTED_SEC_HDR_TYPES)},
    },
)
def parse_0xb0eb(log_time: int, data: bytes) -> Diag0xB0EB | None:
    if len(data) < _WRAPPER_SIZE + 1:
        return None
    version = data[0]
    if version != _B0EB_VERSION_OBSERVED:
        return None

    if data[_WRAPPER_SIZE:] == _EMPTY_BODY:
        return Diag0xB0EB(
            log_time=log_time,
            version=version,
            rrc_rel=data[1],
            rrc_ver_major=data[2],
            rrc_ver_minor=data[3],
            empty_body=True,
            prot_disc=None,
            prot_disc_name=None,
            sec_hdr_type=None,
            sec_hdr_type_name=None,
            mac=None,
            seq_num=None,
            is_ciphered=None,
            inner_nas=b"",
            inner=None,
            payload_size=len(data),
        )

    if len(data) < _MIN_SIZE:
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
            log_code=0xB0EB,
            is_uplink=True,
            type_name="Diag0xB0EB.inner",
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

    return Diag0xB0EB(
        log_time=log_time,
        version=version,
        rrc_rel=data[1],
        rrc_ver_major=data[2],
        rrc_ver_minor=data[3],
        empty_body=False,
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
