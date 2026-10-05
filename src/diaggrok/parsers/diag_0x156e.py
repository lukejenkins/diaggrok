"""0x156E — LOG_IMS_SIP_MESSAGE: SIP signaling message trace (ASCII, PII).

Canonical name ``LOG_IMS_SIP_MESSAGE``. Observed on registered RM520N-GL SDX62
T-Mobile captures. A variable-length record
(697–4109 B observed), byte[0] = 0x01, whose body is a **full SIP message as
ASCII text** — request/response line, headers, and (when present) SDP.

Record framing (SIP text begins ~offset 77, after a per-record contact-id
prefix whose length shifts the offset by ±1):

    [0]    u8    version (0x01)              — Layer-1 gate
    [1]    u8    direction: 0x01 = mobile-originated (UE → network),
                            0x00 = mobile-terminated (network → UE)
    [2]    u8    reserved (0x00, corpus-invariant)
    [3]    u8    pre-SIP prefix length — the firmware's own declaration of the
                 byte distance from [16] to the SIP start-line (== presip_prefix_len
                 114/114 corpus-wide). A length, not a small enum/counter;
                 corpus range {0x34, 0x3C, 0x3D, 0x3E, 0x51} = {52,60,61,62,81}.
    [4:6]  u16LE SIP message byte length — **equals len(SIP text)**, 61/61
    [6:8]  u16LE SIP length + 1 (length including the NUL terminator)
    [8:10] u16LE method-family tag ({1, 7, 8, 11} observed) — surfaced as
                 `method_family`: 1=REGISTER 7=SUBSCRIBE 8=NOTIFY 11=MESSAGE
    [10:12]u16LE SIP **status code** — 0 for a request, else the 3-digit
                 response code (200 / 401 …); 0/61 mismatches vs. the
                 status independently extracted from the SIP start-line
    [12:14]u16LE 0x00FF (corpus-invariant)
    [14:16]u16LE 0x0000 (corpus-invariant)
    [~16]  C-str  contact-id: ``<tag>_<tag>@<IPv6>``
    [~77]  the SIP message (``REGISTER sip:msg.pc.t-mobile.com SIP/2.0`` …
                            or ``SIP/2.0 200 OK`` …), CRLF-delimited.

The [2:16] header was decoded byte-for-byte against all 61 records of the
first source capture. [4:8] is a length pair (msg-len, msg-len+1), not a
free-running sequence counter. All decoded header fields are non-PII binary scalars (a length, two small enums,
a status code, two constants).

This parser **decodes the record faithfully**: it emits the full SIP message
text (`sip_message`) and the pre-SIP contact-id prefix (`presip_prefix`)
alongside the structural metadata (method / status, direction, header names,
CSeq method, has_sdp, realm + MCC/MNC). A SIP message carries the subscriber
IMS public identity (IMSI-derived SIP URI), the device IPv6, and possibly the
MSISDN — decoding them is the whole point: a user troubleshooting their
OWN device must be able to read their own identifiers. This library
never redacts, censors, or withholds decoded content. The
``ascii_kinds=("config-token","identifier")`` values just classify the ASCII
content this record carries.

Sibling IMS/SIP codes: 0x1832 (LOG_IMS_REGISTRATION), 0x1C9C (IMS
messaging-identity), 0x11EB (LOG_DATA_PROTOCOL_LOGGING, SIP-bearing).

Conservative first-observation recognition parser. 114+ records / 4+
captures, RM520N-GL SDX62 only; other chipsets are not yet sampled.

F3 grounding (v0x01). Every F3-bearing capture (14, 251 records): the IMS stack's own logger
``qpSipUtils.cpp`` "OutGoing:LogSipMsg Method: %d RespCode: %d" / "… ActualMsgLen:
%d LoggedMsgLen: %d" sits within 20 ms of every record; ``Method ==
hdr_msg_class``, ``RespCode == hdr_status`` and ``ActualMsgLen == hdr_msg_len``
on 251/251. The ``OutGoing:`` prefix is constant (also beside network-sent
responses), so F3 neither confirms nor contradicts ``direction``.

Log name: LOG_IMS_SIP_MESSAGE_C
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Any

from diaggrok.registry import register

_EXPECTED_VERSION = 0x01

# hdr_msg_class ([8:10] u16LE) is the SIP transaction method-family tag — the
# SAME value for a request and all its responses (grounded across 105 records /
# 3 RM520N-GL captures). The mapping is non-PII (a protocol method name, not
# subscriber content). Unknown classes surface as "" so a future firmware
# value never mis-labels a record (shape != semantics).
_METHOD_FAMILY = {1: "REGISTER", 7: "SUBSCRIBE", 8: "NOTIFY", 11: "MESSAGE"}

# SIP message start-line: a request (``METHOD sip:… SIP/2.0``) or a status
# response (``SIP/2.0 <code> <reason>``).
_START_LINE_RE = re.compile(rb"([A-Z]{3,9}) sip:[^ \r\n]+ SIP/2\.0|SIP/2\.0 (\d{3}) ")
# From/To IMS public identity realm — non-PII carrier identifier.
_REALM_RE = re.compile(rb"@(ims\.mnc(\d{2,3})\.mcc(\d{3})\.3gppnetwork\.org)")
# P-CSCF / registrar host: dotted sip: domain with no userinfo and no ':' port.
_PCSCF_RE = re.compile(rb'sip:([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})(?:[\x00>;,\r "]|$)')
# CSeq: ``<seq-number> <METHOD>`` — we only need the method, so the sequence
# token is matched loosely (\S+) and discarded; its value is irrelevant here.
_CSEQ_RE = re.compile(rb"\r\nCSeq:\s*\S+\s+([A-Za-z]+)")


@dataclass
class Diag0x156E:
    """0x156E LOG_IMS_SIP_MESSAGE — faithful decode incl. full SIP message text."""
    log_time: int
    version: int
    direction: str             # "mo" (mobile-originated) | "mt" (mobile-terminated)
    # [2:16] binary header (all non-PII scalars):
    hdr_msg_len: int           # [4:6] u16LE — SIP message byte length (== sip_len)
    hdr_msg_class: int         # [8:10] u16LE — method-family tag ({1,7,8,11} obs.)
    method_family: str         # name of hdr_msg_class (REGISTER/SUBSCRIBE/NOTIFY/MESSAGE/"")
    hdr_status: int            # [10:12] u16LE — SIP status code (0 for a request)
    presip_prefix_len: int     # bytes between [2:16] header and the SIP start-line
                               # (the contact-id C-string; +routing token on class-11
                               # MESSAGE). A non-PII structural length — NOT its content.
    hdr_presip_len: int        # [3] u8 — the FIRMWARE's own declaration of the
                               # pre-SIP prefix length. == presip_prefix_len 114/114
                               # corpus-wide: byte[3] is this same length, declared
                               # in the header instead of inferred by start-line scan.
    presip_len_ok: bool        # hdr_presip_len == presip_prefix_len (the header-declared
                               # length agrees with the scanned one). False flags a
                               # malformed/truncated record or an unmodeled prefix shape.
    is_request: bool
    method: str                # request method, or "" for a response
    status_code: int | None    # response status, or None for a request
    cseq_method: str           # method named in the CSeq header
    header_names: list[str] = field(default_factory=list)  # convenience index of header field names
    num_headers: int = 0
    has_sdp: bool = False
    ims_realm: str = ""        # ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org — network id
    mcc: int | None = None
    mnc: int | None = None
    pcscf_host: str = ""       # P-CSCF host (config-token), if present
    sip_len: int = 0           # length of the SIP text region
    sip_message: str = ""      # the full decoded SIP message text (faithful decode)
    presip_prefix: str = ""    # the decoded pre-SIP contact-id prefix (device IMS contact)
    payload_size: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x156E",
            "log_time": self.log_time,
            "version": self.version,
            "direction": self.direction,
            "hdr_msg_len": self.hdr_msg_len,
            "hdr_msg_class": self.hdr_msg_class,
            "method_family": self.method_family,
            "hdr_status": self.hdr_status,
            "presip_prefix_len": self.presip_prefix_len,
            "hdr_presip_len": self.hdr_presip_len,
            "presip_len_ok": self.presip_len_ok,
            "is_request": self.is_request,
            "method": self.method,
            "status_code": self.status_code,
            "cseq_method": self.cseq_method,
            "header_names": list(self.header_names),
            "num_headers": self.num_headers,
            "has_sdp": self.has_sdp,
            "ims_realm": self.ims_realm,
            "mcc": self.mcc,
            "mnc": self.mnc,
            "pcscf_host": self.pcscf_host,
            "sip_len": self.sip_len,
            "sip_message": self.sip_message,
            "presip_prefix": self.presip_prefix,
            "payload_size": self.payload_size,
        }


# WiGLE: N/A — IMS SIP message trace — mcc/mnc live in the SIP/IMS identity (PII), not a serving-cell observation. Reviewed, contributes nothing to a WiGLE
# observation.
@register(
    0x156E,
    name="0x156E",
    description="LOG_IMS_SIP_MESSAGE — SIP message trace (ASCII, PII) — RM520N-GL",
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from registered T-Mobile RM520N-GL (SDX62) captures "
        "(114+ records, REGISTER/SUBSCRIBE/NOTIFY and SMS-over-IMS MESSAGE; "
        "VoLTE and VoNR captures included). The [2:16] binary header is "
        "decoded byte-for-byte: [4:6] u16LE = SIP message-region length from "
        "byte 16 (== len(SIP text) when the start-line sits at byte 16; "
        "class-11 MESSAGE records carry a pre-SIP routing token + NUL first), "
        "[6:8] = that length + 1, [8:10] = transaction method-family tag "
        "(1=REGISTER 7=SUBSCRIBE 8=NOTIFY 11=MESSAGE, same for a request and "
        "its responses), [10:12] = SIP status code (0 for a request; "
        "{0,200,202,401} observed), [3] = the pre-SIP prefix length (equal to "
        "the scanned length on all 114 records), [2]=0x00, [12:14]=0x00FF, "
        "[14:16]=0x0000 invariant. F3-grounded on 251/251 records in 14 "
        "captures by qpSipUtils.cpp LogSipMsg (Method / RespCode / "
        "ActualMsgLen). Decodes faithfully: `sip_message` (the full SIP text) "
        "and `presip_prefix` (the contact-id) are emitted alongside method / "
        "status, MO/MT direction (byte 1), header names, CSeq method, has_sdp "
        "and the realm MCC/MNC. Layer-1 version gate on byte 0 == 0x01. A "
        "record with no NUL terminator, or whose NUL falls before byte 16 + "
        "hdr_msg_len, returns None."
    ),
    source_url="",
    issues=(),
    field_invariants={
        "version": {"enum": [_EXPECTED_VERSION]},
    },
    # ASCII: classifies the content this record carries — config-token
    # (request-URI host / P-CSCF) + identifier (IMSI-derived To/From IMS
    # identity). Content classification only; the decoder emits the full
    # message faithfully.
    ascii_kinds=("config-token", "identifier"),
    fields_identified=19,
    fields_parsed=19,
    # WiGLE decided-none: reviewed and found not WiGLE-relevant. The mcc/mnc
    # here live in the SIP/IMS identity (PII), not a serving-cell observation.
    # (False, ()) records that decision explicitly.
    wigle_direct=False,
    wigle_roles=(),
)
def parse_0x156e(log_time: int, data: bytes) -> Diag0x156E | None:
    # Layer-1 version gate (version byte first). byte 1 is a
    # MO/MT direction flag (0x00/0x01), NOT a version — do not gate on it.
    if len(data) < 16:
        return None
    if data[0] != _EXPECTED_VERSION:
        return None

    m = _START_LINE_RE.search(data)
    if not m:
        return None

    # [2:16] binary header. All non-PII scalars, surfaced for record
    # classification/filtering (the SIP body itself is emitted faithfully as
    # `sip_message` below).
    hdr_msg_len = struct.unpack_from("<H", data, 4)[0]    # full msg region from [16]
    hdr_msg_class = struct.unpack_from("<H", data, 8)[0]  # method-family: 1=REGISTER
                                                          # 7=SUBSCRIBE 8=NOTIFY 11=MESSAGE
    hdr_status = struct.unpack_from("<H", data, 10)[0]    # 0=request, else code
    method_family = _METHOD_FAMILY.get(hdr_msg_class, "")  # non-PII protocol name
    sip_off = m.start()
    # Non-PII structural length: bytes between the [2:16] binary header and the
    # SIP start-line. On REGISTER/SUBSCRIBE/NOTIFY this is the contact-id
    # C-string; on class-11 MESSAGE it also includes the SMS routing token +
    # NUL. Both the length AND the decoded prefix content (`presip_prefix`)
    # are exposed; the contact-id carries the device IPv6,
    # decoded faithfully like everything else.
    presip_prefix_len = sip_off - 16
    # byte[3] is the firmware's OWN declaration of that pre-SIP prefix length —
    # it equals the start-line-scanned presip_prefix_len for all 114 corpus
    # records. The scan-derived presip_prefix_len stays the primary value
    # (it locates the actual start-line) and expose byte[3] alongside as an
    # independent header cross-check; a mismatch flags a malformed record.
    hdr_presip_len = data[3]
    presip_len_ok = hdr_presip_len == presip_prefix_len
    # The SIP text runs from the start-line to the trailing NUL. For class-11
    # MESSAGE records the message region begins with a
    # pre-SIP routing token + embedded NUL, so sip_off > 16 and the resulting
    # sip_len is < hdr_msg_len by that prefix (cross-capture 40/44).
    nul = data.find(b"\x00", sip_off)
    # The header declares the SIP region ([4:6]
    # length from byte 16; [6:8] = that length + its NUL terminator). A record
    # with no NUL terminator, or whose NUL falls before byte 16 + hdr_msg_len,
    # is truncated — return None (registry WARN) instead of emitting a
    # silently clipped SIP message.
    if nul == -1 or nul < 16 + hdr_msg_len:
        return None
    sip = data[sip_off:nul]

    method = ""
    status_code: int | None = None
    if m.group(1) is not None:
        is_request = True
        method = m.group(1).decode("ascii")
    else:
        is_request = False
        status_code = int(m.group(2))

    # Convenience index of header field NAMES (token before the first ':' on
    # each header line), up to the blank-line header/body separator. The full
    # header values ride in `sip_message` below (faithful decode); this
    # list is just a quick filterable index.
    blank = sip.find(b"\r\n\r\n")
    header_region = sip[:blank] if blank != -1 else sip
    header_names: list[str] = []
    for line in header_region.split(b"\r\n")[1:]:  # skip the start-line
        if b":" not in line:
            continue
        name = line.split(b":", 1)[0].strip()
        if name and all(32 <= b < 127 for b in name) and b" " not in name:
            header_names.append(name.decode("ascii"))

    cseq_m = _CSEQ_RE.search(sip)
    cseq_method = cseq_m.group(1).decode("ascii").upper() if cseq_m else ""

    has_sdp = b"application/sdp" in sip or (
        blank != -1 and sip[blank + 4: blank + 8].startswith(b"v=0")
    )

    realm_m = _REALM_RE.search(sip)
    ims_realm = realm_m.group(1).decode("ascii") if realm_m else ""
    mnc = int(realm_m.group(2)) if realm_m else None
    mcc = int(realm_m.group(3)) if realm_m else None

    pcscf_host = ""
    for pm in _PCSCF_RE.finditer(sip):
        host = pm.group(1)
        if not host.startswith(b"ims.mnc"):
            pcscf_host = host.decode("ascii")
            break

    return Diag0x156E(
        log_time=log_time,
        version=data[0],
        direction="mo" if data[1] == 0x01 else "mt",
        hdr_msg_len=hdr_msg_len,
        hdr_msg_class=hdr_msg_class,
        method_family=method_family,
        hdr_status=hdr_status,
        presip_prefix_len=presip_prefix_len,
        hdr_presip_len=hdr_presip_len,
        presip_len_ok=presip_len_ok,
        is_request=is_request,
        method=method,
        status_code=status_code,
        cseq_method=cseq_method,
        header_names=header_names,
        num_headers=len(header_names),
        has_sdp=has_sdp,
        ims_realm=ims_realm,
        mcc=mcc,
        mnc=mnc,
        pcscf_host=pcscf_host,
        sip_len=len(sip),
        # Faithful decode: emit the full SIP message + the pre-SIP
        # contact-id prefix. The tool never withholds decoded content.
        sip_message=sip.decode("ascii", "replace"),
        presip_prefix=data[16:sip_off].split(b"\x00", 1)[0].decode("ascii", "replace"),
        payload_size=len(data),
    )
