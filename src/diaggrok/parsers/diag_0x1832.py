"""0x1832 — LOG_IMS_REGISTRATION: IMS registration identity (ASCII, PII).

Observed on registered RM520N-GL SDX62 T-Mobile captures. A compact (147–149 B) record, byte[0] = 0x01,
carrying the device's **IMS registration identity** as ASCII:

    [0]    u8    version (0x01)              — Layer-1 gate
    [1]    u8    subtype (0x00 or 0x02 observed)
    [2]    u8    len, then len B C-str (NUL-terminated, len counts the NUL):
                  Contact ``<tag>_<tag>@<IPv6>`` (device IMS contact address)
    [..]   u8    len + C-str: P-CSCF / registrar host ``sip:msg.pc.t-mobile.com``
    [..]   u8    len + C-str: registered IMS public identity
                  ``<sip:<IMSI>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org>``
    [..]   u16   trailer (undecoded; 0x00C8 / 0x0191 observed)

The parser walks the three length-prefixed strings: a record whose declared
string lengths (or the 2 B trailer) overrun the payload returns None (registry
WARN). Note that the contact's length byte can look like a ``=`` / ``>``
content character; it is a length, not part of the string.

An older name table lists 0x1832 as
``LOG_EVENTS_DS_GSM_RATSCCH_CMI_PHASE_CHANGE``, but the observed payload is
unambiguously IMS registration data, so the alias ``LOG_IMS_REGISTRATION`` is
the operative name.

This parser **decodes the record faithfully**: it emits the registered IMS
public identity (``ims_identity``) and the device contact address
(``contact_address``) alongside the P-CSCF host, the IMS realm
(``ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org``) + its MCC/MNC, and the identity
local-part length. The record embeds the subscriber IMS public identity
(IMSI-derived SIP URI) and the device IMS contact (IPv6) — decoding them is the
whole point, so a user can read their own identifiers. This
library never withholds or flags anything. The ``ascii_kinds`` values just
classify the ASCII content this record carries.

Sibling IMS/SIP codes: 0x156E (LOG_IMS_SIP_MESSAGE), 0x1C9C (IMS
messaging-identity), 0x11EB (LOG_DATA_PROTOCOL_LOGGING, SIP-bearing).

Conservative first-observation recognition parser. 16 records observed,
RM520N-GL SDX62 only; other chipsets are not yet sampled.

Log name: LOG_EVENTS_DS_GSM_RATSCCH_CMI_PHASE_CHANGE
Also known as: LOG_IMS_REGISTRATION
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register

_EXPECTED_VERSION = 0x01
# byte[1]: 0x00 and 0x02 both attested with the identical string layout.
_KNOWN_SUBTYPES = (0x00, 0x02)
_N_STRINGS = 3      # contact, P-CSCF host, IMS public identity
_TRAILER_LEN = 2    # u16 after the last string

# Registered IMS public identity: sip:<IMSI>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org
_IMS_IDENTITY_RE = re.compile(
    rb"sip:([0-9A-Za-z]+)@(ims\.mnc(\d{2,3})\.mcc(\d{3})\.3gppnetwork\.org)"
)
# P-CSCF / registrar host: a sip: URI with a dotted host and no '@'.
_PCSCF_RE = re.compile(rb"sip:([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})(?:[\x00>;]|$)")


@dataclass
class Diag0x1832:
    """0x1832 LOG_IMS_REGISTRATION — faithful decode incl. IMS identity/contact."""
    log_time: int
    version: int
    subtype: int
    pcscf_host: str            # P-CSCF / registrar host — config-token
    ims_realm: str             # ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org — network id
    mcc: int | None            # decoded from the IMS realm — non-PII
    mnc: int | None            # decoded from the IMS realm — non-PII
    contact_is_ipv6: bool      # whether the Contact address is IPv6
    identity_localpart_len: int  # length of the IMS identity local-part (IMSI len) — structural
    ims_identity: str          # registered IMS public identity (IMSI-derived SIP URI) — faithful decode
    contact_address: str       # device IMS contact address (IPv6) — faithful decode
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1832",
            "log_time": self.log_time,
            "version": self.version,
            "subtype": self.subtype,
            "pcscf_host": self.pcscf_host,
            "ims_realm": self.ims_realm,
            "mcc": self.mcc,
            "mnc": self.mnc,
            "contact_is_ipv6": self.contact_is_ipv6,
            "identity_localpart_len": self.identity_localpart_len,
            "ims_identity": self.ims_identity,
            "contact_address": self.contact_address,
            "payload_size": self.payload_size,
        }


# Ground-truth recipe — not yet run on hardware (hw_run_performed=False), target RM520N-GL.

# WiGLE: N/A — IMS registration — mcc/mnc are the subscriber home-PLMN (PII), not an observation. Reviewed, contributes nothing to a WiGLE
# observation.
@register(
    0x1832,
    name="0x1832",
    description="LOG_IMS_REGISTRATION — IMS registration identity (ASCII, PII) — RM520N-GL",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE from two registered T-Mobile captures (Quectel "
        "RM520N-GL SDX62, 16 records). Layout: version (0x01), subtype "
        "(0x00 / 0x02, identical layout), three u8-length-prefixed C-strings "
        "(contact, P-CSCF, IMS identity) + u16 trailer (undecoded). A record "
        "whose declared lengths overrun the payload returns None. Decodes "
        "faithfully: `ims_identity` (the full registered IMS public identity "
        "SIP URI) and `contact_address` (the device IMS contact) are emitted "
        "alongside the P-CSCF host and the realm's MCC/MNC."
    ),
    source_url="",
    issues=(),
    field_invariants={
        "version": {"enum": [_EXPECTED_VERSION]},
    },
    # ASCII: classifies the content this record carries — P-CSCF host
    # (config-token) + IMSI-derived IMS public identity (identifier).
    # Content classification only; the decoder emits the identity faithfully.
    ascii_kinds=("config-token", "identifier"),
    fields_identified=8,
    fields_parsed=8,
    # WiGLE decided-none: reviewed and found not WiGLE-relevant. The mcc/mnc
    # are the subscriber home-PLMN (PII), not an observation. (False, ())
    # records that decision explicitly.
    wigle_direct=False,
    wigle_roles=(),
)
def parse_0x1832(log_time: int, data: bytes) -> Diag0x1832 | None:
    # Layer-1 version gate (version byte first).
    if len(data) < 3:
        return None
    if data[0] != _EXPECTED_VERSION or data[1] not in _KNOWN_SUBTYPES:
        return None

    # Three u8-length-prefixed, NUL-terminated strings, then a u16 trailer.
    # Every declared length must fit the payload, else the record is truncated.
    strings: list[bytes] = []
    off = 2
    for _ in range(_N_STRINGS):
        if off >= len(data):
            return None
        slen = data[off]
        end = off + 1 + slen
        if slen < 1 or end > len(data) or data[end - 1] != 0:
            return None
        strings.append(data[off + 1:end - 1])
        off = end
    if off + _TRAILER_LEN > len(data):
        return None
    contact, pcscf_s, identity_s = strings

    # The registered IMS public identity is the structural signature of this
    # record. Require it (in the 3gppnetwork.org form) for recognition.
    m = _IMS_IDENTITY_RE.search(identity_s)
    if not m:
        return None
    localpart, realm, mnc_b, mcc_b = m.groups()
    identity_localpart_len = len(localpart)
    ims_realm = realm.decode("ascii")
    mnc = int(mnc_b)
    mcc = int(mcc_b)
    # Faithful decode: the full registered IMS public identity SIP URI.
    ims_identity = m.group(0).decode("ascii", "replace")

    # P-CSCF / registrar host: the second string, a sip: host without '@'.
    pcscf_host = ""
    pm = _PCSCF_RE.search(pcscf_s)
    if pm:
        host = pm.group(1)
        if b"@" not in host and not host.startswith(b"ims.mnc"):
            pcscf_host = host.decode("ascii")

    # Contact address (first string): IPv6 if the host part carries ':'.
    contact_is_ipv6 = b"@" in contact and b":" in contact.split(b"@", 1)[-1]
    # Faithful decode: the device IMS contact address itself, not just the
    # is-IPv6 boolean.
    contact_address = contact.decode("ascii", "replace")

    return Diag0x1832(
        log_time=log_time,
        version=data[0],
        subtype=data[1],
        pcscf_host=pcscf_host,
        ims_realm=ims_realm,
        mcc=mcc,
        mnc=mnc,
        contact_is_ipv6=contact_is_ipv6,
        identity_localpart_len=identity_localpart_len,
        ims_identity=ims_identity,
        contact_address=contact_address,
        payload_size=len(data),
    )
