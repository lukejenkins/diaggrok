# diaggrok-provenance: re
"""Shared DPL (Data Protocol Logging) record framing — 0x11EB / 0x1574 / 0x1575.

Grounded on the **populated** family member ``0x11EB``
(``LOG_DATA_PROTOCOL_LOGGING_C``): 68,596 records walked across 6 captures
spanning MDM9250, SDX55 (M2000) and SDX62 (RM520N-GL), and later confirmed
over 408,297 records / 140 captures.

Layout
------

A DPL record is an **8-byte DPL header** followed, for one specific subtype,
by a **verbatim IP packet** (no Ethernet, no framing of its own)::

    +0  u8   version          observed {0x00, 0x01} — two silicon dialects
    +1  u8   hdr_const        0x01 in 68,596/68,596 records
    +2  u8   payload_kind     subtype enum, dialect-specific (v0x01 0x01..0x42,
                              v0x00 0x1c/0x1d/0x38/0x39/0x3a/0x7b); NOT the IP
                              discriminator — use +7 (see below)
    +3  u8   direction        0x40 = TX/uplink, 0x00 = RX/downlink
    +4  u24le counter         steps like a sequence between consecutive records
    +7  u8   flags            bimodal {0x00, 0x80}. 0x80 marks an IP-bearing
                              record on BOTH dialects and for EVERY +2 kind
    +8  ..   payload          IP packet when IP-bearing (+7==0x80) and the
                              length arithmetic holds

How each field was grounded
---------------------------

``payload_kind`` (+2). Bucketing v0x01 records by ``(version, +2, +3)``
alone (without splitting on +7) and testing whether an IP packet at +8 satisfies the
**exact length arithmetic** (``len(record) == 8 + ipv4.total_length``, or
``len(record) == 8 + 40 + ipv6.payload_length``) gives:

===============  =======  ==========  =========
(ver, +2, +3)    records  IP-arith ok  hit rate
===============  =======  ==========  =========
(1, 0x41, 0x00)      451         451     100.0%
(1, 0x41, 0x40)      415         415     100.0%
(1, 0x41, 0x10)        1           1     100.0%
(1, 0x24, 0x00)        3           3     100.0%
(1, 0x01, 0x00)    29723        4083      13.7%
(1, 0x23, 0x40)    28978        4405      15.2%
(1, 0x23, 0x00)     3605         456      12.7%
===============  =======  ==========  =========

A random payload satisfies that arithmetic with probability ~1e-6 (a 1/16
version nibble times an exact u16 length match), so **both** the 100% and the
~14% are real signal, not coincidence. The ~14% buckets mix flag-set IP
records with flag-clear 264-byte records whose bytes are uniformly distributed;
splitting on ``flags (+7)`` separates them (see "The v0x01 flag marker is
cross-kind" below). On both dialects the IP-bearing marker is
``flags (+7) == 0x80``, and the length arithmetic is the final self-checking
gate: everything it rejects is surfaced raw.

``direction`` (+3) — grounded on three mutually independent signals, with
**zero exceptions across 866 records** of the ``0x41`` subtype:

===========  ====  =====================  ==========  ===========
+3           n     addresses              TTL         ICMP type
===========  ====  =====================  ==========  ===========
0x40 (TX)    415   UE PDP -> peer         255         0x08 (echo request)
0x00 (RX)    451   peer -> UE PDP         108..111    0x00 (echo reply)
===========  ====  =====================  ==========  ===========

The source/destination addresses are exactly reversed between the buckets;
TTL 255 means locally originated while 108..111 means internet-decremented;
and the ICMP type flips echo-request/echo-reply in step. That is a ping
session recorded in both directions, and byte +3 tracks it perfectly.

The v0x00 dialect (MDM9x30 / MDM9x50 Sierra)
--------------------------------------------

The table above is **entirely v0x01** (SDX6x / MDM9x15). A separate silicon
family (MC7455 MDM9x30, EM7565
MDM9x50) emits the **same 8-byte framing** but a **different +2 payload_kind
enum**, so a ``+2 == 0x41`` gate decodes **zero** of its records. The
IP packets are nonetheless present — QCSuper and SCAT each emit ~one IP frame
per record (54 / 58 frames from 53 records on an MC7455 GNSS capture),
independently confirming *one DPL record == one IP datagram* (they wrap the
payload in a placeholder-addressed frame — 127.0.0.1 / 0.0.0.0 — and do **not**
recover the real inner header, which this decoder does).

On v0x00 the IP-bearing discriminator is the **flags byte +7 == 0x80**, not
+2. Bucketing a 60k-record EM7565 sample::

    +2     records   complete_ip  truncated_ip  non_ip   +7==0x80
    0x1c     3559        3559            0           0     3559  (always complete)
    0x38    56441        3654        10559       42228    14211  (== complete+trunc)

``+7 == 0x80`` partitions the IP-bearing records (14,213 = complete+truncated)
from the opaque bucket (42,228) almost exactly, across *both* +2 values, so it
is the reliable cross-``+2`` marker. The length arithmetic in ``_decode_ip``
then decodes the complete packets and rejects the truncated ones (a snap-length
cut of a larger packet, ``record < 8 + total_length``) to raw. Direction (+3)
transfers from v0x01 and is corroborated on MC7455 by an exact-reversal TCP
handshake — TX (0x40) ``UE -> peer`` TTL 255, RX (0x00) ``peer -> UE`` TTL 240,
source/destination reversed — the same three-signal agreement as the v0x01
ICMP ping, here on TCP SYN / SYN-ACK.

``F3-VERDICT v0x00: GROUND`` — length-arithmetic self-check (~1e-6 false-positive
per record) on 7,213 complete v0x00 IP packets in the 60k sample, a coherent
real TCP flow whose fields (proto, length, TTL, address reversal) are mutually
consistent, and structural corroboration from the QCSuper/SCAT record⟺datagram
1:1. F3 plaintext is **silent** for the DPL field labels (907,717 F3 lines on
the EM7565; only a ``ds_3gpp_pdn_context.c`` "Setting up Type PDP-IP stack …
mtu_size 1500" context line), as expected for a pure data-plane dump.

The v0x01 flag marker is cross-kind
-----------------------------------
Every non-0x41 bucket in the first table mixes flag-set IP records with
flag-clear 264-byte snap cuts — which is where the "~14%" comes from.
Bucketing by ``(ver, +2, +7)`` over 408,297 records / 140 captures separates
them cleanly::

    v0x01 +2   +7     records   exact   trunc  non_ip   exact%
    0x02       0x80       705     699       1       5    99.2
    0x24       0x80       960     829       9     122    86.4
    0x25       0x80       992     687      47     258    69.3
    0x01       0x80     11418    7185     487    3746    62.9
    0x23       0x80     20213    6109     538   10660    30.2
    0x41       0x80      2311    2300       1      10    99.5
    (any)      0x00    ~77,800       0     ...     ...     0.0  (all 264 B)

A second, **independent** self-check closes it: every IPv4 exact-length record
in every flag-set group also passes the IPv4 **header checksum** (0x01
3,003/3,003; 0x02 616/616; 0x23 431/431; 0x25 51/51; 0x41 2,298/2,298 — on
104 of the captures), a further 1/65,536 per record by chance. Flag-clear
0x41 (32 records) decodes nothing, so ``+7 == 0x80`` is the cross-dialect,
cross-kind IP marker and the only gate; ``+2 == 0x41`` is subsumed by it.
The non-exact flag-set remainder (truncated / continuation / ``longer``
bodies) is still rejected to raw by the length gate. Lower exact shares on
some kinds (0x23 30%) are that remainder, not a different encoding.

Relationship to 0x1574 / 0x1575
-------------------------------

``0x1574`` (``LOG_NETWORK_IP_RM_TX_FULL``) and ``0x1575``
(``LOG_NETWORK_IP_RM_RX_FULL``) express as **two separate log codes** exactly
the TX/RX split that ``0x11EB`` carries **internally** in byte +3. They are at
0 records across 2,071 scanned captures, so their framing
cannot be observed directly; they are registered against this same decoder on
the structural-family argument, with ``direction`` taken from the log code
rather than byte +3. See the module docstrings of ``diag_0x1574`` /
``diag_0x1575`` for the version-bound absence verdict.

PII
---

DPL user-plane records carry the subscriber's own IP addresses in the clear.
Decoding them **in full is a goal** (the parser is tagged
``ascii_kinds=("identifier",)`` via its callers). The contract is about
*captured values*, not capability: the checked-in fixtures have their two
IPv4 addresses rewritten to RFC 5737 documentation addresses
(``192.0.2.1`` / ``198.51.100.1``) with the now-stale IP header checksum
zeroed; every other byte is the untouched on-wire record.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Any

#: DPL header length in bytes — the IP packet, when present, starts here.
DPL_HEADER_LEN = 8

#: Byte-0 version values observed at payload size > 4 across the corpus.
DPL_VERSIONS_OBSERVED = (0x00, 0x01)

#: Byte +2 value that marks a v0x01 "full IP packet" subtype (866/866 exact).
#: Not used as a gate — FLAG_IP_BEARING subsumes it: every
#: flag-set 0x41 record also carries +7==0x80, and flag-clear 0x41 is 0/32
#: exact. Kept as a named subtype value.
PAYLOAD_KIND_IP_FULL = 0x41

#: Byte +7 (flags) value that marks an **IP-bearing** record on the **v0x00**
#: dialect (MDM9x30 / MDM9x50 Sierra), where the +2 payload_kind enum differs
#: (observed 0x1c always-complete, 0x38 truncation-prone). On a
#: 60k-record EM7565 sample, +7==0x80 partitions IP-bearing (14,213) from opaque
#: (42,228) records almost exactly; the length arithmetic in ``_decode_ip`` is
#: still the self-checking gate that decodes complete packets and rejects the
#: truncated/opaque remainder to raw. On **v0x01** it is the IP marker for
#: every payload_kind, not only 0x41: kinds 0x01/0x02/0x23/0x24/0x25/…
#: with +7==0x80 carry complete IP packets that pass both the length arithmetic
#: and the IPv4 header checksum. A cross-dialect, cross-kind IP-bearing flag.
FLAG_IP_BEARING = 0x80

#: Byte +3 direction encoding, grounded on address/TTL/ICMP-type agreement.
DIRECTION_TX = 0x40  # uplink   — UE-originated
DIRECTION_RX = 0x00  # downlink — UE-terminated

_DIRECTION_NAMES = {DIRECTION_TX: "tx", DIRECTION_RX: "rx"}


@dataclass
class DplRecord:
    """One DPL record: the 8-byte header plus, when present, an IP packet."""

    log_time: int
    version: int
    hdr_const: int
    payload_kind: int
    direction_raw: int
    direction: str | None
    counter: int
    flags: int
    payload_size: int
    # Populated only when the record is IP-bearing (flags == FLAG_IP_BEARING)
    # *and* the length arithmetic validates. None otherwise — an un-decoded body is
    # surfaced raw rather than guessed at.
    ip_version: int | None
    ip_src: str | None
    ip_dst: str | None
    ip_proto: int | None
    ip_ttl: int | None
    ip_payload_len: int | None
    body_raw: bytes

    def to_dict(self, type_name: str) -> dict[str, Any]:
        return {
            "type": type_name,
            "log_time": self.log_time,
            "version": self.version,
            "hdr_const": self.hdr_const,
            "payload_kind": self.payload_kind,
            "direction_raw": self.direction_raw,
            "direction": self.direction,
            "counter": self.counter,
            "flags": self.flags,
            "payload_size": self.payload_size,
            "ip_version": self.ip_version,
            "ip_src": self.ip_src,
            "ip_dst": self.ip_dst,
            "ip_proto": self.ip_proto,
            "ip_ttl": self.ip_ttl,
            "ip_payload_len": self.ip_payload_len,
            "body_raw": self.body_raw,
        }


def _decode_ip(body: bytes, record_len: int) -> dict[str, Any] | None:
    """Decode ``body`` as an IP packet, but only if it *proves* itself.

    The gate is the length arithmetic: an IPv4 header's ``total_length`` or an
    IPv6 header's ``payload_length`` must account for the record exactly. That
    is a self-checking test — it is what separates a real user-plane packet
    from a ciphertext body whose first nibble happens to read 4 or 6 — so a
    body that fails it yields ``None`` and is surfaced raw instead.
    """
    if len(body) < 20:
        return None
    ver = body[0] >> 4
    if ver == 4:
        ihl = body[0] & 0x0F
        if ihl < 5 or len(body) < ihl * 4:
            return None
        total_len = int.from_bytes(body[2:4], "big")
        if record_len != DPL_HEADER_LEN + total_len:
            return None
        return {
            "ip_version": 4,
            "ip_src": str(IPv4Address(body[12:16])),
            "ip_dst": str(IPv4Address(body[16:20])),
            "ip_proto": body[9],
            "ip_ttl": body[8],
            "ip_payload_len": total_len - ihl * 4,
        }
    if ver == 6:
        if len(body) < 40:
            return None
        payload_len = int.from_bytes(body[4:6], "big")
        if record_len != DPL_HEADER_LEN + 40 + payload_len:
            return None
        return {
            "ip_version": 6,
            "ip_src": str(IPv6Address(body[8:24])),
            "ip_dst": str(IPv6Address(body[24:40])),
            "ip_proto": body[6],  # next header
            "ip_ttl": body[7],  # hop limit
            "ip_payload_len": payload_len,
        }
    return None


def parse_dpl(
    log_time: int,
    data: bytes,
    *,
    forced_direction: str | None = None,
) -> DplRecord | None:
    """Parse a DPL record shared by 0x11EB / 0x1574 / 0x1575.

    ``forced_direction`` is for the per-direction codes 0x1574 / 0x1575, whose
    direction is implied by the log code itself; 0x11EB leaves it ``None`` and
    takes the direction from byte +3.
    """
    if len(data) < DPL_HEADER_LEN:
        return None
    version = data[0]
    if version not in DPL_VERSIONS_OBSERVED:
        return None

    payload_kind = data[2]
    direction_raw = data[3]
    body = data[DPL_HEADER_LEN:]

    if forced_direction is not None:
        direction = forced_direction
    else:
        direction = _DIRECTION_NAMES.get(direction_raw)

    ip: dict[str, Any] = {}
    # IP-bearing marker: flags (+7) == 0x80, on BOTH dialects. Grounded on
    # v0x00 (where the +2 enum 0x1c/0x38 differs) and on v0x01 (every
    # (kind, +7==0x80) group carries IP, and every IPv4 exact-length hit also
    # passes the header checksum; every flag-clear group is 0% exact). A
    # ``payload_kind == 0x41`` gate is subsumed: flag-clear 0x41 is 0/32 exact,
    # so it adds no decodes. The
    # length arithmetic in _decode_ip remains the self-checking gate, so a
    # flag-set-but-truncated or continuation body falls through to raw.
    carries_ip = data[7] == FLAG_IP_BEARING
    if carries_ip:
        ip = _decode_ip(body, len(data)) or {}

    return DplRecord(
        log_time=log_time,
        version=version,
        hdr_const=data[1],
        payload_kind=payload_kind,
        direction_raw=direction_raw,
        direction=direction,
        counter=int.from_bytes(data[4:7], "little"),
        flags=data[7],
        payload_size=len(data),
        ip_version=ip.get("ip_version"),
        ip_src=ip.get("ip_src"),
        ip_dst=ip.get("ip_dst"),
        ip_proto=ip.get("ip_proto"),
        ip_ttl=ip.get("ip_ttl"),
        ip_payload_len=ip.get("ip_payload_len"),
        body_raw=body,
    )
