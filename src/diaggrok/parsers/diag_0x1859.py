"""0x1859 — LOG_DS_FIRST_REORIG_IP_PACKET_HEADER: first IP packet of a data re-origination.

**This is NOT a GNSS / XTRA event** (F3 + payload census over every
F3-bearing capture). The code is not MC7455-exclusive either — it is
attested on RM520N-GL, RM500Q, EM9291, EG25-G and others (22 captures). Bytes
[4:] carry the leading bytes of the IP packet that re-originated the data call
(the alias ``LOG_DS_FIRST_REORIG_IP_PACKET_HEADER``), so the content is
whatever that packet was:

  * a **DNS query** — the original MC7455 record is one: ``41 00`` (DNS ID)
    ``01 00`` (flags, RD) ``00 01`` (QDCOUNT=1) + 6 zero bytes, then the QNAME
    ``09 xtrapath1 09 izatcloud 03 net 00`` and ``00 01 00 01`` (QTYPE A, QCLASS
    IN). The modem is resolving the XTRA host, which can make the record look
    like an "XTRA server" record. Other attested QNAMEs: the SUPL SLP
    ``h-slp.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org`` and ``time.xtracloud.net``.
  * a **SIP request** (``MESSAGE sip:…`` from the IMS stack, RM520N-GL VoNR);
  * a constant ``a``-fill payload (qping / throughput test traffic).

F3: co-temporal prints are data-services / socket / RRC-security re-origination
prints (``ds_*``, ``ps_route``, ``lte_security.c "Key Generation successful"``),
not GNSS.

The decoder below decodes only the **DNS-query** form (its field names
predate the DNS reading: ``record_marker`` =
DNS ID low byte, ``flag_8``/``reserved_12`` = QDCOUNT/AN/NS/AR counts,
``host_parts`` = QNAME labels, ``magic_post``/``entry_count`` = QTYPE/QCLASS).
A non-DNS payload decodes with empty ``host_parts``; a record whose byte [2]
is 0xFF (attested) fails the u32 version gate and is dropped. The
packet-payload form in general is not yet decoded.

The u32LE at [0:4] is gated first: it must equal 1, so a different layout
in the same 104-byte envelope is rejected rather than decoded plausibly
with these offsets (layer-2 ``field_invariants={"version": {"enum": [1]}}``
backs it up). Every DNS-form record in the corpus carries 1.

DNS-query form (104 B fixed; field names in parentheses are the DNS reading):

    [0:4]    u32LE  version (observed: 1)
    [4]      u8     record_marker (observed: 0x41; DNS ID low byte)
    [5:8]   3B      magic_pre `00 01 00` (DNS ID high byte + flags)
    [8:12]  u32LE   flag_8 (observed: 256 = 0x00000100; QDCOUNT=1 + ANCOUNT)
    [12:16] u32LE   reserved_12 (always 0; NSCOUNT/ARCOUNT)
    [16]    u8      host_part_1_len (= 9)
    [17..25]       "xtrapath1"
    [26]    u8      host_part_2_len (= 9)
    [27..35]       "izatcloud"
    [36]    u8      host_part_3_len (= 3)
    [37..39]       "net"
    [40]    u8      host_terminator (= 0)
    [41..43] 3B     magic_post `00 01 00` (QTYPE A + QCLASS high byte)
    [44:48] u32LE   entry_count (observed: 1; QCLASS low byte)
    [48..104]       zero padding (56 B)

Log name: LOG_EVENTS_DS_GSM_MESSAGE_RECEIVED
Also known as: LOG_DS_FIRST_REORIG_IP_PACKET_HEADER
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0x1859:
    """First re-originated IP packet (0x1859), DNS-query form.

    Every one of the 104 bytes in the payload is named. ``magic_pre`` /
    ``magic_post`` carry the 3-byte `00 01 00` constant that brackets
    the flag block. ``trailer_zero_bytes`` counts the zero padding so
    a test can assert the full 48..104 reserved region is untouched.
    """
    log_time: int
    version: int
    record_marker: int
    magic_pre: bytes           # [5:8] — always b'\\x00\\x01\\x00'
    flag_8: int                # [8:12] u32LE
    reserved_12: int           # [12:16] u32LE (always 0)
    host_parts: list[str]
    host_terminator: int       # post-hostname NUL byte
    magic_post: bytes          # 3-B constant repeating magic_pre
    entry_count: int           # u32LE — "follow-up entry count" (1 observed)
    trailer_zero_bytes: int    # count of zero bytes in the 56-B trailer
    xtra_host: str             # joined host_parts
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1859',
            'log_time': self.log_time,
            'version': self.version,
            'record_marker': self.record_marker,
            'magic_pre': self.magic_pre.hex(),
            'flag_8': self.flag_8,
            'reserved_12': self.reserved_12,
            'host_parts': list(self.host_parts),
            'host_terminator': self.host_terminator,
            'magic_post': self.magic_post.hex(),
            'entry_count': self.entry_count,
            'trailer_zero_bytes': self.trailer_zero_bytes,
            'xtra_host': self.xtra_host,
            'payload_size': self.payload_size,
        }


def _decode_pascal_strings(data: bytes, start: int, max_parts: int = 8) -> list[str]:
    """Read length-prefixed ASCII strings until we hit a zero-length or run out."""
    parts: list[str] = []
    off = start
    while off < len(data) and len(parts) < max_parts:
        n = data[off]
        if n == 0 or off + 1 + n > len(data):
            break
        segment = data[off + 1:off + 1 + n]
        try:
            decoded = segment.decode('ascii')
        except UnicodeDecodeError:
            break
        if not all(32 <= c < 127 for c in segment):
            break
        parts.append(decoded)
        off += 1 + n
    return parts


# Byte 0 / u32LE version-field constant. Observed value on every DNS-form
# record is 1, encoded as the u32LE at [0:4]; the high three bytes are zero
# in every observed record.
_GNSS_1859_EXPECTED_VERSION = 0x01
# Fixed record size (docstring layout): header 16 B + host parts + 8 B trailer
# + zero padding to 104 B. A shorter record is truncated.
_FIXED_LEN = 104
_TRAILER_LEN = 8   # host terminator + magic_post (3) + entry_count (u32)


@register(
    0x1859, domain=None,
    name="0x1859",
    description="LOG_DS_FIRST_REORIG_IP_PACKET_HEADER (0x1859) — first re-originated IP packet; DNS-query form decoded",
    version=4,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "NOT a GNSS XTRA event: [4:] is the leading payload of the IP packet that re-originated the "
        "data call (DNS query / SIP / test traffic), attested on 22 captures "
        "across RM520N-GL/RM500Q/EM9291/EG25-G/MC7455; F3 co-temporal prints are "
        "data-services/RRC-security, not GNSS. Decodes the DNS-query form "
        "(clean-room RE from an MC7455 capture; QNAME as length-prefixed "
        "labels). The u32LE version field at [0:4] is the first-access gate "
        "(enum [1]). A record shorter than the fixed 104 B layout, or whose "
        "host parts leave no room for the 8 B terminator/magic/entry_count "
        "trailer, returns None. Non-DNS payload forms are not yet decoded."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    field_invariants={
        "version": {"enum": [_GNSS_1859_EXPECTED_VERSION]},
    },
    # ASCII: this code carries ASCII in two distinct forms. (a) The DNS-query
    # form this parser decodes embeds the XTRA assistance server hostname (`xtrapath1.izatcloud.net`,
    # `time.xtracloud.net`) — a config-token. (b) A SIP payload, observed on
    # a registered T-Mobile capture as a full SIP REGISTER message whose `From:`
    # header carries the subscriber IMS identity (IMSI-derived SIP URI) =>
    # identifier (PII). That form's first 4 bytes are SIP ASCII (`REGI`),
    # so the version gate above rejects it (it returns None, not a
    # mis-parse) — the ascii_kinds tag stands on the observed ASCII content,
    # independent of which form the parser currently decodes.
    ascii_kinds=("config-token", "identifier"),
)
def parse_0x1859(log_time: int, data: bytes) -> Diag0x1859 | None:
    if len(data) < 4:
        return None
    # Version gate is the FIRST data access. The full
    # u32LE field at [0:4] must equal 1 across the entire observed corpus;
    # any deviation (low byte or high-byte drift) is rejected outright so
    # firmware-format drift surfaces as a no-parser miss rather than a
    # plausible-looking but wrong decomposition.
    version = unpack_from('<I', data, 0)[0]
    if version != _GNSS_1859_EXPECTED_VERSION:
        return None
    # The layout is a fixed 104 B; a shorter record is truncated.
    if len(data) < _FIXED_LEN:
        return None
    parts = _decode_pascal_strings(data, 16)
    # Walk the host_parts to find where the trailer begins. Each part
    # costs (1 + len) bytes. If no parts parsed, skip directly.
    trailer_off = 16 + sum(1 + len(part) for part in parts)
    if trailer_off + _TRAILER_LEN > len(data):
        return None  # host parts overrun the trailer
    host_terminator = data[trailer_off] if trailer_off < len(data) else 0
    magic_post_off = trailer_off + 1
    magic_post = bytes(data[magic_post_off:magic_post_off + 3]) if magic_post_off + 3 <= len(data) else b''
    entry_count_off = magic_post_off + 3
    entry_count = 0
    if entry_count_off + 4 <= len(data):
        entry_count = unpack_from('<I', data, entry_count_off)[0]
    # Count zero bytes in the 56-byte tail (trailer structure is fixed 8 B
    # [terminator + magic_post + entry_count], so the zero-padding region
    # begins 8 B after trailer_off).
    zero_region_off = trailer_off + 8
    trailer_zero_bytes = sum(1 for b in data[zero_region_off:] if b == 0)
    return Diag0x1859(
        log_time=log_time,
        version=version,
        record_marker=data[4],
        magic_pre=bytes(data[5:8]),
        flag_8=unpack_from('<I', data, 8)[0],
        reserved_12=unpack_from('<I', data, 12)[0] if len(data) >= 16 else 0,
        host_parts=parts,
        host_terminator=host_terminator,
        magic_post=magic_post,
        entry_count=entry_count,
        trailer_zero_bytes=trailer_zero_bytes,
        xtra_host='.'.join(parts) if parts else '',
        payload_size=len(data),
    )
