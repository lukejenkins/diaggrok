"""0x11EB — DPL user-plane record: 8-byte DPL header + verbatim IP packet.

Registered under the ID-only naming convention (registry name "0x11EB",
class `Diag0x11EB`, type string `Diag0x11EB`).

The body is not opaque: a DPL record is an **8-byte DPL header followed by a
verbatim IP packet** (no Ethernet, no inner framing). Layout, field grounding,
and the full bucket/direction evidence tables live in ``_dpl_helpers`` —
summarised here:

* byte +7 ``flags`` — ``0x80`` marks an IP-bearing record on BOTH dialects
  and for EVERY ``+2`` payload_kind. Bucketing 408,297 records / 140 captures
  by ``(ver, +2, +7)``: every flag-set group carries IP (0x02 99%, 0x25 69%,
  0x01 63% exact-length), every flag-clear group is 0% exact, and every IPv4
  exact-length hit also passes the IPv4 header checksum. The **exact** length
  arithmetic (``len == 8 + ipv4.total_length`` /
  ``8 + 40 + ipv6.payload_length``), which a random body satisfies with
  probability ~1e-6, is the final gate; everything it rejects (truncated or
  continuation bodies) is surfaced **raw** rather than guessed at.
* byte +2 ``payload_kind`` — a dialect-specific subtype enum. On v0x01
  (SDX6x/MDM9x15) ``0x41`` is a "rest of record is one full IP packet" kind
  (866/866 exact). On v0x00 (MC7455 MDM9x30 / EM7565 MDM9x50 Sierra) the enum
  differs (0x1c/0x38): in a 60k-record EM7565 sample, +7==0x80 partitions
  14,213 IP-bearing from 42,228 opaque records almost exactly, and the length
  arithmetic decodes the 7,213 complete packets.
* byte +3 ``direction`` — ``0x40`` = TX/uplink, ``0x00`` = RX/downlink, with
  **zero exceptions across 866 records**, corroborated by three mutually
  independent signals at once: source/destination addresses exactly reversed
  between the buckets, TTL 255 (locally originated) vs 108..111
  (internet-decremented), and ICMP type flipping echo-request/echo-reply in
  step. On v0x00 a real TCP flow on an MC7455 agrees the same way (TX SYN TTL
  255, RX SYN-ACK TTL 240, addresses reversed).

QCSuper and SCAT each emit ~1 IP frame per record (54/58 from 53 records),
corroborating *one DPL record == one IP datagram*, though they placeholder the
addresses (127.0.0.1 / 0.0.0.0) and do **not** recover the inner header this
decoder does.

0x11EB carries internally, in byte +3, exactly the TX/RX split that 0x1574 /
0x1575 express as two separate log codes. The observed fleet
emits the unified DPL form and never the per-direction form (0 records across
2,071 scanned captures).

``counter`` is the u24 at +4. A ``u32`` read at +4 would straddle the counter
and the +7 flag byte, so there is no ``config_word`` field.

ASCII content: the canonical ``LOG_DATA_PROTOCOL_LOGGING_C`` name fits the
observation — this code logs protocol-services data payloads, and on a
registered RM520N-GL it surfaced **SIP signaling text**:
``REGISTER sip:<registrar host> SIP/2.0``, ``Content-Length: 0``, and
``To: <sip:<IMSI>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org>`` — i.e. the SIP
request-URI / host (config-token) plus the IMSI-derived IMS public identity
(identifier). Tagged ``ascii_kinds=("config-token", "identifier")``. The SIP
text includes the subscriber IMS identity in the clear, which the decoder
emits faithfully like any other content. See also the related
SIP/IMS-identity codes 0x156E / 0x1832 / 0x1C9C.

PII: DPL user-plane records carry the subscriber's own IP addresses in the
clear and the decoder emits them in full, by design. Checked-in fixtures have
their IPv4 addresses rewritten to RFC 5737 documentation addresses.

F3-VERDICT 0x11EB v0x00: GROUND — length self-check, a coherent real TCP
flow, and the QCSuper/SCAT record<=>datagram correspondence; F3 plaintext is
silent for the DPL field labels (data-plane dump).

F3-VERDICT 0x11EB v0x01: INCONCLUSIVE. Across 38 F3-bearing captures, DPL /
ICMP-family prints sit beside the records on 31, and an 8-capture value scan
(6.36 M co-temporal prints) finds only IPA data-path timing locks; no print
carries a record's IP or DPL header values.

Log name: LOG_DATA_PROTOCOL_LOGGING_C
Also known as: LOG_PROTOCOL_SERVICES_DATA
"""
from __future__ import annotations

from typing import Any

from diaggrok.parsers._dpl_helpers import (
    DPL_VERSIONS_OBSERVED,
    DplRecord,
    parse_dpl,
)
from diaggrok.registry import register

# Kept as a module-level alias so existing importers keep working.
_11EB_VERSIONS_OBSERVED = DPL_VERSIONS_OBSERVED


class Diag0x11EB(DplRecord):
    """0x11EB — DPL record: 8-byte DPL header + verbatim IP packet."""

    def to_dict(self) -> dict[str, Any]:  # type: ignore[override]
        return super().to_dict("Diag0x11EB")


@register(
    0x11EB,
    name="0x11EB",
    description=(
        "0x11EB — DPL (Data Protocol Logging) user-plane record: 8-byte DPL "
        "header + verbatim IP packet; byte +3 carries the TX/RX direction "
        "that 0x1574/0x1575 split into separate codes"
    ),
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room decode over 408,297 records / 140 captures. 8-byte DPL "
        "header + verbatim IP packet. IP-bearing records are marked by flags "
        "(+7) == 0x80 on both dialects (v0x01 SDX6x/MDM9x15; v0x00 MC7455 "
        "MDM9x30 / EM7565 MDM9x50, whose +2 payload_kind enum differs) and "
        "for every payload_kind: flag-set kinds 0x02 99%, 0x25 69%, 0x01 63% "
        "exact-length, flag-clear 0%; every IPv4 exact hit passes the header "
        "checksum. The exact length arithmetic (~1e-6 chance rate) is the "
        "final gate; non-matching bodies stay raw. QCSuper/SCAT emit ~1 IP "
        "frame per record, corroborating record<=>datagram. direction (+3) "
        "0x40=TX / 0x00=RX grounded on reversed src/dst addresses, TTL 255 vs "
        "decremented, and ICMP echo-request/echo-reply agreement — 0 "
        "exceptions in 866 records. F3 does not label the DPL fields."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # DPL user-plane bodies carry subscriber IP addresses, and the observed
    # SIP/IMS text (REGISTER sip:..., IMSI-derived IMS
    # public identity) still stands for the non-IP payload kinds.
    ascii_kinds=("config-token", "identifier"),
    fields_identified=6,
    fields_parsed=6,
    field_invariants={
        "version": {"enum": list(DPL_VERSIONS_OBSERVED)},
    },
)
def parse_0x11eb(log_time: int, data: bytes) -> Diag0x11EB | None:
    rec = parse_dpl(log_time, data)
    if rec is None:
        return None
    return Diag0x11EB(**vars(rec))
