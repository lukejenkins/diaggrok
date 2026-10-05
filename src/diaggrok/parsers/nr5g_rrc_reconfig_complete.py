# diaggrok-provenance: re
"""NR UL-DCCH RRCReconfigurationComplete decoder - from-scratch UPER (TS 38.331).

Decodes the UE's uplink acknowledgement of a gNB ``RRCReconfiguration`` — the
missing UL half of the reconfiguration exchange the 0xB821 parser already decodes
on the DL side (``nr5g_rrc_reconfig``). Its one RF-relevant scalar is the
``rrc-TransactionIdentifier`` (INTEGER 0..3), which pairs a Complete with the
RRCReconfiguration that carries the same id — the handle for reconstructing an
RRC reconfiguration round-trip from a one-sided OTA capture.

ASN.1 path (3GPP TS 38.331 v17.17.0):

    UL-DCCH-Message ::= SEQUENCE { message UL-DCCH-MessageType }   -- no preamble
    UL-DCCH-MessageType ::= CHOICE {
        c1 CHOICE {                              -- 16 alternatives -> 4 bits
            measurementReport ...,
            rrcReconfigurationComplete RRCReconfigurationComplete,   -- index 1
            ... },
        messageClassExtension CHOICE { ... }
    }
    RRCReconfigurationComplete ::= SEQUENCE {    -- NOT extensible, no OPTIONAL
        rrc-TransactionIdentifier  RRC-TransactionIdentifier,   -- INTEGER(0..3), 2 bits
        criticalExtensions CHOICE {
            rrcReconfigurationComplete  RRCReconfigurationComplete-IEs,  -- index 0
            criticalExtensionsFuture    SEQUENCE {}
        }                                                        -- 1 bit
    }
    RRCReconfigurationComplete-IEs ::= SEQUENCE { -- NOT extensible; 2 OPTIONAL -> 2-bit preamble
        lateNonCriticalExtension  OCTET STRING                          OPTIONAL,
        nonCriticalExtension      RRCReconfigurationComplete-v1530-IEs   OPTIONAL
    }

UPER bit layout (the decoder receives the full ``msg_data`` and consumes the
5-bit UL-DCCH-Message prefix itself, so offsets are absolute from byte 0):

    bit 0     : UL-DCCH-MessageType CHOICE      (0 = c1)
    bits 1-4  : c1 alternative                  (1 = rrcReconfigurationComplete)
    bits 5-6  : rrc-TransactionIdentifier       (INTEGER 0..3)
    bit 7     : criticalExtensions CHOICE        (0 = -IEs, 1 = criticalExtensionsFuture)
    bits 8-9  : RRCReconfigurationComplete-IEs OPTIONAL preamble
                [lateNonCriticalExtension, nonCriticalExtension]

Both OPTIONALs are rare/heavy container types (``nonCriticalExtension`` chains
the v1530+ IEs — scg/UAI response info, not RF-relevant); like nr5g_rrc_release's
cellReselectionPriorities, they are recorded as presence flags and their bodies
are not walked. On the ``criticalExtensionsFuture`` branch there are no IEs, so
the preamble flags are ``None`` (not applicable).

Reference: 3GPP TS 38.331 (NR RRC) 6.2.2. Validated A/B against the stock
``tshark`` ``nr-rrc.ul.dcch`` dissector on the transaction-id sweep vectors
(via an Exported-PDU wrapper).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader

# UL-DCCH-MessageType.c1 alternative index for rrcReconfigurationComplete.
_UL_DCCH_C1_RRC_RECONFIG_COMPLETE = 1


@dataclass
class NrRrcReconfigComplete:
    """Decoded NR UL-DCCH RRCReconfigurationComplete (3GPP TS 38.331 6.2.2).

    Fields:
      * ``rrc_transaction_identifier``: INTEGER(0..3) — pairs this Complete with
        the RRCReconfiguration carrying the same id. Always present.
      * ``critical_extensions_future``: ``True`` when criticalExtensions selected
        ``criticalExtensionsFuture`` (no IEs follow).
      * ``late_non_critical_extension_present`` / ``non_critical_extension_present``:
        the two RRCReconfigurationComplete-IEs OPTIONAL flags. ``None`` on the
        ``criticalExtensionsFuture`` branch (no IEs to describe).
    """

    log_time: int
    message_type: str = "rrcReconfigurationComplete"
    rrc_transaction_identifier: Optional[int] = None
    critical_extensions_future: Optional[bool] = None
    late_non_critical_extension_present: Optional[bool] = None
    non_critical_extension_present: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "NrRrcReconfigComplete",
            "log_time": self.log_time,
            "message_type": self.message_type,
        }
        for k in (
            "rrc_transaction_identifier",
            "critical_extensions_future",
            "late_non_critical_extension_present",
            "non_critical_extension_present",
        ):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


def decode_nr_rrc_reconfig_complete(
    log_time: int, msg_data: bytes
) -> Optional[NrRrcReconfigComplete]:
    """Decode a UL-DCCH RRCReconfigurationComplete from full ``msg_data``.

    Returns ``None`` if the message is empty or its leading bits do not resolve
    to a ``c1 = rrcReconfigurationComplete`` UL-DCCH message (defensive — the
    caller has already classified it, so a mismatch means a malformed / unexpected
    record).
    """
    if not msg_data:
        return None
    r = UperReader(msg_data)
    if r.read_bits(1) != 0:  # UL-DCCH-MessageType CHOICE: 0 = c1
        return None
    if r.read_bits(4) != _UL_DCCH_C1_RRC_RECONFIG_COMPLETE:  # c1 index
        return None
    return _decode_body(log_time, r)


def decode_nr_rrc_reconfig_complete_direct(
    log_time: int, msg_data: bytes
) -> Optional[NrRrcReconfigComplete]:
    """Decode a BARE RRCReconfigurationComplete (no UL-DCCH-Message wrapper).

    The 0xB821 ``RRC-RECONF-COMPLETE`` pdu_id logs the message SEQUENCE
    itself, starting at rrc-TransactionIdentifier; stock tshark decodes it with
    ``nr-rrc.rrc_reconf_compl``. The common corpus payload is the single byte
    ``00`` (transaction id 0, no OPTIONAL IEs).
    """
    if not msg_data:
        return None
    return _decode_body(log_time, UperReader(msg_data))


def _decode_body(log_time: int, r: UperReader) -> NrRrcReconfigComplete:
    """RRCReconfigurationComplete ::= SEQUENCE { rrc-TransactionIdentifier,
    criticalExtensions CHOICE { rrcReconfigurationComplete, ...Future } }."""
    rec = NrRrcReconfigComplete(log_time=log_time)
    rec.rrc_transaction_identifier = r.read_bits(2)
    if r.read_bits(1) != 0:  # criticalExtensions: 1 = criticalExtensionsFuture
        rec.critical_extensions_future = True
        return rec  # future branch: no IEs
    rec.critical_extensions_future = False
    # RRCReconfigurationComplete-IEs 2-bit OPTIONAL preamble, field order:
    #   [lateNonCriticalExtension, nonCriticalExtension]
    preamble = r.read_bits(2)
    rec.late_non_critical_extension_present = bool((preamble >> 1) & 1)
    rec.non_critical_extension_present = bool(preamble & 1)
    return rec
