# diaggrok-provenance: re
"""NR DL-CCCH message decoder - from-scratch UPER (3GPP TS 38.331 6.2.2).

Decodes the two real alternatives of a ``DL-CCCH-Message`` (``rrcReject`` and
``rrcSetup``): the messages a gNB sends on the Downlink Common Control Channel
during NR RRC connection establishment (before an SRB1/DCCH exists). DL-CCCH
is a tiny channel: after the MIB and SecurityModeCommand, these are among the
smallest fully-defined NR RRC messages, and their leading scalars have no
per-firmware-version drift, so one offset-stable decoder covers every wire
version (v9/v12/v14/v17/v23/v26).

ASN.1 path (3GPP TS 38.331):

    DL-CCCH-Message ::= SEQUENCE { message DL-CCCH-MessageType }
    DL-CCCH-MessageType ::= CHOICE {
        c1 CHOICE {                          -- 4 alternatives -> 2 bits
            rrcReject   RRCReject,            -- index 0
            rrcSetup    RRCSetup,             -- index 1
            spare2      NULL,
            spare1      NULL
        },
        messageClassExtension  SEQUENCE {}
    }

    RRCReject ::= SEQUENCE {
        criticalExtensions CHOICE {
            rrcReject                  RRCReject-IEs,   -- index 0
            criticalExtensionsFuture   SEQUENCE {}
        }                                               -- 1 bit
    }
    RRCReject-IEs ::= SEQUENCE {              -- 3 OPTIONAL -> 3 preamble bits
        waitTime                   RejectWaitTime  OPTIONAL,  -- Need N
        lateNonCriticalExtension   OCTET STRING    OPTIONAL,
        nonCriticalExtension       SEQUENCE {}     OPTIONAL
    }
    RejectWaitTime ::= INTEGER (1..16)        -- 4 bits, value = 1 + field

    RRCSetup ::= SEQUENCE {
        rrc-TransactionIdentifier  RRC-TransactionIdentifier,  -- INTEGER(0..3), 2 bits
        criticalExtensions CHOICE {
            rrcSetup                 RRCSetup-IEs,   -- index 0
            criticalExtensionsFuture SEQUENCE {}
        }                                             -- 1 bit
    }
    RRCSetup-IEs ::= SEQUENCE {               -- 2 OPTIONAL -> 2 preamble bits
        radioBearerConfig  RadioBearerConfig,
        masterCellGroup    OCTET STRING (CONTAINING CellGroupConfig),
        lateNonCriticalExtension  OCTET STRING  OPTIONAL,
        nonCriticalExtension      SEQUENCE {}  OPTIONAL
    }

UPER bit layout (this decoder receives the full ``msg_data`` and consumes the
3-bit DL-CCCH-Message prefix itself, so offsets are absolute from byte 0):

    bit 0     : DL-CCCH-MessageType CHOICE        (0 = c1)
    bits 1-2  : c1 alternative                    (0 = rrcReject, 1 = rrcSetup)

  rrcReject (c1 = 0):
    bit 3     : criticalExtensions CHOICE         (0 = rrcReject-IEs)
    bits 4-6  : RRCReject-IEs OPTIONAL preamble   [waitTime, lateNonCrit, nonCrit]
    bits 7-10 : RejectWaitTime (if waitTime present) -> 1 + value

  rrcSetup (c1 = 1):
    bits 3-4  : rrc-TransactionIdentifier         (INTEGER 0..3)
    bit 5     : criticalExtensions CHOICE         (0 = rrcSetup-IEs)
    (RRCSetup-IEs radioBearerConfig + masterCellGroup CellGroupConfig follow;
     those carry SRB/DRB + MAC/RLC/PHY cell-group config and are intentionally
     left undecoded here: they are heavy structures outside the identity /
     reselection scope this decoder serves. rrc-TransactionIdentifier is the
     clean leading scalar the message exposes.)

The ``RRCReject.waitTime`` decode is complete; ``RRCSetup`` decodes to its
leading transaction id (the rest is structural). ``criticalExtensionsFuture``
on either message yields the message type with the scalar left ``None``.

Reference: 3GPP TS 38.331 (NR RRC Protocol specification), 6.2.2.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader

# DL-CCCH-MessageType.c1 alternative indices (TS 38.331 6.2.2).
_DL_CCCH_C1_RRC_REJECT = 0
_DL_CCCH_C1_RRC_SETUP = 1


@dataclass
class NrDlCcch:
    """Decoded NR DL-CCCH message (3GPP TS 38.331 6.2.2).

    ``message_type`` is ``"rrcReject"`` or ``"rrcSetup"``. Message-specific
    scalars are populated per type and are ``None`` otherwise:

      * ``wait_time`` (rrcReject): RejectWaitTime seconds, INTEGER(1..16).
        ``None`` when the OPTIONAL waitTime is absent or criticalExtensions
        selects the future branch.
      * ``rrc_transaction_identifier`` (rrcSetup): INTEGER(0..3). ``None``
        only if the record is not an rrcSetup.
    """

    log_time: int
    message_type: str
    wait_time: Optional[int] = None
    rrc_transaction_identifier: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "NrDlCcch",
            "log_time": self.log_time,
            "message_type": self.message_type,
        }
        if self.wait_time is not None:
            d["wait_time"] = self.wait_time
        if self.rrc_transaction_identifier is not None:
            d["rrc_transaction_identifier"] = self.rrc_transaction_identifier
        return d


def decode_nr_dl_ccch(log_time: int, msg_data: bytes) -> Optional[NrDlCcch]:
    """Decode a DL-CCCH-Message (rrcReject / rrcSetup) into a dataclass.

    ``msg_data`` is the full DL-CCCH-Message (this decoder consumes the 3-bit
    DL-CCCH-MessageType prefix itself, mirroring ``decode_nr_mib`` /
    ``decode_nr_security_mode_command``). Returns ``None`` when:

      * ``msg_data`` is empty,
      * the outer CHOICE is not ``c1`` (messageClassExtension), or
      * the c1 alternative is a spare (2/3) rather than rrcReject/rrcSetup,
        i.e. the caller mis-routed a non-DL-CCCH-message here.
    """
    if not msg_data:
        return None

    r = UperReader(msg_data)

    if r.read_bool():                       # DL-CCCH-MessageType CHOICE: 1 = ext
        return None
    c1 = r.read_bits(2)

    if c1 == _DL_CCCH_C1_RRC_REJECT:
        # RRCReject SEQUENCE: no preamble.
        if r.read_bool():                   # criticalExtensions: 1 = future
            return NrDlCcch(log_time=log_time, message_type="rrcReject")
        # RRCReject-IEs: 3-bit OPTIONAL preamble [waitTime, lateNonCrit, nonCrit].
        opt = r.read_bits(3)
        wait_time: Optional[int] = None
        if (opt >> 2) & 1:                  # waitTime present (MSB of preamble)
            wait_time = r.read_constrained_int(1, 16)
        return NrDlCcch(
            log_time=log_time, message_type="rrcReject", wait_time=wait_time)

    if c1 == _DL_CCCH_C1_RRC_SETUP:
        # RRCSetup SEQUENCE: no preamble. rrc-TransactionIdentifier first.
        tid = r.read_bits(2)                # RRC-TransactionIdentifier (0..3)
        # criticalExtensions CHOICE consumed for completeness/validation; the
        # RRCSetup-IEs body (radioBearerConfig + masterCellGroup) is structural
        # and intentionally not decoded here.
        r.read_bool()
        return NrDlCcch(
            log_time=log_time, message_type="rrcSetup",
            rrc_transaction_identifier=tid)

    # spare2 (2) / spare1 (3): not a real DL-CCCH message.
    return None
