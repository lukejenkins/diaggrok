# diaggrok-provenance: re
"""NR DL-DCCH SecurityModeCommand decoder — from-scratch UPER.

Decodes the ``securityModeCommand`` alternative of a DL-DCCH-Message per
3GPP TS 38.331 §6.2.2 / §6.3.2. After the MIB, this is one of the smallest
fully-defined NR RRC messages: it carries only an RRC transaction id and the
AS-security algorithm pair (ciphering + integrity) the gNB selects for the UE
during the security-mode procedure. Like the MIB, its core IEs have no
per-firmware-version drift, so a single offset-stable decoder covers every
wire version.

ASN.1 path (3GPP TS 38.331):

    DL-DCCH-Message ::= SEQUENCE { message DL-DCCH-MessageType }
    DL-DCCH-MessageType ::= CHOICE {
        c1 CHOICE {                          -- 16 alternatives → 4 bits
            ... , securityModeCommand SecurityModeCommand , ...  -- index 4
        },
        messageClassExtension SEQUENCE {}
    }
    SecurityModeCommand ::= SEQUENCE {
        rrc-TransactionIdentifier  RRC-TransactionIdentifier,  -- INTEGER(0..3) → 2 bits
        criticalExtensions         CHOICE {
            securityModeCommand        SecurityModeCommand-IEs,   -- index 0
            criticalExtensionsFuture   SEQUENCE {}
        }                                                          -- 1 bit
    }
    SecurityModeCommand-IEs ::= SEQUENCE {        -- 2 OPTIONAL → 2 preamble bits
        securityConfigSMC          SecurityConfigSMC,
        lateNonCriticalExtension   OCTET STRING  OPTIONAL,
        nonCriticalExtension       SEQUENCE {}   OPTIONAL
    }
    SecurityConfigSMC ::= SEQUENCE {              -- extensible → 1 ext-marker bit
        securityAlgorithmConfig    SecurityAlgorithmConfig,
        ...
    }
    SecurityAlgorithmConfig ::= SEQUENCE {        -- extensible + 1 OPTIONAL →
        cipheringAlgorithm         CipheringAlgorithm,        --   2 preamble bits
        integrityProtAlgorithm     IntegrityProtAlgorithm OPTIONAL,
        ...
    }
    CipheringAlgorithm ::= ENUMERATED {           -- extensible → 1 ext bit + 3 bits
        nea0, nea1, nea2, nea3, spare4, spare3, spare2, spare1, ... }
    IntegrityProtAlgorithm ::= ENUMERATED {       -- extensible → 1 ext bit + 3 bits
        nia0, nia1, nia2, nia3, spare4, spare3, spare2, spare1, ... }

UPER bit layout (this decoder receives the full ``msg_data`` and consumes the
5-bit DL-DCCH-Message prefix itself, so the offsets are absolute from byte 0):

    bit  0      : DL-DCCH-MessageType CHOICE  (0=c1)
    bits 1-4    : c1 alternative              (4 = securityModeCommand)
    bits 5-6    : rrc-TransactionIdentifier   (INTEGER 0..3)
    bit  7      : criticalExtensions CHOICE   (0 = securityModeCommand)
    bit  8      : lateNonCriticalExtension present
    bit  9      : nonCriticalExtension present
    bit  10     : SecurityConfigSMC extension marker      (0 = no ext)
    bit  11     : SecurityAlgorithmConfig extension marker (0 = no ext)
    bit  12     : integrityProtAlgorithm present
    bit  13     : cipheringAlgorithm extension bit         (0 = in root)
    bits 14-16  : cipheringAlgorithm value                 (0..7)
    bit  17     : integrityProtAlgorithm extension bit     (0 = in root, if present)
    bits 18-20  : integrityProtAlgorithm value             (0..7, if present)

Validated field-for-field against the stock-tshark (4.6.6) ``nr-rrc``
dissector of the diaggrok NR Exported-PDU pcap (#N) on the real
RM520N-GL R03A04 T-Mobile NR5G-SA capture
``<redacted-pii>``:

    msg_data (hex)         '20 09 10'
    rrc-TransactionIdentifier 0
    cipheringAlgorithm     nea2 (2)
    integrityProtAlgorithm nia2 (2)

tshark independently decodes the same verbatim PDU bytes as
``cipheringAlgorithm: nea2 (2)`` / ``integrityProtAlgorithm: nia2 (2)`` — an
oracle entirely separate from this hand-rolled UPER path.

Reference: 3GPP TS 38.331 v16.x (NR RRC Protocol specification), §6.3.2.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader

# CipheringAlgorithm / IntegrityProtAlgorithm ENUMERATED root labels
# (3GPP TS 38.331 §6.3.2 SecurityAlgorithmConfig). Index 0..7; 4..7 are spare.
_CIPHERING_ALGO_NAMES = (
    "nea0", "nea1", "nea2", "nea3", "spare4", "spare3", "spare2", "spare1")
_INTEGRITY_ALGO_NAMES = (
    "nia0", "nia1", "nia2", "nia3", "spare4", "spare3", "spare2", "spare1")

# DL-DCCH c1 index for securityModeCommand (TS 38.331 DL-DCCH-MessageType.c1).
_DL_DCCH_C1_SECURITY_MODE_COMMAND = 4


@dataclass
class NrSecurityModeCommand:
    """Decoded NR SecurityModeCommand (3GPP TS 38.331 §6.3.2).

    Preserves on-wire enum values and exposes the spec labels alongside.
    ``integrity_prot_algorithm`` is ``None`` when the OPTIONAL field is
    absent (rare — the gNB normally signals both).
    """

    log_time: int
    rrc_transaction_identifier: int
    ciphering_algorithm: int
    ciphering_algorithm_name: str
    integrity_prot_algorithm: Optional[int]
    integrity_prot_algorithm_name: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "NrSecurityModeCommand",
            "log_time": self.log_time,
            "rrc_transaction_identifier": self.rrc_transaction_identifier,
            "ciphering_algorithm": self.ciphering_algorithm,
            "ciphering_algorithm_name": self.ciphering_algorithm_name,
            "integrity_prot_algorithm": self.integrity_prot_algorithm,
            "integrity_prot_algorithm_name": self.integrity_prot_algorithm_name,
        }


def decode_nr_security_mode_command(
        log_time: int, msg_data: bytes) -> Optional[NrSecurityModeCommand]:
    """Decode a DL-DCCH ``securityModeCommand`` into a dataclass.

    ``msg_data`` is the full DL-DCCH-Message (this decoder consumes the 5-bit
    DL-DCCH-MessageType prefix itself, mirroring how callers pass the whole
    PDU to ``decode_nr_mib``). Returns ``None`` when:

      * ``msg_data`` is shorter than 3 bytes (21 bits min content),
      * the outer CHOICE is not c1, or the c1 alternative is not
        securityModeCommand (index 4) — i.e. the caller mis-routed a
        different DL-DCCH message here.
    """
    if not msg_data or len(msg_data) < 3:
        return None

    r = UperReader(msg_data)

    if r.read_bool():           # DL-DCCH-MessageType CHOICE: 1 = messageClassExtension
        return None
    if r.read_bits(4) != _DL_DCCH_C1_SECURITY_MODE_COMMAND:
        return None

    tid = r.read_bits(2)            # rrc-TransactionIdentifier (0..3)
    if r.read_bool():               # criticalExtensions CHOICE: 1 = future
        return None
    r.skip_bits(2)                  # SecurityModeCommand-IEs: late/nonCrit OPTIONAL preamble
    r.skip_bits(1)                  # SecurityConfigSMC extension marker
    r.skip_bits(1)                  # SecurityAlgorithmConfig extension marker
    integ_present = r.read_bool()   # integrityProtAlgorithm OPTIONAL present

    r.skip_bits(1)                  # cipheringAlgorithm extensible-enum: in-root bit
    cipher = r.read_bits(3)
    integ: Optional[int] = None
    if integ_present:
        r.skip_bits(1)              # integrityProtAlgorithm extensible-enum: in-root bit
        integ = r.read_bits(3)

    return NrSecurityModeCommand(
        log_time=log_time,
        rrc_transaction_identifier=tid,
        ciphering_algorithm=cipher,
        ciphering_algorithm_name=_CIPHERING_ALGO_NAMES[cipher],
        integrity_prot_algorithm=integ,
        integrity_prot_algorithm_name=(
            _INTEGRITY_ALGO_NAMES[integ] if integ is not None else None),
    )
