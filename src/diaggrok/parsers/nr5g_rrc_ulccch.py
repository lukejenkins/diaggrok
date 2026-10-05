# diaggrok-provenance: re
"""NR UL-CCCH / UL-CCCH1 message decoder - from-scratch UPER (3GPP TS 38.331 6.2.1).

Decodes every real alternative of the two Uplink Common Control Channel
messages: the UE's first RRC words on a cell, sent on SRB0 before any
dedicated channel exists. They answer the questions a paging/measurement
decode cannot: *why* the UE connected (``establishmentCause`` —
``mt-Access`` after a page, ``mo-Data``, ``emergency`` …), *why* it is resuming
from RRC-Inactive (``resumeCause`` incl. ``rna-Update``), and *why* it is
re-establishing after a radio-link or handover failure (``reestablishmentCause``
with the source-cell ``physCellId``). ``rrcSystemInfoRequest`` names which
on-demand SI messages the UE asked for.

Every UL-CCCH message is a fixed **48-bit** SDU (the CCCH48 logical-channel
size) and UL-CCCH1's ``rrcResumeRequest1`` a fixed **64-bit** one (CCCH64), so
there is no per-firmware-version drift and one offset-stable decoder covers
every wire version. The decoder REFUSES a payload shorter than that size:
``UperReader`` zero-pads past the end, which would otherwise fabricate an
``emergency`` cause and an all-zero identity from a truncated record.

ASN.1 (3GPP TS 38.331 v17.17.0):

    UL-CCCH-Message ::= SEQUENCE { message UL-CCCH-MessageType }
    UL-CCCH-MessageType ::= CHOICE {
        c1 CHOICE {                                   -- 4 alternatives -> 2 bits
            rrcSetupRequest            RRCSetupRequest,            -- 0
            rrcResumeRequest           RRCResumeRequest,           -- 1
            rrcReestablishmentRequest  RRCReestablishmentRequest,  -- 2
            rrcSystemInfoRequest       RRCSystemInfoRequest        -- 3
        },
        messageClassExtension  SEQUENCE {} }
    UL-CCCH1-MessageType ::= CHOICE {
        c1 CHOICE {                                   -- 4 alternatives -> 2 bits
            rrcResumeRequest1 RRCResumeRequest1, spare3 NULL, spare2 NULL, spare1 NULL },
        messageClassExtension  SEQUENCE {} }

    RRCSetupRequest-IEs ::= SEQUENCE {
        ue-Identity         InitialUE-Identity,  -- CHOICE { ng-5G-S-TMSI-Part1 BIT STRING(39),
                                                 --          randomValue        BIT STRING(39) }
        establishmentCause  EstablishmentCause,  -- ENUMERATED, 16 values -> 4 bits
        spare               BIT STRING (SIZE (1)) }
    RRCResumeRequest-IEs ::= SEQUENCE {
        resumeIdentity ShortI-RNTI-Value,        -- BIT STRING(24)
        resumeMAC-I    BIT STRING (SIZE (16)),
        resumeCause    ResumeCause,              -- ENUMERATED, 16 values -> 4 bits
        spare          BIT STRING (SIZE (1)) }
    RRCResumeRequest1-IEs ::= SEQUENCE {         -- UL-CCCH1
        resumeIdentity I-RNTI-Value,             -- BIT STRING(40)
        resumeMAC-I    BIT STRING (SIZE (16)),
        resumeCause    ResumeCause,
        spare          BIT STRING (SIZE (1)) }
    RRCReestablishmentRequest-IEs ::= SEQUENCE {
        ue-Identity ReestabUE-Identity,          -- SEQUENCE { c-RNTI RNTI-Value INTEGER(0..65535),
                                                 --   physCellId INTEGER(0..1007), shortMAC-I BIT STRING(16) }
        reestablishmentCause ReestablishmentCause,  -- ENUMERATED, 4 values -> 2 bits
        spare BIT STRING (SIZE (1)) }
    RRCSystemInfoRequest ::= SEQUENCE {
        criticalExtensions CHOICE {
            rrcSystemInfoRequest RRCSystemInfoRequest-IEs,        -- requested-SI-List BIT STRING(32), spare(12)
            criticalExtensionsFuture-r16 CHOICE {
                rrcPosSystemInfoRequest-r16 RRC-PosSystemInfoRequest-r16-IEs,  -- requestedPosSI-List(32), spare(11)
                criticalExtensionsFuture SEQUENCE {} } } }

Every outer SEQUENCE above is non-extensible with no OPTIONAL, so no preamble
bits precede the IEs; the BIT STRINGs are fixed-size (no length determinant).

Validated field-for-field against the stock tshark ``nr-rrc.ul.ccch`` /
``nr-rrc.ul.ccch1`` dissectors (via an Exported-PDU wrapper) on
synthetic vectors covering every alternative, and on the real corpus UL-CCCH
records. Identity-bearing values (5G-S-TMSI part 1, resume identities, C-RNTI,
MAC-I tokens) are decoded faithfully at runtime; committed fixtures use
synthetic values only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader

#: TS 38.331 EstablishmentCause (RRCSetupRequest) — 16 values, 4 bits.
ESTABLISHMENT_CAUSE = (
    "emergency", "highPriorityAccess", "mt-Access", "mo-Signalling",
    "mo-Data", "mo-VoiceCall", "mo-VideoCall", "mo-SMS",
    "mps-PriorityAccess", "mcs-PriorityAccess",
    "spare6", "spare5", "spare4", "spare3", "spare2", "spare1",
)
#: TS 38.331 ResumeCause (RRCResumeRequest / RRCResumeRequest1) — 16 values.
RESUME_CAUSE = (
    "emergency", "highPriorityAccess", "mt-Access", "mo-Signalling",
    "mo-Data", "mo-VoiceCall", "mo-VideoCall", "mo-SMS", "rna-Update",
    "mps-PriorityAccess", "mcs-PriorityAccess",
    "spare5", "spare4", "spare3", "spare2", "spare1",
)
#: TS 38.331 ReestablishmentCause — 4 values, 2 bits.
REESTABLISHMENT_CAUSE = (
    "reconfigurationFailure", "handoverFailure", "otherFailure", "spare1",
)

_UL_CCCH_BITS = 48    # every UL-CCCH message is a CCCH48 SDU
_UL_CCCH1_BITS = 64   # rrcResumeRequest1 is a CCCH64 SDU

_C1_SETUP_REQUEST = 0
_C1_RESUME_REQUEST = 1
_C1_REESTABLISHMENT_REQUEST = 2
_C1_SYSTEM_INFO_REQUEST = 3
_C1_RESUME_REQUEST1 = 0   # UL-CCCH1


def _si_bitmap_to_list(bitmap: int) -> list[int]:
    """1-based SI-message numbers set in a 32-bit ``requested-SI-List``.

    Bit 0 of the BIT STRING (the MSB as read) is SI-message 1 — the first entry
    of ``si-SchedulingInfo`` — per TS 38.331 ``RRCSystemInfoRequest`` field
    description. Returned ascending."""
    return [i + 1 for i in range(32) if (bitmap >> (31 - i)) & 1]


@dataclass
class NrUlCcch:
    """Decoded NR UL-CCCH / UL-CCCH1 message (3GPP TS 38.331 6.2.1).

    ``message_type`` names the c1 alternative; only that alternative's fields
    are set, everything else stays ``None``.

    rrcSetupRequest:
      * ``ue_identity_type``: ``'ng-5G-S-TMSI-Part1'`` (the 39 LSBs of the UE's
        5G-S-TMSI) or ``'randomValue'`` (no valid TMSI).
      * ``ue_identity_value``: the 39-bit value.
      * ``establishment_cause``: EstablishmentCause name.
    rrcResumeRequest / rrcResumeRequest1:
      * ``resume_identity_type``: ``'shortI-RNTI'`` (24-bit, UL-CCCH) or
        ``'fullI-RNTI'`` (40-bit, UL-CCCH1).
      * ``resume_identity``, ``resume_mac_i`` (16-bit), ``resume_cause``.
    rrcReestablishmentRequest:
      * ``reestab_c_rnti``, ``reestab_phys_cell_id`` (the PCell the UE was
        connected to before the failure), ``reestab_short_mac_i``,
        ``reestablishment_cause``.
    rrcSystemInfoRequest:
      * ``si_request_kind``: ``'si'`` / ``'posSI'`` (r16 positioning) /
        ``'future'`` (criticalExtensionsFuture — no IEs).
      * ``requested_si_list``: 1-based SI-message numbers requested.
    """

    log_time: int
    message_type: str
    ue_identity_type: Optional[str] = None
    ue_identity_value: Optional[int] = None
    establishment_cause: Optional[str] = None
    resume_identity_type: Optional[str] = None
    resume_identity: Optional[int] = None
    resume_mac_i: Optional[int] = None
    resume_cause: Optional[str] = None
    reestab_c_rnti: Optional[int] = None
    reestab_phys_cell_id: Optional[int] = None
    reestab_short_mac_i: Optional[int] = None
    reestablishment_cause: Optional[str] = None
    si_request_kind: Optional[str] = None
    requested_si_list: Optional[list[int]] = field(default=None)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "NrUlCcch",
            "log_time": self.log_time,
            "message_type": self.message_type,
        }
        for k in (
            "ue_identity_type", "ue_identity_value", "establishment_cause",
            "resume_identity_type", "resume_identity", "resume_mac_i",
            "resume_cause", "reestab_c_rnti", "reestab_phys_cell_id",
            "reestab_short_mac_i", "reestablishment_cause",
            "si_request_kind", "requested_si_list",
        ):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


def decode_nr_ul_ccch(log_time: int, msg_data: bytes) -> Optional[NrUlCcch]:
    """Decode a full UL-CCCH-Message (consumes the 3-bit prefix itself).

    Returns ``None`` when ``msg_data`` is shorter than the 48-bit CCCH48 SDU
    (truncated — see module docstring) or the outer CHOICE selects
    ``messageClassExtension``.
    """
    if len(msg_data) * 8 < _UL_CCCH_BITS:
        return None
    r = UperReader(msg_data)
    if r.read_bool():                        # UL-CCCH-MessageType: 1 = extension
        return None
    c1 = r.read_bits(2)

    if c1 == _C1_SETUP_REQUEST:
        # RRCSetupRequest ::= SEQUENCE { rrcSetupRequest RRCSetupRequest-IEs } — no bits.
        choice = r.read_bits(1)              # InitialUE-Identity CHOICE
        return NrUlCcch(
            log_time=log_time, message_type="rrcSetupRequest",
            ue_identity_type=("randomValue" if choice else "ng-5G-S-TMSI-Part1"),
            ue_identity_value=r.read_bits(39),
            establishment_cause=ESTABLISHMENT_CAUSE[r.read_bits(4)],
        )

    if c1 == _C1_RESUME_REQUEST:
        return NrUlCcch(
            log_time=log_time, message_type="rrcResumeRequest",
            resume_identity_type="shortI-RNTI",
            resume_identity=r.read_bits(24),
            resume_mac_i=r.read_bits(16),
            resume_cause=RESUME_CAUSE[r.read_bits(4)],
        )

    if c1 == _C1_REESTABLISHMENT_REQUEST:
        c_rnti = r.read_bits(16)             # RNTI-Value INTEGER(0..65535)
        pci = r.read_constrained_int(0, 1007)
        return NrUlCcch(
            log_time=log_time, message_type="rrcReestablishmentRequest",
            reestab_c_rnti=c_rnti, reestab_phys_cell_id=pci,
            reestab_short_mac_i=r.read_bits(16),
            reestablishment_cause=REESTABLISHMENT_CAUSE[r.read_bits(2)],
        )

    # c1 == _C1_SYSTEM_INFO_REQUEST (the 2-bit index has no other value).
    rec = NrUlCcch(log_time=log_time, message_type="rrcSystemInfoRequest")
    if r.read_bool():                        # criticalExtensions: 1 = future-r16
        if r.read_bool():                    # future-r16 CHOICE: 1 = criticalExtensionsFuture
            rec.si_request_kind = "future"
            return rec
        rec.si_request_kind = "posSI"
    else:
        rec.si_request_kind = "si"
    rec.requested_si_list = _si_bitmap_to_list(r.read_bits(32))
    return rec


def decode_nr_ul_ccch1(log_time: int, msg_data: bytes) -> Optional[NrUlCcch]:
    """Decode a full UL-CCCH1-Message (``rrcResumeRequest1``, fullI-RNTI).

    The c1 index is **2 bits** (rrcResumeRequest1 + spare3..spare1). Returns
    ``None`` on a payload shorter than the 64-bit CCCH64 SDU, the extension
    path, or a spare alternative.
    """
    if len(msg_data) * 8 < _UL_CCCH1_BITS:
        return None
    r = UperReader(msg_data)
    if r.read_bool():                        # UL-CCCH1-MessageType: 1 = extension
        return None
    if r.read_bits(2) != _C1_RESUME_REQUEST1:
        return None                          # spare3 / spare2 / spare1
    return NrUlCcch(
        log_time=log_time, message_type="rrcResumeRequest1",
        resume_identity_type="fullI-RNTI",
        resume_identity=r.read_bits(40),
        resume_mac_i=r.read_bits(16),
        resume_cause=RESUME_CAUSE[r.read_bits(4)],
    )
