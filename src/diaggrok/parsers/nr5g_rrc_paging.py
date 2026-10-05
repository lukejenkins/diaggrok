# diaggrok-provenance: re
"""NR PCCH Paging message decoder - from-scratch UPER (3GPP TS 38.331 6.2.2).

Decodes the ``PCCH-Message`` broadcast on the NR Paging Control Channel: the
list of UE identities a gNB is paging in idle/inactive mode. Paging is by far
the highest-volume PCCH message and, after the MIB / SecurityModeCommand /
DL-CCCH decoders, the next smallest fully-bounded NR RRC message - its leading
structure has no per-firmware-version drift, so one offset-stable decoder
covers every wire version (v9/v12/v14/v17/v23/v26).

ASN.1 path (3GPP TS 38.331):

    PCCH-Message ::= SEQUENCE { message PCCH-MessageType }
    PCCH-MessageType ::= CHOICE {
        c1 CHOICE {                          -- 2 alternatives -> 1 bit
            paging   Paging,                 -- index 0
            spare1   NULL                    -- index 1
        },
        messageClassExtension  SEQUENCE {}
    }

    Paging ::= SEQUENCE {                     -- NOT extensible (no "...")
        pagingRecordList          PagingRecordList  OPTIONAL,  -- Need N
        lateNonCriticalExtension  OCTET STRING      OPTIONAL,
        nonCriticalExtension      SEQUENCE {}       OPTIONAL
    }                                         -- 3 OPTIONAL -> 3 preamble bits

    PagingRecordList ::= SEQUENCE (SIZE (1..maxNrofPageRec)) OF PagingRecord
    maxNrofPageRec  INTEGER ::= 32            -- count is a constrained int 1..32

    PagingRecord ::= SEQUENCE {               -- extensible ("...")
        ue-Identity  PagingUE-Identity,
        accessType   ENUMERATED {non3GPP}  OPTIONAL,  -- Need N
        ...
    }

    PagingUE-Identity ::= CHOICE {            -- extensible ("...")
        ng-5G-S-TMSI  NG-5G-S-TMSI,           -- index 0
        fullI-RNTI    I-RNTI-Value,           -- index 1
        ...
    }
    NG-5G-S-TMSI ::= BIT STRING (SIZE (48))
    I-RNTI-Value ::= BIT STRING (SIZE (40))

UPER bit layout (this decoder receives the full ``msg_data`` and consumes the
2-bit PCCH-Message prefix itself, so offsets are absolute from byte 0):

    bit 0     : PCCH-MessageType CHOICE            (0 = c1)
    bit 1     : c1 alternative                     (0 = paging, 1 = spare1)
    bits 2-4  : Paging OPTIONAL preamble           [pagingRecordList, lateNonCrit, nonCrit]
    bits 5-9  : PagingRecordList count-1 (if list present)  INTEGER(1..32) -> 5 bits

  per PagingRecord (extensible SEQUENCE):
    +1 bit    : PagingRecord extension marker      (0 = no extension)
    +1 bit    : accessType OPTIONAL present
    PagingUE-Identity (extensible CHOICE):
    +1 bit    : PagingUE-Identity extension marker (0 = root alternative)
    +1 bit    : root alternative index             (0 = ng-5G-S-TMSI, 1 = fullI-RNTI)
    +48 bits  : ng-5G-S-TMSI  (or +40 bits fullI-RNTI)
    (accessType, if present, is ENUMERATED {non3GPP} - a single non-extensible
     value, so it consumes 0 bits.)

The 48-bit ``NG-5G-S-TMSI`` (3GPP TS 23.003 §2.10) decomposes as::

    bits [47:38]  AMF Set ID   (10 bits)
    bits [37:32]  AMF Pointer  (6 bits)
    bits [31: 0]  5G-TMSI      (32 bits)

Reference: 3GPP TS 38.331 (NR RRC) 6.2.2; TS 23.003 §2.10 (5G-S-TMSI).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader

# PCCH-MessageType.c1 alternative index for paging (TS 38.331 6.2.2).
_PCCH_C1_PAGING = 0
# PagingUE-Identity root CHOICE alternative indices.
_UE_ID_NG_5G_S_TMSI = 0
_UE_ID_FULL_I_RNTI = 1
# maxNrofPageRec (TS 38.331): PagingRecordList SIZE (1..32).
_MAX_PAGE_REC = 32


@dataclass
class NrPagingRecord:
    """One decoded ``PagingRecord`` (3GPP TS 38.331 6.2.2).

    ``ue_identity_type`` is ``"ng-5G-S-TMSI"`` or ``"fullI-RNTI"``. Exactly one
    of the identity fields is populated per record:

      * ``ng_5g_s_tmsi`` (48-bit int) with its TS 23.003 decomposition
        ``amf_set_id`` / ``amf_pointer`` / ``five_g_tmsi``, or
      * ``full_i_rnti`` (40-bit int).

    ``access_type`` is ``"non3GPP"`` when the OPTIONAL accessType is present,
    else ``None`` (the common 3GPP-access case).
    """

    ue_identity_type: str
    ng_5g_s_tmsi: Optional[int] = None
    amf_set_id: Optional[int] = None
    amf_pointer: Optional[int] = None
    five_g_tmsi: Optional[int] = None
    full_i_rnti: Optional[int] = None
    access_type: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"ue_identity_type": self.ue_identity_type}
        if self.ng_5g_s_tmsi is not None:
            d["ng_5g_s_tmsi"] = self.ng_5g_s_tmsi
            d["ng_5g_s_tmsi_hex"] = f"{self.ng_5g_s_tmsi:012X}"
            d["amf_set_id"] = self.amf_set_id
            d["amf_pointer"] = self.amf_pointer
            d["five_g_tmsi"] = self.five_g_tmsi
            d["five_g_tmsi_hex"] = f"{self.five_g_tmsi:08X}"
        if self.full_i_rnti is not None:
            d["full_i_rnti"] = self.full_i_rnti
            d["full_i_rnti_hex"] = f"{self.full_i_rnti:010X}"
        if self.access_type is not None:
            d["access_type"] = self.access_type
        return d


@dataclass
class NrPaging:
    """Decoded NR PCCH Paging message (3GPP TS 38.331 6.2.2)."""

    log_time: int
    record_count: int
    records: list[NrPagingRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "NrPaging",
            "log_time": self.log_time,
            "record_count": self.record_count,
            "records": [r.to_dict() for r in self.records],
        }


def _decode_ue_identity(r: UperReader) -> Optional[NrPagingRecord]:
    """Decode one PagingRecord (extension marker already NOT yet read).

    Returns ``None`` if the record selects an extension alternative this
    decoder does not model (future-proofing: an unknown identity type would
    otherwise be mis-read as a fixed-width bitstring).
    """
    if r.read_bool():          # PagingRecord extension marker: 1 = extended
        return None
    access_present = r.read_bool()   # accessType OPTIONAL present

    if r.read_bool():          # PagingUE-Identity extension marker: 1 = extended
        return None
    ue_idx = r.read_bits(1)    # root CHOICE: 2 alternatives -> 1 bit

    rec: NrPagingRecord
    if ue_idx == _UE_ID_NG_5G_S_TMSI:
        stmsi = r.read_bitstring(48)
        rec = NrPagingRecord(
            ue_identity_type="ng-5G-S-TMSI",
            ng_5g_s_tmsi=stmsi,
            amf_set_id=(stmsi >> 38) & 0x3FF,
            amf_pointer=(stmsi >> 32) & 0x3F,
            five_g_tmsi=stmsi & 0xFFFFFFFF,
        )
    elif ue_idx == _UE_ID_FULL_I_RNTI:
        rec = NrPagingRecord(
            ue_identity_type="fullI-RNTI",
            full_i_rnti=r.read_bitstring(40),
        )
    else:                       # unreachable for a 1-bit index
        return None

    if access_present:
        # ENUMERATED {non3GPP}: single non-extensible value -> 0 bits.
        rec.access_type = "non3GPP"
    return rec


def decode_nr_paging(log_time: int, msg_data: bytes) -> Optional[NrPaging]:
    """Decode a PCCH-Message (paging) into a dataclass.

    ``msg_data`` is the full PCCH-Message (this decoder consumes the 2-bit
    PCCH-MessageType prefix itself, mirroring ``decode_nr_dl_ccch`` /
    ``decode_nr_security_mode_command``). Returns ``None`` when:

      * ``msg_data`` is empty,
      * the outer CHOICE is not c1 (messageClassExtension),
      * the c1 alternative is spare1 rather than paging (caller mis-route), or
      * the pagingRecordList OPTIONAL is absent (an empty Paging carries no
        identities - nothing to surface).
    """
    if not msg_data:
        return None

    r = UperReader(msg_data)

    if r.read_bool():           # PCCH-MessageType CHOICE: 1 = messageClassExtension
        return None
    if r.read_bits(1) != _PCCH_C1_PAGING:   # c1: 0 = paging, 1 = spare1
        return None

    # Paging SEQUENCE OPTIONAL preamble: [pagingRecordList, lateNonCrit, nonCrit].
    opt = r.read_bits(3)
    if not ((opt >> 2) & 1):    # pagingRecordList absent -> no identities
        return None

    count = r.read_length(1, _MAX_PAGE_REC)
    records: list[NrPagingRecord] = []
    for _ in range(count):
        rec = _decode_ue_identity(r)
        if rec is None:
            break               # stop at the first unmodelled/extension record
        records.append(rec)

    return NrPaging(log_time=log_time, record_count=count, records=records)
