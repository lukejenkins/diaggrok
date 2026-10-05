# diaggrok-provenance: re
"""NR DL-DCCH RRCRelease decoder - from-scratch UPER (3GPP TS 38.331 6.2.2).

Decodes the RF-relevant head of an ``RRCRelease`` — the message a gNB sends on
the Downlink Dedicated Control Channel to tear down (or suspend) an RRC
connection. Its ``redirectedCarrierInfo`` names the carrier the network is
pushing the UE onto (an NR ARFCN, or an inter-RAT E-UTRA EARFCN), which is
serving-infrastructure information of the same class the WiGLE-oriented 0xB821
program already lifts from SIB1 / paging.

ASN.1 path (3GPP TS 38.331 v17.17.0):

    DL-DCCH-MessageType ::= CHOICE {
        c1 CHOICE {                              -- 16 alternatives -> 4 bits
            rrcReconfiguration ..., rrcResume ...,
            rrcRelease  RRCRelease,               -- index 2
            ... },
        messageClassExtension SEQUENCE {}
    }
    RRCRelease ::= SEQUENCE {                     -- not extensible, no OPTIONAL
        rrc-TransactionIdentifier  RRC-TransactionIdentifier,   -- INTEGER(0..3), 2 bits
        criticalExtensions CHOICE {
            rrcRelease                 RRCRelease-IEs,   -- index 0
            criticalExtensionsFuture   SEQUENCE {}
        }                                                -- 1 bit
    }
    RRCRelease-IEs ::= SEQUENCE {                 -- not extensible; 6 OPTIONAL -> 6-bit preamble
        redirectedCarrierInfo      RedirectedCarrierInfo       OPTIONAL,  -- Need N
        cellReselectionPriorities  CellReselectionPriorities   OPTIONAL,  -- Need R
        suspendConfig              SuspendConfig               OPTIONAL,  -- Need R
        deprioritisationReq        SEQUENCE {...}              OPTIONAL,  -- Need N
        lateNonCriticalExtension   OCTET STRING                OPTIONAL,
        nonCriticalExtension       RRCRelease-v1540-IEs        OPTIONAL
    }
    RedirectedCarrierInfo ::= CHOICE {            -- EXTENSIBLE: 1 ext bit + 1 root-index bit
        nr     CarrierInfoNR,                      -- root index 0
        eutra  RedirectedCarrierInfo-EUTRA,        -- root index 1
        ...
    }
    CarrierInfoNR ::= SEQUENCE {                  -- EXTENSIBLE: 1 ext bit, then 1 OPTIONAL (smtc)
        carrierFreq          ARFCN-ValueNR,        -- INTEGER(0..3279165) -> 22 bits
        ssbSubcarrierSpacing SubcarrierSpacing,    -- 8-value ENUMERATED -> 3 bits
        smtc                 SSB-MTC  OPTIONAL,    -- Need S (not decoded)
        ...
    }
    RedirectedCarrierInfo-EUTRA ::= SEQUENCE {    -- not extensible; 1 OPTIONAL (cnType)
        eutraFrequency  ARFCN-ValueEUTRA,          -- INTEGER(0..262143) -> 18 bits
        cnType          ENUMERATED {epc,fiveGC} OPTIONAL   -- Need N -> 1 bit
    }

UPER bit layout (this decoder receives the full ``msg_data`` and consumes the
5-bit DL-DCCH-Message prefix itself, so offsets are absolute from byte 0):

    bit 0     : DL-DCCH-MessageType CHOICE        (0 = c1)
    bits 1-4  : c1 alternative                    (2 = rrcRelease)
    bits 5-6  : rrc-TransactionIdentifier         (INTEGER 0..3)
    bit 7     : criticalExtensions CHOICE         (0 = rrcRelease-IEs, 1 = future)
    bits 8-13 : RRCRelease-IEs OPTIONAL preamble  [redirect, reselPrio, suspend,
                                                   deprio, lateNonCrit, nonCrit]
    (if redirectedCarrierInfo present)
    +1 bit    : RedirectedCarrierInfo extension marker (0 = root)
    +1 bit    : root CHOICE index                 (0 = nr, 1 = eutra)
      nr:    +1 ext bit, +1 smtc-present bit, +22 carrierFreq, +3 ssbSCS
      eutra: +1 cnType-present bit, +18 eutraFrequency, [+1 cnType]

    (if suspendConfig present)
    SuspendConfig ::= SEQUENCE {              -- EXTENSIBLE: ext bit + 2 OPTIONAL bits
        fullI-RNTI    I-RNTI-Value,            -- BIT STRING (SIZE(40))
        shortI-RNTI   ShortI-RNTI-Value,       -- BIT STRING (SIZE(24))
        ran-PagingCycle  PagingCycle,          -- ENUMERATED{rf32,rf64,rf128,rf256}
        ran-NotificationAreaInfo ... OPTIONAL, -- Need M (CHOICE, not walked)
        t380 ... OPTIONAL,                     -- Need R
        nextHopChainingCount  INTEGER(0..7),   -- 3 bits (decoded when both OPTIONALs absent)
        ...
    }

``criticalExtensionsFuture`` yields ``message_type='rrcRelease'`` with every
scalar ``None``. The decoder fully decodes the redirect and the suspendConfig
resume identities (fullI-RNTI / shortI-RNTI are RRC-Inactive UE identities — the
kind of value this library exists to surface for network troubleshooting; the
one rule is that committed fixtures use synthetic values, never a captured one).
cellReselectionPriorities and deprioritisationReq are not yet walked (0 corpus
records exercise them); when cellReselectionPriorities is present the fields
ordered after it are left ``None`` and ``cell_reselection_priorities_present``
records why.

Reference: 3GPP TS 38.331 (NR RRC Protocol specification) 6.2.2 / 6.3.2.
Validated A/B against the stock ``tshark`` ``nr-rrc.dl.dcch`` dissector on
synthetic redirect + suspendConfig vectors and on real 0xB821 DL-DCCH records
(via an Exported-PDU wrapper).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from diaggrok.parsers.uper import UperReader

# DL-DCCH-MessageType.c1 alternative index for rrcRelease (TS 38.331 6.2.2).
_DL_DCCH_C1_RRC_RELEASE = 2

# ARFCN constrained-integer bounds (TS 38.331 constant definitions).
_MAX_NARFCN = 3279165  # ARFCN-ValueNR    INTEGER (0..maxNARFCN) -> 22 bits
_MAX_EARFCN = 262143   # ARFCN-ValueEUTRA INTEGER (0..maxEARFCN) -> 18 bits

# SubcarrierSpacing ENUMERATED (8 values, not extensible -> 3 bits), TS 38.331.
_SCS_KHZ = {0: 15, 1: 30, 2: 60, 3: 120, 4: 240, 5: 480, 6: 960, 7: None}

# RedirectedCarrierInfo-EUTRA.cnType ENUMERATED {epc, fiveGC}.
_CN_TYPE = {0: "epc", 1: "fiveGC"}

# SuspendConfig.ran-PagingCycle ENUMERATED {rf32, rf64, rf128, rf256} (2 bits).
_PAGING_CYCLE = {0: "rf32", 1: "rf64", 2: "rf128", 3: "rf256"}

# Fixed BIT STRING sizes for the RRC-Inactive resume identities (TS 38.331).
_FULL_I_RNTI_BITS = 40   # I-RNTI-Value      BIT STRING (SIZE(40))
_SHORT_I_RNTI_BITS = 24  # ShortI-RNTI-Value BIT STRING (SIZE(24))


@dataclass
class NrRrcRelease:
    """Decoded NR DL-DCCH RRCRelease head (3GPP TS 38.331 6.2.2).

    Populated fields (all ``None`` when absent / not applicable):

      * ``rrc_transaction_identifier``: INTEGER(0..3). ``None`` only on the
        ``criticalExtensionsFuture`` branch.
      * ``redirect_rat``: ``"nr"`` / ``"eutra"`` when redirectedCarrierInfo is
        present and resolves to a root alternative; ``None`` when absent (or the
        extensible CHOICE selected an extension addition this decoder does not
        cover).
      * ``redirect_arfcn``: the redirect target frequency — an NR ARFCN when
        ``redirect_rat == 'nr'``, an E-UTRA EARFCN when ``'eutra'``.
      * ``redirect_scs_khz``: SSB subcarrier spacing in kHz (NR redirect only);
        ``None`` for the ``spare1`` enum value or an EUTRA redirect.
      * ``redirect_cn_type``: ``"epc"`` / ``"fiveGC"`` (EUTRA redirect only,
        when the OPTIONAL cnType is present).
    """

    log_time: int
    message_type: str = "rrcRelease"
    rrc_transaction_identifier: Optional[int] = None
    redirect_rat: Optional[str] = None
    redirect_arfcn: Optional[int] = None
    redirect_scs_khz: Optional[int] = None
    redirect_cn_type: Optional[str] = None
    # suspendConfig (RRC-Inactive) — the resume identities and paging config a
    # gNB hands the UE when it releases into RRC_INACTIVE. suspend_config is
    # True when the OPTIONAL suspendConfig is present. full_i_rnti / short_i_rnti
    # are the 40-bit / 24-bit resume identities; ran_paging_cycle is the RAN
    # paging cycle; next_hop_chaining_count is decoded only when both preceding
    # OPTIONALs (ran-NotificationAreaInfo, t380) are absent (else it sits past a
    # structure this decoder does not walk, and stays None).
    suspend_config: Optional[bool] = None
    suspend_full_i_rnti: Optional[int] = None
    suspend_short_i_rnti: Optional[int] = None
    suspend_ran_paging_cycle: Optional[str] = None
    suspend_ran_notification_area_present: Optional[bool] = None
    suspend_t380_present: Optional[bool] = None
    suspend_next_hop_chaining_count: Optional[int] = None
    # cellReselectionPriorities is OPTIONAL and ordered before suspendConfig in
    # RRCRelease-IEs; it is a variable structure this decoder does not yet walk,
    # so when it is present the fields ordered AFTER it (suspendConfig) are left
    # None and this flag records why.
    cell_reselection_priorities_present: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": "NrRrcRelease",
            "log_time": self.log_time,
            "message_type": self.message_type,
        }
        for k in (
            "rrc_transaction_identifier",
            "redirect_rat",
            "redirect_arfcn",
            "redirect_scs_khz",
            "redirect_cn_type",
            "suspend_config",
            "suspend_full_i_rnti",
            "suspend_short_i_rnti",
            "suspend_ran_paging_cycle",
            "suspend_ran_notification_area_present",
            "suspend_t380_present",
            "suspend_next_hop_chaining_count",
            "cell_reselection_priorities_present",
        ):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


def _decode_redirect(r: UperReader, rec: NrRrcRelease) -> None:
    """Decode RedirectedCarrierInfo into ``rec`` (assumes it is present)."""
    ext = r.read_bits(1)  # extensible CHOICE marker
    if ext:
        return  # extension addition — not covered
    branch = r.read_bits(1)  # root CHOICE index: 0=nr, 1=eutra
    if branch == 0:  # CarrierInfoNR (extensible SEQUENCE)
        rec.redirect_rat = "nr"
        seq_ext = r.read_bits(1)  # SEQUENCE extension marker
        smtc_present = r.read_bits(1)  # OPTIONAL bitmap: smtc
        rec.redirect_arfcn = r.read_constrained_int(0, _MAX_NARFCN)  # 22 bits
        rec.redirect_scs_khz = _SCS_KHZ.get(r.read_bits(3))
        _ = (seq_ext, smtc_present)  # remaining fields not decoded
    else:  # RedirectedCarrierInfo-EUTRA (not extensible)
        rec.redirect_rat = "eutra"
        cn_present = r.read_bits(1)  # OPTIONAL bitmap: cnType
        rec.redirect_arfcn = r.read_constrained_int(0, _MAX_EARFCN)  # 18 bits
        if cn_present:
            rec.redirect_cn_type = _CN_TYPE.get(r.read_bits(1))


def _decode_suspend_config(r: UperReader, rec: NrRrcRelease) -> None:
    """Decode SuspendConfig into ``rec`` (assumes it is present).

    SuspendConfig is the RRC-Inactive resume config: the fullI-RNTI /
    shortI-RNTI resume identities, the RAN paging cycle, and (when reachable)
    the nextHopChainingCount. It is an extensible SEQUENCE, so the encoding is
    the extension marker, then the OPTIONAL bitmap for its two root OPTIONALs
    (ran-NotificationAreaInfo, t380), then the mandatory root fields.
    """
    rec.suspend_config = True
    r.read_bits(1)  # SuspendConfig SEQUENCE extension marker
    notif_present = r.read_bits(1)  # ran-NotificationAreaInfo OPTIONAL
    t380_present = r.read_bits(1)   # t380 OPTIONAL
    rec.suspend_ran_notification_area_present = bool(notif_present)
    rec.suspend_t380_present = bool(t380_present)
    rec.suspend_full_i_rnti = r.read_bitstring(_FULL_I_RNTI_BITS)    # 40 bits
    rec.suspend_short_i_rnti = r.read_bitstring(_SHORT_I_RNTI_BITS)  # 24 bits
    rec.suspend_ran_paging_cycle = _PAGING_CYCLE.get(r.read_bits(2))
    # nextHopChainingCount (INTEGER 0..7, 3 bits) follows the two OPTIONAL
    # fields; decode it only when both are absent, else it sits past the
    # ran-NotificationAreaInfo CHOICE / t380 this decoder does not walk.
    if not notif_present and not t380_present:
        rec.suspend_next_hop_chaining_count = r.read_bits(3)


def decode_nr_rrc_release(log_time: int, msg_data: bytes) -> Optional[NrRrcRelease]:
    """Decode the head of a DL-DCCH RRCRelease from full ``msg_data``.

    Returns ``None`` if the message is empty or its leading bits do not resolve
    to a ``c1 = rrcRelease`` DL-DCCH message (defensive — the caller has already
    classified it, so a mismatch means a malformed / unexpected record).
    """
    if not msg_data:
        return None
    r = UperReader(msg_data)
    if r.read_bits(1) != 0:  # DL-DCCH-MessageType CHOICE: 0 = c1
        return None
    if r.read_bits(4) != _DL_DCCH_C1_RRC_RELEASE:  # c1 index
        return None

    rec = NrRrcRelease(log_time=log_time)
    rec.rrc_transaction_identifier = r.read_bits(2)
    if r.read_bits(1) != 0:  # criticalExtensions: 1 = criticalExtensionsFuture
        return rec  # future branch: no IEs
    # RRCRelease-IEs 6-bit OPTIONAL preamble, decoded in field order:
    #   [redirectedCarrierInfo, cellReselectionPriorities, suspendConfig,
    #    deprioritisationReq, lateNonCriticalExtension, nonCriticalExtension]
    preamble = r.read_bits(6)
    redirect_present = (preamble >> 5) & 1
    resel_present = (preamble >> 4) & 1
    suspend_present = (preamble >> 3) & 1
    if redirect_present:
        _decode_redirect(r, rec)
    if resel_present:
        # cellReselectionPriorities is a variable structure ordered before
        # suspendConfig, and this decoder does not yet walk it (0 corpus
        # records exercise it). Record its presence and stop rather than
        # mis-align the bits for the fields that follow it.
        rec.cell_reselection_priorities_present = True
        return rec
    if suspend_present:
        _decode_suspend_config(r, rec)
    return rec
