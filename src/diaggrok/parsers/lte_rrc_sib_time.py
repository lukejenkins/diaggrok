# diaggrok-provenance: re
"""LTE SI-container decoders — SIB8/SIB16 time + SIB5 neighbor cell harvest.

Decodes SystemInformation messages containing SIB8 (CDMA system time) or
SIB16 (UTC network time) to provide absolute time anchors for converting
DIAG modem-boot-relative timestamps to wall clock time. The SI walker is
also reused by ``decode_si_neighbors`` (#N) to harvest SIB5 inter-freq
carriers + neighbor PCIs — Option B incremental decode, building on the
existing :func:`decode_sib5` extractor rather than re-implementing it.

Navigates the ASN.1 UPER-encoded SystemInformation container:
    BCCH-DL-SCH → c1 → systemInformation → criticalExtensions →
    systemInformation-r8 → sib-TypeAndInfo[N] → sib8 or sib16

SIB8 synchronousSystemTime:
    BIT STRING (SIZE (39)) — CDMA system time in 10ms units since
    1980-01-06 00:00:00 UTC (the CDMA/GPS epoch).

SIB16 timeInfoUTC:
    INTEGER — UTC time in seconds since 1900-01-01 00:00:00 UTC
    (NTP epoch), or GPS time depending on network implementation.
    Note: SIB16 is less commonly broadcast than SIB8.

From-scratch UPER decoder — no pycrate dependency.

Reference: 3GPP TS 36.331 §6.3.1 (SIB8, SIB16), ITU-T X.691 (UPER)
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.asn1_helpers import read_open_type_length

# CDMA epoch: January 6, 1980 00:00:00 UTC
_CDMA_EPOCH = datetime(1980, 1, 6, tzinfo=timezone.utc)

# sib-TypeAndInfo CHOICE indices (3GPP TS 36.331)
# The CHOICE is extensible — base alternatives are sib2..sib11 (indices 0..9),
# extension additions add sib12..sib18+ with extension marker encoding.
_SIB_INDEX = {
    0: "sib2",
    1: "sib3",
    2: "sib4",
    3: "sib5",
    4: "sib6",
    5: "sib7",
    6: "sib8",
    7: "sib9",
    8: "sib10",
    9: "sib11",
    # Extension additions (sib12+) use normally-small-number encoding
    # after the extension marker. We handle sib16 as extension index 4.
}


@dataclass
class SibTimeInfo:
    """Decoded time information from SIB8 or SIB16."""
    source: str  # "sib8" or "sib16"
    utc_datetime: datetime  # Absolute UTC time
    raw_value: int  # Raw decoded value before conversion
    diag_ts64: int  # DIAG timestamp of this record (for calibration)

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'SibTimeInfo',
            'source': self.source,
            'utc_iso': self.utc_datetime.isoformat(),
            'utc_timestamp': self.utc_datetime.timestamp(),
            'raw_value': self.raw_value,
            'diag_ts64': self.diag_ts64,
        }

    def epoch_offset(self) -> float:
        """Calculate the epoch offset: Unix timestamp for DIAG ts64=0.

        Usage: unix_time = epoch_offset + (ts64 * 1.25 / 1000)
        """
        return self.utc_datetime.timestamp() - (self.diag_ts64 * 1.25 / 1000)


@dataclass
class SibNeighborInfo:
    """Decoded neighbor-cell info from SIB5 (#N Option B).

    `carriers` is the deduplicated list of inter-frequency EARFCNs the
    serving cell advertises; `neighbors` is the per-PCI list (with the
    EARFCN each PCI is associated with). Both come straight from the
    existing :func:`decode_sib5` extractor; this wrapper just preserves
    the side-effect harvest the SIB8-time path discards.

    Future SIB extensions (SIB3 cellReselectionInfoCommon, SIB2
    defaultPagingCycle) can land additional fields on this dataclass
    without breaking consumers that only read SIB5 today.
    """
    carriers: list[int]            # deduplicated inter-freq EARFCNs
    neighbors: list[tuple[int, int]]  # (pci, earfcn) pairs

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'SibNeighborInfo',
            'carriers': list(self.carriers),
            'neighbors': [{'pci': p, 'earfcn': e} for p, e in self.neighbors],
        }


def _skip_sib_body(r: UperReader, sib_name: str) -> None:
    """Skip over a SIB body we don't care about.

    We can't fully skip arbitrary ASN.1 SEQUENCE content without knowing
    the exact structure. Instead, this function is called when we encounter
    a SIB type we don't need — but since we can't skip it in UPER without
    decoding it, we abort the scan for this message.
    """
    raise _SkipMessage()


class _SkipMessage(Exception):
    """Raised when we hit a SIB we can't skip past."""
    pass


def _decode_sib8_time(r: UperReader) -> int | None:
    """Decode SIB8 → systemTimeInfo → synchronousSystemTime.

    SystemInformationBlockType8 ::= SEQUENCE {
        systemTimeInfo          SystemTimeInfoCDMA2000  OPTIONAL,
        searchWindowSize        INTEGER (0..15)         OPTIONAL,
        parametersHRPD          SEQUENCE { ... }        OPTIONAL,
        parameters1XRTT         SEQUENCE { ... }        OPTIONAL,
        ...
    }

    SystemTimeInfoCDMA2000 ::= SEQUENCE {
        cdma-EUTRA-Synchronisation  BOOLEAN,
        cdma-SystemTime             CHOICE {
            synchronousSystemTime   BIT STRING (SIZE (39)),
            asynchronousSystemTime  BIT STRING (SIZE (49))
        }
    }
    """
    # SIB8 is extensible SEQUENCE with 4 optionals
    has_extension = r.read_bool()
    opt_bitmap = r.read_bits(4)  # systemTimeInfo, searchWindowSize, parametersHRPD, parameters1XRTT

    has_system_time = (opt_bitmap >> 3) & 1
    if not has_system_time:
        return None

    # SystemTimeInfoCDMA2000
    cdma_eutra_sync = r.read_bool()

    # cdma-SystemTime CHOICE { synchronous(0), asynchronous(1) }
    time_choice = r.read_choice(2)

    if time_choice == 0:
        # synchronousSystemTime: BIT STRING (SIZE (39))
        raw_39bit = r.read_bits(39)
        return raw_39bit
    else:
        # asynchronousSystemTime: BIT STRING (SIZE (49))
        # Not commonly used — skip
        return None


def decode_si_time(
    msg_data: bytes,
    diag_ts64: int = 0,
) -> SibTimeInfo | None:
    """Decode SIB8 or SIB16 time from a BCCH-DL-SCH UPER bitstream.

    Navigates the SystemInformation container to find SIB8 or SIB16.
    Uses structural SIB body decoders (lte_rrc_sib_decode.py) to advance
    past preceding SIBs in the list. No external dependencies.

    Returns the first time anchor found, or None.
    """
    if not msg_data or len(msg_data) < 5:
        return None

    try:
        r = UperReader(msg_data)

        # BCCH-DL-SCH → c1(0) → systemInformation(0)
        msg_choice = r.read_choice(2)
        if msg_choice != 0:
            return None
        c1_choice = r.read_choice(2)
        if c1_choice != 0:  # must be systemInformation, not SIB1
            return None

        # SystemInformation → criticalExtensions CHOICE
        # {systemInformation-r8(0), criticalExtensionsFuture(1)}
        crit_choice = r.read_choice(2)
        if crit_choice != 0:
            return None

        # systemInformation-r8 SEQUENCE (extensible)
        has_extension = r.read_bool()

        # sib-TypeAndInfo: SEQUENCE (SIZE (1..maxSIB)) OF CHOICE
        # maxSIB = 32, so length is constrained integer 1..32
        num_sibs = r.read_constrained_int(1, 32)

        for sib_idx in range(num_sibs):
            # Each element: CHOICE { sib2(0), sib3(1), ..., sib11(9), ... }
            # The CHOICE is extensible. Base has 10 alternatives (sib2..sib11).
            # Extension additions start at sib12.

            # Extension marker for the CHOICE
            is_extension = r.read_bool()

            if is_extension:
                # Extension CHOICE: normally-small-number for index,
                # then open type wrapper (length + content).
                # Extension additions: sib12=0, sib13=1, sib14=2,
                # sib15=3, sib16=4, sib17=5, sib18=6, ...

                # Normally-small-number (ITU-T X.691 §11.6):
                # bit=0 → 6-bit value (0..63)
                # bit=1 → semi-constrained whole number
                nsn_flag = r.read_bool()
                if nsn_flag:
                    break  # Large extension index — can't handle
                ext_idx = r.read_bits(6)

                # Open-type wrapper: unconstrained length determinant
                # (ITU-T X.691 §11.9). Toolkit handles the 7-bit / 14-bit /
                # fragmented forms — see #N (no in-decoder bit-twiddling).
                ot_len = read_open_type_length(r)

                if ext_idx == 4:  # sib16
                    # Extract the open type content as bytes.
                    # Read each byte via UperReader to handle non-aligned
                    # bit positions correctly.
                    ot_bits = ot_len * 8
                    if r.bit_pos + ot_bits > len(r.data) * 8:
                        break  # Not enough data
                    ot_bytes = bytes(r.read_bits(8) for _ in range(ot_len))
                    from diaggrok.parsers.lte_rrc_sib16 import decode_sib16
                    sib16 = decode_sib16(ot_bytes, log_time=diag_ts64)
                    # A max-range/corrupt timeInfoUTC decodes but has no usable
                    # UTC (#N); SibTimeInfo exists solely for time calibration
                    # (epoch_offset needs a real timestamp), so skip it rather
                    # than yield a time-anchor with no time.
                    if sib16 is not None and sib16.utc_datetime is not None:
                        return SibTimeInfo(
                            source="sib16",
                            utc_datetime=sib16.utc_datetime,
                            raw_value=sib16.time_info_utc,
                            diag_ts64=diag_ts64,
                        )
                    continue
                else:
                    # Skip this extension SIB's open type content
                    r.skip_bits(ot_len * 8)
                    continue

            # Base CHOICE: 10 alternatives (0..9)
            choice_idx = r.read_constrained_int(0, 9)

            if choice_idx == 6:  # sib8
                raw_time = _decode_sib8_time(r)
                if raw_time is not None:
                    # Canonical 10ms-tick conversion lives in lte_rrc_sib8 so
                    # the two SIB8 code paths can never drift on the unit again
                    # (the 80ms regression that reopened #N).
                    from diaggrok.parsers.lte_rrc_sib8 import cdma_sync_to_utc
                    utc_dt = cdma_sync_to_utc(raw_time)
                    return SibTimeInfo(
                        source="sib8",
                        utc_datetime=utc_dt,
                        raw_value=raw_time,
                        diag_ts64=diag_ts64,
                    )
                break  # SIB8 present but no time info

            else:
                # Walk past this SIB body using the structural decoders
                from diaggrok.parsers.lte_rrc_sib_decode import SIB_DECODERS, DecodeFailed
                decoder = SIB_DECODERS.get(choice_idx)
                if decoder is None:
                    break  # No decoder available
                try:
                    decoder(r)
                    continue  # Body consumed, try next SIB
                except (DecodeFailed, IndexError, ValueError):
                    break  # Decode failed

    except (IndexError, ValueError, _SkipMessage):
        pass

    return None


def decode_si_neighbors(msg_data: bytes) -> SibNeighborInfo | None:
    """Harvest SIB5 inter-freq carriers + neighbor PCIs from a
    BCCH-DL-SCH SystemInformation UPER bitstream (#N Option B).

    Walks the same SI container as :func:`decode_si_time` but
    preserves the :class:`Sib5Neighbors` value returned by
    ``decode_sib5`` (which the time path discards). Returns
    :class:`SibNeighborInfo` whenever SIB5 was present and decoded;
    returns ``None`` for SI messages that don't carry SIB5, that
    fail UPER framing, or that hit a non-skippable SIB before SIB5.

    The companion of :func:`decode_si_time` — keeping the two
    dispatchers as siblings (rather than a single mega-walker) lets
    callers ask exactly the question they care about. A future
    fused decoder can collapse the two passes when a corpus consumer
    needs both anchors at once.

    Cross-check ground truth: the 2020-05-22 QCAT trace at
    sources/qualcomm/community/tool_analysis_qcat/05-22_signaling.txt
    line 8437 evidences carriers = [3350, 3150, 2950] (3 entries,
    q-RxLevMin = -63, cellReselectionPriority = 7, neighCellConfig
    = 10B). Validating this against a real DLF of the same trace is
    blocked on having raw-bytes alongside the .txt — the QCAT export
    we have is decoded-text-only. Captured as a follow-up note on
    #N.
    """
    if not msg_data or len(msg_data) < 5:
        return None

    carriers: list[int] = []
    neighbors: list[tuple[int, int]] = []

    try:
        r = UperReader(msg_data)

        # BCCH-DL-SCH → c1(0) → systemInformation(0)
        if r.read_choice(2) != 0:
            return None
        if r.read_choice(2) != 0:  # must be systemInformation, not SIB1
            return None
        # criticalExtensions CHOICE: pick systemInformation-r8(0)
        if r.read_choice(2) != 0:
            return None

        # systemInformation-r8 SEQUENCE (extensible)
        r.read_bool()  # has_extension — irrelevant for SIB5 harvest

        # sib-TypeAndInfo: SEQUENCE (SIZE (1..32)) OF CHOICE
        num_sibs = r.read_constrained_int(1, 32)

        for _ in range(num_sibs):
            is_extension = r.read_bool()
            if is_extension:
                # Extension SIBs (sib12+): skip body via open-type length.
                # SIB5 is in the base CHOICE so an extension marker here
                # means we've passed any SIB5 in this SI.
                nsn_flag = r.read_bool()
                if nsn_flag:
                    break
                r.read_bits(6)  # ext_idx
                # Open-type length determinant via toolkit (#N).
                ot_len = read_open_type_length(r)
                r.skip_bits(ot_len * 8)
                continue

            # Base CHOICE: 10 alternatives (0..9). idx 3 = sib5.
            choice_idx = r.read_constrained_int(0, 9)

            if choice_idx == 3:  # SIB5 — harvest, don't discard
                from diaggrok.parsers.lte_rrc_sib_decode import decode_sib5, DecodeFailed
                try:
                    result = decode_sib5(r)
                except (DecodeFailed, IndexError, ValueError):
                    break
                for c in result.carriers:
                    if c not in carriers:
                        carriers.append(c)
                for n in result.neighbors:
                    neighbors.append((n.pci, n.earfcn))
                continue

            # Other SIBs — try to skip past them so we can keep looking.
            from diaggrok.parsers.lte_rrc_sib_decode import SIB_DECODERS, DecodeFailed
            decoder = SIB_DECODERS.get(choice_idx)
            if decoder is None:
                break
            try:
                decoder(r)
            except (DecodeFailed, IndexError, ValueError):
                break

    except (IndexError, ValueError, _SkipMessage):
        pass

    if not carriers and not neighbors:
        return None
    return SibNeighborInfo(carriers=carriers, neighbors=neighbors)


@dataclass
class SibExtract:
    """Per-SIB extraction harvest from one SystemInformation message.

    Produced by the fused :func:`decode_si_sibs` walk (#N/#N/#N —
    the "future fused decoder" anticipated by the sibling-walker notes
    above). Any subset of fields may be populated; a field is ``None``
    when its SIB was absent from the message or failed to decode.
    """
    sib2: Any | None = None    # Sib2AccessParams (access barring / RACH)
    sib3: Any | None = None    # Sib3ReselParams (cell reselection)
    sib4: Any | None = None    # Sib4Neighbors (intra-freq neighbors)
    sib5: Any | None = None    # Sib5Neighbors (inter-freq carriers, #N)
    sib6: Any | None = None    # LteSIB6 (UTRAN/3G neighbor freqs, #N)
    sib7: Any | None = None    # LteSIB7 (GERAN/2G neighbor freqs, #N)
    sib8: Any | None = None    # SibTimeInfo (CDMA2000 system time, #N)
    sib16: Any | None = None   # LteSIB16Time (UTC/GPS network time, #N)
    sib24: Any | None = None   # Sib24NrReselection (NR cell reselection, #N)

    def any_present(self) -> bool:
        return (self.sib2 is not None or self.sib3 is not None
                or self.sib4 is not None or self.sib5 is not None
                or self.sib6 is not None or self.sib7 is not None
                or self.sib8 is not None or self.sib16 is not None
                or self.sib24 is not None)


def decode_si_sibs(msg_data: bytes) -> SibExtract | None:
    """Fused SI-container walk — harvest SIB2..SIB7 + SIB16 in ONE pass
    (#N / #N / #N / #N / #N / #N / #N / #N).

    SIB2 and SIB3 routinely ride in the SAME SystemInformation message
    (both scheduling-mandatory and small), so per-SIB sibling walkers
    would re-decode the container once per SIB. This walker preserves
    the extraction results of ``decode_sib2`` / ``decode_sib3`` / ``decode_sib4``
    (which the time / neighbor paths discard) in a single container walk.

    Returns a :class:`SibExtract` when at least one target SIB was
    harvested; ``None`` for SIB1 / paging / malformed messages or SI
    messages carrying none of the targets. Extension-series SIBs
    (sib12+) are skipped via their open-type length determinant; a
    failed skip of an intervening SIB ends the walk but keeps whatever
    was already harvested (partial harvest beats none).
    """
    from diaggrok.parsers.lte_rrc_sib_decode import (
        SIB_DECODERS, DecodeFailed, decode_sib2, decode_sib3, decode_sib4, decode_sib5,
    )
    from diaggrok.parsers.lte_rrc_sib6 import extract_sib6
    from diaggrok.parsers.lte_rrc_sib7 import extract_sib7
    if not msg_data or len(msg_data) < 2:
        return None

    out = SibExtract()
    try:
        r = UperReader(msg_data)
        # BCCH-DL-SCH → c1(0) → systemInformation(0)
        if r.read_choice(2) != 0:
            return None
        if r.read_choice(2) != 0:  # must be systemInformation, not SIB1
            return None
        if r.read_choice(2) != 0:  # criticalExtensions → systemInformation-r8
            return None

        r.read_bool()  # systemInformation-r8 extension marker
        num_sibs = r.read_constrained_int(1, 32)

        for _ in range(num_sibs):
            if r.read_bool():
                # Extension SIBs (sib12+): body is an open type. sib16
                # (ext_idx 4 — NOT the base-CHOICE index 4 that is SIB6)
                # carries network time (#N); decode its open-type bytes
                # in-place. Any other extension SIB is skipped via its length
                # determinant and the walk continues (they may precede a
                # base-alternative SIB in the schedule).
                nsn_flag = r.read_bool()
                if nsn_flag:
                    break
                ext_idx = r.read_bits(6)
                ot_len = read_open_type_length(r)
                fits = r.bit_pos + ot_len * 8 <= len(r.data) * 8
                if ext_idx in (4, 10) and fits:
                    # Read the open type as bytes (byte-exact advance of the
                    # reader regardless of how far the interior decode consumes).
                    # ext_idx 4 = sib16 (network time, #N); ext_idx 10 = sib24
                    # (NR cell reselection, #N).
                    ot_bytes = bytes(r.read_bits(8) for _ in range(ot_len))
                    if ext_idx == 4:
                        from diaggrok.parsers.lte_rrc_sib16 import decode_sib16
                        out.sib16 = decode_sib16(ot_bytes)
                    else:
                        from diaggrok.parsers.lte_rrc_sib24 import decode_sib24
                        out.sib24 = decode_sib24(ot_bytes)
                else:
                    r.skip_bits(ot_len * 8)
                continue
            choice_idx = r.read_constrained_int(0, 9)
            try:
                if choice_idx == 0:      # SIB2 — extract, don't discard
                    out.sib2 = decode_sib2(r)
                elif choice_idx == 1:    # SIB3 — extract (#N)
                    out.sib3 = decode_sib3(r)
                elif choice_idx == 2:    # SIB4 — extract (#N)
                    out.sib4 = decode_sib4(r)
                elif choice_idx == 3:    # SIB5 — inter-freq extract (#N)
                    out.sib5 = decode_sib5(r)
                elif choice_idx == 4:    # SIB6 — full-field extract (#N)
                    out.sib6 = extract_sib6(r)
                elif choice_idx == 5:    # SIB7 — GERAN full-field extract (#N)
                    out.sib7 = extract_sib7(r)
                elif choice_idx == 6:    # SIB8 — CDMA system-time anchor (#N)
                    raw_time = _decode_sib8_time(r)
                    if raw_time is not None:
                        from diaggrok.parsers.lte_rrc_sib8 import cdma_sync_to_utc
                        out.sib8 = SibTimeInfo(
                            source="sib8",
                            utc_datetime=cdma_sync_to_utc(raw_time),
                            raw_value=raw_time,
                            diag_ts64=0,
                        )
                    # The SIB8 body carries optional HRPD/1XRTT sub-SEQUENCEs we
                    # don't fully decode, so we can't reliably advance past it to
                    # a following SIB. Stop the walk (partial harvest kept) — in
                    # the observed corpus SIB8 is the last element ([sib5, sib8]).
                    break
                else:
                    decoder = SIB_DECODERS.get(choice_idx)
                    if decoder is None:
                        break
                    decoder(r)
            except (DecodeFailed, IndexError, ValueError):
                break
    except (IndexError, ValueError):
        pass

    return out if out.any_present() else None


def decode_si_sib2(msg_data: bytes):
    """Extract LTE SIB2 access-barring / RACH / common-radio-config params
    from a BCCH-DL-SCH SystemInformation UPER bitstream (#N / #N).

    Thin wrapper over the fused :func:`decode_si_sibs` walk, kept for the
    established API: returns the :class:`Sib2AccessParams` whenever SIB2 is
    present and decoded; ``None`` otherwise.

    In the observed 0xB0C0 corpus SIB2 rides as sib-TypeAndInfo element 0 in
    every SIB2-bearing message (validated field-for-field against the stock
    tshark ``lte-rrc`` dissector across 5 firmwares / 3 chipsets), so the
    walk reaches it without a preceding skip.
    """
    result = decode_si_sibs(msg_data)
    return result.sib2 if result is not None else None


def decode_si_sib5(msg_data: bytes):
    """Extract the full LTE SIB5 inter-frequency reselection info from a
    BCCH-DL-SCH SystemInformation UPER bitstream (#N / #N).

    Thin wrapper over the fused :func:`decode_si_sibs` walk, matching the
    per-SIB API: returns the complete
    :class:`~diaggrok.parsers.lte_rrc_sib_decode.Sib5Neighbors` (per-carrier
    q-RxLevMin / threshX / priority / neighbour / excluded lists plus the
    v8h0/v9e0 multi-band overlays and Ext-r12 additional carriers) whenever
    SIB5 is present and decoded; ``None`` otherwise — where
    :func:`decode_si_neighbors` flattens to carriers + (pci, earfcn) pairs
    for the WiGLE path. SIB5 is ``sib-TypeAndInfo`` CHOICE index 3.
    """
    result = decode_si_sibs(msg_data)
    return result.sib5 if result is not None else None


def decode_si_sib6(msg_data: bytes):
    """Extract LTE SIB6 UTRAN (3G) neighbor frequencies from a BCCH-DL-SCH
    SystemInformation UPER bitstream (#N).

    Thin wrapper over the fused :func:`decode_si_sibs` walk, kept for the
    per-SIB API the 0xB0C0 parser calls: returns the decoded
    :class:`~diaggrok.parsers.lte_rrc_sib6.LteSIB6` whenever SIB6 is present
    and decoded; ``None`` otherwise. SIB6 is ``sib-TypeAndInfo`` CHOICE index 4.

    NOTE (#N): SIB6 carries 3G/UTRAN neighbor lists, broadcast only where an
    operational UMTS network exists. It is ABSENT from the entire on-host corpus
    (0/118 RM520N-GL captures; US 3G sunset 2022), so this path is validated
    only against pycrate-encoded vectors (test_lte_rrc_sib6.py), not live
    hardware. Kept wired so a future 3G-neighbor capture (e.g. international) is
    extracted automatically, mirroring the SIB2 integration.
    """
    result = decode_si_sibs(msg_data)
    return result.sib6 if result is not None else None


def decode_si_sib7(msg_data: bytes):
    """Extract LTE SIB7 GERAN (2G) neighbor frequencies from a BCCH-DL-SCH
    SystemInformation UPER bitstream (#N).

    Thin wrapper over the fused :func:`decode_si_sibs` walk, matching the
    per-SIB API the 0xB0C0 parser calls: returns the decoded
    :class:`~diaggrok.parsers.lte_rrc_sib7.LteSIB7` whenever SIB7 is present
    and decoded; ``None`` otherwise. SIB7 is ``sib-TypeAndInfo`` CHOICE index 5.

    NOTE (#N): SIB7 carries 2G/GERAN neighbor lists, broadcast only where an
    operational GSM network exists. It is ABSENT from the on-host RM520N-GL corpus
    (0 SIB7 across 2886 0xB0C0 records in 45 SI-bearing captures; US 2G sunset —
    AT&T 2017, T-Mobile 2024 — while the same scan saw 47 SIB5 records, proving the
    walk is live), so this path is validated only against pycrate-encoded vectors
    (test_lte_rrc_sib7.py), not live hardware. Kept wired so a future 2G-neighbor
    capture (e.g. international) is extracted automatically, mirroring SIB6.
    """
    result = decode_si_sibs(msg_data)
    return result.sib7 if result is not None else None


def decode_si_sib16(msg_data: bytes):
    """Extract LTE SIB16 network time (UTC/GPS) from a BCCH-DL-SCH
    SystemInformation UPER bitstream (#N).

    Thin wrapper over the fused :func:`decode_si_sibs` walk, mirroring the
    per-SIB API the 0xB0C0 parser calls: returns the decoded
    :class:`~diaggrok.parsers.lte_rrc_sib16.LteSIB16Time` (full fields —
    time_info_utc / utc_datetime / leap_seconds / dst / local_time_offset)
    whenever SIB16 is present and decoded; ``None`` otherwise. SIB16 is
    ``sib-TypeAndInfo`` EXTENSION index 4 (distinct from the base-CHOICE
    index 4 that is SIB6).

    NOTE (#N): SIB16 carries UTC/GPS network time, broadcast only where the
    network schedules it. It is ABSENT from the entire on-host corpus
    (0/8037 BCCH-DL-SCH records across 667 captures as of 2026-07-02; US
    operators here anchor time via SIB8 CDMA / GNSS), so this path is
    validated only against pycrate-encoded vectors (test_lte_rrc_sib16.py),
    not live hardware — mirroring the SIB6 integration. Kept wired so a future
    SIB16-bearing capture is extracted automatically with all fields.
    """
    result = decode_si_sibs(msg_data)
    return result.sib16 if result is not None else None


def decode_si_sib24(msg_data: bytes):
    """Extract LTE SIB24 NR (5G) cell-reselection info from a BCCH-DL-SCH
    SystemInformation UPER bitstream (#N).

    Thin wrapper over the fused :func:`decode_si_sibs` walk, mirroring the
    per-SIB API the 0xB0C0 parser calls: returns the decoded
    :class:`~diaggrok.parsers.lte_rrc_sib24.Sib24NrReselection` (per-carrier
    ARFCN-NR / band list / reselection priority + sub-priority / threshX /
    q-RxLevMin / p-MaxNR / q-QualMin / SSB spacing + duration, plus
    t-ReselectionNR) whenever SIB24 is present and decoded; ``None`` otherwise.
    SIB24 is ``sib-TypeAndInfo`` EXTENSION index 10.

    SIB24 presence is already flagged by the 0xB0C0 ``sib_mask`` bit24 (#N);
    the SDX62 RM520N-GL broadcasts it in the corpus (78 records in one
    wardriving capture). Validated field-for-field against pycrate's TS 36.331
    v15 decode on the real RM520N-GL vector plus synthetic all-optional and
    multi-carrier vectors (test_lte_rrc_sib24.py).
    """
    result = decode_si_sibs(msg_data)
    return result.sib24 if result is not None else None
