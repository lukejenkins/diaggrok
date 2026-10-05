# diaggrok-provenance: re
"""LTE RRC SIB9 decoder — Home eNB (HNB) name.

Decodes ``SystemInformationBlockType9`` to extract ``hnb-Name``, the
operator/owner-chosen identity string a Home eNodeB (LTE femtocell) broadcasts.
It is the LTE analogue of a Wi-Fi SSID: a human-readable name attached to a
specific cell, hence WiGLE-direct.

From-scratch UPER decoder — no pycrate or other ASN.1 library dependency
(pycrate is LGPL-2.1+ and is used only as an offline validation oracle).

ASN.1 definition (3GPP TS 36.331 §6.3.1):

    SystemInformationBlockType9 ::= SEQUENCE {
        hnb-Name                    OCTET STRING (SIZE (1..48))     OPTIONAL,
        ...,
        lateNonCriticalExtension    OCTET STRING                    OPTIONAL
    }

Wire layout (UPER, unaligned — confirmed bit-for-bit against pycrate):

    bit 0        extension marker (1 => lateNonCriticalExtension block follows)
    bit 1        hnb-Name presence
    bits 2..7    length determinant, 6 bits, value = n - 1  (SIZE (1..48))
    next n*8     the octets, bit-packed — UPER never octet-aligns

e.g. ``0x45`` = ``0b0_1_000101`` → no extension, name present, n = 6 → the six
octets that follow are ``b"HomeNB"``.

**SIB9 is a base-CHOICE SIB (``sib-TypeAndInfo`` index 7), not an
extension-series open type.** Extension-series SIBs (sib12+, e.g. SIB16 at
ext_idx 4 and SIB24 at ext_idx 10) carry an open-type length determinant, so the
container walk can step over one it does not understand. A base-CHOICE
alternative has no such prefix: if it is not decoded, the walk cannot find where
it ends and must stop. Without a SIB9 decoder, index 7 hits
``SIB_DECODERS.get(7) is None -> break`` in
:func:`~diaggrok.parsers.lte_rrc_sib_time.decode_si_sibs`, so a SIB9 anywhere in
the schedule **truncates the harvest** — every SIB after it in the same
SystemInformation message is lost. Decoding SIB9 recovers both the name and
the SIBs that follow it.

hnb-Name is specified as a UTF-8 string (TS 36.331 §6.3.1 field description), so
the raw octets are exposed alongside the decoded text.

**Do NOT tighten that to `errors='strict'`: real broadcasts violate the UTF-8
requirement.** Across 597 0xB0C0-bearing captures /
48,549 records: **29 records carry a SIB9**, on three vendors, three chipsets and
three wire versions —

===========================  ==========  =============================================
modem / chipset / version    n           decoded ``hnb_name``
===========================  ==========  =============================================
Sierra EM7565 MDM9x50 v15    12          ``et-124-cbs1``     (11 B, valid UTF-8)
Telit LM960 SDX20 v20         2          ``et-124-cbs1``     (11 B, valid UTF-8)
SimCom SIM8202G-M2 SDX55 v27  5          ``ty-outdoor-cbs1-p`` + ``f7 21 7a`` (20 B)
SimCom SIM8202G-M2 SDX55 v27  1          ``mf-outdoor-cbs3-p`` + 15 B (32 B)
===========================  ==========  =============================================

The two SimCom names are **not** a misparse — byte-accounting proves the length
determinant is right. On the 20-octet record the 26-byte PDU is
14 bits preamble + 8 bits (ext + presence + 6-bit length) + 160 bits of name =
182 of 208 bits, leaving 26 bits of trailing padding; reading it as 17 octets
instead would strand three further name bytes (``c3 dc 85``) as unexplained
content. Those operators' Home eNBs simply broadcast a name whose tail is not
valid UTF-8. Hence ``errors='replace'`` **and** the retained ``hnb_name_raw``:
strict decoding would fail on 6 of the 29 real records, and dropping the raw
bytes would make the deviation unrecoverable.

Cross-validation: ``et-124-cbs1`` decodes byte-identically on **two different
vendors, chipsets and wire versions** (EM7565 v15 and LM960 v20) — two
independent modem implementations recovering the same broadcast. And the
firmware's own header bitmap agrees: ``sib_mask`` bit 9 is set on **29/29** of
exactly these records and on no others, an independent confirmation from
a different part of the record than the ASN.1 walk.

Reference: 3GPP TS 36.331 v16.x, ITU-T X.691 (UPER)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.parsers.asn1_helpers import skip_extension_additions
from diaggrok.parsers.lte_rrc_sib import UperReader

# OCTET STRING (SIZE (1..48)) — TS 36.331. The 6-bit length determinant can
# physically encode n up to 64, so the upper bound is checked, not assumed:
# an n in 49..64 means the reader is not positioned on a SIB9.
HNB_NAME_MIN_OCTETS = 1
HNB_NAME_MAX_OCTETS = 48


@dataclass
class LteSIB9:
    """Decoded SIB9 — Home eNB (femtocell) name."""
    log_time: int = 0
    # UTF-8-decoded hnb-Name; None when the OPTIONAL field is absent. Undecodable
    # bytes render as U+FFFD rather than failing — hnb_name_raw stays authoritative.
    hnb_name: str | None = None
    # The hnb-Name octets exactly as broadcast; None when the field is absent.
    hnb_name_raw: bytes | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'LteSIB9',
            'log_time': self.log_time,
        }
        # Present-only: an absent hnb-Name is a legal, meaningful SIB9 (the cell
        # advertises itself as an HNB without naming itself), so the keys are
        # omitted rather than emitted as null.
        if self.hnb_name_raw is not None:
            d['hnb_name'] = self.hnb_name
            d['hnb_name_hex'] = self.hnb_name_raw.hex()
        return d


def extract_sib9(r: UperReader, log_time: int = 0) -> LteSIB9:
    """Full-field extraction of a SIB9 body from an EXISTING UperReader.

    The reader must be positioned at the first bit of the
    ``SystemInformationBlockType9`` body. Used both by :func:`decode_sib9`
    (fresh reader over a bare body) and by the SI-container walker
    :func:`~diaggrok.parsers.lte_rrc_sib_time.decode_si_sibs` (reader already
    advanced past the BCCH-DL-SCH / systemInformation preamble and any preceding
    SIBs). On return the reader sits immediately after the SIB9 body, so the
    walk can continue into the next scheduled SIB.

    Raises ``ValueError`` on a length outside SIZE (1..48) or a name that runs
    past the end of the buffer (callers catch and self-gate).
    """
    result = LteSIB9(log_time=log_time)

    has_ext = r.read_bool()
    has_name = r.read_bool()

    if has_name:
        n = r.read_constrained_int(HNB_NAME_MIN_OCTETS, HNB_NAME_MAX_OCTETS)
        if n > HNB_NAME_MAX_OCTETS:
            raise ValueError(f'hnb-Name length {n} exceeds SIZE (1..48)')
        # UperReader.read_bits zero-PADS past the end of the buffer instead of
        # raising, so a truncated body would otherwise decode as a NUL-padded
        # name that looks like a successful parse. Bound-check before reading.
        if r.bit_pos + n * 8 > len(r.data) * 8:
            raise ValueError(f'hnb-Name of {n} octets runs past the payload')
        raw = bytes(r.read_bits(8) for _ in range(n))
        result.hnb_name_raw = raw
        result.hnb_name = raw.decode('utf-8', errors='replace')

    if has_ext:
        skip_extension_additions(r)

    return result


def decode_sib9(log_time: int, data: bytes) -> LteSIB9 | None:
    """Decode SIB9 from a raw UPER-encoded payload.

    Expects the bare SIB9 body (not wrapped in BCCH-DL-SCH or an SI container).
    Returns None if the payload is empty or decoding fails.

    Args:
        log_time: DIAG log timestamp (modem-boot-relative).
        data: Raw UPER-encoded SIB9 payload bytes.

    Returns:
        LteSIB9 with the decoded Home eNB name, or None on failure.
    """
    # Minimum SIB9: 1 ext bit + 1 optional bit = 2 bits => 1 byte (hnb-Name absent).
    if not data:
        return None

    try:
        return extract_sib9(UperReader(data), log_time)
    except (IndexError, ValueError):
        return None
