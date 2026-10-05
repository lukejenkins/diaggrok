# diaggrok-provenance: re
"""Reusable 3GPP TS 24.007 §11 L3 IEI/TLV NAS message-body decoder.

This is the NAS-layer analogue of the ``uper.py`` / ``asn1_helpers.py``
ASN.1/UPER toolkit: build the message-body decode primitives **once** so
every per-code NAS body decoder (LTE EMM/ESM, NR 5GMM/5GSM) re-uses the same
engine instead of hand-rolling an IE walk each time.

Skipped by ``parsers/__init__.py`` auto-discovery because of the leading
underscore: this is a shared helper, not a registered ``@register``'d parser.

────────────────────────────────────────────────────────────────────────
Why a *table-driven* walker (and not a universal one)
────────────────────────────────────────────────────────────────────────
Unlike a UPER bitstream — which is self-delimiting, so a generic reader can
walk it with no schema — TS 24.007 §11 L3 information elements are **not
self-describing**. Whether an optional IE is encoded as TV (type-3, fixed
length), TLV (type-4, 1-octet length), TLV-E (type-6, 2-octet length), a
half-octet type-1 TV, or a type-2 T (tag only) is a property of *that IEI
in that message*, defined by a per-message IE table in the spec — it is not
recoverable from the bytes alone.

So the unit of reuse is:

  1. **Format primitives** (:func:`read_tlv`, :func:`read_tlv_e`,
     :func:`read_tv`, :func:`read_t`, :func:`read_tv_short`, :func:`read_lv`,
     :func:`read_lv_e`) — each consumes exactly one wire shape and returns
     ``(value, next_pos)``. Used directly when walking *mandatory* IEs (which
     appear in a fixed order with no IEI).

  2. A **table-driven optional-IE walker** (:func:`walk_optional_ies`) that
     takes ``{iei: IeSpec(...)}`` and dispatches each encountered IEI to the
     right primitive, yielding ``(iei, value, recognized)``. Unknown IEIs are
     skipped best-effort using the bit-8 rule below so a single unexpected IE
     can't desync the rest of the walk.

  3. **Common IE value codecs** (:func:`decode_apn`,
     :func:`decode_eps_mobile_identity`, …) shared across many messages.

────────────────────────────────────────────────────────────────────────
The bit-8 rule (TS 24.007 §11.2.4) — how an IEI's own value picks its format
────────────────────────────────────────────────────────────────────────
For the *unknown-IEI* skip path only (known IEIs use the table):

  * IEI bit 8 == 1  → the IE is type-1 (half-octet TV, total 1 octet) or
    type-2 (T, total 1 octet). Either way it is a **single octet** — safe to
    skip 1.
  * IEI bit 8 == 0  → the IE is type-3 (TV, fixed len), type-4 (TLV) or
    type-6 (TLV-E). We can't know the fixed length of an unknown type-3, but
    type-4 (TLV) dominates the optional space, so we assume TLV and skip
    ``2 + L``. This matches the historical best-effort skip in
    ``lte_nas_emm.py`` (which this module now backs).

References: 3GPP TS 24.007 §11.2.1-§11.2.4 (L3 IE formats), TS 24.301
(EPS NAS), TS 24.008 (legacy GMM/MM IE reuse), TS 23.003 §9 (APN).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Iterator


class IeFormat(enum.Enum):
    """Wire format of a TS 24.007 §11 L3 information element."""
    T = "T"          # type-2: IEI only, no value octets
    TV = "TV"        # type-3: IEI + fixed-length value (length is IE-specific)
    TV_SHORT = "TV1"  # type-1: half-octet — IEI in bits 8-5, value in bits 4-1
    LV = "LV"        # length(1) + value — mandatory IE, no IEI
    TLV = "TLV"      # type-4: IEI + length(1) + value
    LV_E = "LVE"     # length(2, big-endian) + value — mandatory extended IE
    TLV_E = "TLVE"   # type-6: IEI + length(2, big-endian) + value


@dataclass(frozen=True)
class IeSpec:
    """One row of a per-message IE table.

    ``fmt`` is the wire format; ``length`` is required for :attr:`IeFormat.TV`
    (type-3 fixed-length) IEs and ignored otherwise — for TV the value length
    is fixed by the spec and not on the wire, so the walker has to be told.
    """
    fmt: IeFormat
    length: int | None = None


class NasL3Error(ValueError):
    """Raised when a primitive read would run off the end of the buffer."""


# ── Low-level format primitives ───────────────────────────────────────────
# Each takes (body, pos) and returns the decoded piece plus the next cursor
# position. They raise NasL3Error rather than returning None so a per-message
# decoder can choose between strict (let it propagate) and tolerant (catch)
# handling — mirroring how lte_nas_emm.py wants to bail out of the IE loop
# but keep whatever it already decoded.


def read_t(body: bytes, pos: int) -> tuple[int, int]:
    """type-2 (T): a lone IEI octet. Returns (iei, next_pos)."""
    if pos >= len(body):
        raise NasL3Error("read_t: past end of body")
    return body[pos], pos + 1


def read_tv_short(body: bytes, pos: int) -> tuple[int, int, int]:
    """type-1 (TV, half-octet): IEI in bits 8-5, value in bits 4-1.

    Returns (iei_nibble, value_nibble, next_pos). The IEI of a type-1 IE is
    the **high** nibble (e.g. the NAS key-set-identifier IE 0xB-, or the
    ciphering-key-sequence IE), and the value occupies the low nibble.
    """
    if pos >= len(body):
        raise NasL3Error("read_tv_short: past end of body")
    octet = body[pos]
    return (octet >> 4) & 0x0F, octet & 0x0F, pos + 1


def read_tv(body: bytes, pos: int, value_len: int) -> tuple[int, bytes, int]:
    """type-3 (TV): IEI octet + ``value_len`` value octets.

    Returns (iei, value, next_pos). ``value_len`` is the spec-fixed length;
    it is NOT read from the wire (that would be TLV).
    """
    if pos + 1 + value_len > len(body):
        raise NasL3Error("read_tv: value runs past end of body")
    iei = body[pos]
    value = body[pos + 1:pos + 1 + value_len]
    return iei, value, pos + 1 + value_len


def read_tlv(body: bytes, pos: int) -> tuple[int, bytes, int]:
    """type-4 (TLV): IEI + 1-octet length + value. Returns (iei, value, next)."""
    if pos + 2 > len(body):
        raise NasL3Error("read_tlv: no room for IEI+length")
    iei = body[pos]
    length = body[pos + 1]
    if pos + 2 + length > len(body):
        raise NasL3Error("read_tlv: value runs past end of body")
    value = body[pos + 2:pos + 2 + length]
    return iei, value, pos + 2 + length


def read_tlv_e(body: bytes, pos: int) -> tuple[int, bytes, int]:
    """type-6 (TLV-E): IEI + 2-octet (big-endian) length + value.

    The extended length variant (used by large 5GS/EPS containers — e.g.
    the NAS message container, EPS bearer context, PDU session containers).
    Returns (iei, value, next_pos).
    """
    if pos + 3 > len(body):
        raise NasL3Error("read_tlv_e: no room for IEI+length16")
    iei = body[pos]
    length = (body[pos + 1] << 8) | body[pos + 2]
    if pos + 3 + length > len(body):
        raise NasL3Error("read_tlv_e: value runs past end of body")
    value = body[pos + 3:pos + 3 + length]
    return iei, value, pos + 3 + length


def read_lv(body: bytes, pos: int) -> tuple[bytes, int]:
    """type-4 LV (no IEI): 1-octet length + value. Returns (value, next_pos).

    Used for *mandatory* IEs encoded LV (e.g. EPS mobile identity in some
    messages, the ESM ``QoS`` IE) where there is no IEI on the wire.
    """
    if pos >= len(body):
        raise NasL3Error("read_lv: no room for length")
    length = body[pos]
    if pos + 1 + length > len(body):
        raise NasL3Error("read_lv: value runs past end of body")
    return body[pos + 1:pos + 1 + length], pos + 1 + length


def read_lv_e(body: bytes, pos: int) -> tuple[bytes, int]:
    """type-6 LV-E (no IEI): 2-octet (big-endian) length + value."""
    if pos + 2 > len(body):
        raise NasL3Error("read_lv_e: no room for length16")
    length = (body[pos] << 8) | body[pos + 1]
    if pos + 2 + length > len(body):
        raise NasL3Error("read_lv_e: value runs past end of body")
    return body[pos + 2:pos + 2 + length], pos + 2 + length


# ── Table-driven optional-IE walker ───────────────────────────────────────


def walk_optional_ies(
    body: bytes,
    table: dict[int, IeSpec],
) -> Iterator[tuple[int, bytes, bool]]:
    """Walk the optional-IE part of an L3 message body.

    ``body`` is the bytes AFTER all mandatory fields (i.e. the caller has
    already consumed the message header + any mandatory IEs). ``table`` maps
    each known IEI to its :class:`IeSpec`.

    Yields ``(iei, value, recognized)`` for each IE in wire order:

      * ``recognized=True``  — IEI was in ``table``; ``value`` is the decoded
        value bytes (empty for type-1/type-2, whose semantic value the caller
        recovers from the low nibble / presence via :func:`read_tv_short` /
        the IEI itself — for type-1 the value nibble is returned as a single
        byte ``bytes([nibble])`` so callers get a uniform ``bytes`` value).
      * ``recognized=False`` — unknown IEI, skipped best-effort via the bit-8
        rule. ``value`` is empty; the caller typically records the IEI for
        forensic visibility.

    The walk stops cleanly (StopIteration) when a primitive read would run
    off the end — a truncated trailing IE ends the stream rather than raising,
    so a partially-captured record still yields everything before the cut.
    """
    pos = 0
    n = len(body)
    while pos < n:
        octet = body[pos]
        # Full-octet match first (TLV / TV / TLV-E / T — IEI is the whole
        # octet). For a type-1 half-octet IE the IEI is only the HIGH nibble,
        # so fall back to a nibble lookup when bit-8 is set and the table row
        # is a TV_SHORT. This two-step lookup is what lets one table mix
        # type-1 IEs (e.g. a key-set-identifier) with type-3/4 IEs.
        iei = octet
        spec = table.get(octet)
        if spec is None and (octet & 0x80):
            nib_spec = table.get((octet >> 4) & 0x0F)
            if nib_spec is not None and nib_spec.fmt is IeFormat.TV_SHORT:
                spec = nib_spec
                iei = (octet >> 4) & 0x0F
        if spec is None:
            # Unknown IEI: bit-8 rule for a safe skip.
            if octet & 0x80:
                # type-1 (half-octet TV) or type-2 (T): single octet.
                pos += 1
            else:
                # Assume type-4 TLV (the common optional case).
                try:
                    _, _, pos = read_tlv(body, pos)
                except NasL3Error:
                    return
            yield octet, b"", False
            continue
        try:
            if spec.fmt is IeFormat.TLV:
                _, value, pos = read_tlv(body, pos)
            elif spec.fmt is IeFormat.TLV_E:
                _, value, pos = read_tlv_e(body, pos)
            elif spec.fmt is IeFormat.TV:
                if spec.length is None:
                    raise NasL3Error("TV IeSpec requires a fixed length")
                _, value, pos = read_tv(body, pos, spec.length)
            elif spec.fmt is IeFormat.TV_SHORT:
                _, nibble, pos = read_tv_short(body, pos)
                value = bytes([nibble])
            elif spec.fmt is IeFormat.T:
                _, pos = read_t(body, pos)
                value = b""
            else:
                raise NasL3Error(
                    f"format {spec.fmt} is mandatory-only; not valid in an "
                    "optional-IE table"
                )
        except NasL3Error:
            return
        yield iei, value, True


# ── Common IE value codecs ────────────────────────────────────────────────


def decode_apn(value: bytes) -> str | None:
    """Decode an Access Point Name IE value (TS 24.301 §9.9.4.1 → TS 23.003 §9).

    The value is a sequence of DNS labels in length-prefixed form:
    ``L₀ <L₀ bytes> L₁ <L₁ bytes> …`` — exactly the wire form of a DNS name
    without the trailing root label. Joined with ``.``.

    Returns the dotted APN string, or ``None`` if the value isn't a clean
    label run (every label 1..63 bytes of printable ASCII and the whole value
    consumed). Strict consumption is what separates this from the tolerant
    *locator* in ``diag_0xb0e1.py``: here the caller has already isolated the
    IE value via the TLV walker, so a malformed value should fail rather than
    salvage a partial run.
    """
    if not value:
        return None
    labels: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        length = value[i]
        if not (1 <= length <= 63) or i + 1 + length > n:
            return None
        chunk = value[i + 1:i + 1 + length]
        if not all(0x21 <= b <= 0x7E for b in chunk):
            return None
        labels.append(chunk.decode("ascii"))
        i += 1 + length
    if i != n or not labels:
        return None
    return ".".join(labels)


def _decode_plmn_tbcd(b3: bytes) -> dict[str, str] | None:
    """Decode a 3-octet TS 24.008 §10.5.1.3 PLMN (MCC/MNC), TBCD-coded.

    Layout (each nibble is a BCD digit, low nibble first):
        octet 1: MCC digit 2 | MCC digit 1
        octet 2: MNC digit 3 | MCC digit 3
        octet 3: MNC digit 2 | MNC digit 1
    MNC digit 3 == 0xF means a 2-digit MNC.

    This is the NAS/L3 BCD form — distinct from the UPER per-digit PLMN in
    ``asn1_helpers.decode_plmn_identity`` (RRC). Returns {'mcc','mnc'}.
    """
    if len(b3) < 3:
        return None
    mcc_d1 = b3[0] & 0x0F
    mcc_d2 = (b3[0] >> 4) & 0x0F
    mcc_d3 = b3[1] & 0x0F
    mnc_d3 = (b3[1] >> 4) & 0x0F
    mnc_d1 = b3[2] & 0x0F
    mnc_d2 = (b3[2] >> 4) & 0x0F
    mcc = f"{mcc_d1}{mcc_d2}{mcc_d3}"
    mnc = f"{mnc_d1}{mnc_d2}" if mnc_d3 == 0x0F else f"{mnc_d1}{mnc_d2}{mnc_d3}"
    return {"mcc": mcc, "mnc": mnc}


# TS 24.301 §9.9.3.12 — EPS mobile identity "type of identity" (low 3 bits).
_EPS_ID_TYPE_GUTI = 0x6
_EPS_ID_TYPE_IMSI = 0x1
_EPS_ID_TYPE_IMEI = 0x3


def decode_eps_mobile_identity(value: bytes) -> dict[str, Any] | None:
    """Decode an EPS Mobile Identity IE value (TS 24.301 §9.9.3.12).

    Handles the two forms that actually carry useful identity in observed captures:

      * **GUTI** (type 0b110): the headline field of an Attach/TAU Accept —
        ``{type:'guti', mcc, mnc, mme_group_id, mme_code, m_tmsi}``. Wire:
        octet 1 = 0xF? type byte, octets 2-4 = PLMN (TBCD), octets 5-6 =
        MME Group ID (u16 BE), octet 7 = MME Code, octets 8-11 = M-TMSI (u32 BE).
      * **IMSI/IMEI** (types 0b001 / 0b011): digit-packed BCD (odd/even
        indication in bit 4 of octet 1) → ``{type:'imsi'|'imei', digits}``.

    Returns a dict, or ``None`` if the value is too short / an unhandled type
    (e.g. IMEISV, or the GUMMEI-only form). Unknown types are surfaced as
    ``{type:'unknown', type_of_identity:N}`` rather than dropped.
    """
    if not value:
        return None
    type_of_identity = value[0] & 0x07
    if type_of_identity == _EPS_ID_TYPE_GUTI:
        if len(value) < 11:
            return None
        plmn = _decode_plmn_tbcd(value[1:4])
        if plmn is None:
            return None
        mme_group_id = (value[4] << 8) | value[5]
        mme_code = value[6]
        m_tmsi = (value[7] << 24) | (value[8] << 16) | (value[9] << 8) | value[10]
        return {
            "type": "guti",
            "mcc": plmn["mcc"],
            "mnc": plmn["mnc"],
            "mme_group_id": mme_group_id,
            "mme_code": mme_code,
            "m_tmsi": m_tmsi,
        }
    if type_of_identity in (_EPS_ID_TYPE_IMSI, _EPS_ID_TYPE_IMEI):
        odd = bool((value[0] >> 3) & 0x01)
        digits = [str((value[0] >> 4) & 0x0F)]  # first digit is the high nibble of octet 1
        for b in value[1:]:
            digits.append(str(b & 0x0F))
            digits.append(str((b >> 4) & 0x0F))
        # Even number of digits → the final high nibble is a 0xF filler; drop it.
        if not odd and digits and digits[-1] == "15":
            digits = digits[:-1]
        label = "imsi" if type_of_identity == _EPS_ID_TYPE_IMSI else "imei"
        return {"type": label, "digits": "".join(d for d in digits if d != "15")}
    return {"type": "unknown", "type_of_identity": type_of_identity}


# TS 24.301 §9.9.4.10 — PDN type value (octet 1, bits 1-3 of a PDN address IE).
_PDN_TYPE_IPV4 = 0b001
_PDN_TYPE_IPV6 = 0b010
_PDN_TYPE_IPV4V6 = 0b011
_PDN_TYPE_NONIP = 0b101  # TS 24.301 Rel-13 — non-IP PDN, no address octets


def _fmt_ipv6_iid(iid: bytes) -> str:
    """Render an 8-octet IPv6 *interface identifier* as the low 64 bits.

    The PDN address IE carries only the interface-identifier half of the IPv6
    address (TS 24.301 §9.9.4.10) — the /64 prefix is assigned separately via
    Router Advertisement. We render it as the ``::`` -suffixed low 64 bits
    (``::a:b:c:d``) so it reads as a partial IPv6 address rather than a full one.
    """
    groups = [f"{(iid[i] << 8) | iid[i + 1]:x}" for i in range(0, 8, 2)]
    return "::" + ":".join(groups)


def decode_pdn_address(value: bytes) -> dict[str, Any] | None:
    """Decode a PDN Address IE value (TS 24.301 §9.9.4.10).

    The PDN address carries the IP address(es) the network assigned to the UE
    in an *Activate Default/Dedicated EPS Bearer Context Request* — the headline
    "what IP did I get" field. The value is **positionally typed** by the low 3
    bits of octet 1 (the PDN type), which fixes how many address octets follow:

      * ``IPv4`` (0b001)   → 4 octets, dotted-quad → ``{pdn_type, ipv4}``
      * ``IPv6`` (0b010)   → 8 octets *interface identifier* (low 64 bits only;
        the /64 prefix arrives via RA) → ``{pdn_type, ipv6_interface_id}``
      * ``IPv4v6`` (0b011) → 8 octets IPv6 IID **then** 4 octets IPv4
        → ``{pdn_type, ipv6_interface_id, ipv4}``
      * ``non-IP`` (0b101) → no address octets → ``{pdn_type}``

    Returns the dict, or ``None`` if the value is too short for its declared
    PDN type (a truncated capture) or empty. Unknown/reserved PDN types are
    surfaced as ``{pdn_type: 'unknown', pdn_type_value: N}`` rather than dropped,
    matching the forensic-visibility convention of
    :func:`decode_eps_mobile_identity`.
    """
    if not value:
        return None
    pdn_type = value[0] & 0x07
    addr = value[1:]
    if pdn_type == _PDN_TYPE_IPV4:
        if len(addr) < 4:
            return None
        return {"pdn_type": "ipv4", "ipv4": ".".join(str(b) for b in addr[:4])}
    if pdn_type == _PDN_TYPE_IPV6:
        if len(addr) < 8:
            return None
        return {"pdn_type": "ipv6", "ipv6_interface_id": _fmt_ipv6_iid(addr[:8])}
    if pdn_type == _PDN_TYPE_IPV4V6:
        if len(addr) < 12:
            return None
        return {
            "pdn_type": "ipv4v6",
            "ipv6_interface_id": _fmt_ipv6_iid(addr[:8]),
            "ipv4": ".".join(str(b) for b in addr[8:12]),
        }
    if pdn_type == _PDN_TYPE_NONIP:
        return {"pdn_type": "non-ip"}
    return {"pdn_type": "unknown", "pdn_type_value": pdn_type}


# TS 24.301 §9.9.3.33 — Tracking area identity list "type of list" (octet-1 bits 7-6).
_TAI_LIST_ONE_PLMN_NONCONSEC = 0b00  # one PLMN, non-consecutive TAC values
_TAI_LIST_ONE_PLMN_CONSEC = 0b01     # one PLMN, consecutive TAC values (run)
_TAI_LIST_DIFF_PLMNS = 0b10          # full TAIs, possibly different PLMNs


def decode_eps_tai_list(value: bytes) -> dict[str, Any] | None:
    """Decode a Tracking Area Identity List IE value (TS 24.301 §9.9.3.33).

    The TAI list is the "which tracking areas am I registered in" field of an
    *Attach Accept* / *TAU Accept* — the set the UE may move within without a
    new TAU. The IE is one or more concatenated **partial lists**, each headed
    by an octet whose bits 7-6 select the layout and bits 5-1 hold the element
    count minus one (so 0 → 1 element, max 32 by the field width):

      * ``00`` one PLMN, **non-consecutive** TACs — PLMN(3) + N×TAC(2)
      * ``01`` one PLMN, **consecutive** TACs — PLMN(3) + first-TAC(2); the N
        elements are ``first, first+1, … first+N-1`` (expanded here, since the
        wire only spells the first)
      * ``10`` **different PLMNs** — N×(PLMN(3) + TAC(2))

    TACs are the 16-bit EPS form. (The 5GS variant — TS 24.501 §9.11.3.9 — uses
    a 24-bit TAC and is a *separate* codec to avoid silently misaligning octets.)

    Returns ``{"tais": [{mcc, mnc, tac}, …]}`` with every TAI expanded, or
    ``None`` if the value is empty, truncated, or carries a reserved (``11``)
    list type whose length can't be determined.
    """
    if not value:
        return None
    pos = 0
    n = len(value)
    tais: list[dict[str, Any]] = []
    while pos < n:
        hdr = value[pos]
        list_type = (hdr >> 5) & 0x03
        count = (hdr & 0x1F) + 1
        pos += 1
        if list_type == _TAI_LIST_ONE_PLMN_NONCONSEC:
            if pos + 3 + 2 * count > n:
                return None
            plmn = _decode_plmn_tbcd(value[pos : pos + 3])
            if plmn is None:
                return None
            pos += 3
            for _ in range(count):
                tac = (value[pos] << 8) | value[pos + 1]
                pos += 2
                tais.append({**plmn, "tac": tac})
        elif list_type == _TAI_LIST_ONE_PLMN_CONSEC:
            if pos + 3 + 2 > n:
                return None
            plmn = _decode_plmn_tbcd(value[pos : pos + 3])
            if plmn is None:
                return None
            pos += 3
            first = (value[pos] << 8) | value[pos + 1]
            pos += 2
            for i in range(count):
                tais.append({**plmn, "tac": (first + i) & 0xFFFF})
        elif list_type == _TAI_LIST_DIFF_PLMNS:
            if pos + 5 * count > n:
                return None
            for _ in range(count):
                plmn = _decode_plmn_tbcd(value[pos : pos + 3])
                if plmn is None:
                    return None
                pos += 3
                tac = (value[pos] << 8) | value[pos + 1]
                pos += 2
                tais.append({**plmn, "tac": tac})
        else:  # reserved (0b11) — length undeterminable, can't safely continue
            return None
    if not tais:
        return None
    return {"tais": tais}


def decode_5gs_tai_list(value: bytes) -> dict[str, Any] | None:
    """Decode a 5GS Tracking Area Identity List IE value (TS 24.501 §9.11.3.9).

    The 5GS sibling of :func:`decode_eps_tai_list`: the "which 5GS tracking areas
    am I registered in" field of a *Registration Accept* — the set the UE may
    roam within without a new registration. Same partial-list framing (header
    octet: bits 7-6 list type, bits 5-1 element-count-minus-one) but the TAC is
    the **24-bit** 5GS form, not the EPS 16-bit form — which is exactly why this
    is a separate codec (running the EPS codec over a 5GS TAI list misaligns
    every octet after the first TAC).

      * ``00`` one PLMN, **non-consecutive** TACs — PLMN(3) + N×TAC(3)
      * ``01`` one PLMN, **consecutive** TACs — PLMN(3) + first-TAC(3), expanded
      * ``10`` **different PLMNs** — N×(PLMN(3) + TAC(3))

    Returns ``{"tais": [{mcc, mnc, tac}, …]}`` (TAC as a 24-bit int), or ``None``
    for an empty/truncated value or a reserved (``11``) list type. Whole-or-reject,
    mirroring the EPS codec.
    """
    if not value:
        return None
    pos = 0
    n = len(value)
    tais: list[dict[str, Any]] = []
    while pos < n:
        hdr = value[pos]
        list_type = (hdr >> 5) & 0x03
        count = (hdr & 0x1F) + 1
        pos += 1
        if list_type == _TAI_LIST_ONE_PLMN_NONCONSEC:
            if pos + 3 + 3 * count > n:
                return None
            plmn = _decode_plmn_tbcd(value[pos : pos + 3])
            if plmn is None:
                return None
            pos += 3
            for _ in range(count):
                tac = int.from_bytes(value[pos : pos + 3], "big")
                pos += 3
                tais.append({**plmn, "tac": tac})
        elif list_type == _TAI_LIST_ONE_PLMN_CONSEC:
            if pos + 3 + 3 > n:
                return None
            plmn = _decode_plmn_tbcd(value[pos : pos + 3])
            if plmn is None:
                return None
            pos += 3
            first = int.from_bytes(value[pos : pos + 3], "big")
            pos += 3
            for i in range(count):
                tais.append({**plmn, "tac": (first + i) & 0xFFFFFF})
        elif list_type == _TAI_LIST_DIFF_PLMNS:
            if pos + 6 * count > n:
                return None
            for _ in range(count):
                plmn = _decode_plmn_tbcd(value[pos : pos + 3])
                if plmn is None:
                    return None
                pos += 3
                tac = int.from_bytes(value[pos : pos + 3], "big")
                pos += 3
                tais.append({**plmn, "tac": tac})
        else:  # reserved (0b11) — length undeterminable, can't safely continue
            return None
    if not tais:
        return None
    return {"tais": tais}


def decode_5gs_tai(value: bytes) -> dict[str, Any] | None:
    """Decode a single 5GS Tracking Area Identity (TS 24.501 §9.11.3.8).

    A bare TAI — PLMN (3 octets TBCD) + 24-bit TAC — used by the *Last visited
    registered TAI* IE of a Registration request (and elsewhere a single TAI is
    needed). Unlike :func:`decode_5gs_tai_list` there is no list-type header.
    Returns ``{mcc, mnc, tac}`` or ``None`` if shorter than 6 octets / the PLMN
    is malformed.
    """
    if len(value) < 6:
        return None
    plmn = _decode_plmn_tbcd(value[0:3])
    if plmn is None:
        return None
    return {**plmn, "tac": int.from_bytes(value[3:6], "big")}


# TS 24.501 §9.11.3.4 — 5GS mobile identity "type of identity" (octet-1 bits 1-3).
_5GS_ID_TYPE_NONE = 0b000
_5GS_ID_TYPE_SUCI = 0b001
_5GS_ID_TYPE_GUTI = 0b010   # 5G-GUTI
_5GS_ID_TYPE_IMEI = 0b011
_5GS_ID_TYPE_STMSI = 0b100  # 5G-S-TMSI
_5GS_ID_TYPE_IMEISV = 0b101

# TS 24.501 §9.11.3.4 — SUPI format (octet-1 bits 5-7 of a SUCI).
_SUPI_FORMAT_IMSI = 0b000
_SUPI_FORMAT_NAMES: dict[int, str] = {0: "imsi", 1: "nsi", 2: "gci", 3: "gli"}
# SUCI protection scheme id (octet after routing indicator, low nibble).
_SUCI_SCHEME_NULL = 0x0
_SUCI_SCHEME_PROFILE_A = 0x1
_SUCI_SCHEME_PROFILE_B = 0x2
_SUCI_SCHEME_NAMES: dict[int, str] = {
    _SUCI_SCHEME_NULL: "null scheme",
    _SUCI_SCHEME_PROFILE_A: "ECIES profile A",
    _SUCI_SCHEME_PROFILE_B: "ECIES profile B",
}
# TS 33.501 Annex C.3.4 — a PROTECTED scheme output is a fixed-size ECC
# ephemeral public key, then the ciphertext, then a fixed 8-octet MAC tag:
#
#     scheme_output = ECC ephemeral public key || ciphertext || MAC tag
#
# The key size is what the profile's curve fixes, and it is the ONLY thing that
# makes the split determinate — the ciphertext is variable-length (it scales
# with the SUPI), so it can only be read as "whatever is left in the middle".
#   profile A: X25519          -> 32-octet key
#   profile B: secp256r1, SEC1 compressed point -> 33-octet key (0x02/0x03 lead)
# An unassigned scheme id has no known key size, so its output is NOT split:
# fabricating a boundary would be a guess presented as a decode.
_SUCI_ECC_KEY_LEN: dict[int, int] = {
    _SUCI_SCHEME_PROFILE_A: 32,
    _SUCI_SCHEME_PROFILE_B: 33,
}
_SUCI_MAC_TAG_LEN = 8


def _decode_bcd_digits(b: bytes) -> str:
    """Decode packed BCD (low nibble first per octet); drop 0xF filler.

    Used for the SUCI routing indicator and the null-scheme MSIN (TS 24.501
    §9.11.3.4) — plain digit packing with no leading type nibble (unlike
    :func:`_decode_5gs_imei_digits`, whose octet 1 carries a type/odd-even
    header).
    """
    out: list[str] = []
    for byte in b:
        out.append(byte & 0x0F)
        out.append((byte >> 4) & 0x0F)
    return "".join(str(n) for n in out if n != 0x0F)


# TS 24.008 §10.5.1.4 — Mobile Identity "type of identity" (octet-1 bits 1-3).
# The classic 2G/3G/EPS form carried by IEI 0x23 (distinct from the EPS Mobile
# Identity IEI 0x50 decoded by :func:`decode_eps_mobile_identity`).
_MS_ID_TYPE_NAMES: dict[int, str] = {
    0: "no identity", 1: "imsi", 2: "imei", 3: "imeisv", 4: "tmsi",
}


def decode_mobile_identity(value: bytes) -> dict[str, Any] | None:
    """Decode a TS 24.008 §10.5.1.4 Mobile Identity IE value (IEI 0x23).

    IMSI/IMEI/IMEISV are BCD digit strings (first digit in the high nibble of
    octet 1, odd/even in bit 4, remaining digits low-nibble-first); TMSI/P-TMSI
    is a 4-octet value. Decoded faithfully and completely — the identity digits
    are surfaced, never withheld. Returns ``None`` for an empty value.
    """
    if not value:
        return None
    id_type = value[0] & 0x07
    name = _MS_ID_TYPE_NAMES.get(id_type, f"0x{id_type:X}")
    if id_type in (1, 2, 3):  # IMSI / IMEI / IMEISV — BCD digits
        odd = bool((value[0] >> 3) & 0x01)
        nibbles = [(value[0] >> 4) & 0x0F]
        for b in value[1:]:
            nibbles.append(b & 0x0F)
            nibbles.append((b >> 4) & 0x0F)
        if not odd and nibbles and nibbles[-1] == 0x0F:
            nibbles = nibbles[:-1]
        digits = "".join(str(n) for n in nibbles if n != 0x0F)
        return {"type": name, "digits": digits}
    if id_type == 4:  # TMSI / P-TMSI — 4-octet identity in octets 2-5
        if len(value) >= 5:
            return {"type": "tmsi", "tmsi": int.from_bytes(value[1:5], "big")}
        return {"type": "tmsi", "value": value.hex()}
    # "no identity" (0) or reserved — surface the type + raw bytes, never drop.
    return {"type": name, "type_of_identity": id_type, "value": value.hex()}


def _decode_5gs_imei_digits(value: bytes) -> str:
    """Decode the BCD-packed digits of a 5GS IMEI/IMEISV identity.

    Identical packing to the EPS form (TS 24.501 §9.11.3.4 reuses TS 24.008
    §10.5.1.4): the first digit is the high nibble of octet 1, odd/even
    indication is bit 4 of octet 1, remaining digits are low-nibble-first.
    The trailing 0xF filler of an even-length identity is dropped.
    """
    odd = bool((value[0] >> 3) & 0x01)
    digits = [str((value[0] >> 4) & 0x0F)]
    for b in value[1:]:
        digits.append(str(b & 0x0F))
        digits.append(str((b >> 4) & 0x0F))
    if not odd and digits and digits[-1] == "15":
        digits = digits[:-1]
    return "".join(d for d in digits if d != "15")


def _decompose_suci_scheme_output(
    scheme: int, scheme_output: bytes) -> dict[str, str] | None:
    """Split a protected SUCI scheme output into its TS 33.501 Annex C.3.4 parts.

    Returns ``{ecc_ephemeral_public_key, ciphertext, mac_tag}`` (hex), or
    ``None`` when the split is not determinate — an unassigned protection
    scheme (unknown key size), or an output too short to leave at least one
    ciphertext octet after the key and the MAC tag. In both cases the caller
    keeps emitting the whole ``scheme_output`` blob: never dropped, never
    split on a guessed boundary.

    The **null** scheme is deliberately absent from the key-size table. Its
    "scheme output" is the plaintext MSIN, not a ciphertext — carving 8 octets
    off the end as a MAC tag would silently truncate a subscriber identity.
    """
    key_len = _SUCI_ECC_KEY_LEN.get(scheme)
    if key_len is None:
        return None
    if len(scheme_output) <= key_len + _SUCI_MAC_TAG_LEN:
        return None
    return {
        "ecc_ephemeral_public_key": scheme_output[:key_len].hex(),
        "ciphertext": scheme_output[key_len:-_SUCI_MAC_TAG_LEN].hex(),
        "mac_tag": scheme_output[-_SUCI_MAC_TAG_LEN:].hex(),
    }


def decode_5gs_mobile_identity(value: bytes) -> dict[str, Any] | None:
    """Decode a 5GS Mobile Identity IE value (TS 24.501 §9.11.3.4).

    The 5G analogue of :func:`decode_eps_mobile_identity` — the headline
    identity field of a *Registration Accept* (5G-GUTI) and the identity the
    UE presents in *Registration Request* (SUCI / 5G-GUTI / 5G-S-TMSI). The
    low 3 bits of octet 1 pick the type:

      * **5G-GUTI** (0b010): octet 1 = type byte, octets 2-4 = PLMN (TBCD),
        octet 5 = AMF Region ID (8b), octets 6-7 = AMF Set ID (10b) + AMF
        Pointer (6b), octets 8-11 = 5G-TMSI (u32 BE). →
        ``{type:'5g-guti', mcc, mnc, amf_region_id, amf_set_id, amf_pointer,
        tmsi_5g}``. The AMF Set ID straddles the octet-6/7 boundary: it is the
        full octet 6 (high 8 bits) plus the top 2 bits of octet 7; the AMF
        Pointer is the low 6 bits of octet 7.
      * **5G-S-TMSI** (0b100): octet 1 = type byte, octets 2-3 = AMF Set ID +
        AMF Pointer (same 10b/6b split), octets 4-7 = 5G-TMSI (u32 BE). →
        ``{type:'5g-s-tmsi', amf_set_id, amf_pointer, tmsi_5g}``.
      * **IMEI / IMEISV** (0b011 / 0b101): BCD digit-packed (odd/even in bit 4
        of octet 1) → ``{type:'imei'|'imeisv', digits}``.

    SUCI (0b001) is decoded faithfully: the full value is emitted as
    ``value`` (hex) plus every plaintext field — ``supi_format``, and for the
    IMSI SUPI format ``mcc`` / ``mnc`` / ``routing_indicator`` /
    ``protection_scheme_id`` / ``home_network_pki`` / ``scheme_output``. For the
    **null protection scheme** the scheme output is the plaintext MSIN, so
    ``msin`` and the reconstructed permanent ``imsi`` are surfaced too — a SUCI
    is a subscriber identity and the tool never withholds it. "No identity"
    (0b000) is surfaced as ``{type:'none', type_of_identity:N}``, and
    unhandled/reserved types as ``{type:'unknown', type_of_identity:N}`` rather
    than dropped, matching :func:`decode_eps_mobile_identity`'s convention.

    Returns the dict, or ``None`` if the value is empty or too short for its
    declared type (a truncated capture).
    """
    if not value:
        return None
    type_of_identity = value[0] & 0x07
    if type_of_identity == _5GS_ID_TYPE_GUTI:
        if len(value) < 11:
            return None
        plmn = _decode_plmn_tbcd(value[1:4])
        if plmn is None:
            return None
        amf_region_id = value[4]
        amf_set_id = (value[5] << 2) | (value[6] >> 6)
        amf_pointer = value[6] & 0x3F
        tmsi_5g = (value[7] << 24) | (value[8] << 16) | (value[9] << 8) | value[10]
        return {
            "type": "5g-guti",
            "mcc": plmn["mcc"],
            "mnc": plmn["mnc"],
            "amf_region_id": amf_region_id,
            "amf_set_id": amf_set_id,
            "amf_pointer": amf_pointer,
            "tmsi_5g": tmsi_5g,
        }
    if type_of_identity == _5GS_ID_TYPE_STMSI:
        if len(value) < 7:
            return None
        amf_set_id = (value[1] << 2) | (value[2] >> 6)
        amf_pointer = value[2] & 0x3F
        tmsi_5g = (value[3] << 24) | (value[4] << 16) | (value[5] << 8) | value[6]
        return {
            "type": "5g-s-tmsi",
            "amf_set_id": amf_set_id,
            "amf_pointer": amf_pointer,
            "tmsi_5g": tmsi_5g,
        }
    if type_of_identity in (_5GS_ID_TYPE_IMEI, _5GS_ID_TYPE_IMEISV):
        label = "imei" if type_of_identity == _5GS_ID_TYPE_IMEI else "imeisv"
        return {"type": label, "digits": _decode_5gs_imei_digits(value)}
    if type_of_identity == _5GS_ID_TYPE_SUCI:
        # Faithful decode: NEVER surface a SUCI by type alone — a
        # null-scheme SUCI carries the plaintext MSIN (the permanent IMSI).
        # Emit the whole value verbatim, then every plaintext field.
        supi_format = (value[0] >> 4) & 0x07
        suci: dict[str, Any] = {
            "type": "suci",
            "type_of_identity": type_of_identity,
            "supi_format": supi_format,
            "supi_format_name": _SUPI_FORMAT_NAMES.get(
                supi_format, f"0x{supi_format:X}"),
            "value": value.hex(),
        }
        if supi_format == _SUPI_FORMAT_IMSI and len(value) >= 8:
            plmn = _decode_plmn_tbcd(value[1:4])
            if plmn is not None:
                suci["mcc"] = plmn["mcc"]
                suci["mnc"] = plmn["mnc"]
            suci["routing_indicator"] = _decode_bcd_digits(value[4:6])
            scheme = value[6] & 0x0F
            suci["protection_scheme_id"] = scheme
            suci["protection_scheme_name"] = _SUCI_SCHEME_NAMES.get(
                scheme, f"0x{scheme:X}")
            suci["home_network_pki"] = value[7]
            scheme_output = value[8:]
            suci["scheme_output"] = scheme_output.hex()
            parts = _decompose_suci_scheme_output(scheme, scheme_output)
            if parts is not None:
                suci.update(parts)
            if scheme == _SUCI_SCHEME_NULL:
                # Null scheme: the scheme output IS the MSIN, in plaintext BCD.
                msin = _decode_bcd_digits(scheme_output)
                suci["msin"] = msin
                if plmn is not None and msin:
                    suci["imsi"] = f"{plmn['mcc']}{plmn['mnc']}{msin}"
        return suci
    if type_of_identity == _5GS_ID_TYPE_NONE:
        return {"type": "none", "type_of_identity": type_of_identity}
    return {"type": "unknown", "type_of_identity": type_of_identity}


# ── S-NSSAI (network slice selection assistance information) ───────────────
# TS 24.501 §9.11.2.8 / Table 9.11.2.8.1. The value-part length selects which
# optional fields follow the mandatory SST octet — the spec enumerates exactly
# this fixed set of lengths.
_SNSSAI_LEN_SST = 1               # SST
_SNSSAI_LEN_SST_MAPPEDSST = 2     # SST + mapped HPLMN SST
_SNSSAI_LEN_SST_SD = 4            # SST + SD
_SNSSAI_LEN_SST_SD_MAPPEDSST = 5  # SST + SD + mapped HPLMN SST
_SNSSAI_LEN_FULL = 8              # SST + SD + mapped HPLMN SST + mapped HPLMN SD
_SNSSAI_LENGTHS = frozenset((
    _SNSSAI_LEN_SST, _SNSSAI_LEN_SST_MAPPEDSST, _SNSSAI_LEN_SST_SD,
    _SNSSAI_LEN_SST_SD_MAPPEDSST, _SNSSAI_LEN_FULL,
))


def decode_s_nssai(value: bytes) -> dict[str, Any] | None:
    """Decode an S-NSSAI IE value (TS 24.501 §9.11.2.8).

    The S-NSSAI ("Single Network Slice Selection Assistance Information") is the
    network-slice identity carried in 5GMM *Registration Request/Accept* (inside
    the Requested / Allowed / Configured / Rejected NSSAI lists) and in 5GSM
    *PDU Session Establishment Request/Accept*. It answers "which network slice
    is this session bound to" — the headline slicing field of the 5G control
    plane, and a direct need of the NR 5GMM/5GSM body decoders.

    The value-part length selects the layout (TS 24.501 Table 9.11.2.8.1):

      * len 1 → ``SST``
      * len 2 → ``SST`` + mapped HPLMN ``SST``
      * len 4 → ``SST`` + ``SD`` (24-bit slice differentiator)
      * len 5 → ``SST`` + ``SD`` + mapped HPLMN ``SST``
      * len 8 → ``SST`` + ``SD`` + mapped HPLMN ``SST`` + mapped HPLMN ``SD``

    Returns ``{sst, [sd], [mapped_sst], [mapped_sd]}`` — ``sd`` / ``mapped_sd``
    as 24-bit ints (big-endian, as on the wire), and the ``mapped_*`` keys
    present only at the lengths that carry them. Returns ``None`` for an empty
    value or a length not in the spec's enumerated set (a truncated/corrupt IE).
    Unlike the open-ended GUTI/IMSI identity types, the S-NSSAI length set is
    closed, so an off-list length is a genuine decode failure rather than an
    unknown-but-present value.
    """
    n = len(value)
    if n not in _SNSSAI_LENGTHS:
        return None
    out: dict[str, Any] = {"sst": value[0]}
    if n == _SNSSAI_LEN_SST_MAPPEDSST:
        out["mapped_sst"] = value[1]
    elif n == _SNSSAI_LEN_SST_SD:
        out["sd"] = int.from_bytes(value[1:4], "big")
    elif n == _SNSSAI_LEN_SST_SD_MAPPEDSST:
        out["sd"] = int.from_bytes(value[1:4], "big")
        out["mapped_sst"] = value[4]
    elif n == _SNSSAI_LEN_FULL:
        out["sd"] = int.from_bytes(value[1:4], "big")
        out["mapped_sst"] = value[4]
        out["mapped_sd"] = int.from_bytes(value[5:8], "big")
    return out


def decode_nssai(value: bytes) -> dict[str, Any] | None:
    """Decode an NSSAI IE value (TS 24.501 §9.11.3.37) — a list of S-NSSAIs.

    The NSSAI IE carries the **Allowed NSSAI**, **Configured NSSAI**,
    **Requested NSSAI**, and **Rejected NSSAI** of a 5GMM *Registration
    Request/Accept* — i.e. "which network slices may this UE use." It is the
    list wrapper around :func:`decode_s_nssai`: the value part is one or more
    concatenated entries, each a 1-octet **length of S-NSSAI contents** followed
    by that many octets of S-NSSAI value (the exact value :func:`decode_s_nssai`
    consumes). There is no count field — the walk runs until the value is
    exhausted.

    Returns ``{"s_nssais": [ {sst, …}, … ]}`` (each element as
    :func:`decode_s_nssai` produces). Returns ``None`` for an empty value or a
    structurally malformed list — an entry whose length octet overruns the
    remaining bytes, or an inner S-NSSAI whose length is not in the spec's
    closed set. Strictness mirrors :func:`decode_eps_tai_list`: a list is decoded
    whole or rejected, never surfaced half-read (a truncated trailing entry would
    otherwise look like a complete, shorter Allowed-NSSAI than the network sent).
    """
    n = len(value)
    if n == 0:
        return None
    s_nssais: list[dict[str, Any]] = []
    pos = 0
    while pos < n:
        ie_len = value[pos]
        pos += 1
        if ie_len == 0 or pos + ie_len > n:
            return None  # zero-length or overrunning entry → corrupt list
        decoded = decode_s_nssai(value[pos:pos + ie_len])
        if decoded is None:
            return None  # an off-list inner S-NSSAI length → corrupt list
        s_nssais.append(decoded)
        pos += ie_len
    if not s_nssais:
        return None
    return {"s_nssais": s_nssais}


# ── EPS quality of service (TS 24.301 §9.9.4.3) ───────────────────────────
# The value part comes in three fixed groups; lengths between them are
# malformed (octets 4-7 and 8-11 are each an all-or-nothing 4-octet group):
_EPS_QOS_LEN_QCI = 1   # QCI only (the non-GBR / default-bearer case)
_EPS_QOS_LEN_GBR = 5   # QCI + MBR/GBR up/down (GBR bearers, pre-extended)
_EPS_QOS_LEN_EXT = 9   # … + the extended MBR/GBR up/down octets
_EPS_QOS_LENGTHS = frozenset((_EPS_QOS_LEN_QCI, _EPS_QOS_LEN_GBR, _EPS_QOS_LEN_EXT))


def _eps_qos_bit_rate(octet: int) -> int:
    """Decode a base bit-rate octet → kbps (TS 24.008 §10.5.6.5).

    0x00 (reserved / "given by the extended octet") and 0xFF ("0 kbps") both
    map to 0; the caller overlays the extended octet when present.
    """
    if octet == 0 or octet == 0xFF:
        return 0
    if octet <= 0x3F:               # 1..63  → N kbps
        return octet
    if octet <= 0x7F:               # 64..127 → 64 + (N-64)*8 kbps
        return 64 + (octet - 0x40) * 8
    return 576 + (octet - 0x80) * 64  # 128..254 → 576 + (N-128)*64 kbps


def _eps_qos_bit_rate_ext(octet: int) -> int | None:
    """Decode an extended bit-rate octet → kbps, or ``None`` when the extended
    octet is unused (TS 24.008 §10.5.6.5). ``0x00`` means "use the base octet";
    251-255 are reserved (also treated as "use the base octet")."""
    if octet == 0:
        return None
    if octet <= 0x4A:               # 1..74   → 8600 + N*100 kbps (8700..16000)
        return 8600 + octet * 100
    if octet <= 0xBA:               # 75..186 → 16000 + (N-74)*1000 (17000..128000)
        return 16000 + (octet - 0x4A) * 1000
    if octet <= 0xFA:               # 187..250 → 128000 + (N-186)*2000 (130000..256000)
        return 128000 + (octet - 0xBA) * 2000
    return None                     # 251..255 reserved → fall back to base octet


def decode_eps_qos(value: bytes) -> dict[str, Any] | None:
    """Decode an EPS quality of service IE value (TS 24.301 §9.9.4.3).

    The EPS QoS IE carries the **QCI** plus, for GBR bearers, the maximum and
    guaranteed bit rates assigned to the bearer — the "what throughput did the
    network grant" field of an *Attach Accept* / *TAU Accept* (assigned EPS
    bearer QoS) and of an *Activate Default/Dedicated EPS Bearer Context
    Request*.

    The value-part length selects the layout (three all-or-nothing octet
    groups, so the length set is closed — TS 24.301 §9.9.4.3):

      * len 1 → ``qci`` only (non-GBR / default bearer — the common case)
      * len 5 → ``qci`` + MBR/GBR up/down (octets 4-7)
      * len 9 → … + extended MBR/GBR up/down (octets 8-11)

    Returns ``{qci, [mbr_ul_kbps, mbr_dl_kbps, gbr_ul_kbps, gbr_dl_kbps]}`` —
    the four bit-rate keys present only at len ≥ 5, each decoded per TS 24.008
    §10.5.6.5. When the extended octet (len 9) is present **and** carries a
    usable value it supersedes the base octet (that is the whole point of the
    extended octets — to express rates above the base octet's 8640 kbps
    ceiling); a zero/reserved extended octet falls back to the base value.

    Returns ``None`` for an empty value or a length not in the spec's closed
    set {1, 5, 9} (a truncated/corrupt IE) — mirroring the whole-or-reject
    discipline of :func:`decode_s_nssai` rather than the surface-unknown
    convention of the type-discriminated identity codecs.
    """
    n = len(value)
    if n not in _EPS_QOS_LENGTHS:
        return None
    out: dict[str, Any] = {"qci": value[0]}
    if n == _EPS_QOS_LEN_QCI:
        return out

    # octets 4-7: base MBR/GBR up/down; octets 8-11 (len 9): extended overlay.
    base = value[1:5]
    ext = value[5:9] if n == _EPS_QOS_LEN_EXT else (None, None, None, None)
    for key, b, e in zip(
        ("mbr_ul_kbps", "mbr_dl_kbps", "gbr_ul_kbps", "gbr_dl_kbps"), base, ext
    ):
        rate = _eps_qos_bit_rate(b)
        if e is not None:
            ext_rate = _eps_qos_bit_rate_ext(e)
            if ext_rate is not None:
                rate = ext_rate
        out[key] = rate
    return out


# ── PLMN list (TS 24.301 §9.9.3.45 — Equivalent PLMNs) ─────────────────────
# The value part is a plain concatenation of 3-octet TBCD PLMN identities
# (TS 24.008 §10.5.1.13), no per-element header — so its length is always a
# positive multiple of 3. Spec caps the list at 15 PLMNs, but the length is
# self-describing, so the decoder just walks every 3-octet group it's given.
_PLMN_OCTETS = 3


def decode_plmn_list(value: bytes) -> dict[str, Any] | None:
    """Decode a PLMN List IE value (TS 24.301 §9.9.3.45 — *Equivalent PLMNs*).

    The Equivalent PLMNs IE of an *Attach Accept* / *TAU Accept* tells the UE
    which PLMNs to treat as equivalent to the registered one for cell
    (re)selection — "which other operators may I camp on without it counting as
    roaming." The value part is a bare list of 3-octet TBCD PLMN identities
    (TS 24.008 §10.5.1.13), the same packing :func:`_decode_plmn_tbcd` already
    handles for the GUTI / TAI-list codecs.

    Returns ``{"plmns": [{mcc, mnc}, …]}`` — one entry per 3-octet group, in
    wire order.

    Returns ``None`` for an empty value or a length that is not a positive
    multiple of 3 (a truncated / corrupt IE) — the whole-or-reject discipline
    of :func:`decode_eps_qos` / :func:`decode_nssai`, since a partial trailing
    PLMN is genuine corruption, not an extension point.
    """
    n = len(value)
    if n == 0 or n % _PLMN_OCTETS != 0:
        return None
    plmns: list[dict[str, str]] = []
    for off in range(0, n, _PLMN_OCTETS):
        plmn = _decode_plmn_tbcd(value[off:off + _PLMN_OCTETS])
        if plmn is None:                      # unreachable given the % check, but explicit
            return None
        plmns.append(plmn)
    return {"plmns": plmns}


# ── GPRS timers (TS 24.008 §10.5.7.3 / §10.5.7.4 / §10.5.7.4a) ─────────────
# A GPRS timer packs a 5-bit value and a 3-bit unit into a single octet. The
# EPS NAS timers (T3402, T3412, T3423, T3324, T3412-extended, …) are all GPRS
# timers, so an *Attach Accept* / *TAU Accept* leans on this codec repeatedly.
# Two encodings exist:
#   - the "basic" GPRS Timer / GPRS Timer 2 unit space (T3402/T3412/T3423/T3324)
#   - the richer GPRS Timer 3 unit space (T3412-extended, eDRX-era long timers)
# Both put the value in bits 5-1 and the unit selector in bits 8-6.

# GPRS Timer / GPRS Timer 2 (§10.5.7.3 / §10.5.7.4) — unit → seconds-per-tick.
# 0b111 is the special "deactivated" sentinel (timer not running); the
# 0b011..0b110 codepoints are not assigned for the basic timer and surface as
# an explicit "reserved" unit rather than a guessed multiplier.
_GPRS_TIMER_UNIT_SECONDS: dict[int, int] = {
    0b000: 2,        # multiples of 2 seconds
    0b001: 60,       # multiples of 1 minute
    0b010: 6 * 60,   # multiples of 1 decihour (6 minutes)
}
_GPRS_TIMER_DEACTIVATED = 0b111

# GPRS Timer 3 (§10.5.7.4a) — a wider unit space for the long periodic-TAU /
# eDRX-era timers (T3412 extended). Same 5-bit value field, different units.
_GPRS_TIMER3_UNIT_SECONDS: dict[int, int] = {
    0b000: 10 * 60,         # multiples of 10 minutes
    0b001: 60 * 60,         # multiples of 1 hour
    0b010: 10 * 60 * 60,    # multiples of 10 hours
    0b011: 2,               # multiples of 2 seconds
    0b100: 30,              # multiples of 30 seconds
    0b101: 60,              # multiples of 1 minute
    0b110: 320 * 60 * 60,   # multiples of 320 hours
}


def _decode_gprs_timer_octet(
    octet: int, unit_table: dict[int, int]
) -> dict[str, Any]:
    """Shared body for the GPRS-timer codecs: split one octet into unit+value.

    ``octet`` is the single GPRS-timer value octet; ``unit_table`` maps the
    3-bit unit selector to its seconds-per-tick. Returns the raw octet, the
    decoded 5-bit value, and — when the unit is assigned and not the
    "deactivated" sentinel — the timer duration in seconds plus a human label.
    An unassigned unit yields ``unit="reserved"`` and no ``seconds`` (we never
    fabricate a multiplier for a codepoint the spec leaves open).
    """
    unit = (octet >> 5) & 0x07
    value = octet & 0x1F
    out: dict[str, Any] = {"raw": octet, "value": value}
    if unit == _GPRS_TIMER_DEACTIVATED:
        out["unit"] = "deactivated"
        out["deactivated"] = True
        return out
    secs_per_tick = unit_table.get(unit)
    if secs_per_tick is None:
        out["unit"] = "reserved"
        return out
    out["seconds"] = value * secs_per_tick
    out["unit"] = f"{secs_per_tick}s"
    return out


def decode_gprs_timer(octet: int) -> dict[str, Any]:
    """Decode a GPRS Timer / GPRS Timer 2 value octet (TS 24.008 §10.5.7.3/4).

    Covers the basic EPS timers carried as a single value octet — T3402, T3412,
    T3423, T3324. Returns ``{raw, value, unit, seconds?, deactivated?}``; see
    :func:`_decode_gprs_timer_octet` for the field semantics.
    """
    return _decode_gprs_timer_octet(octet, _GPRS_TIMER_UNIT_SECONDS)


def decode_gprs_timer3(octet: int) -> dict[str, Any]:
    """Decode a GPRS Timer 3 value octet (TS 24.008 §10.5.7.4a).

    The wider-unit form used by T3412 extended (the long periodic-TAU timer):
    same 5-bit value, a richer unit space spanning 2-second to 320-hour ticks.
    """
    return _decode_gprs_timer_octet(octet, _GPRS_TIMER3_UNIT_SECONDS)


def decode_lai(value: bytes) -> dict[str, Any] | None:
    """Decode a Location Area Identification IE value (TS 24.008 §10.5.1.3).

    Five octets: a 3-octet TBCD PLMN (MCC/MNC) followed by a 2-octet Location
    Area Code. A *network location* identity (the circuit-switched analogue of
    the TAI), not subscriber PII — safe to surface. Returns
    ``{mcc, mnc, lac}`` or ``None`` if the value isn't exactly 5 octets / the
    PLMN doesn't decode.
    """
    if len(value) != 5:
        return None
    plmn = _decode_plmn_tbcd(value[:3])
    if plmn is None:
        return None
    lac = (value[3] << 8) | value[4]
    return {"mcc": plmn["mcc"], "mnc": plmn["mnc"], "lac": lac}


# ── QoS rules (TS 24.501 §9.11.4.13 — Authorized QoS rules) ────────────────
# 5GSM IE. The headline "which packet filters map to which QoS flow, and at
# what precedence" field of a *PDU Session Establishment Accept* and a *PDU
# Session Modification Command*. The value part is one or more QoS rules, each
# self-delimited by a 2-octet "Length of QoS rule" field — so the list walks
# robustly rule-by-rule even though each packet filter's *component* contents
# (the open TS 24.501 §9.11.4.13 component-type space: match-all, IPv4/IPv6
# address ranges, protocol id, port ranges, ToS, flow label, …) are kept as
# raw hex rather than fully unpacked. That structural-decode-with-verbatim-
# contents boundary mirrors how decode_5gs_mobile_identity surfaces a SUCI by
# type without unpacking the SUPI structure: parsed where the layout is closed,
# preserved verbatim where it is open.

# Rule operation code — octet 1 of each rule's content, bits 8-6 (TS 24.501
# Table 9.11.4.13.1).
_QOS_RULE_OP_NAMES: dict[int, str] = {
    0b000: "reserved",
    0b001: "create_new",
    0b010: "delete_existing",
    0b011: "modify_add_filters",
    0b100: "modify_replace_filters",
    0b101: "modify_delete_filters",
    0b110: "modify_no_filter_change",
    0b111: "reserved",
}
# "Modify existing QoS rule and delete packet filters" carries a *shortened*
# packet-filter list: one octet per filter (the packet filter identifier in the
# low nibble), with no direction/length/contents — unlike the create/add/replace
# ops whose filters are full {direction, id, length, contents} octet groups.
_QOS_RULE_OP_DELETE_FILTERS = 0b101
# "Delete existing QoS rule" has no precedence / QoS-flow-identifier trailer.
_QOS_RULE_OP_DELETE_RULE = 0b010

# Packet filter direction — the create/add/replace filter octet, bits 6-5
# (TS 24.501 §9.11.4.13).
_PF_DIRECTION_NAMES: dict[int, str] = {
    0b00: "reserved",
    0b01: "downlink",
    0b10: "uplink",
    0b11: "bidirectional",
}


def _decode_qos_rule_content(rule_id: int, content: bytes) -> dict[str, Any] | None:
    """Decode one QoS rule's content octets (after its id + length header).

    ``content`` is exactly the "Length of QoS rule" octets, so its end is a hard
    structural boundary: any leftover after the packet-filter list and the
    optional precedence/QFI trailer is corruption → ``None``.
    """
    if not content:
        return None
    flags = content[0]
    op_code = (flags >> 5) & 0x07       # bits 8-6
    dqr = bool((flags >> 4) & 0x01)     # bit 5 (default QoS rule)
    num_filters = flags & 0x0F          # bits 4-1
    out: dict[str, Any] = {
        "qos_rule_id": rule_id,
        "rule_operation": _QOS_RULE_OP_NAMES.get(op_code, f"0b{op_code:03b}"),
        "dqr": dqr,
        "num_packet_filters": num_filters,
    }
    pos = 1
    filters: list[dict[str, Any]] = []
    if op_code == _QOS_RULE_OP_DELETE_FILTERS:
        # Shortened list: one octet per filter, packet filter id in bits 4-1.
        for _ in range(num_filters):
            if pos >= len(content):
                return None
            filters.append({"packet_filter_id": content[pos] & 0x0F})
            pos += 1
    else:
        # create / add / replace (and the 0-filter delete/no-change ops, whose
        # num_filters is 0 so this loop is a no-op): each filter is a
        # direction|id octet, a length octet, then that many content octets.
        for _ in range(num_filters):
            if pos + 2 > len(content):
                return None
            hdr = content[pos]
            direction = (hdr >> 4) & 0x03   # bits 6-5
            pf_id = hdr & 0x0F              # bits 4-1
            pf_len = content[pos + 1]
            c_start = pos + 2
            c_end = c_start + pf_len
            if c_end > len(content):
                return None
            filters.append({
                "packet_filter_id": pf_id,
                "direction": _PF_DIRECTION_NAMES.get(direction, f"0b{direction:02b}"),
                "components_raw": content[c_start:c_end].hex(),
            })
            pos = c_end
    out["packet_filters"] = filters

    # Trailer: QoS rule precedence (1 octet) + spare|segregation|QFI (1 octet).
    # Absent only for "delete existing QoS rule"; the rule-length boundary tells
    # us which case we are in without hard-coding per-op presence.
    remaining = len(content) - pos
    if remaining == 0:
        if op_code != _QOS_RULE_OP_DELETE_RULE:
            # A non-delete rule with no trailer is still structurally complete
            # in some encoders, but precedence/QFI are its whole point — surface
            # what we have rather than reject (forensic visibility).
            return out
        return out
    if remaining != 2:
        return None  # stray byte(s) inside a self-delimited rule → corrupt
    out["precedence"] = content[pos]
    qfi_octet = content[pos + 1]
    out["segregation"] = bool((qfi_octet >> 6) & 0x01)   # bit 7
    out["qfi"] = qfi_octet & 0x3F                         # bits 6-1
    return out


def decode_qos_rules(value: bytes) -> dict[str, Any] | None:
    """Decode an Authorized QoS rules IE value (TS 24.501 §9.11.4.13).

    The QoS rules IE is the mandatory 5GSM IE of a *PDU Session Establishment
    Accept* (and *PDU Session Modification Command*) that binds traffic to QoS
    flows: each rule carries a rule operation, a list of packet filters, a
    precedence, and the QoS flow identifier (QFI) the matched traffic is mapped
    to. Walking it positionally is exactly what unblocks reading a PDU Session
    Establishment Accept end-to-end (today its consumer has to scan for the DNN
    by IEI because it can't step over this mandatory IE — see
    ``_nr5g_nas_ota_helpers._decode_pdu_session_establishment_accept``).

    Returns ``{"rules": [ {qos_rule_id, rule_operation, dqr,
    num_packet_filters, packet_filters: [...], [precedence], [segregation],
    [qfi]}, … ]}``. Each packet filter is ``{packet_filter_id[, direction,
    components_raw]}`` — ``direction`` + verbatim ``components_raw`` hex for the
    create/add/replace ops, id-only for the "delete packet filters" op. The
    component bytes are preserved verbatim rather than unpacked (the component
    type space is open — IPv4/IPv6/protocol/port/ToS/flow-label/…).

    Returns ``None`` for an empty value or any structural corruption — a rule
    header that overruns, a "Length of QoS rule" that overruns the value, a
    packet filter whose contents overrun the rule, or stray octets inside a
    rule's self-delimited length window. Whole-or-reject, never half-read,
    mirroring :func:`decode_eps_qos` / :func:`decode_nssai`.
    """
    n = len(value)
    if n == 0:
        return None
    rules: list[dict[str, Any]] = []
    pos = 0
    while pos < n:
        if pos + 3 > n:            # need id(1) + length(2)
            return None
        rule_id = value[pos]
        rule_len = (value[pos + 1] << 8) | value[pos + 2]
        content_start = pos + 3
        content_end = content_start + rule_len
        if rule_len == 0 or content_end > n:
            return None
        decoded = _decode_qos_rule_content(rule_id, value[content_start:content_end])
        if decoded is None:
            return None
        rules.append(decoded)
        pos = content_end
    if not rules:
        return None
    return {"rules": rules}


# ── QoS flow descriptions (TS 24.501 §9.11.4.12) ───────────────────────────
# 5GSM IE, the sibling of the QoS rules IE (§9.11.4.13 above): where a QoS rule
# binds *traffic* (packet filters) to a QoS flow, a QoS flow description carries
# the *QoS parameters* of a flow — its 5QI, guaranteed/maximum bit rates,
# averaging window, mapped EPS bearer identity. It is a mandatory IE of a *PDU
# Session Establishment Accept* / *PDU Session Modification Command*.
#
# The value part is one or more QoS flow descriptions concatenated, each:
#   octet 1: QFI            — bits 8-7 spare, bits 6-1 QoS flow identifier
#   octet 2: operation code — bits 8-6 op code, bits 5-1 spare
#   octet 3: E + count      — bit 8 spare, bit 7 E, bits 6-1 number of parameters
#   then `number of parameters` parameters, each:
#       parameter identifier (1) | length of parameter contents (1) | contents
#
# Design call (matches decode_qos_rules): the parameter *identifiers* are a
# closed set (named below), but each parameter's *contents* (5QI byte, the
# unit+value bit-rate encoding, averaging-window ms, …) are kept verbatim hex —
# parsed where the layout is closed, preserved where it is open.
#
# The number-of-parameters field (octet 3, bits 6-1) is the authoritative count
# that delimits one description from the next — the descriptions carry no outer
# per-description length (unlike a QoS rule's 2-octet length). The E bit only
# distinguishes extension-vs-replacement semantics for the "modify" operation
# (and is spare for create/delete); it does NOT change how many parameters are
# on the wire, so it is surfaced raw and the walk always consumes exactly
# `num_parameters` self-delimited parameters.

# Operation code — octet 2, bits 8-6 (TS 24.501 §9.11.4.12).
_QOS_FLOW_OP_NAMES: dict[int, str] = {
    0b000: "reserved",
    0b001: "create_new",
    0b010: "delete_existing",
    0b011: "modify_existing",
    0b100: "reserved",
    0b101: "reserved",
    0b110: "reserved",
    0b111: "reserved",
}

# Parameter identifier — the closed set of §9.11.4.12 parameter ids. Contents
# stay verbatim (see the design-call note above); naming the id is the closed
# half.
_QOS_FLOW_PARAM_NAMES: dict[int, str] = {
    0x01: "5qi",
    0x02: "gfbr_uplink",
    0x03: "gfbr_downlink",
    0x04: "mfbr_uplink",
    0x05: "mfbr_downlink",
    0x06: "averaging_window",
    0x07: "eps_bearer_identity",
}


def decode_qos_flow_descriptions(value: bytes) -> dict[str, Any] | None:
    """Decode a QoS flow descriptions IE value (TS 24.501 §9.11.4.12).

    The sibling of the Authorized QoS rules IE (:func:`decode_qos_rules`): a QoS
    rule binds *traffic* to a flow, a QoS flow description carries the flow's
    *QoS parameters* (5QI, GFBR/MFBR up/down, averaging window, mapped EPS
    bearer identity). Both are mandatory IEs of a *PDU Session Establishment
    Accept* / *PDU Session Modification Command*, so a positional codec for this
    one is the other half of walking a PDU Session Establishment Accept
    end-to-end.

    Returns ``{"flows": [ {qfi, flow_operation, e_bit, num_parameters,
    parameters: [{parameter_id, [parameter, ]contents_raw}, …]}, … ]}``. Each
    parameter names its id when it is one of the closed §9.11.4.12 identifiers
    (5QI / GFBR / MFBR / averaging window / EPS bearer identity) and preserves
    its contents verbatim as ``contents_raw`` hex — the parameter contents
    layout (the unit+value bit-rate encoding, the 5QI byte, …) is left to a
    consumer, mirroring how :func:`decode_qos_rules` keeps a packet filter's
    ``components_raw`` verbatim.

    The ``num_parameters`` field is the authoritative count delimiting one
    description from the next (the descriptions carry no outer length). The
    ``e_bit`` is surfaced raw — it only marks extension-vs-replacement for the
    modify operation and never changes the wire parameter count.

    Returns ``None`` for an empty value or any structural corruption — a
    description header that overruns, a parameter id/length that overruns, a
    parameter whose contents overrun the value, or trailing octets that cannot
    form a complete description. Whole-or-reject, never half-read, mirroring
    :func:`decode_qos_rules` / :func:`decode_eps_qos`.
    """
    n = len(value)
    if n == 0:
        return None
    flows: list[dict[str, Any]] = []
    pos = 0
    while pos < n:
        if pos + 3 > n:            # need QFI(1) + op(1) + E|count(1)
            return None
        qfi = value[pos] & 0x3F            # bits 6-1 (bits 8-7 spare)
        op_code = (value[pos + 1] >> 5) & 0x07   # bits 8-6
        ctrl = value[pos + 2]
        e_bit = bool((ctrl >> 6) & 0x01)   # bit 7
        num_params = ctrl & 0x3F           # bits 6-1
        pos += 3
        params: list[dict[str, Any]] = []
        for _ in range(num_params):
            if pos + 2 > n:        # need parameter id(1) + length(1)
                return None
            param_id = value[pos]
            param_len = value[pos + 1]
            c_start = pos + 2
            c_end = c_start + param_len
            if c_end > n:
                return None
            param: dict[str, Any] = {"parameter_id": param_id}
            name = _QOS_FLOW_PARAM_NAMES.get(param_id)
            if name is not None:
                param["parameter"] = name
            param["contents_raw"] = value[c_start:c_end].hex()
            params.append(param)
            pos = c_end
        flows.append({
            "qfi": qfi,
            "flow_operation": _QOS_FLOW_OP_NAMES.get(op_code, f"0b{op_code:03b}"),
            "e_bit": e_bit,
            "num_parameters": num_params,
            "parameters": params,
        })
    if not flows:
        return None
    return {"flows": flows}


# ════════════════════════════════════════════════════════════════════════
# ESM message-body decoder (TS 24.301 §8.3 / §9) — the keystone consumer
# ════════════════════════════════════════════════════════════════════════
# An EPS Session Management (ESM) message reuses the L3 IE machinery above but
# carries its own 3-octet header (TS 24.007 §11.2.3.1.1):
#
#   octet 1: EPS bearer identity (bits 8-5) | protocol discriminator (bits 4-1, =0x2)
#   octet 2: procedure transaction identity (PTI)
#   octet 3: ESM message type
#
# ESM messages ride *inside* an EMM message container — the Attach Request's
# piggybacked PDN connectivity request (0xD0), the Attach Accept's Activate
# default EPS bearer context request (0xC1), the Attach Complete's Activate
# default EPS bearer context accept (0xC2) — and also stand alone as the
# 0xB0E1/0xB0E2/0xB0E3 ESM-OTA log codes. One reusable decoder therefore
# serves both the embedded consumers and the standalone code.
#
# Protocol Configuration Options (PCO, IEI 0x27) and Extended PCO (ePCO, IEI
# 0x7B): in the network→UE direction these carry the subscriber's MSISDN (phone
# number) alongside P-CSCF / DNS addresses — confirmed against a real Verizon
# Activate-default-bearer capture, where the MSISDN surfaced as ePCO container
# 0x000E. Their full contents are decoded faithfully into ``pco_hex`` /
# ``epco_hex`` — the tool never withholds them.
_ESM_PROTOCOL_DISCRIMINATOR = 0x2

# TS 24.301 Table 9.8 — ESM message identities.
_ESM_MSG_TYPE_NAMES: dict[int, str] = {
    0xC1: "Activate default EPS bearer context request",
    0xC2: "Activate default EPS bearer context accept",
    0xC3: "Activate default EPS bearer context reject",
    0xC5: "Activate dedicated EPS bearer context request",
    0xC6: "Activate dedicated EPS bearer context accept",
    0xC7: "Activate dedicated EPS bearer context reject",
    0xC9: "Modify EPS bearer context request",
    0xCA: "Modify EPS bearer context accept",
    0xCB: "Modify EPS bearer context reject",
    0xCD: "Deactivate EPS bearer context request",
    0xCE: "Deactivate EPS bearer context accept",
    0xD0: "PDN connectivity request",
    0xD1: "PDN connectivity reject",
    0xD2: "PDN disconnect request",
    0xD3: "PDN disconnect reject",
    0xD4: "Bearer resource allocation request",
    0xD5: "Bearer resource allocation reject",
    0xD6: "Bearer resource modification request",
    0xD7: "Bearer resource modification reject",
    0xD9: "ESM information request",
    0xDA: "ESM information response",
    0xDB: "Notification",
    0xDC: "ESM dummy message",
    0xE8: "ESM status",
    0xE9: "Remote UE report",
    0xEA: "Remote UE report response",
    0xEB: "ESM data transport",
}

# Optional-IE identifiers shared across ESM messages.
_IEI_ESM_PCO = 0x27         # Protocol configuration options — TLV (can carry MSISDN)
_IEI_ESM_EPCO = 0x7B        # Extended protocol configuration options — TLV-E
_IEI_ESM_APN = 0x28         # Access point name — TLV (in PDN connectivity request)
_IEI_ESM_APN_AMBR = 0x5E    # APN aggregate maximum bit rate — TLV
_IEI_ESM_CAUSE = 0x58       # ESM cause — TV(1) (bit-8 clear → MUST be tabled)
_IEI_ESM_LLC_SAPI = 0x32    # Negotiated LLC SAPI — TV(1) (legacy; tabled to avoid desync)
_IEI_ESM_INFO_XFER_FLAG = 0xD  # ESM information transfer flag — type-1 (high nibble)

# TS 24.301 §9.9.4.4 — ESM cause values (the ones that actually appear in our
# corpus / are operationally meaningful; unknown values surface numerically).
_ESM_CAUSE_NAMES: dict[int, str] = {
    0x08: "Operator determined barring",
    0x1A: "Insufficient resources",
    0x1B: "Missing or unknown APN",
    0x1C: "Unknown PDN type",
    0x1D: "User authentication failed",
    0x1F: "Request rejected, unspecified",
    0x20: "Service option not supported",
    0x21: "Requested service option not subscribed",
    0x22: "Service option temporarily out of order",
    0x23: "PTI already in use",
    0x24: "Regular deactivation",
    0x25: "EPS QoS not accepted",
    0x26: "Network failure",
    0x32: "PDN type IPv4 only allowed",
    0x33: "PDN type IPv6 only allowed",
    0x35: "Single address bearers only allowed",
    0x6F: "Protocol error, unspecified",
}


def decode_apn_ambr(value: bytes) -> dict[str, Any] | None:
    """Decode an APN aggregate maximum bit rate IE value (TS 24.301 §9.9.4.2).

    The headline "what aggregate throughput did the network grant for this APN"
    field of an *Activate Default EPS Bearer Context Request*. Octet 1 is the
    downlink base rate, octet 2 the uplink base rate (TS 24.008 §10.5.6.5
    coding, reused via :func:`_eps_qos_bit_rate`); the optional octets 3/4
    carry the *extended* DL/UL rates that supersede the base when present and
    usable (the same extended-octet coding as EPS QoS, :func:`_eps_qos_bit_rate_ext`),
    letting the network express rates above the base octet's 8640 kbps ceiling.

    Returns ``{apn_ambr_dl_kbps, apn_ambr_ul_kbps}`` or ``None`` for a value
    too short to carry even the two base octets.
    """
    if len(value) < 2:
        return None
    dl = _eps_qos_bit_rate(value[0])
    ul = _eps_qos_bit_rate(value[1])
    if len(value) >= 4:
        dl_ext = _eps_qos_bit_rate_ext(value[2])
        ul_ext = _eps_qos_bit_rate_ext(value[3])
        if dl_ext is not None:
            dl = dl_ext
        if ul_ext is not None:
            ul = ul_ext
    return {"apn_ambr_dl_kbps": dl, "apn_ambr_ul_kbps": ul}


def _walk_esm_optional(
    body: bytes, table: dict[int, IeSpec]
) -> tuple[dict[str, Any], list[int]]:
    """Walk the optional-IE tail of an ESM message body.

    Decodes the operationally-useful IEs (APN, APN-AMBR, ESM cause) and surfaces
    the full PCO / ePCO contents as hex (they can carry the subscriber MSISDN,
    DNS/P-CSCF addresses, etc.) — decoded faithfully, never withheld.
    Every other IEI is recorded in the returned unrecognized list for forensic
    visibility. Returns ``(fields, unrecognized_ieis)``.
    """
    out: dict[str, Any] = {}
    unrecognized: list[int] = []
    for iei, value, recognized in walk_optional_ies(body, table):
        if not recognized:
            unrecognized.append(iei)
            continue
        if iei == _IEI_ESM_APN:
            apn = decode_apn(value)
            if apn is not None:
                out["apn"] = apn
        elif iei == _IEI_ESM_APN_AMBR:
            ambr = decode_apn_ambr(value)
            if ambr is not None:
                out["apn_ambr"] = ambr
        elif iei == _IEI_ESM_CAUSE:
            if value:
                out["esm_cause"] = value[0]
                out["esm_cause_name"] = _ESM_CAUSE_NAMES.get(
                    value[0], f"0x{value[0]:02X}")
        elif iei in (_IEI_ESM_PCO, _IEI_ESM_EPCO):
            # Faithful decode: emit the full PCO/ePCO contents as hex
            # (they can carry the subscriber MSISDN / DNS / P-CSCF) — never
            # withheld. presence + length kept as a convenience.
            key = "epco" if iei == _IEI_ESM_EPCO else "pco"
            out[f"{key}_present"] = True
            out[f"{key}_len"] = len(value)
            out[f"{key}_hex"] = value.hex()
        elif iei == _IEI_ESM_INFO_XFER_FLAG and value:
            # type-1 half-octet; bit 1 = "security protected ESM info needed".
            out["esm_info_transfer_flag"] = value[0] & 0x01
        elif iei == _IEI_ESM_LLC_SAPI:
            pass  # tabled only so the walker consumes it at fixed length (no desync)
    return out, unrecognized


# Optional-IE tables, factored out so the (small) tables are built once. PCO and
# ePCO are tabled at their true wire shape (TLV / TLV-E) — if left untabled, the
# walker's bit-8-clear fall-through mis-reads the 2-octet ePCO length as a
# 1-octet TLV length and desyncs the rest of the walk.
_ESM_C1_OPTIONAL_TABLE: dict[int, IeSpec] = {
    _IEI_ESM_APN_AMBR: IeSpec(IeFormat.TLV),
    _IEI_ESM_CAUSE: IeSpec(IeFormat.TV, length=1),
    _IEI_ESM_LLC_SAPI: IeSpec(IeFormat.TV, length=1),
    _IEI_ESM_PCO: IeSpec(IeFormat.TLV),
    _IEI_ESM_EPCO: IeSpec(IeFormat.TLV_E),
}
_ESM_D0_OPTIONAL_TABLE: dict[int, IeSpec] = {
    _IEI_ESM_APN: IeSpec(IeFormat.TLV),
    _IEI_ESM_INFO_XFER_FLAG: IeSpec(IeFormat.TV_SHORT),
    _IEI_ESM_PCO: IeSpec(IeFormat.TLV),
    _IEI_ESM_EPCO: IeSpec(IeFormat.TLV_E),
}
_ESM_ACCEPT_OPTIONAL_TABLE: dict[int, IeSpec] = {
    _IEI_ESM_PCO: IeSpec(IeFormat.TLV),
    _IEI_ESM_EPCO: IeSpec(IeFormat.TLV_E),
}
# ESM information response (0xDA, §8.3.13): all-optional — APN + PCO/ePCO.
_ESM_INFO_RESPONSE_OPTIONAL_TABLE: dict[int, IeSpec] = {
    _IEI_ESM_APN: IeSpec(IeFormat.TLV),
    _IEI_ESM_PCO: IeSpec(IeFormat.TLV),
    _IEI_ESM_EPCO: IeSpec(IeFormat.TLV_E),
}

# TS 24.301 §9.9.4.10 — PDN type (octet 1 bits 5-7) / Request type (bits 1-3)
# half-octets of a PDN connectivity request.
_PDN_REQUEST_TYPE_NAMES: dict[int, str] = {
    0x1: "Initial request",
    0x2: "Handover",
    0x3: "Unused",
    0x4: "Emergency",
    0x5: "Handover of emergency bearer services",
}
_PDN_TYPE_NAMES: dict[int, str] = {
    0x1: "IPv4",
    0x2: "IPv6",
    0x3: "IPv4v6",
    0x4: "Unused",
    0x5: "Non-IP",
}


def _decode_activate_default_bearer_request(body: bytes) -> dict[str, Any]:
    """Body of Activate default EPS bearer context request (0xC1, §8.3.1).

    Mandatory wire order (no IEIs): EPS QoS (LV) → APN (LV) → PDN address (LV).
    Then optional IEs (APN-AMBR, ESM cause, PCO/ePCO) via the shared walker.
    """
    out: dict[str, Any] = {}
    pos = 0
    try:
        qos_val, pos = read_lv(body, pos)
        qos = decode_eps_qos(qos_val)
        if qos is not None:
            out["eps_qos"] = qos
        apn_val, pos = read_lv(body, pos)
        apn = decode_apn(apn_val)
        if apn is not None:
            out["apn"] = apn
        pdn_val, pos = read_lv(body, pos)
        pdn = decode_pdn_address(pdn_val)
        if pdn is not None:
            out["pdn_address"] = pdn
    except NasL3Error:
        return out  # truncated mandatory part — surface whatever decoded
    opt, unrecognized = _walk_esm_optional(body[pos:], _ESM_C1_OPTIONAL_TABLE)
    out.update(opt)
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return out


def _decode_pdn_connectivity_request(body: bytes) -> dict[str, Any]:
    """Body of PDN connectivity request (0xD0, §8.3.20).

    Mandatory: one octet — Request type (bits 1-3) + PDN type (bits 5-7).
    Optional: APN, ESM-information-transfer flag, PCO/ePCO (contents in hex).
    """
    out: dict[str, Any] = {}
    if not body:
        return out
    request_type = body[0] & 0x07
    pdn_type = (body[0] >> 4) & 0x07
    out["request_type"] = request_type
    out["request_type_name"] = _PDN_REQUEST_TYPE_NAMES.get(
        request_type, f"0x{request_type:X}")
    out["pdn_type"] = pdn_type
    out["pdn_type_name"] = _PDN_TYPE_NAMES.get(pdn_type, f"0x{pdn_type:X}")
    opt, unrecognized = _walk_esm_optional(body[1:], _ESM_D0_OPTIONAL_TABLE)
    out.update(opt)
    if unrecognized:
        out["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return out


def _decode_bearer_accept(body: bytes) -> dict[str, Any]:
    """Body of an Activate/Modify *accept* (0xC2/0xC6/0xCA): optional PCO only.

    The accept messages carry no mandatory IEs — just an optional PCO/ePCO
    (PII-skipped). Used for the Attach-Complete-embedded 0xC2.
    """
    opt, unrecognized = _walk_esm_optional(body, _ESM_ACCEPT_OPTIONAL_TABLE)
    if unrecognized:
        opt["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return opt


def _decode_esm_information_response(body: bytes) -> dict[str, Any]:
    """Body of an ESM information response (0xDA, §8.3.13): all-optional IEs.

    Carries the APN (the UE's response to an ESM information request — the
    headline plaintext field, e.g. ``fast.t-mobile.com``) plus PCO/ePCO
    (PII-skipped). The plaintext message behind the standalone 0xB0E1 APN.
    """
    opt, unrecognized = _walk_esm_optional(body, _ESM_INFO_RESPONSE_OPTIONAL_TABLE)
    if unrecognized:
        opt["unrecognized_ieis"] = [f"0x{i:02X}" for i in unrecognized]
    return opt


def decode_esm_message(pdu: bytes) -> dict[str, Any] | None:
    """Decode an EPS Session Management (ESM) message — TS 24.301 §8.3 / §9.

    ``pdu`` is a complete ESM message *including* its 3-octet header
    (EPS-bearer-identity|PD, PTI, ESM-message-type). This is the standalone
    ESM-OTA PDU (0xB0E1/E2/E3) **and** the bytes inside an EMM message's ESM
    message container (Attach Request 0xD0 / Attach Accept 0xC1 / Attach
    Complete 0xC2) — one decoder for both.

    Always surfaces the header fields (``eps_bearer_identity``,
    ``procedure_transaction_id``, ``esm_message_type`` + name) so every ESM
    message gets at least a typed decode; the high-value bodies (Activate
    default bearer request 0xC1 → QCI/APN/PDN-address/APN-AMBR; PDN
    connectivity request 0xD0 → request/PDN type; accepts 0xC2 → PCO presence)
    decode their IE tree. PCO/ePCO contents are surfaced in full as hex
    (``pco_hex`` / ``epco_hex``) — never withheld.

    Returns ``None`` for a PDU too short to carry the 3-octet header.
    """
    if len(pdu) < 3:
        return None
    out: dict[str, Any] = {
        "eps_bearer_identity": (pdu[0] >> 4) & 0x0F,
        "protocol_discriminator": pdu[0] & 0x0F,
        "procedure_transaction_id": pdu[1],
        "esm_message_type": pdu[2],
        "esm_message_type_name": _ESM_MSG_TYPE_NAMES.get(
            pdu[2], f"0x{pdu[2]:02X}"),
    }
    if out["protocol_discriminator"] != _ESM_PROTOCOL_DISCRIMINATOR:
        return out  # not an ESM PDU — surface the typed guess, decode no body
    body = pdu[3:]
    msg_type = pdu[2]
    if msg_type == 0xC1:
        out.update(_decode_activate_default_bearer_request(body))
    elif msg_type == 0xD0:
        out.update(_decode_pdn_connectivity_request(body))
    elif msg_type in (0xC2, 0xC6, 0xCA):
        out.update(_decode_bearer_accept(body))
    elif msg_type == 0xDA:
        out.update(_decode_esm_information_response(body))
    return out


# ── Shared GSM-7 / Network-Name / NITZ time IE codecs ──────────────
# These TS 24.008 §10.5.3.x IEs are reused verbatim by both LTE NAS (the EMM
# Information message, TS 24.301 §8.2.13) and NR5G NAS (the 5GMM Configuration
# update command, TS 24.501 §8.2.19). Promoted here from lte_nas_emm.py so the
# NR5G helper can reuse them without importing a concrete parser module.
# References: TS 23.038 §6.2.1 (GSM-7 alphabet), TS 24.008 §10.5.3.5a (Network
# Name), §10.5.3.8 (Local Time Zone), §10.5.3.9 (Universal Time), §10.5.3.12
# (Daylight Saving Time).

# 3GPP TS 23.038 Table 6.2.1.1 — GSM-7 default alphabet. Index = septet value.
# Most positions map to printable ASCII; a handful are accented Latin / Greek.
# Position 0x1B is ESC for the extension table (lone 0x1B renders as space).
_GSM_7_DEFAULT_ALPHABET: tuple[str, ...] = (
    "@", "£", "$", "¥", "è", "é", "ù", "ì",   # 0x00-0x07
    "ò", "Ç", "\n", "Ø", "ø", "\r", "Å", "å",  # 0x08-0x0F
    "Δ", "_", "Φ", "Γ", "Λ", "Ω", "Π", "Ψ",   # 0x10-0x17
    "Σ", "Θ", "Ξ", " ", "Æ", "æ", "ß", "É",   # 0x18-0x1F  (0x1B is ESC, rendered as space)
    " ", "!", "\"", "#", "¤", "%", "&", "'",   # 0x20-0x27
    "(", ")", "*", "+", ",", "-", ".", "/",   # 0x28-0x2F
    "0", "1", "2", "3", "4", "5", "6", "7",   # 0x30-0x37
    "8", "9", ":", ";", "<", "=", ">", "?",   # 0x38-0x3F
    "¡", "A", "B", "C", "D", "E", "F", "G",   # 0x40-0x47
    "H", "I", "J", "K", "L", "M", "N", "O",   # 0x48-0x4F
    "P", "Q", "R", "S", "T", "U", "V", "W",   # 0x50-0x57
    "X", "Y", "Z", "Ä", "Ö", "Ñ", "Ü", "§",   # 0x58-0x5F
    "¿", "a", "b", "c", "d", "e", "f", "g",   # 0x60-0x67
    "h", "i", "j", "k", "l", "m", "n", "o",   # 0x68-0x6F
    "p", "q", "r", "s", "t", "u", "v", "w",   # 0x70-0x77
    "x", "y", "z", "ä", "ö", "ñ", "ü", "à",   # 0x78-0x7F
)


def decode_gsm_7_packed(data: bytes, num_septets: int) -> str:
    """Decode `num_septets` packed GSM-7 septets out of `data`.

    Unpacks 7-bit characters from 8-bit octets per 3GPP TS 23.038 §6.1.2.1.1.
    Each character occupies 7 bits, bit-packed LSB-first within the stream:
    septet 0 occupies bits 0-6 of octet 0; septet 1 occupies bit 7 of
    octet 0 + bits 0-5 of octet 1; etc.

    Returns the decoded string. ESC extension (septet 0x1B) is rendered
    as a single space rather than triggering the extension-table lookup
    — extension-table characters are rare in network-name IEs and not
    needed for current ground-truth fixtures.
    """
    if num_septets <= 0:
        return ""
    out_chars: list[str] = []
    for i in range(num_septets):
        bit_start = i * 7
        septet = 0
        for k in range(7):
            bit_idx = bit_start + k
            byte_idx = bit_idx // 8
            if byte_idx >= len(data):
                break
            bit = (data[byte_idx] >> (bit_idx % 8)) & 1
            septet |= bit << k
        if 0 <= septet < len(_GSM_7_DEFAULT_ALPHABET):
            out_chars.append(_GSM_7_DEFAULT_ALPHABET[septet])
        else:
            out_chars.append(f"\\x{septet:02X}")
    return "".join(out_chars)


def decode_network_name(value: bytes) -> tuple[str, str] | None:
    """Decode a Network Name IE value (without IEI or length octet).

    Layout per TS 24.008 §10.5.3.5a:
        octet 3:
          bit 8       extension flag (always 1)
          bits 7-6    coding scheme (00=GSM-7 default, 01=UCS-2)
          bit 5       Add CI (whether to add country initials before name)
          bits 4-1    number of spare bits in last octet (0..7)
        octet 4..n  text bytes (packed septets for GSM-7; UCS-2 chars for 01)

    Returns (decoded_text, encoding_label) on success, None on malformed
    inputs. encoding_label is one of "gsm-7" or "ucs-2".
    """
    if len(value) < 2:
        return None
    header = value[0]
    coding = (header >> 5) & 0x03
    spare_bits = header & 0x07
    body = value[1:]
    if coding == 0:
        total_bits = len(body) * 8 - spare_bits
        if total_bits < 0:
            return None
        num_septets = total_bits // 7
        return decode_gsm_7_packed(body, num_septets), "gsm-7"
    if coding == 1:
        try:
            return body.decode("utf-16-be"), "ucs-2"
        except UnicodeDecodeError:
            return None
    return None


def decode_local_time_zone(value: bytes) -> int | None:
    """Decode a Local Time Zone IE value (single octet).

    Per TS 24.008 §10.5.3.8 → TS 23.040 §9.2.3.11: nibble-swapped BCD,
    HIGH nibble = ones digit of quarter-hours, LOW nibble = sign bit
    (bit 3) + tens digit (bits 2-0). Sign 0 = positive, 1 = negative.

    Returns the offset in quarter-hours (UTC+7 = +28, UTC-5 = -20).
    """
    if not value:
        return None
    b = value[0]
    ones = (b >> 4) & 0x0F
    sign = -1 if (b & 0x08) else 1
    tens = b & 0x07
    return sign * (tens * 10 + ones)


def decode_universal_time(value: bytes) -> dict[str, Any] | None:
    """Decode Universal Time and Local Time Zone IE (7 octets).

    Per TS 24.008 §10.5.3.9: year, month, day, hour, minute, second, and
    timezone — each as a BCD nibble pair with the LOW nibble being the
    ones digit (TBCD encoding). Year is 2-digit; this decoder assumes
    20xx. Timezone follows §10.5.3.8.
    """
    if len(value) < 7:
        return None

    def _tbcd(b: int) -> int:
        return ((b & 0x0F) * 10) + ((b >> 4) & 0x0F)

    return {
        "year": 2000 + _tbcd(value[0]),
        "month": _tbcd(value[1]),
        "day": _tbcd(value[2]),
        "hour": _tbcd(value[3]),
        "minute": _tbcd(value[4]),
        "second": _tbcd(value[5]),
        "timezone_qhrs": decode_local_time_zone(value[6:7]),
    }


def decode_dst(value: bytes) -> int | None:
    """Decode Network Daylight Saving Time IE — bits 1-2 of octet 3.

    Per TS 24.008 §10.5.3.12: 00 = no adjustment, 01 = +1h, 10 = +2h.
    """
    if not value:
        return None
    return value[0] & 0x03


# ── Attach Request optional-IE codecs ─────────────────────────────
# Every layout below is A/B-confirmed against Wireshark's TS 24.301 NAS-EPS
# dissector on an LV55 Verizon attach capture (the same capture the
# `_ATTACH_REQUEST` fixture comes from) — not written from the spec alone. tshark named the IE, its format and its length
# for each, which is how `0xC-` was caught: it is **MS network feature
# support**, not the Device-properties IE it is easy to mistake it for.

_DRX_NON_DRX_TIMER_NAMES: dict[int, str] = {
    0: "no non-DRX mode after transfer state",
    1: "max 1 sec non-DRX mode after transfer state",
    2: "max 2 sec non-DRX mode after transfer state",
    3: "max 4 sec non-DRX mode after transfer state",
    4: "max 8 sec non-DRX mode after transfer state",
    5: "max 16 sec non-DRX mode after transfer state",
    6: "max 32 sec non-DRX mode after transfer state",
    7: "max 64 sec non-DRX mode after transfer state",
}


def decode_drx_parameter(value: bytes) -> dict[str, Any] | None:
    """Decode a DRX parameter IE value — TS 24.008 §10.5.5.6 (2 octets).

    Octet 1 is the whole SPLIT PG CYCLE CODE; octet 2 packs the CN-specific
    DRX cycle length coefficient (bits 8-5), SPLIT on CCCH (bit 4) and the
    non-DRX timer (bits 3-1).

    This IE must be in the table, not just for completeness. It is a
    fixed-length **TV** whose IEI (0x5C) has bit 8 CLEAR, so an untabled
    occurrence falls into §11.2.4's "assume TLV" fallback, reads its first
    value octet as a length, and desyncs the remainder of the walk. On the
    LV55 fixture that would silently swallow the three IEs that follow it —
    without even listing them in ``unrecognized_ieis``.
    """
    if len(value) < 2:
        return None
    non_drx = value[1] & 0x07
    return {
        "split_pg_cycle_code": value[0],
        "cn_specific_drx_cycle_length_coefficient": (value[1] >> 4) & 0x0F,
        "split_on_ccch": bool(value[1] & 0x08),
        "non_drx_timer": non_drx,
        "non_drx_timer_name": _DRX_NON_DRX_TIMER_NAMES.get(
            non_drx, f"0x{non_drx:X}"),
    }


_VOICE_DOMAIN_PREF_NAMES: dict[int, str] = {
    0: "CS voice only",
    1: "IMS PS voice only",
    2: "CS voice preferred, IMS PS voice as secondary",
    3: "IMS PS voice preferred, CS voice as secondary",
}


def decode_voice_domain_preference(value: bytes) -> dict[str, Any] | None:
    """Decode a Voice domain preference and UE's usage setting IE — §9.9.3.44.

    One octet: bits 8-4 spare, bit 3 the UE's usage setting (0 = voice
    centric, 1 = data centric), bits 2-1 the voice domain preference for
    E-UTRAN.

    Grounded on the LV55 fixture's ``0x5D 01 07``, which tshark reads as
    *"UE's usage setting: Data centric"* + *"IMS PS voice preferred, CS Voice
    as secondary (3)"* — matching this decode exactly.
    """
    if not value:
        return None
    pref = value[0] & 0x03
    data_centric = bool(value[0] & 0x04)
    return {
        "voice_domain_preference": pref,
        "voice_domain_preference_name": _VOICE_DOMAIN_PREF_NAMES.get(
            pref, f"0x{pref:X}"),
        "ue_usage_setting": "data centric" if data_centric else "voice centric",
    }


def decode_ms_network_feature_support(nibble: int) -> dict[str, Any]:
    """Decode an MS network feature support IE value — TS 24.008 §10.5.1.15.

    A type-1 half-octet: bits 4-2 spare, bit 1 the extended-periodic-timer
    support flag. ``nibble`` is the low half-octet the walker hands back for
    an :attr:`IeFormat.TV_SHORT` row.

    The IEI is ``0xC-``. Reading that as the Device-properties IE is the
    easy mistake — tshark names it for the LV55 fixture's ``c1`` octet as
    *"MS network feature support / Extended periodic timers: MS supports the
    extended periodic timer in this domain"*.
    """
    return {"extended_periodic_timers": bool(nibble & 0x01)}
