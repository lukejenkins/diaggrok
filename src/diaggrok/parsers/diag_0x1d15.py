"""0x1D15 — OEM cryptographic attestation broadcast.

A length-self-describing payload (older name tables list the code as
"RESERVED") that publishes:

- a PEM-formatted RSA-2048 public key (byte-identical pubkey across every
  vendor implementation observed — Sierra EM9291, Quectel RM520N-GL,
  Casa Systems CFW3212, Foxconn T99W640, Quectel RG650V-NA — i.e. shared
  across both SDX62 and SDX72 baselines, so this is a baseline modem
  firmware feature rather than a single-chipset OEM extension),
- a 256 B binary signature trailer that varies between devices (per-device
  signing material — likely the modem's device-binding key signing the
  attestation root).

**Two PEM sub-forms under v0x01.** The firmware emits the SAME broadcast in
one of two PEM encodings, and the 10 B header self-describes which via
bytes 6-7 (PEM length, LE):

  ===========  =========  ==================================  =======  ========
  Body length  hdr b6-7   PEM label                           PEM len  Records
  ===========  =========  ==================================  =======  ========
  724 (dom.)   ``ca 01``  ``-----BEGIN RSA PUBLIC KEY-----``  458      2235
                          (PKCS#1 RSAPublicKey)
  716 (min.)   ``c2 01``  ``-----BEGIN PUBLIC KEY-----``      450      30
                          (X.509 SubjectPublicKeyInfo)
  ===========  =========  ==================================  =======  ========

The 8 B delta is exactly ``RSA `` (4 chars) appearing in both the BEGIN
and END delimiter lines of the PKCS#1 form. The 716 B SPKI form was seen
on two newer RM520N-GL builds, the M3100 and a T99W175 host capture; the
dominant 724 B PKCS#1 form on an older RM520N-GL build, CFW3212, EM9291
and T99W640. Both carry a 256 B per-device signature.

The 10 B header is ``01 01 01 01 00 00 <pemlen_lo> <pemlen_hi> 00 01`` —
bytes 0-5 ``01 01 01 01 00 00``; bytes 6-7 = PEM length LE (458 or 450);
bytes 8-9 = ``00 01`` LE = 256 = signature length. The parser validates
that structural grammar (fixed prefix, an enumerated PEM length, a 256 B
signature, total = 10 + pem_len + 256, PEM markers present) rather than a
single literal 10 B header: bytes 6-7 are a length field, not a constant,
so a literal-header check would drop every SPKI record.

**The record is an ENTRY LIST — the SDX72 1787 B two-entry form.** Bytes
0-5 are not a fixed prefix but a 2 B record header plus the first entry's
header. The general grammar, which consumes every observed record exactly:

  ``[0] version (0x01)  [1] entry_count``, then ``entry_count`` entries, each
  ``a:u8  type:u8  c:u16  len1:u16  len2:u16`` (LE) + ``len1`` B + ``len2`` B.

  ======  ===  ====  ====  =====  =====  ======================================
  type    a    c     len1  len2   entry  meaning
  ======  ===  ====  ====  =====  =====  ======================================
  0x01    1    0     450/  256    1st    PEM pubkey (len1) + per-device
                     458                 signature (len2)
  0x03    1    1     0     1055   2nd    COSE_Encrypt blob (CBOR tag 96)
  ======  ===  ====  ====  =====  =====  ======================================

The 716/724 B forms are ``entry_count == 1``. The 1787 B form
(``2 + 8+458+256 + 8+0+1055``) is ``entry_count == 2``: the SAME shared
pubkey entry followed by a 1055 B **COSE_Encrypt** structure — protected
``{1: 3}`` (A256GCM), unprotected ``{5: <12 B IV>}``, a 741 B ciphertext,
and one recipient with alg −41 (RSAES-OAEP-SHA256) and a 20 B ``kid``. The
blob is encrypted per-device material and is carried opaque
(``cose_encrypt``); its plaintext semantics are unknown. Observed only on
one Foxconn T99W640 firmware build (SDX72; 8 captures, 75 records counting
duplicates — 15/15 walked records exact-consume); an older T99W640 build
emits the 724 B single-entry form. The pubkey, ``a`` and ``c`` bytes, and
both entry lengths are enumerated, so any other layout still returns
``None`` — the registry turns that into a loud WARN + tally, never a
silent mis-decode.

The parser declares ``field_invariants={"version": {"enum": [0x01]},
"payload_size": {"enum": [716, 724, 1787]}}`` and the body enforces the
whole grammar — future-firmware records that ship a different layout (a
third PEM length, a different signature size) must return ``None`` rather
than silently mis-decode.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register


# The 10 B header self-describes the record: bytes 0-5 are a fixed prefix,
# bytes 6-7 are the PEM section length (LE), bytes 8-9 the signature length
# (LE). Two PEM sub-forms are observed under v0x01 — see the module docstring.
# NB: "fixed prefix" is the single-entry view — byte 1 is really the entry
# count and bytes 2-5 the first entry's header; the parser walks that grammar.
# Kept for the fixtures/tests that build the 724 B single-entry form.
_HEADER_PREFIX = b"\x01\x01\x01\x01\x00\x00"  # bytes 0-5, as seen on the entry_count == 1 forms
_HEADER_LEN = 10
_SIG_LEN = 256

# Observed PEM section lengths (header bytes 6-7 LE). Enumerated as a guard so
# a future firmware shipping a third PEM layout is rejected (return None),
# not silently mis-decoded.
_PEM_LEN_SPKI = 450   # "-----BEGIN PUBLIC KEY-----"      (X.509 SPKI)     → 716 B body
_PEM_LEN_PKCS1 = 458  # "-----BEGIN RSA PUBLIC KEY-----"  (PKCS#1)         → 724 B body
_PEM_LENS = (_PEM_LEN_SPKI, _PEM_LEN_PKCS1)

# Back-compat aliases: the dominant PKCS#1 form. `_HEADER`, `_PEM_LEN` and
# `_BODY_LEN` still name the 724 B single-entry form (kept so downstream
# imports / fixtures keyed to the dominant form don't break).
_PEM_LEN = _PEM_LEN_PKCS1
_HEADER = _HEADER_PREFIX + _PEM_LEN_PKCS1.to_bytes(2, "little") + _SIG_LEN.to_bytes(2, "little")
_BODY_LEN = _HEADER_LEN + _PEM_LEN_PKCS1 + _SIG_LEN  # 724
_BODY_LEN_SPKI = _HEADER_LEN + _PEM_LEN_SPKI + _SIG_LEN  # 716
_BODY_LENS = (_BODY_LEN_SPKI, _BODY_LEN)

# Entry-list grammar (see module docstring). Byte 0 = version, byte 1 =
# entry count, then 8 B per-entry headers ``a, type, c:u16, len1:u16, len2:u16``.
_RECORD_HDR_LEN = 2
_ENTRY_HDR_LEN = 8
_ENTRY_PUBKEY = 0x01
_ENTRY_COSE = 0x03
# Per entry type: the (a, c) header bytes observed on it. Enumerated — an
# unseen value is a layout that has not been decoded, so the record is rejected.
_ENTRY_AC = {_ENTRY_PUBKEY: (1, 0), _ENTRY_COSE: (1, 1)}
_COSE_LENS = (1055,)          # observed COSE_Encrypt blob length (T99W640 SDX72)
_COSE_TAG = b"\xd8\x60"      # CBOR tag 96 = COSE_Encrypt
_BODY_LEN_SDX72 = (_RECORD_HDR_LEN + _ENTRY_HDR_LEN + _PEM_LEN_PKCS1 + _SIG_LEN
                   + _ENTRY_HDR_LEN + _COSE_LENS[0])  # 1787
_MAX_ENTRIES = 2              # pubkey, then at most one COSE blob

# Generic PEM markers — both forms start ``-----BEGIN`` and contain
# ``PUBLIC KEY-----`` (covers "RSA PUBLIC KEY" and bare "PUBLIC KEY").
_PEM_BEGIN = b"-----BEGIN"
_PEM_END = b"-----END"
_PEM_KEY_MARKER = b"PUBLIC KEY-----"

# SHA-256 of the (PKCS#1 "RSA PUBLIC KEY") DER body — the shared baseline
# attestation pubkey. Hardware-confirmed byte-identical on T99W640 SDX72:
# SHA-256(der) over the 294B PKCS#1 key == this.
_PUBKEY_SHA256 = "3f43030c9e9fca7625581a25f3e7768c437c3272214bc6bba1540731a84c17fd"


# --- Ground-truth recipe ------------------------------------------------
# Per-modem recipe for 0x1D15, keyed to the Foxconn T99W640 (SDX72). The pem
# field is grounded on hardware: the PEM body decodes to a DER whose SHA-256
# matches the shared baseline attestation key above exactly, so the "pem
# carries the shared RSA-2048 attestation pubkey" mapping is verified on
# SDX72. The 256B signature is per-device (constant across all records of
# this device, distinct from other vendors).

@dataclass
class Diag0x1D15:
    """0x1D15 — SDX62 cryptographic attestation broadcast.

    Fields:
        log_time: DIAG timestamp from the outer LOG_F header (passthrough).
        version: byte 0 — always 0x01 across the observed corpus.
        pem: PEM block carrying the RSA-2048 attestation pubkey — 458 B in the
             dominant PKCS#1 form ("RSA PUBLIC KEY") or 450 B in the minority
             X.509 SPKI form ("PUBLIC KEY"); length self-described by header
             bytes 6-7 (see module docstring).
        signature: 256 B binary trailer — per-device-unique signature.
        payload_size: total body length — 724 (PKCS#1), 716 (SPKI), or 1787
            (SDX72 two-entry form).
        entry_count: byte 1 — 1 (pubkey only) or 2 (pubkey + COSE blob).
        cose_encrypt: the second entry's COSE_Encrypt blob (CBOR tag 96, 1055 B),
            carried opaque; ``None`` on the single-entry forms.
    """

    log_time: int
    version: int
    pem: bytes
    signature: bytes
    payload_size: int
    entry_count: int = 1
    cose_encrypt: bytes | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1D15",
            "log_time": self.log_time,
            "version": self.version,
            "pem": self.pem,
            "signature": self.signature,
            "payload_size": self.payload_size,
            "entry_count": self.entry_count,
            "cose_encrypt": self.cose_encrypt,
        }


@register(
    0x1D15,
    name="0x1D15",
    description=(
        "OEM cryptographic attestation broadcast — length-self-"
        "describing; 10B header + PEM RSA-2048 pubkey (458B PKCS#1 '724B' "
        "form or 450B SPKI '716B' form, baseline modem firmware, byte-identical "
        "across SDX62 + SDX72 vendor builds) + 256B per-device signature "
        "trailer; SDX72 1787B form appends a COSE_Encrypt entry"
    ),
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Cross-modem confirmed on Sierra EM9291 (SDX62), Quectel RM520N-GL "
        "(SDX62), Casa Systems CFW3212, Foxconn T99W640 (SDX72), Quectel "
        "RG650V-NA. Negative control: zero matches across MDM9607/SDX55 "
        "captures. Pubkey SHA-256(PKCS#1 DER) = "
        "3f43030c9e9fca7625581a25f3e7768c437c3272214bc6bba1540731a84c17fd; "
        "pem field hardware-grounded on a live T99W640 SDX72 (18 records, "
        "SHA-256 exact match). Decodes both PEM sub-forms: 724B PKCS#1 and "
        "716B X.509-SPKI (30 records on RM520N-GL, M3100, T99W175), via the "
        "self-describing length grammar (bytes 6-7 = PEM len LE in "
        "{450,458}). The record is an entry list (byte 1 = entry count); the "
        "T99W640 SDX72 1787B two-entry form carries the pubkey + a 1055B "
        "COSE_Encrypt blob, kept opaque."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=6,
    fields_parsed=6,
    field_invariants={
        "version": {"enum": [0x01]},
        "payload_size": {"enum": [_BODY_LEN_SPKI, _BODY_LEN, _BODY_LEN_SDX72]},  # 716, 724, 1787
        "entry_count": {"enum": [1, 2]},
        # The header prefix + length-field grammar is enforced in the parser
        # body (fixed prefix, enumerated PEM length, total reconstruction); it
        # isn't declared as a field_invariants key because it isn't surfaced in
        # to_dict() output.
    },
    # ASCII audit: the body is a PEM-encoded public
    # key ('-----BEGIN PUBLIC KEY-----' + base64 SPKI) — provisioned key
    # material. NOT PII (public key), so config-token, not identifier.
    ascii_kinds=("config-token",),
)
def parse_0x1d15(log_time: int, data: bytes) -> Diag0x1D15 | None:
    # Layer-2 invariants — walk the self-describing entry list (module
    # docstring) and require it to consume ``len(data)`` exactly. Every
    # rejection returns None, which registry.parse() reports as a loud
    # unhandled drop (WARN + tally) rather than a silent one.
    if len(data) < _RECORD_HDR_LEN:
        return None
    version, entry_count = data[0], data[1]
    if version != 0x01 or not 1 <= entry_count <= _MAX_ENTRIES:
        return None

    pem_section: bytes | None = None
    signature: bytes | None = None
    cose: bytes | None = None
    off = _RECORD_HDR_LEN
    for idx in range(entry_count):
        hdr = data[off:off + _ENTRY_HDR_LEN]
        if len(hdr) != _ENTRY_HDR_LEN:
            return None
        a, etype = hdr[0], hdr[1]
        c = int.from_bytes(hdr[2:4], "little")
        len1 = int.from_bytes(hdr[4:6], "little")
        len2 = int.from_bytes(hdr[6:8], "little")
        # The first entry is always the pubkey; any later entry is the COSE blob.
        want = _ENTRY_PUBKEY if idx == 0 else _ENTRY_COSE
        if etype != want or (a, c) != _ENTRY_AC[etype]:
            return None
        off += _ENTRY_HDR_LEN
        if off + len1 + len2 > len(data):
            return None
        part1 = data[off:off + len1]
        part2 = data[off + len1:off + len1 + len2]
        off += len1 + len2
        if etype == _ENTRY_PUBKEY:
            if len1 not in _PEM_LENS or len2 != _SIG_LEN:
                return None
            pem_section, signature = part1, part2
        else:
            if len1 != 0 or len2 not in _COSE_LENS:
                return None
            if not part2.startswith(_COSE_TAG):
                return None
            cose = part2
    if off != len(data):
        return None
    assert pem_section is not None and signature is not None  # the first entry is the pubkey

    # PEM markers must be present. A future firmware could ship a different PEM
    # body or signature shape at one of these enumerated lengths; reject
    # anything that doesn't carry a PUBLIC KEY PEM block.
    if not pem_section.startswith(_PEM_BEGIN):
        return None
    if _PEM_END not in pem_section:
        return None
    if _PEM_KEY_MARKER not in pem_section:
        return None

    return Diag0x1D15(
        log_time=log_time,
        version=version,
        pem=pem_section,
        signature=signature,
        payload_size=len(data),
        entry_count=entry_count,
        cose_encrypt=cose,
    )
