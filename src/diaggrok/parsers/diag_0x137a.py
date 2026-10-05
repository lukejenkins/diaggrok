"""0x137A — CGPS PDSM End Session marker, 8B all-constant magic.

Validated across chipset generations: MDM9607, MDM9x50, SDX55 (incl.
RXM-G1) and MDM9x07 (EG18NA). Payload is entirely constant:

  a3 0d 00 00 00 00 00 00

Presence-only log event sharing the 0xA30D framing magic with 0x1378 and
0x1383. No variable payload across chipset generations — this code is a
zero-content **event marker**, carrying no measurement data itself.

## Semantics (F3-confirmed): the CGPS PDSM *End Session* event

A co-temporal F3 correlation confirms the canonical log name — this is NOT
an LTE marker or batch boundary despite the code range; it is a
GNSS/CGPS position-session-manager event.

On an EG18NA (MDM9x07) GNSS cold-start capture, the single 0x137A
record fires ~799 ts-units (essentially co-temporal; next-nearest F3 cluster
is 38k away) *after* the firmware's own F3 prints:

    pdapi.c:540           =PDSM= pdsm_end_session_ex(). CDPtr %p
    pdapi.c:220           =PDSM= sending PDAPI msg_id=4145 to TM thread
    tm_pdapi_iface.c:1458 End Session Request Client_id=..., Session type=0, Receiver off=1

i.e. the code is emitted at `pdsm_end_session_ex()` — exactly the
canonical `LOG_CGPS_PDSM_END_SESSION_C` / `LOG_INTERNAL_CGPS_PDSM_END_SESSION`.
The all-constant `a3 0d …` body is consistent with a presence-only
"session ended" marker (the interesting content is the *event*, not the payload).

## byte-0 is not a version (version-less)

byte-0 is **not** a DIAG version field — it is the **low byte of the
2-byte `0xA30D` family magic** at offset [0:2] (0x0DA3 LE ⇒ byte-0 == 0xA3),
shared verbatim with siblings 0x1378 and 0x1383. The parser already gates
on the full u16 magic (`if magic_a30d != 0x0DA3: return None`), which is
strictly stronger than a byte-0 gate and already rejects any foreign
format. A `field_invariants["version"]={enum:[0xA3]}` declaration would be
semantically false (0xA3 is half a magic signature, not a version) while
adding no protection, so the parser declares `version_less=True` (as
0x117B does).

Log name: LOG_CGPS_PDSM_END_SESSION_C
Also known as: LOG_INTERNAL_CGPS_PDSM_END_SESSION
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


_137A_EXPECTED = bytes([0xa3, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])


@dataclass
class Diag0x137A:
    """CGPS PDSM End Session marker (0x137A) — 8B all-constant `A3 0D 00 00 00 00 00 00`."""
    log_time: int
    magic_a30d: int
    payload_matches_expected: bool
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x137A',
            'log_time': self.log_time,
            'magic_a30d': self.magic_a30d,
            'payload_matches_expected': self.payload_matches_expected,
            'payload_size': self.payload_size,
        }


@register(0x137A,
    name="0x137A",
    description="CGPS PDSM End Session marker (0x137A) — 8B all-constant magic; F3-confirmed pdsm_end_session_ex() event",
    version=1, author="Luke Jenkins", author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Cross-generation decode from MDM9607, MDM9x50 and SDX55 captures; "
        "semantics F3-confirmed as CGPS PDSM End Session (EG18NA MDM9x07: "
        "0x137A co-temporal with the pdsm_end_session_ex() F3 print)"
    ),
    issues=(),
    fields_identified=3, fields_parsed=3,
    field_invariants={
        "magic_a30d": {"enum": [0x0DA3]},
        "payload_matches_expected": {"enum": [True]},
    },
    # Version-less: byte-0 is the low byte of the 2-byte
    # 0xA30D family magic (0xA3), NOT a DIAG version. The magic_a30d u16 gate
    # below already rejects every foreign payload. See the byte-0 note in
    # the module docstring.
    version_less=True)
def parse_0x137a(log_time: int, data: bytes) -> Diag0x137A | None:
    if len(data) < 8:
        return None
    magic_a30d = unpack_from('<H', data, 0)[0]
    if magic_a30d != 0x0DA3:
        return None
    return Diag0x137A(
        log_time=log_time,
        magic_a30d=magic_a30d,
        payload_matches_expected=bytes(data[:8]) == _137A_EXPECTED,
        payload_size=len(data),
    )
