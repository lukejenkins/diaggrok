# diaggrok-provenance: re
"""NR SystemInformation (SI) container walker — from-scratch UPER (no pycrate).

Walks a BCCH-DL-SCH ``systemInformation`` message (c1=0), enumerating every
``sib-TypeAndInfo`` element and dispatching per-SIB decode/skip:

  * **sib2** → extract serving-cell reselection parameters
    (``nr5g_rrc_sib_decode.decode_sib2``, the #N "NR SIB2" row)
  * **sib4** → extract inter-frequency neighbour carriers
    (``decode_sib4`` → ``NrSib4``, the #N "NR SIB4" row)
  * **sib5** → extract inter-RAT EUTRA neighbour carriers
    (``decode_sib5`` → ``NrSib5``, the #N "NR SIB5" row)
  * **sib9** → extract network time (``nr5g_rrc_sib9.decode_sib9_body``,
    the #N NR time item)
  * anything else → stop the walk (recorded in ``walk_stopped_at``); the
    tags decoded so far stay valid.

Corpus shape (gate 2026-07-02, #N): 416 SI records / 78 captures /
6 chipsets carry exactly two message layouts — ``sib2,sib4,sib5`` and
``sib2,sib4,sib5,sib9`` — so this walker fully consumes every observed
message. The header ``sib_mask`` cross-check: mask bit k set ⟺ SIBk
present holds for masks 0x34/0x234; mask 0x200 marks a subset flag on
otherwise-identical sib2,4,5,9 messages (semantics unresolved, see #N).

ASN.1 path (3GPP TS 38.331):

    BCCH-DL-SCH-Message → c1(0)=systemInformation
      → criticalExtensions(0)=SystemInformation-IEs
      → sib-TypeAndInfo SEQUENCE (SIZE (1..maxSIB=32)) OF CHOICE {
            sib2, sib3, sib4, sib5, sib6, sib7, sib8, sib9, ... }

Reference: 3GPP TS 38.331 v16.x, ITU-T X.691 (UPER)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from diaggrok.parsers.uper import UperReader
from diaggrok.parsers.nr5g_rrc_sib9 import NrSib9Time, decode_sib9_body
from diaggrok.parsers.nr5g_rrc_sib_decode import (
    NrSib2,
    NrSib4,
    NrSib5,
    decode_sib2,
    decode_sib4,
    decode_sib5,
)

# sib-TypeAndInfo CHOICE root alternatives (TS 38.331 §6.2.2), index → name.
SI_SIB_ROOT_TAGS = {i: f"sib{i + 2}" for i in range(8)}  # sib2..sib9


@dataclass
class NrSiInfo:
    """Decoded NR SystemInformation container."""
    sib_count: int                     # declared sib-TypeAndInfo size
    sib_tags: list[str]                # tags walked, in order
    sib2: Optional[NrSib2] = None
    sib4: Optional[NrSib4] = None
    sib5: Optional[NrSib5] = None
    sib9: Optional[NrSib9Time] = None
    # Tag name where the walk stopped early (no skip/decode support), or
    # "" when the whole list was consumed. Tags before the stop are valid.
    walk_stopped_at: str = ""


def decode_nr_si(log_time: int, msg_data: bytes) -> NrSiInfo | None:
    """Walk a BCCH-DL-SCH SystemInformation message.

    ``msg_data`` is the full BCCH-DL-SCH-Message UPER payload as carried by
    0xB821. Returns None unless the message is a c1=0 systemInformation with
    the plain (non-r16-future) critical extension.
    """
    if not msg_data or len(msg_data) < 2:
        return None

    try:
        r = UperReader(msg_data)
        if r.read_choice(2) != 0:      # BCCH-DL-SCH-MessageType → c1
            return None
        if r.read_choice(2) != 0:      # c1 → systemInformation
            return None
        if r.read_choice(2) != 0:      # criticalExtensions → IEs
            return None
        r.read_bits(2)                 # IEs optional bitmap (lateNCE, NCE)
        n_sibs = r.read_constrained_int(1, 32)

        info = NrSiInfo(sib_count=n_sibs, sib_tags=[])

        for _ in range(n_sibs):
            if r.read_bool():          # CHOICE extension bit → sib10+ series
                info.walk_stopped_at = "ext-series"
                break
            tag = SI_SIB_ROOT_TAGS[r.read_bits(3)]

            if tag == "sib2":
                info.sib2 = decode_sib2(r)
            elif tag == "sib4":
                info.sib4 = decode_sib4(r)
            elif tag == "sib5":
                info.sib5 = decode_sib5(r)
            elif tag == "sib9":
                sib9 = decode_sib9_body(r, log_time)
                if sib9 is None:
                    info.walk_stopped_at = tag
                    break
                info.sib9 = sib9
            else:
                # sib3 / sib6 / sib7 / sib8 — no skip implemented (0 corpus
                # records at gate time); stop rather than misparse.
                info.walk_stopped_at = tag
                break

            info.sib_tags.append(tag)

            # Overrun guard: a mis-skip that ran past the buffer means every
            # subsequent tag would decode from phantom zero bits.
            if r.bit_pos > len(msg_data) * 8:
                info.walk_stopped_at = tag
                info.sib_tags.pop()
                if tag == "sib2":
                    info.sib2 = None
                elif tag == "sib4":
                    info.sib4 = None
                elif tag == "sib5":
                    info.sib5 = None
                elif tag == "sib9":
                    info.sib9 = None
                break

        return info

    except (IndexError, ValueError, KeyError):
        return None
