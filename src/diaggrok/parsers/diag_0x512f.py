"""
0x512F — LOG_GSM_RR_SIGNALING_MESSAGE: a GSM RR L3 message on BCCH/CCCH.

Layout (all 700 corpus records, 10 sessions, EG25-G MDM9207 + MC7700
MDM9600):

    [0]  channel      0x81 = BCCH (only System Information seen)
                      0x83 = CCCH (only Paging Request 1 / Immediate
                      Assignment seen)
    [1]  RR message type — equals the message-type octet inside the L3
         block on 700/700
    [2]  L3 length    == len(record) - 3 on 700/700 (always 23: one
         BCCH/CCCH block)
    [3:] GSM RR L3 block, starting with the L2 pseudo length octet
         (TS 44.018 §10.5.2.19), then PD 0x6 + message type + IEs

**Byte 0 is a CHANNEL, not a version** (``version_less=True``). One modem
emits both 0x81 and 0x83 because it logs two channels, not two format
versions. u32@4 lies inside the L3 block; there is no config word.

The L3 decode lives in ``_gsm_rr_l3.py`` (shared helper). It covers
SI1/SI2/SI2bis/SI3/SI4/SI13/SI2quater, Paging Request Type 1 and Immediate
Assignment, which is every message type in the corpus. SI3 gives the full
cell identity (MCC, MNC, LAC, CI); SI1/SI2/SI2bis give the cell and
neighbour ARFCN lists; SI2quater gives 3G (UARFCN) and E-UTRAN (EARFCN)
neighbours. Validated field-by-field against stock tshark ``gsm_a_ccch``
on all 102 distinct corpus bodies: 0
mismatches, and every CSN.1 rest-octet walk ends on the spare padding.

In-capture grounding, per channel (byte 0 = 0x81 / 0x83):

* **F3 co-emission, both channels:** ``rr_gprs_debug.c:3981 "gs1:IMsg:
  <MSG> state <RR_STATE>"`` is the GSM RR task's inbound-message trace. An
  order-preserving alignment of that label stream against 0x512F
  ``message_name`` matches **393/393** records in all 4 F3-bearing captures
  (EG25-G): **336/336 CCCH** (PAGING_REQUEST_TYPE_1,
  IMMEDIATE_ASSIGNMENT) and **57/57 BCCH** (SI1/2/2quater/3/4/13). A
  nearest-timestamp join is wrong here: SI bursts share one log tick.
* **BCCH identity:** SI3 MCC/MNC/LAC/CI equal ``tle_log.c:669 "MCC:..,
  MNC:.., LAC:.., CellId:.."`` in both F3 captures that carry SI3.
* **CCCH page mode (n=1, CANDIDATE corroboration):** the only non-normal
  ``page_mode`` in the corpus (1, extended paging, on an Immediate
  Assignment) comes just before the corpus's only ``RR_IMSG_PAGE_MODE_IND``.
* **SCAT:** its GSMTAP ``chan_type`` is 1 (BCCH) or 2
  (CCCH) exactly where byte 0 is 0x81 / 0x83, and every SCAT frame payload
  is byte-identical to ``l3_raw``, pseudo-length octet included. That holds
  for all 10 captures, MC7700 MDM9600 among them, with 0 channel
  conflicts. SCAT drops some records; it never emits one this parser lacks.

Channels other than 0x81/0x83 are not decoded past the header. Dedicated
channels (SDCCH/SACCH) carry L3 without the L2 pseudo length octet, and
none are in the corpus to prove the framing.

PII: Paging Request Type 1 carries the TMSI / IMSI of *other* subscribers
being paged on the cell. They are decoded in full (``ascii_kinds``
"identifier"); committed fixtures use synthetic identities only.

Log name: LOG_GSM_RR_SIGNALING_MESSAGE
Also known as: GSM RR Signaling Message
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.parsers._gsm_rr_l3 import decode_ccch_block
from diaggrok.registry import register

HEADER_LEN = 3

CHANNEL_BCCH = 0x81
CHANNEL_CCCH = 0x83
CHANNEL_NAMES: dict[int, str] = {CHANNEL_BCCH: "BCCH", CHANNEL_CCCH: "CCCH"}


@dataclass
class Diag0x512F:
    """0x512F — GSM RR signalling message (BCCH/CCCH L3 block)."""
    log_time: int
    channel: int
    channel_name: str
    rr_message_type: int
    l3_length: int
    l3_raw: bytes
    # From the L3 block (None when the channel's framing is not decoded).
    message_name: str | None
    l2_pseudo_length: int | None
    skip_indicator: int | None
    protocol_discriminator: int | None
    message: dict[str, Any] | None
    body_error: str | None
    # Promoted for WiGLE / wardrive consumers (None when absent).
    mcc: str | None
    mnc: str | None
    lac: int | None
    cell_identity: int | None
    arfcns: list[int] | None
    eutran_earfcns: list[int] | None
    utran_uarfcns: list[int] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x512F",
            "log_time": self.log_time,
            "channel": self.channel,
            "channel_name": self.channel_name,
            "rr_message_type": self.rr_message_type,
            "l3_length": self.l3_length,
            "l3_raw": self.l3_raw,
            "message_name": self.message_name,
            "l2_pseudo_length": self.l2_pseudo_length,
            "skip_indicator": self.skip_indicator,
            "protocol_discriminator": self.protocol_discriminator,
            "message": self.message,
            "body_error": self.body_error,
            "mcc": self.mcc,
            "mnc": self.mnc,
            "lac": self.lac,
            "cell_identity": self.cell_identity,
            "arfcns": self.arfcns,
            "eutran_earfcns": self.eutran_earfcns,
            "utran_uarfcns": self.utran_uarfcns,
        }


def _promote(body: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "mcc": None, "mnc": None, "lac": None, "cell_identity": None,
        "arfcns": None, "eutran_earfcns": None, "utran_uarfcns": None,
    }
    if not body:
        return out
    lai = body.get("lai")
    if lai:
        out["mcc"], out["mnc"], out["lac"] = lai["mcc"], lai["mnc"], lai["lac"]
    out["cell_identity"] = body.get("cell_identity")
    fl = body.get("cell_channel_description") or body.get("neighbour_cell_description")
    if fl:
        out["arfcns"] = list(fl["arfcns"])
    ro = body.get("rest_octets") or {}
    if "eutran_neighbours" in ro:
        out["eutran_earfcns"] = [c["earfcn"] for g in ro["eutran_neighbours"]
                                 for c in g["earfcns"]]
    if "utran_fdd_neighbours" in ro:
        out["utran_uarfcns"] = [n["uarfcn"] for n in ro["utran_fdd_neighbours"]]
    return out


@register(
    0x512F,
    name="0x512F",
    description="GSM RR signalling message: channel + RR type + L3 length header, "
                "then a full BCCH/CCCH RR L3 decode (SI1/2/2bis/2quater/3/4/13, "
                "Paging Request 1, Immediate Assignment)",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. 3-byte header measured on 700/700 corpus records "
        "(byte0 channel 0x81 BCCH / 0x83 CCCH, byte1 = L3 message type, byte2 = "
        "len-3). L3 body per public TS 44.018 / TS 24.008 layouts, each decoded "
        "branch checked against stock tshark gsm_a_ccch output "
        "on all 102 distinct bodies: 0 mismatches. In-capture F3 RR inbound-"
        "message trace matches 393/393 records on EG25-G; SCAT GSMTAP payloads "
        "are byte-identical to l3_raw on all 10 captures. Byte 0 is a channel, "
        "not a version."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=19,
    fields_parsed=19,
    version_less=True,
    field_invariants={
        "channel": {"enum": [CHANNEL_BCCH, CHANNEL_CCCH]},
        "l3_length": {"enum": [23]},
        "protocol_discriminator": {"enum": [6]},
    },
    wigle_direct=True,
    wigle_roles=("identity", "rat-context"),
    ascii_kinds=("identifier",),  # TMSI / IMSI of paged subscribers
)
def parse_0x512f(log_time: int, data: bytes) -> Diag0x512F | None:
    if len(data) < HEADER_LEN:
        return None
    if data[2] != len(data) - HEADER_LEN:  # self-describing length
        return None
    channel = data[0]
    l3 = bytes(data[HEADER_LEN:])
    l3d = decode_ccch_block(l3) if channel in CHANNEL_NAMES else None
    body = l3d["body"] if l3d else None
    return Diag0x512F(
        log_time=log_time,
        channel=channel,
        channel_name=CHANNEL_NAMES.get(channel, f"0x{channel:02X}"),
        rr_message_type=data[1],
        l3_length=data[2],
        l3_raw=l3,
        message_name=l3d["message_name"] if l3d else None,
        l2_pseudo_length=l3d["l2_pseudo_length"] if l3d else None,
        skip_indicator=l3d["skip_indicator"] if l3d else None,
        protocol_discriminator=l3d["protocol_discriminator"] if l3d else None,
        message=body,
        body_error=l3d["body_error"] if l3d else None,
        **_promote(body),
    )
