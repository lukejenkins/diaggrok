"""0xB88A — NR5G MAC RACH Attempt: one record per RA attempt, Msg1 → Msg4.

Community catalog name `LOG_NR5G_MAC_RACH_ATTEMPT` ("NR5G MAC RACH Attempt").
One record per random-access attempt. It carries the Msg1 preamble, the RAR
window, the Msg2 RAR (RAPID echo, TC-RNTI, timing advance), the Msg3 identity
(C-RNTI MAC CE or the 48-bit UL-CCCH SDU), and the RNTI the UE ends on.

### Versions

Three wire versions share one record shape. Fields are inserted between them,
so each version has its own offset table (`_LAYOUT`).

    v0x07  108 B  SDX55 (M2000, RXM-G1, RM500Q, LV55, SIM8202G-M2)
    v0x0a  180 B  SDX62 (RM520N-GL R03A03/R03A04)
    v0x0e  196 B  SDX6x Foxconn T99W640 (FDE2.F0.0.0.1.2)

v0x0e is v0x0a plus 16 B ahead of the Msg1 block. Its RAR UL grant sits right
after the Msg2 time instead of after the Msg3 time.

### Packed timing word (u16 + u16)

bits 0-9 SFN, bits 10-15 slot. The slot is 0..9 on every one of 1,333 timing
words in the corpus, on 15 kHz and 30 kHz carriers alike. That is the µ=0
reference TS 38.321 uses for t_id with long (L=839) preambles. The high u16
(`0x0000`/`0x0001`/`0x0101`) is not decoded and is left out.

### Layout (offsets per version: v0x07 / v0x0a / v0x0e)

    hdr   preamble_tx_counter  u8   @16 / @8  / @8
          contention_type      u8   @22 / @18 / @18   0 = contention-free
          msg_bitmask          u8   @23 / @19 / @19   bit0 Msg1 .. bit3 Msg4
                                    Fields of an unfilled block are None:
                                    tc_rnti / TA / rapid need bit1,
                                    msg3_c_rnti needs bit2, the RAR grant
                                    needs the bit of the block it is logged
                                    in (bit2 on v0x07/v0x0a, bit1 on v0x0e)
    msg1  msg1 timing word          @28 / @68 / @84
          root_sequence_u      u16  @38 / @76 / @92   CANDIDATE
          preamble_index            @35 u8 / @78 u16 / @94 u16
          cyclic_shift         u16  @40 / @80 / @96
          n_cs                 u16   -  / @82 / @98
          ra_rnti              u16  @42 / @84 / @100
          rar window start/end      @44,@48 / @92,@96 / @108,@112
    msg2  msg2 timing word          @56 / @112 / @128
          tc_rnti              u16  @62 / @118 / @138
          timing_advance       u16  @64 / @120 / @140   CANDIDATE
          rapid                u16   -  / @132 / @152
    msg3  msg3 timing word          @68 / @136 / @156
          rar_ul_grant_raw     u32  @72 / @140 / @132   CANDIDATE
          msg3_c_rnti          u16   -  / @148 / @166   0xFFFF = none
          msg3_ccch_sdu        6 B  @80 / @152 / @168
    end   post_rach_rnti       u16  @104 / @176 / @192

All other bytes stay in `body_raw`.

### Grounding (276 records, 37 captures, all three versions)

There is no F3 oracle. The firmware prints no `nr5g_mac_rach*` F3 site in any
F3-bearing capture, which is why two earlier `diag_f3_correlate` runs found
nothing. The record is grounded on TS 38.211 / 38.321 identities instead. Each
one ties two fields that are logged separately:

* **RA-RNTI** == 1 + 14·t_id (s_id = f_id = ul_carrier_id = 0), with t_id the
  Msg1 slot (TS 38.321 §5.1.3). 264/264 populated records.
* **RAR window** end == start + 1 frame, and the start falls 1-3 slots after
  Msg1. 264/264.
* **Cyclic shift** Cv == (p mod floor(839/N_CS))·N_CS (TS 38.211 §6.3.3.1).
  118/118 on v0x0a/v0x0e, where every N_CS is in Table 6.3.3.1-5. v0x07 logs no
  N_CS. There it is 145/146 at N_CS = 119, plus one LV55 record with Cv = 0,
  which is what an N_CS = 0 cell gives.
* **RAPID echo** == the preamble sent (TS 38.321 §5.1.4). 107/107 records with
  a Msg2.
* **msg_bitmask** matches which Msg blocks are filled. 264/264.
* **Contention-free stops at Msg2**: every `msg_bitmask == 0x03` record has
  contention_type 0 (TS 38.321 §5.1.4).
* **preamble_tx_counter** steps 1 → 10 with no RAR, then a header-only record
  (counter 10, bitmask 0) marks RA failure at preambleTransMax n10. It resets
  to 1 after every success (M2000, 6 cycles).
* **post_rach_rnti**: with a C-RNTI MAC CE Msg3 it equals that C-RNTI (6/6
  v0x0a/v0x0e, none equal the TC-RNTI). With a CCCH Msg3 it equals the
  TC-RNTI (TS 38.321 §5.1.5), 88/91. The 3 exceptions are R03A04 Msg3 retries:
  two of them resend the same CCCH SDU on different TC-RNTIs.
* **msg3_ccch_sdu is the UL-CCCH PDU, byte for byte.** 83 of 87 values turn
  up whole in a same-capture 0xB821 NR RRC OTA record, always as its trailing
  6-byte PDU (the other 4 have no matching 0xB821 logged). Wireshark's NR RRC
  dissector, run as a black box on all 87 SDUs, agrees with `_decode_ul_ccch`
  87/87: message (80 rrcSetupRequest, 7 rrcResumeRequest), ue-Identity type,
  establishment/resume cause, and short I-RNTI. Many SDX55/SDX62 setups
  really do carry establishmentCause mps-PriorityAccess.

CANDIDATE fields:

* timing_advance: always 0..3846, the 12-bit RAR TA range. It holds steady on
  stationary bench captures (T99W640 9/9/9/9; the R03A04 UIM bench repeats a
  per-cell 7/4/2 cycle 6 times) and swings on the drive capture (74/36/49/20).
  No independent TA oracle is held yet.
* root_sequence_u: 0..838. 8 pairs of adjacent root groups sum to 839, the
  (u, 839-u) pairing. Captures that span several cells confound the rest.
* rar_ul_grant_raw: the 27-bit RAR grant is not split.

### Unfilled blocks are None

A block whose msg_bitmask bit is clear is all zero on the wire. Reading it
would report TA 0 ("0 m from the gNB") and C-RNTI 0 for an attempt that never
got a RAR. Measured over 317 records / 47 captures: with bit1 clear, TA,
TC-RNTI, RAPID and the Msg2 time are 0 on 147/147. With it set, TA is nonzero
on 170/170, so None never hides a real TA 0. Without Msg3 the C-RNTI slot is
0x0000, not the 0xFFFF sentinel (39/39 v0x0a/v0x0e). The RAR grant follows the
block it is logged in, not its spec origin: it is 0 on all 27 v0x0a CFRA
(0x03) records but present on the v0x0e one. msg3_ccch_sdu stays raw bytes;
msg3_ccch is already None when it is zero.

Log name: LOG_NR5G_MAC_RACH_ATTEMPT
Also known as: NR5G MAC RACH Attempt
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

_SIZE = {0x07: 108, 0x0A: 180, 0x0E: 196}

# Per-version field offsets (see module docstring). None = not in this version.
# grant_bit is the msg_bitmask bit of the block the RAR grant is logged in.
_LAYOUT: dict[int, dict[str, int | None]] = {
    0x07: dict(counter=16, ctype=22, mask=23, msg1=28, root=38, preamble=35,
               cv=40, ncs=None, ra_rnti=42, win_start=44, win_end=48,
               msg2=56, tc_rnti=62, ta=64, rapid=None, msg3=68, grant=72,
               grant_bit=0x04, c_rnti=None, ccch=80, post_rnti=104),
    0x0A: dict(counter=8, ctype=18, mask=19, msg1=68, root=76, preamble=78,
               cv=80, ncs=82, ra_rnti=84, win_start=92, win_end=96,
               msg2=112, tc_rnti=118, ta=120, rapid=132, msg3=136, grant=140,
               grant_bit=0x04, c_rnti=148, ccch=152, post_rnti=176),
    0x0E: dict(counter=8, ctype=18, mask=19, msg1=84, root=92, preamble=94,
               cv=96, ncs=98, ra_rnti=100, win_start=108, win_end=112,
               msg2=128, tc_rnti=138, ta=140, rapid=152, msg3=156, grant=132,
               grant_bit=0x02, c_rnti=166, ccch=168, post_rnti=192),
}

# UL-CCCH-MessageType c1 alternatives (TS 38.331).
_UL_CCCH_C1 = ("rrcSetupRequest", "rrcResumeRequest",
               "rrcReestablishmentRequest", "rrcSystemInfoRequest")
_ESTABLISHMENT_CAUSE = (
    "emergency", "highPriorityAccess", "mt-Access", "mo-Signalling", "mo-Data",
    "mo-VoiceCall", "mo-VideoCall", "mo-SMS", "mps-PriorityAccess",
    "mcs-PriorityAccess", "spare6", "spare5", "spare4", "spare3", "spare2", "spare1")
_RESUME_CAUSE = (
    "emergency", "highPriorityAccess", "mt-Access", "mo-Signalling", "mo-Data",
    "mo-VoiceCall", "mo-VideoCall", "mo-SMS", "rna-Update", "mps-PriorityAccess",
    "mcs-PriorityAccess", "spare1", "spare2", "spare3", "spare4", "spare5")


def _sfn_slot(data: bytes, off: int) -> tuple[int | None, int | None]:
    """(sfn, slot) from a packed timing u16; (None, None) when the block is empty."""
    w = unpack_from("<H", data, off)[0]
    if w == 0:
        return None, None
    return w & 0x3FF, (w >> 10) & 0x3F


def _decode_ul_ccch(sdu: bytes) -> dict[str, Any] | None:
    """Split a 48-bit UL-CCCH SDU (UPER) into its message type and identity."""
    if sdu == b"\x00" * 6:
        return None
    bits = format(int.from_bytes(sdu, "big"), "048b")
    if bits[0] != "0":
        return {"message": "messageClassExtension"}
    msg = _UL_CCCH_C1[int(bits[1:3], 2)]
    out: dict[str, Any] = {"message": msg}
    if msg == "rrcSetupRequest":
        # InitialUE-Identity CHOICE (1 bit) + 39-bit value.
        out["ue_identity_type"] = ("ng-5G-S-TMSI-Part1", "randomValue")[int(bits[3])]
        out["ue_identity"] = int(bits[4:43], 2)
        out["establishment_cause"] = _ESTABLISHMENT_CAUSE[int(bits[43:47], 2)]
    elif msg == "rrcResumeRequest":
        out["short_i_rnti"] = int(bits[3:27], 2)
        out["resume_mac_i"] = int(bits[27:43], 2)
        out["resume_cause"] = _RESUME_CAUSE[int(bits[43:47], 2)]
    return out


@dataclass
class Diag0xB88A:
    """0xB88A — NR5G MAC RACH attempt (Msg1 → Msg4)."""
    log_time: int
    version: int
    preamble_tx_counter: int
    contention_type: int
    msg_bitmask: int
    msg1_sfn: int | None
    msg1_slot: int | None
    preamble_index: int
    root_sequence_u: int
    cyclic_shift: int
    n_cs: int | None
    ra_rnti: int
    rar_window_start_sfn: int | None
    rar_window_start_slot: int | None
    rar_window_end_sfn: int | None
    rar_window_end_slot: int | None
    msg2_sfn: int | None
    msg2_slot: int | None
    tc_rnti: int | None
    timing_advance: int | None
    rapid: int | None
    msg3_sfn: int | None
    msg3_slot: int | None
    rar_ul_grant_raw: int | None
    msg3_c_rnti: int | None
    msg3_ccch_sdu: bytes
    msg3_ccch: dict[str, Any] | None
    post_rach_rnti: int
    payload_size: int
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB88A",
            "log_time": self.log_time,
            "version": self.version,
            "preamble_tx_counter": self.preamble_tx_counter,
            "contention_type": self.contention_type,
            "msg_bitmask": self.msg_bitmask,
            "msg1_sfn": self.msg1_sfn,
            "msg1_slot": self.msg1_slot,
            "preamble_index": self.preamble_index,
            "root_sequence_u": self.root_sequence_u,
            "cyclic_shift": self.cyclic_shift,
            "n_cs": self.n_cs,
            "ra_rnti": self.ra_rnti,
            "rar_window_start_sfn": self.rar_window_start_sfn,
            "rar_window_start_slot": self.rar_window_start_slot,
            "rar_window_end_sfn": self.rar_window_end_sfn,
            "rar_window_end_slot": self.rar_window_end_slot,
            "msg2_sfn": self.msg2_sfn,
            "msg2_slot": self.msg2_slot,
            "tc_rnti": self.tc_rnti,
            "timing_advance": self.timing_advance,
            "rapid": self.rapid,
            "msg3_sfn": self.msg3_sfn,
            "msg3_slot": self.msg3_slot,
            "rar_ul_grant_raw": self.rar_ul_grant_raw,
            "msg3_c_rnti": self.msg3_c_rnti,
            "msg3_ccch_sdu": self.msg3_ccch_sdu,
            "msg3_ccch": self.msg3_ccch,
            "post_rach_rnti": self.post_rach_rnti,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }


@register(
    0xB88A,
    name="0xB88A",
    description=(
        "0xB88A — NR5G MAC RACH attempt: preamble counter / contention type / "
        "Msg bitmask, Msg1 SFN/slot + preamble / root u / Cv / N_CS / RA-RNTI, "
        "RAR window, Msg2 TC-RNTI / TA / RAPID, Msg3 C-RNTI or UL-CCCH SDU, "
        "post-RACH RNTI"
    ),
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Body decoded on v0x07 (108 B SDX55), v0x0a (180 B SDX62) and v0x0e "
        "(196 B T99W640) via per-version offset tables. No F3 oracle (no "
        "nr5g_mac_rach F3 site in any F3-bearing capture). Grounded on TS "
        "38.211/38.321 identities over 276 records / 37 captures: RA-RNTI = "
        "1 + 14*t_id 264/264; RAR window = +1 frame 264/264; Cv = (p mod "
        "floor(839/Ncs))*Ncs 118/118 (v0x07 146/146 at Ncs 119/0); RAPID echo "
        "== preamble 107/107; Msg bitmask == filled blocks 264/264; CFRA => "
        "Msg1+Msg2 only; preamble counter 1..10 then RA failure. Msg3 CCCH SDU "
        "== the same-capture 0xB821 UL-CCCH PDU 83/87, and its UPER decode "
        "matches Wireshark nr-rrc 87/87. TA / root u / RAR grant are CANDIDATE."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=26,
    fields_parsed=26,
    field_invariants={
        "version": {"enum": [0x07, 0x0A, 0x0E]},
        "preamble_index": {"range": (0, 63)},
        "root_sequence_u": {"range": (0, 838)},
        "timing_advance": {"range": (0, 3846)},
    },
)
def parse_0xb88a(log_time: int, data: bytes) -> Diag0xB88A | None:
    if len(data) < 1:
        return None
    version = data[0]
    if version not in _SIZE or len(data) < _SIZE[version]:
        return None
    o = _LAYOUT[version]
    u16 = lambda off: unpack_from("<H", data, off)[0]  # noqa: E731
    msg1_sfn, msg1_slot = _sfn_slot(data, o["msg1"])
    ws_sfn, ws_slot = _sfn_slot(data, o["win_start"])
    we_sfn, we_slot = _sfn_slot(data, o["win_end"])
    m2_sfn, m2_slot = _sfn_slot(data, o["msg2"])
    m3_sfn, m3_slot = _sfn_slot(data, o["msg3"])
    preamble = data[o["preamble"]] if version == 0x07 else u16(o["preamble"])
    mask = data[o["mask"]]
    # Msg2 fields exist only once a RAR arrived (msg_bitmask bit1). Without
    # it the slots hold 0, and a TA of 0 would read as "0 m from the gNB".
    has_msg2 = bool(mask & 0x02)
    msg2 = lambda off: u16(off) if has_msg2 and off is not None else None  # noqa: E731
    c_rnti = None
    if (mask & 0x04 and o["c_rnti"] is not None
            and u16(o["c_rnti"]) != 0xFFFF):
        c_rnti = u16(o["c_rnti"])
    ccch = bytes(data[o["ccch"]:o["ccch"] + 6])
    return Diag0xB88A(
        log_time=log_time,
        version=version,
        preamble_tx_counter=data[o["counter"]],
        contention_type=data[o["ctype"]],
        msg_bitmask=mask,
        msg1_sfn=msg1_sfn,
        msg1_slot=msg1_slot,
        preamble_index=preamble,
        root_sequence_u=u16(o["root"]),
        cyclic_shift=u16(o["cv"]),
        n_cs=u16(o["ncs"]) if o["ncs"] is not None else None,
        ra_rnti=u16(o["ra_rnti"]),
        rar_window_start_sfn=ws_sfn,
        rar_window_start_slot=ws_slot,
        rar_window_end_sfn=we_sfn,
        rar_window_end_slot=we_slot,
        msg2_sfn=m2_sfn,
        msg2_slot=m2_slot,
        tc_rnti=msg2(o["tc_rnti"]),
        timing_advance=msg2(o["ta"]),
        rapid=msg2(o["rapid"]),
        msg3_sfn=m3_sfn,
        msg3_slot=m3_slot,
        rar_ul_grant_raw=(unpack_from("<I", data, o["grant"])[0]
                          if mask & o["grant_bit"] else None),
        msg3_c_rnti=c_rnti,
        msg3_ccch_sdu=ccch,
        msg3_ccch=_decode_ul_ccch(ccch),
        post_rach_rnti=u16(o["post_rnti"]),
        payload_size=len(data),
        body_raw=bytes(data[1:]),
    )
