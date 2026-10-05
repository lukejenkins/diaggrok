"""0x14CE — LOG_UIM_DS_DATA: UIM (smart-card) T=0 APDU byte log.

See the module body for the item grammar, field map and evidence.

Log name: LOG_UIM_DS_DATA
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# 0x14CE — LOG_UIM_DS_DATA: UIM (smart-card) APDU byte log
# ---------------------------------------------------------------------------
# F3-grounded: the record is the UIM driver's byte-level transcript of the
# ISO 7816-3 T=0 link to the SIM/UICC. It is not a GNSS log despite the code
# range, and it has no TLV tag catalog, heartbeat frames or layout-version
# byte — those readings are explained by the item grammar below.
#
# Layout (validated corpus-wide):
#
#     [0]      u8   length          = payload_size - 1 (self-length prefix)
#     [1..]    item stream, consumed exactly to the end of the payload:
#                data item  (3 B): u8 attrib, u8 slot, u8 byte
#                   attrib 0x10 = TX  (UIM driver -> card)
#                   attrib 0x80 = RX  (card -> UIM driver)
#                ts item   (10 B): u8 attrib = 0x01, u8 slot,
#                                  u64 LE DIAG timestamp (same ts64 axis as
#                                  the DIAG log header)
#              `slot` (CANDIDATE, 0-based UIM instance) is constant within a
#              record: 0x00 on 25,827 records; 0x01 on every item of the 16
#              records from Fibocom FM101-GL + Foxconn T77W968 (no F3 slot print
#              in those captures to confirm the reading).
#
# A normal record is `len + N data items + 1 ts item` = 3N + 11 bytes. Read as
# fixed triplets, the ts item looks like a "(0x01, 0x00, x) terminator triplet
# + 5-byte tail + 0x0F/0x10/0x11 + 0x01"; those bytes are simply bytes 0, 1-5,
# 6 and 7 of the u64 timestamp. A record with no ts item (82 data items = the
# fixed 247-B class) is a CONTINUATION chunk
# of a long transfer (e.g. a 250-byte READ BINARY response) that filled the log
# buffer; the transfer's last chunk carries the ts item.
#
# Evidence (corpus: 25,843 records / 88 captures; 25,827 = 99.94 % consume
# exactly to `len` under this item grammar; 25,005 carry a ts item, 822 are
# ts-less continuation chunks; the 16 others are the slot-1 records, which
# also parse). Whole-corpus walk: 25,843 / 25,843 parse, 0 invariant
# violations; SW histogram 9000 ×6629, 61xx, 6A82 ×406,
# 91xx; cmd_header INS READ RECORD / SELECT / GET RESPONSE / READ BINARY /
# STATUS / FETCH / TERMINAL RESPONSE … (5 unnamed = 5-byte TX data runs, the
# documented CANDIDATE ambiguity):
#   * ISO 7816 transcript, byte for byte. A SIM power cycle (EG95-NA
#     capture) reads as: RX ATR `3B 9F 96 80 1F C6 …`; TX/RX PPS
#     `FF 10 96 79`; TX `00 A4 00 04 02` (SELECT) / RX `A4` (T=0 procedure
#     byte = INS echo) / TX `3F 00` (MF) / RX `61 1F`; TX `00 C0 00 00 1F`
#     (GET RESPONSE) / RX FCP `62 1D 82 02 78 21 83 02 3F 00 …` `90 00`; then
#     EF-ICCID READ BINARY, TERMINAL PROFILE (80 10), FETCH (80 12) /
#     TERMINAL RESPONSE (80 14), SELECT-by-AID of the 3GPP USIM
#     (A0000000871002…), VERIFY-PIN retry query (00 20 … -> 63 Cx) …
#     The recurring 74-byte record with 0xF2 is the periodic UICC STATUS
#     poll: RX `F2` (procedure byte) + `84 10 <16-B USIM AID>` + `90 00`.
#   * F3 value-level join (the in-capture oracle). The UIM driver prints the
#     outcome of every command: `UIM_%d: cmd status 0x%x SW1 0x%x,SW2 0x%x,
#     Response data length 0x%x` (LM960 uim.c:1961, 0x79 plaintext). Joined to
#     the reassembled 0x14CE command in flight at each print: 196/199 exact on
#     SW1 + SW2 + response length (= RX bytes minus the INS procedure byte and
#     SW). The 3 misses are reassembly-heuristic artifacts (2× two back-to-back
#     250-B READ BINARYs merged; 1 error-path command). Sierra EM7565
#     (0x99 QSR4; the hash database labels the format "AID is present" but
#     the [slot, status, SW1, SW2, len] args are identical): 21/21.
#     Note the print fires BEFORE the response's 0x14CE record is flushed.
#   * Timestamp. u64 at the ts item == DIAG header ts64 within −211 raw
#     units .. +10 ms (20,749 within +1 ms), and its byte 6 ==
#     (header_ts64 >> 48) & 0xFF in every capture: 0x00 on boot-relative-clock captures,
#     0x0F -> 0x10 -> 0x11 -> 0x12 as the GPS-synced clock advances (one step
#     ~ 62 days). It is a clock byte, not a layout version.
#
# Gating on byte[-2] as a "version" would reject every boot-clock record
# (whose ts item reads as a "zeroed tail") and every record past the next
# clock rollover: 19,740 of 25,021 well-formed records (79 %) in the current
# corpus. The parser is `version_less` — no byte of the record is a layout
# version — and gates on the item stream itself instead.
#
# Names: the procedure-byte / status-word / command-header names are the ISO
# 7816-3/-4 T=0 conventions and are F3-grounded for SW + length only. The
# per-record `cmd_header` / `status_word` are single-record CANDIDATES: a
# 5-byte TX run is a command header only when it opens a command (a TX data
# run can also be 5 bytes), and a trailing 2-byte RX run is the status word
# only when it closes the response. Reassembling commands across records is a
# consumer's job (records split at every direction change).
#
# PII: RX data carries the card's identifiers (EF-ICCID, EF-IMSI, MSISDN …).
# They are decoded in full (rx_hex); fixtures and docs use non-identifying
# records only.
#
# Shape-based readings this grammar accounts for: byte 0 is a length prefix
# (not a subtype); a "40-bit inner tick" is ts64 bytes 1-5; apparent "tags",
# "heartbeats" and "transport flags" are INS procedure bytes, SWs (0x6C =
# "wrong Le") and CLA 0x80; a "sentinel 0x0F/0x01" is ts64 bytes 6-7.

_ATTR_TX = 0x10
_ATTR_RX = 0x80
_ATTR_TS = 0x01
_DATA_ITEM_LEN = 3
_TS_ITEM_LEN = 10

# ISO 7816-4 / ETSI TS 102 221 INS codes observed in the corpus.
_INS_NAMES: dict[int, str] = {
    0x04: 'DEACTIVATE FILE', 0x10: 'TERMINAL PROFILE', 0x12: 'FETCH',
    0x14: 'TERMINAL RESPONSE', 0x20: 'VERIFY PIN', 0x24: 'CHANGE PIN',
    0x26: 'DISABLE PIN', 0x28: 'ENABLE PIN', 0x2C: 'UNBLOCK PIN',
    0x32: 'INCREASE', 0x44: 'ACTIVATE FILE', 0x70: 'MANAGE CHANNEL',
    0x73: 'MANAGE SECURE CHANNEL', 0x75: 'TRANSACT DATA', 0x84: 'GET CHALLENGE',
    0x88: 'AUTHENTICATE', 0x89: 'AUTHENTICATE', 0xA2: 'SEARCH RECORD',
    0xA4: 'SELECT', 0xAA: 'TERMINAL CAPABILITY', 0xB0: 'READ BINARY',
    0xB2: 'READ RECORD', 0xC0: 'GET RESPONSE', 0xC2: 'ENVELOPE',
    0xCA: 'GET DATA', 0xCB: 'RETRIEVE DATA', 0xD6: 'UPDATE BINARY',
    0xDB: 'SET DATA', 0xDC: 'UPDATE RECORD', 0xF2: 'STATUS',
}

# SW1 values that can close a T=0 response (ISO 7816-4 §5.6, ETSI TS 102 221
# §10.2). 0x60 and 0x6X "procedure" values that never end a response are absent.
_SW1_FINAL = frozenset({
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C,
    0x6D, 0x6E, 0x6F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x98, 0x9E, 0x9F,
})


@dataclass
class Diag0x14CE:
    """0x14CE LOG_UIM_DS_DATA — UIM T=0 APDU byte log."""
    log_time: int
    length: int                       # byte[0] = payload_size - 1
    slot: int                         # CANDIDATE: byte 1 of every item (0-based UIM slot)
    runs: list[tuple[str, bytes]]     # consecutive same-direction bytes, in wire order
    n_data_items: int
    has_timestamp: bool               # False => continuation chunk (buffer-full)
    timestamp: int | None             # u64 DIAG ts64 from the ts item
    payload_size: int

    @property
    def tx_bytes(self) -> bytes:
        return b''.join(b for d, b in self.runs if d == 'tx')

    @property
    def rx_bytes(self) -> bytes:
        return b''.join(b for d, b in self.runs if d == 'rx')

    @property
    def cmd_header(self) -> dict[str, Any] | None:
        """CANDIDATE: a record that is exactly one 5-byte TX run."""
        if len(self.runs) != 1 or self.runs[0][0] != 'tx' or len(self.runs[0][1]) != 5:
            return None
        cla, ins, p1, p2, p3 = self.runs[0][1]
        return {'cla': cla, 'ins': ins, 'ins_name': _INS_NAMES.get(ins),
                'p1': p1, 'p2': p2, 'p3': p3}

    @property
    def status_word(self) -> int | None:
        """CANDIDATE: the last two RX bytes when the record ends on an RX run
        whose penultimate byte is a closing SW1 (F3-grounded, see module)."""
        if not self.runs or self.runs[-1][0] != 'rx' or len(self.runs[-1][1]) < 2:
            return None
        sw1, sw2 = self.runs[-1][1][-2:]
        return (sw1 << 8) | sw2 if sw1 in _SW1_FINAL else None

    def to_dict(self) -> dict[str, Any]:
        hdr = self.cmd_header
        sw = self.status_word
        return {
            'type': 'Diag0x14CE',
            'log_time': self.log_time,
            'length': self.length,
            'slot': self.slot,
            'n_data_items': self.n_data_items,
            'first_dir': self.runs[0][0] if self.runs else None,
            'runs': [{'dir': d, 'hex': b.hex()} for d, b in self.runs],
            'tx_hex': self.tx_bytes.hex(),
            'rx_hex': self.rx_bytes.hex(),
            'cmd_header': hdr,
            'status_word': sw,
            'has_timestamp': self.has_timestamp,
            'timestamp': self.timestamp,
            'timestamp_delta': (None if self.timestamp is None
                                else self.timestamp - self.log_time),
            'payload_size': self.payload_size,
        }


@register(
    0x14CE,  # domain unset: UIM has no domain bucket (F3 shows it is not GNSS)
    name="0x14CE",
    description="LOG_UIM_DS_DATA — UIM T=0 APDU byte log: len prefix + (attrib 0x10 TX / 0x80 RX, slot, byte) items + optional (0x01, slot, u64 ts64) item. F3-grounded 217/220 on SW1/SW2/response length (LM960 uim.c:1961 + EM7565). No version byte: byte[-2] is ts64 byte 6.",
    version=11,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room RE, F3-grounded. The record is the UIM driver's ISO 7816-3 T=0 byte transcript — items (attrib, slot, byte) with attrib 0x10 = TX, 0x80 = RX, and a trailing (0x01, slot, u64 LE ts64) timestamp item (== DIAG header ts64 within ~1 ms; byte 6 == header ts64 byte 6 in all 88 captures); 25,827/25,843 records fit the grammar exactly, the other 16 are slot-1 (byte 1 = 0x01 on FM101-GL/T77W968) and also parse. No byte is a layout version (byte[-2] is ts64 byte 6, a clock), so the parser gates on the item stream and is version_less. F3 value join: the UIM driver's per-command outcome print `UIM_%d: cmd status SW1 SW2 Response data length` matches the reassembled 0x14CE command 196/199 (Telit LM960, uim.c:1961, 0x79) and 21/21 (Sierra EM7565, QSR4) on SW1+SW2+length. 247-B records are ts-less continuation chunks (82 items) of long transfers. qcsuper/SCAT/rayhunter declare neither 0x14CE nor 0x1098.",
    source_url="",
    fields_parsed=13,
    fields_identified=13,
    issues=(),
    primary_issue=None,
    ascii_kinds=("identifier",),
    # Version-less: byte 0 is the self-length
    # prefix and the former byte[-2] "version" is ts64 byte 6 (a clock).
    version_less=True,
)
def parse_0x14ce(log_time: int, data: bytes) -> Diag0x14CE | None:
    n = len(data)
    if n < 1 + _DATA_ITEM_LEN or data[0] + 1 != n:
        return None
    slot = data[2]
    runs: list[tuple[str, bytearray]] = []
    n_items = 0
    timestamp = None
    i = 1
    while i < n:
        attrib = data[i]
        if attrib in (_ATTR_TX, _ATTR_RX):
            if i + _DATA_ITEM_LEN > n or data[i + 1] != slot:
                return None
            d = 'tx' if attrib == _ATTR_TX else 'rx'
            if runs and runs[-1][0] == d:
                runs[-1][1].append(data[i + 2])
            else:
                runs.append((d, bytearray((data[i + 2],))))
            n_items += 1
            i += _DATA_ITEM_LEN
        elif attrib == _ATTR_TS:
            # The ts item closes the record; anything after it is not this layout.
            if i + _TS_ITEM_LEN != n or data[i + 1] != slot:
                return None
            timestamp = int.from_bytes(data[i + 2:i + 10], 'little')
            i += _TS_ITEM_LEN
        else:
            return None
    if n_items == 0:
        return None
    return Diag0x14CE(
        log_time=log_time,
        length=data[0],
        slot=slot,
        runs=[(d, bytes(b)) for d, b in runs],
        n_data_items=n_items,
        has_timestamp=timestamp is not None,
        timestamp=timestamp,
        payload_size=n,
    )
