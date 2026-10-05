"""0xB116 — LTE LL1 serving-cell measurement results (legacy `LteMacB116`).

Two wire versions are seen, v0x01 and v0x15, at payload sizes of 28 B
(two-slot) and 48 B (v0x15 four-slot):

- ``config_word`` (u32 @4) is the LTE serving / measured-cell PCI.
- data[1:3] is the LTE ``sfn_subfn`` of the measurement occasion (``sfn`` /
  ``subframe``), grounded on both versions against the co-emitted 0xB0C0 RRC
  header SFN (MDM9600 on v0x01; SDX55 and SDX20 on v0x15).
- data[3] is a raw ``marker`` byte.
- ``slot_values`` is one raw u16 per Rx chain, F3-grounded per chain on an
  RF-dynamic SDX20 drive capture; its absolute scale is mode-dependent.

The registry name is ``0xB116``, the class and type string ``Diag0xB116``.
``config_word`` falls back to byte 1 on a record too short for u32 @4, and
``data_density`` is the non-zero byte fraction of data[2:].

Log name: LOG_LTE_LL1_SERVING_CELL_MEASUREMENT_RESULTS
Also known as: LTE LL1 Serving Cell Measurement Result
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0xB116:
    """0xB116 — LTE LL1 serving-cell measurement (legacy `LteMacB116`).

    ``sfn`` / ``subframe`` are decoded on v0x01 and v0x15 (both grounded
    against the co-emitted 0xB0C0 RRC-header SFN). ``marker``
    (raw data[3]) is set on both. ``slot_values`` is one raw u16 per Rx chain
    (slot i = chain i, 0 = not populated), read at the three grounded
    ``(version, length)`` layouts in ``_SLOT_LAYOUT``. All four are ``None``
    on any other (longer) record; truncated records return None.
    """
    log_time: int
    version: int
    config_word: int
    data_density: float
    payload_size: int
    body_raw: bytes
    sfn: int | None = None
    subframe: int | None = None
    marker: int | None = None
    slot_values: tuple[int, ...] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB116",
            "log_time": self.log_time,
            "version": self.version,
            "config_word": self.config_word,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
            "sfn": self.sfn,
            "subframe": self.subframe,
            "marker": self.marker,
            "slot_values": (list(self.slot_values)
                            if self.slot_values is not None else None),
        }


# byte 0 is the DIAG log version. Across the corpus, every byte-0 value seen
# at payload size > 4 is in {0x01, 0x15} (size <= 4 is HDLC framing residue).
# Size varies across versions and chipsets, so there is no payload_size
# invariant: a constant size is not a format invariant.
_B116_VERSIONS_OBSERVED = (0x01, 0x15)

# v0x01 — 28 B, Sierra MC7700 (MDM9600), 950 records / 10 captures / 3
# firmware builds, grounded field-by-field.
# The 28 B record is the TWO-slot instance of the grammar the 48 B v0x15
# record fills with four slots:
#   +0 version · +1 u16 sfn_subfn · +3 marker · +4 u32 config_word (PCI)
#   +8..+15 zero · +16,+17 per-slot const 0x28 · +18 0x08 · +19..+23 zero
#   +24 u16 slot_values[0] · +26 u16 slot_values[1]
# sfn_subfn uses the 0xB0C0 header packing (subframe 4b | SFN 10b | 2
# reserved bits): SFN = the serving cell's radio-frame number of the
# measurement occasion, matched against the co-emitted 0xB0C0 RRC header SFN
# on 407/407 records and SCAT's GSMTAP frame number on 278/278.
# slot_values are INVERSE to serving RSRP (AGC-gain class), not an RSRP.
V01_VERSION = 0x01
V15_VERSION = 0x15
_V01_TWO_SLOT_LEN = 28
_V15_FOUR_SLOT_LEN = 48

# (version, length) -> (offset, count) of the per-Rx-chain u16 slot array
# The slot offset depends on the slot count, so a length not
# listed here gets no slot_values. 28 B v0x15 (MDM9x07/9x30 class, 25,757
# records) is byte-identical to the v0x01 two-slot grammar; 48 B v0x15 carries
# four slots after a per-slot const quad at +24..+27 and 0x08 at +28.
_SLOT_LAYOUT = {
    (V01_VERSION, _V01_TWO_SLOT_LEN): (24, 2),
    (V15_VERSION, 28): (24, 2),
    (V15_VERSION, 48): (38, 4),
}


# config_word == LTE serving / measured-cell PCI, verified on EG25-G and Telit
# LM960. On EG25-G an LTE limited-service run saw config_word in {236
# (serving), 221 (AT-confirmed neighbour), 404}, 99.4% of records in the
# AT+QENG PCI set; on LM960 config_word in {242, 3} == AT#CSURV phyCellId.
# Both modems show config_word tracking the measured-cell PCI, not a constant.

@register(
    0xB116,
    name="0xB116",
    description=(
        "0xB116 — LTE LL1 serving-cell measurement results: config_word @4 == "
        "LTE serving / measured-cell PCI; data[1:3] = LTE sfn_subfn of the "
        "measurement occasion (sfn/subframe, v0x01 and v0x15); data[3] = a "
        "13-value nibble-structured marker, not cell identity; slot_values = "
        "per-Rx-chain raw u16 energy (+24/+26 at 28 B, +38/+40/+42/+44 at 48 B), "
        "inverse to own-chain RSRP (AGC-gain class, not an RSRP) with a "
        "measurement-mode-dependent scale, so no dB conversion is applied"
    ),
    version=24,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "config_word (u32@4) == LTE serving / measured-cell PCI, verified against "
        "same-modem serving-PCI readouts (AT+QENG, AT!LTEINFO?, AT#CSURV, QMI, "
        "co-emitted 0xB0C0 / 0xB193) on nine module families across MDM9600, "
        "MDM9230, X16, SDX20, SDX55 and SDX62, with multi-value runs matching "
        "neighbour PCIs and values > 255 confirming full PCI width. data[1:3] is "
        "the LTE sfn_subfn (subframe 4b | SFN 10b | 2 reserved bits, the 0xB0C0 "
        "header packing). On v0x01 (28 B, MC7700 / MDM9600, all 950 corpus "
        "records) the SFN matches the co-emitted 0xB0C0 RRC header SFN on "
        "407/407 records and SCAT's GSMTAP frame number on 278/278; the record "
        "step follows the SIB2 idle paging cycle. On v0x15 the structural "
        "signature holds on 11,845/11,845 records across SDX55 (RM500Q-AE, FN980) "
        "and SDX20 (LM960A18), and the SFN matches the co-emitted 0xB0C0 with a "
        "median residual of 0-1 sfn_subfn units. slot_values is the per-Rx-chain "
        "u16 array (+24/+26 in the 28 B two-slot grammar shared by v0x01 and "
        "28 B v0x15; +38..+44 at 48 B after a per-slot constant quad at +24..+27 "
        "and 0x08 at +28). It is F3-grounded per chain on an RF-dynamic SDX20 "
        "drive capture (22,128 records co-emitted with the connected-mode "
        "per-chain serving RSRP print; own-chain partial r = -0.55/-0.57, "
        "cross-chain ~0; rx2/rx3 silent and at most two slots populated), and "
        "inverse to serving RSRP on MDM9600 against 0xB17F (r = -0.94, n = 793) "
        "and on SDX62 (high byte steps with a weak serving cell). The scale is "
        "raw and mode-dependent (idle ~20 dB above connected at equal RSRP), so "
        "no dB conversion is applied. Known gaps: the four-slot per-chain reading "
        "on SDX55/SDX62 is a structural transfer without per-chain F3 truth; why "
        "slots 2-3 populate only intermittently on SDX62 is open; the marker "
        "byte's 13 nibble-structured values are not decoded. Payloads shorter "
        "than 28 B, or v0x15 between 28 and 48 B, return None."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=6,
    fields_parsed=6,
    field_invariants={
        "version": {"enum": [0x01, 0x15]},
    },
    # Time-alignment capability: 0xB116 is a METRONOME. It emits once per
    # measurement occasion, and data[1:3] (16-bit LE) steps 1024 or 2048 per
    # record while ts64 steps 2^25 / 2^26. That field is the LTE sfn_subfn,
    # the serving cell's radio-frame clock, on both v0x01 and v0x15; it is not
    # derived from ts64. An SFN is a radio-frame beat that wraps every 10.24 s,
    # not a wall-clock or GPS map, so the role is "metronome" only, not a
    # ts-anchor or absolute time. The cadence is the idle DRX paging cycle and
    # so depends on modem state (LM960 on B48 fires ~64x faster than on B66).
    timebase_roles=("metronome",),
)
def parse_0xb116(log_time: int, data: bytes) -> Diag0xB116 | None:
    if len(data) < 1:
        return None
    version = data[0]
    if version not in _B116_VERSIONS_OBSERVED:
        return None
    # Every attested layout is 28 B (two-slot) or
    # 48 B (v0x15 four-slot). Shorter than 28 B, or a v0x15 between the two, is
    # a truncated record — return None (registry WARN) instead of a stub.
    if len(data) < _V01_TWO_SLOT_LEN:
        return None
    if version == V15_VERSION and _V01_TWO_SLOT_LEN < len(data) < _V15_FOUR_SLOT_LEN:
        return None
    if len(data) >= 8:
        config_word = unpack_from('<I', data, 4)[0]
    elif len(data) >= 2:
        config_word = data[1]
    else:
        config_word = 0
    if len(data) > 2:
        nonzero = sum(1 for b in data[2:] if b != 0)
        total = max(len(data) - 2, 1)
        density = round(nonzero / total, 2)
    else:
        density = 0.0
    sfn = subframe = marker = None
    slot_values = None
    if version == V01_VERSION and len(data) >= 4:
        sfn_subfn = unpack_from('<H', data, 1)[0]
        subframe = sfn_subfn & 0xF
        sfn = (sfn_subfn >> 4) & 0x3FF
        marker = data[3]
    elif version == V15_VERSION and len(data) >= 4:
        # data[1:3] is the same LTE sfn_subfn packing as v0x01 and the 0xB0C0
        # RRC header (subframe 4b | SFN 10b | 2 reserved bits). The structural
        # signature holds on 11,845/11,845 v0x15 records across SDX55
        # (RM500Q-AE, FN980) and SDX20 (LM960A18): reserved bits always clear,
        # SFN <= 1023, subframe in {0..9}. The SFN matches the co-emitted 0xB0C0
        # RRC-header SFN (ts64-projected nearest neighbour) with a median
        # residual of 0-1 sfn_subfn units (1639/1686 within one frame on
        # RM500Q-AE, median 0). marker (data[3]) is exposed raw: on v0x15 it
        # takes 13 nibble-structured values (measurement context), not the
        # paging-cycle key it is on v0x01.
        sfn_subfn = unpack_from('<H', data, 1)[0]
        subframe = sfn_subfn & 0xF
        sfn = (sfn_subfn >> 4) & 0x3FF
        marker = data[3]
    # slot i = Rx chain i: per-chain F3-grounded on an RF-dynamic SDX20 drive
    # (own-chain partial r = -0.55/-0.57, cross-chain ~0). Raw u16,
    # inverse to that chain's RSRP with a mode-dependent scale; 0 = the chain was
    # not populated on this occasion (the count tracks the active Rx chains).
    layout = _SLOT_LAYOUT.get((version, len(data)))
    if layout is not None:
        off, count = layout
        slot_values = unpack_from(f'<{count}H', data, off)
    return Diag0xB116(
        log_time=log_time,
        version=version,
        config_word=config_word,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
        sfn=sfn,
        subframe=subframe,
        marker=marker,
        slot_values=slot_values,
    )
