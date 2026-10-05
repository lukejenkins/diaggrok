"""0xB17F — LTE ML1 cell record: earfcn@4 + pci@8 (legacy `LtePdcpB17F`).

**The canonical name does not fit the content; the aliases do.** The
canonical log name is `LOG_LTE_ML1_PBCH_DECODE_LOG_PACKET`, but
the record decodes as per-cell identity (earfcn + pci) plus
rsrp/rsrq/rssi, emitted for serving *and* neighbour cells alike. That is a
cell-measurement record, not a PBCH decode — the aliases
`LOG_LTE_ML1_SERVING_CELL_MEASUREMENTS` /
`LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL` fit what the bytes actually carry.
The registered `description` notes the name as contested rather than
renaming the code.

The u32 at byte-offset 4 was first identified as the **EARFCN** of the
record's cell by DIAG×AT correlation on an LM960A18 (SDX20), 294/294
records. `to_dict()` emits it under an `earfcn` key (never the generic
`config_word`), so consumers keyed on `earfcn` keep working.

Log name: LOG_LTE_ML1_PBCH_DECODE_LOG_PACKET
Also known as: LOG_LTE_ML1_SERVING_CELL_MEASUREMENTS, LOG_LTE_ML1_SERVING_CELL_MEASUREMENTS_AND_EVALUATION, LOG_PBCH_DECODE_LOG_PACKET, LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

# byte-0 version/layout discriminator — both values observed at
# size>4: 0x05 (size 40, 49,990 records) and 0x03 (size 32, 612 records). byte-0
# co-varies with payload size, so it is the de-facto version/sub-layout field.
_B17F_VERSIONS_OBSERVED = (0x03, 0x05)

# byte-0 co-varies with payload size: 0x05 -> 40 B, 0x03 -> 32 B. The two
# layouts carry the SAME semantic record with different field widths — v0x03
# (older MDM9200 / Sierra MC7700 packing) uses 16-bit identity fields where
# v0x05 uses 32-bit, so everything after byte 4 shifts down 4 bytes and v0x05's
# trailing @36 word is absent (40 - 4 - 4 = 32). Each layout is decoded by its
# own branch in parse_0xb17f(); applying one layout's offsets to the other
# emits garbage.
_B17F_V05_SIZE = 40
_B17F_V03_SIZE = 32


@dataclass
class Diag0xB17F:
    """0xB17F — per-cell LTE ML1 record (legacy `LtePdcpB17F`).

    `earfcn` is the u32-LE at byte-offset 4. DIAG×AT correlation against
    serving-cell EARFCN sets confirms this is the cell-attribution field.
    For payloads < 8B the byte-1 fallback applies; for < 2B
    the slot is 0 — match the `_simple_parser` factory's parse contract.

    `pci` is the low 9 bits of the u32-LE at byte-offset 8 = the cell's
    PhysCellID; 0 on payloads < 12 B. Together `(earfcn, pci)`
    identify which cell each record pertains to — the tuple reproduces
    independently surveyed serving *and* neighbour cells, so records are not
    serving-cell-only.

    The measurement block uses 12-bit fixed-point subfields of a
    u32 — the same convention as sibling 0xB193:

        rsrp = (u32@12       & 0xFFF) / 16 - 180   dBm
        rsrq = ((u32@20>>20) & 0xFFF) / 16 -  30   dB
        rssi = ((u32@24>>10) & 0xFFF) / 16 - 110   dBm

    v0x03 carries the SAME fields at DIFFERENT offsets — a 32 B layout with
    16-bit identity fields (older MDM9200 / Sierra MC7700 packing), everything
    after byte 4 shifted down 4 bytes:

        earfcn = u16@4
        pci    = u16@6 & 0x1FF
        rsrp   = (u32@8        & 0xFFF) / 16 - 180   dBm
        rsrq   = ((u32@16>>20) & 0xFFF) / 16 -  30   dB
        rssi   = ((u32@20>>10) & 0xFFF) / 16 - 110   dBm

    Each layout is decoded by its own version branch; a payload too short for
    its layout is truncated and the parser returns None. Applying the
    other layout's offsets produces garbage: v0x05's u32@4 read out of a
    v0x03 frame gives a 9-digit EARFCN on 794/794 corpus records. AT-grounded on the MC7700 (earfcn 2300 == AT!GSTATUS,
    pci 236 == the EG25-G/CFW-3212 serving cell, rsrp median -101.25 vs AT -100).

    **Two filtered RSRP words at two filter time-constants.**
    `u32@12` and `u32@16` each carry a 12-bit RSRP TWICE (bits 0..11 and
    12..23 — 8,489/8,489 drive records have the two halves identical). The two
    WORDS are two IIR taps of the same serving RSRP:

        rsrp     = (u32@12 & 0xFFF)/16 - 180   the shorter/FASTER tap
        rsrp_avg = (u32@16 & 0xFFF)/16 - 180   the longer/SLOWER (averaged) tap

    Grounded on 3 Telit FN980 (SDX55) DRIVE captures — the regime where the two
    taps separate (a stationary camp converges them; a memcpy chipset never
    separates them). Over 5,257 sample-pairs: `var(Δrsrp) ≈ 2×var(Δrsrp_avg)`
    (rsrp_avg is smoother), lag-1 autocorr(rsrp_avg) > autocorr(rsrp), and the
    signed difference `(rsrp - rsrp_avg)` correlates with `d(RSRP)/dt` at
    Pearson **r ≈ +0.65** — i.e. rsrp LEADS on rising RSRP and lags on falling,
    the defining fast-vs-slow-filter signature. Scale-grounded to AT#MONI over
    the same drive (medians −94.5 / −94.6 vs AT −95.0).

    **The separation is chipset-dependent.** FN980 (SDX55) and CFW-3212
    (SDX62) write two distinct taps (FN980: 216/2350 records differ by >1 dB
    under motion; CFW-3212 shows the 1-LSB stationary divergence). Quectel
    RM520N-GL / RM500Q-AE, Telit LM960 (SDX20) and the MDM9200 v0x03 parts
    copy one value into both slots, so `rsrp_avg == rsrp` there. A stationary
    capture on such a chipset (e.g. MC7411) shows all four 12-bit slots
    equal. Neither word is the ML1 `rsrp_inst` (F3: ~1 dB above both) — both
    are filtered; `rsrp` is just the shorter tap. The two words are not an
    rx0/rx1 split; the measured-vs-averaged axis is a fast-tap/slow-tap axis.
    """
    log_time: int
    version: int
    earfcn: int
    pci: int
    rsrp: float | None
    rsrp_avg: float | None
    rsrq: float | None
    rssi: float | None
    data_density: float
    payload_size: int
    body_raw: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB17F",
            "log_time": self.log_time,
            "version": self.version,
            "earfcn": self.earfcn,
            "pci": self.pci,
            "rsrp": self.rsrp,
            "rsrp_avg": self.rsrp_avg,
            "rsrq": self.rsrq,
            "rssi": self.rssi,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }


# Emission hardware-validated on a connected EG25-G.

@register(
    0xB17F,
    name="0xB17F",
    wigle_direct=True,
    wigle_roles=("signal", "pci-earfcn-bridge", "rat-context"),
    description="0xB17F — LTE ML1 per-cell measurement record (fixed 40B; earfcn+pci identity + rsrp/rsrp_avg/rsrq/rssi; canonical name contested, see docstring; legacy mislabel LtePdcpB17F)",
    version=12,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Two fixed layouts keyed on byte 0: v0x05 (40 B) and v0x03 (32 B, the "
        "older MDM9200 / Sierra MC7700 packing with 16-bit identity fields and "
        "everything after byte 4 shifted down 4 bytes). earfcn = u32@4 (v0x05) "
        "/ u16@4 (v0x03), first attributed by LM960A18 DIAG×AT correlation; "
        "corpus max 68,911 over 32,601 records / 239 captures, none over the "
        "18-bit width. pci = u32@8 & 0x1FF (v0x05) / u16@6 & 0x1FF (v0x03); "
        "the mask matters because bits above 8 carry an unidentified field "
        "(observed {0,2,3,4,6}), so raw u16@8 reads 3308 where the PCI is 236. "
        "Cross-chipset on 1,542 v0x05 records with zero out-of-range: EG25-G "
        "MDM9607 306/306 -> PCI 236 == AT+QENG servingcell, CFW-3212 SDX62 "
        "223/223 on-earfcn -> 236 == AT+QENG, MC7411 SDX50M 135/136 on-earfcn "
        "-> 473 == the surveyed serving PCI; the (earfcn, pci) tuple also "
        "reproduces 5 of 8 independently surveyed cells (serving + 4 "
        "neighbours) on the MC7411 capture. Measurement block: "
        "rsrp=(u32@12 & 0xFFF)/16-180 dBm, rsrq=((u32@20>>20) & 0xFFF)/16-30 dB, "
        "rssi=((u32@24>>10) & 0xFFF)/16-110 dBm on v0x05 (each 4 bytes earlier "
        "on v0x03), the same 12-bit fixed-point convention as sibling 0xB193. "
        "Against SCAT's independent 16-cell decode of the MC7411 survey: MAE "
        "0.41 dB (rsrp) / 0.65 (rsrq) / 0.46 (rssi), 8 of 16 cells bit-exact. "
        "Against AT: EG25-G rsrp -100.88 (AT+QENG -101), CFW-3212 -106.88 (AT "
        "-107). v0x03 decodes all 794 corpus records (Sierra MC7700 / MDM9200, "
        "9 captures) with zero invariant violations; an MC7700 capture gives "
        "cell (2300, 236), earfcn == AT!GSTATUS, rsrp median -101.25 vs AT -100. "
        "rsrp_avg = the slower filter tap: u32@12 and u32@16 (v0x05) each carry "
        "a 12-bit RSRP twice (halves equal 8,489/8,489 across 4 chipsets under "
        "motion); over 5,257 sample-pairs from 3 Telit FN980 (SDX55) drive "
        "captures var(Δrsrp)≈2×var(Δrsrp_avg), autocorr(rsrp_avg) > "
        "autocorr(rsrp), and (rsrp-rsrp_avg) correlates with d(RSRP)/dt at "
        "r≈+0.65; scale-grounded to AT#MONI (medians -94.5/-94.6 vs AT -95.0). "
        "Separation is chipset-dependent: FN980/SDX55 and CFW-3212/SDX62 write "
        "two distinct taps; RM520N-GL/RM500Q-AE, LM960/SDX20 and MDM9200 v0x03 "
        "copy one value into both. Neither tap is the ML1 rsrp_inst (F3 ~1 dB "
        "above both), and the words are not an rx0/rx1 split. Payloads shorter "
        "than the fixed layout return None (registry warning)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=7,
    fields_parsed=7,
    field_invariants={
        "version": {"enum": list(_B17F_VERSIONS_OBSERVED)},
        "earfcn": {"range": (0, 262143)},
        "pci": {"range": (0, 511)},
        "rsrp": {"range": (-140.0, -30.0)},
        "rsrp_avg": {"range": (-140.0, -30.0)},
        "rsrq": {"range": (-40.0, 0.0)},
        "rssi": {"range": (-130.0, -20.0)},
    },
)
def parse_0xb17f(log_time: int, data: bytes) -> Diag0xB17F | None:
    if len(data) < 1:
        return None
    version = data[0]
    # Layer-1 byte-0 version gate.
    if version not in _B17F_VERSIONS_OBSERVED:
        return None
    # Each version is a fixed layout (v0x03 32 B, v0x05 40 B); a shorter
    # payload is truncated -> None (registry warning) instead of a record
    # with the measurement block silently None.
    if len(data) < (_B17F_V03_SIZE if version == 0x03 else _B17F_V05_SIZE):
        return None
    rsrp = rsrp_avg = rsrq = rssi = None
    if version == 0x03:
        # v0x03 — older MDM9200 (Sierra MC7700) packing: 16-bit identity
        # fields where v0x05 uses 32-bit. Reading v0x05's u32@4 earfcn /
        # u32@8 pci out of a v0x03 frame gives a 9-digit garbage channel
        # number on 794/794 corpus records.
        # Every field is v0x05's shifted down 4 bytes (identity halved u32->u16):
        #   earfcn u16@4, pci u16@6, rsrp u32@8 (doubled @12), rsrq u32@16,
        #   rssi u32@20 — 32 B total (v0x05's trailing @36 word is absent).
        if len(data) >= 6:
            earfcn = unpack_from('<H', data, 4)[0]
        elif len(data) >= 2:
            earfcn = data[1]
        else:
            earfcn = 0
        pci = (unpack_from('<H', data, 6)[0] & 0x1FF) if len(data) >= 8 else 0
        if len(data) >= _B17F_V03_SIZE:
            rsrp = (unpack_from('<I', data, 8)[0] & 0xFFF) / 16 - 180
            # rsrp_avg — the slower/averaged filter tap. In v0x03's
            # shifted layout it is u32@12 (the doubled RSRP word after rsrp@8);
            # MDM9200 memcpies it so rsrp_avg == rsrp on all 794 v0x03 records.
            rsrp_avg = (unpack_from('<I', data, 12)[0] & 0xFFF) / 16 - 180
            rsrq = ((unpack_from('<I', data, 16)[0] >> 20) & 0xFFF) / 16 - 30
            rssi = ((unpack_from('<I', data, 20)[0] >> 10) & 0xFFF) / 16 - 110
    else:
        # v0x05 — 32-bit identity fields.
        if len(data) >= 8:
            earfcn = unpack_from('<I', data, 4)[0]
        elif len(data) >= 2:
            earfcn = data[1]
        else:
            earfcn = 0
        # pci = low 9 bits of the u32-LE @8. The upper bits carry an
        # unidentified field (observed {0, 2, 3, 4, 6}) — masking them off is what
        # keeps this in-range; the raw u16@8 reads 3308 on EG25-G/CFW-3212 where
        # the AT-attested serving PCI is 236. Absent on any payload < 12 B.
        pci = (unpack_from('<I', data, 8)[0] & 0x1FF) if len(data) >= 12 else 0
        # Measurement block — 12-bit subfields of a u32, the same
        # fixed-point convention as sibling 0xB193. Gated to the v0x05 /
        # 40 B layout: v0x03's measurements live at different offsets (see above).
        if version == 0x05 and len(data) >= _B17F_V05_SIZE:
            rsrp = (unpack_from('<I', data, 12)[0] & 0xFFF) / 16 - 180
            # rsrp_avg — the slower/averaged filter tap. u32@16 is a
            # second filtered serving-RSRP word: on separating chipsets (FN980
            # SDX55, CFW-3212 SDX62) it lags `rsrp` under motion (r≈+0.65 vs the
            # RSRP slope on 3 FN980 drives); on memcpy chipsets it equals `rsrp`.
            rsrp_avg = (unpack_from('<I', data, 16)[0] & 0xFFF) / 16 - 180
            rsrq = ((unpack_from('<I', data, 20)[0] >> 20) & 0xFFF) / 16 - 30
            rssi = ((unpack_from('<I', data, 24)[0] >> 10) & 0xFFF) / 16 - 110
    if len(data) > 2:
        nonzero = sum(1 for b in data[2:] if b != 0)
        total = max(len(data) - 2, 1)
        density = round(nonzero / total, 2)
    else:
        density = 0.0
    return Diag0xB17F(
        log_time=log_time,
        version=version,
        earfcn=earfcn,
        pci=pci,
        rsrp=rsrp,
        rsrp_avg=rsrp_avg,
        rsrq=rsrq,
        rssi=rssi,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
