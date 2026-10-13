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

# byte-0 version/layout discriminator, co-varying with payload size:
# 0x05 (40 B, 156,836 records), 0x03 (32 B, 794 records, MDM9200) and
# 0x04 (36 B, 423 records, MDM9625 T77W595).
_B17F_VERSIONS_OBSERVED = (0x03, 0x04, 0x05)

# The three layouts carry the SAME semantic record with different field
# widths. v0x03 (MDM9200 / Sierra MC7700) and v0x04 (MDM9625 / Foxconn T77W595)
# use 16-bit identity fields where v0x05 uses 32-bit, so everything after byte
# 4 sits 4 bytes lower. v0x04 is v0x05 minus those 4 bytes (36 B); v0x03
# also lacks the final trailing word (32 B).
# Applying v0x05's offsets to a narrow-identity frame emits garbage.
_B17F_V05_SIZE = 40
_B17F_V04_SIZE = 36
_B17F_V03_SIZE = 32
_B17F_SIZES = {0x03: _B17F_V03_SIZE, 0x04: _B17F_V04_SIZE, 0x05: _B17F_V05_SIZE}


@dataclass
class Diag0xB17F:
    """0xB17F — per-cell LTE ML1 record (legacy `LtePdcpB17F`).

    `earfcn` is the u32-LE at byte-offset 4. DIAG×AT correlation against
    serving-cell EARFCN sets confirms this is the cell-attribution field.

    `pci` is the low 9 bits of the u32-LE at byte-offset 8 = the cell's
    PhysCellID; 0 on payloads < 12 B. Together `(earfcn, pci)`
    identify which cell each record pertains to — the tuple reproduces
    independently surveyed serving *and* neighbour cells, so records are not
    serving-cell-only.

    The measurement block uses 12-bit fixed-point subfields of a
    u32 — the same convention as sibling 0xB193:

        rsrp     = (u32@12       & 0xFFF) / 16 - 180   dBm
        rsrq     = (u32@20       & 0x3FF) / 16 -  30   dB
        rsrq_avg = ((u32@20>>20) & 0x3FF) / 16 -  30   dB
        rssi     = ((u32@24>>10) & 0xFFF) / 16 - 110   dBm

    v0x03 (32 B, MDM9200 / Sierra MC7700) and v0x04 (36 B, MDM9625 / Foxconn
    T77W595) carry the SAME fields with 16-bit identity, so everything after
    byte 4 sits 4 bytes lower:

        earfcn   = u16@4
        pci      = u16@6 & 0x1FF
        rsrp     = (u32@8        & 0xFFF) / 16 - 180   dBm
        rsrq     = (u32@16       & 0x3FF) / 16 -  30   dB
        rsrq_avg = ((u32@16>>20) & 0x3FF) / 16 -  30   dB
        rssi     = ((u32@20>>10) & 0xFFF) / 16 - 110   dBm

    **`rsrp` is the best rx branch.** On the T77W595 v0x04 records the
    co-emitted 0xB196 cell carries rsrp_rx0 / rsrp_rx1 / rsrp, and 0xB17F
    `rsrp` == max(rx0, rx1) on 235/235 (== rx1 on 183 of them). F3
    `lte_ml1_common_ant_switch.c:2766` "ML1 ASDiv: Filtered RSRP0" == 0xB196
    rsrp_rx0 within 1/32 dB on 232/232, so it matches 0xB17F `rsrp` only on the
    cell where rx0 is the stronger branch (46/46 on PCI 221).

    **RSRQ.** The rsrq word is three 10-bit fields. Bits 0..9 (==
    bits 10..19) are the rsrq that 0xB196 carries: 235/235 on v0x04, vs 60/235
    for bits 20..29. Bits 20..29 is `rsrq_avg`, a slower tap: same mean, about
    half the step variance and a higher lag-1 autocorrelation (v0x04 PCI 242:
    var(Δ) 3.2-3.6 vs 7.4-7.6, autocorr 0.42-0.53 vs 0.16-0.23). On memcpy
    chipsets the two are equal. Parser <= v12 read bits 20..29 as `rsrq`.

    v0x04 (MDM9625) separates both tap pairs only in some regimes: rsrp/rsrp_avg
    and rsrq/rsrq_avg are equal on 235/235 records of a 1.28 s DRX camp (PCI
    221) and differ on 104/188 and 175/188 records at 640 ms DRX (PCI 242).

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
    rsrq_avg: float | None
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
            "rsrq_avg": self.rsrq_avg,
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
    description="0xB17F — LTE ML1 per-cell measurement record (fixed 32/36/40 B by version; earfcn+pci identity + rsrp/rsrp_avg/rsrq/rsrq_avg/rssi; canonical name contested, see docstring; legacy mislabel LtePdcpB17F)",
    version=13,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Three fixed layouts keyed on byte 0: v0x05 (40 B), v0x04 (36 B, "
        "MDM9625 / Foxconn T77W595, 16-bit identity like v0x03) and v0x03 (32 B, the "
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
        "above both), and the words are not an rx0/rx1 split. v0x04 (423 records, "
        "7 T77W595 captures): earfcn/pci == 0xB196 and the 0xB0C0-grounded cells "
        "(2050, 221) / (2300, 242) 423/423; rsrp == max(0xB196 rsrp_rx0, rsrp_rx1) "
        "235/235 and rssi == 0xB196 rssi 235/235; F3 ant_switch.c:2766 'Filtered "
        "RSRP0' == rsrp_rx0 within 1/32 dB on 232/232. rsrq = bits 0..9 of the rsrq "
        "word (== 0xB196 rsrq 235/235); bits 20..29 = rsrq_avg, a slower "
        "tap (about half the step variance). Payloads shorter "
        "than the fixed layout return None (registry warning)."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=8,
    fields_parsed=8,
    field_invariants={
        "version": {"enum": list(_B17F_VERSIONS_OBSERVED)},
        "earfcn": {"range": (0, 262143)},
        "pci": {"range": (0, 511)},
        # -160: TS 36.133 reports RSRP down to -156 dBm; 39 real RM500Q cells
        # sit at -141.x (RSRQ ~-28). rssi 0: FN980 wardrive reaches -15 dBm
        # next to a tower (RSRP -45).
        "rsrp": {"range": (-160.0, -30.0)},
        "rsrp_avg": {"range": (-160.0, -30.0)},
        "rsrq": {"range": (-40.0, 0.0)},
        "rsrq_avg": {"range": (-40.0, 0.0)},
        "rssi": {"range": (-130.0, 0.0)},
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
    if len(data) < _B17F_SIZES[version]:
        return None
    rsrp = rsrp_avg = rsrq = rsrq_avg = rssi = None
    # v0x03 and v0x04 share the 16-bit identity packing; v0x05 widens it to u32
    # and moves the measurement block down 4 bytes.
    if version in (0x03, 0x04):
        # Reading v0x05's u32@4 earfcn / u32@8 pci out of a v0x03 frame gives a
        # 9-digit garbage channel number on 794/794 corpus records.
        earfcn = unpack_from('<H', data, 4)[0]
        pci = unpack_from('<H', data, 6)[0] & 0x1FF
        base = 8
    else:
        earfcn = unpack_from('<I', data, 4)[0]
        # pci = low 9 bits of the u32-LE @8. The upper bits carry an
        # unidentified field (observed {0, 2, 3, 4, 6}) — masking them off is what
        # keeps this in-range; the raw u16@8 reads 3308 on EG25-G/CFW-3212 where
        # the AT-attested serving PCI is 236.
        pci = unpack_from('<I', data, 8)[0] & 0x1FF
        base = 12
    # Measurement block — subfields of u32 words at base, base+4, base+8,
    # base+12, the same 1/16-LSB fixed-point convention as sibling 0xB193.
    # rsrp = best rx branch (max(rx0, rx1), v0x04 0xB196 join);
    # rsrp_avg = the slower filter tap (u32@base+4). On memcpy chipsets
    # (MDM9200 v0x03, ...) rsrp_avg == rsrp. MDM9625 v0x04 writes two taps:
    # equal 235/235 on a 1.28 s DRX camp, distinct on 104/188 at 640 ms DRX.
    rsrp = (unpack_from('<I', data, base)[0] & 0xFFF) / 16 - 180
    rsrp_avg = (unpack_from('<I', data, base + 4)[0] & 0xFFF) / 16 - 180
    # The rsrq word holds three 10-bit fields: bits 0..9 == bits 10..19
    # are the rsrq that 0xB196 carries; bits 20..29 is a slower tap.
    rsrq_word = unpack_from('<I', data, base + 8)[0]
    rsrq = (rsrq_word & 0x3FF) / 16 - 30
    rsrq_avg = ((rsrq_word >> 20) & 0x3FF) / 16 - 30
    rssi = ((unpack_from('<I', data, base + 12)[0] >> 10) & 0xFFF) / 16 - 110
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
        rsrq_avg=rsrq_avg,
        rssi=rssi,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
