"""0x1479 — Per-constellation demodulation/tracking measurement (high volume).

Per-constellation demodulation/tracking measurement with 20 i16 values
(likely pseudorange residuals or correlator outputs).  seq_num (byte 1)
is the constellation family index, F3-grounded as
{1:GPS, 2:GLONASS, 3:BeiDou, 4:Galileo} (see the seq-map note in the
body). Three (size, version) profiles: 56B / v=2 (modern: SDX55, SDX62,
M2000), 53B / v=1 (legacy: MDM9x40 / SDX20), 56B / v=0 (Sierra MC7700
MDM9200, GLONASS-only, all-zero tail; on seq_num=2 sv_or_prn is the
GLONASS FDMA channel k+8, grounded 936/936 against the co-emitted
0x1480). field_invariants and the 53B/v=1 variant are validated against a
1,690,901-record corpus walk across 14 chipset families.

## Measurement-array shape (both versions)

The 20×i16 array at bytes [+8..+47] has a striking byte-pattern signature
in both v=1 and v=2: every other byte (the i16 low byte at even offsets
+8, +10, +12, …, +46) is high-entropy (256 unique values), while the
adjacent high byte (odd offsets +9, +11, …, +47) has only ~55-110 unique
values dominated by `0x00`, `0xff`, `0x01`, `0xfe`. This is the
signature of **signed i16 LE values clustered around zero**
— small positive numbers sign-extend `0x00` into the high byte, small
negative numbers sign-extend `0xff`.

This supports the "pseudorange residuals or correlator outputs"
hypothesis but does NOT identify which slot is which physical
quantity. Per-slot semantic decode requires DIAG×AT correlation against
per-SV signal-strength polls.

The v=2 (modern) array has substantially higher non-zero rates per
half-i16 (97-99% vs v=1's 68-70%), suggesting v=2 emits a fuller
measurement set per record (more populated slots) than v=1.

## Per-version tail layout

  v=1 (53B, MDM9x40/SDX20 legacy):
    [+48]      binary flag {0x00:55%, 0x02:45%}   — `tail_flag_48`
    [+49..+52] zero (4 bytes of padding)

  v=2 (56B, SDX55/SDX62/SDX20-V2 modern):
    [+48]      binary flag {0x00:62%, 0x02:38%}   — `tail_flag_48`
    [+49]      enum {0x01:79%, 0x05:21%}, NEVER zero — `tail_flag_49` (v=2-only)
                (looks like a 3-bit subfield: 001 vs 101)
    [+50..+51] zero
    [+52]      sparse enum, 16 uniq, ~8% nonzero — top:
                {0x00:92%, 0x40, 0x10, 0x50 each ~0.6%}
                (upper-nibble flag region — `tail_byte_52`)
    [+53..+54] not decoded separately (kept in the raw `tail` bytes)
    [+55]      opportunistic byte, 256 uniq, ~8% nonzero — `tail_byte_55`

The +48 flag is the only tail byte common to both versions; the rest of
v=2's tail (+49..+55) is structurally absent on v=1. The +49 flag is
**never zero on v=2**, which means a v=2 record with `tail_flag_49 == 0`
would indicate corruption or a third (unseen) v=2 sub-variant. This is
enforced as a `field_invariants` enum (see below).

## tail_flag_49 invariant validation

A version-conditional walk over the full corpus (DLF and HDLC captures)
confirms the v=2-only `tail_flag_49 ∈ {1, 5}` invariant:

  full corpus: 1,665,519 records — v=2: 1,196,871, v=1: 468,648
  v=2 records with +49 ∉ {1, 5}: 0  (also 0 at zero)
  v=1: +49 is 100% 0x00 (zero padding)

Conditioning +49 on the version byte is what makes this rigorous: a
marginal walk would fold any hypothetical v=2 +49==0 into v=1's large
zero-padding count and hide it. The invariant is declared v=2-only —
`to_dict()` omits the field on v=1 (gated is-not-None), so the registry's
`check_invariants` skips it there.

## Constellation grounding

v=2: a co-temporal join of 47,541 0x1479 records from an RM500Q-AE
all-mask capture against the firmware's own per-constellation demod F3
prints (mc_{gps,glo,gal}demod.c) matches 46,817 (98.5%) to a demod print
within 1 ms; the dominant family per seq_num is 1→GPS (84%), 2→GLONASS
(94%), 4→Galileo (99%). The firmware's `gpsfft_spansrchcore.c:1590`
NumMeas print ("GPS … GLO … BDS … GAL … GPSL5 … Navic … E5B") lists
families in a fixed order, and the three join-confirmed anchors sit at
positions 1/2/4, so seq 3=BeiDou. The v=2 tail invariants hold on all
47,541 records: tail_flag_48∈{0,2} (61/39%), tail_flag_49∈{1,5}
(82.9/17.1%), tail_byte_52 16-unique / 11.2% nonzero, no layout
violations apart from one integration_ms RF-transient outlier (0.002%).

v=1: the legacy chipsets emit no steady-state per-constellation demod F3
in the available captures (GNSS is in spectrum-scan / acquisition, so only
gpsfft_spansrchcore.c fires), so the grounding uses two independent
references:
  • NMEA GSV (external constellation truth) on an EG95-NA MDM9x07 GNSS
    bench capture (7,295 v=1 records, seq {1:3363, 2:3048, 3:285, 4:599}):
      seq=1 sv_or_prn = exactly the GPGSV GPS-tracked set
        {1,2,3,4,16,25,26,28,31,32} including the GPS-exclusive high PRNs
        25-32; 0% carry a GLONASS-distinctive slot ⇒ seq 1 = GPS (direct).
      seq=2 sv_or_prn confined to {1,4,5,7,8,9,10,12} (within the GLONASS
        FDMA frequency-channel range 1-14); 0% GPS-distinctive PRNs (25-32);
        distinct-SV count 8 ≈ GLGSV 9 tracked ⇒ seq 2 = GLONASS (direct).
  • The F3 NumMeas family-order print (gpsfft_spansrchcore.c) — "GPS NumMeas
    N GLO NumMeas N BDS NumMeas N GAL NumMeas N" / "CfgPut GPS N GLO N BDS N
    GAL N" — appears on two v=1 chipsets (MDM9250 and MDM9x40/LM960) in the
    same fixed GPS/GLO/BDS/GAL order as the SDX55 v=2 firmware. With seq 1,2
    confirmed as the 1-based family index, 3=BDS and 4=GAL follow by the
    fixed order, the same argument that fixes seq 3=BeiDou on v=2.
    Corroborated by a plausible US-GNSS distribution (GPS/GLO dominant,
    BDS/GAL minority), tail_flag_48==2 ⇔ seq=4 (599:599), and seq=4
    tracking a single Galileo satellite (E09). Invariants hold on all 7,295
    EG95 v=1 records: no layout violations (one integration_ms=5 RF
    transient, the documented by-design outlier), tail_flag_48∈{0,2}.

v=0 (56B, Sierra MC7700, MDM9200; 936 records from one capture): the
header is byte-compatible with v1/v2 (seq_num@1, sv_or_prn@2, tick@3 ×20,
flags@4, integration_ms@7 = 20 on all 936), the 20×i16 array sits at
[8:48], and the 8-byte tail is all-zero on every record (so it gets v1's
tail treatment, not v2's tail_flag_49 ∈ {1,5} contract). The capture is
DLF with log items only (no F3), so the reference is the co-emitted 0x1480
GLONASS measurement report — the firmware's own per-SV labels for the same
epochs:
  • seq_num is always 2 = GLONASS, as on v1/v2. The co-emitted 0x1477
    GPS tracked set {5,11,12,13,21,25,28,29} shares only one value with
    0x1479 v0's sv_or_prn set {4,7,8,9,12}, so it is not GPS.
  • sv_or_prn on seq=2 is the GLONASS FDMA frequency channel k shifted by
    +8 (k ∈ -7..+6 → 1..14). Per-record join to the nearest 0x1480 epoch
    (p50 Δt -26 ms): sv_or_prn ∈ {freq_index+8} **936/936**; null offsets
    k+6/+7/+9/+10 score 132/333/351/150 of 936. The tracked GLONASS SVs
    NMEA 69/70/75/76/85 carry k = +1/-4/0/-1/+4, i.e. channels 9/4/8/7/12 —
    exactly the five values v0 emits.
  • k+8 holds on v1 and v2 too: the same per-record join to the nearest
    0x1480 epoch scores +8 on every seq=2 record — v1 EM7455 MDM9x30
    3154/3154, v1 LM960 MDM9x40 5402/5402, v2 FN980 SDX55 2801/2801, v2
    SIM8202G SDX55 5645/5645 — while the best null offset (k+6/7/9/10)
    reaches at most 2897/3154 (EM7455 k+7, adjacent channels).

QCSuper does not decode 0x1479. Per-slot semantics of the measurement
array remain open (DIAG×AT correlation-gated).

Log name: LOG_GNSS_DEMOD_SOFT_DECISIONS_C
Also known as: LOG_GAN_HANDIN_COMPLETE
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

LOG_GNSS_DEMOD_TRACKING = 0x1479

# Constellation mapping for 0x1479 seq_num (byte 1).
#
# F3-grounded against the firmware's own per-constellation demod prints
# (mc_{gps,glo,gal}demod.c):
#
#   seq_num  constellation  evidence
#   1        GPS            mc_gpsdemod.c co-temporal join, 83% dominant
#   2        GLONASS        mc_glodemod.c co-temporal join, 94% dominant
#   3        BeiDou         F3 NumMeas family order (see below)
#   4        Galileo        mc_galdemod.c co-temporal join, 99% dominant
#
# The join ran over an RM500Q-AE all-mask F3 capture: each of 47,541 0x1479
# records aligned to its nearest constellation-labelled demod F3 print
# within ~1 ms, and the dominant family per seq_num is unambiguous.
# seq_num=3 is absent in that capture, but the firmware's own
# `gpsfft_spansrchcore.c:1590` NumMeas print enumerates families in a
# fixed order — GPS, GLO, BDS, GAL, GPSL5, Navic, E5B — and the three
# directly join-confirmed values land at exactly positions 1/2/4 of that
# list, so seq_num is that 1-based family index and position 3 = BDS
# (BeiDou). SBAS is not in that family list. Matching seq_num record
# counts to expected constellation prevalence does not recover this map
# (it suggests 2=SBAS, 3=GLONASS); do not label these by corpus frequency.
#
# Corroboration: sibling 0x1478 decodes its per-constellation clock block
# in the same family order GPS→GLO→BDS (Galileo shares the GPS timescale).
# Do not reconcile this seq_num with 0x1476's `const_id`: that is a
# different enum (2=GLONASS, 4=BeiDou, 6/7=Galileo, 0x0a=SBAS). 0x1479's
# seq_num is the NumMeas 1-based family index (4=Galileo), directly
# join-confirmed; they are not the same numbering.
#
# v=1 (53B legacy): the same map holds. seq 1=GPS and 2=GLONASS are
# grounded directly by NMEA GSV on an EG95-NA (MDM9x07) bench capture
# (seq=1 sv_or_prn = exactly the GPGSV GPS-tracked PRN set including the
# GPS-exclusive 25-32; seq=2 sv_or_prn within the GLONASS FDMA channel range
# 1-14, no GPS PRNs). seq 3=BeiDou / 4=Galileo follow from the
# gpsfft_spansrchcore.c NumMeas family-order print (GPS/GLO/BDS/GAL),
# identical on two v=1 chipsets (MDM9250, MDM9x40/LM960) and the SDX55 v=2.
# See the module docstring for the full grounding.
_DEMOD_SEQ = {
    1: 'GPS',       # F3-confirmed (mc_gpsdemod.c co-temporal join)
    2: 'GLONASS',   # F3-confirmed (mc_glodemod.c co-temporal join, 94%)
    3: 'BeiDou',    # NumMeas family order (seq=3 absent in the join capture)
    4: 'Galileo',   # F3-confirmed (mc_galdemod.c co-temporal join, 99%)
}


@dataclass
class Diag0x1479:
    """Per-constellation demodulation/tracking measurement (0x1479).

    Contains 20 × i16 values (bytes 8-47) that appear to be correlator
    outputs or pseudorange residuals (small signed values centered on
    zero — see module docstring for the byte-pattern evidence).

    Per-version tail layout:
      v=0 (56B): all-zero 8-byte tail; tail_flag_48 only
      v=1 (53B): tail_flag_48 only (rest of tail is zero padding)
      v=2 (56B): tail_flag_48 + tail_flag_49 + sparse tail_byte_52 + tail_byte_55
    """
    log_time: int
    version: int          # byte 0 — enum {0, 1, 2}
    seq_num: int          # byte 1 — constellation index
    constellation: str
    sv_or_prn: int        # byte 2 — SV PRN; GLONASS (seq 2): FDMA channel k+8 (v0/v1/v2)
    tick: int             # byte 3 — incrementing (×20 pattern)
    flags: int            # byte 4 — 0-6
    integration_ms: int   # byte 7 — 10 or 20 (predetect integration time)
    measurements: list[int]  # 20 × i16 values
    tail_flag_48: int     # u8 @ +48 — enum {0, 2} on both versions
    tail_flag_49: int | None    # u8 @ +49 — v=2 only, enum {1, 5}; None on v=1
    tail_byte_52: int | None    # u8 @ +52 — v=2 only, sparse upper-nibble flag
    tail_byte_55: int | None    # u8 @ +55 — v=2 only, opportunistic byte
    tail: bytes           # raw tail bytes from +48 to end (5B v=1, 8B v=2)

    def to_dict(self) -> dict[str, Any]:
        d = {
            'type': 'Diag0x1479',
            'log_time': self.log_time,
            'version': self.version,
            'seq_num': self.seq_num,
            'constellation': self.constellation,
            'sv_or_prn': self.sv_or_prn,
            'tick': self.tick,
            'flags': self.flags,
            'integration_ms': self.integration_ms,
            'measurements': self.measurements,
            'tail_flag_48': self.tail_flag_48,
            'tail_hex': self.tail.hex(),
        }
        # v=2-only fields surfaced when present
        if self.tail_flag_49 is not None:
            d['tail_flag_49'] = self.tail_flag_49
        if self.tail_byte_52 is not None:
            d['tail_byte_52'] = self.tail_byte_52
        if self.tail_byte_55 is not None:
            d['tail_byte_55'] = self.tail_byte_55
        return d


# ---------------------------------------------------------------------------
# Validation anchor: EG95-NA (Quectel, MDM9x07), which emits the
# legacy 53B / v=0x01 profile (7,295 v=0x01 records in a bench GNSS
# comparison capture). The header scalars (constellation, sv_or_prn) ground
# by correlation against the live NMEA GSV satellite list; the 20×i16
# measurement array (candidate: pseudorange residuals / correlator outputs)
# grounds only structurally or by quality correlation — no AT command
# returns it.

#: Fixed per-version record size: v=0 MC7700 56 B, v=1 legacy 53 B,
#: v=2 modern 56 B.
_FIXED_SIZE = {0: 56, 1: 53, 2: 56}


@register(
    LOG_GNSS_DEMOD_TRACKING,
    name="0x1479",
    description=(
        "Per-constellation demodulation/tracking measurements (0x1479) — "
        "three (size, version) profiles: 56B/v=2 (modern: SDX55, SDX62, M2000), "
        "53B/v=1 (legacy: MDM9x40/SDX20), 56B/v=0 (MC7700 MDM9200, GLONASS-only). "
        "7 header scalars + 20×i16 measurement array + per-version tail "
        "(5B/v=1, 8B/v=0 all-zero, 8B/v=2)."
    ),
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Three (size, version) profiles: 56 B v=2 (SDX55, SDX62, M2000), 53 B "
        "v=1 (legacy MDM9x07..MDM9x40 / SDX20) and 56 B v=0 (Sierra MC7700, "
        "MDM9200). The header scalars, 20×i16 measurement array and per-version "
        "tail are validated over a 1,690,901-record corpus walk across 14 "
        "chipset families. The array's byte pattern (high byte clustered on "
        "0x00/0xff/0x01/0xfe, low byte 256-unique) indicates signed i16 values "
        "centered on zero (pseudorange residuals or correlator outputs); "
        "per-slot semantics are not identified. The seq_num→constellation map "
        "(1 GPS, 2 GLONASS, 3 BeiDou, 4 Galileo) is grounded on v=2 by a "
        "co-temporal join of 47,541 RM500Q-AE records against the firmware's "
        "per-constellation demod F3 prints (mc_{gps,glo,gal}demod.c; 98.5% "
        "matched within 1 ms; dominant family GPS 84%, GLONASS 94%, Galileo "
        "99%) plus the firmware's fixed GPS/GLO/BDS/GAL NumMeas family order "
        "for seq 3; on v=1 by NMEA GSV satellite sets on an EG95-NA bench "
        "capture and the same NumMeas order on MDM9250 and MDM9x40 firmware; "
        "and on v=0 (no F3 in the capture) by the co-emitted 0x1480 GLONASS "
        "measurement report. On GLONASS records sv_or_prn is the FDMA "
        "frequency channel k+8, matched per record against the nearest 0x1480 "
        "epoch on every seq=2 record of v0, v1 and v2 captures (MC7700, "
        "EM7455, LM960, FN980, SIM8202G). The v=2-only tail_flag_49 ∈ {1, 5} "
        "invariant holds on all 1,196,871 v=2 records. QCSuper does not "
        "decode 0x1479. Truncated records return None."
    ),
    source_url="",
    issues=(),
    fields_parsed=13,
    fields_identified=13,
    field_invariants={
        "version":        {"enum": [0, 1, 2]},
        "seq_num":        {"enum": [1, 2, 3, 4]},
        "integration_ms": {"enum": [10, 20]},
        "tail_flag_48":   {"enum": [0, 2]},
        # v=2-only: to_dict() omits tail_flag_49 on v=1 (gated is-not-None),
        # so check_invariants skips it there. On v=2 it is always present
        # and always {1,5} — a v=2 record with +49 ∈ {0,2,...} (corruption
        # or an unseen third sub-variant) surfaces as an enum violation.
        "tail_flag_49":   {"enum": [1, 5]},
    },
)
def parse_0x1479(log_time: int, data: bytes) -> Diag0x1479 | None:
    # SDX55: 56 bytes (20×i16 + 8B tail). SDX20: 53 bytes (20×i16 + 5B tail).
    if len(data) < 48:  # minimum: 8B header + 20×i16 measurements
        return None

    version = data[0]
    if version not in (0, 1, 2):
        return None
    # Each version is a fixed layout (v=1 53 B = 48 + 5 B tail, v=0 / v=2
    # 56 B = 48 + 8 B tail). A record missing part of its tail is truncated:
    # return None (registry WARN) instead of a partial tail.
    if len(data) < _FIXED_SIZE[version]:
        return None
    seq_num = data[1]
    sv_or_prn = data[2]
    tick = data[3]
    flags = data[4]
    integration_ms = data[7] if len(data) > 7 else 0
    constellation = _DEMOD_SEQ.get(seq_num, f'unknown-{seq_num}')

    measurements = list(unpack_from('<20h', data, 8))
    tail = data[48:min(56, len(data))]

    # Per-version tail-byte field extraction. tail_flag_48 is common to
    # both versions (it's the only meaningful byte in v=1's 5-byte tail).
    # tail_flag_49/tail_byte_52/tail_byte_55 are gated on version=2 because
    # on v=1 (and v=0, 936/936) those positions are zero padding only;
    # surfacing them as named fields would falsely imply they carry data.
    tail_flag_48 = data[48] if len(data) > 48 else 0
    if version == 2 and len(data) >= 56:
        tail_flag_49 = data[49]
        tail_byte_52 = data[52]
        tail_byte_55 = data[55]
    else:
        tail_flag_49 = None
        tail_byte_52 = None
        tail_byte_55 = None

    return Diag0x1479(
        log_time=log_time,
        version=version,
        seq_num=seq_num,
        constellation=constellation,
        sv_or_prn=sv_or_prn,
        tick=tick,
        flags=flags,
        integration_ms=integration_ms,
        measurements=measurements,
        tail_flag_48=tail_flag_48,
        tail_flag_49=tail_flag_49,
        tail_byte_52=tail_byte_52,
        tail_byte_55=tail_byte_55,
        tail=tail,
    )
