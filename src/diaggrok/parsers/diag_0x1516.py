"""0x1516 — GNSS engine parameter/config report (ME parameter table + SDP registry).

See the module body for the per-version field map and evidence.

Log name: LOG_DTV_L1_L3_API_COMMAND
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# ---------------------------------------------------------------------------
# 0x1516 — GNSS engine parameter/config report, two disjoint (version, size)
# forms
# ---------------------------------------------------------------------------
#
# Corpus field map, F3-grounded. The structural map comes from per-capture
# per-offset byte histograms aggregated across every 0x1516-bearing capture,
# split by size class using single-size-class ("pure") captures. F3 grounding
# uses an F3-rich EG18-NA extended-GNSS capture (1.14 GB all-diag; 1.16M
# plaintext 0x79 + 3.7k 0x60 events).
#
# v=0x06  (72 B) — GNSS MEASUREMENT-ENGINE (ME) PARAMETER TABLE.
#   Full 72-byte record decoded. Across ~15 distinct modems (MDM9607 EG25-G →
#   MDM9x55 EM7455/EM7565 → SDX55 fleet → SDX62 RM520N-GL / T99W640) the
#   record is a firmware-baked constant table EXCEPT two single-byte fields:
#     off 66: {0x00, 0x42}          off 68: {0x04, 0x10, 0x14}
#   (platform/config-dependent; NOT pinned as invariants). Everything else —
#   bytes 0..65, 67, 69..71 — is byte-for-byte identical fleet-wide.
#   Decoded little-endian float32 / u32 (values OBSERVED; semantic labels are
#   CANDIDATE hypotheses only — see below):
#     off 14: 5.0f   off 18: 1.5f   off 22: 0.8f   off 26: 0.15f
#     off 30: 0.0f   off 34: 6.0f   off 42: 100.0f off 46: 0.01f
#     off 50: u32 30   off 54: u32 45   off 58: u32 60
#   Not-yet-decoded raw regions kept verbatim: off 13 = 0x01 (const flag),
#   off 38..41 = 92 00 02 01, off 62..63 = 02 0a.
#
#   F3-VERDICT v0x06: GROUND (record identity + subsystem + cadence).
#   * Co-emission (measured, n=4 in the EG18-NA capture): each v0x06 fires
#     PHASE-LOCKED to the ~1 Hz GNSS ME measurement epoch — −0.008..−1.06 ms
#     before every `mc_gnssmeasreport.c "SV  Status  FCount…"` epoch header,
#     4/4. An independent timer would land uniformly in the 1000 ms gap; the
#     ~1 ms clamp proves v0x06 is emitted INSIDE the ME search-strategy /
#     measurement-report cycle (`mc_gnsssearchstrategy.c` / `mc_gnssmeasreport.c`).
#   * Cadence: strict 600.00 s between v0x06 emissions (31,457,3xx diag ticks,
#     3× consecutive), and each v0x06 is trailed ~4 ms later by a v0x03 pair —
#     they emit as a group. The engine had been ON 8,225 s at capture start
#     ("Time from Engine ON" F3), so v0x06 is a PERIODIC parameter report, NOT
#     an init-only "GNSS Init" event.
#   * F3 label search: the config values (5.0/1.5/0.8/0.15/6.0/100.0/0.01 and
#     30/45/60) do NOT appear as F3 `%f`/`%u` args in 754k GNSS-engine F3
#     records — the 0x1516 packet is the authoritative source of these words,
#     not re-printed in F3, so per-field semantic names stay CANDIDATE and the
#     values are exposed raw. Candidate reads: off 50/54/60 as timeout tiers
#     in s (cf. F3 "START FIX … timeout[30000]" = 30 s); off 14/34 as
#     elevation/PDOP masks (deg). Not asserted.
#   * QCSuper and SCAT do not decode 0x1516 (0 records; the code is absent
#     from both tools' tables).
#
# v=0x03  (295 B) — SDP SENSOR-CALIBRATION REGISTRY snapshot + SDP status.
#   (F3-grounded.) "SDP" is the GNSS stack's sensor-data-processing engine
#   (sdp_core.c / lbs_sdp*.c / slim_*.c). Bytes 14..21 are a u64 GPS-ms
#   timestamp, not an identifier, despite looking ID/name-shaped.
#
#   F3 site that labels the body: at every GNSS-engine-OFF emission the
#   firmware prints "**** Dumping SDP Registry ****" (sdp_core.c:574..625)
#   10–11 ms BEFORE the v0x03 pair, and its values are the record's bytes:
#     sdp_core.c:577 "Version %d, Author %d, time known %d"
#         -> u32@6 = 6, u16@10 = 257 (01 01), u8@12 = time_known
#     sdp_core.c:580 "Time Week %d, MS_IN_WEEK %d"
#         -> u64@14 = week*604800000 + ms_in_week, EXACT (2/2 OFF anchors:
#            EG18-NA warm 2426/234919786, cold 2426/236208382)
#     sdp_core.c:591 "Accel Scale (*1000) (1000,1000,1000)" -> f32@42/46/50 = 1.0
#     sdp_core.c:605 "Gyro Scale (*1000) (1000,1000,1000)"  -> f32@98/102/106 = 1.0
#     sdp_core.c:613/617 "Gyro Noise, 250" / "Gyro Bias Norm, Bias Norm Noise
#         (*1000), 0, 250" -> f32@134 = 0.25, f32@138 = 0.0, f32@142 = 0.25
#     sdp_core.c:622 "G Vection Params : GVAL 20 GyroThresh 300, accelThresh
#         1000" -> u32@154 = 20, f32@150 = 0.3, f32@146 = 1.0
#   Printed but NOT position-pinnable (every record in the corpus carries the
#   same value in two candidate slots, so the slot cannot be told apart) —
#   kept as observed raw/float lists, not named:
#     "Accel bias (0,0,0)" + an unprinted 8 B   -> raw 22..41 (all zero)
#     "Gyro Cal Time 0/0" + "Gyro Bias (0,0,0)"  -> raw 78..97 (all zero)
#     "Gyro Bias Unc (1000000 x3)"               -> one triplet of f32@110..133
#                                                   (1000.0 x6); f32@54..77 is
#                                                   the unprinted accel twin
#
#   SDP status tail (158..294, not in the registry dump):
#     f32@269 = the SDP's current HEPE (m). F3 sdp_core.c:7047 "old HEPE = %d
#       [x100], new HEPE = %d [x100]" (and :3705/:3774 "HEPE = %d [x100]")
#       equals int(hepe*100) (C truncation) at 5/5 EG18-NA anchors, and each
#       "old" equals the PREVIOUS v0x03's value: 459->472 (-46 ms before the
#       warm OFF record), 472->1013 and 374->1826 (-0.02 / -0.00 ms, the ON
#       records); the cold ON value also prints at lm_mgp.c:341 "New fix saved
#       as best. hepe: 18.264465" (6-dp exact). EG25-G (legacy 0x92) shows the
#       same PE-update args [926, 926] beside its periodic record (9.267767).
#       Recurring exact values across devices (3.535534 = 2.5*sqrt(2),
#       9.267767, 0.0) are the PE's formula HEPE for propagated / no-fix
#       updates, not per-fix measurements.
#     u8@262 = CANDIDATE SDP HF-auto state: equals the post-transition state
#       in sdp_core.c:3310 "valid event %d for state %d" at 5/5 anchors
#       (2 = HFAutoInjecting, 3 = HFAutoNotInjecting on EG18-NA/EG25-G). The
#       fleet also shows 1 (MDM9x50/SDX55 builds) and 7 (SDX6x) — the enum is
#       build-specific, so the value is surfaced, not decoded to a name.
#     u8@268 = CANDIDATE sensor-injection-active: 1 only where F3 shows
#       "HFAutoNotInjecting - starting sensor injection" (5/5 consistent).
#     u8@267 = 0 at both engine-OFF records, 1 at both ON records and on
#       running engines — engine-on / PE-valid CANDIDATE, unconfirmed.
#     Everything else in the tail is surfaced raw/observed (see
#     _decode_v03_sdp): twin f32@229/233 in {50, 10, 0}; twin u16@256/260 in
#     {25, 5}; u32@273 in {10, 20}; flags 249/250/294; constants at 158..174,
#     245 (1e-5) and 277..292.
#
#   Emission (measured): always a back-to-back PAIR, byte 5 = 1 then 0, the
#   two bodies otherwise byte-identical (35/35 pairs; whole corpus: byte5=1 on
#   exactly 530 of 1,060 v0x03 records). Three triggers: (a) the periodic
#   600 s group trailing v0x06 (EM7455 / EG25-G: phase-locked to the ME
#   measurement epoch, mc_gnsssearchstrategy.c / mc_gnssmeasreport.c within
#   ~1 ms); (b) GNSS engine OFF (AT+QGPSEND -> SDP stop -> registry dump);
#   (c) the first SDP PE update after engine ON. (b)/(c) emit WITHOUT v0x06.
#   The registry time is carried unchanged from an OFF record into the next
#   ON record, and can be days old on a periodic record (a persisted value).
#
#   Header constants pinned whole-corpus via per-offset byte histograms
#   (offsets 0..63, 406 captures / 1,060 v0x03 records, 0 violations):
#   byte1 = 0x01, u32@6 = 6, u16@10 = 257, byte13 = 0xff. Bytes 64..294 were
#   walked on a SAMPLE — 324 distinct v0x03 records / 147 captures / 55
#   module sessions, all decoded, 0 invariant violations (the tail layout
#   above) — so the tail is not claimed invariant.
#   Only the registry format version (6) is pinned as an invariant — the
#   body values are NOT, since a device with calibrated sensors legitimately
#   fills them. A future registry version surfaces as an invariant violation
#   and is left undecoded (the decode is gated on version 6 AND 295 B).
#
# byte[1] ("sub_type") is version-correlated (0x01 for v=0x03,
# 0x00 for v=0x06), constant per form — kept as a field but not an
# independent discriminator.
# ---------------------------------------------------------------------------

def _decode_v06_config(data: bytes) -> dict[str, Any]:
    """Decode the v=0x06 (72 B) GNSS ME parameter table.

    Fields are exposed as OBSERVED values (little-endian float32 / u32) with
    offset-keyed neutral names — semantic labels are CANDIDATE only (see the
    module F3-VERDICT block), so the parser does not name them. off 66 / off 68
    are the only fleet-varying bytes; the raw regions off 38..41 and off 62..63
    are kept verbatim rather than guessed.
    """
    return {
        'f32_14': unpack_from('<f', data, 14)[0],
        'f32_18': unpack_from('<f', data, 18)[0],
        'f32_22': unpack_from('<f', data, 22)[0],
        'f32_26': unpack_from('<f', data, 26)[0],
        'f32_30': unpack_from('<f', data, 30)[0],
        'f32_34': unpack_from('<f', data, 34)[0],
        'raw_38_41': data[38:42].hex(),
        'f32_42': unpack_from('<f', data, 42)[0],
        'f32_46': unpack_from('<f', data, 46)[0],
        'u32_50': unpack_from('<I', data, 50)[0],
        'u32_54': unpack_from('<I', data, 54)[0],
        'u32_58': unpack_from('<I', data, 58)[0],
        'raw_62_63': data[62:64].hex(),
        'var_66': data[66],   # fleet-varying: {0x00, 0x42}
        'var_68': data[68],   # fleet-varying: {0x04, 0x10, 0x14}
    }


_V03_SIZE = 295

# v=0x00 — the MDM9200 (Sierra MC7700, two firmware builds A and B)
# generation. Two exact-size forms, each byte-1-tagged like the
# modern pair (byte1 0x01 = registry-style, 0x00 = parameter table):
#   50 B, byte1 0x00 — the ME PARAMETER TABLE's predecessor. Bytes [13:50] are
#     the v=0x06 table byte-for-byte at the SAME offsets (f32 5.0/1.5/0.8/0.15/
#     0.0/6.0/100.0/0.01; only byte 38 differs, 0x82 vs 0x92); it ends before
#     v0x06's u32 30/45/60 tier. Header words u32@5 and f32@9 (25.0) are v0x00-only.
#   143 B, byte1 0x01 — the SDP-REGISTRY-style PAIR: always two records on one
#     timestamp, byte 5 = 1 then 0 (the v=0x03 emission signature), bodies
#     otherwise identical. u32@6 is 0 (not registry format 6), so the v0x03
#     registry names are NOT applied: pair_index is exposed, the body stays raw.
# Corpus: 5 captures / 2 units / 2 builds, every one exactly 2 x 143 B + 1 x 50 B
# (15 records), byte-identical across units. Not a misframe: the per-capture
# shape is fixed and the 50 B body is the v0x06 table.
#
#   F3-VERDICT v0x00: ABSENT (structural), grounded by LOG co-emission. All 5
#   v0x00 captures are .dlf, which stores demuxed LOG records only: no
#   0x79/0x99/0x92 F3 and no 0x60 can be present. The only raw-HDLC MC7700
#   capture (a third build) has F3 absent (outer 0x10 only) and no 0x1516.
#   QCSuper and SCAT do not decode 0x1516, as for v0x03/v0x06. Measured
#   instead, 5/5 captures, at the .dlf's 1.25 ms timestamp resolution:
#   * 50 B lands 0..1.25 ms after the capture's FIRST 0x1480 (per-SV measurement
#     report) and 0..2.5 ms after the first 0x1477. That is the v0x06 lock to the
#     ME measurement epoch (above), on the MDM9200's first epoch.
#   * The 143 B pair lands 0..2.5 ms after the FIRST 0x150B (PDS time
#     state) and 87.5..103.75 ms after the 50 B on build B. On build A the PE
#     started late, and the pair trails the 50 B by 29,596 ms but is still +2.5 ms
#     after the first 0x150B. So the pair has its own trigger, the position engine
#     start: v0x03's trigger (c), the first SDP PE update after engine ON.
#   The 50 B / 143 B split into ME table + PE-side pair is therefore emission-
#   grounded. The 143 B body and the 50 B header words stay raw (no label exists).
_V00_SIZES = {50: 0x00, 143: 0x01}     # size -> required byte 1
_SDP_REGISTRY_VERSION = 6        # sdp_core.c:577 "Version 6" — the format guard
_GPS_WEEK_MS = 604_800_000


def _f32s(data: bytes, off: int, n: int) -> list[float]:
    return list(unpack_from(f'<{n}f', data, off))


def _decode_v03_sdp(data: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode the v=0x03 (295 B) SDP registry snapshot and SDP status tail.

    Returns ``(sdp_registry, sdp_status)``. Registry names follow the F3
    "Dumping SDP Registry" print (sdp_core.c:574..625) that carries the same
    values; regions whose slot the corpus cannot pin (all-zero or duplicated
    values) stay raw. In the tail only ``hepe_m`` is F3-grounded; the two
    ``*_candidate`` bytes match F3 on 5/5 anchors but are not asserted, and
    the rest is surfaced as observed, offset-keyed values.
    """
    t_ms = unpack_from('<Q', data, 14)[0]
    registry = {
        'author': unpack_from('<H', data, 10)[0],
        'time_known': data[12],
        'raw_13': data[13],
        'time_gps_ms': t_ms,
        'time_gps_week': t_ms // _GPS_WEEK_MS,
        'time_gps_ms_in_week': t_ms % _GPS_WEEK_MS,
        'raw_22_41': data[22:42].hex(),       # accel bias (printed 0,0,0) + 8 B
        'accel_scale': _f32s(data, 42, 3),
        'f32x6_54': _f32s(data, 54, 6),       # unprinted accel twin of 110..133
        'raw_78_97': data[78:98].hex(),       # gyro cal time + gyro bias (0s)
        'gyro_scale': _f32s(data, 98, 3),
        'f32x6_110': _f32s(data, 110, 6),     # "Gyro Bias Unc" is one triplet
        'gyro_noise': unpack_from('<f', data, 134)[0],
        'gyro_bias_norm': unpack_from('<f', data, 138)[0],
        'gyro_bias_norm_noise': unpack_from('<f', data, 142)[0],
        'gvection_accel_thresh': unpack_from('<f', data, 146)[0],
        'gvection_gyro_thresh': unpack_from('<f', data, 150)[0],
        'gvection_gval': unpack_from('<I', data, 154)[0],
    }
    status = {
        'raw_158_174': data[158:175].hex(),   # constant fleet-wide
        'f32_229': unpack_from('<f', data, 229)[0],   # twin of f32_233
        'f32_233': unpack_from('<f', data, 233)[0],
        'f32_245': unpack_from('<f', data, 245)[0],   # constant 1e-5
        'u8_249': data[249],
        'u8_250': data[250],                  # 1 on SDX6x builds
        'u16_254': unpack_from('<H', data, 254)[0],
        'u16_256': unpack_from('<H', data, 256)[0],   # twin of u16_260
        'u16_258': unpack_from('<H', data, 258)[0],
        'u16_260': unpack_from('<H', data, 260)[0],
        'sdp_state_candidate': data[262],
        'u8_267': data[267],                  # engine-on / PE-valid candidate
        'sensor_injection_candidate': data[268],
        'hepe_m': unpack_from('<f', data, 269)[0],
        'u32_273': unpack_from('<I', data, 273)[0],
        'f32x4_277': _f32s(data, 277, 4),     # constant fleet-wide
        'u8_293': data[293],
        'u8_294': data[294],                  # 1 on SDX6x builds
    }
    return registry, status


@dataclass
class Diag0x1516:
    """GNSS engine parameter/config report (0x1516) — two disjoint forms.

    v=0x06 (72 B) is the periodic ME parameter table (F3-grounded); its
    decoded config words live in ``v06_config``. v=0x03 (295 B) is the SDP
    sensor-calibration registry snapshot + SDP status (F3-grounded):
    ``pair_index`` (byte 5), ``sdp_registry_version`` (u32@6), and the
    ``sdp_registry`` / ``sdp_status`` dicts.
    """
    log_time: int
    version: int       # byte 0
    sub_type: int      # byte 1
    payload_size: int
    body_raw: bytes
    v06_config: dict[str, Any] | None = None
    pair_index: int | None = None
    sdp_registry_version: int | None = None
    sdp_registry: dict[str, Any] | None = None
    sdp_status: dict[str, Any] | None = None
    v00_config: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            'type': 'Diag0x1516',
            'log_time': self.log_time,
            'version': self.version,
            'sub_type': self.sub_type,
            'payload_size': self.payload_size,
        }
        if self.v06_config is not None:
            d['v06_config'] = self.v06_config
        if self.pair_index is not None:
            d['pair_index'] = self.pair_index
            d['sdp_registry_version'] = self.sdp_registry_version
        if self.sdp_registry is not None:
            d['sdp_registry'] = self.sdp_registry
            d['sdp_status'] = self.sdp_status
        if self.v00_config is not None:
            d['v00_config'] = self.v00_config
        return d


@register(
    0x1516, domain="gnss",
    name="0x1516",
    description="GNSS engine parameter/config report (0x1516) — v0x06 ME table + v0x03 SDP sensor registry, both F3-grounded",
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Clean-room RE from FN980m SDX55 + EG18-NA SDX20 V2 and a fleet of ~15 modems. v0x06 (72 B) is the periodic ME parameter table, F3-grounded by phase-lock to the ME measurement epoch and a strict 600 s cadence; its values are exposed raw (no F3 label exists). v0x03 (295 B) is the SDP sensor registry + SDP status, F3-grounded vs the sdp_core.c registry dump and HEPE prints (EG18-NA, EG25-G). v0x00 is the MC7700 MDM9200 generation, two exact-size forms: 50 B (byte1 0x00) = the v0x06 ME table predecessor, [13:50] identical to v0x06 at the same offsets; 143 B (byte1 0x01) = a byte5 1/0 pair like v0x03, body raw (u32@6 = 0, not registry v6); 15 records / 5 captures / 2 units / 2 builds, grounded by LOG co-emission only. A payload shorter than its version's fixed record (v0x06 72 B / v0x03 295 B) returns None.",
    source_url="",
    issues=(),
    primary_issue=None,
    # Corpus-wide (version, payload_size) 1:1 mapping:
    #   v=0x03 ↔ 295 B  (the FN980m SDX55 / EG18-NA SDX20 V2 form)
    #   v=0x06 ↔ 72 B   (ME parameter table)
    #   v=0x00 ↔ 50 / 143 B (MDM9200)
    # Locks the enum so a future capture emitting an undocumented byte+0
    # surfaces as an invariant violation rather than misroute through the
    # header-only passthrough.
    # sdp_registry_version: the SDP registry's own format version (u32@6,
    # F3 sdp_core.c:577 "Version 6"), constant on every v0x03 record in the
    # corpus. A registry v7 in the same 295 B is flagged here and left
    # undecoded by the parse-time gate below.
    field_invariants={
        "version": {"enum": [0x00, 0x03, 0x06]},
        "payload_size": {"enum": [50, 72, 143, 295]},
        "sdp_registry_version": {"enum": [_SDP_REGISTRY_VERSION]},
    },
)
def parse_0x1516(log_time: int, data: bytes) -> Diag0x1516 | None:
    if len(data) < 4:
        return None
    # Layer-1 version gate: reject out-of-enum byte[0] before structural
    # decode, matching field_invariants["version"]["enum"]. Guards against
    # silently mis-decoding a same-length foreign payload.
    if data[0] not in (0x00, 0x03, 0x06):
        return None
    if data[0] == 0x00:
        return _parse_v00(log_time, data)
    # Each version is a fixed-size record (v0x06 72 B, v0x03 295 B). A
    # shorter payload is truncated and returns None (registry WARN) rather
    # than degrading silently to a header-only record.
    if len(data) < (72 if data[0] == 0x06 else _V03_SIZE):
        return None
    # v=0x06 decodes to the 72 B ME parameter table (F3-grounded).
    v06_config = (
        _decode_v06_config(data)
        if data[0] == 0x06 and len(data) >= 72
        else None
    )
    # v=0x03 decodes to the SDP registry + status only at exactly 295 B AND
    # registry format version 6 (F3-grounded). pair_index and the
    # registry version are surfaced for any full-length v0x03 record so a
    # new registry version is visible (invariant) without being mis-decoded.
    pair_index = sdp_registry_version = None
    sdp_registry = sdp_status = None
    if data[0] == 0x03 and len(data) == _V03_SIZE:
        pair_index = data[5]
        sdp_registry_version = unpack_from('<I', data, 6)[0]
        if sdp_registry_version == _SDP_REGISTRY_VERSION:
            sdp_registry, sdp_status = _decode_v03_sdp(data)
    return Diag0x1516(
        log_time=log_time,
        version=data[0],
        sub_type=data[1],
        payload_size=len(data),
        body_raw=data[4:],
        v06_config=v06_config,
        pair_index=pair_index,
        sdp_registry_version=sdp_registry_version,
        sdp_registry=sdp_registry,
        sdp_status=sdp_status,
    )


def _parse_v00(log_time: int, data: bytes) -> Diag0x1516 | None:
    """v=0x00 (MDM9200): exact size AND byte 1 per _V00_SIZES, else None."""
    if _V00_SIZES.get(len(data)) != data[1]:
        return None
    v00_config = pair_index = None
    if len(data) == 50:
        v00_config = {
            'u32_5': unpack_from('<I', data, 5)[0],
            'f32_9': unpack_from('<f', data, 9)[0],
            'f32_14': unpack_from('<f', data, 14)[0],
            'f32_18': unpack_from('<f', data, 18)[0],
            'f32_22': unpack_from('<f', data, 22)[0],
            'f32_26': unpack_from('<f', data, 26)[0],
            'f32_30': unpack_from('<f', data, 30)[0],
            'f32_34': unpack_from('<f', data, 34)[0],
            'raw_38_41': data[38:42].hex(),
            'f32_42': unpack_from('<f', data, 42)[0],
            'f32_46': unpack_from('<f', data, 46)[0],
        }
    else:
        pair_index = data[5]
    return Diag0x1516(
        log_time=log_time,
        version=0x00,
        sub_type=data[1],
        payload_size=len(data),
        body_raw=data[4:],
        pair_index=pair_index,
        v00_config=v00_config,
    )
