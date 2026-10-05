"""0x1C90 — GNSS Client API SV Report (6693B fixed, SDX62 RM520N-GL, v0x06).

The record is the location-client-API **SV report**: a 5-byte header and a fixed array of 176
38-byte per-SV slots (5 + 176*38 = 6693, which is why the size never varies).
Only the first ``sv_count`` slots are live. The rest of the buffer is NOT
zeroed, so it carries whatever was in that memory before: Quectel AT-daemon
heap text (NMEA, ``+QGPSLOC:``, ``+QTEMP:``, ``thermal_zone*`` sysfs names,
``ql_add_response()`` traces). That residue is not a diagnostic snapshot
and not part of the SV report. Across the corpus no NMEA ever appears inside the live
``sv_count*38`` region.

Layout (little-endian)::

    [0]      u8   version = 0x06
    [1:5]    u32  sv_count   (0..176; byte 1 is its low byte, not a counter)
    [5:]     176 x GnssSv slot, 38 B each, first sv_count live:
      +0   u16  sv_id             observed: GPS 1-32, SBAS 131-133,
                                  GLONASS 65-88, Galileo 302-333 (300+PRN)
      +2   u32  constellation     1 GPS, 2 SBAS, 3 GLONASS, 6 GALILEO observed
      +6   f32  cn0_dbhz
      +10  f32  elevation_deg
      +14  f32  azimuth_deg
      +18  u16  options_mask      see SV_OPTION_BITS
      +20  f32  carrier_frequency_hz
      +24  u32  signal_type_mask  see SIGNAL_TYPE_BITS
      +28  f64  baseband_cn0_dbhz (3.6-5.3 dB below cn0_dbhz)
      +36  u16  glo_frequency     GLONASS FDMA channel k + 8 (1..14); 0 otherwise

Ground truth:

* **F3 1:1 (loc_pd.c:1094 ``locPd_dumpSvIn: sig sv_id elev azi c_no sv_state
  FreqNum``).** On an RM520N-GL cold-start capture, 406 of 440 F3
  SV-dump bursts have a 0x1C90 record (median lag 0.6 ms) whose every slot
  matches ``int(elevation)``, ``int(azimuth)`` and ``round(cn0*10)`` exactly,
  with ``sv_count`` equal to the burst's ``num_svs``. The other 34 bursts have
  no record within 0.47 s; geometry still agrees there and only that epoch's
  C/N0 differs. Per-SV exact: 11,022 / 11,440.
* **F3 masks (loc_pd.c:1085 ``eph_svmask alm_svmask num_svs``).** options bit0
  matches eph_svmask and bit1 matches alm_svmask on 3,960 / 3,960 GPS slots.
* **Modem NMEA (NMEA-splitter capture).** options bit2 (used in fix)
  equals the ``$GPGSA`` used-PRN set on 331 / 331 records; the ``$GPGSV``
  elevation/azimuth/SNR agree record-for-record.
* **Self-consistency.** carrier_frequency_hz matches every signal_type_mask
  bit exactly (L1/E1/SBAS 1575.42, L5/E5a 1176.45, GLONASS 1602+k*0.5625 MHz),
  and glo_frequency equals k + 8 on every GLONASS slot.

Log name: LOG_GNSS_CLIENT_API_SV_REPORT
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from struct import Struct, unpack_from
from typing import Any

from diaggrok.parsers.diag_0x1cb2 import _verify_nmea_checksum
from diaggrok.registry import register

EXPECTED_VERSION_1C90 = 0x06
HEADER_LEN = 5
SV_SLOT_LEN = 38
SV_SLOTS = 176                                    # 5 + 176*38 = 6693
PAYLOAD_LEN = HEADER_LEN + SV_SLOTS * SV_SLOT_LEN

_SLOT = Struct("<HIfffHfIdH")
assert _SLOT.size == SV_SLOT_LEN

# Observed values only. Each is pinned by the carrier frequency it carries and
# by the sv_id range; F3 ``sig`` 1/5/7 maps to 1/3/6 on the joined slots.
CONSTELLATIONS = {1: "GPS", 2: "SBAS", 3: "GLONASS", 6: "GALILEO"}

# Observed bits only; each is pinned by the carrier frequency on the same slot.
SIGNAL_TYPE_BITS = {
    0: "GPS_L1CA",      # 1575.42 MHz
    3: "GPS_L5",        # 1176.45 MHz
    4: "GLONASS_G1",    # 1602 + k*0.5625 MHz
    6: "GALILEO_E1",    # 1575.42 MHz
    7: "GALILEO_E5A",   # 1176.45 MHz
    15: "SBAS_L1",      # 1575.42 MHz
}

# bit0/1: F3 eph/alm masks 3960/3960. bit2: NMEA GSA 331/331. bit6/7: set
# exactly when elevation/azimuth are populated (clear on 829 zero-geometry
# slots). bit3/4: always set alongside a populated carrier/signal mask, never
# seen clear — CANDIDATE names. bit5 never set in the corpus.
SV_OPTION_BITS = {
    0: "has_ephemeris",
    1: "has_almanac",
    2: "used_in_fix",
    3: "has_carrier_frequency",   # CANDIDATE
    4: "has_signal_type",         # CANDIDATE
    6: "has_elevation",
    7: "has_azimuth",
}

# $ + talker(2) + type(3) , body ... *XX, checksum-gated. Only used on the
# stale tail past the live slots.
_NMEA_RE = re.compile(rb"\$[A-Z]{2}[A-Z]{3},[\x20-\x7e]*?\*[0-9A-Fa-f]{2}")


def _bits(mask: int, names: dict[int, str]) -> list[str]:
    return [names.get(b, f"bit{b}") for b in range(32) if mask >> b & 1]


def _extract_nmea(data: bytes) -> list[str]:
    """Checksum-valid NMEA sentences in ``data``, in order."""
    out: list[str] = []
    for m in _NMEA_RE.finditer(data):
        s = m.group().decode("ascii", "replace")
        if _verify_nmea_checksum(s):
            out.append(s)
    return out


@dataclass
class GnssSv1C90:
    """One live 38-byte SV slot."""
    sv_id: int
    constellation: int
    cn0_dbhz: float
    elevation_deg: float
    azimuth_deg: float
    options_mask: int
    carrier_frequency_hz: float
    signal_type_mask: int
    baseband_cn0_dbhz: float
    glo_frequency: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "sv_id": self.sv_id,
            "constellation": self.constellation,
            "constellation_name": CONSTELLATIONS.get(self.constellation, f"UNKNOWN_{self.constellation}"),
            "cn0_dbhz": round(self.cn0_dbhz, 2),
            "elevation_deg": round(self.elevation_deg, 2),
            "azimuth_deg": round(self.azimuth_deg, 2),
            "options_mask": self.options_mask,
            "options": _bits(self.options_mask, SV_OPTION_BITS),
            "used_in_fix": bool(self.options_mask & 0x04),
            "carrier_frequency_hz": round(self.carrier_frequency_hz),
            "signal_type_mask": self.signal_type_mask,
            "signal_types": _bits(self.signal_type_mask, SIGNAL_TYPE_BITS),
            "baseband_cn0_dbhz": round(self.baseband_cn0_dbhz, 2),
            "glo_frequency": self.glo_frequency,
        }


@dataclass
class Diag0x1C90:
    """0x1C90 — GNSS Client API SV Report (v0x06, 6693 B: header + 176 SV slots).

    ``svs`` holds the ``sv_count`` live slots. ``stale_tail`` is the
    rest of the buffer, which is never zeroed and carries leftover AP heap
    text. ``nmea_sentences`` / ``nmea_talkers`` are the checksum-valid NMEA
    found in that residue. They are leftovers, NOT part of the SV report,
    and they may hold a real position from an earlier fix.
    """
    log_time: int
    version: int
    sv_count: int
    svs: tuple[GnssSv1C90, ...]
    payload_size: int
    stale_tail: bytes
    nmea_sentences: tuple[str, ...] = ()
    nmea_talkers: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1C90",
            "log_time": self.log_time,
            "version": self.version,
            "sv_count": self.sv_count,
            "used_in_fix_count": sum(1 for s in self.svs if s.options_mask & 0x04),
            "svs": [s.to_dict() for s in self.svs],
            "payload_size": self.payload_size,
            "stale_tail_len": len(self.stale_tail),
            "nmea_sentence_count": len(self.nmea_sentences),
            "nmea_talkers": list(self.nmea_talkers),
            "nmea_sentences": list(self.nmea_sentences),
            "stale_tail": self.stale_tail,
        }


# Ground-truth recipe. RM520N-GL SDX62 emits v0x06. The live slots
# are the per-SV view the modem also prints as F3 locPd_dumpSvIn and as NMEA
# GSV/GSA: AT+QGPSGNMEA="GSV"/"GSA" of the same epoch should return the same
# sv_id/elevation/azimuth/SNR and used-in-fix set.

@register(
    0x1C90, domain="gnss",
    name="0x1C90",
    description="0x1C90 — GNSS Client API SV Report (v0x06, 6693B = u8 version + u32 sv_count + 176 x 38B GnssSv slots: sv_id, constellation, cn0, elevation, azimuth, options_mask, carrier_frequency_hz, signal_type_mask, baseband_cn0, glo_frequency). F3-grounded 1:1 against loc_pd.c locPd_dumpSvIn. Slots past sv_count hold stale AP heap text (NMEA/+QGPSLOC/+QTEMP), surfaced as stale_tail + nmea_sentences.",
    version=7,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail="Location-client-API SV report — u8 version, u32 sv_count, 176 fixed 38-byte GnssSv slots (5+176*38=6693); payloads shorter than 6693 B return None (registry WARN). F3 grounding on an RM520N-GL cold-start capture: 406/440 loc_pd.c:1094 locPd_dumpSvIn bursts match a 0x1C90 record slot-for-slot (int elev, int azi, c_no=cn0*10 exact; sv_count==num_svs; median lag 0.6 ms); the other 34 have no co-temporal record. options bit0/bit1 == F3 loc_pd.c:1085 eph_svmask/alm_svmask on 3960/3960 GPS slots. bit2 == modem NMEA $GPGSA used-PRN set on 331/331 records (NMEA-splitter capture). carrier_frequency_hz agrees with signal_type_mask on every slot; glo_frequency == FDMA k+8. 0x60 events (GPS PD session start/end) carry no per-SV field. The ASCII content (NMEA, +QGPSLOC, +QTEMP, thermal sysfs, f3-debug) is non-zeroed memory past the live slots, never inside sv_count*38; checksum-valid NMEA there is surfaced as nmea_sentences. Byte 1 is the low byte of sv_count, not a sequence counter.",
    source_url="",
    issues=(),
    fields_identified=12,
    fields_parsed=12,
    field_invariants={
        "version": {"enum": [EXPECTED_VERSION_1C90]},
        "payload_size": {"enum": [PAYLOAD_LEN]},
        "sv_count": {"range": [0, SV_SLOTS]},
    },
    # Leftover AP heap text in the never-zeroed slots past sv_count: NMEA,
    # +QGPSLOC/+QTEMP AT responses, thermal_zone/cooling_device sysfs labels,
    # ql_add_response() traces.
    ascii_kinds=("nmea", "config-token", "label", "f3-debug"),
)
def parse_0x1c90(log_time: int, data: bytes) -> Diag0x1C90 | None:
    if len(data) < HEADER_LEN or data[0] != EXPECTED_VERSION_1C90:
        return None
    # The 176-slot array is fixed-size (6693 B on every record);
    # a shorter payload is truncated -> None (registry WARN), not a record
    # with a silently clipped stale tail.
    if len(data) < PAYLOAD_LEN:
        return None
    sv_count = unpack_from("<I", data, 1)[0]
    if sv_count > SV_SLOTS or HEADER_LEN + sv_count * SV_SLOT_LEN > len(data):
        return None
    svs = tuple(
        GnssSv1C90(*_SLOT.unpack_from(data, HEADER_LEN + i * SV_SLOT_LEN))
        for i in range(sv_count)
    )
    tail = data[HEADER_LEN + sv_count * SV_SLOT_LEN:]
    nmea = _extract_nmea(tail)
    return Diag0x1C90(
        log_time=log_time,
        version=data[0],
        sv_count=sv_count,
        svs=svs,
        payload_size=len(data),
        stale_tail=tail,
        nmea_sentences=tuple(nmea),
        nmea_talkers=tuple(sorted({s[:6] for s in nmea})),
    )
