"""Public zero-PII fixture for 0x1C8F (GNSS Client-API location report).

Tier 1 (risk_tiers.RISK_TIER[0x1C8F] == 1): named fields include
utc_timestamp_ms and latitude_deg/longitude_deg -- a real byte snippet
would carry a real position + time. This fixture is built entirely from
fabricated values via public_corpus.support.synthetic / struct.pack_into
-- no bytes are copied from any capture, private test, or real DIAG log.
Fabricated lat/lon are plain packed IEEE-754 doubles (not NMEA text), so
there is no NMEA-coordinate-token leak risk here (see 0x1C90/0x1CB2
fixtures for that pattern).

Layout transcribed from diaggrok.parsers.diag_0x1c8f (module docstring +
parse_0x1c8f), 2240 B fixed, v=0x0A:

    0x000 u8  version = 0x0A                      (Layer-1 gate)
    0x001 u8  motion_fix_state = 0x77              (one of the enum {0x33,0x77,0xFF})
    0x002 u8  const_0x07 = 0x07                     (Layer-1 gate)
    0x003 u64 utc_timestamp_ms (8 B, LE, read via int.from_bytes(data[3:11]))
    0x00B f64 latitude_deg
    0x013 f64 longitude_deg
    0x01B f64 altitude_ellipsoid_m
    0x061 u32 horizontal_reliability
    0x065 u32 vertical_reliability
    0x138 u8  n_sv_signal_entries = 0               (no SV table entries -> no per-slot loop)
    0x867 char[16] loc_client_name = "atfwd_daemon007\\0"
    0x887 u8  report_class_flag = 1
    (every other byte zero-filled -- reserved / not asserted on)
"""
import struct

from diaggrok.parsers.diag_0x1c8f import parse_0x1c8f, GNSS_LOC_REPORT_1C8F_SIZE

_VERSION = 0x0A
_SPEC_BYTE = 0x07

_MOTION_FIX_STATE = 0x77          # "stationary" enum member (speed == 0)
_UTC_TIMESTAMP_MS = 1_700_000_000_000  # fabricated UTC-ms value, not derived from any real capture

# Fabricated WGS84-shaped position -- plain floats, not an NMEA string.
_LATITUDE_DEG = 12.5
_LONGITUDE_DEG = -34.75
_ALTITUDE_ELLIPSOID_M = 250.0

_HORIZONTAL_RELIABILITY = 3
_VERTICAL_RELIABILITY = 3
_REPORT_CLASS_FLAG = 1

_LOC_CLIENT_NAME = "atfwd_daemon007"  # 15 chars + NUL == 16-byte name field exactly


def _synthetic_1c8f() -> bytes:
    data = bytearray(GNSS_LOC_REPORT_1C8F_SIZE)
    data[0x000] = _VERSION
    data[0x001] = _MOTION_FIX_STATE
    data[0x002] = _SPEC_BYTE
    data[0x003:0x00B] = _UTC_TIMESTAMP_MS.to_bytes(8, "little")

    struct.pack_into('<d', data, 0x00B, _LATITUDE_DEG)
    struct.pack_into('<d', data, 0x013, _LONGITUDE_DEG)
    struct.pack_into('<d', data, 0x01B, _ALTITUDE_ELLIPSOID_M)

    struct.pack_into('<2I', data, 0x061, _HORIZONTAL_RELIABILITY, _VERTICAL_RELIABILITY)

    # n_sv_signal_entries = 0 -> parser's SV-table loop does zero iterations.
    data[0x138] = 0

    name_bytes = _LOC_CLIENT_NAME.encode('ascii') + b'\x00'
    assert len(name_bytes) == 16
    data[0x867:0x877] = name_bytes
    # residue window 0x877:0x887 left zero-filled -- no embedded NMEA fragments.

    data[0x887] = _REPORT_CLASS_FLAG

    assert len(data) == GNSS_LOC_REPORT_1C8F_SIZE
    return bytes(data)


def test_1c8f_decodes_synthetic_fixed_record():
    rec = parse_0x1c8f(1000, _synthetic_1c8f())
    assert rec is not None
    assert rec.version == _VERSION
    assert rec.motion_fix_state == _MOTION_FIX_STATE
    assert rec.utc_timestamp_ms == _UTC_TIMESTAMP_MS
    assert rec.latitude_deg == _LATITUDE_DEG
    assert rec.longitude_deg == _LONGITUDE_DEG
    assert rec.altitude_ellipsoid_m == _ALTITUDE_ELLIPSOID_M
    assert rec.horizontal_reliability == _HORIZONTAL_RELIABILITY
    assert rec.vertical_reliability == _VERTICAL_RELIABILITY
    assert rec.n_sv_signal_entries == 0
    assert rec.sv_signals == []
    assert rec.loc_client_name == _LOC_CLIENT_NAME
    assert rec.loc_client_instance == 7
    assert rec.nmea_fragments == []
    assert rec.report_class_flag == _REPORT_CLASS_FLAG
    assert rec.payload_size == GNSS_LOC_REPORT_1C8F_SIZE
