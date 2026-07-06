"""Per-code PII risk tier for the 58-code first-push slice (D10).

0 = real-snippet-eligible: the parser's named fields carry no cell identity,
    geographic/GNSS position, GNSS absolute time, IMEI/IMSI/GUTI, firmware/
    build string, or absolute wall-clock timestamp, AND the payload is
    FULLY decoded with no opaque/undecoded region (no leftover
    body_raw/raw tail) — a real byte-snippet of any undecoded region could
    carry PII (coordinate, cell-ID, IMEI) that the text-only leak_tokens
    guard cannot see, so any such region forces tier-1 regardless of the
    decoded fields' content.
1 = synthetic-only: at least one named field falls into one of the above
    categories, OR the parser leaves any undecoded body_raw/raw/opaque
    region, OR the parser's own docstring flags unresolved/opaque bytes
    that plausibly hold one of those categories (asymmetric-risk default:
    under doubt, tier-1 — see task-5-brief.md).

Classified by reading each parser at
``libs/diaggrok/src/diaggrok/parsers/diag_0xNNNN.py`` (dataclass fields,
struct-offset comments, and docstring field tables). See
``.superpowers/sdd/task-5-report.md`` for the per-code justification table.
"""
RISK_TIER: dict[int, int] = {
    0x117E: 1,  # GPS multi-peaks searcher: docstring flags SV/Doppler fields unresolved (doubt)
    0x1375: 1,  # CGPS IPC: v7 payload decode exposes gnss_tow_ms + week (GNSS abs time)
    0x1455: 0,  # GNSS epoch counter: version/sequence(monotonic)/flags/reserved only
    0x1456: 0,  # GNSS heartbeat: version/flag/state/aux6-8 pure enum/status
    0x1476: 1,  # GNSS WLS fix: lat_rad/lon_rad/alt_m + gps_week/gps_tow_ms
    0x1477: 1,  # GPS clock/SV report: header gps_week + gps_milliseconds
    0x1478: 1,  # GNSS clock report: header gps_week + gps_ms
    0x147B: 1,  # GNSS clock/cell-DB report: header gps_week + gps_ms
    0x147C: 1,  # GNSS PE WLS Position Report (by name); body_raw undecoded (doubt)
    0x147D: 1,  # GNSS nav DB, companion to 0x147C position report; undecoded slots (doubt)
    0x147E: 1,  # GNSS RF HW status: fw_id is an explicit GNSS RF firmware identifier string
    0x1480: 1,  # GLONASS fix: glonass_cycle_number/days/ms convert to absolute UTC (validated)
    0x1482: 1,  # GNSS measurement: byte_27 explicitly named "firmware variant identifier"
    0x1488: 1,  # GNSS config/measurement: timestamp_u32 named field, high-entropy (doubt: absolute?)
    0x148E: 0,  # GNSS event: version/param_a/counter1/code4/value_a/... pure enum/counter
    0x1490: 0,  # GNSS state/event: version/state_byte/sub_state/status pure enum/status
    0x1494: 1,  # Per-SV constellation slots: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x14A6: 1,  # GNSS per-SV CNo snapshot: fw_tag explicit firmware-tag field
    0x14B0: 1,  # GNSS data report: build_marker explicit 3-byte per-chipset firmware fingerprint
    0x14FD: 1,  # GNSS data report header stub: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x1516: 1,  # Rare GNSS init/event: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x1526: 1,  # Per-SV measurement: unverified/undecoded tail -- real snippet could hide PII -> synthetic-only
    0x1544: 1,  # GNSS SV aggregate: body_kind can be 'nmea' -> NMEA sentence carries lat/lon/UTC
    0x1587: 1,  # GNSS tracking detail: mid_raw (6B opaque) + variable body_raw undecoded (doubt)
    0x1589: 1,  # GNSS 17B record: chunk_3_10 docstring candidate "u56 ts" (doubt: absolute time?)
    0x158C: 1,  # Per-constellation RF stats: unverified/undecoded tail -- real snippet could hide PII -> synthetic-only
    0x15BD: 1,  # Rare GNSS report: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x1634: 0,  # Per-SV range measurement: meas_a/b/cno_dbhz measurement fields only
    0x1636: 1,  # Structural header stub: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x163D: 1,  # GNSS RF Bandpass AGC status: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x1646: 1,  # GLONASS RF bandpass: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x1837: 1,  # GNSS per-fix position record: latitude_deg/longitude_deg/altitude_m explicit
    0x1843: 1,  # Galileo E6 skeleton: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x184E: 1,  # BeiDou B2b skeleton: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x1855: 1,  # GPS L1C skeleton: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x1856: 1,  # BeiDou B1C skeleton: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x1859: 1,  # GNSS XTRA assistance server URL: unverified/undecoded tail -- real snippet could hide PII -> synthetic-only
    0x1885: 1,  # GNSS measurement/status: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x1886: 1,  # Galileo E1 measurement: per-SV gps_tow_tick explicitly named GPS time-of-week
    0x188B: 1,  # GNSS reference-position cache: ref_lat_rad/ref_lon_rad + snapshot lat/lon/altitude
    0x1893: 1,  # GNSS measurement-engine status: slot timestamp_u40 ambiguous absolute-time (doubt)
    0x1899: 0,  # GNSS status tick report: counter/status_byte_2/status_flag pure enum/status
    0x18AC: 1,  # LTE ML1 inter-freq measurement: PCI + EARFCN together (cell identity)
    0x18F8: 0,  # GNSS misc status: all sentinel/const fields (version/type_b/sentinel_a-d)
    0x197F: 0,  # GNSS/RF state flag: single constant state_word
    0x1980: 0,  # GNSS/RF state flag: single constant state_word (sibling of 0x197F)
    0x19DE: 1,  # GNSS ME fix report: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x19EB: 1,  # GPS L5 measurement: raw_header docstring hypothesizes "packed timestamp" (doubt)
    0x1C8F: 1,  # GNSS Client-API location report: utc_timestamp_ms + latitude_deg/longitude_deg
    0x1C90: 1,  # GNSS LocEng diagnostic snapshot: embeds plaintext NMEA sentences + QGPSLOC AT response
    0x1CB2: 1,  # GNSS NMEA batch: sentences[] are NMEA (e.g. GPGGA) carrying lat/lon + UTC time
    0x1D23: 1,  # GNSS power profiling: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x1D2E: 1,  # GNSS/config cell-array: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0x4179: 1,  # LTE intra-freq neighbor measurement: camp_context_u32 flagged serving-cell/coarse-time candidate
    0x7160: 1,  # GNSS-engine-start cluster stub: undecoded body_raw/raw tail -- real snippet could hide PII -> synthetic-only
    0xB192: 1,  # LTE ML1 idle-mode neighbor measurement: PCI + EARFCN together (cell identity)
    0xB193: 1,  # LTE ML1 serving cell measurement: PCI + EARFCN together (cell identity)
    0xB195: 1,  # LTE ML1 connected-mode neighbor measurement: PCI + EARFCN together (cell identity)
}
