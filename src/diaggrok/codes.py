# diaggrok-provenance: re
"""Log code constants for Qualcomm DIAG protocol."""

# GNSS log codes
# Canonical names cross-checked against an external MIT reference.
# Historical diaggrok names
# for 0x1478 ("GPS RF Status") and 0x147B ("GPS SV Health") were wrong;
# the actual codes are CLOCK_REPORT and CD_DB_REPORT.  The legacy aliases
# are kept below so existing code keeps working.
LOG_GNSS_POSITION_REPORT            = 0x1476
LOG_GNSS_GPS_MEASUREMENT_REPORT     = 0x1477
LOG_GNSS_CLOCK_REPORT               = 0x1478
LOG_GNSS_CD_DB_REPORT               = 0x147B
LOG_GNSS_COUNTER_1455               = 0x1455
LOG_GNSS_HEARTBEAT_1456             = 0x1456
LOG_GNSS_DEMOD_TRACKING             = 0x1479
LOG_GNSS_NAV_DB_147C                = 0x147C
LOG_GNSS_NAV_DB_147D                = 0x147D
LOG_GNSS_PRX_RF_HW_STATUS_REPORT    = 0x147E
LOG_GNSS_GLONASS_MEASUREMENT_REPORT = 0x1480
LOG_GNSS_DATA_1482                  = 0x1482
LOG_GNSS_CONFIG_1488                = 0x1488
LOG_GNSS_STATUS_148E                = 0x148E
LOG_GNSS_STATE_1490                 = 0x1490
LOG_GNSS_NAV_DATA_1494              = 0x1494
LOG_GNSS_DATA_14A6                  = 0x14A6
LOG_GNSS_DATA_14B0                  = 0x14B0
LOG_GNSS_ME_POSITION_FIX            = 0x14D8
LOG_GNSS_OEMDRE_MEASUREMENT_REPORT  = 0x14DE
LOG_GNSS_OEMDRE_EXT_14E0           = 0x14E0
LOG_GNSS_OEMDRE_SVPOLY_REPORT      = 0x14E1
LOG_GNSS_BDS_MEASUREMENT_REPORT     = 0x1756
LOG_GNSS_GAL_MEASUREMENT_REPORT_C   = 0x1886  # Galileo Measurement Report (Compact, per zukgit QXDM table — #N)
LOG_GNSS_ME_GAL_E6                  = 0x1843  # Galileo E6 measurement (#N)
LOG_GNSS_ME_BDS_B2B                 = 0x184E  # BeiDou B2b measurement (#N)
LOG_GNSS_ME_GPS_L1C                 = 0x1855  # GPS L1C measurement (#N)
LOG_GNSS_ME_BDS_B1C                 = 0x1856  # BeiDou B1C measurement (#N)
LOG_GNSS_SV_STATUS                  = 0x148A
LOG_GNSS_DATA_14FD                  = 0x14FD
LOG_GNSS_INIT_1509                  = 0x1509
LOG_GNSS_INIT_1516                  = 0x1516
LOG_GNSS_NAV_MEAS_VALIDITY          = 0x1526
LOG_GNSS_SV_AGGREGATE               = 0x1544
LOG_GNSS_TRACKING_1587              = 0x1587
LOG_GNSS_RF_STATS                   = 0x158C
LOG_GNSS_NMEA_OVER_DIAG             = 0x1384
LOG_GNSS_RARE_15BD                  = 0x15BD
LOG_GNSS_CONFIG_1596                = 0x1596

# Legacy aliases — historical diaggrok names that were incorrect.
# Keep pointed at the correct constants so importers keep working.
# Tools that report a canonical "the" name for a log code (e.g.
# tools/generate_diaggrok_inventory.py) consult `_LEGACY_ALIASES`
# below to skip these names in favour of the canonical one.
LOG_GNSS_GPS_RF_STATUS              = LOG_GNSS_CLOCK_REPORT             # 0x1478
LOG_GNSS_GPS_SV_HEALTH              = LOG_GNSS_CD_DB_REPORT             # 0x147B
LOG_GNSS_GAL_MEASUREMENT_REPORT     = LOG_GNSS_GAL_MEASUREMENT_REPORT_C # 0x1886 (#N)

_LEGACY_ALIASES: frozenset[str] = frozenset({
    "LOG_GNSS_GPS_RF_STATUS",
    "LOG_GNSS_GPS_SV_HEALTH",
    "LOG_GNSS_GAL_MEASUREMENT_REPORT",
})

# LTE log codes
LOG_LTE_CELL_SEARCH_RESULTS         = 0x4801
LOG_LTE_ML1_MEASUREMENT             = 0x41BC
LOG_LTE_ML1_MEAS_REPORT             = 0x18AE
LOG_LTE_ML1_NEIGHBOR_MEAS           = 0x187B
LOG_LTE_ML1_SYSTEM_SCAN             = 0x1900
LOG_LTE_MAC_DL_TB                   = 0x1950
LOG_LTE_ML1_DL_STATS                = 0x18E8
LOG_LTE_ML1_SERVING_CELL_TIMING     = 0x1875
LOG_LTE_ML1_COMPOSITE_LOG_BUFFER    = 0x1841
# 0x1807 — multiplexed ML1 measurement log; byte2=subtype selects 4 layouts
# (heartbeat / medium / large per-cell grid / fine cell array). See diag_0x1807.py (#N).
LOG_LTE_ML1_MEAS_MULTIPLEX          = 0x1807
LOG_LTE_RRC_OTA_SDX20               = 0x7001
LOG_LTE_RRC_OTA_MSG                 = 0xB0C0

# LTE ML1 serving cell measurement
LOG_LTE_ML1_SERVING_CELL_MEAS_RSP   = 0xB193
LOG_LTE_ML1_NEIGHBOR_CELL_MEAS      = 0xB192
LOG_LTE_ML1_CONNECTED_NEIGHBOR_MEAS = 0xB195
LOG_LTE_ML1_SYSTEM_SCAN_RESULTS     = 0xB18E

# LTE ML1 measurement pair
LOG_LTE_ML1_INTRA_FREQ_MEAS         = 0x18AB
LOG_LTE_ML1_INTER_FREQ_MEAS         = 0x18AC

# LTE LL1 / DCI / PDCCH
LOG_LTE_LL1_DCI_INFO_REPORT         = 0xB16C
LOG_LTE_LL1_PDCCH_DECODING_RESULT   = 0xB130

# LTE RRC CA band combinations
LOG_LTE_RRC_SUPPORTED_CA_COMBOS     = 0xB0CD

# LTE NAS OTA log codes (plain, unencrypted)
LOG_LTE_NAS_ESM_PLAIN_OTA_IN_MSG    = 0xB0E2
LOG_LTE_NAS_ESM_PLAIN_OTA_OUT_MSG   = 0xB0E3
LOG_LTE_NAS_EMM_PLAIN_OTA_IN_MSG    = 0xB0EC
LOG_LTE_NAS_EMM_PLAIN_OTA_OUT_MSG   = 0xB0ED

# EM7511 edge-case discoveries (2026-04-20) — log codes surfaced during
# airplane-mode and SIM power-cycle transitions on MDM9650/SDX20.
LOG_GNSS_MISC_18F8                  = 0x18F8  # 20B fixed, GNSS/loc misc (#N)
LOG_GNSS_STATE_197F                 = 0x197F  # 4B fixed, RF state flag (#N)
LOG_GNSS_STATE_1980                 = 0x1980  # 4B fixed, RF state flag (#N)
LOG_CODE_7150                       = 0x7150  # 19B fixed, range/misc (#N)
LOG_LTE_NAS_ESM_B0E0                = 0xB0E0  # variable, NAS/ESM OTA incoming twin of 0xB0E1 (#N)
LOG_LTE_NAS_ESM_B0E1                = 0xB0E1  # 33B fixed, NAS/ESM sibling (#N)
LOG_LTE_NAS_ESM_EPS_QOS_B0E5        = 0xB0E5  # 20B v=0x01 NAS/ESM EPS-QoS/bearer-ctx; recognition only (#N)
LOG_LTE_NAS_ESM_B0F6                = 0xB0F6  # 3B fixed, NAS/ESM tiny event (#N)
LOG_LTE_NAS_ML1_B190                = 0xB190  # 264B fixed, NAS/ML1 (#N)
LOG_LTE_NAS_EVENT_B19A              = 0xB19A  # 24B fixed, NAS frequent event (#N)
LOG_LTE_NAS_SEC_B1C6                = 0xB1C6  # 244B fixed, NAS security (#N)
LOG_LTE_NAS_STATUS_B1DA             = 0xB1DA  # 32B fixed, NAS status (#N)
LOG_LTE_B1B0                        = 0xB1B0  # 2B fixed, byte0=0x01 version, byte1 ∈ {0x71,0x72} two-valued sub-state enum (#N, SIM8202G-M2 SDX55 single-chipset)

# Inseego M2000B SDX55 ingest 2026-04-25 — single-shot LTE/RRC boundary code
# whose internal layout decomposes as a 16B header + 18 × 24B entries (entry
# count is byte[1]). Single sample; structural hypothesis only — see #N.
LOG_LTE_RRC_186B                    = 0x186B  # 448B fixed, 18×24B entry table (#N, layout-only parser at N=1)

# QShrink / QTrace runtime telemetry
# 0x1FE8 carries runtime-text trace records from the modem firmware's QShrink
# F3-message channel (also known as LOG_QSH_QTRACE_TEXT_F3_C, LOG_QTRACE_MSG).
# QCAT renders these as human-readable function/file/line/severity + format-
# resolved messages using the SILK descriptor blocks; the raw wire format is
# not yet RE'd (no in-hand raw records, only QCAT decoded output). See #N.
LOG_QTRACE_MESSAGES                 = 0x1FE8

# 2G / GPRS signalling
LOG_GPRS_MAC_SIGNALLING_MESSAGE     = 0x5226  # #N GPRS MAC-layer signalling (PACCH/PBCCH/PCCCH)

# 2G / GSM-GPRS (equipment-ID 0x5) — subsystem identified 2026-06-13 by
# cross-referencing the osmo-qcdiag log-code table already in this repo
# (docs/qualcomm/diag-protocol-reference.md). These codes were tracked as
# "subsystem undetermined" (#N/#N/#N/#N/#N/#N) because the
# 0x5xxx range is not in diaggrok's standard family map — but equip-id 0x5 is
# the legacy GSM/GPRS stack. On 5G-only parts (SDX55/SDX72) the GSM/GPRS
# subsystem is compiled in but inert, so these fire with all-zero / poison /
# idle-marker payloads; a GSM/GPRS-capable part (EG25-G MDM9607) populates at
# least one struct field (0x5202 @32==0x14, 213/213) confirming the layer is
# real, just not exercised here.
LOG_GSM_L2_STATE                    = 0x50C8  # #N GSM L2 (LAPDm) state; byte0 marker {0,3} = L2 state
LOG_GPRS_RLC_UL_STATS               = 0x5202  # #N GPRS RLC uplink statistics (46B)
LOG_GPRS_RLC_DL_STATS               = 0x520A  # #N GPRS RLC downlink statistics (47B)
LOG_GPRS_LLC_ME_INFO                = 0x5212  # #N GPRS LLC ME info (TLLI, encryption); poison 0xFFFFFFFF@2 = unassigned TLLI
LOG_GPRS_LLC_5213                   = 0x5213  # #N GPRS LLC per-SAPI state (0x5213–0x521A LLC block); index 1/3/5/7/9/11 = LLC SAPIs
LOG_GPRS_LLC_5214                   = 0x5214  # #N GPRS LLC per-SAPI record (37B); index = LLC SAPI, body = per-SAPI LLC params

# 3G / WCDMA signalling
LOG_WCDMA_SIGNALLING_MESSAGE        = 0x412F  # #N WCDMA RRC/RLC/MAC signalling PDU

# 3G / UMTS NAS OTA
LOG_UMTS_NAS_OTA_MESSAGE            = 0x713A  # #N UMTS NAS MM/GMM/SM OTA

# RM520N-GL SDX62 2026-04-23 corpus additions — 5 high-volume codes from the
# simultaneous 5-modem wardrive surfaced by #N histogram, brought to
# partial-decode / full-decode tiers via <redacted-ref> session.
LOG_LTE_ML1_18EA                    = 0x18EA  # 64B LTE ML1 paired subframe (#N)
LOG_NR5G_ML1_1C07                   = 0x1C07  # 2708B NR5G ML1 (#N, structural — 18×138B slot array)
LOG_GNSS_CLIENT_API_LOCATION_REPORT = 0x1C8F  # 2240B GNSS Client-API location report (#N, full v4 decode) — canonical QXDM name; NOT NR5G ML1 despite the 0x1C00 range
LOG_NR5G_ML1_1C8F                   = 0x1C8F  # legacy alias (misnomer: this is a GNSS code, see above) — kept for back-compat
LOG_GNSS_LOCENG_1C90                = 0x1C90  # 6693B GNSS LocEng config snapshot (#N, structural)
LOG_GNSS_NMEA_BATCH_1CB2            = 0x1CB2  # variable-size NMEA burst (#N, full decode)
LOG_UIM_APDU_PARSE_1CC8             = 0x1CC8  # 11316B UICC/SIM APDU-parse F3 trace, v=0x03 (#N) — NOT NR5G ML1
LOG_NR5G_ML1_1D24                   = 0x1D24  # 144B NR5G ML1 short (#N)
# EM9291 SWIX65C session-7896 first-observation cluster (#N).
LOG_NR5G_ML1_1CE5                   = 0x1CE5  # 24B v=0x01 NR5G ML1 sleep-state event (#N)
LOG_NR5G_ML1_1D1E                   = 0x1D1E  # 117B v=0x00 NR5G ML1, length-prefixed APN @78 (#N)
LOG_NR5G_ML1_1D31                   = 0x1D31  # 31B v=0x01 NR5G ML1 boot/cycle state (#N)
LOG_FRAME_TELEMETRY_1D3D            = 0x1D3D  # 18+79k v=0x02 per-frame telemetry array, 10 Hz (#N; range is NR5G ML1 but emitter unpinned)
LOG_NR5G_ML1_1DD9                   = 0x1DD9  # 16+88*N v=0x00 NR5G ML1 count-prefixed entry array (EM9291 SDX62; #N)
LOG_NR5G_ML1_1DDF                   = 0x1DDF  # 317B v=0x00 NR5G ML1 RAT-switch report (#N)
LOG_LTE_NR5G_SIG_B364               = 0xB364  # var 4+N*16 freq-measurement container, marker=0x4000 (#N)
LOG_LTE_NR5G_SIG_B06E               = 0xB06E  # 52B v=0x30 LTE/NR5G sig measurement; u16 seq @2, var payload [9:24] (#N)
LOG_LTE_NR5G_SIG_B093               = 0xB093  # 16B v=0x38 LTE/NR5G sig; u16 idx@10, u16 metric@12, flag u16@14 (#N)
LOG_LTE_NR5G_SIG_B0D3               = 0xB0D3  # 75B v=0x01 LTE/NR5G sig; corpus-invariant 0101+zeros snapshot (#N)
LOG_LTE_NR5G_SIG_B0D4               = 0xB0D4  # 294B v=0x01 LTE/NR5G sig frame; marker@20, u16 trailer@292 (#N)
LOG_LTE_NR5G_SIG_B0D5               = 0xB0D5  # 17B v=0x01 LTE/NR5G sig; corpus-invariant 01+16 zeros (#N)

# MDM9600 (Sierra SWI9200X / MC7700) subsystem/client name-table family.
# Fixed 56B header + count-prefixed list of null-terminated ASCII client
# names (DIAG/GPS/ADC/FWS/LTE ML1 on 0x125E; Q6SW/DIAG/HS-USB/SDCC1 on
# 0x1263). NOT WCDMA codes — ASCII names self-identify a registered-client
# snapshot, same KIND as the SDX-era CMAPI table 0x19EC (#N). (#N/#N)
LOG_MDM9600_SUBSYS_TABLE_125E       = 0x125E  # var 56+N names, v=0x38 (#N)
LOG_MDM9600_SUBSYS_TABLE_1263       = 0x1263  # var 56+N names, v=0x38 (#N)

# MDM9600 (Sierra SWI9200X / MC7700) gpsOne/PDS GNSS time-state record.
# Fixed 40B, v=0x0101: two LE-u32 clocks (clock_a @4, clock_b @10) ticking
# in lockstep at 1 Hz with a constant bias clock_b-clock_a == 0x0916ED07
# (local-tick vs GPS-referenced time); 26B zero tail. GPS-active only.
# Sibling gpsOne records 0x13BA/0x1440 share the same fix clock. (#N)
LOG_MDM9600_GNSS_TIMESTATE_150B     = 0x150B  # fixed 40B, v=0x0101 (#N)

# MDM9600 (Sierra SWI9200X / MC7700) gpsOne/PDS GNSS measurement records that
# share ONE millisecond time-of-week (TOW) clock during a live standalone fix:
# 0x13BA TOW @+0x0B and 0x1440 TOW @+0x35 carry 27 exact shared values in the
# discovery capture — co-emitted from the same measurement engine. byte+0 type
# tags 0x33 / 0x32 are adjacent. Conservative parsers decode version + TOW +
# well-understood fields; the per-SV array (0x1440) and float metric (0x13BA)
# semantics await multi-epoch hardware ground-truth. (#N/#N)
LOG_MDM9600_GNSS_MEAS_13BA          = 0x13BA  # fixed 15B, v=0x33; TOW @+0x0B (#N)
LOG_MDM9600_GNSS_MEAS_1440          = 0x1440  # fixed 102B, v=0x32; TOW @+0x35 (#N)

# IMS-signaling ASCII cluster (registered RM520N-GL SDX62 T-Mobile survey,
# #N audit). These carry the subscriber IMS identity; the parsers decode it
# faithfully (#N) — the tool never withholds content.
LOG_IMS_REGISTRATION_1832           = 0x1832  # IMS registration identity, 148/149B v=0x01 (#N)
LOG_IMS_SIP_MESSAGE_156E            = 0x156E  # full SIP message text, var 697-4109B v=0x01, byte1=MO/MT (#N)
LOG_IMS_MESSAGING_IDENTITY_1C9C     = 0x1C9C  # IMS messaging-identity (NAI/MSISDN/ICCID), v=0x02 (#N)

# NR5G log codes
LOG_NR5G_ML1_MEAS_B897              = 0xB897  # structural (#N)
LOG_NR5G_ML1_MEAS_B8AE              = 0xB8AE  # structural (#N)
LOG_NR5G_ML1_MEAS_B8B5              = 0xB8B5  # structural (#N)
LOG_NR5G_ML1_MEAS_B95B              = 0xB95B  # structural (#N)
LOG_NR5G_L1_MEAS_STATUS             = 0xB8C5
LOG_NR5G_ML1_MEAS_DB                = 0xB8CB
LOG_NR5G_ML1_MEAS_DB_UPDATE         = 0xB97F
LOG_NR5G_RRC_OTA_MSG                = 0xB821
LOG_LTE_NR5G_SIGNALLING_ARRAY_B8E5  = 0xB8E5  # 16B hdr + Nx32B block array, v=0x02, SDX55 (#N)
LOG_LTE_NR5G_SIGNALLING_B8E2        = 0xB8E2  # fixed 232B, v=0x06, seq+marker+tail, SDX55 (#N)
LOG_LTE_NR5G_SIGNALLING_B843        = 0xB843  # chipset-split: SDX55 78B/v4, SDX62 82B/v5 (#N)
LOG_LTE_NR5G_SIGNALLING_B89B        = 0xB89B  # hdr+N elements: SDX55 v2/16B, SDX62 v0/8B (#N)
LOG_LTE_NR5G_SIGNALLING_B89C        = 0xB89C  # chipset-split fixed: SDX62 36B/v0, SDX55 44B/v1 (#N)
LOG_LTE_NR5G_SIGNALLING_B8E8        = 0xB8E8  # 12B hdr + N*16B blocks; block_count==(len-12)//16, SDX55 (#N)
LOG_LTE_NR5G_SIGNALLING_B896        = 0xB896  # byte0=v0, byte2 marker 2/3; 8B hdr + N var sub-records (#N)
LOG_LTE_NR5G_SIGNALLING_B868        = 0xB868  # byte0=v4; size split SDX55 36/140 b2=0, SDX62 172/444 b2=3 (#N)
LOG_LTE_NR5G_SIGNALLING_B8E7        = 0xB8E7  # 8B hdr + N*16B blocks; (len-8)%16==0; flag6/7 size class, SDX55 (#N)
LOG_LTE_NR5G_SIGNALLING_B860        = 0xB860  # per-modem byte0 {0x00,0x06,0x09}; (ver,mk) dispatch; 8B hdr+zero-pad tail, SDX55+SDX62 (#N)
LOG_LTE_NR5G_SIGNALLING_B812        = 0xB812  # v=0x01; 6B hdr (count@4 u8) + count*6B entries; len==6+count*6, SDX62 R03A04 (#N)
LOG_LTE_NR5G_SIGNALLING_B844        = 0xB844  # variable container, byte0 {0x00,0x01}; v0 32 sizes / v1 fixed 1076B; hdr+raw, SDX55+SDX62+SDX65 (#N)
LOG_LTE_NR5G_SIGNALLING_B84B        = 0xB84B  # variable TLV container, byte0 {0x02,0x04,0x05}; no hdr length field; hdr+raw, SDX55+SDX62+SDX65 (#N)
LOG_LTE_NR5G_SIGNALLING_B84D        = 0xB84D  # entry array, byte0 {0x00,0x03,0x04}; count@4 u32; len==hdr[v]+count*stride[v], SDX55+SDX62+SDX65 (#N)
LOG_LTE_NR5G_SIGNALLING_B84E        = 0xB84E  # entry array, byte0 {0x00,0x01}; count@4 u32; len==8+count*11, SDX55+SDX62+SDX65 (#N)
LOG_DIAG_1DA2                       = 0x1DA2  # multi-kind report v=0x01; subsystem unresolved (NR5G-ML1-range vs community GNSS_CC); u32 kind@4 selects size {5->140,6->156,0->662} (#N)
LOG_NR5G_ML1_1DDA                   = 0x1DDA  # NR5G ML1 high-rate 146B fixed v=0x04; counter+config+meas (#N)
LOG_PDN_APN_CONTEXT_1CB6            = 0x1CB6  # PDN/APN data-context, 230B fixed v=0x00; embeds APN string (#N)
LOG_B3XX_B368                       = 0xB368  # 0xB3xx 1768B fixed, 4-byte ver dword 0x3B; cell-id hdr + structured front (5 const 04 02 entries) + dynamic tail; not TLV (#N). Corpus: T99W640/SDX72-EXCLUSIVE (543 caps incl. RM520N-GL/SDX62 x125, RM500Q x50 — none emit it); the 0xB36x band is generationally split — SDX62 emits 0xB360/0xB364, SDX72 emits 0xB368, never overlapping. Sibling 0xB364=LOG_LTE_NR5G_SIG_B364 (decoded freq-meas) ⇒ 0xB368 ≈ the SDX72-gen LTE/NR5G sig/meas occupant of the same band
LOG_NR5G_ML1_B835                   = 0xB835  # NR5G ML1 var record v=0x00; 20B hdr, slot_value@16 keyed by (subtype,freq/slot) (#N)
LOG_NR5G_ML1_B834                   = 0xB834  # NR5G ML1 large var meas-dump v=0x00; 16B hdr, up to 8226B (#N)


# ── Name resolution (single-sourced for every generated diag-log list) ──
#
# Every tool that emits a list or table of DIAG log codes resolves the log's
# human name through ``display_name()`` below, so the rule "the community /
# Android source-code name, or what we're calling it if it's more specific"
# is applied IDENTICALLY everywhere:
#   tools/generate_diaggrok_inventory.py · generate_parser_issue_map.py ·
#   diag_groundtruth.py · diag_multiversion.py · diag_version_triage.py
#
# This module is intentionally dependency-free (pure constants, no imports),
# so these helpers can even be loaded in ISOLATION (importlib from this file
# path) by the pure-text-scan tools that deliberately avoid importing the
# parser registry — they still get the community ``LOG_*`` names for free.


def _hex_forms(log_code: int) -> frozenset[str]:
    """Lowercased spellings of a code that count as "just the bare code".

    A parser whose registered ``name`` is literally its own hex code (the
    common default) is NOT treated as a "more specific" name — these forms
    are what we match it against.
    """
    return frozenset({
        f"0x{log_code:04x}", f"0x{log_code:x}",
        f"{log_code:04x}", f"{log_code:x}", str(log_code),
    })


def constant_name(log_code: int) -> str:
    """The community / Android DIAG constant for ``log_code``, or ``''``.

    Returns the ``LOG_*`` symbol used by QXDM and the Android diag headers
    (e.g. ``LOG_LTE_ML1_DL_STATS``). When several constants map to the same
    code (a canonical name plus a legacy alias — see ``_LEGACY_ALIASES``),
    the canonical name wins; an alias is returned only when it is the sole
    mapping.
    """
    fallback = ""
    for name, value in globals().items():
        if (name.startswith("LOG_")
                and isinstance(value, int)
                and value == log_code):
            if name in _LEGACY_ALIASES:
                fallback = fallback or name
                continue
            return name
    return fallback


def _short_label(log_code: int, description: str) -> str:
    """A concise human label pulled from a parser ``description``.

    Most parsers carry no ``LOG_*`` constant and default their ``name`` to the
    bare hex code — but their ``description`` is "what we're calling it".
    Descriptions in this codebase conventionally open ``0xXXXX — <label> …``
    or ``LOG_FOO (0xXXXX) — <label> …``; this strips that leading code token
    and returns the label up to the next separator, length-capped.
    """
    s = (description or "").strip()
    if not s:
        return ""
    # Strip a leading code / LOG_ token followed by a separator.
    for sep in (" — ", " -- ", " - ", ": ", " "):
        idx = s.find(sep)
        if idx == -1 or idx > 40:
            continue
        head = s[:idx]
        hl = head.lower()
        if hl.startswith("0x") or head.upper().startswith("LOG_") or f"0x{log_code:04x}" in hl:
            rest = s[idx + len(sep):].strip()
            if rest:
                s = rest
            break
    # Cut the label at the first downstream boundary.
    cuts = [i for i in (s.find(c) for c in (" — ", " -- ", " (", "; ", ". ")) if i != -1]
    if cuts:
        s = s[:min(cuts)].strip()
    s = s.rstrip(" ;:.,")
    if len(s) > 60:
        s = s[:59].rstrip() + "…"
    return s


def display_name(log_code: int, entry=None) -> str:
    """Human-facing name for ``log_code`` in any auto-generated list.

    Resolution honors "what we're calling it if it's more specific, else
    the community / Android source-code name":

      1. The parser's own ``name`` (``entry.name``) when it's more specific
         than the bare hex code — our chosen identifier, e.g.
         ``GnssSvInfo163D``, ``MePositionFix14D8``.
      2. The community / Android ``LOG_*`` constant (``constant_name``).
      3. A concise label from the parser ``description`` (``_short_label``) —
         covers the majority of codes, which have no constant and a hex
         ``name`` but a meaningful description.
      4. ``0xXXXX`` as a last resort (no name known anywhere).

    ``entry`` is any object exposing ``.name`` / ``.description`` attributes
    (e.g. a ``registry.ParserEntry`` or a lightweight shim built from a
    text scan) or ``None`` when the caller has only the code.
    """
    name = (getattr(entry, "name", "") or "") if entry is not None else ""
    if name and name.strip().lower() not in _hex_forms(log_code):
        return name
    const = constant_name(log_code)
    if const:
        return const
    desc = (getattr(entry, "description", "") or "") if entry is not None else ""
    label = _short_label(log_code, desc)
    if label:
        return label
    return f"0x{log_code:04X}"
