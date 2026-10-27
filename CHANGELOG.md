# Changelog

Changes to diaggrok's public decoders that can affect code reading their output.
A parser's record shape is part of the public interface: renamed, removed or
re-typed fields are listed here, even when the new decode is more correct.

Releases are tagged `vYYYY.MM.DD`. Releases before this file existed
(`v2026.08.05`, `v2026.08.23`) carry no entries.

## v2026.10.26

191 log codes: the 187 of `v2026.10.12` plus four new parsers, `0xB169`,
`0xB16A`, `0xB88A` and `0xB8DD`. No parser was removed. Two shared helper
modules are new: `parsers/_pdsm_client_ids.py` and `parsers/_short_form_4b.py`.

### New log codes

| code | name | versions | record type |
|---|---|---|---|
| `0xB169` | LTE ML1 UE Identification Message (MSG3) Report | v0x01 (MDM9x07/9x30), v0x18 (SDX20/24), v0x28 (SDX55 onward); all 12 B | `Diag0xB169` |
| `0xB16A` | LTE ML1 Contention Resolution Message (MSG4) Report | v0x01, 8 B (MDM9x07 to SDX6x) | `Diag0xB16A` |
| `0xB88A` | NR5G MAC RACH Attempt | v0x07 (108 B, SDX55), v0x0a (180 B, SDX62), v0x0e (196 B, T99W640) | `Diag0xB88A` |
| `0xB8DD` | NR5G LL1 FW Serving FTL (frequency-tracking loop) | v0x07 (544 B, SDX55), v0x06 (588 B, SDX62/SDX65) | `Diag0xB8DD` |

`0xB169` / `0xB16A` complete the LTE RACH sequence after `0xB167` (MSG1) and
`0xB168` (RAR). `0xB169` carries the RAR UL grant (TPC, MCS, RIV), the MSG3
PUSCH allocation (start RB, RB count, TBS index, HARQ id) and the MSG3 time.
It is grounded on the RAR transport block in `0xB063`, the TS 36.213 RIV and
TBS tables and the firmware's MSG3 F3 text. `0xB16A` carries the MSG4 time,
the contention-resolution result and the scheduled UL ACK time, grounded on
the firmware's contention-resolution F3 text and FDD HARQ timing.
`modulation_raw`, `grant_flags_raw` and the header bytes stay raw.

`0xB8DD` is one record per NR serving-carrier frequency-tracking-loop update:
SFN/slot, NR-ARFCN, RF frequency in kHz (v0x07), the XO frequency error (Q45
and ppm) and four per-chain FTL SNR words. The frequency error and SFN are
grounded on the firmware's F3 text, the SNR words on `0xB8D8` and the ARFCN on
`0xB97F`. The SNR words are raw: their dB scale is not yet confirmed, so no dB
value is emitted. A record whose size is not its version's exact layout is
rejected (`None`, with a warning).

`0xB88A` is one record per NR random-access attempt, Msg1 through Msg4: preamble, RA-RNTI,
RAR window, the Msg2 RAR (RAPID, TC-RNTI, timing advance), the Msg3 identity
(C-RNTI or the UL-CCCH SDU, decoded as RRC) and the RNTI the UE ends on. The
firmware logs no F3 text for this record, so the layout is grounded on
TS 38.211 / 38.321 identities instead (RA-RNTI, RAR window, cyclic shift, RAPID
echo, Msg3 CCCH against the same capture's `0xB821`). `timing_advance`,
`root_sequence_u` and `rar_ul_grant_raw` are not yet confirmed and are marked
candidate in the module. Fields of a message that never arrived (per
`msg_bitmask`) are `None`, not `0`.

### ⚠️ Breaking: record-shape change in 1 parser

Measured by comparing the dataclass fields of each parser as published in
`v2026.10.12` with this release.

| code | parser | removed | new |
|---|---|---|---|
| `0x1899` | v9 → v10 | `status_byte_2_name` | `sequence` |

`0x1899`: bytes `[1:5]` are one u32 record sequence number. The old reading
treated byte 2 as a small engine-state enum and named it; it is the count's
second byte, so the name map is gone. `counter` and `status_byte_2` are kept
(the sequence's low and second bytes). Long-uptime records that v9 dropped,
because byte 3 was non-zero, now decode.

### Additive field changes

New fields only; no existing field was removed or re-typed.

| code / type | parser | new |
|---|---|---|
| `0x1350` | v8 → v9 | `Diag0x1350V6.cfg_b27` |
| `0x1D2E` | v3 → v4 | `n_groups`, `groups`, `hdr_11_18`; new `TrailerGroup` type |
| `0x4177` | v7 → v8 | `num_peaks`, `peaks_capped`, `freq_word`, `freq_word_prev`, `hdr_i16_at2`, `hdr_const_ok`, `peaks`; new `Diag0x4177Step1Peak` type |
| `0x4179` | v12 → v13 | `freq_word` |
| `0xB0EE` | v3 → v4 | `emm_substate_name` |
| `0xB11C` | v6 → v7 | `sfn` |
| `0xB176` | v11 → v12 | `B176Cell.word8_raw` |
| `0xB17F` | v13 → v14 | `serving_priority`, `srxlev`, `srxlev_raw`, `squal`, `squal_raw` |
| `0xB183` | v12 → v13 | `sfn_tti_start` |
| `0xB193` | v32 → v39 | `LteMl1ServingCellMeasEntry.rssi` |
| `0xB197` | v4 → v5 | `sfn` |

`0xB17F`: the new fields are the cell-reselection (S-criterion) evaluation:
the serving cell's reselection priority and its Srxlev / Squal margins in dB.
`0x1D2E`: records with a trailing group block, which were dropped before, now
decode. `0xB193`: `rssi` is set on the layouts where it is verified and is
`None` elsewhere.

### Decode changes with no shape change

- `0xB193` (v32 → v39): RSRP / RSRQ now decode on subpacket versions 3, 18,
  22, 35 and 41, where they were `None`.
- Older-chipset (MDM9200 / MDM9625) payload versions now decode: `0x14FD`
  (v5 → v6), `0xB0C1` (v3 → v4), `0xB0C2` (v3 → v4), `0xB17C` (v7 → v8),
  `0xB17E` (v6 → v7), `0xB18E` (v16 → v17), and the `0xB197` / `0xB183`
  changes above.
- `0xB180` (v8 → v9): the 32-byte-block sub-layout of payload version `0x04`
  decodes; records it cannot decode are dropped with a logged reason.
- `0x137A` (v1 → v2), `0x1482` (v11 → v12): the record gate is a shared list
  of PDSM client IDs instead of a fixed magic value.
- `0x192A` (v6 → v7), `0x197F` (v1 → v2), `0x1980` (v1 → v2): 4-byte records
  are real events and decode through one shared short-form decoder.
- `0x18AB` (v19 → v24): payload versions 5, 6, 7 and 9 decode as GNSS time
  records.
- `0xB063` (v4 → v5), `0xB064` (v4 → v5): field grounding; same fields.

## v2026.10.12

Same 187 log codes as `v2026.10.04`; no parser was added or removed.

### Added: opt-in lazy parser import

`import diaggrok` imports every parser module up front (about 1.2 s). Set
`DIAGGROK_LAZY_PARSERS=1` before the first import to skip that sweep: only the
parser modules you import yourself are registered. The first lookup of a code
that is not registered, and any listing (`registered_codes()`,
`all_parser_info()`), runs the full sweep then, so results are the same, only
slower on that call. `diaggrok.parsers.load_all()` runs the sweep explicitly.
⚠️ One gap: a per-version override registered in a module you did not import
is not seen, so import every module that registers the codes you decode.
Without the variable nothing changes.

### ⚠️ Breaking: record-shape changes in 2 parsers

Measured by comparing the dataclass fields of each parser as published in
`v2026.10.04` with this release.

| code | parser | removed | new |
|---|---|---|---|
| `0x13C7` | v4 → v5 | `col_peak_value`, `col_peak_value_echo`, `col_peak_energy`, `grid_word12` | `rtc_dwell_ms`, `rtc_dwell_ms_echo`, `code_phase_cx1024`, `doppler_nco_word`, `code_hyp_count`, `noncoh_count`, `threshold`, `cno_x100`, `sv`, `srch_mode`, `grid_cells`, `grid_peak_energy` |
| `0xB821` | v28 → v29 | `slot` | `subframe`, `sfn_stamped` |

`0x13C7`: the old `col_peak_value` / `col_peak_energy` are a dwell RTC in ms and
a Cx1024 code phase, now named `rtc_dwell_ms` / `code_phase_cx1024`. `0xB821`:
the SFN / subframe bit packing was re-derived per payload version against the
DIAG timestamp; the old `sfn << 4 | slot` reading was wrong on every version, so
`sfn` values change too.

### Additive field changes

New fields only; no existing field was removed or re-typed.

| code / type | parser | new |
|---|---|---|
| `0x1526` | v7 → v8 | `aux_b2_raw`, `aux_b8_23_raw` |
| `0x15B2` | v1 → v2 | `heading_raw`, `heading_unc_raw`, `heading_raw_unit` |
| `0x15BD` | v8 → v9 | `V3SubRecord.gps_time_s` |
| `0xB061` | v3 → v4 | `rach_reason_name` |
| `0xB062` | v4 → v5 | `preamble_index`, `preamble_target_power_dbm`, `tc_rnti`, `msg3_grant_bytes`, `msg3_mac_pdu`, `msg3_c_rnti`, `msg3_ccch` |
| `0xB17F` | v12 → v13 | `rsrq_avg` |
| `0xB195` | v6 → v8 | `sp_version`, `num_cells_word`, `sf_counter`; `LteMl1ConnectedNeighborEntry.pci_flags` |
| LTE NAS OTA (`0xB0E2` and siblings) | `0xB0E2` v7 → v8 | `LteNasOtaMsg.esm_message_len`, `attach_accept_tail` |
| LTE RRC SIB2 decode | — | `Sib2AccessParams.ra_response_window_sf`, `max_harq_msg3_tx`, `prach_high_speed_flag`, `prach_zero_correlation_zone_config`, `prach_freq_offset` |

`0xB195`: `num_cells` is now `word & 0x7F` on every layout, replacing a
body-size heuristic, so its value can change on records the old rule misread.

### Decode changes with no shape change

- `0x1476` (v24 → v25): payload versions `0x04` (1151 B) and `0x0B` (2244 B)
  now decode on the compact-header path. They were dropped before.
- `0x14E1` (v5 → v6), `0xB0CD` (v5 → v6): field grounding; same fields.
- `0xB0C0` (v32 → v34): the payload-version `0x07` channel enum is complete.
- `0xB193` (v31 → v32): subpacket version 60 decodes on the v59 layout.
- `registry.check_invariants` uses a `Mapping` result (e.g. `to_dict()`
  output) as the field map. Before, a plain dict passed every invariant
  vacuously. A non-`None` result it cannot convert now raises `TypeError`.

## v2026.10.04

### Added: 124 log codes

New public parsers. These are additive and change no existing record shape:

`0x10BA` `0x11EB` `0x1350` `0x137A` `0x13C6` `0x13C7` `0x1449` `0x1457` `0x1458` `0x145E` `0x1479` `0x1486` `0x148A` `0x14CE` `0x14DE` `0x14E1` `0x156E` `0x15B1` `0x15B2` `0x1755` `0x1807` `0x1832` `0x1850` `0x1851` `0x1852` `0x1874` `0x187B` `0x18AB` `0x18AE` `0x18E8` `0x192A` `0x196E` `0x1C0D` `0x1C46` `0x1C53` `0x1C60` `0x1C6C` `0x1C7C` `0x1CC6` `0x1CC8` `0x1CCB` `0x1CCC` `0x1CE1` `0x1D15` `0x1D20` `0x1D36` `0x4177` `0x5065` `0x5066` `0x506A` `0x506C` `0x5071` `0x507A` `0x507B` `0x512F` `0x7001` `0x7150` `0x7153` `0x7155` `0x7156` `0xB061` `0xB062` `0xB063` `0xB064` `0xB0A3` `0xB0A5` `0xB0B3` `0xB0B5` `0xB0C1` `0xB0C2` `0xB0CD` `0xB0D2` `0xB0E1` `0xB0E2` `0xB0E3` `0xB0EA` `0xB0EB` `0xB0EC` `0xB0ED` `0xB0EE` `0xB114` `0xB115` `0xB116` `0xB11C` `0xB136` `0xB141` `0xB167` `0xB168` `0xB176` `0xB17C` `0xB17E` `0xB17F` `0xB180` `0xB183` `0xB18B` `0xB18E` `0xB18F` `0xB196` `0xB197` `0xB1A7` `0xB1C5` `0xB1F5` `0xB368` `0xB800` `0xB801` `0xB808` `0xB809` `0xB80A` `0xB80B` `0xB80C` `0xB814` `0xB822` `0xB823` `0xB825` `0xB826` `0xB8B5` `0xB8C0` `0xB8C5` `0xB8C8` `0xB8C9` `0xB8CB` `0xB8FD` `0xB8FF` `0xB9B9`

### ⚠️ Breaking: record-shape changes in 21 parsers (`0x4179` is covered separately below)

Measured by comparing the dataclass fields of each parser as published in
`v2026.08.23` with this release. **Removed** fields are gone from the record.
**Re-typed** fields keep their name; `int → int | None` means the field is now
`None` where the record does not carry it. **New** fields are listed so you can
find what replaced a removed one. Most of these parsers moved from a structural
placeholder decode to a grounded one, so a removed field usually has no
one-to-one successor.

| code | parser | removed | re-typed | new |
|---|---|---|---|---|
| `0x117E` | v4 → v6 | `is_compact`, `reserved_2_6`, `len_marker`, `tag`, `timestamp`, `measurement_raw`, `field_52` | — | `fragment_index`, `last_fragment`, `body_len`, `record_kind`, `layout`, `descriptor_tag`, `sv`, `search_mode`, `grid_a`, `grid_n`, `grid_m`, `job_id`, `ms`, `doppler`, `code_phase`, `num_noncoh`, `peak_index`, `peak_bin_idx`, `field_17`, `sample_encoding` |
| `0x1456` | v3 → v4 | `flag`, `state`, `aux6`, `aux7`, `aux8` | — | `tracking_state`, `acq_track_state_change`, `dpo_active`, `dpo_state_change` |
| `0x1478` | v7 → v11 | — | `bds_ms`: `int` → `int | None` | `gal_ms`, `navic_ms` |
| `0x1488` | v3 → v4 | `counter_u32`, `timestamp_u32`, `raw_0`, `raw_1`, `f_measure_0`, `f_variance_0`, `f_hdop_like`, `f_elev_like` | — | `slow_clk_count`, `latch_fcount`, `newl_arg1`, `gps_time_ms`, `gps_time_residual_ms`, `gps_time_unc_ms`, `newl_arg7`, `newl_arg8` |
| `0x1494` | v6 → v9 | — | `type_hi`: `int` → `int | None`, `type_lo`: `int` → `int | None`, `slots`: `list[Slot1494]` → `list[Slot1494 | Slot1494V0]` | — |
| `0x14B0` | v6 → v8 | `counter_block`, `build_marker` | — | `gps_ms`, `gps_week` |
| `0x1589` | v3 → v4 | `vendor_tag`, `record_type`, `variant`, `chunk_3_10`, `marker_10`, `triplet`, `data_density`, `body_raw` | — | `gps_week`, `gps_tow_ms`, `gps_time_valid`, `tick_ms`, `from_state`, `to_state`, `event`, `from_state_name`, `to_state_name` |
| `0x1636` | v2 → v3 | `config_word`, `data_density`, `body_raw` | — | `rtc_ms`, `xo_offset_ppm_q20`, `header_word_5`, `banks`, `trailer_raw` |
| `0x1837` | v4 → v5 | `timestamp`, `session_marker`, `counter_a`, `counter_b`, `reserved_zero_1`, `reserved_zero_2`, `seq_num` | — | `position_report_time_ms`, `report_seq`, `horizontal_confidence_pct_candidate`, `heading_rad`, `gps_week`, `gps_tow_ms`, `v3_byte_53`, `reserved_tail` |
| `0x1843` | v3 → v4 | `constellation`, `band` | — | `record_id`, `header_state`, `newest_ustmr_lo22`, `sentinel_count`, `sentinel_partial_count`, `reserved_nonzero_count`, `events` |
| `0x184E` | v3 → v5 | `sub_version`, `flag_8`, `constellation`, `band` | — | `event`, `asubs_id`, `number_of_stacks`, `stacks`, `subs_block` |
| `0x1855` | v6 → v9 | `session_tag`, `header_marker`, `reserved_4`, `descriptor`, `size_variant`, `constellation`, `band` | `config_word`: `int` → `int | None` | `timetick`, `dump_word`, `table_id`, `table_sub`, `table_word`, `body_len`, `body_len_ok`, `pad14`, `header_len`, `rule_generation`, `rule_count`, `header_layout`, `header_residual_ok`, `walk_status`, `trailer_magic`, `rules` |
| `0x1856` | v5 → v8 | `session_tag`, `header_marker`, `reserved_4`, `size_variant`, `constellation`, `band` | `flags_8`: `int` → `int | None` | `timetick`, `dump_word`, `table_id`, `table_sub`, `table_word`, `body_len`, `body_len_ok`, `pad14`, `header_len`, `rule_generation`, `rule_count`, `header_layout`, `header_residual_ok`, `walk_status`, `trailer_magic`, `rules` |
| `0x188B` | v9 → v12 | `dop_h_like`, `dop_v_like` | — | `h_quality_scalar`, `v_quality_scalar` |
| `0x18F5` | v2 → v4 | `Gnss18F5Block`: `angle_rad_48` | — | `Gnss18F5Block`: `sv_id`, `Gnss18F5Block`: `observation_state`, `Gnss18F5Block`: `observations`, `Gnss18F5Block`: `good_observations`, `Gnss18F5Block`: `parity_error_count`, `Gnss18F5Block`: `filter_stages`, `Gnss18F5Block`: `carrier_noise`, `Gnss18F5Block`: `latency_ms`, `Gnss18F5Block`: `predetect_interval`, `Gnss18F5Block`: `postdetections`, `Gnss18F5Block`: `meas_integral_ms`, `Gnss18F5Block`: `meas_fraction_ms`, `Gnss18F5Block`: `time_unc_ms`, `Gnss18F5Block`: `speed_mps`, `Gnss18F5Block`: `speed_unc_mps`, `Gnss18F5Block`: `measurement_status`, `Gnss18F5Block`: `misc_status`, `Gnss18F5Block`: `multipath_estimate`, `Gnss18F5Block`: `azimuth_rad`, `Gnss18F5Block`: `elevation_rad`, `Gnss18F5Block`: `carrier_phase_integral`, `Gnss18F5Block`: `carrier_phase_fraction`, `Gnss18F5Block`: `fine_speed_mps`, `Gnss18F5Block`: `fine_speed_unc_mps`, `Gnss18F5Block`: `cycle_slip_count`, `Gnss18F5Block`: `pad` |
| `0x19EB` | v6 → v8 | `Gnss19EBL5Entry`: class removed | `entries`: `list[Gnss19EBL5Entry]` → `list[Gnss19EBL5Sv]` | `f_count`, `gps_week`, `gps_milliseconds`, `time_bias`, `clock_time_unc`, `clock_freq_bias`, `clock_freq_unc`, `l5_reserved`, `sv_count` |
| `0x1C90` | v5 → v7 | `seq_counter`, `config_word`, `data_density`, `body_raw` | — | `sv_count`, `svs`, `stale_tail` |
| `0x1D23` | v1 → v2 | `context_block`, `trailer_u32_a`, `trailer_u32_b`, `trailer_u32_c`, `counter_u32_a`, `counter_u32_b`, `trailer_tail`, `body_raw` | — | `reserved_1`, `pwrprf_u8`, `pwrprf_u32_27`, `pwrprf_u16_28`, `dpo_dwell_ms`, `tail_u32_a`, `tail_u32_b`, `tail_u32_c` |
| `0x1D2E` | v2 → v3 | — | `field_pre`: `int` → `int | None`, `magic`: `int` → `int | None`, `field_32`: `int` → `int | None` | `layout`, `hdr_byte18` |
| `0x7160` | v4 → v5 | `body_raw` | — | `entries` |
| `0xB97F` | v12 → v16 | `Nr5gCellMeasurement`: `ssb_index`, `Nr5gComponentCarrier`: `serving_rsrq`, `Nr5gComponentCarrier`: `serving_rsrq_raw` | — | `Nr5gCellMeasurement`: `pbch_sfn`, `Nr5gCellMeasurement`: `beams`, `Nr5gComponentCarrier`: `serving_ssb_index`, `Nr5gComponentCarrier`: `serving_rsrp_b`, `Nr5gComponentCarrier`: `serving_rsrp_b_raw`, `Nr5gComponentCarrier`: `rx_beam_a`, `Nr5gComponentCarrier`: `rx_beam_b`, `Nr5gComponentCarrier`: `serving_rsrp_c`, `Nr5gComponentCarrier`: `serving_rsrp_c_raw`, `Nr5gComponentCarrier`: `serving_rsrp_d`, `Nr5gComponentCarrier`: `serving_rsrp_d_raw` |

### ⚠️ Breaking: `0x4179` re-identified as WCDMA PN search results (parser v9 → v12)

`0x4179` was previously decoded as LTE neighbour-measurement framing. Firmware
debug-message (F3) evidence identifies it as the **WCDMA searcher's PN search
results**, so the record's fields were renamed to what they are. The byte layout
and the accepted payload versions (`0x05`, `0x08`) are unchanged; the meaning of
several fields is not.

Measured by decoding the same records with both parser versions:

| v9 field (removed) | v11 field | note |
|---|---|---|
| `earfcn_or_freq` (list) | `uarfcn` (int) | a WCDMA UARFCN, not an LTE EARFCN |
| `measured_cell_count` | `peaks_reported` | same value |
| `block_count` | `num_tasks` | same value |
| `block_count_mirror_ok` | `num_tasks_mirror_ok` | same value |
| `blocks` (list) | `tasks` (list) | per-search-task entries |
| `measurement_raw` (list) | `peak_energy`, `peak_pos_cx8` (lists) | search-peak energy and position (chip×8) |
| `seq_u16` | `prefix_u16_at3` | same value; no longer claimed to be a sequence number |
| `camp_context_u32` | — | removed |
| `prev_earfcn_or_freq`, `prev_measured_cell_count`, `prev_measurement_raw`, `array_a_prev_raw`, `array_b_prev_raw` | — | removed |
| — | `psc_list`, `results_per_task`, `tasks_capped` | new |

Also changed: `prefix_flag_a` keeps its name but not always its value.

**Migrating:** a consumer that read `earfcn_or_freq` as an LTE channel was reading
a WCDMA UARFCN. Read `uarfcn`, and treat `0x4179` as a 3G search result rather
than an LTE measurement.
