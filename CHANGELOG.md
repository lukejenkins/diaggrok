# Changelog

Changes to diaggrok's public decoders that can affect code reading their output.
A parser's record shape is part of the public interface: renamed, removed or
re-typed fields are listed here, even when the new decode is more correct.

Releases are tagged `vYYYY.MM.DD`. Releases before this file existed
(`v2026.08.05`, `v2026.08.23`) carry no entries.

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
