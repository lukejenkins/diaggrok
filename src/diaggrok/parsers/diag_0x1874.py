"""LTE ML1 DL power/quality measurement (0x1874) — version-dispatched parser.

Byte[0] of every 0x1874 payload is a version field. Each version selects a
distinct on-wire layout — and, as a *consequence* of that layout, a distinct
payload size. **Version is the protocol's discriminator; size is a
consequence of which version is active.** Size invariance is not format
invariance: dispatching on size silently mis-decodes a future firmware
shipping a new struct layout in an already-observed byte count.

Despite the historical "LTE ML1 DL power" title, 0x1874 is an MCPM (Modem
Core Power Manager) session-power log; LTE ML1 is the *requesting*
subsystem. See the per-version F3 grounding below.

## Versions observed in the corpus

| byte[0]      | Observed size | Chipset / modem family                              | Records    | Status     |
|--------------|---------------|-----------------------------------------------------|-----------:|------------|
| ``0x04`` (4) | 52 B          | SDX20 LM960, MDM9x07 EG18-NA, Quectel SDX24 EG12-GT |     66,997 | ✅ decoded |
| ``0x06`` (6) | 247 B         | SDX55 FN980 / EM9190 / LV55 / Inseego M2000         |  4,134,104 | ✅ decoded |
| ``0x0c`` (12)| 50 B          | SDX62 RM520N-GL, Casa CFW-3212 (Quectel RG520N-NA)  | 14,684,720 | ✅ GROUND v0x0c |
| ``0x6b`` (107)| 56 B         | MDM9650 Sierra EM7511 / EM7565 / MC7411, Fibocom FM101-GL |     56,745 | ✅ decoded |
| ``0x05`` (5) | 76 B          | SDX24 Quectel EM120R-GL / EM160R-GL (3 fw builds)   |      7,611 | ✅ GROUND v0x05 |
| ``0x11`` (17)| 58 B head + body_type tail (12 sizes, 58..343 B) | SDX72 Foxconn T99W640 / Dell DW5934e | 113,005 | ✅ GROUND v0x11 |
| ``0x0d`` (13)| 50 B head + body_type tail (7 sizes, 50..576 B) | SDX62 Orbic R562L5 (MeiG ODM)       |     77,525 | ✅ GROUND v0x0d |

✅ = a dedicated decode branch exists; "GROUND" = the version also carries its
own F3 grounding verdict (below).

Every observed version has a dedicated decode branch. The v0x11 record counts
above include the ``.dlf``/``.bin`` sidecar pairs some surveys carry for one
capture, so they are sidecar-summed totals, not distinct-record counts. Byte0
strays 0x00 / 0x71 / 0x7C / 0x9D (7 records, all from one stress-test kismet
capture, each embedding a ``a8 12 01`` timestamp fragment) are not versions
and stay refused. A future firmware can still ship an unseen version byte —
this parser refuses it (returns ``None``) rather than mis-decoding it through
an existing layout, and a new branch + enum entry must be added.

## The cross-version measurement-window timestamp pair

**Every decoded version carries a measurement-window timestamp PAIR at a fixed
tail offset** — ``window_start`` then ``window_end``, one immediately after the
other on an 8-byte *stride* (not an 8-byte payload boundary). Each is read as a
``u64``, but only the low **≤6 bytes** are ever populated in the corpus (the
value is a free-running ``≤48``-bit timer; bytes 7–8 of each u64 are always
zero). Monotonic non-decreasing within each capture: **v04/v06 ≈ 99.99 %,
v0c ≈ 98.9 %** (measured over the curated extract corpus). ``window_end >=
window_start`` in 100 % of records with a small positive delta:

| ver | window_start | window_end | median (end−start) | > 2³² |
|-----|-------------:|-----------:|-------------------:|------:|
| 0x04| u64 @36      | u64 @44    | 1422 ticks | 65 % |
| 0x06| u64 @231     | u64 @239   |  279 ticks | 87 % |
| 0x0c| u64 @34      | u64 @42    |  216 ticks | 100 % |

On v=0x0c these words are monotonic timestamps, not per-RX power, and the
same holds on SDX55 (v06) and SDX20/SDX24/MDM9x07 (v04). Each timer must be
read as a whole ``u64``: splitting it into a ``u32 value`` + a ``u8
qualifier`` drops a nonzero 6th byte on v0c (byte 39 reaches 0x05 on
CFW-3212). (On v04/v06 the 6th byte is always zero, so such a split would be
lossless there — the ``u64`` reading is *correct* for those, not *forced*.)

## Layout for version=0x06 (247 bytes, SDX55)

    Byte  0:       u8   version (always 6 for this layout)
    Bytes 1..3:    zeros
    Byte  4:       u8   num_entries (4/10/11/18/19 — configured cell count)
    Byte  5:       u8   band_or_subtype (structural; band/subtype candidate, uncited)
    Byte  6:       u8   cell_info
    Bytes 7..8:    zeros (corpus-zero; unasserted reserved gap)
    Bytes 9..10:   u16  freq_field (75-quantised measurement enum, NOT EARFCN)
    Byte 11:       zero (corpus-zero reserved)
    Bytes 12..15:  u32  measurement_a (u24 in practice; byte 15 zero)
    Bytes 16..19:  u32  measurement_b (== u16@17 << 8; often zero)
                   NOTE: on an RM500Q-AE LTE camp, co-temporal F3
                   (`quectel_led_modem.c:696 rsrp_signa = -101`, `cell.rsrp`
                   = -100.8 ×10) grounds serving RSRP at -101 dBm — yet NO v6
                   field carries -101/-11/-70 in dBm form (measurement_a=681663,
                   measurement_b∈{0,288000}, freq_field=3000). The
                   measurement_* words are not RSRP/RSRQ in dBm; if power at
                   all they are linear/energy-domain. Physical identity still
                   needs a varied-signal drive (a stationary camp has no
                   x-variance).
                   F3-VERDICT v0x06: GROUND (dBm reading ruled out).
                   Re-verified independently on an RM500Q-AE SDX55 drive
                   capture (36,356 v0x06 records, all 247 B / byte0=0x06):
                   co-temporal serving RSRP −77 dBm (`quectel_led` F3 print) —
                   measurement_a=681663 (u24 @12, byte15≡0),
                   measurement_b∈{0,288000} (u16@17<<8), freq_field ∈
                   {1500,3000,3675,5175,5850,…} = exact ×75 enum (÷75 →
                   {20,40,49,69,78}). No v0x06 field encodes a small signed
                   dBm value; fields are ×75 enums / energy-domain.
                   num_entries @4 ∈ {4,10,11,18,19} corpus-stable.
    Bytes 20..230: OPTIONAL event-gated body — populated in ~9 % of records,
                   21 distinct shapes; bytes 84..230 always zero in the corpus.
                   Preserved verbatim as ``body_hex`` when non-zero (needs
                   dedicated event-triggered captures to decode).
    Bytes 231..238: u64  window_start (measurement-window START timestamp)
    Bytes 239..246: u64  window_end   (measurement-window END timestamp)

## Layout for version=0x0c (50 bytes, SDX62)

Field offsets are corpus-locked (60K-record per-byte histogram across
RM520N-GL + CFW-3212). freq_field and measurement_b are ×75-quantised
enums (measurement_a is discrete but NOT ×75); their *physical* quantity is
still open (they are not EARFCN or per-RX power), so they are named
structurally.

    Byte  0:      u8   version (always 0x0c)
    Bytes 1..2:   u16  header_filler (always 0xffff — exposed + name-locked)
    Byte  3:      u8   band_or_subtype (observed {0x04,0x09,0x0d,0x0e,0x10,0x18})
    Byte  4:      u8   entry_count (observed {0x00,0x01,0x04..0x07})
    Bytes 5..6:   zeros
    Byte  7:      u8   subtype_a (observed {0x00,0x30,0x50})
    Bytes 8..9:   zeros
    Byte 10:      u8   flags (observed {0x00,0x60,0xa0})
    Bytes 11..12: zeros
    Byte 13:      u8   subtype_b (observed {0x04,0x06})
    Byte 14:      zero
    Byte 15:      u8   rare_flag (observed {0x00,0x03}; 0x00 in 99.96 %)
    Bytes 16..21: zeros
    Bytes 22..23: u16  freq_field (75-quantised measurement enum, NOT EARFCN)
    Byte 24:      zero
    Bytes 25..28: u32  measurement_a (u24 in practice; byte 28 zero)
    Bytes 29:     zero
    Bytes 30..31: u16  measurement_b (75-quantised)
    Bytes 32..33: zeros
    Bytes 34..41: u64  window_start (measurement-window START timestamp)
    Bytes 42..49: u64  window_end   (measurement-window END timestamp)

    F3-VERDICT v0x0c: GROUND (EARFCN / dBm readings ruled out). Grounded on
    v0x0c's OWN 234,368 records from a **varied-signal drive** (Quectel
    RM520N-GL, SDX62; a moving LTE drive on band 66 / EARFCN 66536 with a
    co-temporal `AT+QENG="servingcell"` reference), so the exclusions below
    are stronger than a stationary contrast (they hold under active
    x-variance):
    - **STRUCTURAL.** 234,368/234,368 v0x0c records decode (100 %), all 50 B /
      byte0=0x0c, 0 refused.
    - **window_start/window_end self-ground (in-capture oracle).** monotone
      non-decreasing 99.98 % (uniqueness 100 %); `window_end >= window_start` in
      234,368/234,368 with median delta 230 ticks (0 exceed 2^20) → a
      free-running measurement-window **timer pair**, not per-RX power. A device
      timer validates itself by its own monotonicity — no external reference
      needed.
    - **freq_field is not EARFCN.** freq_field ∈ {0,2325,3225,3900,4875,5475,
      6225} (every non-zero value ×75 → {31,43,52,65,73,83}) — matches NEITHER
      the serving EARFCN **66536** (band 66) NOR any neighbour EARFCN
      ({975,5230,55342,55344,55540,55542,55740,66536} from the QENG poll). A
      band-independent ×75-quantised enum, not a channel number.
    - **measurement_a/measurement_b are not RSRP/RSRQ dBm.** Serving RSRP swung
      across **34 distinct values (−112…−54 dBm, a 58 dB span)** over the drive,
      yet measurement_a took only **7 distinct** values and measurement_b **4** —
      discrete enums cannot track continuous 58 dB serving-power variation.
    - **MCPM subsystem identity (corroborating, cross-version).** 0x1874 is
      grounded as the MCPM session log on v0x04 (mcpm.c `MCPM_Process_Req`
      begin/end tick ↔ window_start/window_end hi u32 at conf 1.00) and v0x6b
      (lte_ml1_mcpm.c prints). The SDX62 RM520N-GL F3 string database (407,917
      records) carries the SAME 64-bit session-timer prints —
      `mcpm.c:2618 MCPM_Process_Req … tick: 0x%x%08x`, `mcpm.c:1434
      MCPM_MCVSConfig_Modem End … (Timestamp: 0x%x%08x) (Duration (us): %u)`,
      `mcpm.c:2356 MCPM_Get_Ota_Time64 … time 0x%x%08x` — and v0x0c's
      window_start/window_end pair is the byte-identical role. A **direct** 1:1
      mcpm↔window correlation is not available on v0x0c: 12,690,492/12,690,492
      (100 %) QShrink4 hashes resolve, but there are **0 mcpm F3 samples** —
      the drive captures **mask-gate the MCPM F3 subsystem off** (only
      `wmcpmdrv.c` WCDMA prints fire), so the identity is version-consistent +
      string-database-attested, NOT independently re-measured on v0x0c. An
      mcpm-armed RM520N-GL F3 capture would upgrade this to a direct bind.
    - **Oracles.** F3 0x79 plaintext = GNSS-dominated (gnss_gpm_api.cpp), no
      mcpm; F3 0x99 QShrink4 = mcpm mask-gated off (see above). QCSuper/SCAT =
      N/A (0x1874 not in their tables — internal MCPM log). 0x60 = not
      MCPM-field-relevant.

## Layout for version=0x05 (76 bytes, SDX24 EM120R-GL / EM160R-GL)

The v=0x04 layout (same header, same five u24-in-u32 measurement words) with a
24-byte region inserted before the window pair, which moves from @36/@44 to
@60/@68 (76 = 52 + 24). Per-byte histogram over 4,000 records / 8 captures:

    Byte  0:      u8   version (always 0x05)
    Bytes 1..3:   u24  header_counter (free-running; often 0)
    Byte  4:      u8   sub_count (always 4)
    Byte  5:      u8   flag_5 ({0,1,2,3,6}; v0x04's same byte is {0,1})
    Byte  6:      u8   cell_info ({0x03,0x27,0x28,0x2a})
    Bytes 7..8:   zeros
    Bytes 9..10:  u16  freq_field (×75 enum: 2250/3000/3675/4575/5850; NOT EARFCN)
    Byte 11:      zero
    Bytes 12..31: u32 ×5 measurement_a..e (u24 in practice; top byte zero)
    Bytes 32..35: zeros (v0x04's word_32 position; corpus-zero on v0x05)
    Bytes 36..39: u32  aux_36 (small enum {0,2,0x10,0x11,0x1c}, byte 37 0/4, byte 38 0/1)
    Bytes 40..43: u32  aux_40 ({0,1,4,8})
    Bytes 44..47: u32  aux_44 (byte 44 always 0)
    Bytes 48..52: zeros
    Bytes 53..54: u16  freq_field_2 (same ×75 value set as freq_field; often 0)
    Bytes 55..59: zeros
    Bytes 60..67: u64  window_start (MCPM session-window START tick; 5 bytes populated)
    Bytes 68..75: u64  window_end   (MCPM session-window END tick)

    F3-VERDICT v0x05: GROUND. Grounded on v0x05's OWN captures (sidecar
    sweep: 7,611 records, 10 captures, EM120R-GL + EM160R-GL across three
    firmware builds, 100 % at 76 B):
    - **STRUCTURAL.** 4,000/4,000 sampled records decode; window_end >=
      window_start in 4,000/4,000.
    - **MCPM bind (direct).** On an EM160R-GL capture (565 v0x05 records, F3
      0x79 resolution 1.0) the window pair sits on the MCPM session clock:
      ``mcpm.c:965 MCPM_MCVSConfig_Modem End (Timestamp)`` lands within 2,000
      ticks of a window in **264/264** prints and ``mcpm_drv_mcvs.c:702
      Finished MCVS request … end time`` in **264/264**; request *begin*
      prints hit about half the time. Chance would give about 0.5 % (565
      windows over ~860 M ticks). Negative controls on the same clock never
      land near a window: ``MCPM_Get_WakeUp_Time`` 0/207, ``vstmr_epoch``
      0/205, ``gts`` latch 0/85. So each v0x05 record is one MCPM
      MCVS-request completion, the same MCPM identity v0x04 grounded.
    - **freq_field is not EARFCN.** An EM120R-GL capture (4,810 v0x05
      records) camps on EARFCN 66786 (B66) with neighbours {66786, 66911,
      900, 5035}; freq_field / freq_field_2 take {2250, 3000, 3675, 4575,
      5850}, all ×75, none in the cell list.
    - measurement_a carries 681663 on the EM120R-GL, the same constant v0x06
      carries on the SDX55 RM500Q-AE camp: same field family across versions.
      Its physical unit is still open (no varied-signal v0x05 drive yet).

## Layout for version=0x11 (SDX72 Foxconn T99W640 / Dell DW5934e)

A 58-byte head followed by a tail selected by ``body_type`` (byte 41). The
head is the v=0x0c layout with its measurement words and window pair moved
+8 bytes (freq_field 22→30, measurement_b 30→38, window 34/42→42/50).
Per-byte histogram over 24,226 records spanning all 12 sizes:

    Byte  0:      u8   version (always 0x11)
    Bytes 1..2:   u16  header_filler (always 0xffff, the v0x0c signature; gated)
    Byte  3:      u8   band_or_subtype ({0x02,0x04,0x08,0x0b,0x0c,0x0d,0x0f,0x18})
    Byte  4:      u8   entry_count (4..7 for body_type 4; 1 for 6; 0 for 7)
    Bytes 5..19:  zeros
    Byte 20:      u8   rare_flag ({0,3}, v0x0c's rare_flag set)
    Byte 22:      u8   flag_22 ({0,0x0c})
    Byte 23:      u8   subtype_a ({0,0x10,0x20,0x30,0x50}, v0x0c's subtype_a set)
    Byte 26:      u8   field_26 ({0,1,2,3,5,6,0x0c})
    Byte 27/28:   u8   flag_27 ({0,0x80}) / flag_28 ({0,1})
    Bytes 30..31: u16  freq_field (100 % ×75: {2325,3150,3900,4950,5475,6225}, NOT EARFCN)
    Byte 37:      u8   flag_37 ({0,0x80})
    Bytes 38..39: u16  measurement_b (99.9 % ×75)
    Byte 41:      u8   body_type (4, 6 or 7)
    Bytes 42..49: u64  window_start (QTimer ticks; <=48-bit)
    Bytes 50..57: u64  window_end

    body_type 4: no tail (58 B).
    body_type 6: u32 @58 tail_sub_version (always 2), u32 @62 tail_block_mask,
                 u32 @66/70/74 tail_aux, u8 @78 tail_entry_count; block bytes
                 82..157 (verbatim); for len >= 174, 16-byte entries from @158
                 with count == tail_entry_count (corpus-exact). Attested sizes
                 86/98/158/174/190/206/222; the mask does NOT predict the size
                 on its own (0x100 ships at both 158 and 174), so unattested
                 sizes are refused.
    body_type 7: 213-byte block @58..270 (verbatim) then 24-byte entries from
                 @271, count == u8 @131 (corpus-exact for 271/295/319/343).

    F3-VERDICT v0x11: GROUND. v0x11 ships 12 sizes because it is a fixed head
    + a counted tail, not because the records are mis-framed. The T99W640
    emits no other 0x1874 byte0, which fits a new chip shipping a new version.
    - **STRUCTURAL.** 24,226/24,226 sampled records (all 12 sizes, 54 captures,
      two T99W640 units) decode; 0xffff at bytes 1..2 in 100 %; window_end >=
      window_start in 100 % at every size; window_start monotone 24,186/24,191
      (99.98 %) per capture in time order. A DLF mis-frame cannot hold a
      constant 0xffff and a monotone timer pair at a fixed offset across 12
      sizes.
    - **Timebase.** On an RF low-power-cycle capture (2,464 v0x11 records, F3
      resolution 0.9999) the window pair sits on the modem QTimer/XO clock:
      ``VSTMR suspend XO=`` prints land within 2,000 ticks of a window in 9/22
      (chance about 0.5 %), i.e. at modem sleep entry, a power-session
      boundary.
    - **freq_field is not EARFCN.** The same capture's serving cell is EARFCN
      5110 (``tle_cell_mgr.cpp`` + ``mgp_pe_common.c`` F3); freq_field takes 7
      ×75 values there and never 5110.
    - **MCPM identity: version-consistent, not directly re-measured.** None of
      the 18 T99W640 F3 artifacts carries an MCPM session-tick print; the only
      mcpm F3 sites are boot-time init (``rcinit`` task start,
      ``mcpm_ulog.c: ULOG log init``, ``mcpm_qtrace.c``). Same limitation v0x0c
      has. An MCPM-armed T99W640 F3 capture would upgrade this to a direct bind.
    - Open: the type-6 block / entries and the type-7 213-byte block are
      framed and count-validated but their inner fields are not yet named.

## Layout for version=0x0d (SDX62 Orbic R562L5, MeiG ODM)

A 50-byte head followed by a tail selected by ``body_type`` (byte 33). The
head is the v=0x0c layout at the v=0x0c offsets (no +8 shift, unlike v=0x11);
bytes 6, 11 and 33, which are zero on v=0x0c, are populated. Per-byte
histogram over all 77,525 records (3 captures, one firmware build):

    Byte  0:      u8   version (always 0x0d)
    Bytes 1..2:   u16  header_filler (always 0xffff, the v0x0c signature; gated)
    Byte  3:      u8   band_or_subtype ({0x02,0x04,0x09,0x0d,0x0e,0x0f,0x18,0x19})
    Byte  4:      u8   entry_count (4..7 for body_type 4; 1 for 6; 0 for 7 — the
                       v=0x11 coupling)
    Byte  6:      u8   flag_6 ({0,0x0c}; v=0x11's flag_22 value set)
    Byte  7:      u8   subtype_a ({0x10,0x20,0x30,0x50,0x90,0xc0})
    Byte 10:      u8   flags ({0,0x20,0x80,0xa0})
    Byte 11:      u8   flag_11 ({0,1})
    Byte 13:      u8   subtype_b ({0x04,0x06})
    Byte 15:      u8   rare_flag ({0,3,0x60})
    Bytes 22..23: u16  freq_field (100 % ×75: {0,2325,3225,3900,4875,5475,6225},
                       v0x0c's exact set; 0 on body_type 4; NOT EARFCN)
    Bytes 25..28: u32  measurement_a (u24; 0x1ffd34 = 2096436 in 77,521/77,525)
    Bytes 30..31: u16  measurement_b (100 % ×75: {0,1125,1500,2175,3300,3750})
    Byte 33:      u8   body_type (4, 6 or 7)
    Bytes 34..41: u64  window_start (QTimer 19.2 MHz ticks; <=48-bit)
    Bytes 42..49: u64  window_end

    body_type 4: no tail (50 B).
    body_type 6: u8 @50 tail_sub_version (always 2), u24 @51 tail_block_mask,
                 block bytes 54..148 (verbatim), u32 @149 tail_entry_count;
                 13-byte entries from @153. For len > 153, entries ==
                 tail_entry_count (corpus-exact, 28,799/28,799); 153 B carries
                 no entries (count reads 1). Attested sizes 153/166/179; no
                 header byte or bit separates 153 B from 166 B, so unattested
                 sizes are refused. (In 166 B records the block and the entry are
                 never both populated — 0/28,792 — not yet explained.)
    body_type 7: 198-byte block @50..247 (verbatim) then 41-byte entries from
                 @248, count == u8 @176 (corpus-exact for 248/535/576:
                 28,809 × 0 + 17 × 7 + 71 × 8).

    F3-VERDICT v0x0d: GROUND. Direct MCPM bind on the QTimer clock, and the
    first DIRECT bind of a body_type-6 window in any version (v0x11 type 6 is
    consistency-only).
    - **STRUCTURAL.** 77,525/77,525 records (all 7 sizes, 3 captures: a
      72,627-record survey, a 1,403-record extra-log capture and a
      3,495-record F3-armed capture) decode; 0xffff at bytes 1..2 in 100 %;
      body_type ↔ size exact; window_end >= window_start in 100 % at every
      size; window_start monotone per capture in record order 98.87 % /
      99.86 % / 100 % (v0x0c: 98.9 %).
      Captures are HDLC CRC-clean. A mis-frame cannot hold a constant header,
      v0x0c's exact ×75 freq_field set and a monotone timer pair at fixed
      offsets across 7 sizes.
    - **Timebase.** On the 180 s F3-armed capture the window pair spans
      179.88 s at 19.2 MHz, and the 40,767 decoded QTrace 0x9D timestamps
      (QTimer low 32, unwrapped) land in the same range.
    - **MCPM bind, body_type 6 (direct).** ``rf_nr5g_sync.c:219`` "send
      RFI_NR5G_MSG_ID_MCPM_CLK_PROC_UPDATE … clk proc 844800" falls INSIDE a
      v0x0d window in 10/12 prints, every one a type-6 window, and the other 2
      land <=1,300 ticks after a type-6 window end. Inside-coverage chance is
      0.02 % (windows are ~227 ticks / 12 us). Shifting the prints by ±500
      ticks drops 10/12 → 0/12. Its receiver ``rf_nr5g_rfiu_tx.c:1516`` "MCPM
      clock proc update rxd" is inside 8/12, all type 6.
    - **MCPM bind, body_type 7 (replicates v0x11 on other silicon).** LTE
      ``rflte_mc_common.c:13635`` "set_mcpm_lte_wakeup_status … API =0" →
      next ``rflte_dispatch.c:2288`` CDRX_WAKEUP_CNF brackets a window in
      20/42 calls (random same-length intervals: 0.54 %), 17 of them type 7.
      The ``API =1`` contrast brackets 4/42, none type 7 — the same API=0/1
      asymmetry measured on the T99W640.
    - **F3 plane silent.** 97,616 F3 records (0x79/0x99, 100 % resolved)
      carry no mcpm.c session-tick print; the only MCPM-named sites are
      ``dcvsq_logger.c`` buffer warnings with no tick argument. 0x60: absent
      (no outer 0x60 frames). QCSuper/SCAT: N/A (0x1874 is not in their
      tables).
    - **freq_field is not EARFCN.** The survey's serving cell is band 66
      EARFCN 66536 (PCI 310), neighbours EARFCN 975; freq_field takes only its
      ×75 set, never either.
    - **measurement_a is not RSRP.** measurement_a is the constant 2096436 in
      77,521/77,525 records while the per-RX RSRP read -113/-118 dBm.
    - Open: body_type 4 is not isolated by any caller pair (same as v0x11); the
      type-6 block/entries and type-7 block/entries are framed and
      count-validated but their inner fields are not yet named.

## Layout for version=0x04 (52 bytes, SDX20 / SDX24 / MDM9x07)

    Byte  0:      u8   version (always 0x04)
    Bytes 1..3:   u24  header_counter (partial free-running counter; 71 % monotone)
    Byte  4:      u8   sub_count (observed {0x02,0x04})
    Byte  5:      u8   valid_flag (observed {0x00,0x01})
    Byte  6:      u8   cell_info (observed {0x26..0x2d})
    Bytes 7..8:   zeros (corpus-zero; unasserted reserved gap)
    Bytes 9..10:  u16  freq_field (75-quantised measurement enum; {2100,2550,3375,4050})
    Byte 11:      zero (corpus-zero reserved)
    Bytes 12..15: u32  measurement_a (u24 in practice)
    Bytes 16..19: u32  measurement_b (u24 in practice)
    Bytes 20..23: u32  measurement_c (u24; bit-packed top bits)
    Bytes 24..27: u32  measurement_d (u24; byte 26 const 0x0c)
    Bytes 28..31: u32  measurement_e (u24)
    Bytes 32..35: u32  word_32 (high-entropy, ~69 % monotone — counter-ish; semantics open)
    Bytes 36..43: u64  window_start (measurement-window START; ~99.99 % monotone)
    Bytes 44..51: u64  window_end   (measurement-window END)

    F3-VERDICT v0x04: GROUND. Grounded on a varied-signal drive (Telit
    LM960A18, SDX20; 1705 v0x04 records, all 52 B / byte0=0x04) — a
    band-cycle capture (B2/B4-B66/B5, AT#BND drive) with a co-temporal AT
    poll AND a matching F3 string database (F3 resolution 1.00). Unlike the
    v0x06 camp, this drive has active signal variation, so the exclusions
    below are stronger than a stationary contrast.
    - **Identity → MCPM session log.** Over the mcpm F3 subsystem: 35,152
      co-temporal F3 samples; `mcpm.c` `MCPM_Process_Req` /
      `MCPM_Config_Modem` ("Start of request … begin time = 0x%x%08x, end
      time = …, duration = %lu uSec") co-emits 1:1 with 0x1874, and the
      packet's window-region u32s at off 40 (window_start hi) and off 48
      (window_end hi) match the mcpm begin/end-time args at conf 1.00
      (1697/1697). 0x1874 is therefore the **MCPM session log**; "LTE ML1 DL
      Power" is the *requesting* subsystem (`lte_ml1_mcpm.c` bridges
      ML1↔MCPM: DL data-rate / bandwidth / CA session requests).
      `window_start`/`window_end` are the MCPM **session begin/end
      timestamps** (mcpm.c).
    - **measurement_* are not RSRP/RSRQ dBm.** `measurement_a` (u24@12) is a
      corpus CONSTANT = 531,499 (0x081c2b) — identical in this capture AND an
      independent LM960 capture (9,399 recs) — while AT-truth RSRP varied
      −95…−104 dBm and RSRQ −11…−20 dB across the same band cycle. A field
      constant under a varied-signal drive cannot be RSRP/RSRQ. Consistent
      with the v0x06 result, now under active x-variance.
    - **freq_field is not EARFCN.** freq_field (u16@9) ∈ {3375, 4050} (×75 →
      {45, 54}) ≠ serving EARFCN {66786 (B66), 800 (B5/B2)}; it tracks the RF
      config as a ×75-quantised enum (2 values ↔ 2 bands), physical unit open.
    - Coincidental encoding near-hits are not adopted: off21 `negdiv16` ≈ −11
      resembles RSRQ but is a single byte mid-`measurement_c` with an exotic
      encoding at conf 0.81.
    - Oracles: F3 = GROUND (mcpm); AT correlation rules out dBm; QCSuper/SCAT =
      N/A (0x1874 not in their tables — internal MCPM log); 0x60 = present
      (1085) but NAS/RRC events, not MCPM-field-relevant.

## Layout for version=0x6b (56 bytes, MDM9650 Sierra + Fibocom FM101-GL)

    Byte  0:      u8   version (always 0x6b)
    Bytes 1..3:   u24  counter_a (partial free-running counter; ~70 % monotone)
    Bytes 4..51:  reserved — all zero across the corpus (empty measurement region)
    Bytes 52..55: u32  field_b (low byte a 0x10-granular value; ~50 % == counter_a)

F3-VERDICT v0x6b: GROUND. Two independent grounds, both specific to v0x6b:

1. **Subsystem identity — MCPM (Modem Core Power Manager), not a cell
   measurement.** Co-temporal F3 in the same v0x6b captures names the emitting
   source file outright: an EM7565 F3 capture carries **30,159
   `lte_ml1_mcpm.c` F3 prints** (sites :924/:1657/:1663/:2292 "MCPM using
   EFS…", "MCPM updating pcc bw…", "MCPM_MCVSConfig_Modem"), and an MC7411 F3
   capture carries `Tech 4--MCPM_MODEM_BLK`. 0x1874 is an LTE-ML1
   **power-management** log, not a DL-power *measurement*.
2. **No RSRP/RSRQ/EARFCN (WiGLE-cell) reading of v0x6b.** The measurement
   region (bytes 4..51) is **census-exact `0x00` in 100 %** of the corpus
   across FOUR chipsets — EM7511, EM7565, MC7411 (Sierra) AND Fibocom
   FM101-GL (sidecar offset distributions at offsets 4..51 = `{0x00}` on all
   three F3 captures; 3230/3230 records decode, 0 refused). No v0x6b field
   carries a signed dBm value; WiGLE cell-measurement validation is N/A for
   this version (nothing populated to validate). The two data-carrying
   fields are power-session bookkeeping: counter_a (u24 free-running) and
   field_b (u32 whose byte-52 low byte is strictly **0x10-granular /
   16-quantised** — census-confirmed on all three F3 captures; a power/rail
   index shape, not a measurement).

The corpus is idle / stationary; a full semantic decode of counter_a/field_b
would need a connected-mode power-transition drive (they are internal counters
no F3 print binds a co-temporal value to).

Offsets for every version are cross-validated across ≥2 chipset generations
where available (LM960+EG12-GT+EG18-NA / FN980+EM9190+M2000 /
RM520N-GL+CFW-3212 / EM7511+MC7411). Every data-carrying byte of every version
is extracted into a named field; the remaining gaps are corpus-zero reserved
bytes (unasserted, except v=0x6b's bytes 4..51, which are checked via
``reserved_all_zero``).

Log name: LOG_EVENTS_DS_GPRS_PAGE_RECEIVED
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# --- Ground-truth recipe (version=0x0c, SDX62) ---------------------------
# The v=0x0c layout is RM520N-GL (SDX62). Field offsets are corpus-locked;
# the *physical* meaning of the ×75-quantised measurement words is still
# open. The window_start/window_end u64 pair is GROUNDED (monotonic
# measurement-window timestamps, not per-RX power). Hardware runs on
# RM520N-GL and CFW-3212 rule out freq_field / the window words as power.
# --- end recipe ----------------------------------------------------------


# Per-version payload-size invariants observed corpus-wide. A ``version``
# byte whose payload size doesn't match its row here is either truncated
# or a corpus-novel layout, and the parser refuses it on the
# consequence-check.
_V04_PAYLOAD_SIZE = 52
_V6_PAYLOAD_SIZE = 247
_V0C_PAYLOAD_SIZE = 50
_V6B_PAYLOAD_SIZE = 56
_V05_PAYLOAD_SIZE = 76

# v=0x11 (SDX72) is a fixed 58-byte head + a tail selected by body_type
# (byte 41). Accepted sizes per body_type are exactly the ones attested in the
# corpus sweep; an unattested size is refused (None)
# rather than guessed. Type 6's block mask (u32 @ 62) does NOT predict the
# size on its own (mask 0x100 ships at both 158 and 174 B), so type 6 is an
# attested-size set, not a derived law.
_V11_HEAD_SIZE = 58
_V11_SIZES_BY_BODY_TYPE = {
    4: frozenset({58}),
    6: frozenset({86, 98, 158, 174, 190, 206, 222}),
    7: frozenset({271, 295, 319, 343}),
}
_V11_T6_ENTRY_BASE = 158     # type-6 16-byte entries start here (len >= 174)
_V11_T6_ENTRY_SIZE = 16
_V11_T7_ENTRY_BASE = 271     # type-7 24-byte entries start here
_V11_T7_ENTRY_SIZE = 24

# v=0x0d (SDX62 Orbic R562L5) is the v=0x0c 50-byte head + a tail selected by
# body_type (byte 33). Same attested-size policy as v=0x11:
# type 6's 153 vs 166 B split is not predicted by any header byte or bit.
_V0D_HEAD_SIZE = 50
_V0D_SIZES_BY_BODY_TYPE = {
    4: frozenset({50}),
    6: frozenset({153, 166, 179}),
    7: frozenset({248, 535, 576}),
}
_V0D_T6_ENTRY_BASE = 153     # type-6 13-byte entries start here (len > 153)
_V0D_T6_ENTRY_SIZE = 13
_V0D_T7_ENTRY_BASE = 248     # type-7 41-byte entries start here
_V0D_T7_ENTRY_SIZE = 41


@dataclass
class Diag0x1874:
    """LTE ML1 DL power/quality measurement (0x1874) — version=0x06 layout (SDX55)."""
    log_time: int
    version: int
    num_entries: int
    band_or_subtype: int    # u8 @ 5 (structural; a band/subtype candidate, uncited)
    cell_info: int
    freq_field: int         # u16 @ 9 (75-quantised measurement enum, NOT EARFCN)
    measurement_a: int      # u32 @ 12
    measurement_b: int      # u32 @ 16
    window_start: int       # u64 @ 231 (measurement-window START timestamp; <=48-bit timer)
    window_end: int         # u64 @ 239 (measurement-window END timestamp)
    body_hex: str | None    # optional event-gated body (bytes 20..230) when non-zero
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1874',
            'log_time': self.log_time,
            'version': self.version,
            'num_entries': self.num_entries,
            'band_or_subtype': self.band_or_subtype,
            'cell_info': self.cell_info,
            'freq_field': self.freq_field,
            'measurement_a': self.measurement_a,
            'measurement_b': self.measurement_b,
            'window_start': self.window_start,
            'window_end': self.window_end,
            'body_hex': self.body_hex,
            'payload_size': self.payload_size,
        }


@dataclass
class Diag0x1874V0c:
    """LTE ML1 DL power/quality measurement (0x1874) — version=0x0c layout (SDX62).

    Field offsets are corpus-locked (60K-record histogram across RM520N-GL +
    CFW-3212). window_start/window_end are VERIFIED measurement-window
    timestamps; the ×75-quantised measurement words' physical meaning is open.
    """
    log_time: int
    version: int
    header_filler: int      # u16 LE @ 1 (constant 0xffff across the corpus)
    band_or_subtype: int    # u8 @ 3
    entry_count: int        # u8 @ 4
    subtype_a: int          # u8 @ 7
    flags: int              # u8 @ 10
    subtype_b: int          # u8 @ 13
    rare_flag: int          # u8 @ 15
    freq_field: int         # u16 LE @ 22 (75-quantised measurement enum)
    measurement_a: int      # u32 LE @ 25 (u24 in practice)
    measurement_b: int      # u16 LE @ 30
    window_start: int       # u64 LE @ 34 (measurement-window START timestamp)
    window_end: int         # u64 LE @ 42 (measurement-window END timestamp)
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1874V0c',
            'log_time': self.log_time,
            'version': self.version,
            'header_filler': self.header_filler,
            'band_or_subtype': self.band_or_subtype,
            'entry_count': self.entry_count,
            'subtype_a': self.subtype_a,
            'flags': self.flags,
            'subtype_b': self.subtype_b,
            'rare_flag': self.rare_flag,
            'freq_field': self.freq_field,
            'measurement_a': self.measurement_a,
            'measurement_b': self.measurement_b,
            'window_start': self.window_start,
            'window_end': self.window_end,
            'payload_size': self.payload_size,
        }


@dataclass
class Diag0x1874V04:
    """LTE ML1 DL power/quality measurement (0x1874) — version=0x04 layout
    (SDX20 LM960 / SDX24 EG12-GT / MDM9x07 EG18-NA)."""
    log_time: int
    version: int
    header_counter: int     # u24 @ 1 (partial free-running counter)
    sub_count: int          # u8 @ 4
    valid_flag: int         # u8 @ 5
    cell_info: int          # u8 @ 6
    freq_field: int         # u16 LE @ 9 (75-quantised measurement enum)
    measurement_a: int      # u32 LE @ 12 (u24)
    measurement_b: int      # u32 LE @ 16 (u24)
    measurement_c: int      # u32 LE @ 20 (u24)
    measurement_d: int      # u32 LE @ 24 (u24)
    measurement_e: int      # u32 LE @ 28 (u24)
    word_32: int            # u32 LE @ 32 (high-entropy counter-ish; semantics open, ~69% monotone)
    window_start: int       # u64 LE @ 36 (measurement-window START timestamp; <=48-bit timer)
    window_end: int         # u64 LE @ 44 (measurement-window END timestamp)
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1874V04',
            'log_time': self.log_time,
            'version': self.version,
            'header_counter': self.header_counter,
            'sub_count': self.sub_count,
            'valid_flag': self.valid_flag,
            'cell_info': self.cell_info,
            'freq_field': self.freq_field,
            'measurement_a': self.measurement_a,
            'measurement_b': self.measurement_b,
            'measurement_c': self.measurement_c,
            'measurement_d': self.measurement_d,
            'measurement_e': self.measurement_e,
            'word_32': self.word_32,
            'window_start': self.window_start,
            'window_end': self.window_end,
            'payload_size': self.payload_size,
        }


@dataclass
class Diag0x1874V6b:
    """LTE ML1 DL power/quality measurement (0x1874) — version=0x6b layout
    (MDM9650 Sierra EM7511 / MC7411).

    Only offsets 0..3 and 52..55 carry data in the corpus (idle / stationary
    captures); bytes 4..51 are a validated-zero measurement region whose
    active-mode layout needs a connected-mode capture to decode.
    ``reserved_all_zero`` records whether that region was in fact empty."""
    log_time: int
    version: int
    counter_a: int          # u24 @ 1 (partial free-running counter)
    field_b: int            # u32 @ 52
    reserved_all_zero: bool  # bytes 4..51 all zero (True across the corpus)
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1874V6b',
            'log_time': self.log_time,
            'version': self.version,
            'counter_a': self.counter_a,
            'field_b': self.field_b,
            'reserved_all_zero': self.reserved_all_zero,
            'payload_size': self.payload_size,
        }


@dataclass
class Diag0x1874V05:
    """LTE ML1 / MCPM session-power log (0x1874) — version=0x05 layout
    (SDX24 Quectel EM120R-GL / EM160R-GL).

    The v=0x04 layout plus a 24-byte region (bytes 36..59) inserted before
    the window pair. window_start/window_end are GROUNDED against co-temporal
    MCPM MCVS-request completion prints (see the v0x05 F3-VERDICT)."""
    log_time: int
    version: int
    header_counter: int     # u24 @ 1 (partial free-running counter)
    sub_count: int          # u8 @ 4 (always 4 in the corpus)
    flag_5: int             # u8 @ 5 ({0,1,2,3,6}; v0x04's same byte is {0,1})
    cell_info: int          # u8 @ 6 ({0x03,0x27,0x28,0x2a})
    freq_field: int         # u16 LE @ 9 (×75-quantised enum, NOT EARFCN)
    measurement_a: int      # u32 LE @ 12 (u24)
    measurement_b: int      # u32 LE @ 16 (u24)
    measurement_c: int      # u32 LE @ 20 (u24)
    measurement_d: int      # u32 LE @ 24 (u24)
    measurement_e: int      # u32 LE @ 28 (u24)
    aux_36: int             # u32 LE @ 36 (small enum; semantics open)
    aux_40: int             # u32 LE @ 40 (small enum {0,1,4,8}; semantics open)
    aux_44: int             # u32 LE @ 44 (byte 44 always 0; u24 value << 8)
    freq_field_2: int       # u16 LE @ 53 (×75 enum, same value set as freq_field)
    window_start: int       # u64 LE @ 60 (MCPM session-window START tick)
    window_end: int         # u64 LE @ 68 (MCPM session-window END tick)
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1874V05',
            'log_time': self.log_time,
            'version': self.version,
            'header_counter': self.header_counter,
            'sub_count': self.sub_count,
            'flag_5': self.flag_5,
            'cell_info': self.cell_info,
            'freq_field': self.freq_field,
            'measurement_a': self.measurement_a,
            'measurement_b': self.measurement_b,
            'measurement_c': self.measurement_c,
            'measurement_d': self.measurement_d,
            'measurement_e': self.measurement_e,
            'aux_36': self.aux_36,
            'aux_40': self.aux_40,
            'aux_44': self.aux_44,
            'freq_field_2': self.freq_field_2,
            'window_start': self.window_start,
            'window_end': self.window_end,
            'payload_size': self.payload_size,
        }


@dataclass
class Diag0x1874V11:
    """LTE ML1 / MCPM session-power log (0x1874) — version=0x11 layout
    (SDX72 Foxconn T99W640 / Dell DW5934e).

    A 58-byte head (the v=0x0c layout with its measurement words and window
    pair shifted +8) followed by a tail chosen by ``body_type`` (byte 41).
    Head fields are named; the tail's framing (sub-header, entry counts,
    entry boundaries) is decoded and count-validated, while the inner block
    bytes whose semantics are still open are preserved verbatim in
    ``tail_block_hex`` (same convention as v=0x06's ``body_hex``)."""
    log_time: int
    version: int
    header_filler: int      # u16 LE @ 1 (constant 0xffff — the v0x0c lineage signature)
    band_or_subtype: int    # u8 @ 3
    entry_count: int        # u8 @ 4 (4..7 for body_type 4, 1 for 6, 0 for 7)
    rare_flag: int          # u8 @ 20 ({0,3}; v0x0c's rare_flag value set)
    flag_22: int            # u8 @ 22 ({0,0x0c})
    subtype_a: int          # u8 @ 23 ({0,0x10,0x20,0x30,0x50}; v0x0c subtype_a set)
    field_26: int           # u8 @ 26 (small enum {0,1,2,3,5,6,0x0c})
    flag_27: int            # u8 @ 27 ({0,0x80})
    flag_28: int            # u8 @ 28 ({0,1})
    freq_field: int         # u16 LE @ 30 (×75 enum, NOT EARFCN; v0x0c @22 + 8)
    flag_37: int            # u8 @ 37 ({0,0x80})
    measurement_b: int      # u16 LE @ 38 (×75 enum; v0x0c @30 + 8)
    body_type: int          # u8 @ 41 (4 = head only, 6 = block+16B entries, 7 = block+24B entries)
    window_start: int       # u64 LE @ 42 (session-window START, QTimer ticks; v0x0c @34 + 8)
    window_end: int         # u64 LE @ 50 (session-window END)
    tail_sub_version: int | None   # type 6: u32 @ 58 (always 2)
    tail_block_mask: int | None    # type 6: u32 @ 62 (block-presence mask)
    tail_aux: list[int] | None     # type 6: u32 @ 66 / 70 / 74
    tail_entry_count: int | None   # type 6: u8 @ 78; type 7: u8 @ 131
    tail_entries: list[str] | None  # 16 B (type 6) / 24 B (type 7) entries, hex
    tail_block_hex: str | None     # unRE'd block bytes, verbatim when non-zero
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1874V11',
            'log_time': self.log_time,
            'version': self.version,
            'header_filler': self.header_filler,
            'band_or_subtype': self.band_or_subtype,
            'entry_count': self.entry_count,
            'rare_flag': self.rare_flag,
            'flag_22': self.flag_22,
            'subtype_a': self.subtype_a,
            'field_26': self.field_26,
            'flag_27': self.flag_27,
            'flag_28': self.flag_28,
            'freq_field': self.freq_field,
            'flag_37': self.flag_37,
            'measurement_b': self.measurement_b,
            'body_type': self.body_type,
            'window_start': self.window_start,
            'window_end': self.window_end,
            'tail_sub_version': self.tail_sub_version,
            'tail_block_mask': self.tail_block_mask,
            'tail_aux': self.tail_aux,
            'tail_entry_count': self.tail_entry_count,
            'tail_entries': self.tail_entries,
            'tail_block_hex': self.tail_block_hex,
            'payload_size': self.payload_size,
        }


@dataclass
class Diag0x1874V0d:
    """LTE ML1 / MCPM session-power log (0x1874) — version=0x0d layout
    (SDX62 Orbic R562L5, MeiG ODM).

    The v=0x0c 50-byte head (same offsets) followed by a tail chosen by
    ``body_type`` (byte 33), the v=0x11 scheme. Type-6 and type-7 windows are
    DIRECTLY bound to MCPM calls on the QTimer clock (see the v0x0d
    F3-VERDICT). Inner tail bytes whose semantics are open are preserved
    verbatim in ``tail_block_hex`` / ``tail_entries``."""
    log_time: int
    version: int
    header_filler: int      # u16 LE @ 1 (constant 0xffff — the v0x0c lineage signature)
    band_or_subtype: int    # u8 @ 3
    entry_count: int        # u8 @ 4 (4..7 for body_type 4, 1 for 6, 0 for 7)
    flag_6: int             # u8 @ 6 ({0,0x0c})
    subtype_a: int          # u8 @ 7
    flags: int              # u8 @ 10
    flag_11: int            # u8 @ 11 ({0,1})
    subtype_b: int          # u8 @ 13
    rare_flag: int          # u8 @ 15
    freq_field: int         # u16 LE @ 22 (×75 enum, NOT EARFCN; 0 on body_type 4)
    measurement_a: int      # u32 LE @ 25 (u24; constant 0x1ffd34 in practice)
    measurement_b: int      # u16 LE @ 30 (×75 enum)
    body_type: int          # u8 @ 33 (4 = head only, 6 = block+13B entries, 7 = block+41B entries)
    window_start: int       # u64 LE @ 34 (MCPM session-window START, QTimer ticks)
    window_end: int         # u64 LE @ 42 (MCPM session-window END)
    tail_sub_version: int | None   # type 6: u8 @ 50 (always 2)
    tail_block_mask: int | None    # type 6: u24 LE @ 51
    tail_entry_count: int | None   # type 6: u32 @ 149; type 7: u8 @ 176
    tail_entries: list[str] | None  # 13 B (type 6) / 41 B (type 7) entries, hex
    tail_block_hex: str | None     # unRE'd block bytes, verbatim when non-zero
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x1874V0d',
            'log_time': self.log_time,
            'version': self.version,
            'header_filler': self.header_filler,
            'band_or_subtype': self.band_or_subtype,
            'entry_count': self.entry_count,
            'flag_6': self.flag_6,
            'subtype_a': self.subtype_a,
            'flags': self.flags,
            'flag_11': self.flag_11,
            'subtype_b': self.subtype_b,
            'rare_flag': self.rare_flag,
            'freq_field': self.freq_field,
            'measurement_a': self.measurement_a,
            'measurement_b': self.measurement_b,
            'body_type': self.body_type,
            'window_start': self.window_start,
            'window_end': self.window_end,
            'tail_sub_version': self.tail_sub_version,
            'tail_block_mask': self.tail_block_mask,
            'tail_entry_count': self.tail_entry_count,
            'tail_entries': self.tail_entries,
            'tail_block_hex': self.tail_block_hex,
            'payload_size': self.payload_size,
        }


def _parse_v6(log_time: int, data: bytes) -> Diag0x1874 | None:
    # Per-version consequence check: every v=0x06 record observed
    # (4.1M+ across SDX55 vendors) is exactly 247 bytes.
    if len(data) != _V6_PAYLOAD_SIZE:
        return None
    # Optional event-gated body (bytes 20..230): preserve verbatim when any
    # byte is non-zero (populated in ~9% of records; bytes 84..230 always
    # zero in the corpus but read the full span to stay future-proof).
    body = data[20:231]
    body_hex = body.hex() if any(body) else None
    return Diag0x1874(
        log_time=log_time,
        version=data[0],
        num_entries=data[4],
        band_or_subtype=data[5],
        cell_info=data[6],
        freq_field=unpack_from('<H', data, 9)[0],
        measurement_a=unpack_from('<I', data, 12)[0],
        measurement_b=unpack_from('<I', data, 16)[0],
        window_start=unpack_from('<Q', data, 231)[0],
        window_end=unpack_from('<Q', data, 239)[0],
        body_hex=body_hex,
        payload_size=len(data),
    )


def _parse_v0c(log_time: int, data: bytes) -> Diag0x1874V0c | None:
    # Per-version consequence check: every v=0x0c record observed
    # (14.7M corpus-wide across SDX62 RM520N-GL + Casa CFW-3212) is 50 bytes.
    if len(data) != _V0C_PAYLOAD_SIZE:
        return None
    return Diag0x1874V0c(
        log_time=log_time,
        version=data[0],
        header_filler=unpack_from('<H', data, 1)[0],
        band_or_subtype=data[3],
        entry_count=data[4],
        subtype_a=data[7],
        flags=data[10],
        subtype_b=data[13],
        rare_flag=data[15],
        freq_field=unpack_from('<H', data, 22)[0],
        measurement_a=unpack_from('<I', data, 25)[0],
        measurement_b=unpack_from('<H', data, 30)[0],
        window_start=unpack_from('<Q', data, 34)[0],
        window_end=unpack_from('<Q', data, 42)[0],
        payload_size=len(data),
    )


def _parse_v04(log_time: int, data: bytes) -> Diag0x1874V04 | None:
    # Per-version consequence check: every v=0x04 record observed
    # (67K across SDX20 LM960 / SDX24 EG12-GT / MDM9x07 EG18-NA) is 52 bytes.
    if len(data) != _V04_PAYLOAD_SIZE:
        return None
    return Diag0x1874V04(
        log_time=log_time,
        version=data[0],
        header_counter=data[1] | (data[2] << 8) | (data[3] << 16),
        sub_count=data[4],
        valid_flag=data[5],
        cell_info=data[6],
        freq_field=unpack_from('<H', data, 9)[0],
        measurement_a=unpack_from('<I', data, 12)[0],
        measurement_b=unpack_from('<I', data, 16)[0],
        measurement_c=unpack_from('<I', data, 20)[0],
        measurement_d=unpack_from('<I', data, 24)[0],
        measurement_e=unpack_from('<I', data, 28)[0],
        word_32=unpack_from('<I', data, 32)[0],
        window_start=unpack_from('<Q', data, 36)[0],
        window_end=unpack_from('<Q', data, 44)[0],
        payload_size=len(data),
    )


def _parse_v6b(log_time: int, data: bytes) -> Diag0x1874V6b | None:
    # Per-version consequence check: every v=0x6b record observed
    # (85K across MDM9650 Sierra EM7511 / MC7411) is 56 bytes.
    if len(data) != _V6B_PAYLOAD_SIZE:
        return None
    return Diag0x1874V6b(
        log_time=log_time,
        version=data[0],
        counter_a=data[1] | (data[2] << 8) | (data[3] << 16),
        field_b=unpack_from('<I', data, 52)[0],
        reserved_all_zero=not any(data[4:52]),
        payload_size=len(data),
    )


def _parse_v05(log_time: int, data: bytes) -> Diag0x1874V05 | None:
    # Per-version consequence check: every v=0x05 record observed (7,611
    # across SDX24 EM120R-GL + EM160R-GL, 3 firmware builds) is 76 bytes.
    if len(data) != _V05_PAYLOAD_SIZE:
        return None
    return Diag0x1874V05(
        log_time=log_time,
        version=data[0],
        header_counter=data[1] | (data[2] << 8) | (data[3] << 16),
        sub_count=data[4],
        flag_5=data[5],
        cell_info=data[6],
        freq_field=unpack_from('<H', data, 9)[0],
        measurement_a=unpack_from('<I', data, 12)[0],
        measurement_b=unpack_from('<I', data, 16)[0],
        measurement_c=unpack_from('<I', data, 20)[0],
        measurement_d=unpack_from('<I', data, 24)[0],
        measurement_e=unpack_from('<I', data, 28)[0],
        aux_36=unpack_from('<I', data, 36)[0],
        aux_40=unpack_from('<I', data, 40)[0],
        aux_44=unpack_from('<I', data, 44)[0],
        freq_field_2=unpack_from('<H', data, 53)[0],
        window_start=unpack_from('<Q', data, 60)[0],
        window_end=unpack_from('<Q', data, 68)[0],
        payload_size=len(data),
    )


def _parse_v11(log_time: int, data: bytes) -> Diag0x1874V11 | None:
    n = len(data)
    if n < _V11_HEAD_SIZE:
        return None
    # Lineage signature: bytes 1..2 are 0xffff in every v=0x11 record (as in
    # v=0x0c). A stray 0x11 byte0 from a mis-frame does not carry it.
    if data[1] != 0xFF or data[2] != 0xFF:
        return None
    body_type = data[41]
    sizes = _V11_SIZES_BY_BODY_TYPE.get(body_type)
    if sizes is None or n not in sizes:
        return None
    tail_sub_version = tail_block_mask = tail_entry_count = None
    tail_aux: list[int] | None = None
    tail_entries: list[str] | None = None
    tail_block_hex: str | None = None
    if body_type == 6:
        tail_sub_version = unpack_from('<I', data, 58)[0]
        if tail_sub_version != 2:
            return None
        tail_block_mask = unpack_from('<I', data, 62)[0]
        tail_aux = [unpack_from('<I', data, o)[0] for o in (66, 70, 74)]
        tail_entry_count = data[78]
        block = data[82:min(n, _V11_T6_ENTRY_BASE)]
        if n > _V11_T6_ENTRY_BASE:
            # Count law (corpus-exact for every len >= 174): one 16-byte entry
            # per tail_entry_count. A mismatch is truncation or a mis-frame.
            if tail_entry_count * _V11_T6_ENTRY_SIZE != n - _V11_T6_ENTRY_BASE:
                return None
            tail_entries = [
                data[o:o + _V11_T6_ENTRY_SIZE].hex()
                for o in range(_V11_T6_ENTRY_BASE, n, _V11_T6_ENTRY_SIZE)
            ]
        tail_block_hex = block.hex() if any(block) else None
    elif body_type == 7:
        # Count law (corpus-exact for 271/295/319/343): u8 @ 131 is the number
        # of 24-byte entries appended after the 213-byte block.
        tail_entry_count = data[131]
        if tail_entry_count * _V11_T7_ENTRY_SIZE != n - _V11_T7_ENTRY_BASE:
            return None
        block = data[_V11_HEAD_SIZE:_V11_T7_ENTRY_BASE]
        tail_block_hex = block.hex() if any(block) else None
        tail_entries = [
            data[o:o + _V11_T7_ENTRY_SIZE].hex()
            for o in range(_V11_T7_ENTRY_BASE, n, _V11_T7_ENTRY_SIZE)
        ]
    return Diag0x1874V11(
        log_time=log_time,
        version=data[0],
        header_filler=unpack_from('<H', data, 1)[0],
        band_or_subtype=data[3],
        entry_count=data[4],
        rare_flag=data[20],
        flag_22=data[22],
        subtype_a=data[23],
        field_26=data[26],
        flag_27=data[27],
        flag_28=data[28],
        freq_field=unpack_from('<H', data, 30)[0],
        flag_37=data[37],
        measurement_b=unpack_from('<H', data, 38)[0],
        body_type=body_type,
        window_start=unpack_from('<Q', data, 42)[0],
        window_end=unpack_from('<Q', data, 50)[0],
        tail_sub_version=tail_sub_version,
        tail_block_mask=tail_block_mask,
        tail_aux=tail_aux,
        tail_entry_count=tail_entry_count,
        tail_entries=tail_entries,
        tail_block_hex=tail_block_hex,
        payload_size=n,
    )


def _parse_v0d(log_time: int, data: bytes) -> Diag0x1874V0d | None:
    n = len(data)
    if n < _V0D_HEAD_SIZE:
        return None
    # Lineage signature: bytes 1..2 are 0xffff in every v=0x0d record (as in
    # v=0x0c / v=0x11). A stray 0x0d byte0 from a mis-frame does not carry it.
    if data[1] != 0xFF or data[2] != 0xFF:
        return None
    body_type = data[33]
    sizes = _V0D_SIZES_BY_BODY_TYPE.get(body_type)
    if sizes is None or n not in sizes:
        return None
    tail_sub_version = tail_block_mask = tail_entry_count = None
    tail_entries: list[str] | None = None
    tail_block_hex: str | None = None
    if body_type == 6:
        tail_sub_version = data[50]
        if tail_sub_version != 2:
            return None
        tail_block_mask = data[51] | (data[52] << 8) | (data[53] << 16)
        tail_entry_count = unpack_from('<I', data, 149)[0]
        if n > _V0D_T6_ENTRY_BASE:
            # Count law (corpus-exact for 166/179): one 13-byte entry per
            # tail_entry_count. 153 B carries no entries (count still reads 1).
            if tail_entry_count * _V0D_T6_ENTRY_SIZE != n - _V0D_T6_ENTRY_BASE:
                return None
            tail_entries = [
                data[o:o + _V0D_T6_ENTRY_SIZE].hex()
                for o in range(_V0D_T6_ENTRY_BASE, n, _V0D_T6_ENTRY_SIZE)
            ]
        block = data[54:149]
        tail_block_hex = block.hex() if any(block) else None
    elif body_type == 7:
        # Count law (corpus-exact for 248/535/576): u8 @ 176 is the number of
        # 41-byte entries appended after the 198-byte block.
        tail_entry_count = data[176]
        if tail_entry_count * _V0D_T7_ENTRY_SIZE != n - _V0D_T7_ENTRY_BASE:
            return None
        block = data[_V0D_HEAD_SIZE:_V0D_T7_ENTRY_BASE]
        tail_block_hex = block.hex() if any(block) else None
        tail_entries = [
            data[o:o + _V0D_T7_ENTRY_SIZE].hex()
            for o in range(_V0D_T7_ENTRY_BASE, n, _V0D_T7_ENTRY_SIZE)
        ]
    return Diag0x1874V0d(
        log_time=log_time,
        version=data[0],
        header_filler=unpack_from('<H', data, 1)[0],
        band_or_subtype=data[3],
        entry_count=data[4],
        flag_6=data[6],
        subtype_a=data[7],
        flags=data[10],
        flag_11=data[11],
        subtype_b=data[13],
        rare_flag=data[15],
        freq_field=unpack_from('<H', data, 22)[0],
        measurement_a=unpack_from('<I', data, 25)[0],
        measurement_b=unpack_from('<H', data, 30)[0],
        body_type=body_type,
        window_start=unpack_from('<Q', data, 34)[0],
        window_end=unpack_from('<Q', data, 42)[0],
        tail_sub_version=tail_sub_version,
        tail_block_mask=tail_block_mask,
        tail_entry_count=tail_entry_count,
        tail_entries=tail_entries,
        tail_block_hex=tail_block_hex,
        payload_size=n,
    )


@register(
    0x1874,
    name="0x1874",
    description=(
        "LTE ML1 DL power/quality measurement (0x1874) — version-dispatched. "
        "Decodes version=0x04 (52B), 0x05 (SDX24, 76B), 0x06 (SDX55, 247B), "
        "0x0c (SDX62, 50B), 0x0d (SDX62 R562L5, 50B head + body_type tail), "
        "0x11 (SDX72, 58B head + body_type tail) and 0x6b (MDM9650, 56B); "
        "refuses unknown versions pending RE."
    ),
    version=14,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Version-dispatched decode (byte 0 is the discriminator; size is a "
        "per-version consequence-check) of seven attested versions: 0x04 (52B, "
        "SDX20/SDX24/MDM9x07), 0x05 (76B, SDX24 EM120R-GL/EM160R-GL), 0x06 "
        "(247B, SDX55), 0x0c (50B, SDX62), 0x0d (SDX62 Orbic R562L5, 50B head + "
        "body_type tail), 0x11 (SDX72 T99W640, 58B head + body_type tail) and "
        "0x6b (56B, MDM9650). Clean-room RE from per-byte histograms, offsets "
        "cross-validated across >=2 chipset generations per version; every "
        "data-carrying byte is a named field. Identity: an MCPM session-power "
        "log (LTE ML1 is the requesting subsystem). On v0x04 the mcpm.c "
        "MCPM_Process_Req begin/end times match window_start/window_end hi u32 "
        "at conf 1.00 (1697/1697); v0x05 windows bind MCPM MCVS-request "
        "completion prints 264/264 (controls 0/497); v0x0d windows bind "
        "rf_nr5g_sync.c MCPM_CLK_PROC_UPDATE 10/12 (chance 0.02 %) and LTE "
        "wakeup API=0 -> CDRX_WAKEUP_CNF 20/42; v0x6b captures carry 30,159 "
        "lte_ml1_mcpm.c prints; v0x0c and v0x11 are MCPM-consistent but their "
        "captures mask-gate mcpm F3 off. The window pair is a free-running "
        "<=48-bit timer (monotone, end >= start). On every version checked "
        "against a serving-cell reference, freq_field is a ×75-quantised enum, "
        "not EARFCN, and the measurement_* words are not RSRP/RSRQ in dBm "
        "(constant or few-valued under a 58 dB RSRP swing). v0x11 and v0x0d "
        "tails are framed and count-validated against attested sizes; their "
        "inner fields, and the physical unit of the ×75 words, remain open. "
        "Byte0 strays 0x00/0x71/0x7c/0x9d (one stress-test capture) are "
        "refused."
    ),
    source_url="",
    # v=0x0c (the RM520N-GL primary / recipe target) is byte-complete: the
    # primary layout is 14/14 structurally. The semantic meaning of the
    # ×75-quantised measurement words remains open.
    fields_parsed=14,
    fields_identified=14,
    issues=(),
    field_invariants={"version": {"enum": [0x04, 0x05, 0x06, 0x0C, 0x0D, 0x11, 0x6B]}},
)
def parse_0x1874(
    log_time: int, data: bytes
) -> (Diag0x1874 | Diag0x1874V0c | Diag0x1874V0d | Diag0x1874V04
      | Diag0x1874V05 | Diag0x1874V11 | Diag0x1874V6b | None):
    if not data:
        return None
    # Layer-1 version gate: dispatch on byte[0]; any version
    # not enumerated below is refused (None) rather than mis-decoded through
    # a foreign layout. Size is a per-version consequence-check inside each
    # branch — NOT the discriminator (size invariance != format invariance).
    version = data[0]
    if version == 0x06:
        return _parse_v6(log_time, data)
    if version == 0x0C:
        return _parse_v0c(log_time, data)
    if version == 0x04:
        return _parse_v04(log_time, data)
    if version == 0x6B:
        return _parse_v6b(log_time, data)
    if version == 0x05:
        return _parse_v05(log_time, data)
    if version == 0x11:
        return _parse_v11(log_time, data)
    if version == 0x0D:
        return _parse_v0d(log_time, data)
    return None
