"""0x18F8 — LOG_MCS_VBATT_INFO: VBATT (battery-voltage power limiting) band/threshold log.

SUBSYSTEM: **VBATT** (``vbatt_core.c`` / ``vbatt_efs.c``, the MCS battery-voltage
Tx-power limiter that ``lmtsmgr`` consults per tech/band) — **F3-grounded**.
Every record is co-emitted (≤ 0.1 ms) with the VBATT module's own prints, and
its u16 @[6:8] EQUALS the band argument of those prints, record for record:

  * v0x01 (EM7565 / LM960, Sierra/Telit SDX20-class): ``vbatt_core.c:458 "VBATT:
    Record not found for new band %d for tech %d"`` arg0 = 178 ↔ [6:8] = 0x00B2;
    ``new band 4294967295`` (-1) ↔ [6:8] = 0xFFFF. On SC200E each record is
    co-emitted with ``vbatt_core.c:644 "ADC read completed … new level is %d"``.
  * v0x02-B (RM520N-GL SDX62): ``vbatt_core.c:609 "VBATT New Tech:%d Band:%d …"``
    arg1 (New Band) = 191 / 196 / 216 ↔ [6:8]; ``vbatt_core.c:882 "VBATT: Band %d
    stage %d"`` repeats it. [16:18] = 0x0A8C = 2700 ↔ ``"Set threshold %d to %d.
    EFS value: 2700"``.

A capture can contain records with no VBATT print in their window, so a
single capture is not enough to rule the co-emission in or out. The name
``LOG_MCS_VBATT_INFO`` is corroborated, and the code is NOT a GNSS log.
``measurement`` keeps its name for compatibility but IS the VBATT band id
(an internal RF band enum, not a 3GPP band number) and is also exposed as
``vbatt_band`` (None when 0xFFFF = no band).

Two versions coexist in the corpus, partitioned by byte[0] (the DIAG
version byte). The corpus is **~97% v0x02**; v0x01 is the residual ~3%.

--- v0x01 (20 B fixed) — EM7511 / MC7411 (MDM9650) -------------------------
Emitted during LTE mode transitions. Layout from 12 EM7511 records.
  [0]     u8   version    = 0x01 (const; the DIAG version byte)
  [1]     u8   type_b     = 0x02 (const)
  [2:6]   u32  sentinel_a = 0xFFFFFFFF (const)
  [6:8]   u16  measurement — valid range 121-168; 0xFFFF = not available
  [8:10]  u16  sentinel_b  = 0xFFFF (const)
  [10:12] u16  reserved_0  = 0x0000 (const)
  [12:14] u16  sentinel_c  = 0xFFFE (const; literal bytes fe ff)
  [14]    u8   reserved_1  = 0x00 (const)
  [15]    u8   const_7d    = 0x7D (const; 125 decimal)
  [16:20] u32  sentinel_d  — NOT a constant: 0xFFFFFFFF where
                VBATT logs "Record for band %d not found" (no EFS threshold
                record: EM7511/EM7565/LM960/EM120R/FM101), but 0x00000000 and
                other unrelated values on SC200E (8 of 18 records 0, the rest
                varied). The v0x02-B twin of this slot holds the EFS threshold
                (2700), so this reads as the threshold slot, unfilled when no
                record exists. Exposed raw; not pinned as an invariant.
[6:8] is the VBATT band (F3-grounded above; 0xFFFF = no band).

--- v0x02 — RM520N-GL (SDX62) + EM9291 (SDX65) ----------------------------
A DISTINCT dual-shape format, discriminated by byte[1] (``record_type``). Each
mode-transition event emits a **pair** — one 72 B record (record_type=0x01)
and one 20 B record (record_type=0x02); the corpus counts the two shapes in
near-lockstep. The layouts are **byte-identical across SDX62 and SDX65**
(two chipset generations).

  v0x02-A (72 B, record_type=0x01): a firmware-static capability/config table —
    (a 48 B compact form also occurs: the same blocks minus the 8 zero bytes
    between IDs and values) —
    every one of the 72 bytes is invariant across both chipset gens. Structure:
    three blocks, each ``[4 sequential u16 IDs][zeros][2 u16 values]`` —
    IDs 200-203 / 190-193 / 180-183, values ~2400-3200. CANDIDATE: the VBATT
    per-band threshold table (the values sit in the mV range of the 2700 EFS
    threshold the 20 B twin carries; no F3 print enumerates the table, so it
    stays raw as ``table_raw``).

  v0x02-B (20 B, record_type=0x02): richer than v0x01 — byte[2] is a real
    per-record value (30-36 on SDX62, 57-61 on SDX65 — firmware-scaled) where
    v0x01 carries the 0xFF sentinel there. byte[3] varies (0x0b-0x10). The u16
    at [6:8] is the VBATT band (F3-grounded: = ``New Band`` of vbatt_core.c:609),
    the same field as v0x01's [6:8]. [16:18] u16 = the VBATT EFS threshold
    (2700 ↔ ``Set threshold … EFS value: 2700``), exposed as ``vbatt_threshold``.
    byte[2]/byte[3] are not labelled by any VBATT print (raw).

Version compliance: byte[0] is the version discriminant. Both v0x01 and
v0x02 are modelled; a future v0x03 (or a v0x02 sub-shape with an unknown
record_type) fails fast rather than being mis-decoded (the same size does
not imply the same format).

Log name: LOG_MCS_VBATT_INFO
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0x18F8:
    """0x18F8 v0x01 — 20B fixed, EM7511/MC7411 MDM9650, LTE mode transitions."""
    log_time: int
    version: int     # [0] const 0x01 — DIAG version byte
    type_b: int      # [1] const 0x02
    sentinel_a: int  # [2:6] const 0xFFFFFFFF
    measurement: int # [6:8] varying; 0xFFFF = not available
    sentinel_b: int  # [8:10] const 0xFFFF
    reserved_0: int  # [10:12] const 0x0000
    sentinel_c: int  # [12:14] const 0xFFFE
    reserved_1: int  # [14] const 0x00
    const_7d: int    # [15] const 0x7D (125)
    sentinel_d: int  # [16:20] threshold slot: 0xFFFFFFFF = no VBATT record (NOT const)

    @property
    def measurement_valid(self) -> bool:
        return self.measurement != 0xFFFF

    def to_dict(self) -> dict[str, Any]:
        # All fields are exposed so layer-2 check_invariants can audit the
        # sentinels (silent-mis-parse protection). Sentinels are constants in
        # the observed corpus; downstream consumers can ignore them, but
        # auditors need them visible.
        d: dict[str, Any] = {
            'type': 'Diag0x18F8',
            'log_time': self.log_time,
            'version': self.version,
            'type_b': self.type_b,
            'sentinel_a': self.sentinel_a,
            'measurement': self.measurement if self.measurement_valid else None,
            'measurement_valid': self.measurement_valid,
            # F3-grounded: [6:8] IS the VBATT band (vbatt_core.c).
            'vbatt_band': self.measurement if self.measurement_valid else None,
            'sentinel_b': self.sentinel_b,
            'reserved_0': self.reserved_0,
            'sentinel_c': self.sentinel_c,
            'reserved_1': self.reserved_1,
            'const_7d': self.const_7d,
            'sentinel_d': self.sentinel_d,
        }
        return d


@dataclass
class Diag0x18F8V2:
    """0x18F8 v0x02 — dual-shape, RM520N-GL (SDX62) + EM9291 (SDX65).

    ``record_type`` (byte[1]) selects the shape: 0x01 → 72 B static table
    (or its 48 B compact form, ``length == 48``), 0x02 → 20 B per-record status. Byte-identical across both chipset gens
    (cross-gen attested; see the module docstring).
    """
    log_time: int
    version: int          # [0] const 0x02 — DIAG version byte
    record_type: int      # [1] 0x01 (72B table) | 0x02 (20B status)
    length: int           # record length (72 or 20)
    # v0x02-B (20B) named fields — None on the 72B shape:
    field_2: int | None       # [2] per-record value (30-36 SDX62 / 57-61 SDX65)
    field_3: int | None       # [3] varies 0x0b-0x10
    measurement: int | None   # [6:8] u16 — the VBATT band (F3-grounded; = v0x01 [6:8])
    vbatt_threshold: int | None  # [16:18] u16 — VBATT EFS threshold (2700 ↔ F3)
    # v0x02-A (72B) static table — None on the 20B shape:
    table_raw: str | None     # [2:72] (or [2:48] compact) hex; firmware-static

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            'type': 'Diag0x18F8V2',
            'log_time': self.log_time,
            'version': self.version,
            'record_type': self.record_type,
            'length': self.length,
        }
        if self.record_type == 0x02:
            d['field_2'] = self.field_2
            d['field_3'] = self.field_3
            d['measurement'] = self.measurement
            d['vbatt_band'] = None if self.measurement == 0xFFFF else self.measurement
            d['vbatt_threshold'] = self.vbatt_threshold
        elif self.record_type == 0x01:
            d['table_raw'] = self.table_raw
        return d


# --- Validation notes --------------------------------------------------
# v0x01 (EM7511): 19/20 bytes are constants/sentinels and `measurement` is the
# lone variable field (range 121-216, 0xFFFF=N/A). `measurement` is the VBATT
# band (vbatt_core.c "new band %d" / "New Tech:%d Band:%d" equality, see the
# module docstring), so it is grounded in-capture. It is NOT a GNSS
# measurement and NOT a battery-voltage reading (the voltage is in
# vbatt_core.c "ADC read … new level is %d", not in this record).
#
# v0x01 is emitted by the Sierra EM7511 (MDM9650); RM520N-GL/EM9291 emit
# ONLY v0x02.

@register(
    0x18F8, domain=None,
    name="0x18F8",
    description="LOG_MCS_VBATT_INFO (0x18F8) — VBATT band/threshold log, v0x01 20B + v0x02 dual-shape, F3-grounded",
    version=5,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Clean-room RE. v0x01: 12 EM7511 MDM9650 records across airplane/SIM/"
        "reboot transitions, 19/20 bytes constant (sentinel_d [16:20] is not: "
        "0 / varied on SC200E, so it is not pinned). v0x02: dual-shape (72B, "
        "or a 48 B compact form, record_type=0x01 static table + 20B "
        "record_type=0x02 status), byte-identical across RM520N-GL SDX62 + "
        "EM9291 SDX65. F3-grounded subsystem = VBATT: every record co-emits "
        "with vbatt_core.c prints and u16 [6:8] equals their band argument "
        "(v0x01 'new band %d', v0x02 'New Tech:%d Band:%d'), exposed as "
        "vbatt_band; v0x02-B [16:18] = VBATT EFS threshold (2700), exposed as "
        "vbatt_threshold. Not a GNSS log; domain left unset."
    ),
    issues=(),
    fields_identified=15,
    fields_parsed=15,
    field_invariants={
        # Layer-2 drift detection. version is the shared discriminant across
        # both modelled layouts. The remaining v0x01 sentinels and the v0x02
        # discriminators are named per-layout; check_invariants() skips any
        # invariant whose field is absent from a given record's to_dict(),
        # so v0x01 and v0x02 invariants coexist harmlessly in one dict —
        # each fires only on records of its own version.
        #
        # ``measurement`` (= VBATT band) and ``field_2``/``field_3`` (v0x02) are the
        # varying fields and are deliberately NOT enumerated (too few
        # distinct values observed to pin).
        # byte[0]=version, gated at layer-1 (parser body) too.
        "version":       {"enum": [0x01, 0x02]},
        # --- v0x01 constants (skipped for v0x02 records) ---
        "type_b":     {"enum": [0x02]},
        "sentinel_a": {"enum": [0xFFFFFFFF]},
        "sentinel_b": {"enum": [0xFFFF]},
        "reserved_0": {"enum": [0x0000]},
        "sentinel_c": {"enum": [0xFFFE]},
        "reserved_1": {"enum": [0x00]},
        "const_7d":   {"enum": [0x7D]},
        # sentinel_d [16:20] deliberately NOT pinned: 0xFFFFFFFF where VBATT
        # has no threshold record, but 0 / varied on SC200E — it is the
        # threshold slot (v0x02-B carries 2700 there), not a sentinel.
        # --- v0x02 discriminator (skipped for v0x01 records) ---
        "record_type":   {"enum": [0x01, 0x02]},
    },
)
def parse_0x18f8(log_time: int, data: bytes) -> Diag0x18F8 | Diag0x18F8V2 | None:
    if len(data) < 2:
        return None
    # First-byte version gate (Layer-1). Only the two known versions are
    # modelled; a future v0x03 (or unknown) fails fast rather than being
    # mis-decoded. Explicit `data[0] not in (...)` form for the version-gate
    # ratchet audit (test_parser_version_gate_ratchet).
    if data[0] not in (0x01, 0x02):
        return None
    version = data[0]
    if version == 0x01:
        if len(data) < 20:
            return None
        return Diag0x18F8(
            log_time=log_time,
            version=data[0],
            type_b=data[1],
            sentinel_a=unpack_from('<I', data, 2)[0],
            measurement=unpack_from('<H', data, 6)[0],
            sentinel_b=unpack_from('<H', data, 8)[0],
            reserved_0=unpack_from('<H', data, 10)[0],
            sentinel_c=unpack_from('<H', data, 12)[0],
            reserved_1=data[14],
            const_7d=data[15],
            sentinel_d=unpack_from('<I', data, 16)[0],
        )
    if version == 0x02:
        record_type = data[1]
        if record_type == 0x01:
            # 72B static table (cross-gen-identical). Preserve the body.
            # A 48 B COMPACT form of the same table is attested —
            # the identical three ``[4 u16 IDs][2 u16 values][00 00]`` blocks
            # without the 8 zero bytes between IDs and values (3 x 8 = 24 B
            # shorter). Discriminated from a truncated 72 B record by the
            # non-zero first value at [14:16] (zero padding in the 72 B form).

            if len(data) >= 72:
                body_end = 72
            elif len(data) == 48 and data[14:16] != b'\x00\x00':
                body_end = 48
            else:
                return None
            return Diag0x18F8V2(
                log_time=log_time,
                version=version,
                record_type=record_type,
                length=len(data),
                field_2=None, field_3=None, measurement=None,
                vbatt_threshold=None,
                table_raw=data[2:body_end].hex(),
            )
        if record_type == 0x02:
            # 20B per-record status.
            if len(data) < 20:
                return None
            return Diag0x18F8V2(
                log_time=log_time,
                version=version,
                record_type=record_type,
                length=len(data),
                field_2=data[2],
                field_3=data[3],
                measurement=unpack_from('<H', data, 6)[0],
                vbatt_threshold=unpack_from('<H', data, 16)[0],
                table_raw=None,
            )
        # Unknown v0x02 sub-shape — fail fast (do not mis-decode).
        return None
    return None
