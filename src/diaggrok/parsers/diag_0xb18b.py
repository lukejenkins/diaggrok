"""0xB18B — LTE ML1 sleep (legacy `LteMl1B18B`).

Log name **LOG_LTE_ML1_SLEEP** (LTE ML1 sleep/wake statistics).

## The EARFCN offset is variant-dependent

LM960A18 DIAG×AT correlation places `earfcn` at u32@4. Raw-byte verification
across 5 modems / 3 chipset gens shows that holds for the 66/68 B shapes but
**NOT for the 72 B shape**, where
offset-4 is a varying counter and the real EARFCN sits at **u32@8**:

    (version, size)   gen           earfcn offset   attested on
    (0x01, 60)        MDM9200       u16@4 (+pci@6)  mc7700 (SWI9200X)
    (0x30, 66)        SDX62         u32@4           rm520ngl, em9291, cfw3212
    (0x20, 68)        MDM9607/SDX20 u32@4           lm960, eg25g, mc7411
    (0x20, 72)        SDX55         u32@8           rm500q, fn980m, sim8202g, em9190

## The v0x01 (60 B) MDM9200 shape — a 16-bit EARFCN + serving PCI

The Sierra MC7700 (SWI9200X = MDM9200) emits a distinct **60 B / v0x01** shape
the modern u32-EARFCN logic mis-reads (u32@4 = 0x01d9087f = 31,001,727, not a
channel). This gen packs a **16-bit** EARFCN at u16@4 and the **serving PCI** at
u16@6. The whole v0x01 corpus (655 records / 8 captures / 3 firmwares) is one
stationary camped cell, so u16@4 = 2175 (Band 4) and u16@6 = 473 are constant.

Grounded **in-capture** (MDM9200 emits **no F3** — 0x79/0x92/0x99 absent
corpus-wide — so this is a cross-code, not an F3, verdict): in the same MC7700
session, 0xB0C0 (LTE RRC OTA) and 0xB193 (LTE ML1 serving-cell meas)
independently report **EARFCN 2175 / PCI 473**, matching this shape's u16@4 /
u16@6 exactly. `pci` is single-cell-grounded (no multi-cell corpus yet), so a
pci range=(0,503) invariant guards it but a multi-cell confirmation is deferred.

Concretely: a rm500q 72 B record reads `u32@4 = 0xf4856100` (4.1 G — a
counter, not a channel) while `u32@8 = 66786` (Band 66). fn980m 72 B reads
`u32@8 = 5330/9260` (Bands 13/5). Search-mode 72 B records (e.g. LV55) are
all zeros at both offsets, so they cannot distinguish the two. The parser
dispatches the EARFCN offset per (version, size); the `earfcn` to_dict key is
the same for every shape. A payload shorter than an attested shape is
truncated and returns None; a longer unknown shape falls back to a u32@4
read.

Other structure is not encoded: `byte[1]` is the counter's low byte on
72 B records (not an invariant 0x00); `sub_id` (u16@2) varies by **modem/
firmware**, not by (version,size) — rm500q 72 B = 0x00ec but fn980m 72 B =
0x00de — so it is surfaced raw, not asserted. The live counter region
[8:38], reserved block, and tail config decode stay deferred pending a
DIAG×AT-correlated capture (sleep-statistic field naming).

`to_dict()` emits an `earfcn` key (never the generic `config_word`), so
consumers keyed on `earfcn` keep working.

Log name: LTE ML1 Sleep
Also known as: LOG_LTE_ML1_SLEEP
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.registry import register


# (version, payload_size) -> byte offset of the serving-cell EARFCN u32.
# Verified at the raw-byte level across 5 modems / 3 chipset gens.
_EARFCN_OFFSET_BY_SHAPE = {
    (0x30, 66): 4,   # SDX62 (rm520ngl, em9291, cfw3212)
    (0x20, 68): 4,   # MDM9607/SDX20 (lm960, eg25g, mc7411)
    (0x20, 72): 8,   # SDX55 (rm500q, fn980m, sim8202g, em9190) — earfcn shifts to @8
}

# The v0x01 (60 B) MDM9200 shape (Sierra SWI9200X) carries a **16-bit** EARFCN
# at u16@4 and the serving PCI at u16@6 — NOT the u32 EARFCN of the modern
# shapes (a u32@4 read here is 0x01d9087f = 31,001,727, an invalid channel).
# Grounded in-capture on the MC7700 corpus: 0xB0C0 (LTE RRC OTA)
# and 0xB193 (LTE ML1 serving-cell meas) in the same session both independently
# report EARFCN 2175 / PCI 473, matching this shape's u16@4 / u16@6 exactly. The
# MDM9200 emits **no F3** (0x79/0x92/0x99 all absent corpus-wide), so this is an
# in-capture cross-code verdict, not an F3 one. See `_V01_SHAPE`.
_V01_SHAPE = (0x01, 60)          # (version, payload_size) — MDM9200 / SWI9200X
_V01_EARFCN_OFF = 4              # u16 little-endian
_V01_PCI_OFF = 6                 # u16 little-endian (serving PCI, single-cell-grounded)
_KNOWN_VERSIONS = (0x01, 0x20, 0x30)

# Attested payload sizes per version. A payload shorter than the largest
# attested size that is not itself an attested size is a truncated record ->
# None (registry warning). Longer payloads keep the legacy
# unstructured fallback.
_SIZES_BY_VERSION = {0x01: (60,), 0x20: (68, 72), 0x30: (66,)}


def _tail_density(data: bytes) -> float:
    """Fraction of non-zero bytes in the post-header body (bytes[2:]).

    A crude populated-vs-search-mode signal (a zeroed body is an idle/search
    record); shared by every (version, size) branch so the metric is uniform.
    """
    if len(data) <= 2:
        return 0.0
    nonzero = sum(1 for b in data[2:] if b != 0)
    return round(nonzero / max(len(data) - 2, 1), 2)


@dataclass
class Diag0xB18B:
    """0xB18B — LTE ML1 sleep (legacy `LteMl1B18B`).

    `earfcn` is the serving-cell EARFCN, read from a **variant-dependent**
    offset (u32@4 for the 66/68 B shapes, u32@8 for the 72 B SDX55 shape, and
    **u16@4 for the 60 B v0x01 MDM9200 shape**; see `_EARFCN_OFFSET_BY_SHAPE`
    and `_V01_SHAPE`). `pci` is the serving PCI, populated only for the v0x01
    shape (u16@6; `None` for the u32-EARFCN shapes, which do not carry it here).
    `sub_id` is the u16@2 sub-identifier (varies by modem/firmware — surfaced
    raw, not an invariant). `structured` is True when the (version, size) shape
    is recognised. Every record carries the `earfcn` to_dict key.
    """
    log_time: int
    version: int
    earfcn: int
    sub_id: int
    structured: bool
    data_density: float
    payload_size: int
    body_raw: bytes
    pci: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB18B",
            "log_time": self.log_time,
            "version": self.version,
            "earfcn": self.earfcn,
            "pci": self.pci,
            "sub_id": self.sub_id,
            "structured": self.structured,
            "data_density": self.data_density,
            "payload_size": self.payload_size,
            "body_raw": self.body_raw,
        }


# Emission hardware-validated on a connected EG25-G.

@register(
    0xB18B,
    name="0xB18B",
    wigle_direct=False,
    wigle_roles=("pci-earfcn-bridge",),
    description=(
        "0xB18B — LTE ML1 sleep (LOG_LTE_ML1_SLEEP); variant-dependent EARFCN "
        "offset (u32@4 for 66/68B, u32@8 for 72B SDX55); legacy LteMl1B18B. "
        "v0x01 (60B) MDM9200/SWI9200X shape: 16-bit "
        "earfcn@4 + serving pci@6, grounded in-capture on the MC7700 corpus "
        "(0xB0C0 RRC-OTA + 0xB193 ML1 both report EARFCN 2175 / PCI 473; MDM9200 "
        "emits no F3, so cross-code not F3). EM7565 (MDM9x50) v0x20 "
        "earfcn verified on CBRS B48"
    ),
    version=9,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "earfcn first attributed at u32@4 by LM960A18 DIAG×AT correlation. The "
        "EARFCN offset is variant-dependent — u32@4 for (0x30,66)/(0x20,68) but "
        "u32@8 for the (0x20,72) SDX55 shape (offset-4 there is a counter; "
        "verified RM500Q 66786/Band66, FN980 5330/Band13). The (0x01,60) "
        "MDM9200/SWI9200X shape reads a 16-bit earfcn@4 + serving pci@6 (a u32@4 "
        "read is 0x01d9087f, invalid), grounded in-capture on the Sierra MC7700 "
        "corpus (655 records / 8 captures / 3 firmware builds, all camped on one "
        "cell): 0xB0C0 (LTE RRC OTA) and 0xB193 (LTE ML1 serving-cell meas) in "
        "the same session independently report EARFCN 2175 / PCI 473, matching "
        "u16@4 / u16@6 exactly. MDM9200 emits no F3 (0x79/0x92/0x99 absent "
        "corpus-wide), so this is an in-capture cross-code verdict, not F3. "
        "Version enum {0x01,0x20,0x30} + earfcn range=(0,262143) + pci "
        "range=(0,503) invariants. pci is single-cell-grounded (the whole v0x01 "
        "corpus is one cell); sub_id@2 varies by modem; the live "
        "counter/reserved/tail decode is not done. A payload shorter than the "
        "version's largest attested size (v0x01 60 B, v0x20 68/72 B, v0x30 66 B) "
        "that is not itself an attested size returns None (registry warning); "
        "longer unknown shapes fall back to an unstructured u32@4 read."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=4,
    fields_parsed=4,
    field_invariants={
        "version": {"enum": [0x01, 0x20, 0x30]},
        "earfcn": {"range": (0, 262143)},
        "pci": {"range": (0, 503)},
    },
)
def parse_0xb18b(log_time: int, data: bytes) -> Diag0xB18B | None:
    if len(data) < 1:
        return None
    version = data[0]
    # Layer-1 version gate: reject off-enum versions up-front so a foreign
    # same-size payload can't route through structural decode and emit
    # plausible-but-garbage output. Backs the field_invariants[version] enum
    # at Layer-1.
    if version not in _KNOWN_VERSIONS:
        return None
    sizes = _SIZES_BY_VERSION[version]
    if len(data) < max(sizes) and len(data) not in sizes:
        return None
    sub_id = unpack_from('<H', data, 2)[0] if len(data) >= 4 else 0
    pci: int | None = None
    # v0x01 (60 B) MDM9200: 16-bit EARFCN@4 + serving PCI@6 (see _V01_SHAPE).
    if (version, len(data)) == _V01_SHAPE:
        earfcn = unpack_from('<H', data, _V01_EARFCN_OFF)[0]
        pci = unpack_from('<H', data, _V01_PCI_OFF)[0]
        structured = True
        density = _tail_density(data)
        return Diag0xB18B(
            log_time=log_time,
            version=version,
            earfcn=earfcn,
            sub_id=sub_id,
            structured=structured,
            data_density=density,
            payload_size=len(data),
            body_raw=data[1:],
            pci=pci,
        )
    offset = _EARFCN_OFFSET_BY_SHAPE.get((version, len(data)))
    structured = offset is not None
    if offset is not None and len(data) >= offset + 4:
        earfcn = unpack_from('<I', data, offset)[0]
    elif len(data) >= 8:
        # Unrecognised shape: best-effort legacy u32@4 read (the earfcn
        # range invariant flags it if offset-4 isn't a real channel here).
        earfcn = unpack_from('<I', data, 4)[0]
    elif len(data) >= 2:
        earfcn = data[1]
    else:
        earfcn = 0
    density = _tail_density(data)
    return Diag0xB18B(
        log_time=log_time,
        version=version,
        earfcn=earfcn,
        sub_id=sub_id,
        structured=structured,
        data_density=density,
        payload_size=len(data),
        body_raw=data[1:],
    )
