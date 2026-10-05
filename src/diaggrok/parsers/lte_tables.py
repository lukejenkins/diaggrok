# diaggrok-provenance: re
"""EARFCN-to-band and EARFCN-to-frequency lookup tables.

Derived from 3GPP TS 36.101 Table 5.7.3-1, checked row for row against the
DL columns of v20.0.0.
"""

# (low_earfcn, high_earfcn, band_number)
_EARFCN_BANDS = [
    (0, 599, 1), (600, 1199, 2), (1200, 1949, 3), (1950, 2399, 4),
    (2400, 2649, 5), (2650, 2749, 6), (2750, 3449, 7), (3450, 3799, 8),
    (3800, 4149, 9), (4150, 4749, 10), (4750, 4949, 11),
    (5010, 5179, 12), (5180, 5279, 13), (5280, 5379, 14),
    (5730, 5849, 17), (5850, 5999, 18), (6000, 6149, 19),
    (6150, 6449, 20), (6450, 6599, 21), (6600, 7399, 22),
    (7500, 7699, 23), (7700, 8039, 24), (8040, 8689, 25),
    (8690, 9039, 26), (9040, 9209, 27), (9210, 9659, 28),
    (9660, 9769, 29), (9770, 9869, 30), (9870, 9919, 31),
    (9920, 10359, 32), (36000, 36199, 33), (36200, 36349, 34),
    (36350, 36949, 35), (36950, 37549, 36), (37550, 37749, 37),
    (37750, 38249, 38), (38250, 38649, 39), (38650, 39649, 40),
    (39650, 41589, 41), (41590, 43589, 42), (43590, 45589, 43),
    (45590, 46589, 44), (46590, 46789, 45), (46790, 54539, 46),
    (54540, 55239, 47), (55240, 56739, 48), (56740, 58239, 49),
    (58240, 59089, 50), (59090, 59139, 51), (59140, 60139, 52),
    (60140, 60254, 53), (60255, 60304, 54),
    (65536, 66435, 65), (66436, 67335, 66), (67336, 67535, 67),
    (67536, 67835, 68), (67836, 68335, 69), (68336, 68585, 70),
    (68586, 68935, 71), (68936, 68985, 72), (68986, 69035, 73),
    (69036, 69465, 74), (69466, 70315, 75), (70316, 70365, 76),
    (70366, 70545, 85), (70546, 70595, 87), (70596, 70645, 88),
    (70646, 70655, 103), (70656, 70705, 106), (73386, 73485, 111),
]

# band -> (offset_earfcn, base_freq_mhz, step_mhz)
_FREQ_TABLE = {
    1: (0, 2110.0, 0.1),
    2: (600, 1930.0, 0.1),
    3: (1200, 1805.0, 0.1),
    4: (1950, 2110.0, 0.1),
    5: (2400, 869.0, 0.1),
    7: (2750, 2620.0, 0.1),
    8: (3450, 925.0, 0.1),
    12: (5010, 729.0, 0.1),
    13: (5180, 746.0, 0.1),
    14: (5280, 758.0, 0.1),
    17: (5730, 734.0, 0.1),
    25: (8040, 1930.0, 0.1),
    26: (8690, 859.0, 0.1),
    28: (9210, 758.0, 0.1),
    29: (9660, 717.0, 0.1),
    30: (9770, 2350.0, 0.1),
    38: (37750, 2570.0, 0.1),
    39: (38250, 1880.0, 0.1),
    40: (38650, 2300.0, 0.1),
    41: (39650, 2496.0, 0.1),
    66: (66436, 2110.0, 0.1),
    71: (68586, 617.0, 0.1),
}


def earfcn_to_band(earfcn: int) -> int:
    """Map LTE EARFCN to band number. Returns 0 for unknown."""
    for lo, hi, band in _EARFCN_BANDS:
        if lo <= earfcn <= hi:
            return band
    return 0


def earfcn_to_freq_mhz(earfcn: int) -> float:
    """Convert EARFCN to DL frequency in MHz. Returns 0.0 for unknown."""
    band = earfcn_to_band(earfcn)
    if band in _FREQ_TABLE:
        offset_earfcn, base_freq, step = _FREQ_TABLE[band]
        return base_freq + (earfcn - offset_earfcn) * step
    return 0.0


# Duplex mode per E-UTRA band, from 3GPP TS 36.101 Table 5.5-1. A band's duplex
# is a fixed property of the band, so it is derivable from earfcn_to_band with no
# per-cell decode. Three classes matter for a WiGLE/kismet `duplex` field:
#   TDD -- time-division duplex (one carrier, up/down time-shared)
#   FDD -- frequency-division duplex (paired UL/DL carriers)
#   SDL -- supplemental downlink (DL-only; neither FDD nor TDD). Emitting "FDD"
#          for an SDL band would be a plausible-but-wrong value, so SDL bands are
#          classified explicitly rather than defaulted.
_TDD_BANDS = frozenset(range(33, 55))          # 33..54 inclusive (TS 36.101 5.5-1)
# UL "N/A" + NOTE 2 in 5.5-1 marks a DL-only band; 69 carries it too.
_SDL_BANDS = frozenset({29, 32, 67, 69, 75, 76})  # supplemental downlink, DL-only
_FDD_BANDS = frozenset(
    set(range(1, 29))                          # 1..28
    | {30, 31}
    | {65, 66, 68, 70, 71, 72, 73, 74}
    | {85, 87, 88, 103, 106, 111}               # there is no LTE band 86
) - _SDL_BANDS                                 # 29 is SDL, not FDD


def band_to_duplex(band: int) -> str | None:
    """Map an E-UTRA band number to its duplex mode ('TDD'/'FDD'/'SDL').

    Returns None for band 0 (unknown EARFCN) or any band not classified in
    TS 36.101 Table 5.5-1, so an unknown band is OMITTED rather than guessed.
    """
    if band in _TDD_BANDS:
        return "TDD"
    if band in _SDL_BANDS:
        return "SDL"
    if band in _FDD_BANDS:
        return "FDD"
    return None
