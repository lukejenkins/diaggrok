from public_corpus.risk_tiers import RISK_TIER

SLICE = [0x117E,0x1375,0x1455,0x1456,0x1476,0x1477,0x1478,0x147B,0x147C,0x147D,
0x147E,0x1480,0x1482,0x1488,0x148E,0x1490,0x1494,0x14A6,0x14B0,0x14FD,0x1516,
0x1526,0x1544,0x1587,0x1589,0x158C,0x15BD,0x1634,0x1636,0x163D,0x1646,0x1837,
0x1843,0x184E,0x1855,0x1856,0x1859,0x1885,0x1886,0x188B,0x1893,0x1899,0x18AC,
0x18F8,0x197F,0x1980,0x19DE,0x19EB,0x1C8F,0x1C90,0x1CB2,0x1D23,0x1D2E,0x4179,
0x7160,0xB192,0xB193,0xB195]

def test_every_slice_code_has_a_tier():
    missing = [hex(c) for c in SLICE if c not in RISK_TIER]
    assert not missing, f"codes with no risk tier: {missing}"

def test_tiers_are_0_or_1():
    assert set(RISK_TIER.values()) <= {0, 1}

import pathlib, re
from diaggrok.pii_scan import leak_tokens
FIXDIR = pathlib.Path(__file__).parent

def test_tier1_fixtures_are_synthetic_and_clean():
    for f in FIXDIR.glob("test_diag_0x*.py"):
        code = int(f.stem.split("_")[-1], 16)
        src = f.read_text()
        assert leak_tokens(src) == [], f"{f.name} leaks PII"
        if RISK_TIER.get(code) == 1:
            assert "fromhex" not in src, f"tier-1 {f.name} uses a real snippet"


def test_every_present_fixture_code_is_known():
    """Carve-safe sync guard: whichever fixture files actually got carved
    (all 58 SLICE codes in the private repo, or a subset in a partial public
    carve), every present ``test_diag_0x*.py`` file's code must be a key in
    RISK_TIER. Catches a typo'd/renamed/orphaned fixture regardless of how
    many of the 58 codes are present in this tree."""
    missing = []
    for f in FIXDIR.glob("test_diag_0x*.py"):
        code = int(f.stem.split("_")[-1], 16)
        if code not in RISK_TIER:
            missing.append(f.name)
    assert not missing, f"fixtures with no RISK_TIER entry: {missing}"
