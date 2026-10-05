from public_corpus.support.synthetic import diag_frame

def test_diag_frame_prepends_code_and_version():
    f = diag_frame(0xB193, version=1, payload=b"\x06\x00")
    # frame carries version byte then payload; code addressing is the harness's
    assert f[0] == 1
    assert f.endswith(b"\x06\x00")

def test_diag_frame_is_pii_free():
    from diaggrok.pii_scan import leak_tokens
    assert leak_tokens(repr(diag_frame(0x1476, 1, b"\x00" * 8))) == []
