"""Unit tests for the offline replay reader (apps/diagreplay, #N).

Fixtures are synthesized with :func:`diaggrok.dlf.pack_records` so the flat-DLF
framing definition lives in exactly one place (the library) rather than being
re-hand-rolled here — the whole point of the consolidation.
"""
from __future__ import annotations

import gzip

import pytest

from diaggrok.dlf import pack_records
from diagreplay import ReplayRecord, read_capture_bytes, replay_dlf

# A small synthetic flat-DLF corpus: (log_code, ts64, payload) triples.
# Codes interleaved so the codes= filter has something to exclude. The corpus
# is intentionally >= 8 records of *registered* codes (0x1544/0x1476/0x1478 are
# all real GNSS parsers) — diaggrok.dlf.detect_format only classifies a stream
# as flat-DLF once it has walked 8 registered-code records (the _looks_like_
# flat_dlf false-positive guard, #N). A shorter corpus would misroute to the
# HDLC/unknown branch and raise UnknownFormatError.
_RECORDS = [
    (0x1544, 1000, b"\x02\x02payloadA"),
    (0x1476, 1001, b"\x0a\x00posreport1"),
    (0x1544, 1002, b"\x02\x02payloadB"),
    (0x1478, 1003, b"\x03clockrep1"),
    (0x1544, 1004, b"\x02\x02payloadC"),
    (0x1476, 1005, b"\x0a\x00posreport2"),
    (0x1478, 1006, b"\x03clockrep2"),
    (0x1544, 1007, b"\x02\x02payloadD"),
    (0x1476, 1008, b"\x0a\x00posreport3"),
]


@pytest.fixture
def flat_dlf(tmp_path):
    """A plain (uncompressed) flat-DLF capture file."""
    p = tmp_path / "cap.dlf"
    p.write_bytes(pack_records(_RECORDS))
    return p


class TestReplayFlatDlf:
    def test_yields_every_record_unfiltered(self, flat_dlf):
        recs = list(replay_dlf(flat_dlf))
        assert len(recs) == len(_RECORDS)
        assert all(isinstance(r, ReplayRecord) for r in recs)
        # Order + field fidelity preserved end-to-end.
        assert [(r.code, r.ts, r.payload) for r in recs] == _RECORDS

    def test_code_filter_single(self, flat_dlf):
        recs = list(replay_dlf(flat_dlf, codes={0x1544}))
        assert [r.code for r in recs] == [0x1544] * 4
        assert [r.payload for r in recs] == [
            b"\x02\x02payloadA",
            b"\x02\x02payloadB",
            b"\x02\x02payloadC",
            b"\x02\x02payloadD",
        ]

    def test_code_filter_multi(self, flat_dlf):
        recs = list(replay_dlf(flat_dlf, codes={0x1476, 0x1478}))
        assert [r.code for r in recs] == [0x1476, 0x1478, 0x1476, 0x1478, 0x1476]

    def test_code_filter_accepts_any_iterable(self, flat_dlf):
        # A list (not a set) must work too — replay_dlf normalizes internally.
        recs = list(replay_dlf(flat_dlf, codes=[0x1544]))
        assert len(recs) == 4

    def test_empty_filter_yields_nothing(self, flat_dlf):
        assert list(replay_dlf(flat_dlf, codes=set())) == []

    def test_record_is_frozen(self, flat_dlf):
        rec = next(iter(replay_dlf(flat_dlf)))
        with pytest.raises(Exception):
            rec.ts = 5  # type: ignore[misc]


class TestDecompression:
    def test_reads_zst(self, tmp_path):
        zstandard = pytest.importorskip("zstandard")
        raw = pack_records(_RECORDS)
        p = tmp_path / "cap.dlf.zst"
        p.write_bytes(zstandard.ZstdCompressor().compress(raw))
        assert read_capture_bytes(p) == raw
        recs = list(replay_dlf(p, codes={0x1544}))
        assert len(recs) == 4

    def test_reads_gz(self, tmp_path):
        raw = pack_records(_RECORDS)
        p = tmp_path / "cap.dlf.gz"
        p.write_bytes(gzip.compress(raw))
        assert read_capture_bytes(p) == raw
        assert len(list(replay_dlf(p))) == len(_RECORDS)

    def test_plain_file_passthrough(self, flat_dlf):
        assert read_capture_bytes(flat_dlf) == pack_records(_RECORDS)


class TestTruncationTolerance:
    def test_stops_cleanly_at_truncated_tail(self, tmp_path):
        """A capture cut mid-record still yields every complete record — the
        library walker returns at the first malformed header, no exception."""
        raw = pack_records(_RECORDS)
        p = tmp_path / "trunc.dlf"
        p.write_bytes(raw[:-3])  # lop 3 bytes off the last record's payload
        recs = list(replay_dlf(p))
        assert len(recs) == len(_RECORDS) - 1
        assert recs[-1].code == 0x1544  # 0x1544 payloadD is the last whole record
