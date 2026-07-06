# diaggrok-provenance: re
"""HDLC framing + opcode classification for Qualcomm DIAG byte streams.

Shared between ``tools/hdlc_to_dlf.py`` (offline QMDL → DLF conversion) and
``apps/diaggpsd/dlf_to_jsonl.py`` (raw-HDLC replay). Handles both the
legacy DIAG_LOG_F (``0x10``) opcode and the multi-RADIO routing
DIAG_MULTI_RADIO_CMD_F (``0x98``) wrapper that carries an inner ``0x10``
LOG packet at offset 8.

Why this matters:
    Captures from ``diag_mdlog`` on SDX72-class devices (Quectel RG650V,
    Snapdragon X72 5G Advanced) contain **zero** bare ``0x10`` packets —
    every LOG record is wrapped in ``0x98``. Parsers that only recognize
    ``0x10`` decode 0% of those captures.

    Pre-SDX72 chipsets ALSO use ``0x98`` selectively. On SDX20 LTE-only
    chipsets (Telit LM960 32.01.110 confirmed 2026-04-28, #N), LTE
    Layer 2 codes (RLC / MAC / PDCP / Layer 2, code range 0xB0xx-0xB1xx)
    come over ``0x98`` while higher-layer LTE + GNSS + LTE PHY come over
    bare ``0x10``. The split is by per-RAT diag routing: when the kernel
    diag driver hands a record off to a per-RAT subsystem demuxer, that
    demuxer wraps it in ``0x98`` with a ``radio_id`` (byte 1) and a
    ``tx_mask`` (bytes 4:8) identifying which radio produced it. The
    wrapper is NOT an SDX72/5G-NR-only construct — chipset class is not
    a sufficient predictor.

    Unwrapping the 8-byte ``0x98`` header exposes a standard ``0x10``
    frame that the rest of the stack already understands. Parsers that
    consume from ``iter_log_records`` get correct coverage of both
    framings for free.

Other observed opcodes on newer modems (classified but not decoded):
    ``0x9E`` DIAG_SECURE_LOG_F — encrypted log packets; need Qualcomm
        QCAT with device auth to decrypt.
    ``0x80`` DIAG_SUBSYS_CMD_VER_2_F — subsystem cmd/response traffic,
        not log data.
    ``0x99`` DIAG_QSR4_EXT_MSG_TERSE_F — QSR4-compressed F3 messages;
        need the companion ``.qdb`` QShrink4 database to render text.

Opcode values and their ``DIAG_*_F`` names are Qualcomm DIAG **interface
constants** — fixed command-code bytes and their canonical macro names from
the baseband command interface (Qualcomm ``diagcmd.h``). ``OPCODE_NAMES`` is
an independent transcription of the subset this project observes on capture
(20 of the ~30 enumerated opcodes), stored as a plain ``dict[int, str]``.
The names are compelled by the interface — ``0x10`` *is* ``DIAG_LOG_F`` — so
they coincide with every public DIAG tool that lists them; no third-party
code, table structure, or opcode selection was copied.
"""
from __future__ import annotations

import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Iterator


# Diag opcodes (cmd_code byte at offset 0 of an unescaped HDLC frame).
OPCODE_NAMES: dict[int, str] = {
    0x00: "DIAG_VERNO_F",
    0x10: "DIAG_LOG_F",
    0x13: "DIAG_BAD_CMD_F",
    0x1C: "DIAG_DIAG_VER_F",
    0x1D: "DIAG_TS_F",
    0x4B: "DIAG_SUBSYS_CMD_F",
    0x60: "DIAG_EVENT_REPORT_F",
    0x63: "DIAG_STATUS_SNAPSHOT_F",
    0x73: "DIAG_LOG_CONFIG_F",
    0x79: "DIAG_EXT_MSG_F",
    0x7C: "DIAG_EXT_BUILD_ID_F",
    0x7D: "DIAG_EXT_MSG_CONFIG_F",
    0x7E: "DIAG_EXT_MSG_TERSE_F",
    0x80: "DIAG_SUBSYS_CMD_VER_2_F",
    0x92: "DIAG_QSR_EXT_MSG_TERSE_F",
    0x98: "DIAG_MULTI_RADIO_CMD_F",
    0x99: "DIAG_QSR4_EXT_MSG_TERSE_F",
    0x9C: "DIAG_MSG_SMALL_F",
    0x9D: "DIAG_QSH_TRACE_PAYLOAD_F",
    0x9E: "DIAG_SECURE_LOG_F",
}

# Opcodes whose *inner* payload starting at offset 8 is a full DIAG_LOG_F
# (opcode 0x10) packet. SDX72-class devices wrap every LOG record in 0x98;
# pre-SDX72 chipsets (e.g. SDX20 LM960) wrap selectively for per-RAT
# routing — see file-level docstring.
#
# DO NOT add 0x80 here: the byte at offset 8 in a 0x80 frame is a fixed
# inner-segment marker that coincidentally shares the LOG_F opcode value,
# but the bytes after it are a frame-counter + QShrink4 header, NOT an
# inner LOG_F. See ``parse_subsys_v2_header`` and #N.
_MULTI_RADIO_WRAPPER_OFFSET: dict[int, int] = {
    0x98: 8,  # [0]=0x98, [1]=radio_id, [2:4]=pad, [4:8]=tx_mask, [8:]=inner 0x10 frame
}

# DIAG_SUBSYS_CMD_VER_2_F (0x80) wrapper layout — RE'd from a 742-frame
# RG650V SDX72 corpus walk. Carries QShrink4 bulk-log batches under
# subsystem DIAG_SERV (0x12). See ``docs/qualcomm/subsys-cmd-ver-2-0x80-dissection.md``.
_SUBSYS_0x80_HEADER_LEN = 27
_SUBSYS_0x80_PAYLOAD_LEN_OFFSET = 22


@dataclass
class Subsys0x80Header:
    """Parsed structured header from a ``DIAG_SUBSYS_CMD_VER_2_F`` frame.

    The body itself is QShrink4-compressed and requires a per-firmware
    message-hash database to decode (not in our corpus). The wrapper
    header, however, is fully RE'd — see the dissection doc cited above.

    The ``counter`` field is a monotonic u16 LE sequence number that
    enables drop-detection across long captures: consecutive 0x80 frames
    should carry counter values that increment by 1 (mod 2**16).
    """
    subsystem: int        # offset 1 — expected 0x12 (DIAG_SERV)
    command: int          # offset 2 — observed 0x16 on SDX72 RG650V
    version: int          # offset 3 — observed 0x08 on SDX72 RG650V
    counter: int          # offsets 10-11 (u16 LE) — monotonic frame counter
    format_id: int        # offsets 12-13 (u16 LE) — observed 1
    record_type: int      # offsets 14-15 (u16 LE) — observed 2
    field_count: int      # offsets 16-17 (u16 LE) — observed 4
    channel_tag: int      # offset 18 — sparse (~8 unique values)
    payload_len: int      # offsets 22-23 (u16 LE) — observed 0x0fa0 (4000)
    payload: bytes        # offset 27+ — compressed body, opaque without QShrink4 DB


def parse_subsys_v2_header(body: bytes) -> Subsys0x80Header | None:
    """Parse a DIAG_SUBSYS_CMD_VER_2_F (0x80) frame body into its header fields.

    ``body`` is the unescaped HDLC frame with the trailing 2-byte CRC
    already stripped. Returns None if the frame is too short or the
    opcode at offset 0 is not 0x80.

    The body of the resulting ``Subsys0x80Header.payload`` is the
    compressed QShrink4 bulk block — opaque without the firmware-side
    message-hash database. The header fields ARE recoverable and are
    useful for coverage-matrix accounting + sequence-gap detection.
    """
    if len(body) < _SUBSYS_0x80_HEADER_LEN or body[0] != 0x80:
        return None
    counter, format_id, record_type, field_count = struct.unpack_from("<HHHH", body, 10)
    payload_len = struct.unpack_from("<H", body, _SUBSYS_0x80_PAYLOAD_LEN_OFFSET)[0]
    return Subsys0x80Header(
        subsystem=body[1],
        command=body[2],
        version=body[3],
        counter=counter,
        format_id=format_id,
        record_type=record_type,
        field_count=field_count,
        channel_tag=body[18],
        payload_len=payload_len,
        payload=bytes(body[_SUBSYS_0x80_HEADER_LEN:]),
    )


# DIAG_SECURE_LOG_F (0x9E) cleartext-envelope layout (#N). The body @24+ is
# ENCRYPTED (entropy 7.998 b/B, all 256 byte values, 0.39% zeros — measured on
# 125,798 rm520ngl frames) and undecodable without the modem's secure
# (TrustZone) keys, which we do not hold. The header IS recoverable.
# CROSS-VENDOR CONFIRMED (#N, <redacted-ref> 2026-06-17): the same envelope holds on a
# Sierra EM9291 (SWIX65C_02.17.08.00, SDX-class) — 25,992/25,992 frames parse,
# version=0x01 + type_flags=0xc2 uniformly (matching the rm520ngl observation),
# sequence@12 monotonic-nondecreasing 99.77% (17956..210665), body@24+ entropy
# 7.996 b/B with 0.39% zeros (identical to rm520ngl). So this is a Qualcomm-
# platform-wide envelope, not a Quectel quirk — the recoverable header generalizes
# across vendors; only the keyed body stays opaque.
#
# REFINED (#N, <redacted-ref> 2026-06-20): the body @24+ is NOT opaque from byte 0 — it
# carries a CLEARTEXT inner sub-header before the ciphertext. Found by the
# check-EVERY-capture rule when a 4th chipset family — Quectel rg650vna SDX72
# (RG650VNA01ACR02A04G8G, 2902 frames over 2 captures) — surfaced a near-fixed
# 100-B body whose lower entropy (6.33 b/B vs 7.998) exposed structure the
# single-rm520ngl view missed. Inner sub-header (offsets RELATIVE to body @24):
#   body[0:4]  per-record VARYING (100% distinct on rg650vna AND em9291) — IV /
#              nonce / per-record counter candidate.
#   body[4:6]  build/vendor tag bytes — body[5] is build-CONST but NOT universal:
#              0x13 (rg650vna SDX72/Quectel), 0xcc (em9291 SDX65/Sierra), 0x00
#              (t99w640 SDX72/Foxconn AND rm520ngl SDX62/Quectel). body[4] is
#              const on rg650vna (0x4d) but small-varying on em9291 (0x1c..0x20)
#              — semantics TBD, deliberately not asserted.
#   body[6:8]  u16 LE inner sub-header tag — build-specific, NOT platform-wide.
#              CORRECTED (#N, <redacted-ref> 2026-06-20 2nd pass, check-EVERY-capture):
#              the earlier "INVARIANT 0x0110 / Qualcomm platform-wide tag" call
#              overgeneralized from the two captures that happened to share it.
#              Two more families REFUTE invariance: t99w640 SDX72/Foxconn carries
#              0x0000 across 5,260 CRC-valid frames (100%), and rm520ngl SDX62/
#              Quectel carries 0x0111 (n=3, small). So body[6:8] is a per-build
#              constant, not a universal record tag:
#                  0x0110  rg650vna SDX72 (Quectel) + em9291 SDX65 (Sierra)
#                  0x0000  t99w640  SDX72 (Foxconn)   — 5,260/5,260
#                  0x0111  rm520ngl SDX62 (Quectel)   — 3/3 (small sample)
#              Exposed as SecureLog0x9EHeader.inner_tag (value is build-dependent;
#              do not assert a specific constant).
#   body[8:]   ciphertext — stays keyed/opaque (this is where the encryption
#              actually begins, NOT at byte 24 as #N first framed it). Deep-body
#              entropy is ~8.0 b/B on every family measured (rg650vna's lower 6.33
#              was the near-fixed-100B short record exposing the cleartext prefix,
#              not a less-encrypted body).
_SECURE_LOG_0x9E_BODY_OFFSET = 24
_SECURE_LOG_0x9E_SEQ_OFFSET = 12   # u32 LE monotonic event counter
_SECURE_LOG_0x9E_INNER_TAG_OFFSET = 6   # u16 LE within body; build-specific (not universal)


@dataclass
class SecureLog0x9EHeader:
    """Cleartext envelope of a ``DIAG_SECURE_LOG_F`` (0x9E) frame (#N).

    The ``body`` (offset 24+) is ENCRYPTED and opaque without the modem's
    secure keys. The header fields are recoverable: ``sequence`` is a monotonic
    u32 LE event counter — it advances by a VARIABLE step (observed median
    ~1-2, so it indexes secure-log *events*, not 0x9E frames 1:1), so a backward
    jump flags a stream restart / dropped span (drop-detection without the body,
    mirroring the 0x80 QShrink4 counter).
    """
    version: int       # offset 1  — observed 0x01
    type_flags: int    # offset 2  — observed 0xc2 (rare 0x82 sub-type)
    sequence: int      # offsets 12-15 (u32 LE) — monotonic event counter
    body: bytes        # offset 24+ — cleartext inner sub-header then ciphertext
    inner_tag: int | None = None   # u16 LE at body[6:8] — build-specific inner
                                   # sub-header tag (#N; NOT a universal 0x0110
                                   # — observed 0x0110 / 0x0000 / 0x0111 across
                                   # families). None when body < 8 B. The
                                   # ciphertext proper starts at body[8:].


def parse_secure_log_envelope(body: bytes) -> "SecureLog0x9EHeader | None":
    """Parse the CLEARTEXT envelope of a ``DIAG_SECURE_LOG_F`` (0x9E) frame.

    ``body`` is the unescaped HDLC frame with the trailing 2-byte CRC stripped.
    Returns None if too short or the opcode at offset 0 is not 0x9E. The
    ``body`` field of the result is the ENCRYPTED payload (#N) — opaque
    without the modem's secure keys — but version/type/sequence are recoverable
    and the sequence enables gap analysis of dropped secure-log batches.
    """
    if len(body) < _SECURE_LOG_0x9E_SEQ_OFFSET + 4 or body[0] != 0x9E:
        return None
    sequence = struct.unpack_from("<I", body, _SECURE_LOG_0x9E_SEQ_OFFSET)[0]
    inner = bytes(body[_SECURE_LOG_0x9E_BODY_OFFSET:])
    inner_tag = None
    if len(inner) >= _SECURE_LOG_0x9E_INNER_TAG_OFFSET + 2:
        inner_tag = struct.unpack_from(
            "<H", inner, _SECURE_LOG_0x9E_INNER_TAG_OFFSET)[0]
    return SecureLog0x9EHeader(
        version=body[1],
        type_flags=body[2],
        sequence=sequence,
        body=inner,
        inner_tag=inner_tag,
    )


# DIAG_QSR_EXT_MSG_TERSE_F (0x92) — legacy (pre-QSR4) terse F3 envelope (#N).
# Clean-room characterized from 210,891 records on the EG25-G MDM9207 capture
# (<redacted-pii>), then
# CROSS-CHIPSET-validated (#N, 2026-06-19) against EM7455 SWI9X30C / MDM9230
# (1,597,412 frames) + EG25-G A0.301 DLF (136,213 frames). The STRUCTURAL
# envelope is cross-chipset-invariant — all three sets parse 100% and ts is
# monotonic on all — but several sub-fields the original single-capture pass
# annotated as "const" are in fact CHIPSET-SPECIFIC (const within a chipset,
# divergent across). Layout (offsets/widths) is universal; field VALUES are not:
#   [0]     u8   opcode = 0x92            (const, universal)
#   [1]     u8   = 0x00                   (const, universal — both chipsets)
#   [2:4]   u16  num_args (LE)            — body_len == 24 + 4*num_args (100%, universal)
#   [4]     u8   QSR terse format/version marker — CHIPSET-SPECIFIC, NOT universal:
#                0x09 const on MDM9207 (EG25-G), 0x00 const on MDM9230 (EM7455).
#                The parser deliberately does NOT assert this byte (see below).
#   [5:9]   u32  timestamp (LE)           — monotonic non-decreasing on BOTH chipsets
#   [9:12]  3B   descriptor tail — CHIPSET-SPECIFIC: all-zero on MDM9207 (so the
#                original pass read it as "timestamp high padding"), but NON-zero
#                on MDM9230. Since ts[5:9] stays monotonic on MDM9230 regardless,
#                [9:12] is a real descriptor field, NOT timestamp overflow.
#   [12:20] 8B   message descriptor (line/ss/flags; not split — byte[16] varies:
#                ~56% == 0x04 on MDM9207 vs ~9% on MDM9230, another chipset split)
#   [20:24] u32  message hash (LE)        — per-build QSR message-DB key. Hash
#                vocabularies are DISJOINT per build (704 distinct on EG25-G A0.301,
#                1278 on EM7455 SWI9X30C): the #N DB-gate is strictly per-build.
#                SAME role as the 0x99 QSR4 hash (#N): rendering the text is
#                message-DB-gated (no MDM9207/MDM9230 qdb yet, #N), but the
#                STRUCTURED envelope (ts, hash, args) decodes offline today.
#   [24:]   args[]  — num_args * u32 (LE)
# So 0x92's text-render blocker is IDENTICAL to the 0x99 qdb gate, NOT a novel
# undecodable format — this refines the #N decode-blocker matrix. The parser
# asserts ONLY opcode + the length relation (never the chipset-specific marker at
# [4]), which is why it already generalizes across MDM9207/MDM9230 unchanged: the
# version marker varies WITHOUT a layout change, the one legitimate case where a
# permissive (non-version-asserting) parse is correct rather than a mis-parse risk.
_QSR_0x92_HEADER_LEN = 24
_QSR_0x92_NUM_ARGS_OFFSET = 2
_QSR_0x92_TS_OFFSET = 5
_QSR_0x92_HASH_OFFSET = 20


@dataclass
class Qsr0x92Header:
    """Structured envelope of a legacy ``DIAG_QSR_EXT_MSG_TERSE_F`` (0x92) frame.

    The message TEXT is render-gated on the build's QSR message DB (``hash``
    indexes it — the same role as the 0x99 QSR4 hash, #N), which we do not
    hold for MDM9207 (#N). But the envelope decodes offline: ``num_args``,
    a monotonic ``timestamp``, the message ``hash`` (message identity), and the
    raw ``args``. Clean-room RE'd from the EG25-G MDM9207 corpus (#N).
    """
    num_args: int      # offsets 2-3 (u16 LE) — body_len == 24 + 4*num_args
    timestamp: int     # offsets 5-8 (u32 LE) — monotonic
    hash: int          # offsets 20-23 (u32 LE) — per-build QSR message-DB key
    args: tuple        # num_args * u32 LE, starting at offset 24


def parse_qsr_terse_0x92_envelope(body: bytes) -> "Qsr0x92Header | None":
    """Parse the envelope of a legacy ``DIAG_QSR_EXT_MSG_TERSE_F`` (0x92) frame.

    ``body`` is the unescaped HDLC frame with the trailing 2-byte CRC stripped.
    Returns None if too short, if the opcode at offset 0 is not 0x92, or if the
    length does not match ``24 + 4*num_args`` (the 100%-verified invariant) — so
    a stray/corrupt frame is rejected, not mis-parsed. The message text is NOT
    rendered (DB-gated, #N); the structured envelope fields are.
    """
    if len(body) < _QSR_0x92_HEADER_LEN or body[0] != 0x92:
        return None
    num_args = struct.unpack_from("<H", body, _QSR_0x92_NUM_ARGS_OFFSET)[0]
    if len(body) != _QSR_0x92_HEADER_LEN + 4 * num_args:
        return None
    timestamp = struct.unpack_from("<I", body, _QSR_0x92_TS_OFFSET)[0]
    hash_ = struct.unpack_from("<I", body, _QSR_0x92_HASH_OFFSET)[0]
    args = (
        struct.unpack_from("<%dI" % num_args, body, _QSR_0x92_HEADER_LEN)
        if num_args
        else ()
    )
    return Qsr0x92Header(
        num_args=num_args, timestamp=timestamp, hash=hash_, args=tuple(args)
    )


# DIAG_LOG_F (0x10) layout after HDLC unescape, CRC stripped:
#   [0]      opcode = 0x10
#   [1]      pending_msgs
#   [2:4]    outer_len (u16 LE)
#   [4:6]    inner_len (u16 LE)
#   [6:8]    log_code (u16 LE)
#   [8:16]   timestamp (u64 LE, Qualcomm 1.25 ms ticks) — this is the
#            OUTER HDLC LOG_F-header timestamp, equivalent to the DLF
#            file-format ts64 at the same offset. The INNER DIAG frame
#            ``log_time`` (parsed by ``diaggrok.frame.parse_outer_frame``
#            in the diaggpsd live-streaming path) is a SEPARATE
#            chipset-dependent high-frequency counter (~17.24 ns/tick on
#            SDX62, etc.). See ``frame.py`` docstring + #N.
#   [16:]    payload
_LOG_F_MIN_LEN = 16


@dataclass
class HdlcStats:
    """Running counters for an HDLC extraction pass."""
    opcode_frames: Counter[int] = field(default_factory=Counter)
    opcode_bytes: Counter[int] = field(default_factory=Counter)
    # Inner opcode of each 0x98 DIAG_MULTI_RADIO_CMD_F wrapper (the byte at
    # offset 8). The wrapper carries a MIX — inner 0x10 LOG, but also inner
    # 0x79/0x99 F3 — so a top-level-only opcode tally hides wrapped F3 (#N).
    inner_0x98_opcodes: Counter[int] = field(default_factory=Counter)
    log_records: int = 0
    log_records_from_wrapper: int = 0
    crc_ok: int = 0
    crc_bad: int = 0
    skipped_short: int = 0
    # Monotonic u16 LE counter values pulled from 0x80 wrappers in order
    # encountered. Consecutive entries should increment by 1 (mod 2**16);
    # gaps indicate dropped QShrink4 batches. See ``parse_subsys_v2_header``.
    subsys_0x80_counters: list[int] = field(default_factory=list)
    # 0x9E DIAG_SECURE_LOG_F envelope sequence values, in order seen (#N).
    secure_log_0x9e_seqs: list[int] = field(default_factory=list)

    def summary_lines(self) -> list[str]:
        """One-line-per-opcode summary suitable for stderr logging."""
        lines = []
        for op, n in self.opcode_frames.most_common():
            name = OPCODE_NAMES.get(op, "(unknown)")
            lines.append(
                f"  0x{op:02X}  frames={n:<6}  bytes={self.opcode_bytes[op]:<9}  {name}"
            )
        return lines

    def subsys_0x80_gap_report(self) -> dict | None:
        """Sequence-gap analysis of the 0x80 (QShrink4) wrapper counter.

        The 0x80 ``DIAG_SUBSYS_CMD_VER_2_F`` wrapper carries a monotonic
        u16 LE frame counter (see ``Subsys0x80Header.counter``).
        Consecutive frames should increment by 1 (mod 2**16); any other
        delta is a dropped/reordered QShrink4 batch — invisible without
        the counter because the compressed bodies are opaque to us.

        Returns ``None`` if no 0x80 frames were seen. Otherwise a dict:

        - ``frames``        — number of 0x80 frames observed
        - ``transitions``   — counter-to-counter steps (``frames - 1``)
        - ``in_sequence``   — transitions with delta == 1 (mod 2**16)
        - ``counter_min`` / ``counter_max`` — raw counter range
        - ``gaps``          — list of ``(index, prev, next, delta)`` for
          every transition whose delta != 1, where
          ``delta = (next - prev) mod 2**16`` and ``index`` is the
          position of ``next`` in ``subsys_0x80_counters``.

        See #N and ``docs/qualcomm/subsys-cmd-ver-2-0x80-dissection.md``.
        """
        counters = self.subsys_0x80_counters
        if not counters:
            return None
        gaps: list[tuple[int, int, int, int]] = []
        for i in range(1, len(counters)):
            delta = (counters[i] - counters[i - 1]) & 0xFFFF
            if delta != 1:
                gaps.append((i, counters[i - 1], counters[i], delta))
        transitions = len(counters) - 1
        return {
            "frames": len(counters),
            "transitions": transitions,
            "in_sequence": transitions - len(gaps),
            "counter_min": min(counters),
            "counter_max": max(counters),
            "gaps": gaps,
        }

    def secure_log_0x9e_gap_report(self) -> dict | None:
        """Sequence analysis of the 0x9E DIAG_SECURE_LOG_F envelope counter (#N).

        The 0x9E cleartext header carries a u32 LE ``sequence`` (see
        :class:`SecureLog0x9EHeader`). Unlike the strict-+1 0x80 counter, the
        secure-log sequence advances by a VARIABLE step (it indexes secure-log
        *events*, not 0x9E frames 1:1), so the useful signal is **monotonicity +
        resets** (a backward jump = a stream restart / dropped span), not a
        strict ``delta == 1`` check. The body is encrypted (key-blocked), so
        this envelope-level drop-detection is all that's recoverable.

        Returns ``None`` if no 0x9E frames were seen. Otherwise a dict:

        - ``frames``           — number of 0x9E frames observed
        - ``transitions``      — seq-to-seq steps (``frames - 1``)
        - ``seq_min`` / ``seq_max`` / ``span`` — raw u32 sequence range
        - ``monotonic``        — non-decreasing transitions (u32-wrap-aware)
        - ``resets``           — backward jumps that are NOT a u32 wrap
          (a real stream restart / lost span)
        - ``max_forward_gap``  — largest forward step (a candidate dropped batch)
        """
        seqs = self.secure_log_0x9e_seqs
        if not seqs:
            return None
        resets = 0
        monotonic = 0
        max_gap = 0
        for i in range(1, len(seqs)):
            prev, cur = seqs[i - 1], seqs[i]
            if cur >= prev:
                monotonic += 1
                max_gap = max(max_gap, cur - prev)
            elif prev > (1 << 31) and cur < (1 << 31):
                monotonic += 1  # u32 wrap — still monotonic
            else:
                resets += 1
        return {
            "frames": len(seqs),
            "transitions": len(seqs) - 1,
            "seq_min": min(seqs),
            "seq_max": max(seqs),
            "span": max(seqs) - min(seqs),
            "monotonic": monotonic,
            "resets": resets,
            "max_forward_gap": max_gap,
        }

    def subsys_0x80_gap_lines(self) -> list[str]:
        """Human-readable rendering of :meth:`subsys_0x80_gap_report`.

        Empty list when no 0x80 frames were seen, so callers can
        unconditionally ``extend`` their report with it.
        """
        report = self.subsys_0x80_gap_report()
        if report is None:
            return []
        lines = [
            f"  0x80 QShrink4 sequence: {report['frames']} frames, "
            f"{report['in_sequence']}/{report['transitions']} in-sequence, "
            f"{len(report['gaps'])} gap(s); "
            f"counter 0x{report['counter_min']:04X}->0x{report['counter_max']:04X}"
        ]
        for index, prev, nxt, delta in report["gaps"]:
            lines.append(
                f"    gap at frame {index}: 0x{prev:04X}->0x{nxt:04X} "
                f"(delta {delta}, expected 1)"
            )
        return lines


def hdlc_unescape(frame: bytes) -> bytes:
    """Remove HDLC escape sequences (0x7D + byte XOR 0x20)."""
    out = bytearray()
    i = 0
    while i < len(frame):
        if frame[i] == 0x7D and i + 1 < len(frame):
            out.append(frame[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(frame[i])
            i += 1
    return bytes(out)


def _make_crc16():
    """Build CRC-16 CCITT matching Qualcomm DIAG framing.

    Wire format on SDX20/SDX55/SDX62/SDX72 captures is the reflected
    variant produced by ``crcmod.mkCrcFun(0x11021, initCrc=0,
    xorOut=0xFFFF)`` with ``rev=True`` (crcmod's default) — equivalent
    to running CRC-16/X-25 with the register seeded from ``xorOut ^
    initCrc``. Concretely: reflected poly 0x8408, register starts at
    0xFFFF, byte fed LSB-first, output XORed with 0xFFFF. Known test
    vector: ``crc16_ccitt(b"123456789") == 0x906E``.

    Prefers ``crcmod`` (C extension, ~100x faster). Falls back to a
    pure-Python reflected table-driven implementation that produces
    byte-identical output. (An earlier fallback used the forward
    non-reflected algorithm and silently rejected 100% of real frames
    on hosts without crcmod — see #N.)
    """
    try:
        from crcmod import mkCrcFun
        return mkCrcFun(0x11021, initCrc=0, xorOut=0xFFFF)
    except ImportError:
        pass

    # Reflected poly for CRC-16-CCITT: bit-reverse of 0x1021.
    _RPOLY = 0x8408
    _table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ _RPOLY if (crc & 1) else (crc >> 1)
        _table.append(crc)

    def crc16_ccitt(data: bytes) -> int:
        # Equivalent to crcmod(initCrc=0, xorOut=0xFFFF, rev=True):
        # seed = xorOut ^ initCrc = 0xFFFF, run reflected loop,
        # XOR result with xorOut.
        crc = 0xFFFF
        for byte in data:
            crc = _table[byte ^ (crc & 0xFF)] ^ (crc >> 8)
        return crc ^ 0xFFFF

    return crc16_ccitt


crc16_ccitt = _make_crc16()


def _extract_log_f(frame_no_crc: bytes) -> tuple[int, int, bytes] | None:
    """Parse a DIAG_LOG_F (opcode 0x10) frame body into (log_code, ts64, payload).

    ``frame_no_crc`` must be the unescaped HDLC frame with its trailing
    2-byte CRC already stripped. Returns None if the frame is too short
    or the opcode is not 0x10.
    """
    if len(frame_no_crc) < _LOG_F_MIN_LEN or frame_no_crc[0] != 0x10:
        return None
    log_code = struct.unpack_from("<H", frame_no_crc, 6)[0]
    ts64 = struct.unpack_from("<Q", frame_no_crc, 8)[0]
    payload = frame_no_crc[_LOG_F_MIN_LEN:]
    return log_code, ts64, payload


def _process_frame(
    raw_frame: bytes,
    *,
    verify_crc: bool,
    stats: HdlcStats,
) -> tuple[int, int, bytes] | None:
    """Decode ONE raw (still-escaped, delimiter-stripped) HDLC frame.

    Shared single-frame core for both the whole-buffer
    :func:`iter_log_records` and the chunked :func:`iter_log_records_stream`
    (#N). ``raw_frame`` is the bytes between two ``0x7E`` delimiters,
    exactly one element of ``data.split(b"\\x7e")``.

    Returns the ``(log_code, ts64, payload)`` record for a LOG packet
    (bare ``0x10`` or unwrapped ``0x98``), or ``None`` for everything
    else (too-short, bad CRC, non-LOG opcode). ``stats`` is mutated in
    place either way — opcode/byte counts, CRC tallies, and ``0x80``
    QShrink4 counters accrue even when no record is yielded.
    """
    if len(raw_frame) < 4:  # need opcode + 2 CRC + at least 1 byte
        return None

    frame = hdlc_unescape(raw_frame)
    if len(frame) < 3:
        stats.skipped_short += 1
        return None

    if verify_crc:
        payload_part = frame[:-2]
        crc_expected = struct.unpack_from("<H", frame, len(frame) - 2)[0]
        if crc16_ccitt(payload_part) != crc_expected:
            stats.crc_bad += 1
            return None
        stats.crc_ok += 1

    opcode = frame[0]
    stats.opcode_frames[opcode] += 1
    stats.opcode_bytes[opcode] += len(frame)

    # Strip the 2-byte trailing CRC from the body we hand to extractors.
    body = frame[:-2]

    if opcode == 0x10:
        rec = _extract_log_f(body)
        if rec is not None:
            stats.log_records += 1
        return rec

    wrap_off = _MULTI_RADIO_WRAPPER_OFFSET.get(opcode)
    if wrap_off is not None and len(body) > wrap_off:
        # Tally the inner opcode so wrapped F3 (0x79/0x99) is visible to the
        # census, not just the inner-0x10 LOG case extracted below (#N).
        stats.inner_0x98_opcodes[body[wrap_off]] += 1
        # The 0x98 wrapper holds a complete inner 0x10 LOG_F frame;
        # it does NOT carry its own inner CRC, so no second strip.
        rec = _extract_log_f(body[wrap_off:])
        if rec is not None:
            stats.log_records += 1
            stats.log_records_from_wrapper += 1
        return rec

    if opcode == 0x80:
        hdr = parse_subsys_v2_header(body)
        if hdr is not None:
            stats.subsys_0x80_counters.append(hdr.counter)

    if opcode == 0x9E:
        env = parse_secure_log_envelope(body)
        if env is not None:
            stats.secure_log_0x9e_seqs.append(env.sequence)

    return None


def iter_log_records(
    data: bytes,
    *,
    verify_crc: bool = False,
    stats: HdlcStats | None = None,
) -> Iterator[tuple[int, int, bytes]]:
    """Yield ``(log_code, ts64, payload)`` for every LOG packet in a raw
    HDLC-framed DIAG byte stream.

    Handles two source layouts transparently:

    * **Legacy 0x10** — frames whose first byte is ``0x10``; decoded in
      place.
    * **Wrapped 0x98** — ``DIAG_MULTI_RADIO_CMD_F`` envelopes carrying
      an inner 0x10 frame at offset 8; the wrapper is stripped and the
      inner frame is decoded.

    Frames with other opcodes (``0x9E`` secure log, ``0x80`` subsys cmd,
    etc.) are counted in ``stats`` but not yielded.

    Parameters
    ----------
    data:
        Raw HDLC byte stream (concatenated 0x7E-delimited frames). Any
        non-HDLC preamble before the first 0x7E is skipped naturally by
        the ``split`` boundary.
    verify_crc:
        When True, validate the trailing CRC-16 CCITT on each unescaped
        frame; frames with bad CRC are dropped and counted.
    stats:
        Optional ``HdlcStats`` to populate. The caller can inspect this
        after iteration for opcode counts + CRC stats. A fresh stats
        object is created if not provided (but then discarded).
    """
    if stats is None:
        stats = HdlcStats()

    for raw_frame in data.split(b"\x7e"):
        rec = _process_frame(raw_frame, verify_crc=verify_crc, stats=stats)
        if rec is not None:
            yield rec


def iter_log_records_stream(
    chunks: Iterable[bytes],
    *,
    verify_crc: bool = False,
    stats: HdlcStats | None = None,
    flush_tail: bool = True,
) -> Iterator[tuple[int, int, bytes]]:
    """Streaming equivalent of :func:`iter_log_records` (#N).

    Consumes an **iterable of byte chunks** (e.g. successive
    ``os.read(fd, 65536)`` results from a live ``diaggulp.py`` pipe)
    instead of one complete buffer, and yields each LOG record **as soon
    as its terminating ``0x7E`` arrives** — without waiting for the
    stream to close. This is the missing primitive that lets agents watch
    DIAG decode live rather than only post-processing a closed capture.

    Why this is safe to slice on raw ``0x7E`` across chunk boundaries:
    HDLC byte-stuffs any ``0x7E`` that occurs *inside* a frame as
    ``0x7D 0x5E``, so a literal ``0x7E`` in the stream is *always* a frame
    delimiter, never frame content. We accumulate a ``residual`` buffer of
    the bytes after the last delimiter seen so far; a frame that spans
    chunks simply stays in ``residual`` until its delimiter arrives. The
    residual never grows beyond a single in-flight frame, so memory is
    bounded regardless of stream length.

    Parameters
    ----------
    chunks:
        Iterable of raw HDLC byte chunks. Empty chunks are skipped (a
        ``b""`` from a non-blocking read does not signal EOF here — the
        iterator ending is EOF).
    verify_crc:
        Same semantics as :func:`iter_log_records`.
    stats:
        Optional shared :class:`HdlcStats`; created if not given.
    flush_tail:
        When ``True`` (default), the trailing ``residual`` left after the
        last chunk is processed as a final frame once the iterable is
        exhausted. This makes the stream **byte-for-byte equivalent** to
        ``iter_log_records(b"".join(chunks))`` — the property the test
        suite pins. Set ``False`` only if you know the producer was cut
        mid-frame and you want to drop the dangling partial.

    Equivalence contract (pinned by ``test_hdlc.py``)::

        list(iter_log_records_stream(chunks, flush_tail=True))
            == list(iter_log_records(b"".join(chunks)))

    for *any* chunking of the same underlying bytes.
    """
    if stats is None:
        stats = HdlcStats()

    residual = b""
    for chunk in chunks:
        if not chunk:
            continue
        buf = residual + chunk
        parts = buf.split(b"\x7e")
        # The final element is whatever follows the last delimiter — a
        # possibly-incomplete frame. Hold it for the next chunk.
        residual = parts.pop()
        for raw_frame in parts:
            rec = _process_frame(raw_frame, verify_crc=verify_crc, stats=stats)
            if rec is not None:
                yield rec

    if flush_tail and residual:
        rec = _process_frame(residual, verify_crc=verify_crc, stats=stats)
        if rec is not None:
            yield rec


def log_crc_report(stats: HdlcStats, stream=sys.stderr) -> None:
    """Write a one-line CRC validation summary, if CRC checking ran."""
    total = stats.crc_ok + stats.crc_bad
    if total == 0:
        return
    print(
        f"CRC check: {stats.crc_ok}/{total} OK, "
        f"{stats.crc_bad} bad ({stats.crc_bad * 100 / total:.1f}%)",
        file=stream,
    )


@dataclass(frozen=True)
class OuterFrame:
    """One de-HDLC'd DIAG frame, opcode-agnostic (#N scope-item-2 plumbing).

    Unlike :func:`iter_log_records` (which yields only ``0x10`` LOG payloads)
    this exposes the body of **every** outer opcode — the recognized-but-undecoded
    ones (``0x92``/``0x9C``/``0x9D``/``0x7E`` …) included — so a clean-room RE
    pass can reach their raw bytes (e.g. the data-only "scan body u32s, find which
    offset resolves as a qdb hash" method, #N). It does **no** per-opcode
    format decode; it is pure HDLC framing.

    Attributes
    ----------
    opcode:
        First byte of this frame's body — the opcode whose payload ``body`` is.
    body:
        Unescaped frame with the trailing 2-byte CRC stripped (starts with
        ``opcode``). For a ``wrapped`` inner frame, this is the inner frame bytes
        (the ``0x98`` envelope carries one OUTER CRC and no inner CRC, so the
        inner body is the envelope body from the wrapper offset on, un-stripped).
    wrapped:
        ``True`` when this frame was unwrapped one level from a multi-radio
        (``0x98``) envelope; ``False`` for a top-level frame.
    outer_opcode:
        The enclosing frame's opcode — equals ``opcode`` for a top-level frame,
        or ``0x98`` for a ``wrapped`` inner frame.
    """

    opcode: int
    body: bytes
    wrapped: bool
    outer_opcode: int


def iter_outer_frames(
    data: bytes,
    *,
    verify_crc: bool = False,
    unwrap_multi_radio: bool = True,
) -> Iterator[OuterFrame]:
    """Yield an :class:`OuterFrame` for **every** de-HDLC'd frame, all opcodes.

    The opcode-agnostic counterpart to :func:`iter_log_records`. The frontier of
    #N is the recognized-but-undecoded opcodes whose payloads diaggrok drops;
    a decoder for any of them first needs their raw bytes, and the only existing
    walkers yield LOG (``0x10``) records only. This provides the clean-room
    plumbing: split on ``0x7E``, unescape, optionally CRC-check, and surface the
    body of each frame regardless of opcode.

    When ``unwrap_multi_radio`` is set (default), a ``0x98``
    ``DIAG_MULTI_RADIO_CMD_F`` envelope yields **two** frames: the envelope itself
    (``opcode==0x98``, ``wrapped=False``) and its inner frame
    (``wrapped=True``, ``outer_opcode==0x98``) — so wrapped ``0x79``/``0x99``/
    ``0x92``/``0x7E`` payloads are reachable the same as top-level ones (the
    Finding-1 loss this issue measured). Recursion is one level only.

    No ``HdlcStats`` is taken or mutated: this is an ad-hoc payload-extraction
    path, distinct from the census walk in :func:`iter_log_records`, so the two
    never double-count.
    """
    for raw_frame in data.split(b"\x7e"):
        if len(raw_frame) < 4:  # opcode + 2 CRC + >=1 byte
            continue
        frame = hdlc_unescape(raw_frame)
        if len(frame) < 3:
            continue
        if verify_crc:
            crc_expected = struct.unpack_from("<H", frame, len(frame) - 2)[0]
            if crc16_ccitt(frame[:-2]) != crc_expected:
                continue
        body = frame[:-2]  # strip trailing CRC, same convention as _process_frame
        if not body:
            continue
        opcode = body[0]
        yield OuterFrame(opcode=opcode, body=body, wrapped=False, outer_opcode=opcode)

        if unwrap_multi_radio:
            wrap_off = _MULTI_RADIO_WRAPPER_OFFSET.get(opcode)
            if wrap_off is not None and len(body) > wrap_off:
                # The 0x98 wrapper carries one OUTER CRC and no inner CRC, so the
                # inner frame is body[wrap_off:] un-stripped (matches the 0x98 F3
                # unwrap in iter_f3_samples / the LOG unwrap in _process_frame).
                inner = body[wrap_off:]
                if inner:
                    yield OuterFrame(
                        opcode=inner[0],
                        body=inner,
                        wrapped=True,
                        outer_opcode=opcode,
                    )
