# diaggrok-provenance: re
"""HDLC framing + opcode classification for DIAG byte streams.

Used by offline QMDL → DLF conversion and by raw-HDLC replay. Handles both the
legacy DIAG_LOG_F (``0x10``) opcode and the multi-RADIO routing
DIAG_MULTI_RADIO_CMD_F (``0x98``) wrapper that carries an inner ``0x10``
LOG packet at offset 8.

Why this matters:
    Captures from ``diag_mdlog`` on SDX72-class devices (e.g. Quectel
    RG650V) contain **zero** bare ``0x10`` packets —
    every LOG record is wrapped in ``0x98``. Parsers that only recognize
    ``0x10`` decode 0% of those captures.

    Pre-SDX72 chipsets ALSO use ``0x98`` selectively. On SDX20 LTE-only
    chipsets (confirmed on a Telit LM960), LTE
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
    ``0x9E`` DIAG_SECURE_LOG_F — encrypted log packets; need a vendor
        decoder with device authentication to decrypt.
    ``0x80`` DIAG_SUBSYS_CMD_VER_2_F — subsystem cmd/response traffic,
        not log data.
    ``0x99`` DIAG_QSR4_EXT_MSG_TERSE_F — QSR4-compressed F3 messages;
        need the companion ``.qdb`` QShrink4 database to render text.

Opcode values and their ``DIAG_*_F`` names are DIAG **interface
constants** — fixed command-code bytes and their canonical macro names from
the baseband command interface (``diagcmd.h``). ``OPCODE_NAMES`` is
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
# inner LOG_F. See ``parse_subsys_v2_header``.
_MULTI_RADIO_WRAPPER_OFFSET: dict[int, int] = {
    0x98: 8,  # [0]=0x98, [1]=radio_id, [2:4]=pad, [4:8]=tx_mask, [8:]=inner 0x10 frame
}

# DIAG_SUBSYS_CMD_VER_2_F (0x80) wrapper layout — subsystem DIAG_SERV (0x12).
#
# These bodies are not compressed log batches and there is no codec: they are
# a FILE being streamed to the host (the build's ``qdsp6m.qdb``) by
# ``diag_qshrink4_daemon`` over a small open/read/close protocol. Evidence:
# 741/742 RG650V bodies and 426/426 Wistron LV55 bodies equal
# ``qdb[offset:offset+len]`` byte-for-byte. See ``diaggrok.diag_serv_file``
# for the transfer-level reassembler.
_SUBSYS_0x80_READ_HEADER_LEN = 27   # record_type=2, data starts here
_SUBSYS_0x80_MIN_LEN = 16           # enough to read record_type @14
_SUBSYS_0x80_MORE_DATA_BIT = 0x8000

DIAG_SERV_SUBSYSTEM = 0x12  # body[1] — the only subsystem carrying this protocol

# ``record_type`` @[14:16] is the file-transfer OPERATION. Active injection on
# a T99W175 plus the modem firmware's own handler symbols
# (``diag_qshrink4_file_{list,open,read,close}_handler``) establish the
# mapping: rec-0 is the File List, rec-1 the OPEN, rec-2 READ, rec-3 CLOSE.
# The four handlers map one-to-one onto record_types 0/1/2/3. (A passive-only
# reading tends to mislabel rec-0 as "OPEN" and rec-1 as "OPEN_ACK".)
DIAG_SERV_FILE_LIST = 0  # list: guid_count @16, then per GUID: guid @18 + size @34
DIAG_SERV_OPEN = 1       # bind: guid @16 + handle @32
DIAG_SERV_READ = 2       # data: handle @16, offset @18, len @22, bytes @27
DIAG_SERV_CLOSE = 3      # teardown: handle @16

# A FILE_LIST is a LIST: `guid_count` @[16:18], then a packed array of
# (guid[16], size u32 LE) entries starting at [18]. So an N-file list is exactly
# ``18 + 20*N`` bytes — which makes the FRAME LENGTH a second, independent
# witness to N, recoverable without trusting the count field at all.
_FILE_LIST_ENTRIES_OFFSET = 18
_FILE_LIST_ENTRY_LEN = 20        # guid (16) + file_size u32 LE (4)

_RECORD_TYPE_MIN_LEN = {
    DIAG_SERV_FILE_LIST: _FILE_LIST_ENTRIES_OFFSET + _FILE_LIST_ENTRY_LEN,  # 38 — one entry
    DIAG_SERV_OPEN: 33,
    DIAG_SERV_READ: _SUBSYS_0x80_READ_HEADER_LEN,
    DIAG_SERV_CLOSE: 18,
}


def swap_guid_layout(guid: bytes) -> bytes:
    """Convert a QShrink4 GUID between its two on-the-wire byte layouts.

    The same 16-byte GUID is stored in **two different byte orders** depending on
    where you harvest it, and neither side ever says so:

    ==============================  ==========================================
    layout                          where it appears
    ==============================  ==========================================
    **mixed-endian** (groups 1-3     the DIAG wire — ``FILE_LIST``/``OPEN``
    byte-reversed)                   frames; therefore ``header.guid_str()``,
                                     the ``.scan.json`` ``diag_serv.guid``
                                     field, and the ``qsr4_qdb`` corpus key
    **RFC-4122** (all groups in      the ``\\x7fQDB`` file header at ``[4:20]``;
    order)                           therefore the ``<guid>.qdb`` filename and
                                     the ``<guid>`` in
                                     ``diag_qsr4_guid_list.xml``
    ==============================  ==========================================

    So the *same* database is ``d17b0980-ef05-0851-e3f8-933c5c5c9020`` on the
    wire and ``80097bd1-05ef-5108-e3f8-933c5c5c9020`` in the vendor's own
    filename. A string compare between a captured GUID and a vendor artifact
    therefore fails **even when the matching qdb is in hand** — measured on a
    T99W175, and corroborated on RG650V (``45b4621f`` / ``1f62b445``) and
    LV55 (``9f1532ab`` / ``ab32159f``) artifacts.

    Only the first three groups differ (4-, 2- and 2-byte fields, each
    byte-reversed); groups 4 and 5 are byte arrays and are identical in both.
    The conversion is its own inverse, so one function serves both directions.

    Raises ``ValueError`` on anything that is not exactly 16 bytes — a
    silently-truncated GUID would compare unequal for the wrong reason.
    """
    if len(guid) != 16:
        raise ValueError(f"GUID must be 16 bytes, got {len(guid)}")
    return guid[0:4][::-1] + guid[4:6][::-1] + guid[6:8][::-1] + guid[8:16]


def _render_guid(guid: bytes) -> str:
    """Render 16 raw GUID bytes as 8-4-4-4-12, no layout conversion."""
    h = guid.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


@dataclass(frozen=True)
class DiagServFileEntry:
    """One ``(guid, file_size)`` pair announced by a FILE_LIST response.

    A File List may announce more than one file — one per served message
    database. Every device observed so far (including a live active pull on
    an LM960A18 / SDX24) announces exactly one. Reading a single pair at fixed
    offsets cannot tell a one-file list from a three-file list, so the whole
    list is decoded. See :attr:`Subsys0x80Header.guid_entries`.
    """

    guid: bytes       # 16 raw wire bytes (mixed-endian; see swap_guid_layout)
    file_size: int    # u32 LE — this file's total length in bytes

    def guid_str(self) -> str:
        """The wire (mixed-endian) spelling — matches the ``qsr4_qdb`` corpus key."""
        return _render_guid(self.guid)

    def guid_str_file_layout(self) -> str:
        """The RFC-4122 spelling — matches the vendor's ``<guid>.qdb`` filename."""
        return _render_guid(swap_guid_layout(self.guid))


@dataclass
class Subsys0x80Header:
    """Parsed header of a ``DIAG_SUBSYS_CMD_VER_2_F`` DIAG_SERV file-transfer frame.

    Field applicability depends on ``record_type`` — inapplicable fields are
    ``None`` rather than silently decoded from bytes that mean something else.

    ``counter`` is the raw u16 @[10:12]. Its **bit 15 is a more-data-follows
    flag**, not part of the sequence number: every chunk of a transfer carries
    it set except the last. Read ``sequence`` / ``more_data`` instead of
    interpreting ``counter`` directly.

    ``[0:12]`` is the standard ``DIAG_SUBSYS_CMD_VER_2_F``
    **delayed-response** header — ``status`` u32 @[4:8], ``delayed_rsp_id`` u16
    @[8:10], and ``counter`` is that mechanism's ``rsp_cnt`` (bit 15 = more
    fragments follow). The DIAG_SERV file protocol (``format_id`` +
    ``record_type`` + record fields) begins at ``[12:]``. Only the bulk READ
    stream uses the delayed mechanism: FILE_LIST / OPEN / CLOSE are immediate
    responses and carry ``delayed_rsp_id == 0``.
    """
    subsystem: int              # offset 1 — 0x12 (DIAG_SERV)
    command: int                # offset 2 — 0x16 on both observed builds
    version: int                # offset 3 — 0x08 on both observed builds
    counter: int                # offsets 10-11 (u16 LE) — see sequence/more_data
    format_id: int              # offsets 12-13 (u16 LE) — 1 on both builds
    record_type: int            # offsets 14-15 (u16 LE) — DIAG_SERV_* above
    status: int = 0                 # offsets 4-7 (u32 LE) — DIAG_SUBSYS status; 0 = success
    delayed_rsp_id: int = 0         # offsets 8-9 (u16 LE) — delayed-response id; 0 unless READ
    handle: int | None = None       # READ/CLOSE @[16:18]; OPEN @[32]
    file_offset: int | None = None  # READ @[18:22] (u32 LE)
    read_len: int | None = None     # READ @[22:24] (u16 LE)
    payload: bytes = b""            # READ @[27:] — the served file's bytes
    guid: bytes | None = None       # FILE_LIST first entry; OPEN @[16:32]
    file_size: int | None = None    # FILE_LIST first entry's size (u32 LE)
    guid_count: int | None = None   # FILE_LIST @[16:18] (u16 BE) — GUIDs in the list
    #: Every ``(guid, size)`` entry a FILE_LIST announces, in wire order; empty
    #: for every other record_type. ``guid`` / ``file_size`` above are the FIRST
    #: entry, kept as scalars because the reassembler, the ``.scan.json`` schema
    #: and ``diag_serv_pull`` all read them.
    guid_entries: tuple[DiagServFileEntry, ...] = ()
    #: Bytes after the last whole entry — nonzero means part of the frame did not
    #: decode, which is how an unknown trailing field would otherwise stay invisible.
    file_list_trailing_bytes: int = 0

    @property
    def guid_count_matches_entries(self) -> bool | None:
        """Whether ``guid_count`` agrees with the entry count the LENGTH implies.

        ``None`` for non-FILE_LIST records (which carry no count and no list).

        This is the cross-check that settles how ``guid_count`` is encoded.
        At N=1 it cannot: the observed frames carry ``00 01`` at [16:18],
        which reads as 1 big-endian and is equally consistent with "byte[17] is
        the count, byte[16] reserved", and both agree with the one entry the
        38-byte frame holds. At N>1 the readings diverge — a three-file list is
        ``03`` somewhere and 78 bytes long — so the first device that serves more
        than one qdb decides it.
        """
        if self.record_type != DIAG_SERV_FILE_LIST:
            return None
        return self.guid_count == len(self.guid_entries)

    @property
    def sequence(self) -> int:
        """Chunk sequence number — ``counter`` with the more-data flag masked off."""
        return self.counter & ~_SUBSYS_0x80_MORE_DATA_BIT

    @property
    def more_data(self) -> bool:
        """True while more chunks follow; False on a transfer's final chunk."""
        return bool(self.counter & _SUBSYS_0x80_MORE_DATA_BIT)

    @property
    def is_file_read_chunk(self) -> bool:
        """True for a well-formed READ whose body length matches ``read_len``."""
        return self.record_type == DIAG_SERV_READ and len(self.payload) == self.read_len

    def guid_str(self) -> str | None:
        """The 16-byte GUID rendered 8-4-4-4-12, or None when this frame has none.

        These are the **wire** bytes, which are mixed-endian — this string
        matches the ``qsr4_qdb`` corpus key but NOT the vendor's ``<guid>.qdb``
        filename. Use :meth:`guid_str_file_layout` for that.
        """
        if self.guid is None:
            return None
        h = self.guid.hex()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"

    def guid_str_file_layout(self) -> str | None:
        """The same GUID in the layout the qdb FILE header and vendor use.

        This is what a ``<guid>.qdb`` filename and the ``<guid>`` element of
        ``diag_qsr4_guid_list.xml`` carry. Compare against those, never
        :meth:`guid_str`.
        """
        if self.guid is None:
            return None
        h = swap_guid_layout(self.guid).hex()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"

    def describe(self) -> str:
        """One-line human label for this frame."""
        if self.record_type == DIAG_SERV_READ:
            return (f"DIAG_SERV file-read chunk @0x{self.file_offset:x} "
                    f"len={self.read_len}")
        if self.record_type == DIAG_SERV_FILE_LIST:
            return (f"DIAG_SERV file-list {self.guid_str()} "
                    f"count={self.guid_count} size={self.file_size}")
        if self.record_type == DIAG_SERV_OPEN:
            return f"DIAG_SERV file-open {self.guid_str()} handle={self.handle}"
        if self.record_type == DIAG_SERV_CLOSE:
            return f"DIAG_SERV file-close handle={self.handle}"
        return f"DIAG_SERV record_type={self.record_type} (unrecognized)"


def _is_final_chunk_step(prev: int, cur: int) -> bool:
    """True when ``prev -> cur`` is a +1 step on which the more-data flag cleared.

    That is a transfer ending cleanly on its last chunk, not a dropped one.
    """
    return (
        bool(prev & _SUBSYS_0x80_MORE_DATA_BIT)
        and not (cur & _SUBSYS_0x80_MORE_DATA_BIT)
        and cur == ((prev & ~_SUBSYS_0x80_MORE_DATA_BIT) + 1) & ~_SUBSYS_0x80_MORE_DATA_BIT
    )


def parse_subsys_v2_header(body: bytes) -> Subsys0x80Header | None:
    """Parse a DIAG_SUBSYS_CMD_VER_2_F (0x80) frame body into its header fields.

    ``body`` is the unescaped HDLC frame with the trailing 2-byte CRC already
    stripped. Returns None when the opcode at offset 0 is not 0x80, when the
    frame is too short to reach ``record_type``, or when it is too short for
    the layout its own ``record_type`` implies.

    Frames **shorter than 27 bytes** are accepted: OPEN (35 B) and CLOSE
    (19 B) are well-formed frames with their own layouts, and a >= 27 floor
    would reject every CLOSE.

    The subsystem gate is load-bearing, not cosmetic: ``0x80`` is only one
    byte, and non-DIAG data that HDLC-splits into frames starting with it will
    otherwise "decode" into file-opens announcing multi-gigabyte files. A raw
    RTCM capture is a real-world example.
    """
    if (len(body) < _SUBSYS_0x80_MIN_LEN
            or body[0] != 0x80
            or body[1] != DIAG_SERV_SUBSYSTEM):
        return None
    status = struct.unpack_from("<I", body, 4)[0]
    delayed_rsp_id = struct.unpack_from("<H", body, 8)[0]
    counter, format_id, record_type = struct.unpack_from("<HHH", body, 10)
    if len(body) < _RECORD_TYPE_MIN_LEN.get(record_type, _SUBSYS_0x80_MIN_LEN):
        return None
    hdr = Subsys0x80Header(
        subsystem=body[1],
        command=body[2],
        version=body[3],
        counter=counter,
        format_id=format_id,
        record_type=record_type,
        status=status,
        delayed_rsp_id=delayed_rsp_id,
    )
    if record_type == DIAG_SERV_READ:
        hdr.handle = struct.unpack_from("<H", body, 16)[0]
        hdr.file_offset = struct.unpack_from("<I", body, 18)[0]
        hdr.read_len = struct.unpack_from("<H", body, 22)[0]
        hdr.payload = bytes(body[_SUBSYS_0x80_READ_HEADER_LEN:])
    elif record_type == DIAG_SERV_FILE_LIST:
        # guid_count @[16:18]. Read BIG-ENDIAN: the observed FILE_LIST frames
        # both carry bytes `00 01`, and the frame is exactly 38 B — room for ONE
        # (guid[18:34], size[34:38]) entry. A little-endian read (0x0100=256)
        # contradicts that single entry; big-endian (=1) matches both the frame
        # and live-hardware "guid_count=1". At N=1 (every observed device ships
        # one qdb) this cannot be told from "byte[17] count, byte[16]
        # reserved"; a first multi-GUID capture would settle it. See
        # `guid_count_matches_entries`, which is that comparison.
        hdr.guid_count = struct.unpack_from(">H", body, 16)[0]
        # Decode the WHOLE list. The entry count comes from the frame's own
        # length, never from guid_count, so the two stay independent witnesses:
        # trusting the count would make it unfalsifiable, and capping the list at
        # it would hide a device announcing more files than it claims.
        span = len(body) - _FILE_LIST_ENTRIES_OFFSET
        n_entries, hdr.file_list_trailing_bytes = divmod(span, _FILE_LIST_ENTRY_LEN)
        entries = []
        for i in range(n_entries):
            base = _FILE_LIST_ENTRIES_OFFSET + i * _FILE_LIST_ENTRY_LEN
            entries.append(DiagServFileEntry(
                guid=bytes(body[base:base + 16]),
                file_size=struct.unpack_from("<I", body, base + 16)[0],
            ))
        hdr.guid_entries = tuple(entries)
        # The scalars stay the FIRST entry: OPEN binds it and the reassembler
        # sizes against it, so pointing them at the last file would open one and
        # expect another's length.
        hdr.guid = hdr.guid_entries[0].guid
        hdr.file_size = hdr.guid_entries[0].file_size
    elif record_type == DIAG_SERV_OPEN:
        hdr.guid = bytes(body[16:32])
        hdr.handle = body[32]
    elif record_type == DIAG_SERV_CLOSE:
        hdr.handle = struct.unpack_from("<H", body, 16)[0]
    return hdr


class DiagServTransfer:
    """Geometry of one DIAG_SERV file transfer — offsets and lengths, no bytes.

    This is the half of a transfer that a *census* needs: which file was
    announced (guid, size), how much of it arrived, in how many chunks, with
    what holes, and whether it finished. It deliberately does **not** retain
    the served payload, so a corpus walk can tally a 7 MB transfer for the
    cost of a dict of ints.

    :class:`diaggrok.diag_serv_file.DiagServFileReassembler` extends this with
    payload retention and :meth:`contiguous_bytes`. The split keeps a scan
    summary and a full reassembly from ever disagreeing about whether a
    transfer is complete: there is one definition of ``gaps`` / ``complete``,
    inherited, not two that can drift.

    It lives here, beside :func:`parse_subsys_v2_header`, rather than in
    ``diag_serv_file`` because :class:`HdlcStats` holds one and ``diag_serv_file``
    already imports *from* this module — the other direction would be circular.
    """

    def __init__(self) -> None:
        # offset -> chunk length. Payload, when kept at all, is a subclass's
        # business; the geometry is complete without it.
        self._lengths: dict[int, int] = {}
        self.guid: bytes | None = None
        self.file_size: int | None = None
        self.handle: int | None = None
        self.closed: bool = False
        #: READ frames whose body disagreed with their declared ``read_len``.
        #: A runt chunk is never folded in as data; on the scan path it is
        #: counted rather than raised (see :meth:`add`).
        self.runt_chunks: int = 0
        #: How many ``FILE_LIST`` frames (the transfer-announcing record_type 0)
        #: this capture carried, and the distinct GUIDs they announced, in
        #: first-seen order. The attribute keeps the name ``opens`` — it is a
        #: persisted ``.scan.json`` sidecar key predating the record-type
        #: naming — but it counts announces, one per transfer. One tally serves a
        #: whole capture, so a capture carrying TWO transfers would otherwise
        #: overwrite ``guid``/``file_size`` and fold both offset spaces into one
        #: — overlapping chunks clobbering each other while ``complete``
        #: describes a file that never existed. That is a hole reporting itself
        #: as whole, which is worse than the shifted-file failure the
        #: offset-keyed design exists to prevent, so it is recorded instead of
        #: merged. Follows the :attr:`qshrink4_bindings` precedent: keep the
        #: list, surface the disagreement, let the reader decide.
        self.opens: int = 0
        #: Every GUID any FILE_LIST in this capture announced — the GUID
        #: manifest. A single list may announce several files, so this is NOT one
        #: entry per transfer; see :attr:`multi_transfer` for that.
        self.announced_guids: list[bytes] = []
        #: The file each FILE_LIST actually leads to — its FIRST entry, which is
        #: what OPEN binds. Kept apart from ``announced_guids`` because "this
        #: capture holds two interleaved transfers" and "this device offered a
        #: choice of three files" are different claims with different
        #: consequences for ``complete``.
        self._transfer_guids: list[bytes] = []

    # -- accumulation ------------------------------------------------------

    def add(self, header: "Subsys0x80Header") -> None:
        """Fold one parsed ``0x80`` header into the transfer state.

        Raises ``ValueError`` when a READ frame's body length disagrees with
        its declared ``read_len`` — a runt frame must never be trusted as
        data. Callers walking untrusted bytes should use :meth:`add_lenient`.
        """
        if header.record_type == DIAG_SERV_FILE_LIST:
            self.opens += 1
            # The manifest gets EVERY announced file; recording only the first
            # would hide a multi-file list one layer up from the FILE_LIST
            # parser that decodes it.
            for entry in header.guid_entries:
                if entry.guid not in self.announced_guids:
                    self.announced_guids.append(entry.guid)
            if header.guid is not None and header.guid not in self._transfer_guids:
                self._transfer_guids.append(header.guid)
            # First-wins, matching HdlcStats.qshrink4_binding(): a second FILE_LIST
            # is a second transfer, not a correction to the first one.
            if self.guid is None:
                self.guid = header.guid
                self.file_size = header.file_size
        elif header.record_type == DIAG_SERV_OPEN:
            if self.guid is None:
                self.guid = header.guid
            self.handle = header.handle
        elif header.record_type == DIAG_SERV_CLOSE:
            self.closed = True
        elif header.record_type == DIAG_SERV_READ:
            if len(header.payload) != header.read_len:
                raise ValueError(
                    f"truncated READ chunk at offset 0x{header.file_offset:x}: "
                    f"read_len={header.read_len} but body carries "
                    f"{len(header.payload)} bytes"
                )
            if header.read_len:  # len=0 READs bookend the transfer; not data
                self._store(header)

    def add_lenient(self, header: "Subsys0x80Header") -> None:
        """:meth:`add`, but a runt READ increments :attr:`runt_chunks`.

        The scan path walks whatever bytes a capture holds, and one truncated
        chunk must not take down every other sidecar block with it — the
        census still wants to report the rest of the transfer.
        """
        try:
            self.add(header)
        except ValueError:
            self.runt_chunks += 1

    def _store(self, header: "Subsys0x80Header") -> None:
        """Record one accepted READ chunk. Subclasses also keep its bytes."""
        self._lengths[header.file_offset] = header.read_len

    # -- views -------------------------------------------------------------

    def chunk_count(self) -> int:
        return len(self._lengths)

    def bytes_held(self) -> int:
        return sum(self._lengths.values())

    def gaps(self) -> list[tuple[int, int]]:
        """``(start, end)`` byte ranges missing *between* the chunks held.

        A transfer caught mid-flight has no gap before its first chunk — that
        is a shorter file, not a hole — so the span before ``min(offset)`` is
        reported by :meth:`first_offset`, not here.
        """
        out: list[tuple[int, int]] = []
        offsets = sorted(self._lengths)
        for prev, nxt in zip(offsets, offsets[1:]):
            end = prev + self._lengths[prev]
            if end != nxt:
                out.append((end, nxt))
        return out

    def first_offset(self) -> int | None:
        return min(self._lengths) if self._lengths else None

    def contiguous_bytes(self) -> bytes:
        """Not available without payload retention — see the reassembler."""
        raise NotImplementedError(
            "DiagServTransfer tracks geometry only; use "
            "diaggrok.diag_serv_file.DiagServFileReassembler for the bytes"
        )

    def coverage_fraction(self) -> float | None:
        """Held bytes / announced file size, or None without an OPEN frame."""
        if not self.file_size:
            return None
        return self.bytes_held() / self.file_size

    @property
    def multi_transfer(self) -> bool:
        """True when this capture carries more than one distinct file TRANSFER.

        Counted over the file each FILE_LIST leads to (its first entry, the one
        OPEN binds) — deliberately not over :attr:`announced_guids`. One list
        offering three files is not two interleaved transfers: nothing shares an
        offset space and only the opened file is ever read, so deriving this from
        the manifest would force :attr:`complete` False on a perfectly good pull
        the moment a multi-GUID device appears. Identical on every capture
        observed so far, where each list announces exactly one file.
        """
        return len(self._transfer_guids) > 1

    @property
    def complete(self) -> bool:
        """True when every announced byte arrived, contiguously, from offset 0.

        Always False for a :attr:`multi_transfer` capture. The chunks of two
        transfers share one offset space here, so "held == announced size"
        stops meaning "that file is complete" — it could be two half-files whose
        offsets happen to sum. A merged tally must not claim a whole file.
        """
        if not self.file_size or self.multi_transfer:
            return False
        return (
            self.first_offset() == 0
            and not self.gaps()
            and self.bytes_held() == self.file_size
        )

    def guid_str(self) -> str | None:
        if self.guid is None:
            return None
        h = self.guid.hex()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"

    def summary(self) -> str:
        """One-line status suitable for a capture-quality report."""
        size = f"{self.file_size}" if self.file_size is not None else "unknown"
        frac = self.coverage_fraction()
        pct = f"{100 * frac:.1f}%" if frac is not None else "?"
        return (
            f"DIAG_SERV file transfer: guid={self.guid_str() or '?'} "
            f"size={size} held={self.bytes_held()} ({pct}) "
            f"chunks={self.chunk_count()} gaps={len(self.gaps())} "
            f"{'COMPLETE' if self.complete else 'PARTIAL'}"
        )


# DIAG_SECURE_LOG_F (0x9E) cleartext-envelope layout. The body @24+ is mostly
# ENCRYPTED (entropy 7.998 b/B, all 256 byte values, 0.39% zeros — measured on
# 125,798 RM520N-GL frames) and undecodable without the modem's secure
# (TrustZone) keys. The header IS recoverable. The same envelope holds on a
# Sierra EM9291 (SDX65): 25,992/25,992 frames parse, version=0x01 +
# type_flags=0xc2 uniformly, sequence@12 monotonic-nondecreasing 99.77%
# (17956..210665), body@24+ entropy 7.996 b/B with 0.39% zeros. So this is a
# platform-wide envelope, not a single-vendor quirk: the recoverable header
# generalizes across vendors; only the keyed body stays opaque.
#
# The body @24+ is NOT opaque from byte 0 — it carries a CLEARTEXT inner
# sub-header before the ciphertext. It is visible on an RG650V (SDX72; 2902
# frames over 2 captures), whose near-fixed 100-B body has lower entropy
# (6.33 b/B vs 7.998). Inner sub-header (offsets RELATIVE to body @24):
#   body[0:4]  per-record VARYING (100% distinct on RG650V and EM9291) — IV /
#              nonce / per-record counter candidate.
#   body[4:6]  build/vendor tag bytes — body[5] is build-CONST but NOT universal:
#              0x13 (RG650V SDX72/Quectel), 0xcc (EM9291 SDX65/Sierra), 0x00
#              (T99W640 SDX72/Foxconn AND RM520N-GL SDX62/Quectel). body[4] is
#              const on RG650V (0x4d) but small-varying on EM9291 (0x1c..0x20)
#              — semantics unknown, deliberately not asserted.
#   body[6:8]  u16 LE inner sub-header tag — a per-build constant, NOT a
#              universal record tag:
#                  0x0110  RG650V   SDX72 (Quectel) + EM9291 SDX65 (Sierra)
#                  0x0000  T99W640  SDX72 (Foxconn)   — 5,260/5,260
#                  0x0111  RM520N-GL SDX62 (Quectel)  — 3/3 (small sample)
#              Exposed as SecureLog0x9EHeader.inner_tag (value is build-dependent;
#              do not assert a specific constant).
#   body[8:]   ciphertext — stays keyed/opaque (the encryption begins here, not
#              at frame byte 24). Deep-body entropy is ~8.0 b/B on every family
#              measured (RG650V's lower 6.33 comes from the near-fixed 100-B
#              short record exposing the cleartext prefix, not a less-encrypted
#              body).
_SECURE_LOG_0x9E_BODY_OFFSET = 24
_SECURE_LOG_0x9E_SEQ_OFFSET = 12   # u32 LE monotonic event counter
_SECURE_LOG_0x9E_INNER_TAG_OFFSET = 6   # u16 LE within body; build-specific (not universal)


@dataclass
class SecureLog0x9EHeader:
    """Cleartext envelope of a ``DIAG_SECURE_LOG_F`` (0x9E) frame.

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
                                   # sub-header tag (NOT a universal 0x0110
                                   # — observed 0x0110 / 0x0000 / 0x0111 across
                                   # families). None when body < 8 B. The
                                   # ciphertext proper starts at body[8:].


def parse_secure_log_envelope(body: bytes) -> "SecureLog0x9EHeader | None":
    """Parse the CLEARTEXT envelope of a ``DIAG_SECURE_LOG_F`` (0x9E) frame.

    ``body`` is the unescaped HDLC frame with the trailing 2-byte CRC stripped.
    Returns None if too short or the opcode at offset 0 is not 0x9E. The
    ``body`` field of the result is the ENCRYPTED payload — opaque
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


# DIAG_QSR_EXT_MSG_TERSE_F (0x92) — legacy (pre-QSR4) terse F3 envelope.
# Clean-room characterized from 210,891 records on an EG25-G (MDM9207) capture
# and validated against an EM7455 (MDM9230; 1,597,412 frames) and a second
# EG25-G firmware build (136,213 frames). The STRUCTURAL envelope is
# cross-chipset-invariant — all three sets parse 100% and ts is monotonic on
# all — but several sub-fields are CHIPSET-SPECIFIC (const within a chipset,
# divergent across). Layout (offsets/widths) is universal; field VALUES are not:
#   [0]     u8   opcode = 0x92            (const, universal)
#   [1]     u8   = 0x00                   (const, universal — both chipsets)
#   [2:4]   u16  num_args (LE)            — body_len == 24 + 4*num_args (100%, universal)
#   [4]     u8   QSR terse format/version marker — CHIPSET-SPECIFIC, NOT universal:
#                0x09 const on MDM9207 (EG25-G), 0x00 const on MDM9230 (EM7455).
#                The parser deliberately does NOT assert this byte (see below).
#                Exactly ONE distinct value per chipset across 473,602 (EG25-G)
#                and 637,727 (EM7455) frames. That matters because a model with
#                the timestamp as a u64 at [4:12] would make this byte the
#                clock's LOW byte, and a clock's low byte cannot be constant over
#                a million frames. The field is a u56 at [5:12].
#   [5:12]  u56  TIMESTAMP (LE) — the DIAG u64 clock with its low 8 bits dropped:
#                ``u56 == (diag_u64_ts >> 8)``. ``timestamp`` reports the low u32
#                of it; ``timestamp64`` reports ``u56 << 8``, i.e. the SAME scale
#                as the 0x79/0x99 u64 ``ts``, so 0x92 is directly co-temporally
#                correlatable. [9:12] is the clock's top 24 bits, not a separate
#                descriptor field (a low word stays monotonic while its high word
#                is constant, so [5:9]'s monotonicity says nothing about [9:12]).
#                Measured on two unrelated chipsets:
#                  u56@5 == (co-temporal 0x79 u64) >> 8 — within 65536 ticks for
#                    100.00% (EG25-G) / 99.90% (EM7455) of frames;
#                  the EG25-G capture carries exactly ONE [9:12] value, 011171 =
#                    bits [32:56] of its own 0x79 u64 0x011171386BE8B809;
#                  the EM7455 capture carries TWO, 000010 -> 0110f7, incrementing
#                    when the u32 WRAPPED mid-capture — which a descriptor does not do.
#   [12:14] u16  line (LE)   ─┐ IDENTICAL to the plaintext 0x79 DIAG_EXT_MSG_F
#   [14:16] u16  ss_id (LE)   ├ descriptor block, at the SAME offsets — see
#   [16:20] u32  ss_mask (LE)─┘ ``f3correlate._parse_ext_msg_f``.
#                Evidence, measured within single captures so the build is
#                fixed, on two unrelated chipsets (frame-weighted):
#                  ss_id  @14 ∈ the same capture's self-decoding 0x79 ss_id set:
#                             93.6% (EM7455/MDM9230)  92.2% (EG25-G/MDM9207)
#                  ss_mask@16 single-bit:  97.6% / 95.8%  (max 3 bits set — a
#                             level MASK, not an enum; 0x04 = the familiar
#                             MSG_LVL_HIGH bit)
#                NEGATIVE CONTROL — the same two tests one byte off (@13/@17)
#                score 0.05-0.11%, i.e. the reading collapses when shifted, so
#                these are the field boundaries rather than a lucky alignment.
#                The residual ~7% of ss_id values absent from the 0x79 set is
#                expected and not a defect: a subsystem whose sites were ALL
#                shrunk has no plaintext representation to be compared against.
#                line@12 is load-bearing: on-device INDEX attribution accepts a
#                wire hash only at a row whose ``line`` equals this field, and
#                resolves 964/964 hashes.
#   [20:24] u32  message hash (LE)        — QSR message-DB key. Hash vocabularies
#                are NOT disjoint per build, so one message DB can serve more
#                than one build. Full-capture measurement, EG25-G (Quectel,
#                MDM9207) vs EM7455 (Sierra, MDM9230) — two vendors, two
#                chipsets, unrelated build trees:
#                  4,129 vs 1,278 distinct hashes, **761 shared**
#                  (18.4% of A's, 59.5% of B's; ~0.001 expected by chance, so the
#                   overlap is real rather than 32-bit collision)
#                  shared hashes carry **73.0% / 92.2% of FRAME VOLUME**
#                and the shared rows agree on everything except location:
#                  ss_id 99.9%  ss_mask 99.6%  num_args 99.6%  —  line only 8.8%
#                  (random-pair control: ss_id 3.7%, num_args 18.8%)
#                That is the signature of a key on the MESSAGE (same subsystem,
#                severity and arg count) whose source line moved between trees —
#                i.e. common baseband code shared across MDM parts. Practical
#                consequence: a legacy-QSR string DB obtained for ONE MDM build
#                should render the majority of 0x92 traffic on others.
#                SAME role as the 0x99 QSR4 hash: rendering the text is
#                message-DB-gated (no MDM9207/MDM9230 qdb is available), but the
#                STRUCTURED envelope (ts, hash, args) decodes offline.
#   [24:]   args[]  — num_args * u32 (LE)
# So 0x92's text-render blocker is IDENTICAL to the 0x99 qdb gate, not a novel
# undecodable format. The parser asserts ONLY opcode + the length relation (never
# the chipset-specific marker at [4]), which is why it generalizes across
# MDM9207/MDM9230 unchanged: the version marker varies WITHOUT a layout change,
# the one legitimate case where a permissive (non-version-asserting) parse is
# correct rather than a mis-parse risk.
_QSR_0x92_HEADER_LEN = 24
_QSR_0x92_NUM_ARGS_OFFSET = 2
_QSR_0x92_TS_OFFSET = 5
_QSR_0x92_TS56_LEN = 7      # [5:12] — the u32 above plus the 3 high bytes
_QSR_0x92_LINE_OFFSET = 12
_QSR_0x92_SS_ID_OFFSET = 14
_QSR_0x92_SS_MASK_OFFSET = 16
_QSR_0x92_HASH_OFFSET = 20


@dataclass
class Qsr0x92Header:
    """Structured envelope of a legacy ``DIAG_QSR_EXT_MSG_TERSE_F`` (0x92) frame.

    The message TEXT is render-gated on the build's QSR message DB (``hash``
    indexes it — the same role as the 0x99 QSR4 hash), which is not available
    for MDM9207. But the envelope decodes offline: ``num_args``, a monotonic
    ``timestamp``, the message ``hash`` (message identity), and the raw
    ``args``. Clean-room characterized from EG25-G (MDM9207) captures.
    """
    num_args: int      # offsets 2-3 (u16 LE) — body_len == 24 + 4*num_args
    timestamp: int     # offsets 5-8 (u32 LE) — the LOW word of timestamp64
    hash: int          # offsets 20-23 (u32 LE) — QSR message-DB key. NOT per-build:
                       # 761 hashes are shared between an MDM9207 and an MDM9230
                       # build, carrying 73%/92% of frame volume (see above).
    args: tuple        # num_args * u32 LE, starting at offset 24
    # The full clock: u56 at [5:12] shifted up 8, so it is on the SAME scale as
    # the 0x79/0x99 u64 ``ts`` and can be compared to it directly. The
    # low 8 bits are not on the wire and read as zero — a sub-tick truncation,
    # not a missing epoch.
    timestamp64: int = 0
    # The (line, ss_id, ss_mask) descriptor at [12:20] — the SAME block plaintext
    # 0x79 carries at the same offsets. ``line`` is the message site's
    # source line (the key on-device INDEX attribution matches on);
    # ``ss_mask`` is a RUNTIME readback like the 0x79 one — the firmware emitted
    # this frame because the site's mask intersected the armed mask — not the
    # build-time declared mask the qdb-resolved 0x99 path reports.
    line: int = 0      # offsets 12-13 (u16 LE)
    ss_id: int = 0     # offsets 14-15 (u16 LE)
    ss_mask: int = 0   # offsets 16-19 (u32 LE)


def parse_qsr_terse_0x92_envelope(body: bytes) -> "Qsr0x92Header | None":
    """Parse the envelope of a legacy ``DIAG_QSR_EXT_MSG_TERSE_F`` (0x92) frame.

    ``body`` is the unescaped HDLC frame with the trailing 2-byte CRC stripped.
    Returns None if too short, if the opcode at offset 0 is not 0x92, or if the
    length does not match ``24 + 4*num_args`` (the 100%-verified invariant) — so
    a stray/corrupt frame is rejected, not mis-parsed. The message text is NOT
    rendered (DB-gated); the structured envelope fields are.
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
    ts56 = int.from_bytes(
        body[_QSR_0x92_TS_OFFSET:_QSR_0x92_TS_OFFSET + _QSR_0x92_TS56_LEN], "little")
    return Qsr0x92Header(
        num_args=num_args, timestamp=timestamp, hash=hash_, args=tuple(args),
        timestamp64=ts56 << 8,
        line=struct.unpack_from("<H", body, _QSR_0x92_LINE_OFFSET)[0],
        ss_id=struct.unpack_from("<H", body, _QSR_0x92_SS_ID_OFFSET)[0],
        ss_mask=struct.unpack_from("<I", body, _QSR_0x92_SS_MASK_OFFSET)[0],
    )


# --- 0x4B / subsys 0x12 / cmd 0x0222 — the QSHRINK4 diag_id binding ---------
#
# DIAG_SUBSYS_CMD_F body layout, CRC stripped:
#   [0]     opcode = 0x4B
#   [1]     subsys_id = 0x12 (the DIAG service itself)
#   [2:4]   subsys_cmd (u16 LE) = 0x0222
#   [4]     version      — observed 1 in every capture
#   [5]     entry_count  — libdiag.so's own `diagid_entry_count`
#   [6:]    entry_count * [u8 diag_id][u8 name_len][char name[name_len]]
#
# `name_len` INCLUDES the NUL terminator (5 for "APPS\0", 18 for
# "mdm/modem/root_pd\0"). That is what makes the walk SELF-CHECKING: a
# wrong reading leaves trailing bytes rather than landing exactly on the
# end of the body, so this parser returns None instead of plausible junk.
#
# Spec: diag_hdlc_frame.ksy::qshrink4_binding_table. That .ksy is the source
# of truth — this is a port of it, not a re-derivation.
#
# DO NOT hardcode `1 = APPS, 2 = mdm/modem/root_pd`. All 8
# observations agree on that pair, but all three device trees behind them
# are SDX55-class. The frame exists precisely BECAUSE the mapping is
# per-device — the whole point is to read it.
_QSHRINK4_BINDING_SUBSYS = 0x12
_QSHRINK4_BINDING_CMD = 0x0222
_QSHRINK4_BINDING_HEADER_LEN = 6  # opcode + subsys + u16 cmd + version + count


@dataclass(frozen=True)
class Qshrink4BindingEntry:
    """One ``diag_id`` → protection-domain name binding."""
    diag_id: int
    name: str


@dataclass
class Qshrink4Binding:
    """The in-band QSHRINK4 ``diag_id`` binding table.

    A ``diag_id`` is a per-protection-domain logical channel on the shared
    DIAG path. This table is the only structure in a capture that *names*
    those peripherals — which matters because it is the index that says
    WHICH ``qdsp6m.qdb`` could resolve a given peripheral's hashed ``0x99``
    F3 / ``0x9D`` QSH-trace messages. Without it, a multi-PD capture has to
    be treated as having one symbol database.

    Emitted as an ordinary DIAG frame, so it survives in raw-HDLC captures
    that have no QMDL2 file prologue at all — which is most of them. It is
    the RESPONSE to ``DIAGNOSTIC_SERVICES_DIAGID_TABLE`` (request
    ``4B 12 22 02 01``; the bare four-byte form is silently dropped), which
    is why it appears in on-device ``diag_mdlog`` captures and in captures
    whose host tool sends that request at session start. Served by
    SDX55 / SDX62 parts; SDX20 and MDM9607 answer ``0x13``.
    """
    version: int
    entries: tuple[Qshrink4BindingEntry, ...]

    def as_map(self) -> dict[int, str]:
        """``{diag_id: pd_name}``. Convenience for the qdb-selection path."""
        return {e.diag_id: e.name for e in self.entries}


def parse_qshrink4_binding(body: bytes) -> "Qshrink4Binding | None":
    """Parse a ``0x4B`` / subsys ``0x12`` / cmd ``0x0222`` binding frame.

    ``body`` is the unescaped HDLC frame with the trailing 2-byte CRC
    already stripped — same contract as :func:`parse_subsys_v2_header`.

    Returns ``None`` for any frame that is not this ``(subsys, cmd)`` pair,
    and — importantly — also for one that IS but whose entry walk does not
    consume the body exactly. Trailing or missing bytes mean the reading is
    wrong, and saying so is better than returning a table that looks fine.
    """
    if len(body) < _QSHRINK4_BINDING_HEADER_LEN or body[0] != 0x4B:
        return None
    if body[1] != _QSHRINK4_BINDING_SUBSYS:
        return None
    if struct.unpack_from("<H", body, 2)[0] != _QSHRINK4_BINDING_CMD:
        return None

    version, entry_count = body[4], body[5]
    off = _QSHRINK4_BINDING_HEADER_LEN
    entries: list[Qshrink4BindingEntry] = []
    for _ in range(entry_count):
        if off + 2 > len(body):
            return None
        diag_id, name_len = body[off], body[off + 1]
        off += 2
        name = body[off:off + name_len]
        if len(name) != name_len:
            return None
        off += name_len
        entries.append(
            Qshrink4BindingEntry(
                diag_id=diag_id,
                # name_len counts the NUL; strip it for the Python string.
                name=name.rstrip(b"\x00").decode("ascii", "replace"),
            )
        )
    if off != len(body):
        return None  # the walk is wrong — say so rather than guess
    return Qshrink4Binding(version=version, entries=tuple(entries))


# DIAG_LOG_F (0x10) layout after HDLC unescape, CRC stripped:
#   [0]      opcode = 0x10
#   [1]      pending_msgs
#   [2:4]    outer_len (u16 LE)
#   [4:6]    inner_len (u16 LE)
#   [6:8]    log_code (u16 LE)
#   [8:16]   timestamp (u64 LE, 1.25 ms DIAG ticks) — this is the
#            OUTER HDLC LOG_F-header timestamp, equivalent to the DLF
#            file-format ts64 at the same offset. The INNER DIAG frame
#            ``log_time`` (parsed by ``diaggrok.frame.parse_outer_frame``
#            in a live-streaming client) is a SEPARATE
#            chipset-dependent high-frequency counter (~17.24 ns/tick on
#            SDX62, etc.). See the ``frame.py`` docstring.
#   [16:]    payload
_LOG_F_MIN_LEN = 16

# 0x9D DIAG_QSH_TRACE_PAYLOAD_F, for the scan-pass subsystem tally.
# Defined locally rather than imported from ``qsr4`` to keep this module free of
# a decode-layer dependency; ``qsr4.parse_qsh_trace_frame`` remains the
# authority on the header, and ``test_hdlc_qsh_subsys`` pins the two together.
_QSH_TRACE_CMD = 0x9D
_QSH_TRACE_HDR_LEN = 16      # == qsr4._QSH_TRACE_HEADER_LEN
# == qsr4._QSH_TRACE_HEADER: cmd, subtype, w2, h4, marker, timestamp, hash.
# Kept in step by ``test_hdlc_qsh_subsys``, which pins the two modules together
# rather than letting each hold its own copy of the layout.
_QSH_TRACE_HDR_FMT = "<BBHHHII"


def _tally_qsh_trace(stats: "HdlcStats", frame_no_crc: bytes) -> None:
    """Accrue the scan-pass 0x9D tallies from one QSH-trace frame.

    Reads the packed 16-byte header — **no qdb, no payload decode, no object
    allocated per frame**. Four things come out of that one ``unpack_from``:

    * ``subsys_id`` / ``sub_stream`` — the per-subsystem histogram;
    * ``hash`` — the Qtrace **site** census;
    * ``subtype`` — the envelope's record-kind discriminator;
    * ``timestamp`` — first/last, giving the plane a co-temporal span.

    **Why here.** ``qsr4.parse_qsh_trace_frame`` decodes the whole envelope
    with no qdb, but calling it on the scan path would allocate a dataclass per
    frame (tens of millions of ``0x9D`` frames across a large corpus) to produce
    the same numbers. Reading the fields off the header this function already
    unpacks keeps the existing cost profile.

    This does **not** route ``0x9D`` into the F3 plane. It is QSH telemetry,
    not a debug-message stream: it stays out of ``iter_f3_samples`` and never
    counts as ``wrapped_f3_recovered``.

    The ``u16`` at offset 2 carries the routing fields, bit layout::

        bits [13:6]  subsys_id   -- qsh_cat_e / the 0x9001 arming SSID
        bits  [5:1]  sub_stream  -- index into that SSID's level bitmask
        bit      0   always 0

    Do NOT re-derive these boundaries by eye. Splitting this field at the
    byte boundary (a ``>> 8`` reading) is lossy by two bits and
    silently MERGES distinct subsystems — it collapses DS+IPA+TRM into one id
    and WMS+NR5GML1 into another. The qdb-free cross-vendor check that
    distinguishes them: at the correct boundary 100.00% of recovered ids are
    members of the armed maskset, versus 26.5% at the byte boundary.

    Runt frames are skipped, matching ``qsr4.parse_qsh_trace_frame``'s
    size≠format discipline — a frame too short to hold the header is not counted
    as any subsystem rather than guessed at — but they are **counted** in
    ``qsh_trace_runts`` rather than skipped *silently*. That is what lets the
    integrity check be an identity instead of an inequality::

        sum(qsh_trace_subsys.values()) + qsh_trace_runts == opcode_frames[0x9D]

    Without the runt term a bare equality fails for a benign reason: an RM500Q
    SIM power-cycle capture reports 558,445 ``0x9D`` fragments against 558,444
    subsys-summed, the difference being ONE 4-byte runt.
    """
    if len(frame_no_crc) < _QSH_TRACE_HDR_LEN:
        stats.qsh_trace_runts += 1
        return
    _cmd, subtype, w2, _h4, _marker, ts, site_hash = struct.unpack_from(
        _QSH_TRACE_HDR_FMT, frame_no_crc, 0
    )
    subsys_id = (w2 >> 6) & 0xFF
    stats.qsh_trace_subsys[subsys_id] += 1
    stats.qsh_trace_sub_streams.setdefault(subsys_id, set()).add((w2 >> 1) & 0x1F)
    stats.qsh_trace_hashes[site_hash] += 1
    stats.qsh_trace_subtypes[subtype] += 1
    # Span, not a sorted list: the walk is in capture order, so first-seen and
    # last-seen bound the plane. Tracked separately from `min`/`max` on purpose —
    # a wrapped DIAG clock would make min/max lie about the span's ENDS, and the
    # honest reading of a decreasing pair is "the clock wrapped", not "no data".
    if stats.qsh_trace_ts_first is None:
        stats.qsh_trace_ts_first = ts
    stats.qsh_trace_ts_last = ts


@dataclass
class HdlcStats:
    """Running counters for an HDLC extraction pass."""
    opcode_frames: Counter[int] = field(default_factory=Counter)
    opcode_bytes: Counter[int] = field(default_factory=Counter)
    # CRC-VERIFIED shadow of ``opcode_frames`` / ``inner_0x98_opcodes``, populated
    # only when a walk passes ``crc_census=True``. Empty otherwise.
    #
    # Why these exist as a SEPARATE tally rather than as a `verify_crc=True` walk:
    # ``verify_crc`` also DROPS failing frames from the record yield, so flipping
    # it to fix the census would change record extraction for every consumer of
    # this module. ``crc_census`` is stats-only — the yield is byte-for-byte
    # identical with it on or off; the only cost is one CRC-16 per frame.
    #
    # Why it matters: ``opcode_frames`` tallies the first byte of EVERY
    # 0x7E-delimited fragment, valid frame or not. For a high-volume opcode the
    # noise is a rounding error; for a rare one it is the entire signal. Measured
    # over 1 695 757 CRC-valid frames across 278 hdlc captures: 0x00 claimed
    # 45 844 frames and has 6; 0x7C claimed 3 084 and has 3. Read these counters,
    # not ``opcode_frames``, whenever the question is "how many frames are there".
    opcode_frames_crc_ok: Counter[int] = field(default_factory=Counter)
    opcode_bytes_crc_ok: Counter[int] = field(default_factory=Counter)
    # True once a walk has run with ``crc_census=True`` (or ``verify_crc=True``),
    # i.e. the ``*_crc_ok`` counters and ``crc_ok``/``crc_bad`` are meaningful.
    # Distinguishes "0 CRC-valid frames" from "nobody checked" — the exact
    # ambiguity that lets a raw opcode histogram read as a population count.
    crc_checked: bool = False
    # Inner opcode of each 0x98 DIAG_MULTI_RADIO_CMD_F wrapper (the byte at
    # offset 8). The wrapper carries a MIX — inner 0x10 LOG, but also inner
    # 0x79/0x99 F3 — so a top-level-only opcode tally hides wrapped F3.
    inner_0x98_opcodes: Counter[int] = field(default_factory=Counter)
    inner_0x98_opcodes_crc_ok: Counter[int] = field(default_factory=Counter)
    # Log code of every record extracted from a checked, CRC-valid frame (bare
    # 0x10 or 0x98-wrapped inner), under the same ``crc_census`` rule.
    # A bad-CRC frame is still yielded, and on a byte-losing stream its "code"
    # is two bytes of a mis-framed run: a code seen with 0 here is framing
    # residue, not a code. Empty when nobody checked.
    log_codes_crc_ok: Counter[int] = field(default_factory=Counter)
    log_records: int = 0
    log_records_from_wrapper: int = 0
    crc_ok: int = 0
    crc_bad: int = 0
    skipped_short: int = 0
    # LOG_F frames dropped by the opt-in `drop_desync` length-consistency gate
    # the inner outer_len field (bytes[2:4]) disagrees with the
    # frame's true length, so a strict flat-DLF reader stepping by that field
    # would desync. Only counted when drop_desync=True; 0 otherwise.
    desync_dropped: int = 0
    # 8 KiB replay seams split by :func:`_recover_replay_tail`: a frame
    # whose wire bytes at [8192:] REPLAY its own head instead of its tail, so the
    # deframer ran on into the next packet. The head's real tail never reached the
    # host (lost: one record per seam); ``replay_tail_recovered`` counts the
    # trailing frames recovered with a VALID CRC and yielded in its place.
    replay_fused_frames: int = 0
    replay_tail_recovered: int = 0
    # Monotonic u16 LE counter values pulled from 0x80 wrappers in order
    # encountered. Consecutive entries should increment by 1 (mod 2**16);
    # gaps indicate dropped QShrink4 batches. See ``parse_subsys_v2_header``.
    subsys_0x80_counters: list[int] = field(default_factory=list)
    # Geometry of the DIAG_SERV file transfer this capture carries, or None if
    # it carries none. ``None`` is a different answer from an empty
    # transfer and a truer one: most captures have no 0x80 at all, whereas a
    # zeroed tally would read as "a transfer that moved nothing". Populated
    # from EVERY record type — a refused open (FILE_LIST + OPEN, size=0, no
    # READ) still names the build's qdb GUID, which is the one signal some
    # captures have no other source for. Payload-free: see DiagServTransfer.
    diag_serv_transfer: "DiagServTransfer | None" = None
    # 0x9E DIAG_SECURE_LOG_F envelope sequence values, in order seen.
    secure_log_0x9e_seqs: list[int] = field(default_factory=list)
    # In-band QSHRINK4 diag_id -> protection-domain bindings, in order seen.
    # Usually one per capture, at the head of the stream; a
    # list because nothing guarantees that, and a capture that re-announces
    # a CHANGED binding mid-stream is exactly the event you would want to
    # see rather than have overwritten. See ``qshrink4_binding``.
    qshrink4_bindings: list["Qshrink4Binding"] = field(default_factory=list)

    def qshrink4_binding(self) -> "Qshrink4Binding | None":
        """The capture's ``diag_id`` binding, or ``None`` if none was seen.

        Returns the FIRST binding observed. If a walk saw more than one and
        they disagree, that is a real signal and this accessor hides it —
        read :attr:`qshrink4_bindings` directly in that case.
        """
        return self.qshrink4_bindings[0] if self.qshrink4_bindings else None
    # Per-subsystem 0x9D QSH-trace frame counts, keyed by the wire ``subsys_id``.
    # Tallied for BOTH bare 0x9D and inner-0x9D-under-0x98, so it does
    # not miss the SDX72-class all-wrapped case.
    #
    # Why this is worth counting on the scan pass: ``subsys_id`` is ``qsh_cat_e``
    # is the 0x9001 arming SSID — ONE namespace — so per-subsystem routing and
    # rate accounting need **no qdb at all**. Most 0x9D frames in practice are
    # text-undecodable for want of the build's qdb; this block still describes
    # them.
    qsh_trace_subsys: Counter[int] = field(default_factory=Counter)
    # subsys_id -> the distinct sub_stream indices seen for it. Cross-checks the
    # armed 0x9001 ``level`` bitmask: a sub_stream that was never armed should
    # never appear.
    qsh_trace_sub_streams: dict[int, set[int]] = field(default_factory=dict)
    # Qtrace-site HASH census, and the DIAG-clock span the plane covers.
    #
    # The 0x9D envelope is fully decodable with no qdb
    # (``qsr4.parse_qsh_trace_frame``). These three fields come at the SAME cost
    # profile as the subsystem tally: the header is already unpacked here, so
    # they are extra fields off one ``unpack_from``, not a second pass and not
    # an object per frame. ``parse_qsh_trace_frame`` is not called here because
    # it allocates a ``QshTraceFrame`` per frame, and a large corpus holds tens
    # of millions of 0x9D frames.
    #
    # This is still NOT the F3 plane. 0x9D is QSH telemetry; it does not enter
    # ``iter_f3_samples`` and never counts as ``wrapped_f3_recovered``.
    qsh_trace_hashes: Counter[int] = field(default_factory=Counter)
    # subtype (byte 1) histogram — the envelope's own record-kind discriminator.
    qsh_trace_subtypes: Counter[int] = field(default_factory=Counter)
    # First/last u32 DIAG timestamp seen on the 0x9D plane, or None if none was.
    # Makes the plane co-temporally correlatable against 0x79/0x99/LOG without
    # decompressing the capture, as ``timestamp64`` does for 0x92.
    qsh_trace_ts_first: "int | None" = None
    qsh_trace_ts_last: "int | None" = None
    # 0x9D fragments too short to hold the 16-byte header, skipped by every
    # per-frame tally above. Counted so the integrity check can CLOSE:
    #
    #     sum(qsh_trace_subsys.values()) + qsh_trace_runts == opcode_frames[0x9D]
    #
    # Without the runt term a bare equality reports a benign, tested exclusion
    # (`test_qsh_trace_runt_frame_is_not_counted_as_a_subsystem`) as corruption:
    # an RM500Q SIM power-cycle capture has 558,445 fragments, 558,444
    # subsys-summed, and ONE 4-byte runt.
    qsh_trace_runts: int = 0

    def summary_lines(self) -> list[str]:
        """One-line-per-opcode summary suitable for stderr logging."""
        lines = []
        for op, n in self.opcode_frames.most_common():
            name = OPCODE_NAMES.get(op, "(unknown)")
            # Show the CRC-verified count alongside the raw one when it is
            # available, so a reader cannot mistake the raw tally for a
            # population count.
            crc = (
                f"  crc_ok={self.opcode_frames_crc_ok[op]:<6}"
                if self.crc_checked else ""
            )
            lines.append(
                f"  0x{op:02X}  frames={n:<6}  bytes={self.opcode_bytes[op]:<9}"
                f"{crc}  {name}"
            )
        return lines

    def subsys_0x80_gap_report(self) -> dict | None:
        """Sequence-gap analysis of the 0x80 (QShrink4) wrapper counter.

        The 0x80 ``DIAG_SUBSYS_CMD_VER_2_F`` READ frames carry a u16 LE counter
        at [10:12] whose **bit 15 is a more-data-follows flag** and whose low 15
        bits are the chunk sequence. Consecutive chunks increment the
        sequence by 1; any other step is a dropped/reordered chunk of the served
        file.

        A transfer's **final** chunk clears bit 15, which a naive mod-2**16
        comparison reads as a delta of 32769. That is a *completed transfer*,
        not a drop: on an RG650V capture the chunk after such a step ends
        exactly on the served qdb's last byte. Such transitions are counted in
        ``final_chunks`` and excluded from ``gaps``.

        Returns ``None`` if no 0x80 READ frames were seen. Otherwise a dict:

        - ``frames``        — number of 0x80 READ frames observed
        - ``transitions``   — counter-to-counter steps (``frames - 1``)
        - ``in_sequence``   — transitions that are a clean +1 or a final chunk
        - ``final_chunks``  — transitions where bit 15 cleared on a +1 step
        - ``counter_min`` / ``counter_max`` — raw counter range
        - ``gaps``          — list of ``(index, prev, next, delta)`` for
          every remaining transition whose delta != 1, where
          ``delta = (next - prev) mod 2**16`` and ``index`` is the
          position of ``next`` in ``subsys_0x80_counters``.
        """
        counters = self.subsys_0x80_counters
        if not counters:
            return None
        gaps: list[tuple[int, int, int, int]] = []
        final_chunks = 0
        for i in range(1, len(counters)):
            prev, cur = counters[i - 1], counters[i]
            delta = (cur - prev) & 0xFFFF
            if delta == 1:
                continue
            if _is_final_chunk_step(prev, cur):
                final_chunks += 1
                continue
            gaps.append((i, prev, cur, delta))
        transitions = len(counters) - 1
        return {
            "frames": len(counters),
            "transitions": transitions,
            "in_sequence": transitions - len(gaps),
            "final_chunks": final_chunks,
            "counter_min": min(counters),
            "counter_max": max(counters),
            "gaps": gaps,
        }

    def secure_log_0x9e_gap_report(self) -> dict | None:
        """Sequence analysis of the 0x9E DIAG_SECURE_LOG_F envelope counter.

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
            f"  0x80 DIAG_SERV file-read sequence: {report['frames']} chunks, "
            f"{report['in_sequence']}/{report['transitions']} in-sequence, "
            f"{len(report['gaps'])} gap(s), "
            f"{report['final_chunks']} completed transfer(s); "
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
    """Build CRC-16 CCITT matching DIAG HDLC framing.

    Wire format on SDX20/SDX55/SDX62/SDX72 captures is the reflected
    variant produced by ``crcmod.mkCrcFun(0x11021, initCrc=0,
    xorOut=0xFFFF)`` with ``rev=True`` (crcmod's default) — equivalent
    to running CRC-16/X-25 with the register seeded from ``xorOut ^
    initCrc``. Concretely: reflected poly 0x8408, register starts at
    0xFFFF, byte fed LSB-first, output XORed with 0xFFFF. Known test
    vector: ``crc16_ccitt(b"123456789") == 0x906E``.

    Prefers ``crcmod`` (C extension, ~100x faster). Falls back to a
    pure-Python reflected table-driven implementation that produces
    byte-identical output. (The forward non-reflected algorithm would
    silently reject 100% of real frames.)
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


def _is_len_desync(inner: bytes) -> bool:
    """True when a LOG_F inner frame's outer_len field (bytes[2:4], u16 LE)
    disagrees with the frame's true byte length.

    A well-formed DIAG_LOG_F carries ``outer_len == len(inner) - 4`` (the 4 bytes
    a flat-DLF record drops: cmd+pending at [0:2] and the redundant inner_len
    duplicate at [4:6]). A boot-blob fragment that merely *starts* with 0x10 but
    carries a bogus length violates this (e.g. a ``rec_len=1`` frame that
    desyncs a flat-DLF stream). ``inner`` must be the CRC-stripped
    LOG_F frame (bare 0x10, or the inner frame already unwrapped from a 0x98
    envelope) and at least ``_LOG_F_MIN_LEN`` bytes.
    """
    return (inner[2] | (inner[3] << 8)) != len(inner) - 4


# The wire offset at which /dev/mhi_DIAG (Foxconn T99W640, SDX7x) splits
# a long DIAG packet, and the prefix length compared to recognise a replay. A
# frame's first 16 wire bytes are its opcode + wrapper/LOG header (code + ts
# included), so a repeat of them exactly at the seam is not a coincidence.
_REPLAY_SEAM = 8192
_REPLAY_PROBE = 16


def _recover_replay_tail(raw_frame: bytes) -> bytes | None:
    """Return the trailing frame hidden behind an 8 KiB replay seam, or None.

    ``raw_frame`` is still HDLC-escaped. The fused shape is::

        wire[0:8192] + wire[0:T-8192] + next_frame

    where ``wire`` is the long packet's escaped bytes and T its escaped length
    including its (lost) 0x7E. The head's own length field gives its unescaped
    size U, so ``T >= U + 1 + <escapes in wire[0:8192]>``; the replay must also
    match the head byte-for-byte up to T. The first offset in that window whose
    suffix unescapes to a CRC-valid frame is the trailing frame. Requiring the
    CRC keeps a false split out: the window is a handful of bytes, not the ~2 KiB
    a blind scan would test.
    """
    # The replay is a prefix of the head, so it matches up to (at least) T; it
    # overshoots only while the next frame's first bytes happen to equal the
    # head's, a few bytes at most. So T lies just below ``match_end``.
    match_end = _REPLAY_SEAM
    limit = min(len(raw_frame), 2 * _REPLAY_SEAM)
    while match_end < limit and raw_frame[match_end] == raw_frame[match_end - _REPLAY_SEAM]:
        match_end += 1
    # A LOG_F head (bare or 0x98-wrapped) states its length, which floors T.
    # Other long heads (0x9E secure log, measured) do not: search a short
    # window under ``match_end`` instead.
    head = hdlc_unescape(raw_frame[:64])
    off = _MULTI_RADIO_WRAPPER_OFFSET.get(head[0], 0) if head else 0
    if len(head) >= off + 4 and head[off] == 0x10:
        outer_len = head[off + 2] | (head[off + 3] << 8)
        unescaped = off + 4 + outer_len + 2  # wrapper + LOG_F + CRC
        t_min = unescaped + 1 + raw_frame[:_REPLAY_SEAM].count(0x7D)
    else:
        t_min = max(_REPLAY_SEAM + _REPLAY_PROBE, match_end - 64)
    for p in range(min(match_end, len(raw_frame) - 3), t_min - 1, -1):
        suffix = raw_frame[p:]
        frame = hdlc_unescape(suffix)
        if len(frame) >= 3 and crc16_ccitt(frame[:-2]) == struct.unpack_from("<H", frame, len(frame) - 2)[0]:
            return suffix
        # Back-to-back long packets: the trailing frame is itself replay-fused, so
        # its own CRC fails; accept it when ITS tail recovers.
        if (len(suffix) > _REPLAY_SEAM + _REPLAY_PROBE
                and suffix[_REPLAY_SEAM:_REPLAY_SEAM + _REPLAY_PROBE] == suffix[:_REPLAY_PROBE]
                and _recover_replay_tail(suffix) is not None):
            return suffix
    return None


def _replay_seam(raw_frame: bytes) -> tuple[bool, bytes | None]:
    """Classify ``raw_frame`` (still escaped) against the 8 KiB replay seam.

    Returns ``(is_seam, tail)``: ``is_seam`` when the wire bytes at 8192 repeat
    the frame's head AND the whole frame's CRC fails; ``tail`` is the recovered
    trailing frame (see :func:`_recover_replay_tail`) or None. The shared gate for
    every single-frame core, so the LOG walker and the outer-frame walker split
    identically.
    """
    if not (len(raw_frame) > _REPLAY_SEAM + _REPLAY_PROBE
            and raw_frame[_REPLAY_SEAM:_REPLAY_SEAM + _REPLAY_PROBE] == raw_frame[:_REPLAY_PROBE]):
        return False, None
    whole = hdlc_unescape(raw_frame)
    if crc16_ccitt(whole[:-2]) == struct.unpack_from("<H", whole, len(whole) - 2)[0]:
        return False, None
    return True, _recover_replay_tail(raw_frame)


def resolve_replay_seam(raw_frame: bytes) -> bytes:
    """Return the fragment a seam-aware walker would decode in place of ``raw_frame``.

    For deframers that split on ``0x7E`` themselves instead of using the walkers.
    ``raw_frame`` is one escaped, delimiter-stripped fragment. When it is
    replay-fused at the 8 KiB seam and a CRC-valid trailing frame sits behind the seam, the
    trailing frame is returned (following back-to-back seams to the last one), so
    the frame the seam hid is decoded rather than lost inside a bad-CRC blob. The
    fused head is dropped, exactly as the walkers drop it: its tail never reached
    the host. Anything else, including a seam with nothing recoverable behind it,
    comes back unchanged.
    """
    while True:
        _, tail = _replay_seam(raw_frame)
        if tail is None:
            return raw_frame
        raw_frame = tail


def _process_frame(
    raw_frame: bytes,
    *,
    verify_crc: bool,
    stats: HdlcStats,
    drop_desync: bool = False,
    crc_census: bool = False,
) -> tuple[int, int, bytes] | None:
    """Decode ONE raw (still-escaped, delimiter-stripped) HDLC frame.

    Shared single-frame core for both the whole-buffer
    :func:`iter_log_records` and the chunked :func:`iter_log_records_stream`.
    ``raw_frame`` is the bytes between two ``0x7E`` delimiters,
    exactly one element of ``data.split(b"\\x7e")``.

    Returns the ``(log_code, ts64, payload)`` record for a LOG packet
    (bare ``0x10`` or unwrapped ``0x98``), or ``None`` for everything
    else (too-short, bad CRC, non-LOG opcode). ``stats`` is mutated in
    place either way — opcode/byte counts, CRC tallies, and ``0x80``
    QShrink4 counters accrue even when no record is yielded.

    ``drop_desync``: when True, a LOG_F frame whose outer_len field disagrees
    with its true length (:func:`_is_len_desync`) is dropped (counted in
    ``stats.desync_dropped``) instead of yielded. This lets a caller that
    re-encodes records into a strict flat-DLF byte stream (whose reader steps by
    that length field) stay in sync when a capture carries a boot-blob fragment
    with a bogus length. Default False yields everything.

    ``crc_census``: when True, the CRC is computed and the outcome is
    tallied into ``stats.crc_ok``/``crc_bad`` and the ``*_crc_ok`` opcode
    counters — but a failing frame is still processed and still yielded. This is
    the STATS-ONLY half of ``verify_crc``: it makes a truthful frame census
    available without changing what any consumer extracts.
    """
    if len(raw_frame) < 4:  # need opcode + 2 CRC + at least 1 byte
        return None

    # 8 KiB replay seam: always on, independent of verify_crc, because the
    # split is only taken when the whole frame's CRC FAILS and the recovered tail's
    # CRC PASSES. The head is counted, not yielded (its tail bytes are gone).
    is_seam, tail = _replay_seam(raw_frame)
    if is_seam:
        stats.replay_fused_frames += 1
        if tail is not None:
            stats.replay_tail_recovered += 1
            return _process_frame(
                tail, verify_crc=verify_crc, stats=stats,
                drop_desync=drop_desync, crc_census=crc_census,
            )

    frame = hdlc_unescape(raw_frame)
    if len(frame) < 3:
        stats.skipped_short += 1
        return None

    # Local, not ``stats.crc_checked`` — that flag is sticky for the walk's
    # lifetime, and a stats object shared across a checked and an unchecked walk
    # would otherwise credit the unchecked frames as CRC-valid.
    checked = verify_crc or crc_census
    crc_valid = True
    if checked:
        stats.crc_checked = True
        payload_part = frame[:-2]
        crc_expected = struct.unpack_from("<H", frame, len(frame) - 2)[0]
        crc_valid = crc16_ccitt(payload_part) == crc_expected
        if crc_valid:
            stats.crc_ok += 1
        else:
            stats.crc_bad += 1
        # Only ``verify_crc`` drops. ``crc_census`` observes and moves on.
        if verify_crc and not crc_valid:
            return None

    opcode = frame[0]
    stats.opcode_frames[opcode] += 1
    stats.opcode_bytes[opcode] += len(frame)
    if checked and crc_valid:
        stats.opcode_frames_crc_ok[opcode] += 1
        stats.opcode_bytes_crc_ok[opcode] += len(frame)

    # Strip the 2-byte trailing CRC from the body we hand to extractors.
    body = frame[:-2]

    if opcode == _QSH_TRACE_CMD:
        _tally_qsh_trace(stats, body)

    if opcode == 0x10:
        if drop_desync and len(body) >= _LOG_F_MIN_LEN and _is_len_desync(body):
            stats.desync_dropped += 1
            return None
        rec = _extract_log_f(body)
        if rec is not None:
            stats.log_records += 1
            if checked and crc_valid:
                stats.log_codes_crc_ok[rec[0]] += 1
        return rec

    wrap_off = _MULTI_RADIO_WRAPPER_OFFSET.get(opcode)
    if wrap_off is not None and len(body) > wrap_off:
        # Tally the inner opcode so wrapped F3 (0x79/0x99) is visible to the
        # census, not just the inner-0x10 LOG case extracted below.
        stats.inner_0x98_opcodes[body[wrap_off]] += 1
        if checked and crc_valid:
            stats.inner_0x98_opcodes_crc_ok[body[wrap_off]] += 1
        if body[wrap_off] == _QSH_TRACE_CMD:
            # On SDX72-class parts EVERY record is 0x98-wrapped, so a
            # top-level-only tally misses all of that part's QSH.
            _tally_qsh_trace(stats, body[wrap_off:])
        # The 0x98 wrapper holds a complete inner 0x10 LOG_F frame;
        # it does NOT carry its own inner CRC, so no second strip.
        inner = body[wrap_off:]
        if (drop_desync and body[wrap_off] == 0x10
                and len(inner) >= _LOG_F_MIN_LEN and _is_len_desync(inner)):
            stats.desync_dropped += 1
            return None
        rec = _extract_log_f(inner)
        if rec is not None:
            stats.log_records += 1
            stats.log_records_from_wrapper += 1
            if checked and crc_valid:
                stats.log_codes_crc_ok[rec[0]] += 1
            return rec
        # The inner frame is NOT a LOG_F, so re-dispatch it through the same
        # per-family logic a top-level frame gets; otherwise a wrapped
        # 0x80/0x9E/0x4B would be tallied and dropped. Not yet observed (the
        # inner-0x98 opcodes seen are 0x10/0x99/0x79/0x60 plus CRC noise), but
        # every record is 0x98-wrapped on SDX72-class parts (see
        # _MULTI_RADIO_WRAPPER_OFFSET), which is exactly when a whole family
        # would hide here.
        _dispatch_non_log_families(body[wrap_off], inner, stats)
        return None

    _dispatch_non_log_families(opcode, body, stats)
    return None


def _dispatch_non_log_families(opcode: int, body: bytes, stats: HdlcStats) -> None:
    """Run the per-family envelope parsers for one frame, mutating ``stats``.

    Shared by the top-level path and the ``0x98``-unwrapped path in
    :func:`_process_frame` so a family becomes wrapper-aware by
    construction rather than one opcode at a time.

    ``body`` is the CRC-stripped frame for a top-level call, and the inner frame
    for a wrapped one — the ``0x98`` envelope carries one OUTER CRC and no inner
    CRC, so both are "opcode first, no trailing CRC" and the parsers need no
    variant. Yields nothing and returns nothing: every family here is
    stats-only, which is why the caller can treat both paths identically.

    Deliberately NOT called for a frame that already decoded as LOG_F — a
    LOG record must not also be offered to these parsers.
    """
    if opcode == 0x80:
        hdr = parse_subsys_v2_header(body)
        if hdr is not None:
            # Only READ frames carry the chunk sequence. FILE_LIST/OPEN/CLOSE
            # hold 0 at [10:12], so folding them in would manufacture an
            # enormous false "gap" at the end of every transfer.
            if hdr.record_type == DIAG_SERV_READ:
                stats.subsys_0x80_counters.append(hdr.counter)
            # …but the transfer tally wants ALL FOUR: the GUID and the
            # announced size live on OPEN, which is precisely what a capture
            # whose transfer was refused has and nothing else does.
            if stats.diag_serv_transfer is None:
                stats.diag_serv_transfer = DiagServTransfer()
            stats.diag_serv_transfer.add_lenient(hdr)

    elif opcode == 0x9E:
        env = parse_secure_log_envelope(body)
        if env is not None:
            stats.secure_log_0x9e_seqs.append(env.sequence)

    elif opcode == 0x4B:
        # Almost every (subsys, cmd) pair under 0x4B is opaque — 19 frames
        # spanning 18 distinct pairs in one 64 KB real prefix. The parser
        # returns None for all of them and only fires on 0x12/0x0222, so this
        # costs a subsys byte compare on the others.
        binding = parse_qshrink4_binding(body)
        if binding is not None:
            stats.qshrink4_bindings.append(binding)


def iter_log_records(
    data: bytes,
    *,
    verify_crc: bool = False,
    stats: HdlcStats | None = None,
    drop_desync: bool = False,
    crc_census: bool = False,
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
    crc_census:
        When True, compute each frame's CRC and tally the outcome into
        ``stats`` **without** dropping anything. Use this — not
        ``verify_crc`` — when you want a truthful per-opcode frame census:
        ``verify_crc=True`` would also change which records this function
        yields, and ``opcode_frames`` alone overstates rare opcodes by 3-4
        orders of magnitude. Read ``stats.opcode_frames_crc_ok`` after.
    """
    if stats is None:
        stats = HdlcStats()

    for raw_frame in data.split(b"\x7e"):
        rec = _process_frame(raw_frame, verify_crc=verify_crc, stats=stats,
                             drop_desync=drop_desync, crc_census=crc_census)
        if rec is not None:
            yield rec


def iter_log_records_stream(
    chunks: Iterable[bytes],
    *,
    verify_crc: bool = False,
    stats: HdlcStats | None = None,
    flush_tail: bool = True,
    drop_desync: bool = False,
    crc_census: bool = False,
) -> Iterator[tuple[int, int, bytes]]:
    """Streaming equivalent of :func:`iter_log_records`.

    Consumes an **iterable of byte chunks** (e.g. successive
    ``os.read(fd, 65536)`` results from a live DIAG pipe) instead of one
    complete buffer, and yields each LOG record **as soon as its
    terminating ``0x7E`` arrives** — without waiting for the stream to
    close. This lets a consumer decode DIAG live rather than only
    post-processing a closed capture.

    Why this is safe to slice on raw ``0x7E`` across chunk boundaries:
    HDLC byte-stuffs any ``0x7E`` that occurs *inside* a frame as
    ``0x7D 0x5E``, so a literal ``0x7E`` in the stream is *always* a frame
    delimiter, never frame content. A ``residual`` buffer accumulates
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
            rec = _process_frame(raw_frame, verify_crc=verify_crc, stats=stats,
                                 drop_desync=drop_desync, crc_census=crc_census)
            if rec is not None:
                yield rec

    if flush_tail and residual:
        rec = _process_frame(residual, verify_crc=verify_crc, stats=stats,
                             drop_desync=drop_desync, crc_census=crc_census)
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
    """One de-HDLC'd DIAG frame, opcode-agnostic.

    Unlike :func:`iter_log_records` (which yields only ``0x10`` LOG payloads)
    this exposes the body of **every** outer opcode — the recognized-but-undecoded
    ones (``0x92``/``0x9C``/``0x9D``/``0x7E`` …) included — so a clean-room RE
    pass can reach their raw bytes (e.g. the data-only "scan body u32s, find which
    offset resolves as a qdb hash" method). It does **no** per-opcode
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

    The opcode-agnostic counterpart to :func:`iter_log_records`. A decoder for
    any recognized-but-undecoded opcode first needs its raw bytes, and the LOG
    walkers yield ``0x10`` records only. This provides the clean-room
    plumbing: split on ``0x7E``, unescape, optionally CRC-check, and surface the
    body of each frame regardless of opcode.

    When ``unwrap_multi_radio`` is set (default), a ``0x98``
    ``DIAG_MULTI_RADIO_CMD_F`` envelope yields **two** frames: the envelope itself
    (``opcode==0x98``, ``wrapped=False``) and its inner frame
    (``wrapped=True``, ``outer_opcode==0x98``) — so wrapped ``0x79``/``0x99``/
    ``0x92``/``0x7E`` payloads are reachable the same as top-level ones.
    Recursion is one level only.

    No ``HdlcStats`` is taken or mutated: this is an ad-hoc payload-extraction
    path, distinct from the census walk in :func:`iter_log_records`, so the two
    never double-count.
    """
    for raw_frame in data.split(b"\x7e"):
        yield from _outer_frames_from_raw(
            raw_frame, verify_crc=verify_crc,
            unwrap_multi_radio=unwrap_multi_radio)


def _outer_frames_from_raw(
    raw_frame: bytes,
    *,
    verify_crc: bool,
    unwrap_multi_radio: bool,
) -> Iterator[OuterFrame]:
    """Decode ONE raw (still-escaped, delimiter-stripped) frame into OuterFrames.

    Shared single-frame core for the whole-buffer :func:`iter_outer_frames` and
    the chunked :func:`iter_outer_frames_stream`, mirroring what
    :func:`_process_frame` is to the two LOG walkers. Yields 0, 1, or 2 frames
    (2 when a ``0x98`` envelope is unwrapped).
    """
    if len(raw_frame) < 4:  # opcode + 2 CRC + >=1 byte
        return
    # Yield the frame recovered from behind an 8 KiB replay seam in
    # place of the corrupt head, same as the LOG walker does.
    _, tail = _replay_seam(raw_frame)
    if tail is not None:
        yield from _outer_frames_from_raw(
            tail, verify_crc=verify_crc, unwrap_multi_radio=unwrap_multi_radio)
        return
    frame = hdlc_unescape(raw_frame)
    if len(frame) < 3:
        return
    if verify_crc:
        crc_expected = struct.unpack_from("<H", frame, len(frame) - 2)[0]
        if crc16_ccitt(frame[:-2]) != crc_expected:
            return
    body = frame[:-2]  # strip trailing CRC, same convention as _process_frame
    if not body:
        return
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


def iter_outer_frames_stream(
    chunks: Iterable[bytes],
    *,
    verify_crc: bool = False,
    unwrap_multi_radio: bool = True,
    flush_tail: bool = True,
) -> Iterator[OuterFrame]:
    """Streaming equivalent of :func:`iter_outer_frames`.

    ``iter_outer_frames`` takes a complete ``bytes`` buffer, so reaching a
    non-LOG opcode (``0x9D`` QSH-trace, ``0x92``, …) in a multi-GB drive
    capture would mean reading the whole file into memory — the OOM trap
    :func:`iter_log_records_stream` exists to avoid on the LOG side. This
    is the same primitive for the opcode-agnostic walk, so one pass over a
    capture can feed a LOG consumer **and** a ``0x9D`` consumer without either
    buffering the file.

    The chunk-boundary argument is identical to
    :func:`iter_log_records_stream`'s: HDLC byte-stuffs any in-frame ``0x7E`` as
    ``0x7D 0x5E``, so a literal ``0x7E`` is always a delimiter. The residual
    holds at most one in-flight frame, so memory is bounded.

    Equivalence contract (pinned by ``test_hdlc.py``)::

        list(iter_outer_frames_stream(chunks, flush_tail=True))
            == list(iter_outer_frames(b"".join(chunks)))

    for *any* chunking of the same underlying bytes.
    """
    residual = b""
    for chunk in chunks:
        if not chunk:
            continue
        buf = residual + chunk
        parts = buf.split(b"\x7e")
        residual = parts.pop()
        for raw_frame in parts:
            yield from _outer_frames_from_raw(
                raw_frame, verify_crc=verify_crc,
                unwrap_multi_radio=unwrap_multi_radio)

    if flush_tail and residual:
        yield from _outer_frames_from_raw(
            residual, verify_crc=verify_crc,
            unwrap_multi_radio=unwrap_multi_radio)


def qsh_trace_bodies_from_raw_frame(
    raw_frame: bytes, *, verify_crc: bool = False,
) -> Iterator[bytes]:
    """Yield the ``0x9D`` QSH-trace bodies carried by ONE raw HDLC frame.

    ``raw_frame`` is a still-escaped, delimiter-stripped frame — i.e. one element
    of ``data.split(b"\\x7e")``, or one frame handed up by a live reader. Yields
    the CRC-stripped ``0x9D`` body ready for
    :func:`diaggrok.qsr4.parse_qsh_trace_frame`: at most one, and **zero** for
    every non-QSH frame.

    A hand-rolled ``unescape, drop non-0x9D, strip CRC`` loop is top-level-only
    by construction, so it silently drops every ``0x98``-wrapped ``0x9D``. On an
    SDX72-class part, where **every** record is wrapped (see
    :data:`_MULTI_RADIO_WRAPPER_OFFSET`), that is not a slice of the plane but
    all of it — and the symptom is indistinguishable from "QSH-trace was never
    armed".

    The two cases strip differently and that is not a detail: a top-level frame
    carries a trailing 2-byte CRC, while a ``0x98`` envelope carries **one outer
    CRC and no inner CRC**, so the inner body must NOT be stripped again. Doing it
    by hand at each call site is precisely how the arg array loses its last word.
    :func:`_outer_frames_from_raw` already encodes both conventions; this is a
    filter over it, not a second implementation.
    """
    for frame in _outer_frames_from_raw(
        raw_frame, verify_crc=verify_crc, unwrap_multi_radio=True
    ):
        if frame.opcode == _QSH_TRACE_CMD:
            yield frame.body


def iter_qsh_trace_bodies(
    data: bytes, *, verify_crc: bool = False,
) -> Iterator[bytes]:
    """Yield every ``0x9D`` QSH-trace body in a raw HDLC byte stream.

    Top-level **and** ``0x98``-wrapped, in file order. The opcode-filtered
    counterpart to :func:`iter_outer_frames`; see
    :func:`qsh_trace_bodies_from_raw_frame`.
    """
    for raw_frame in data.split(b"\x7e"):
        yield from qsh_trace_bodies_from_raw_frame(
            raw_frame, verify_crc=verify_crc)


def iter_qsh_trace_bodies_stream(
    chunks: Iterable[bytes],
    *,
    verify_crc: bool = False,
    flush_tail: bool = True,
) -> Iterator[bytes]:
    """Streaming equivalent of :func:`iter_qsh_trace_bodies`.

    ``iter_qsh_trace_bodies`` takes a complete ``bytes`` buffer and does
    ``data.split(b"\\x7e")``, so a caller pays ~2.5x the decompressed capture
    in RSS *before producing anything* (7.6 GB on a 3.03 GB capture). ``0x9D``
    is the wrong plane to leave whole-buffer: a single capture can carry over
    8 million CRC-verified ``0x9D`` frames.

    This is a filter over :func:`iter_outer_frames_stream`, not a second
    tokenizer, for the same reason :func:`iter_qsh_trace_bodies` is a filter over
    :func:`iter_outer_frames`: the CRC convention that makes hand-rolling
    dangerous (a top-level body is CRC-stripped, a ``0x98`` inner body is **not**,
    because the envelope carries one outer CRC and no inner one) lives in
    :func:`_outer_frames_from_raw` and must keep living in exactly one place.

    Equivalence contract (pinned by ``test_hdlc.py``)::

        list(iter_qsh_trace_bodies_stream(chunks, flush_tail=True))
            == list(iter_qsh_trace_bodies(b"".join(chunks)))

    for *any* chunking of the same underlying bytes.
    """
    for frame in iter_outer_frames_stream(
        chunks, verify_crc=verify_crc, unwrap_multi_radio=True,
        flush_tail=flush_tail,
    ):
        if frame.opcode == _QSH_TRACE_CMD:
            yield frame.body


#: Public alias for the LOG_F body decoder. A consumer walking
#: :func:`iter_outer_frames_stream` needs to turn an ``opcode==0x10`` body into
#: ``(log_code, ts64, payload)`` itself — the LOG walkers do that internally, so
#: without this the only route is reaching into the private name.
extract_log_f = _extract_log_f
