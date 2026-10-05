"""0xB136 — LTE LL1 RX-on toggle info: per-subframe RX-path on/off batch.

A 4 B header (version | carrier index | record count) followed by N fixed-size
per-subframe records, flushed in batches (N <= 5 on SDX20-class and older,
N <= 20 on SDX55+). Four record layouts share the header, keyed by version:

  * v0xa1 (SDX55 / SDX62 / SDX65 / SDX72) — 88 B records;
  * v0x8f (EM120R-GL SDX24; one lone T99W175 SDX55 packet) — 80 B records:
    the v0xa1 layout without its trailing time_80 / time_84;
  * v0x7c / v0x7d (MDM9x50 / SDX20 / SDX50M) — 92 B records;
  * v0x29 / v0x65 / v0x01 (MDM9x30 / QCM2290 / MDM9x35 / MDM9x40-class) —
    60 / 64 / 48 B records, "legacy" layout: shared prefix decoded, tail kept
    raw (v0x29 also decodes its RX-config action / state slots).

F3-grounded against ``lte_ml1_dlm_ard_new.c`` — the
Adaptive RX Diversity state machine, whose ``ARD STM[cc] sf_now:N RxMap:…``
print carries the same (carrier, absolute subframe) key. See ``Diag0xB136``.

Log name: LOG_LTE_LL1_RX_ON_TOGGLE_INFO
"""
from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from
from typing import Any

from diaggrok.registry import register

#: record stride per version byte; the header count must agree with it.
_STRIDE = {0xA1: 88, 0x8F: 80, 0x7C: 92, 0x7D: 92, 0x29: 60, 0x65: 64, 0x01: 48}
_HEADER_LEN = 4


def _sfn_word(w: int) -> dict[str, int]:
    """The u32 @0 bitfield shared by the 92 B and legacy layouts."""
    return {
        "sfn": w & 0x3FF,
        "subframe": (w >> 10) & 0xF,
        "w0_flags": (w >> 14) & 0x3FF,
        "rx_path_mask": (w >> 24) & 0xFF,
    }


def _rec_a1(r: bytes) -> dict[str, Any]:
    """88 B record, v0xa1; also the 80 B v0x8f record (no time_80 / time_84)."""
    u32 = lambda off: unpack_from("<I", r, off)[0]  # noqa: E731
    rec = {
        "sfn": unpack_from("<H", r, 0)[0],
        "subframe": r[2],
        "rx_path_mask": r[3],
        "path_cfg": u32(4),
        "path_on_state": [r[8 + 2 * i] for i in range(4)],
        "path_param": [r[9 + 2 * i] for i in range(4)],
        "path_off_state": list(r[16:20]),
        "sf_time": u32(20),
        "time_slots": [u32(24 + 4 * i) for i in range(12)],
        "slot_mask_word": u32(72),
        "toggle_path_mask": r[76],
        "toggle_param": r[77],
    }
    if len(r) >= 88:
        rec["time_80"] = u32(80)
        rec["time_84"] = u32(84)
    return rec


def _rec_92(r: bytes) -> dict[str, Any]:
    """92 B record, v0x7c / v0x7d."""
    u32 = lambda off: unpack_from("<I", r, off)[0]  # noqa: E731
    return {
        **_sfn_word(u32(0)),
        "path_state_a": [u32(4 + 4 * i) for i in range(4)],
        "path_state_b": [u32(20 + 4 * i) for i in range(4)],
        "time_36": u32(36),
        "sf_time": u32(40) & 0xFFFFFF,
        "rx_on_time_a": u32(44),
        "rx_on_time_b": u32(48),
        "word_52": u32(52),
        "flags_56": u32(56),
        "words_60": [u32(60 + 4 * i) for i in range(3)],
        "time_slots": [u32(72 + 4 * i) for i in range(4)],
        "word_88": u32(88),
    }


def _rec_legacy(r: bytes) -> dict[str, Any]:
    """48 / 60 / 64 B record, v0x01 / v0x29 / v0x65: prefix decoded, tail raw."""
    return {
        **_sfn_word(unpack_from("<I", r, 0)[0]),
        "time_slots": [unpack_from("<I", r, 4 + 4 * i)[0] for i in range(3)],
        "sf_time": unpack_from("<I", r, 16)[0] & 0xFFFFFF,
        "sf_time_ts": unpack_from("<I", r, 20)[0],
        "tail_raw": r[24:],
    }


def _rec_29(r: bytes) -> dict[str, Any]:
    """60 B record, v0x29: legacy prefix + the RX-config action / state slots."""
    act = unpack_from("<I", r, 36)[0]
    state = unpack_from("<I", r, 48)[0]
    return {
        **_rec_legacy(r),
        "rx_action_time": act & 0xFFFFFF,
        "rx_action": act >> 24,
        "rx_state_time": state & 0xFFFFFF,
        "rx_state": state >> 24,
    }


def _rec_01(r: bytes) -> dict[str, Any]:
    """48 B record, v0x01 (MDM9x35): legacy prefix + the RX-config action /
    state slots, at the 12 B-shorter offsets of the 48 B stride.

    v0x29 (60 B) carries these at @36 / @48; v0x01 is 12 B shorter and carries
    them at **@24 / @36** — the same slots shifted back by the stride delta.
    F3-grounded on a live AirCard 791L: see the
    ``Diag0xB136`` docstring, evidence (g).
    """
    act = unpack_from("<I", r, 24)[0]
    state = unpack_from("<I", r, 36)[0]
    return {
        **_rec_legacy(r),
        "rx_action_time": act & 0xFFFFFF,
        "rx_action": act >> 24,
        "rx_state_time": state & 0xFFFFFF,
        "rx_state": state >> 24,
    }


_DECODE = {
    0xA1: _rec_a1,
    0x8F: _rec_a1,
    0x7C: _rec_92,
    0x7D: _rec_92,
    0x29: _rec_29,
    0x01: _rec_01,
}


@dataclass
class Diag0xB136:
    """0xB136 — LTE LL1 RX-on toggle info (``LOG_LTE_LL1_RX_ON_TOGGLE_INFO``).

    **Header (4 B, all versions)** — u32 @0: bits 0-7 ``version``, bits 8-11
    ``carrier_idx``, bits 12-16 ``num_records``, bits 17-31 ``hdr_rsvd`` (3 on
    every walked record but one). ``num_records`` equals ``(len - 4) / stride``
    on every on-stride record in the corpus (521 captures); the parser couples
    the two, so a misframed or merged payload is rejected, not mis-split.

    **v0xa1 record (88 B)** — one per LTE subframe, consecutive records step by
    exactly one subframe:

      ======  ====================  ==========================================
      off     field                 meaning / evidence
      ======  ====================  ==========================================
      0       sfn (u16)             SFN 0..1023          — F3-GROUND (a)
      2       subframe (u8)         0..9                 — F3-GROUND (a)
      3       rx_path_mask (u8)     RX paths on this SF  — F3-GROUND (b)
      4       path_cfg (u32)        nibble-packed per-path config, raw
      8+2i    path_on_state[i]      4 iff path i in mask (99.996%) (c)
      9+2i    path_param[i]         per-path value (1/2/3/4/5/8), raw
      16+i    path_off_state[i]     4 iff path i NOT in mask (99.8%) (c)
      20      sf_time (u32)         24-bit 19.2 MHz tick of the SF: steps
                                    19,200 +/- 4 per record (= 1 ms); byte 3 = 0
      24..68  time_slots[12]        24-bit tick slots, mostly 0; pairs
                                    (24,28) (32,36) (40,44) (48,52) identical
      72      slot_mask_word (u32)  per-slot nibble masks (0x11/0x33/...), raw
      76      toggle_path_mask      0 or == rx_path_mask; when set, byte 7 == 2
                                    and time_slots[8]/[9] (off 56/60) are both
                                    populated (100%): an RX-on toggle scheduled
                                    for those paths, slot 56 ~12-14.5k ticks
                                    (~650-750 us) ahead of slot 60 ~= sf_time
      77      toggle_param (u8)     1/2/3, raw
      80, 84  time_80 / time_84     24-bit tick slots (0xFFFFFFFF = unset), raw
      ======  ====================  ==========================================

    **v0x8f record (80 B)** — the v0xa1 layout through offset 79 (u16 ``sfn``
    @0, ``subframe`` @2, ``rx_path_mask`` @3, per-path states @8..19,
    ``sf_time`` @20, 12 tick slots @24..68, ``slot_mask_word`` @72, toggle
    bytes @76/77), minus ``time_80`` / ``time_84``. SFN/subframe/carrier
    F3-GROUND (f); ``rx_path_mask`` reads 0x3 (paths 2/3 off-state 4) on
    nearly every record, so it is CANDIDATE on this version.

    **v0x7c / v0x7d record (92 B)** — u32 @0 bitfield: bits 0-9 ``sfn``, 10-13
    ``subframe`` (F3-GROUND (d)), 14-23 ``w0_flags`` (raw), 24-31
    ``rx_path_mask`` (0 or 0x3 on SDX20; ceiling == ARD ``desired rxmap:2
    [0 1 ..]``, the on/off flip itself is not F3-labelled). ``path_state_a`` /
    ``path_state_b``: 2 x 4 per-path u32 (3 on / 2 off / 0). ``sf_time`` @40:
    24-bit 19.2 MHz tick, 19,200 per record. When ``rx_path_mask == 0`` the
    RX-on slots ``time_36`` / ``rx_on_time_a`` / ``rx_on_time_b`` read
    0xFFFFFF (24-bit unset) and so does ``word_52``; with the mask set,
    ``rx_on_time_a/b`` sit ~10.5-11.5k ticks (~550-600 us) ahead of
    ``sf_time`` — the same RX-on lead as v0xa1's slot 56. Tick slots carry a
    flag in their top byte (0/1/2; 0xFFFFFF low = unset).

    **Legacy records (v0x29 60 B, v0x65 64 B, v0x01 48 B)** — the same u32 @0
    bitfield (SFN/subframe continuity verified per record), three tick slots
    @4, ``sf_time`` @16 (19.2 MHz, 19,200 per record), ``sf_time_ts`` @20 (u32
    stepping exactly 30,720 per subframe: a 30.72 MHz LTE-Ts counter). The rest
    is kept as ``tail_raw``; on v0x29 ``rx_path_mask`` (byte 3) reads 0.
    v0x29 additionally decodes two slots of its tail (F3-GROUND (e)):
    ``rx_action_time`` / ``rx_action`` (u32 @36: 24-bit 19.2 MHz tick |
    kind<<24; 1 = RX-config enable applied on this subframe, tick ==
    ``sf_time``; 0 = disable, tick ~20 us into the subframe; 2 = no action)
    and ``rx_state_time`` / ``rx_state`` (u32 @48: ``sf_time`` copy |
    state<<24; 1 from the enable subframe through the disable subframe, 0
    from the subframe after it; 2 on 3,701 of 1.04 M v0x29 records, all
    MDM9x30, uncharacterised). **v0x01 (MDM9x35, 48 B) carries the same two
    slots 12 B earlier — action u32 @24, state u32 @36** — the v0x29 @36 / @48
    pair shifted back by the 48-vs-60 stride delta (F3-GROUND (g)). On an enable subframe the three tick slots
    @4 are populated ~530 us ahead of ``sf_time`` (the v0x7d RX-on lead);
    ``w0_flags`` is constant within an on/off window but chipset-specific (QCM2290 5/0, MDM9x30 7/0), raw. On the
    legacy layouts ``carrier_idx`` is CANDIDATE: it takes 0/1/2 in equal counts
    on every legacy device (all three slots always logged), and packets with
    adjacent indices cover the same subframes with sf_time a few ticks apart.

    Whole-corpus walk (521 captures): 1,219,328 packets parse, 0
    invariant violations; 52 rejected, all off-stride misframes (mostly one
    HDLC stress capture) or truncations (two 4 B v0x29 packets
    whose header claims records the body does not carry).

    Evidence:
      (a) RM520N-GL (SDX62) F3 ``lte_ml1_dlm_ard_new.c:6000``
          ``ARD STM[cc] sf_now:N RxMap:A/B``: 10,345 of 10,456 events join a
          v0xa1 record on exact (carrier_idx, sfn*10+subframe), median dt 10 ms.
      (b) byte 3 == the first-N path nibbles of RxMap B (the applied map) on
          10,272 / 10,345 (99.29%); the residue is ARD transition events
          (decided-not-yet-applied) and GAP_START (mask 0 in a measurement
          gap). Negative control: joining on carrier_idx +1 / +3 drops
          agreement to 57.8% — the header nibble is the carrier.
      (c) internal consistency with (b), whole-capture walk.
      (d) LM960 (SDX20) F3 ``[stm] (..) ==> ARD STM[cc] @.. sf_now:N``: 65,332
          of 65,475 events join a v0x7d record on exact (carrier_idx, sf_now).
      (e) SC200E (QCM2290) F3 ``lte_ml1_dlm_rx_cfg.c:5794``
          ``sf_now = N Config app action time A``: every one of 349 events
          has a v0x29 cc0 record with ``rx_action == 1`` at exactly
          sfn*10+subframe == A (controls: == sf_now 0/349, == A+1 0/349);
          all 349 such records are accounted for. The 348 ``rx_action == 0``
          records pair 1:1 with the 348 ``lte_ml1_dlm_rx_cfg.c:6169``
          ``Rx Cfg[0] Masks old: E new: 4`` disables; ``rx_state`` flips
          0->1 on every enable record and 1->0 on the record after every
          disable (697/697). MC7455 (MDM9x30, 38,865 records, no F3): same
          alternation (810 enables / 811 disables), 799/811 flip on the
          next record (12 show no 0-state within 5 records). The
          nearest-record (sfn*10+subframe - sf_now) offset is -1..-5 on
          349/349 events; a +1 s time shift moves it to +996..+999 and a
          37 s shift scatters it (SFN/subframe grounded on v0x29).
      (f) EM120R-GL (SDX24) F3
          ``lte_ml1_dlm_ard_new.c:3848`` ``(EVT) ==> ARD STM[cc] @STATE
          sf_now:N``: 229 of 484 events fall inside a v0x8f batch's
          subframe span and 206 of those (90.0%) join a record on exact
          (carrier_idx, sfn*10+subframe), median dt 0.009 ms; carrier+1
          control 0/484. The residue matches the ~2.7% in-batch subframe
          discontinuities (21,530 / 22,119 consecutive steps are +1).
      (g) AirCard 791L (MDM9x35) F3
          ``lte_ml1_dlm_rx_cfg.c:4396`` ``Rx Cfg[0] Masks old:E new:F`` (0x79
          plaintext), live LTE-only re-acquisition churn
          (60,339 v0x01 records / 301,380 subframe entries, all carrier 0/1/2).
          The v0x01 tail top-byte scan isolates exactly two active slots:
          u32 @24 top byte {2: 301,311 none, 1: 35 enable, 0: 34 disable} and
          u32 @36 top byte {0: 201,179 off, 1: 100,195 on, 2: 6 rare} whose low
          24 bits == ``sf_time`` on 301,380 / 301,380 (100%) — the v0x29 action
          and state signatures (incl. the rare "2" state), 12 B earlier. Three
          grounds: (i) enable ticks == ``sf_time`` 35/35, disable ticks
          == ``sf_time`` + 211 (~11 us in) 34/34 — the v0x29 enable/disable
          timing; (ii) state == 1 on 35/35 enable entries and the entry after
          every disable reads state == 0 on 34/34 — the v0x29 alternation
          invariant; (iii) the 65 records carrying an action entry each fall
          within 100 ms of a ``:4396`` config-apply event 65/65, a +5 s time
          shift 6/65.
    v0x7c (EM7565) matches v0x7d byte-for-byte structurally; its ARD F3 prints
    are present but their args are unrendered, so it is not F3-joined.
    """
    log_time: int
    version: int
    carrier_idx: int
    num_records: int
    hdr_rsvd: int
    payload_size: int
    records: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0xB136",
            "log_time": self.log_time,
            "version": self.version,
            "carrier_idx": self.carrier_idx,
            "num_records": self.num_records,
            "hdr_rsvd": self.hdr_rsvd,
            "payload_size": self.payload_size,
            "records": self.records,
        }


# ── WiGLE-indirect (rat-context) ──────────────────────────────────────────────
# 0xB136 is the LTE LL1 per-subframe RX-path on/off log. WiGLE-indirect
# (rat-context): rx_path_mask bounds when (and on how many antennas) the
# receiver is demodulating, which gates the validity window of the measurement
# codes WiGLE consumes. Target = RM520N-GL (SDX62), v0xA1.

@register(
    0xB136,
    name="0xB136",
    description=(
        "LTE LL1 RX-on toggle info: 4 B header (version | carrier_idx | "
        "num_records) + N per-subframe records (v0xa1 88 B, v0x8f 80 B, "
        "v0x7c/7d 92 B, "
        "legacy v0x29/65/01 60/64/48 B). SFN/subframe/carrier + RX-path mask "
        "F3-joined to lte_ml1_dlm_ard ARD STM; v0x29 (@36/@48) + v0x01 (@24/@36) "
        "RX-config action/state slots F3-joined to lte_ml1_dlm_rx_cfg action "
        "time"
    ),
    version=6,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Header u32 = version | carrier_idx<<8 | num_records<<12, coupled to "
        "len == 4 + stride*N (strides 88/80/92/60/64/48; 1,219,328 packets "
        "parse across 521 captures, 52 off-stride/truncated rejects, 0 "
        "invariant violations). v0xa1: SFN/subframe/carrier joined to F3 "
        "lte_ml1_dlm_ard_new.c:6000 ARD STM[cc] sf_now on 10,345/10,456 "
        "(RM520N-GL SDX62); byte 3 rx_path_mask == RxMap on 99.29%, carrier "
        "negative control 57.8%. v0x8f (80 B = v0xa1 layout minus "
        "time_80/84): EM120R-GL ARD STM sf_now exact join 206/229 in-span, "
        "carrier+1 control 0. v0x7d: 65,332/65,475 exact sf_now joins "
        "(LM960 SDX20). Per-subframe 19.2 MHz tick @20 (a1) / @40 (7c/7d) / "
        "@16 (legacy); 30.72 MHz Ts @20 on legacy layouts. v0x29 tail "
        "RX-config action slot u32@36 (tick|kind: 1 enable/0 disable/2 none) "
        "+ state slot u32@48 (tick|on-flag); rx_action==1 lands exactly on F3 "
        "lte_ml1_dlm_rx_cfg.c:5794 'Config app action time' 349/349 "
        "(SC200E QCM2290; sf_now and +1 controls 0/349). v0x01 (MDM9x35 "
        "AirCard 791L) carries the same action/state pair at u32@24/@36, "
        "shifted back 12 B by the 48 B stride; F3-grounded live on "
        "lte_ml1_dlm_rx_cfg.c:4396 'Rx Cfg Masks' (60,339 v0x01 records): "
        "enable tick==sf_time 35/35, disable==sf_time+211 34/34, state "
        "alternation 69/69, :4396 co-temporal 65/65 (+5 s control 6/65). "
        "v0x7c is structurally identical to v0x7d but not F3-joined."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    fields_identified=35,
    fields_parsed=35,
    field_invariants={
        "version": {"enum": sorted(_STRIDE)},
        "num_records": {"range": [0, 20]},
    },
    wigle_direct=False,
    wigle_roles=("rat-context",),
)
def parse_0xb136(log_time: int, data: bytes) -> Diag0xB136 | None:
    if len(data) < _HEADER_LEN:
        return None
    stride = _STRIDE.get(data[0])
    if stride is None:
        return None
    hdr = unpack_from("<I", data, 0)[0]
    n = (hdr >> 12) & 0x1F
    if len(data) != _HEADER_LEN + stride * n:
        return None
    decode = _DECODE.get(data[0], _rec_legacy)
    records = [
        decode(data[_HEADER_LEN + stride * i:_HEADER_LEN + stride * (i + 1)])
        for i in range(n)
    ]
    return Diag0xB136(
        log_time=log_time,
        version=data[0],
        carrier_idx=(hdr >> 8) & 0xF,
        num_records=n,
        hdr_rsvd=hdr >> 17,
        payload_size=len(data),
        records=records,
    )
