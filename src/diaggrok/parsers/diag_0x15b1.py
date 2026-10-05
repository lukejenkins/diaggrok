"""0x15B1 — LOG_GNSS_PDSM_BEST_AVAILABLE_INFO, 21B v=0x01.

The **request-side** PDSM API log for a "best available position" query: one
record is emitted each time a client calls ``pdsm_pd_get_best_avail_pos()``.
The answer comes back ~1 ms later as sibling **0x15B2**
(``LOG_GNSS_PDSM_EXT_STATUS_BEST_AVAILABLE_INFO``); the two are a 1:1
request→result pair (4/4 in the corpus, 0x15B2 lagging by 0–1.0 ms).

Name: ``LOG_GNSS_PDSM_BEST_AVAILABLE_INFO`` (from a community log-name
table). The F3 below confirms the name is literally correct.

## Layout (v=0x01, 21 bytes)

  [ 0]     version               u8   = 0x01 (Layer-1 gate)
  [ 1: 5]  client_id             u32  PDSM client id — F3-GROUNDED (3491)
  [ 5: 9]  cand_client_data_ptr  u32  CANDIDATE — the API's client_data_ptr
  [ 9:21]  reserved_raw          12B  all-zero on every observed record

## F3 grounding (v0x01)

Subject: an LM960A18 (SDX20) drive capture carrying 7.95M ``0x99`` (100%
QShrink-resolved) + 501k ``0x79`` F3 messages.

* **Emitting site, 1:1 over the whole capture.** ``pdapi.c:2846 "=PDSM=
  pdsm_pd_get_best_avail_pos(). CDPtr %p"`` fires exactly **once** in the
  capture's 2.4M log records, and 0x15B1 appears exactly **once**, 4 µs after
  it (followed in the same tick by ``tm_pdapi_client.c:799 "PDAPI cmd for best
  avail position"`` and ``tm_core.c:13428 "Calling
  tm_core_handle_best_avail_pos() for source 5"``). Negative control: the two
  other ``tm_core_handle_best_avail_pos()`` calls in the capture come from
  **source 4** (internal, no PDAPI entry) and produce **no** 0x15B1 — the log
  is emitted by the PDAPI entry point, not by TM-core.
* **[1:5] client_id = 3491.** ``tm_loc_processing_client.c:2875`` prints
  ``"PDSM client is 3491"`` throughout the capture; ``0x00000DA3`` == 3491. The
  same u32 opens the PDSM command-log siblings 0x1378 / 0x137A / 0x1383 (where
  it is also the client id, not a "family magic" constant) — here it sits one byte later, behind the version byte. It is constant 3491 on
  both chipsets because the on-modem QMI-LOC shim (``loc_pd.c``) registers its
  PDSM client in a fixed init order; it is NOT pinned as an invariant, because
  a different PDSM client calling the same API would legitimately change it.
* **[5:9] cand_client_data_ptr — CANDIDATE, not grounded.** The API banner
  prints ``CDPtr 0`` and the slot is 0, and 0x137A (``pdsm_end_session_ex``,
  same ``CDPtr %p`` banner) carries the same ``[client_id u32][u32 0]`` shape.
  But 0 == 0 on one F3-bearing record may be a coincidental match; the name
  stays ``cand_`` until a record with a non-zero pointer is observed.
* **Trigger (why the code is rare).** On this capture the caller is **LTE RRC**
  building a Radio-Link-Failure report: the ``0x60`` event id 1608
  (``EVENT_LTE_RRC_RADIO_LINK_FAILURE``) lands at dt = 0.0, ``lte_rrc_ueinfo.c``
  prints ``"RLF - RL_FAILURE"``, and ``lte_rrc_loc_services.c`` issues QMI-LOC
  ``msg_id 103`` (0x67, GET_BEST_AVAILABLE_POSITION) → ``pdapi.c:2846`` → 0x15B1.
  The response is consumed by ``lte_rrc_loc_services.c:1765-1801`` (lat/lon/
  unc_cir/tod) for the RLF report's location info. So the code fires on
  on-demand position queries (here RLF-driven), not periodically — which is why
  a wardrive produced it and bench GNSS captures rarely do. The MC7411 capture
  (no F3, no ``0x60``) cannot say what its caller was.

## Corpus

4 records / 2 sessions, all 21 B, all byte-identical
(``01 a30d0000 00000000 000000000000000000000000``):

  * Sierra MC7411 (MDM9x50), a GNSS comparison capture — 3
  * Telit LM960A18 (SDX20), a drive capture — 1

Size-invariance ≠ format-invariance: 21 B on every record says nothing about
a future firmware shipping a new layout at the same length under a new version
byte; the Layer-1 ``version`` gate rejects that rather than mis-decoding it.
The body [5:21] has never been observed populated — no populated fixture exists,
so no body byte is pinned.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from
from typing import Any

from diaggrok.codes import LOG_GNSS_PDSM_BEST_AVAILABLE_INFO
from diaggrok.registry import register

_SIZE = 21


@dataclass
class Diag0x15B1:
    """PDSM best-available-position request (0x15B1) — 21B v=0x01."""
    log_time: int
    version: int                # [0] = 0x01
    client_id: int              # [1:5] u32 LE — PDSM client id (F3: 3491)
    cand_client_data_ptr: int   # [5:9] u32 LE — CANDIDATE client_data_ptr
    reserved_raw: bytes         # [9:21] — all-zero on every observed record
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x15B1',
            'log_time': self.log_time,
            'version': self.version,
            'client_id': self.client_id,
            'cand_client_data_ptr': self.cand_client_data_ptr,
            'reserved_raw': self.reserved_raw.hex(),
            'payload_size': self.payload_size,
        }


@register(
    LOG_GNSS_PDSM_BEST_AVAILABLE_INFO, domain="gnss",
    name="0x15B1",
    description=(
        "LOG_GNSS_PDSM_BEST_AVAILABLE_INFO (0x15B1) — 21B v=0x01; the "
        "pdsm_pd_get_best_avail_pos() request log, client_id F3-grounded"
    ),
    version=1,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "RE from the whole corpus (4 records: MC7411 MDM9x50 ×3, LM960A18 "
        "SDX20 ×1). F3-grounded on the LM960 drive capture: "
        "co-emitted 1:1 with pdapi.c:2846 pdsm_pd_get_best_avail_pos() "
        "(1 call / 1 record, 4 µs), client_id == F3 'PDSM client is 3491'."
    ),
    issues=(),
    fields_identified=4,
    fields_parsed=4,
    field_invariants={
        "version": {"enum": [0x01]},
        "payload_size": {"enum": [_SIZE]},
    },
)
def parse_0x15b1(log_time: int, data: bytes) -> Diag0x15B1 | None:
    if len(data) != _SIZE:
        return None
    if data[0] != 0x01:
        return None
    client_id, cdptr = unpack_from('<II', data, 1)
    return Diag0x15B1(
        log_time=log_time,
        version=data[0],
        client_id=client_id,
        cand_client_data_ptr=cdptr,
        reserved_raw=bytes(data[9:_SIZE]),
        payload_size=len(data),
    )
