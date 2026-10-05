"""0x1486 — QCRIL call-flow arrow: ``src -> dst`` entity + arrow kind + label string.

``LOG_QCRIL_CALL_FLOW_C`` (canonical log name, listed below) is the packet the
vendor log viewer renders as a **call-flow / sequence diagram** of the RIL stack.
Each record is ONE arrow: a 3-byte header naming the source column, destination
column and arrow kind, then the NUL-terminated label drawn on it. Despite the
``0x14xx`` range this is not a GNSS log; the body is text. It is a generic QCRIL
trace emitted by the **apps-side** ``rild`` — not a C-V2X code, and not a modem
(MPSS) log: its timestamp carries no sub-tick chip bits (low 16 bits always 0 —
84/84 records), unlike every MPSS log record around it.

Layout (header grounded against QCRIL's own F3)::

    [0]   u8    src     source entity   (1 AMSS, 2 RIL, 3 UI)
    [1]   u8    dst     destination entity (same enum)
    [2]   u8    arrow   arrow kind — observed {0, 1, 4}; see below
    [3:]  cstr  message the arrow's label (QCRIL event / RIL request / unsol / QMI call)

F3 grounding (1:1, same 1.25 ms tick)
-------------------------------------
An MDM9250 factory-mode capture also carries rild's **own plaintext F3**
(``0x79``, ss_id 63, ``qcril*.c``), which draws the same arrows in ASCII. On the
MDM9250 the apps timebase shares the modem epoch, so the join is by timestamp:
**33/39 records have a same-tick, same-label F3 echo**, and the header matches
the drawn arrow on every one —

* ``01 02`` ↔ ``qcril.c:6344 qcril_process_event: RIL <--- <EVT>(id), RID, MID --- AMSS``
* ``02 02`` ↔ ``qcril.c:6337 qcril_process_event: RIL --- <EVT>(id), RID, MID ---> RIL``
* ``02 03`` ↔ ``qcril.c:4220 qcril_send_unsol_response_epilog: UI <--- RIL_UNSOL_* (id) --- RIL``
* ``03 03`` ↔ ``qcril.c:6664 currentState: currentState() -> Radio Off(0)``

— which **names the entity enum from the firmware itself: 1 = AMSS (the modem,
via QMI), 2 = RIL (QCRIL), 3 = UI (the telephony framework)**. The 6 records
without a same-label echo are all ``02 01`` (RIL -> AMSS: ``qmi_uim_service -
init / event register / get card status / refresh register``, ``qmi_cat_service
- init``); at the same tick F3 shows QCRIL opening its QMI clients to the modem
(``qcril_uim_init_state: Trying qcril_qmi_uim_srvc_init_client()``,
``qcril_gstk_qmi_init``) — the RIL -> AMSS direction the header claims.

``src`` is how ``qcril_process_event`` *draws* the arrow, not a proof of
physical origin: internally-queued events (e.g.
``QCRIL_EVT_QMI_RIL_ASSESS_EMRGENCY_NUMBER_LIST_DESIGNATED_COUNTRY``) are also
drawn ``AMSS -> RIL`` by the F3, and the record agrees with the F3.

Corpus directions (84 records, 11 captures — MDM9250 + Quectel SC20A)::

    01 02 00  AMSS -> RIL   QCRIL events / QMI indications + callbacks (WDS, NAS, UIM, PBM, PDC)
    02 01 00  RIL  -> AMSS  QCRIL's QMI service calls (qmi_uim_service / qmi_cat_service)
    02 02 00  RIL  -> RIL   QCRIL-internal event (QCRIL_EVT_PBM_CARD_ERROR)
    02 03 01  RIL  -> UI    RIL_UNSOL_* unsolicited response
    02 03 00  RIL  -> UI    RIL_REQUEST_* completion (RID, Token id, status)   [SC20A]
    03 02 04  UI   -> RIL   RIL_REQUEST_* dispatch (Token id)                  [SC20A]
    03 03 00  UI   -> UI    currentState() -> Radio Off

``arrow`` (CANDIDATE — F3 draws all arrows alike, so only the correlation is
measured): 4 only ever on a UI -> RIL request, 1 only ever on a RIL -> UI
unsolicited, 0 everywhere else. Exposed raw; not named.

Byte 0 is the source column, not a version or record-type byte: all three
values occur. No header byte value is ever a drop reason; a label missing its
NUL terminator is (the record was truncated). ``src``/``dst``/``arrow`` carry
SOFT ``field_invariants`` enums so a new value is flagged by the corpus-walk
verifier, never dropped. Size is not gated (26..90 B observed).

The message is split best-effort (all ``None`` on a non-matching line, raw
``message`` always kept):

* event form ``<EVENT>(<event_id>), RID <rid>, MID <mid>`` → ``event``,
  ``event_id``, ``rid``, ``mid``;
* request-completion ``<REQ> - RID <rid>, Token id <token_id>, <status>`` →
  ``rid``, ``token_id``, ``status``;
* request-dispatch ``<REQ> - Token id <token_id>`` → ``token_id``.

``RID`` = RIL instance id, ``MID`` = modem id. ``Token id`` pairs a UI -> RIL
dispatch with its RIL -> UI completion.

Log name: LOG_QCRIL_CALL_FLOW_C
Also known as: LOG_GAN_ACTIVATE_DATA_CHANNEL
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register

_MSG_OFFSET = 3  # [0]=src, [1]=dst, [2]=arrow, [3:]=NUL-terminated label
# Entity enum, named by QCRIL's own F3 arrows (qcril.c:6344/6337/4220).
_ENTITIES = {1: "AMSS", 2: "RIL", 3: "UI"}
_ARROWS = (0x00, 0x01, 0x04)  # observed; soft invariant, NOT a gate

# QCRIL event form: "<EVENT_NAME>(<event_id>), RID <rid>, MID <mid>".
_EVENT = re.compile(
    r"^(?P<event>[A-Za-z0-9_]+)\((?P<event_id>-?\d+)\),\s*"
    r"RID\s*(?P<rid>-?\d+),\s*MID\s*(?P<mid>-?\d+)\s*$"
)
# RIL request completion: "<REQ> - RID <rid>, Token id <token>, <status>".
_REQ_DONE = re.compile(
    r"^(?P<request>[A-Za-z0-9_]+)\s*-\s*RID\s*(?P<rid>-?\d+),\s*"
    r"Token id\s*(?P<token>-?\d+),\s*(?P<status>.+?)\s*$"
)
# RIL request dispatch: "<REQ> - Token id <token>".
_REQ_DISPATCH = re.compile(
    r"^(?P<request>[A-Za-z0-9_]+)\s*-\s*Token id\s*(?P<token>-?\d+)\s*$"
)


@dataclass
class Diag0x1486:
    """0x1486 — QCRIL call-flow arrow (src -> dst, arrow kind, label)."""
    log_time: int
    src: int
    src_name: str | None
    dst: int
    dst_name: str | None
    arrow: int
    message: str
    event: str | None
    event_id: int | None
    rid: int | None
    mid: int | None
    token_id: int | None
    status: str | None
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "Diag0x1486",
            "log_time": self.log_time,
            "src": self.src,
            "src_name": self.src_name,
            "dst": self.dst,
            "dst_name": self.dst_name,
            "arrow": self.arrow,
            "message": self.message,
            "event": self.event,
            "event_id": self.event_id,
            "rid": self.rid,
            "mid": self.mid,
            "token_id": self.token_id,
            "status": self.status,
            "payload_size": self.payload_size,
        }


@register(
    0x1486,
    name="0x1486",
    description="QCRIL call-flow arrow 0x1486 (LOG_QCRIL_CALL_FLOW_C) — [0] src / [1] dst entity (1 AMSS, 2 RIL, 3 UI — named by QCRIL's own same-tick F3 arrows, 33/39 1:1), [2] arrow kind (0/1/4 raw), then the NUL-terminated arrow label (QCRIL event / RIL request / RIL_UNSOL / QMI call). event/event_id/rid/mid/token_id/status split out best-effort. Apps-side rild trace, NOT C-V2X; observed MDM9250 + Quectel SC20A, absent on MDM9150.",
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    version=5,
    source_type="re",
    source_detail=(
        "Clean-room RE. The 3-byte header is a call-flow arrow — [0] src "
        "entity, [1] dst entity, [2] arrow kind — grounded 1:1 against rild's "
        "own plaintext F3 (0x79, ss_id 63) in an MDM9250 factory-mode capture: "
        "33/39 records have a same-tick same-label F3 echo whose drawn arrow "
        "matches the header (qcril.c:6344 'RIL <--- EVT --- AMSS' = 01 02; "
        "qcril.c:6337 'RIL --- EVT ---> RIL' = 02 02; qcril.c:4220 'UI <--- "
        "RIL_UNSOL_* --- RIL' = 02 03; qcril.c:6664 currentState() = 03 03), "
        "naming the enum 1=AMSS 2=RIL 3=UI; the other 6 are 02 01 (RIL->AMSS "
        "qmi_uim/qmi_cat service calls) co-timed with QCRIL's QMI-client init "
        "F3. Corpus: 84 records / 11 captures (MDM9250 69 + Quectel SC20A 15), "
        "all 7 directions consistent; apps-side timestamps (low 16 bits 0, "
        "84/84). arrow: 4 only on UI->RIL requests, 1 only on RIL->UI unsols, "
        "else 0 — exposed raw (CANDIDATE). src/dst/arrow are SOFT enum "
        "invariants (flag, never drop); size not gated (26..90 B). A label "
        "with no NUL terminator (truncated record) returns None. Not a GNSS "
        "log despite the 0x14xx range."
    ),
    source_url="",
    issues=(),
    primary_issue=None,
    # src + dst + arrow (header) + message + event/event_id/rid/mid +
    # token_id/status (split from message). src_name/dst_name are derived.
    fields_identified=10,
    fields_parsed=10,
    field_invariants={
        "src": {"enum": sorted(_ENTITIES)},
        "dst": {"enum": sorted(_ENTITIES)},
        "arrow": {"enum": list(_ARROWS)},
    },
    # Carries printf-style QCRIL debug text — event names + numeric
    # enum/instance/token ids, NOT subscriber identity, so f3-debug (not identifier).
    ascii_kinds=("f3-debug",),
    # Version-less: byte 0 is `src`; corpus byte 0 spans 3 values over 349 records.
    version_less=True,
)
def parse_0x1486(log_time: int, data: bytes) -> Diag0x1486 | None:
    # Structural gate ONLY: 3-byte header + at least one message byte. No header
    # byte value is ever a drop reason; an unseen
    # entity/arrow is exposed as-is and merely soft-checked via field_invariants.
    if len(data) <= _MSG_OFFSET:
        return None
    # The label is a NUL-terminated cstr — every
    # attested record ends in its terminator. A label with no NUL was cut
    # short: return None (registry WARN) rather than a silently clipped message.
    nul = data.find(b"\x00", _MSG_OFFSET)
    if nul < 0:
        return None
    raw = data[_MSG_OFFSET:nul]
    message = raw.decode("ascii", errors="replace")
    event = event_id = rid = mid = token_id = status = None
    if (m := _EVENT.match(message)) is not None:
        event = m.group("event")
        event_id = int(m.group("event_id"))
        rid = int(m.group("rid"))
        mid = int(m.group("mid"))
    elif (m := _REQ_DONE.match(message)) is not None:
        rid = int(m.group("rid"))
        token_id = int(m.group("token"))
        status = m.group("status")
    elif (m := _REQ_DISPATCH.match(message)) is not None:
        token_id = int(m.group("token"))
    return Diag0x1486(
        log_time=log_time,
        src=data[0],
        src_name=_ENTITIES.get(data[0]),
        dst=data[1],
        dst_name=_ENTITIES.get(data[1]),
        arrow=data[2],
        message=message,
        event=event,
        event_id=event_id,
        rid=rid,
        mid=mid,
        token_id=token_id,
        status=status,
        payload_size=len(data),
    )
