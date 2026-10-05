"""0x10BA — LOG_SECURITY_SSL_ALERT_PROTOCOL_ALERT.

**Security Services SSL/TLS** subsystem log (equipment_id 1). The canonical log
name comes from a public log-code name table: a TLS **Alert protocol** record.

=== Captures (evidence) ===

Observed on a Compal **RXM-G1** GNSS module, in a capture that fired the whole
SSL log family while ~5 DNS-resolved TLS sockets ran, one of which got an
empty DNS answer (F3 `DNS Response has 0 RRs in answer section`).

  10 records, all exactly **3 bytes = `00 01 00`** (byte-invariant across all
  observed records).

  off  value   read
  ---  -----   ---------------------------------------------------------------
  0    0x00    version (byte-0 convention; pinned invariant)
  1    0x01    alert_level       — TLS AlertLevel, FIRMWARE-GROUNDED (1 = warning)
  2    0x00    alert_description — TLS AlertDescription, F3-GROUNDED (0 = close_notify)

The TLS Alert record on the wire is `{ AlertLevel u8, AlertDescription u8 }`
(RFC 5246 §7.2), and `01 00` maps to *warning / close_notify* — the benign
end-of-session alert a TLS client sends when it closes cleanly. Every observed
record is identical, so the fields are left unconstrained: a future non-`01/00`
alert (e.g. `02 28` handshake_failure) parses rather than being rejected.

F3 grounding of byte2 (alert_description). The capture carries a full TLS
session (secssl*/secx509* to a carrier IMS gateway; 170,891 0x99 QSR4 frames
resolved 100% against a build-matched qdb). Its `secsslalp.c Line 416 "SSL:
Send alert 0"` fires exactly 10 times — one per 0x10BA record — each ~6-24k
ticks BEFORE its record (the alert-protocol code sends the alert, then 0x10BA
logs it), inside the session-close sequence (`secssli_close_session: ENTER`
-> `enter session shutdown` -> Send alert 0 -> `Conn closed`). "alert 0" ==
TLS AlertDescription close_notify, so byte2=0x00=close_notify is F3-grounded.

Further evidence:

* **F3 byte2, 10/10.** The "Send alert 0" line is emitted by the shared SSL
  logger `secloggingsslutils.c:216`, which formats "<file> Line <n> <msg>" at
  runtime (the `SSL: Send alert %d` fmt is NOT in the build-matched qdb; it is
  plaintext in rodata at VA 0xc3e3ff53). So the F3 only ever carries the
  description value, never the level.
* **Firmware disassembly of this build: not possible.** Neither the fmt string
  nor `secsslalp.c` has any immediate/pointer xref in the resident executable
  segments of the reconstructed modem image; the SSL stack lives in a
  demand-paged compressed pool with no decoder yet. The same holds on
  FN980 / EM9190 / RM500Q / LV55 / T99W175 / SC200E images.
* **F3 sweep across 263 captures (56 GB) negative.** The only SSL-alert prints
  anywhere are these 10 `Send alert 0`. The firmware's level-carrying sites
  (`secsslalp.c:168 "ALP rcvd alert level %d alert id %d"`,
  `qpdpltls.c "Secssl alert level[%d]"`) never fire — no capture has a
  received alert.
* **0x60 events: absent** (the capture has no 0x60 frames). **QCSuper / SCAT /
  rayhunter: silent** (0x10BA is in none of their decode tables).
* **Direction = TX.** Each 0x10BA is logged 258–416 ticks after a 0x10AD
  TX-stats record with record_len=64 (10/10; the only 10 len=64 TX records)
  and F3 `dss_write_dsm_chain ret = 69` (5 hdr + 16 IV + 48 = 2-byte alert +
  32 SHA-256 MAC + pad): the client SENT the alert, then logged it.

Firmware grounding of byte1 (alert_level). The level namespace is not
obvious from the data alone: the secssl API alert-level enum has FOUR members
(qdb `pd_comms_tcp_task.c` "SSL Alert Received. Level: Warning / Info / Fatal
/ Suspend"), and the family has no byte1=const-1 convention (0x10AD byte1 is a
length, 12 distinct values). An unstripped MDM9607 debug modem ELF (from a
Quectel EG25-G OpenCPU SDK) carries the same secssl tree with symbols, not
paged out of the image (`secsslalp.c` "Send alert %d" at line 415 there vs 416
on the RXM-G1):

* `secsslalp_send_alert(ses, desc, level)` @0xd0f4837c stores desc->sp+7 and
  level->sp+6, then `dsm_pushdown_tail(sp+6)` (line 407) and `(sp+7)` (line 408).
  The DSM body is the wire alert `{level, desc}` with NO translation of either
  argument, and the F3 "Send alert %d" prints sp+7 = desc (the byte2 grounding).
* Its callers pass RFC 5246 wire levels as literals: `secssli_close_session`
  -> `(ses, 0, 1)` close_notify/warning (the exact `close_session: ENTER ->
  Send alert 0` F3 sequence on the RXM-G1) and `(ses, 0x28, 2)`
  handshake_failure/fatal; `secsslrx_parse_header` -> `(ses, 0x1e, 2)`;
  `secsslhsp_alert` clones -> `(10, 2)` and `(47, 2)`. The receive side
  switches on the same wire byte ("ALP rcvd warning alert" / "rcvd fatal" /
  "rcvd invalid alert level").
* The DSM is then handed to `secssltx_write_record(ses, 0x15, dsm)`, whose first
  act is `secssli_log_ssl_msg(ses, content_type, dsm, dir)` with dir=0 (TX);
  `secsslrx_read_v3_record` makes the same call with dir=1 (RX) before
  `secsslalp_process_alert`. That hook is the 0x10BA source; on the 9607
  build it is compiled to a bare `jumpr r31` (SSL logging off) and on SDX55 it
  is paged, so its body is not read. But the only alert bytes it can log are
  the DSM's `{level, desc}`, and byte2 = DSM[1] is F3-proven, so byte1 =
  DSM[0] = the wire AlertLevel. 0x01 = warning, as close_session passes.
* The secssl API "Warning / Info / Fatal / Suspend" enum (pd_comms_tcp_task.c)
  is the *callback-side* alert notification to clients (ds_ssl alert mask),
  NOT the logged wire byte: no enum value is translated on the send path.

Hypothesis, not baked in: byte0 may be the hook's `dir` argument (0=TX) rather
than a version byte. Every observed record is TX, so the two readings agree on
all data; the `version` const-0 gate stays and would surface an RX alert as an
invariant violation rather than silently mis-parsing it.

Log name: LOG_SECURITY_SSL_ALERT_PROTOCOL_ALERT
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from diaggrok.registry import register


@dataclass
class Diag0x10BA:
    """LOG_SECURITY_SSL_ALERT_PROTOCOL_ALERT (0x10BA) — 3-byte TLS Alert record.

    alert_description is F3-grounded (secsslalp.c "SSL: Send alert <desc>",
    10/10 1:1); alert_level is firmware-grounded as the RFC 5246 §7.2 wire
    AlertLevel (secsslalp_send_alert pushes it verbatim as DSM[0]).
    """
    log_time: int
    version: int
    alert_level: int
    alert_level_name: str | None
    alert_description: int
    alert_description_name: str | None
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            'type': 'Diag0x10BA',
            'log_time': self.log_time,
            'version': self.version,
            'alert_level': self.alert_level,
            'alert_level_name': self.alert_level_name,
            'alert_description': self.alert_description,
            'alert_description_name': self.alert_description_name,
            'payload_size': self.payload_size,
        }


# TLS AlertLevel (RFC 5246 §7.2) — the wire byte secsslalp_send_alert pushes.
_TLS_ALERT_LEVEL = {1: "warning", 2: "fatal"}

# TLS AlertDescription registry (RFC 5246 §7.2 + RFC 8446 §6). Names only —
# the byte is the wire value, which F3 "Send alert <desc>" confirms (desc 0).
_TLS_ALERT_DESCRIPTION = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
    40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked",
    45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
    50: "decode_error", 51: "decrypt_error", 60: "export_restriction",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 90: "user_canceled",
    100: "no_renegotiation", 109: "missing_extension",
    110: "unsupported_extension", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 115: "unknown_psk_identity",
    116: "certificate_required", 120: "no_application_protocol",
}


@register(
    0x10BA,
    name="0x10BA",
    description="LOG_SECURITY_SSL_ALERT_PROTOCOL_ALERT (0x10BA) — TLS Alert record, rxm-g1",
    version=3,
    author="Luke Jenkins",
    author_url="https://github.com/lukejenkins",
    source_type="re",
    source_detail=(
        "Structural decode from 10 records on an RXM-G1 GNSS module. "
        "3-byte payload, const `00 01 00`. "
        "byte0=version (0x00). byte2=TLS AlertDescription, F3-grounded 10/10 "
        "vs secsslalp.c 'SSL: Send alert 0' (close_notify), each alert a TX "
        "(0x10AD len=64 / dss_write ret=69 just before). byte1=TLS wire "
        "AlertLevel (01=warning), firmware-grounded on the unstripped MDM9607 "
        "debug ELF: secsslalp_send_alert pushes {level,desc} verbatim to the "
        "DSM logged by secssli_log_ssl_msg; secssli_close_session passes "
        "(desc 0, level 1). Family: Security SSL/TLS (equip_id 1); name "
        "from a public log-code name table."
    ),
    source_url="",
    fields_identified=3,
    fields_parsed=3,
    issues=(),
    field_invariants={"version": {"const": 0x00}},
)
def parse_0x10ba(log_time: int, data: bytes) -> Diag0x10BA | None:
    if len(data) != 3:
        return None
    if data[0] != 0x00:          # layer-1 version gate
        return None
    return Diag0x10BA(
        log_time=log_time,
        version=data[0],
        alert_level=data[1],
        alert_level_name=_TLS_ALERT_LEVEL.get(data[1]),
        alert_description=data[2],
        alert_description_name=_TLS_ALERT_DESCRIPTION.get(data[2]),
        payload_size=len(data),
    )
