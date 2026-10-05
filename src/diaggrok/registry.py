# diaggrok-provenance: re
"""Core parser registry for diaggrok."""
from __future__ import annotations

import ast
import dataclasses
import importlib.util
import inspect
import logging
import os
import re
import textwrap
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from diaggrok.types import ParserFunc

# ── WiGLE-complete tagging vocabulary ──────────────────────────────
# Closed vocabulary for the wigle_roles kwarg on @register().

WIGLE_DIRECT_ROLES = frozenset({
    "identity",
    "signal",
    "position",
    "gnss-quality",
})

WIGLE_INDIRECT_ROLES = frozenset({
    "pci-earfcn-bridge",
    "cross-capture-ref",
    "rat-context",
})

WIGLE_TIMING_SUBFLAGS = frozenset({
    "one-shot",
    "periodic",
    "on-fix",
})

# ── Ground-truth recipe schema ─────────────────────────────────────
# In-code, **per-version** capture recipe for a DIAG log code: which modems
# emit that version, what drive-state (cond:*) to capture in, and — field by
# field — every known source (AT / QMI / MBIM command, NMEA, or a
# modem-specific trigger) that returns the same physical quantity so a
# diag_correlate_at_poll capture can validate the parser's unknown fields.
#
# Keyed PER VERSION because the layout (and thus the field map) differs
# across the log's version byte — e.g. 0xB885 SDX55 v0x05 vs SDX62 v0x0b
# are different structs. A slot carries one GroundTruth per (version, modem).
#
# Recipes live in the standalone ``diaggrok.ground_truth`` store, joined to
# the parser by (log_code, log_version) identity; they are not attached to
# the ParserEntry. This module still owns the recipe dataclass and its
# *structural* invariants (so the store loads through them), but the base lib
# never imports the store. Referential integrity (cond in the conditions
# vocabulary, AT command in a known poller, modem in the device inventory) is
# enforced outside this library, because the diaggrok lib must not depend on
# the capture tooling.

GROUND_TRUTH_STATUSES = frozenset({
    "hypothesis",  # field→quantity mapping is a guess, no capture yet
    "partial",     # some correlation evidence, not conclusive
    "verified",    # confirmed against a paired AT/QMI capture
    "refuted",     # capture disproved the hypothesised mapping
})

# Source kinds — how a ground-truth quantity is obtained. Open-ended by
# design (as many sources as can be named), but typed so consumers
# (the AT-script generator, the QMI/MBIM pollers, the reproducer tool) can
# route each source to the right transport.
SOURCE_KINDS = frozenset({
    "at",       # an AT command (validated against the known poller sets)
    "qmi",      # a QMI service/message (qmicli / libqmi)
    "mbim",     # an MBIM CID (mbimcli)
    "nmea",     # an NMEA sentence (from a GNSS NMEA stream)
    "f3",       # an F3 ext-msg debug print co-captured in the SAME DIAG stream
                # (0x79 plaintext / 0x99 QSR4-terse / 0x98-wrapped). The
                # firmware's own label for a quantity — value is the F3 site
                # (file:line or rendered template). Unlike at/qmi/mbim it is
                # not a transport to poll: it is already in the capture, so it
                # grounds a field with zero extra HW interaction.
    "event",    # a 0x60 DIAG_EVENT_REPORT_F state-transition event co-captured
                # in the same DIAG stream. The second in-capture oracle beside
                # "f3": like f3 it is not a transport to poll — it is already
                # there, so it grounds a field with zero extra HW interaction.
                # Value is the resolvable event id + name, e.g.
                # "1966 EVENT_LTE_EMM_OTA_INCOMING_MSG"; the loader asserts the
                # id resolves in the event-name index.
                #
                # Unlike "f3", an event ground is self-contained with no extra
                # citation: f3 resolves against a build-specific qdb (so it must
                # carry firmware, GUID, origin and checksum), whereas the event
                # index is build-independent.
                #
                # Example: the EVENT_LTE_EMM_OTA_INCOMING_MSG (1966) payload is
                # the EMM msg_type, 3/3 exact against 0xB0EC records;
                # EVENT_NAS_ATTACH (2556) byte[4] is the EMM reject cause, 3/3
                # exact. That is n=3 on one modem and one msg_type, so treat it
                # as a lead rather than an established mapping.
    "trigger",  # an action that makes the modem EMIT the log (not read the
                # quantity) — e.g. "AT+QGPSLOC=2 forces a fix". Often
                # modem-specific; see Source.modem.
    "other",    # anything else, free-form (documented in value/notes)
})

# F3 rendering families. A kind="f3" source is EITHER self-rendered 0x79
# plaintext (no qdb) OR 0x99/0x98-wrapped QSR4-terse (needs a GUID-matched
# qdb). The family disambiguates the two so a provenance audit reads a
# declared value instead of inferring it from prose. The ground_truth loader
# requires it on every f3 source; Source itself enforces it only when set,
# because older inline f3 sources predate the field and must still import.
F3_FAMILIES = frozenset({"plaintext", "qsr4"})

# Recipe validation modes. Selects how a recipe is validated and
# whether a canary liveness control is required:
#   triggered   — a command deterministically emits the log; the trigger IS
#                 the recipe. No canary, no ablation.
#   subtractive — the required-config set is DISCOVERED by ablation (turn
#                 switches off, watch whether the code stops). Requires a
#                 canary so "I gated the code" is distinguishable from "I
#                 killed the whole log pipeline".
TEST_MODES = frozenset({"triggered", "subtractive"})

# Validation states. A *derived* outcome — not a stored field. The
# stored axis is the boolean `GroundTruth.hw_run_performed` (process: "was a
# hardware validation run done?"); the outcome is a FUNCTION of the field-map
# statuses, so the two can never contradict. Computed by
# `GroundTruth.validation_state`:
#   unvalidated  — no HW run yet (hw_run_performed=False). Every field is still
#                  `hypothesis`/`partial` by construction; nothing was tested.
#   confirmed    — HW run; ≥1 field `verified`, none `refuted`.
#   refuted      — HW run; ≥1 field `refuted`, none `verified`.
#   mixed        — HW run; BOTH `verified` and `refuted` fields present.
#   inconclusive — HW run, but no field reached `verified`/`refuted` (all still
#                  `hypothesis`/`partial` — e.g. environment-gated, the quantity
#                  never appeared). A real run that confirmed nothing.
# Only `confirmed` means "this recipe's mappings are trustworthy". The other
# four all need more RE — that is exactly the `needs_validation_work` predicate
# the `--needs-work` worklist keys on, so a refuted recipe stays visible as
# work-to-do instead of silently reading as "done".
VALIDATION_STATES = frozenset({
    "unvalidated", "confirmed", "refuted", "mixed", "inconclusive",
})

# Parser provenance — where a parser's field layout / decode came from. This is
# the canonical vocabulary; both `register()` (via ParserEntry construction) and
# the metadata test (tests/test_registry.py) reference this set, so the two can
# never drift.
#   re        — reverse-engineered from the capture corpus (the default; nearly
#               every parser)
#   oss       — ported from a specific open-source decoder codebase. Currently
#               unused but retained as a real provenance class: the GNSS
#               leaves (0x1476/1477/1480/14DE/14E1) are `re`, their struct
#               layouts confirmed clean-room from the GNSS capture corpus,
#               co-captured F3 output and a vendor decoder's rendered output.
#   community — derived from community / reference implementations + community-
#               sourced names. Distinct from `oss`: a reference impl / community
#               spec, not a single upstream library port. Currently unused but
#               retained: the 0xB0Ex LTE-NAS-OTA family is `re`, its DIAG
#               wrapper derived clean-room from the capture corpus and a
#               vendor decoder's rendered output.
#   vendor    — from a vendor-supplied decoder or reference. Currently unused
#               but retained as a provenance class, and already rendered by
#               docs._render_source_type.
SOURCE_TYPES = frozenset({"re", "oss", "community", "vendor"})


@dataclass(frozen=True)
class Source:
    """One way to obtain a ground-truth quantity (or to trigger the log).

    ``kind`` routes the source to a transport (see SOURCE_KINDS). ``value``
    is the command / message / sentence / action text. ``modem`` names an
    inventory slug when this source is **specific to one modem** — such
    per-modem recipes are kept because that may be the only modem a user owns.
    """
    kind: str
    value: str
    modem: str | None = None
    notes: str = ""
    # F3 rendering family. Only meaningful on kind="f3": "plaintext" (0x79,
    # self-rendered, no qdb) or "qsr4" (0x99/0x98-wrapped, needs a
    # GUID-matched qdb). None = unset. The ground_truth loader requires it on
    # f3 sources; Source only validates it here when it is set, so older
    # inline f3 sources (f3_family=None) still construct.
    f3_family: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in SOURCE_KINDS:
            raise ValueError(
                f"Source.kind={self.kind!r} not in {sorted(SOURCE_KINDS)}"
            )
        if not self.value:
            raise ValueError("Source.value must be non-empty")
        if self.f3_family is not None:
            if self.kind != "f3":
                raise ValueError(
                    f"Source.f3_family={self.f3_family!r} set on a "
                    f"kind={self.kind!r} source; f3_family is only meaningful "
                    f"on kind='f3'."
                )
            if self.f3_family not in F3_FAMILIES:
                raise ValueError(
                    f"Source.f3_family={self.f3_family!r} not in "
                    f"{sorted(F3_FAMILIES)}"
                )


@dataclass(frozen=True)
class FieldGround:
    """How one parser field is ground-truthed, via one or more sources.

    ``parser_field`` is a key in the parser's ``to_dict()`` output (dotted
    for nested/struct fields); ``quantity`` is the physical quantity it is
    believed to carry; ``sources`` is the (non-empty) set of ways to obtain
    that quantity — as many as are known. ``status`` tracks validation.
    """
    parser_field: str
    quantity: str
    sources: tuple[Source, ...] = ()
    status: str = "hypothesis"
    notes: str = ""
    method_notes: str = ""  # authored, witness-free reproduction prose (public)

    def __post_init__(self) -> None:
        if not self.parser_field:
            raise ValueError("FieldGround.parser_field must be non-empty")
        if not self.quantity:
            raise ValueError("FieldGround.quantity must be non-empty")
        if self.status not in GROUND_TRUTH_STATUSES:
            raise ValueError(
                f"FieldGround.status={self.status!r} not in "
                f"{sorted(GROUND_TRUTH_STATUSES)}"
            )
        if not self.sources:
            raise ValueError(
                f"FieldGround for {self.parser_field!r} has no sources — give "
                f"at least one Source so the quantity is actually capturable."
            )

    def sources_of_kind(self, kind: str) -> tuple[Source, ...]:
        return tuple(s for s in self.sources if s.kind == kind)


@dataclass(frozen=True)
class Canary:
    """A liveness-control log code captured alongside the code under test.

    Used only by ``subtractive``-mode recipes. During config ablation, the
    canary discriminates a real per-code prerequisite ("test code gone, canary
    alive") from a global kill that silences the whole log path ("test code
    gone, canary also gone"). The canary MUST be a **log code** (not a DIAG
    event — events ride a separate path and don't prove the ``LOG_F`` pipeline
    is alive) in a **different equipment ID** from the code under test, so the
    ablation cannot silence it for an unrelated reason.

    ``log_code`` is the 16-bit DIAG log code; ``notes`` records WHY it is
    orthogonal to the code under test (its subsystem, why it's always-on, any
    camp-state assumption). The equipment ID is the top nibble
    (``log_code >> 12``); ``equipment_id`` exposes it for the orthogonality
    check.
    """
    log_code: int
    notes: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.log_code, int) or not 0 <= self.log_code <= 0xFFFF:
            raise ValueError(
                f"Canary.log_code={self.log_code!r} must be a 16-bit DIAG log "
                f"code (0x0000–0xFFFF)"
            )
        if not self.notes:
            raise ValueError(
                "Canary.notes must be non-empty — record why this code is "
                "orthogonal to the code under test (subsystem, always-on "
                "reason, camp-state assumption)."
            )

    @property
    def equipment_id(self) -> int:
        """The DIAG equipment ID (top nibble of the 16-bit log code)."""
        return self.log_code >> 12


@dataclass(frozen=True)
class GroundTruth:
    """A per-version capture recipe for a DIAG log code.

    ``version`` is the log version this recipe describes — recipes are
    per-version because the struct layout varies across versions. It is the
    payload[0] version byte for the common byte-versioned codes, but the
    little-endian **u32** version field for the NR5G ML1 family that versions
    itself in a u32 (e.g. 0xB8B5 ``v=0x00030000``). Construction accepts any
    u32; the per-code byte-vs-u32 width is enforced referentially against the
    parser's declared version domain by ``validate_recipe``. A recipe
    may also key to a deliberate *sentinel* version (e.g. 0x1999 ``v=0``) that
    is not the real log version — the width check bounds by width, never by
    enum membership, so sentinels remain legal. ``emitting_modems`` are
    device-inventory slugs observed to emit THIS version. ``cond`` is the
    ``cond:*`` drive-state (a closed conditions vocabulary).
    ``rat`` is the radio access tech (lte/nr5g/gnss/…), free-text. The
    ``field_map`` enumerates the field→quantity→sources groundings.

    Validation workflow. Two orthogonal axes, deliberately kept separate (a
    single ``validated`` boolean would conflate them and force a refuted recipe
    to read as "validated"):

    * **Process** — ``hw_run_performed: bool``. "Was a hardware validation run
      actually done?" An author with no modem leaves it ``False``; the validator
      who runs the capture flips it ``True``.
    * **Outcome** — derived, NOT stored. ``validation_state`` is a *function* of
      the per-field ``status`` values (``hypothesis``/``partial``/``verified``/
      ``refuted``), so the headline outcome can never contradict the field map.
      Only ``confirmed`` means "trustworthy"; ``refuted``/``mixed``/
      ``inconclusive`` all still need RE and stay on the ``--needs-work``
      worklist (see ``VALIDATION_STATES`` and ``needs_validation_work``).

    A recipe is authored as a hypothesis (``hw_run_performed=False``, all fields
    ``hypothesis``/``partial``); a later validator runs it against hardware, flips
    ``hw_run_performed=True``, sets each field to ``verified``/``refuted``, and
    records the exact modem it was run against:

    * ``modem_make`` / ``modem_model`` — the device the recipe was (or, before
      the run, is *recommended* to be) run against. Plain strings so consumers
      can script against them (e.g. filter recipes by make).
    * ``modem_firmware`` — when a run was performed, the firmware version USED
      FOR that run; before it may be blank or a *recommended* version.

    An ``hw_run_performed=True`` recipe MUST carry all three (you cannot claim a
    hardware run without recording what you ran against); a recipe with no run
    may leave any of them blank.
    """
    version: int
    emitting_modems: tuple[str, ...]
    cond: str
    rat: str | None = None
    field_map: tuple[FieldGround, ...] = ()
    notes: str = ""
    # Process axis only: "was a hardware validation run performed?".
    # The OUTCOME ("did the mappings hold?") is derived — see validation_state.
    hw_run_performed: bool = False
    modem_make: str = ""
    modem_model: str = ""
    modem_firmware: str = ""
    method_notes: str = ""  # authored, witness-free reproduction prose (public)
    # Recipe-validation methodology fields. recipe_version tracks edits
    # to THIS recipe over time, independent of the log `version` byte — it is
    # NOT part of recipe_key (identity stays version+make+model+firmware).
    # test_mode selects the validation strategy; canary is the liveness control
    # required by (and only allowed in) subtractive mode.
    recipe_version: str = "1.0.0"
    test_mode: str = "triggered"
    canary: "Canary | None" = None

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or not 0 <= self.version <= 0xFFFFFFFF:
            raise ValueError(
                f"GroundTruth.version={self.version!r} must fit a u32 log "
                f"version (0–0xFFFFFFFF): byte-versioned codes use payload[0] "
                f"(0–255); u32-versioned NR5G ML1 codes (e.g. 0xB8B5 "
                f"v=0x00030000) use the little-endian u32 version field. The "
                f"per-code WIDTH (byte vs u32) is checked against the "
                f"parser's declared version domain when a recipe is validated."
            )
        if not self.emitting_modems:
            raise ValueError(
                "GroundTruth.emitting_modems is empty — a recipe must name "
                "at least one modem that emits this version (else it is not a "
                "reproducible capture target)."
            )
        if not self.cond:
            raise ValueError("GroundTruth.cond must be a non-empty cond:* key")
        if self.hw_run_performed and not (
            self.modem_make and self.modem_model and self.modem_firmware
        ):
            raise ValueError(
                "a GroundTruth with hw_run_performed=True must record the modem "
                "it was run against: set modem_make, modem_model, and "
                "modem_firmware (the firmware version used for the run)."
            )
        # `verified`/`refuted` are hardware-validation outcomes — they can only
        # be produced by a dedicated verification run that captures the log on
        # the modem AND polls the paired AT/QMI reference. An authoring pass has
        # no modem in hand and runs no capture, so a recipe with
        # hw_run_performed=False must not pre-declare any field as
        # verified/refuted; the honest authoring statuses are `hypothesis` and
        # `partial`. The later validator flips hw_run_performed=True and sets the
        # confirmed/disproved field statuses together. Without this guard an
        # author could silently overclaim a mapping as confirmed. A no-hardware
        # author cannot fabricate outcomes, yet a hardware run that refutes a
        # mapping does not produce a "looks-validated" state, because the
        # headline is derived (validation_state), not a boolean.
        if not self.hw_run_performed:
            bad = sorted({
                f.status for f in self.field_map
                if f.status in ("verified", "refuted")
            })
            if bad:
                raise ValueError(
                    f"GroundTruth(hw_run_performed=False) has field(s) with "
                    f"status {bad} — but {bad} are hardware-validation outcomes "
                    "that only a dedicated verification run can set. An authoring "
                    "pass cannot verify (no modem, no capture): use "
                    "status='hypothesis' or 'partial'. The validator sets "
                    "verified/refuted when it flips hw_run_performed=True."
                )
        if not self.recipe_version:
            raise ValueError(
                "GroundTruth.recipe_version must be a non-empty version string "
                "(e.g. '1.0.0') — it tracks edits to this recipe over time."
            )
        if self.test_mode not in TEST_MODES:
            raise ValueError(
                f"GroundTruth.test_mode={self.test_mode!r} not in "
                f"{sorted(TEST_MODES)}"
            )
        # Biconditional: a subtractive recipe MUST name a canary, and a
        # triggered recipe MUST NOT (the trigger is the recipe — a canary would
        # be meaningless).
        if self.test_mode == "subtractive" and self.canary is None:
            raise ValueError(
                "a subtractive-mode recipe must name a canary liveness-control "
                "log code (set canary=Canary(...)); without it, an ablation "
                "negative cannot be distinguished from a global log-path kill."
            )
        if self.test_mode == "triggered" and self.canary is not None:
            raise ValueError(
                "a triggered-mode recipe must not set a canary (the trigger IS "
                "the recipe). Use test_mode='subtractive' if you are discovering "
                "the required-config set by ablation."
            )
        if self.canary is not None and not isinstance(self.canary, Canary):
            raise ValueError(
                f"GroundTruth.canary must be a Canary instance, got "
                f"{type(self.canary).__name__}"
            )

    @property
    def recipe_key(self) -> tuple[int, str, str, str]:
        """Identity of this recipe within a log code: ``(version, make, model,
        firmware)``. Recipes are unique by this tuple, so a code can hold many
        recipes per version as long as each targets a distinct modem."""
        return (self.version, self.modem_make, self.modem_model,
                self.modem_firmware)

    @property
    def verified_fields(self) -> tuple[FieldGround, ...]:
        """Field-map entries whose mapping is confirmed against a capture."""
        return tuple(f for f in self.field_map if f.status == "verified")

    @property
    def validation_state(self) -> str:
        """Derived headline outcome — a member of ``VALIDATION_STATES``.

        A function of ``hw_run_performed`` + the field-map statuses, so it can
        never contradict the detail. ``"confirmed"`` is the ONLY state that
        means the recipe's mappings are trustworthy; the other four all still
        need RE (see :pyattr:`needs_validation_work`).
        """
        if not self.hw_run_performed:
            return "unvalidated"
        statuses = {f.status for f in self.field_map}
        has_verified = "verified" in statuses
        has_refuted = "refuted" in statuses
        if has_verified and has_refuted:
            return "mixed"
        if has_verified:
            return "confirmed"
        if has_refuted:
            return "refuted"
        # A real run that reached no verified/refuted field — everything is
        # still hypothesis/partial (e.g. the quantity never appeared in the
        # capture, environment-gated). The run happened but confirmed nothing.
        return "inconclusive"

    @property
    def needs_validation_work(self) -> bool:
        """True when this recipe still needs RE — i.e. it is NOT ``confirmed``.

        The ``--needs-work`` worklist predicate. Keeps refuted / mixed /
        inconclusive recipes visible as work-to-do instead of letting a hardware
        run silently drop them off the worklist."""
        return self.validation_state != "confirmed"

    @property
    def validation_target(self) -> str:
        """Human ``"Make Model @ firmware"`` string for the modem this recipe
        was (or is recommended to be) validated against; ``""`` if no make/model
        is set, and the ``@ firmware`` suffix is omitted when firmware is blank.
        """
        base = f"{self.modem_make} {self.modem_model}".strip()
        if not base:
            return ""
        return f"{base} @ {self.modem_firmware}" if self.modem_firmware else base


def _validate_wigle_kwargs(
    wigle_direct: bool | None,
    wigle_roles: tuple[str, ...],
) -> None:
    """Validate the @register() WiGLE-tagging kwargs against the spec.

    Invariants enforced:
      1. Each role string is in WIGLE_DIRECT_ROLES, WIGLE_INDIRECT_ROLES,
         or of the form "timing-anchor:<sub>" with <sub> in
         WIGLE_TIMING_SUBFLAGS. Bare "timing-anchor" without a sub-flag
         is rejected.
      2. wigle_direct=True requires at least one role in
         WIGLE_DIRECT_ROLES.
      3. wigle_direct=False requires all roles to be indirect.
      4. The four representable states are:
           (None,  ())            — unlabeled / not yet triaged
           (True,  <≥1 direct>)   — direct tier
           (False, <all indirect>)— indirect tier
           (False, ())            — DECIDED-NONE: reviewed and found
                                    not WiGLE-relevant (a decision, not
                                    absence-of-decision)
         The only rejected empty-roles combinations are (None, <roles>),
         (<flag>, <roles>) mismatches, and (True, ()) — a direct-tier parser
         must carry at least one direct role.

    Raises ValueError with an actionable message on any violation. The
    caller (register()) propagates this up at decorator-evaluation time,
    surfacing bad tags as parser-import failures.
    """
    # Invariant 4a: both unset is the "unlabeled" path — accept.
    if wigle_direct is None and not wigle_roles:
        return

    # Invariant 4b: roles present without a flag is a contradiction.
    if wigle_direct is None and wigle_roles:
        raise ValueError(
            f"wigle_roles={wigle_roles!r} but wigle_direct is unset. "
            f"Set wigle_direct=True (for direct-tier) or wigle_direct=False "
            f"(for indirect-tier) to match the roles."
        )
    if wigle_direct is True and not wigle_roles:
        raise ValueError(
            f"wigle_direct={wigle_direct!r} but wigle_roles is empty. "
            f"Provide at least one role from WIGLE_DIRECT_ROLES "
            f"or WIGLE_INDIRECT_ROLES."
        )
    # Invariant 4c: wigle_direct=False with no roles is the DECIDED-NONE
    # state — "reviewed, contributes nothing to a WiGLE observation."
    # It is a *decision*, distinct from the (None, ()) "not yet triaged"
    # state above. Accept and short-circuit before
    # the role-vocabulary loop (there are no roles to validate).
    if wigle_direct is False and not wigle_roles:
        return

    # Invariant 1: every role string is in the closed vocabulary.
    direct_seen: list[str] = []
    for role in wigle_roles:
        if role in WIGLE_DIRECT_ROLES:
            direct_seen.append(role)
            continue
        if role in WIGLE_INDIRECT_ROLES:
            continue
        if role == "timing-anchor":
            raise ValueError(
                "wigle_roles contains bare 'timing-anchor' without a "
                "sub-flag. Use 'timing-anchor:one-shot', "
                "'timing-anchor:periodic', or 'timing-anchor:on-fix' "
                "(see WIGLE_TIMING_SUBFLAGS)."
            )
        if role.startswith("timing-anchor:"):
            sub = role.split(":", 1)[1]
            if sub not in WIGLE_TIMING_SUBFLAGS:
                raise ValueError(
                    f"wigle_roles contains {role!r}; sub-flag {sub!r} "
                    f"is not in WIGLE_TIMING_SUBFLAGS "
                    f"({sorted(WIGLE_TIMING_SUBFLAGS)})."
                )
            continue
        raise ValueError(
            f"wigle_roles contains unknown role {role!r}. Allowed: "
            f"WIGLE_DIRECT_ROLES={sorted(WIGLE_DIRECT_ROLES)}, "
            f"WIGLE_INDIRECT_ROLES={sorted(WIGLE_INDIRECT_ROLES)}, "
            f"or 'timing-anchor:<sub>' with sub in "
            f"{sorted(WIGLE_TIMING_SUBFLAGS)}."
        )

    # Invariants 2 + 3: the iff rule.
    if wigle_direct is True and not direct_seen:
        raise ValueError(
            f"wigle_direct=True but wigle_roles={wigle_roles!r} has no "
            f"role in WIGLE_DIRECT_ROLES "
            f"({sorted(WIGLE_DIRECT_ROLES)}). A direct-tier parser must "
            f"carry at least one direct role."
        )
    if wigle_direct is False and direct_seen:
        raise ValueError(
            f"wigle_direct=False conflicts with wigle_roles={wigle_roles!r} "
            f"containing direct role(s) {direct_seen!r}. An indirect-tier "
            f"parser must not carry any role in WIGLE_DIRECT_ROLES."
        )


# ── ASCII-content tagging vocabulary ───────────────────────────────
# Closed vocabulary for the ascii_kinds kwarg on @register().
#
#   xml-event    — QSR/F3-rendered structured-event XML (<in mod=...><arg/>)
#   f3-debug     — free-text F3 / extended debug (printf-style; e.g. 0x1FFB)
#   config-token — embedded config/profile/APN/path/operator-name strings
#   nmea         — NMEA sentences in a GNSS passthrough code
#   label        — short fixed diagnostic labels / enum names ("Small pool")
#   identifier   — ASCII identifiers that may be PII (IMSI/ICCID/SW version)
ASCII_KINDS = frozenset({
    "xml-event",
    "f3-debug",
    "config-token",
    "nmea",
    "label",
    "identifier",
})


def _validate_ascii_kinds(ascii_kinds: tuple[str, ...]) -> None:
    """Validate the @register() ascii_kinds kwarg against ASCII_KINDS.

    Empty / unset is the "no ASCII" path — accepted. Otherwise every token
    must be in the closed ASCII_KINDS vocabulary. Raises ValueError with the
    allowed set on any unknown kind, surfacing bad tags as parser-import
    failures (same ergonomics as _validate_wigle_kwargs).
    """
    for kind in ascii_kinds:
        if kind not in ASCII_KINDS:
            raise ValueError(
                f"ascii_kinds contains unknown ascii kind {kind!r}. "
                f"Allowed: {sorted(ASCII_KINDS)}."
            )


# Closed vocabulary for the timebase_roles kwarg on @register().
#
# A timebase_roles tag marks a log code as useful for time-based alignment of
# different log files. It is a capability axis distinct from wigle_roles
# (WiGLE-wardrive completeness) and ascii_kinds (carries ASCII).
#
#   metronome     — emits at a regular cadence and carries a monotonic,
#                   capture-clock-correlated per-record field (ideally a clean
#                   linear function of ts64). Usable as a beat for resampling
#                   sparse logs and detecting ts64 resets/gaps. The cadence MAY
#                   be modem-state-dependent. (e.g. 0xB116: body data[1:3] ==
#                   ts64/2^15.)
#   ts-anchor     — body carries a field mapping the modem DIAG ts64 to an
#                   external/absolute clock (wall or GPS), enabling cross-stream
#                   anchoring.
#   absolute-time — body carries a real-world timestamp directly (GPS week/TOW,
#                   UTC) — e.g. GNSS time logs.
TIMEBASE_ROLES = frozenset({
    "metronome",
    "ts-anchor",
    "absolute-time",
})


def _validate_timebase_roles(timebase_roles: tuple[str, ...]) -> None:
    """Validate the @register() timebase_roles kwarg against TIMEBASE_ROLES.

    Empty / unset is the "not a timebase log" path — accepted. Otherwise every
    token must be in the closed TIMEBASE_ROLES vocabulary. Raises ValueError
    with the allowed set on any unknown role, surfacing bad tags as parser-import
    failures (same ergonomics as _validate_ascii_kinds).
    """
    for role in timebase_roles:
        if role not in TIMEBASE_ROLES:
            raise ValueError(
                f"timebase_roles contains unknown timebase role {role!r}. "
                f"Allowed: {sorted(TIMEBASE_ROLES)}."
            )


# Closed vocabulary for the @register() ``domain`` kwarg. A domain is the
# topical bucket codes are grouped by (the ``--domain`` selector on the
# diaggrok-extract tool). Unlike wigle_roles / ascii_kinds (capability axes, a
# code can carry several), a code has at most one domain.
# Extensible: add a `name: human description` entry to grow the vocabulary;
# DOMAIN_VOCAB (the validation set) and the generated domain descriptions both
# derive from this one dict.
DOMAIN_DESCRIPTIONS: dict[str, str] = {
    "gnss": ("GNSS position/measurement (GPS/GLONASS/BeiDou/Galileo engine, "
             "NMEA-over-DIAG, per-SV measurements)"),
    "lte-signal": ("LTE serving/neighbor signal levels (PCI, EARFCN, RSRP, "
                   "RSRQ measurements)"),
    "lte-ml1": ("LTE ML1 Layer-1 state (connected-mode scheduler, RX-diversity "
                "antenna selection, intra/inter-freq measurement, sleep-manager "
                "snapshots) - distinct from lte-signal serving/neighbor levels"),
    "coex": ("Modem RF coexistence manager (MCS_CXM WWAN/WLAN/BT/GNSS "
             "arbitration priority + activity tables, cxm_send_log dumps)"),
    "nas": ("EMM/ESM NAS signaling (LTE EMM/ESM, NR5G 5GMM/5GSM, UMTS MM/GMM "
            "OTA + state)"),
    "rrc": ("LTE/NR RRC OTA + state (ASN.1 PER OTA messages, RRC events, CA "
            "band combos)"),
    "wcdma-signal": ("WCDMA/UMTS searcher + signal (PN search peaks per "
                     "scrambling code, UARFCN/PSC identity, searcher energies)"),
}

DOMAIN_VOCAB = frozenset(DOMAIN_DESCRIPTIONS)


def _validate_domain(domain: str | None) -> None:
    """Validate the @register() ``domain`` kwarg against DOMAIN_VOCAB.

    None (unset) is the "undomained" path — accepted; such a code is still
    reachable via diaggrok-extract's ``--codes`` escape hatch. Otherwise the
    value must be a single token in the closed DOMAIN_VOCAB. Raises ValueError
    with the allowed set on any unknown domain, surfacing a bad tag as a
    parser-import failure (same ergonomics as _validate_timebase_roles).
    """
    if domain is None:
        return
    if domain not in DOMAIN_VOCAB:
        raise ValueError(
            f"domain={domain!r} is not in the closed vocabulary. "
            f"Allowed: {sorted(DOMAIN_VOCAB)}."
        )


logger = logging.getLogger(__name__)


_ISSUE_REF_RE = re.compile(r"#(\d+)")


@dataclass
class ParserEntry:
    """Metadata and function for a registered parser."""
    func: ParserFunc
    log_code: int
    name: str
    description: str
    version: int
    author: str
    author_url: str
    source_type: str      # one of SOURCE_TYPES: "re" | "oss" | "community" | "vendor"
    source_detail: str
    source_url: str
    # Completeness metrics — optional, default None ("unknown").
    # fields_identified: total fields observed in the binary payload (decoded
    #   + still-opaque), i.e. everything the log is known to carry.
    # fields_parsed: of those, how many the parser currently exposes in its
    #   result dataclass. When parsed == identified > 0 AND a cross-modem
    #   test exists, the inventory marks the row as verified.
    fields_identified: int | None = None
    fields_parsed: int | None = None
    # GitHub issue numbers tracking this parser (open OR closed). When
    # empty, issue_refs falls back to parsing `(#NNN)` tokens out of
    # source_detail + description — the historical free-text convention.
    # Explicit kwarg wins over inferred refs.
    issues: tuple[int, ...] = field(default_factory=tuple)
    # The canonical "main tracker" issue for this log code.
    # When None, primary_ref auto-derives it for single-issue codes; a
    # multi-issue code with no explicit primary is "undesignated". When set
    # alongside issues=, it must be a member of issues= (validated in register()).
    primary_issue: int | None = None
    # Layer-2 plausibility invariants. Mapping of field-name → spec.
    # Spec keys: ``range=(lo, hi)`` (inclusive numeric bounds), ``enum``
    # (allowed values), ``required_populated=True`` (non-None present).
    # Evaluated by ``check_invariants()`` against the parser's
    # ``to_dict()`` output. Empty dict / None means "no invariants".
    field_invariants: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Versions this parser explicitly supports (set of integers).
    # When non-empty, Layer 1's corpus sweep flags any payload[0] value
    # NOT in this set as real version drift (vs the old "multi-value
    # histogram" heuristic that over-fires on counter-in-byte-0 parsers).
    # Empty frozenset = unset = preserve legacy heuristic.
    supported_versions: frozenset[int] = field(default_factory=frozenset)
    # RE-proven version-less marker. When True, an RE pass has
    # concluded this log code carries NO version byte at all — byte-0 is
    # something else (a state, an identity-type selector, a message-class
    # descriptor, or pure residue). This is a *deliberate, evidenced* third
    # state distinct from "never analyzed": it tells the version-compliance
    # worklist to stop demanding a `field_invariants['version']` enum that
    # would be factually wrong. It is mutually exclusive with declaring a
    # version (validated in register()): a code cannot both have and lack a
    # version. The RE evidence must be cited in source_detail/description so
    # the marker can never become a silent escape hatch for un-RE'd parsers.
    version_less: bool = False
    # WiGLE-complete tagging. Both default to "unlabeled"
    # (off-topic for WiGLE). When set, they must satisfy the iff invariant
    # validated by _validate_wigle_kwargs() in register().
    wigle_direct: bool | None = None
    wigle_roles: tuple[str, ...] = field(default_factory=tuple)
    # ASCII-content tagging. Empty = "no ASCII". When set,
    # every entry must be in ASCII_KINDS, validated by _validate_ascii_kinds()
    # in register().
    ascii_kinds: tuple[str, ...] = field(default_factory=tuple)
    # Time-alignment capability tagging. Empty = "not a
    # timebase log". When set, every entry must be in TIMEBASE_ROLES, validated
    # by _validate_timebase_roles() in register(). A capability axis distinct
    # from wigle_roles / ascii_kinds — marks logs useful for time-based
    # alignment of different log files.
    timebase_roles: tuple[str, ...] = field(default_factory=tuple)
    # Topical domain. At most one bucket per code; None = "undomained". When
    # set, must be in DOMAIN_VOCAB (validated by _validate_domain() in
    # register()). This is the register-time source of truth the per-domain
    # code listing is generated from.
    domain: str | None = None
    # Ground-truth capture recipes are not on the ParserEntry: they live in the
    # standalone diaggrok.ground_truth store, joined to parsers by
    # (log_code, log_version) identity. A code may carry many recipes —
    # typically one per modem — for each log version. Query via
    # GroundTruthStore.recipes_for(entry.log_code, ...) — see that module.
    # Parser-version tie-break. log_version: the specific diag log
    # version this parser handles; None = combined/catch-all (handles any
    # version not covered by an enumerated override — every built-in parser).
    # parser_version (pv): a monotonic generation counter, the tie-breaker among
    # registrations sharing (log_code, log_version). version_field: how the log
    # version is extracted from the payload for override routing.
    log_version: int | None = None
    parser_version: int = 1
    version_field: str = "u8"

    # Recipe queries live on GroundTruthStore, not here. Use
    # GroundTruthStore.recipes_for(entry.log_code[, version]) and filter on the
    # GroundTruth fields (hw_run_performed / validation_state /
    # needs_validation_work), or GroundTruthStore.confirmed_recipes(code).

    @property
    def has_ascii(self) -> bool:
        """True when this log code is tagged as carrying any ASCII content."""
        return bool(self.ascii_kinds)

    @property
    def issue_refs(self) -> tuple[int, ...]:
        """All GitHub issue numbers associated with this parser.

        Returns the explicit ``issues=`` tuple when set; otherwise parses
        ``#NNN`` tokens from ``source_detail`` + ``description`` (the legacy
        free-text convention) and folds in ``primary_issue`` if set.
        """
        if self.issues:
            return self.issues
        haystack = f"{self.source_detail} {self.description}"
        refs = {int(m) for m in _ISSUE_REF_RE.findall(haystack)}
        if self.primary_issue is not None:
            refs.add(self.primary_issue)
        return tuple(sorted(refs))

    @property
    def primary_ref(self) -> int | None:
        """The canonical 'main tracker' issue, or None if undesignated.

        Explicit ``primary_issue`` wins; otherwise a single-issue code
        auto-derives its one issue; a multi-issue code with no explicit
        primary returns None ('undesignated').
        """
        if self.primary_issue is not None:
            return self.primary_issue
        refs = self.issue_refs
        return refs[0] if len(refs) == 1 else None

    @property
    def additional_refs(self) -> tuple[int, ...]:
        """Issue refs other than the primary, ascending. When undesignated,
        this is all refs (they render as the 'also=' list under primary=?)."""
        refs = self.issue_refs
        p = self.primary_ref
        if p is None:
            return tuple(sorted(refs))
        return tuple(sorted(n for n in refs if n != p))

    @property
    def wigle_tier(self) -> str | None:
        """Return 'direct', 'indirect', 'none', or None from the wigle tags.

        Four states, matching _validate_wigle_kwargs invariant 4:
          - ``"direct"``   — wigle_direct=True (≥1 direct role)
          - ``"indirect"`` — wigle_direct=False with indirect role(s)
          - ``"none"``     — wigle_direct=False, wigle_roles=() — the
            DECIDED-NONE state: reviewed and found not
            WiGLE-relevant. A decision, distinct from ``None``.
          - ``None``       — wigle_direct=None — unlabeled / not yet triaged

        Consumers can switch on the string; the ``"none"`` string vs Python
        ``None`` split is what lets tooling (e.g. wigle_tag_suggest rule-0)
        tell "reviewed, skip" from "nobody has looked yet."
        """
        if self.wigle_direct is True:
            return "direct"
        if self.wigle_direct is False:
            return "indirect" if self.wigle_roles else "none"
        return None


# Version-extraction schemes for per-log_version override routing.
# Only consulted for codes that actually carry enumerated overrides — combined
# (catch-all) parsers never trigger extraction.
VERSION_FIELDS = frozenset({"u8", "u32le", "none"})

# ``"u8@N"``: a single version byte at payload offset N (1..63) — for codes
# whose version is not byte 0 (the 0x1CAF/0x1CB0/0x1CB1 outer-header family at
# data[3]; 0xB110 at data[9], where byte 0 is a sequence-id LSB). Declaring it
# makes the unhandled WARN and the unhandled tally report the real version
# instead of whatever byte happens to sit at offset 0.
_U8_AT_MAX = 63


def _u8_at_offset(version_field: str) -> int | None:
    """Return N for a well-formed ``"u8@N"`` (1..63), else None."""
    if not version_field.startswith("u8@"):
        return None
    tail = version_field[3:]
    if not tail.isdigit():
        return None
    n = int(tail)
    return n if 1 <= n <= _U8_AT_MAX else None


def is_valid_version_field(version_field: str) -> bool:
    return version_field in VERSION_FIELDS or _u8_at_offset(version_field) is not None


def version_offset(version_field: str) -> int | None:
    """Byte offset of a single-byte version field (0 for ``"u8"``, N for
    ``"u8@N"``); None for ``"u32le"`` / ``"none"``."""
    if version_field == "u8":
        return 0
    return _u8_at_offset(version_field)


def version_of(version_field: str, data: bytes) -> int | None:
    """Extract a DIAG record's log-version from its payload.

    ``"u8"`` reads ``data[0]`` (the byte-versioned majority); ``"u8@N"`` reads
    ``data[N]``; ``"u32le"`` reads a little-endian u32 at offset 0 (the NR5G ML1
    family); ``"none"`` is a version-less code. Returns ``None`` when the scheme
    is ``"none"`` or the payload is too short to carry the version field — the
    caller then falls through to the catch-all parser (graceful degradation).
    """
    if version_field == "u8":
        return data[0] if len(data) >= 1 else None
    if version_field == "u32le":
        return int.from_bytes(data[0:4], "little") if len(data) >= 4 else None
    if version_field == "none":
        return None
    n = _u8_at_offset(version_field)
    if n is not None:
        return data[n] if len(data) > n else None
    raise ValueError(
        f"unknown version_field {version_field!r}; expected one of "
        f"{sorted(VERSION_FIELDS)} or 'u8@N' (N in 1..{_U8_AT_MAX})"
    )


_registry: dict[int, ParserEntry] = {}

# Winning enumerated (per-log_version) parser per (log_code, log_version).
# Empty by default: the built-in parsers are all catch-alls in _registry.
_overrides: dict[int, dict[int, ParserEntry]] = {}


def _extract_to_dict_keys_via_ast(dataclass_cls: type) -> set[str] | None:
    """Best-effort extract the string keys returned by ``dataclass_cls.to_dict``.

    Walks the AST of the method body looking for a single ``return {literal}``
    expression and returns its string-Constant keys. Returns ``None`` when
    the method body isn't a simple dict-literal return (conditional logic,
    dict comprehensions, computed/non-string keys) so callers can fall back
    rather than false-positive on inspectable methods. The goal
    is to catch the schema-mismatch pattern (invariant key not emitted
    by to_dict) without blocking parsers whose to_dict() does legitimate
    branching.
    """
    if not hasattr(dataclass_cls, "to_dict"):
        return None
    try:
        source = textwrap.dedent(inspect.getsource(dataclass_cls.to_dict))
    except (TypeError, OSError):
        return None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    if not tree.body or not isinstance(tree.body[0], ast.FunctionDef):
        return None
    returns = [n for n in ast.walk(tree.body[0]) if isinstance(n, ast.Return)]
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Dict):
        return None
    keys: set[str] = set()
    for key_node in returns[0].value.keys:
        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
            keys.add(key_node.value)
        else:
            return None
    return keys


def _check_field_invariants_schema(
    parser_func: ParserFunc,
    field_invariants: dict[str, dict[str, Any]],
) -> None:
    """Check for the schema-mismatch pattern in ``field_invariants``.

    The canonical pattern is an invariant declared on
    a dataclass field that ``to_dict()`` splits or renames before emitting
    (e.g. the ``slots`` field becomes ``gps_slots`` + ``glonass_slots`` in
    ``to_dict()``). The invariant checker walks ``to_dict()`` output, so
    such an invariant produces a 100% false-positive violation rate that
    stays silent until a corpus audit runs.

    Detection strategy: parse the parser's return type annotation, find the
    declared dataclass, AST-inspect its ``to_dict()`` method to extract the
    set of emitted keys, and compare against the invariant keys. If AST
    inspection can't statically resolve the keys (conditional logic, dict
    comprehensions, etc.), the check is silently skipped — better to miss
    some bugs than false-positive on parser-import.

    Mode: by default, orphan keys produce a ``logger.warning`` (visible in
    log output but non-fatal). When the env var
    ``DIAGGROK_STRICT_INVARIANT_SCHEMA=1`` is set, orphan keys raise
    ``ValueError`` instead — used in CI to ratchet the regression floor.
    Warn-by-default accommodates orphan-key cases that predate the check;
    strict mode becomes the default once none remain.
    """
    if not field_invariants:
        return
    try:
        hints = typing.get_type_hints(parser_func)
    except Exception:
        return
    return_type = hints.get("return")
    if return_type is None:
        return
    args = typing.get_args(return_type)
    candidates = (
        [a for a in args if a is not type(None)] if args else [return_type]
    )
    for cand in candidates:
        if not dataclasses.is_dataclass(cand):
            continue
        to_dict_keys = _extract_to_dict_keys_via_ast(cand)
        if to_dict_keys is None:
            continue
        invariant_keys = set(field_invariants.keys())
        orphan = invariant_keys - to_dict_keys
        if orphan:
            msg = (
                f"field_invariants declares keys not emitted by "
                f"{cand.__module__}.{cand.__name__}.to_dict(): "
                f"{sorted(orphan)}. to_dict() emits: {sorted(to_dict_keys)}. "
                f"This is a schema mismatch — either rename "
                f"the invariant key to match to_dict() output or remove the "
                f"orphan keys."
            )
            if os.environ.get("DIAGGROK_STRICT_INVARIANT_SCHEMA") == "1":
                raise ValueError(msg)
            logger.warning(msg)
        return


def _same_identity(a: ParserFunc, b: ParserFunc) -> bool:
    """True when two parser functions are the same definition (module +
    qualified name) — the importlib.reload / re-import pattern."""
    a_q = getattr(a, "__qualname__", a.__name__)
    b_q = getattr(b, "__qualname__", b.__name__)
    return a.__module__ == b.__module__ and a_q == b_q


def _resolve_slot(
    existing: ParserEntry | None, new: ParserEntry, replace: bool, ident: str
) -> ParserEntry:
    """Decide which entry occupies a (log_code, log_version) slot, applying the
    pv tie-break and collision rule. Higher parser_version supersedes; equal
    parser_version from a different function raises (a duplicate-registration
    guard); a same-identity reload or replace=True updates in place."""
    if existing is None or replace or _same_identity(existing.func, new.func):
        return new
    if new.parser_version > existing.parser_version:
        return new
    if new.parser_version < existing.parser_version:
        return existing
    raise ValueError(
        f"Parser already registered for {ident} at parser_version="
        f"{existing.parser_version}: {existing.func.__module__}."
        f"{existing.func.__name__} (name={existing.name!r}). Bump "
        f"parser_version to supersede it, or pass replace=True."
    )


def _check_version_field_agreement(log_code: int, version_field: str) -> None:
    """All registrations for a code must agree on how its version is extracted,
    so a standalone drop-in override file is self-contained."""
    seen: list[ParserEntry] = []
    ca = _registry.get(log_code)
    if ca is not None:
        seen.append(ca)
    seen.extend(_overrides.get(log_code, {}).values())
    for e in seen:
        if e.version_field != version_field:
            raise ValueError(
                f"version_field mismatch for log_code 0x{log_code:04X}: "
                f"existing {e.version_field!r} vs new {version_field!r}; all "
                f"registrations for a code must agree on version extraction"
            )


def register(
    log_code: int,
    *,
    name: str = "",
    description: str = "",
    version: int = 0,
    author: str = "Unknown",
    author_url: str = "",
    source_type: str = "re",
    source_detail: str = "",
    source_url: str = "",
    fields_identified: int | None = None,
    fields_parsed: int | None = None,
    issues: int | Sequence[int] | None = None,
    primary_issue: int | None = None,
    field_invariants: dict[str, dict[str, Any]] | None = None,
    supported_versions: Sequence[int] | None = None,
    version_less: bool = False,
    wigle_direct: bool | None = None,
    wigle_roles: Sequence[str] | None = None,
    ascii_kinds: Sequence[str] | None = None,
    timebase_roles: Sequence[str] | None = None,
    domain: str | None = None,
    replace: bool = False,
    log_version: int | None = None,
    parser_version: int = 1,
    version_field: str = "u8",
) -> Callable:
    """Decorator that registers a parser function with metadata.

    Usage:
        @register(0x1477,
            name="GPS L1 Measurement Report",
            version=1,
            author="Luke Jenkins",
            author_url="https://github.com/lukejenkins",
            source_type="re",
            source_detail="Clean-room: struct confirmed from the "
                          "DIAG capture corpus + co-captured F3 output",
            issues=(),
        )
        def parse_gps_measurement(log_time: int, data: bytes) -> Result:
            ...

    All keyword arguments are optional for backward compatibility.
    If name is omitted, the function name is used (underscores → spaces).
    ``issues`` accepts a single int or a sequence of ints; when omitted,
    ``ParserEntry.issue_refs`` falls back to parsing ``#NNN`` tokens out
    of ``source_detail`` + ``description``.

    Duplicate-registration policy: registering a parser for a ``log_code``
    that already has a parser raises ``ValueError`` by default. This
    catches a class of bugs where a generic stub registered later in
    import order silently displaces a dedicated parser registered
    earlier (0x1900 is the canonical case). To intentionally replace an
    existing registration (e.g. in tests or when promoting a stub to a
    dedicated parser without deleting the stub call site), pass
    ``replace=True``.
    """
    if issues is None:
        issues_tuple: tuple[int, ...] = ()
    elif isinstance(issues, int):
        issues_tuple = (issues,)
    else:
        issues_tuple = tuple(int(i) for i in issues)

    primary_int: int | None = None if primary_issue is None else int(primary_issue)
    if primary_int is not None and issues_tuple and primary_int not in issues_tuple:
        raise ValueError(
            f"primary_issue=#{primary_int} is not in issues={issues_tuple} for "
            f"log_code 0x{log_code:04X}; add it to issues= or fix the number"
        )

    invariants_dict = dict(field_invariants) if field_invariants else {}

    # Normalize supported_versions: accept list/tuple/set/None, store as
    # frozenset of ints. Reject non-int / negative values explicitly —
    # these come from byte[0] of a DIAG payload so 0–255 is the legal range.
    if supported_versions is None:
        supported_versions_set: frozenset[int] = frozenset()
    else:
        try:
            supported_versions_set = frozenset(int(v) for v in supported_versions)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"supported_versions must be a sequence of ints (0–255); "
                f"got {supported_versions!r}"
            ) from exc
        for v in supported_versions_set:
            if not 0 <= v <= 255:
                raise ValueError(
                    f"supported_versions entry {v} out of byte range 0–255"
                )

    # Parser-version tie-break params. bool is an int subclass, so
    # reject it explicitly to avoid True/False sneaking in as 1/0.
    if not isinstance(parser_version, int) or isinstance(parser_version, bool) \
            or parser_version < 1:
        raise ValueError(
            f"parser_version must be an int >= 1; got {parser_version!r} "
            f"for log_code 0x{log_code:04X}"
        )
    if not is_valid_version_field(version_field):
        raise ValueError(
            f"version_field={version_field!r} not in {sorted(VERSION_FIELDS)} "
            f"or 'u8@N' (N in 1..{_U8_AT_MAX}) "
            f"for log_code 0x{log_code:04X}"
        )
    if log_version is not None:
        if not isinstance(log_version, int) or isinstance(log_version, bool) \
                or not 0 <= log_version <= 0xFFFFFFFF:
            raise ValueError(
                f"log_version must be None or a u32 int (0-0xFFFFFFFF); got "
                f"{log_version!r} for log_code 0x{log_code:04X}"
            )
        if version_field == "none":
            raise ValueError(
                f"log_version={log_version} set on a version-less "
                f"(version_field='none') code 0x{log_code:04X}; a version-less "
                f"code cannot carry enumerated per-version overrides"
            )

    # version_less is mutually exclusive with declaring a version: a
    # code cannot both carry and lack a version byte. Reject the contradiction
    # at registration time rather than letting it ship a self-inconsistent
    # header. Both the canonical key and the legacy non-canonical keys count
    # as "declares a version".
    if version_less:
        _VERSION_INVARIANT_KEYS = ("version", "version_byte")
        declared_via = [
            k for k in _VERSION_INVARIANT_KEYS
            if (invariants_dict.get(k) or {}).get("enum")
        ]
        if declared_via or supported_versions_set:
            offenders = declared_via + (
                ["supported_versions"] if supported_versions_set else []
            )
            raise ValueError(
                f"version_less=True conflicts with a declared version "
                f"({', '.join(offenders)}) for log_code 0x{log_code:04X}; "
                f"a code is either version-less OR version-aware, not both"
            )

    # Validate source_type against the canonical provenance vocabulary so a
    # typo (or a new value added without updating SOURCE_TYPES) is caught at
    # registration time, not silently shipped.
    if source_type not in SOURCE_TYPES:
        raise ValueError(
            f"source_type={source_type!r} not in {sorted(SOURCE_TYPES)} for "
            f"log_code 0x{log_code:04X}"
        )

    # Normalize wigle_roles: accept list/tuple/None, store as tuple.
    wigle_roles_tuple: tuple[str, ...] = (
        () if wigle_roles is None else tuple(wigle_roles)
    )
    _validate_wigle_kwargs(wigle_direct, wigle_roles_tuple)
    # Normalize ascii_kinds: accept list/tuple/None, dedup preserving order.
    ascii_kinds_tuple: tuple[str, ...] = (
        () if ascii_kinds is None
        else tuple(dict.fromkeys(ascii_kinds))
    )
    _validate_ascii_kinds(ascii_kinds_tuple)
    # Normalize timebase_roles: accept list/tuple/None, dedup preserving order.
    timebase_roles_tuple: tuple[str, ...] = (
        () if timebase_roles is None
        else tuple(dict.fromkeys(timebase_roles))
    )
    _validate_timebase_roles(timebase_roles_tuple)
    # Normalize domain: treat an empty string as unset (None), then validate.
    domain_norm: str | None = domain or None
    _validate_domain(domain_norm)

    def decorator(func: ParserFunc) -> ParserFunc:
        _check_field_invariants_schema(func, invariants_dict)
        _check_version_field_agreement(log_code, version_field)
        entry_name = name or func.__name__.replace("_", " ")
        entry = ParserEntry(
            func=func,
            log_code=log_code,
            name=entry_name,
            description=description,
            version=version,
            author=author,
            author_url=author_url,
            source_type=source_type,
            source_detail=source_detail,
            source_url=source_url,
            fields_identified=fields_identified,
            fields_parsed=fields_parsed,
            issues=issues_tuple,
            primary_issue=primary_int,
            field_invariants=invariants_dict,
            supported_versions=supported_versions_set,
            version_less=version_less,
            wigle_direct=wigle_direct,
            wigle_roles=wigle_roles_tuple,
            timebase_roles=timebase_roles_tuple,
            ascii_kinds=ascii_kinds_tuple,
            domain=domain_norm,
            log_version=log_version,
            parser_version=parser_version,
            version_field=version_field,
        )
        if log_version is None:
            ident = f"log_code 0x{log_code:04X} (catch-all)"
            _registry[log_code] = _resolve_slot(
                _registry.get(log_code), entry, replace, ident
            )
        else:
            slot = _overrides.setdefault(log_code, {})
            ident = f"log_code 0x{log_code:04X} log_version={log_version}"
            slot[log_version] = _resolve_slot(
                slot.get(log_version), entry, replace, ident
            )
        return func
    return decorator


def resolve(log_code: int, data: bytes) -> ParserEntry | None:
    """The ParserEntry parse() would dispatch to for this record, or None.

    Enumerated (per-log_version) overrides take precedence over the catch-all
    for their version; the highest parser_version within each tier already won
    at registration. Version extraction is lazily gated — it runs only when the
    code actually has enumerated overrides, so catch-all-only codes (every
    built-in) never invoke it.
    """
    overrides = _overrides.get(log_code)
    if overrides:
        version_field = next(iter(overrides.values())).version_field
        v = version_of(version_field, data)
        if v is not None and v in overrides:
            return overrides[v]
    return _registry.get(log_code)


# Rate-limit state for the unhandled-(code, version) WARN. One entry
# per (log_code, version) that has already been announced. A silent drop on a
# multi-100k-record corpus walk would otherwise fire per record; the corpus
# only holds a handful of distinct (code, version) pairs, so this set stays
# tiny while a downgraded-to-once-each WARN still surfaces every blind spot.
_UNHANDLED_WARN_SEEN: set[tuple[int, int | None]] = set()

# Full runtime tally of unhandled (code, version) drops. Where the set
# above records a key once to gate the WARN emission, this counts every drop and
# keeps a representative payload length plus the dropping parser's identity —
# the harvest side of the unhandled channel. A sweep reads it via
# unhandled_seen() / unhandled_tally() instead of regexing WARN text (a log
# line is a gauge nobody reads). It is populated independently of the WARN
# rate-limit AND of DIAGGROK_QUIET_UNHANDLED: that env silences the *log line*,
# not this *data channel*.
_UNHANDLED_TALLY: dict[tuple[int, int | None], dict[str, Any]] = {}


def reset_unhandled_warn_cache() -> None:
    """Clear both the WARN rate-limit set and the runtime tally.

    For tests (so one test's drop does not suppress another's WARN or leak into
    another's ``unhandled_tally()`` reading) and for a long-lived sweep that
    wants each distinct blind spot re-announced and re-counted per run.
    """
    _UNHANDLED_WARN_SEEN.clear()
    _UNHANDLED_TALLY.clear()


def unhandled_seen() -> list[tuple[int, int | None]]:
    """Distinct ``(log_code, version)`` pairs ``parse()`` dropped this run.

    The public read side of the unhandled-drop channel: every pair for
    which a *registered* parser returned ``None``, so a corpus sweep can harvest
    what was dropped without scraping WARN text. Sorted by code, then version
    (``version=None`` sorts last within a code). Independent of
    ``DIAGGROK_QUIET_UNHANDLED`` — that env silences the log, not this tally.
    """
    return sorted(
        _UNHANDLED_TALLY,
        key=lambda k: (k[0], k[1] is None, k[1] if k[1] is not None else -1),
    )


def unhandled_tally() -> list[dict[str, Any]]:
    """Rich rows for the unhandled collector — one per dropped ``(code, version)``.

    Each row carries ``code`` (int), ``version`` (int | None), ``length`` (a
    representative dropped-payload length), ``count`` (total drops this run), and
    ``module`` / ``func`` (the parser that dropped it). Ordered most-dropped
    first so the loudest blind spot reads at the top of a sweep report.
    """
    rows = [
        {
            "code": code,
            "version": version,
            "length": rec["length"],
            "count": rec["count"],
            "module": rec["module"],
            "func": rec["func"],
        }
        for (code, version), rec in _UNHANDLED_TALLY.items()
    ]
    rows.sort(
        key=lambda r: (
            -r["count"],
            r["code"],
            r["version"] if r["version"] is not None else -1,
        )
    )
    return rows


def _warn_unhandled(log_code: int, entry: "ParserEntry", data: bytes) -> None:
    """Emit a structured, rate-limited WARN that a registered code produced no
    decode for this payload — a loud no-op replacing a silent ``None`` —
    and tally the drop for the harvest channel.

    The version is extracted with the entry's own ``version_field`` (so it
    matches how dispatch routes the code); a ``version_field='none'`` code or a
    payload too short to carry the field reports ``version=None`` rather than
    fabricating a byte. The tally (``_UNHANDLED_TALLY``) counts every drop and is
    populated first — before the opt-out and the rate-limit — so a sweep can run
    with ``DIAGGROK_QUIET_UNHANDLED=1`` to mute the log spam yet still harvest
    the full count. The WARN log line is rate-limited once per ``(log_code,
    version)`` and suppressed entirely by ``DIAGGROK_QUIET_UNHANDLED=1``.
    """
    version = version_of(entry.version_field, data)
    key = (log_code, version)

    # Tally every drop first — the programmatic collector. Cheap dict
    # bump; runs regardless of the WARN opt-out and rate-limit below.
    rec = _UNHANDLED_TALLY.get(key)
    if rec is None:
        _UNHANDLED_TALLY[key] = {
            "length": len(data),
            "count": 1,
            "module": entry.func.__module__,
            "func": getattr(entry.func, "__name__", "?"),
        }
    else:
        rec["count"] += 1

    # Log emission: silenceable + rate-limited once per (code, version).
    if os.environ.get("DIAGGROK_QUIET_UNHANDLED") == "1":
        return
    if key in _UNHANDLED_WARN_SEEN:
        return
    _UNHANDLED_WARN_SEEN.add(key)
    vtxt = "None" if version is None else f"0x{version:02X}"
    logger.warning(
        "diaggrok: unhandled (code=0x%04X, version=%s, len=%d) — registered "
        "parser %s.%s returned no block; dropping (rate-limited once per "
        "(code, version))",
        log_code, vtxt, len(data),
        entry.func.__module__, getattr(entry.func, "__name__", "?"),
    )


def declared_versions(log_code: int) -> frozenset[int]:
    """The versions a registered code's parser declares it implements:
    ``supported_versions`` ∪ ``field_invariants['version'].enum`` ∪ the
    enumerated per-version override keys. Empty for an unregistered code."""
    entry = _registry.get(log_code)
    if entry is None:
        return frozenset()
    acc: set[int] = set(entry.supported_versions or ())
    spec = (entry.field_invariants or {}).get("version") or {}
    for v in spec.get("enum", ()) or ():
        if isinstance(v, int) and not isinstance(v, bool):
            acc.add(v)
    # ``{"const": N}`` pins one version just as ``{"enum": [N]}`` does; without
    # this, const-pinned codes (e.g. 0x10AD) would read as declaring nothing
    # and fall to "reject_all".
    c = spec.get("const")
    if isinstance(c, int) and not isinstance(c, bool):
        acc.add(c)
    acc |= set(_overrides.get(log_code, {}).keys())
    return frozenset(acc)


def version_contract(log_code: int) -> str:
    """How a registered parser must treat versions (the loud-drop rule).

    ``"version_less"`` — RE-evidenced: the code has no version byte; exempt.
    ``"declared"``     — decodes its declared versions; any other version
                         must return None (so the dispatch WARN fires).
    ``"reject_all"``   — declares no version, so implements none: every record
                         returns None (never-observed placeholders).
    """
    entry = _registry.get(log_code)
    if entry is None:
        raise KeyError(f"0x{log_code:04X} is not registered")
    if entry.version_less or entry.version_field == "none":
        return "version_less"
    return "declared" if declared_versions(log_code) else "reject_all"


def parse(log_code: int, log_time: int, data: bytes) -> Any | None:
    """Look up and call the parser for log_code. Returns None for unknown codes.

    When the code IS registered but its parser returns ``None`` — it recognised
    the code yet produced no decode for this specific payload, the classic
    version-gate drop — a rate-limited WARN is emitted so the
    blind spot surfaces in a corpus walk instead of hiding in it. An
    unregistered code stays silent: it is not a decode blind spot, since nothing
    ever claimed to decode it.
    """
    entry = resolve(log_code, data)
    if entry is None:
        return None
    result = entry.func(log_time, data)
    if result is None:
        _warn_unhandled(log_code, entry, data)
    elif entry.field_invariants:
        violations = check_invariants(entry, result)
        if violations:
            _warn_invariant(log_code, entry, data, violations)
    return result


# Invariant-violation channel: parse() checks a parser's declared
# field_invariants on every decoded record, so a record breaking one does not
# reach consumers silently. Like the unhandled channel, it tallies every
# violation and WARNs once per (code, version, field, check). The record is
# still returned:
# loud, not dropped. DIAGGROK_QUIET_INVARIANTS=1 silences the log line only.
_INVARIANT_WARN_SEEN: set[tuple] = set()
_INVARIANT_TALLY: dict[tuple, dict[str, Any]] = {}


def reset_invariant_warn_cache() -> None:
    """Clear the invariant WARN rate-limit set and tally (tests, long sweeps)."""
    _INVARIANT_WARN_SEEN.clear()
    _INVARIANT_TALLY.clear()


def invariant_tally() -> list[dict[str, Any]]:
    """One row per (code, version, field, check) violated this run, most first."""
    rows = [{"code": k[0], "version": k[1], "field": k[2], "check": k[3], **rec}
            for k, rec in _INVARIANT_TALLY.items()]
    rows.sort(key=lambda r: (-r["count"], r["code"]))
    return rows


def _warn_invariant(log_code: int, entry: "ParserEntry", data: bytes,
                    violations: list[dict[str, Any]]) -> None:
    version = version_of(entry.version_field, data)
    quiet = os.environ.get("DIAGGROK_QUIET_INVARIANTS") == "1"
    for v in violations:
        key = (log_code, version, v["field"], v["check"])
        rec = _INVARIANT_TALLY.get(key)
        if rec is None:
            _INVARIANT_TALLY[key] = {"count": 1, "observed": v["observed"],
                                     "spec": v["spec"], "length": len(data)}
        else:
            rec["count"] += 1
        if quiet or key in _INVARIANT_WARN_SEEN:
            continue
        _INVARIANT_WARN_SEEN.add(key)
        vtxt = "None" if version is None else f"0x{version:02X}"
        logger.warning(
            "diaggrok: invariant violated (code=0x%04X, version=%s, len=%d) — "
            "%s %s observed=%r spec=%r in %s.%s; record returned (rate-limited "
            "once per (code, version, field, check))",
            log_code, vtxt, len(data), v["field"], v["check"], v["observed"],
            v["spec"], entry.func.__module__, getattr(entry.func, "__name__", "?"),
        )


def check_invariants(
    entry: ParserEntry, result: Any
) -> list[dict[str, Any]]:
    """Validate ``result`` against ``entry.field_invariants``.

    Returns a list of violation dicts, one per failed check. Each
    violation has keys ``field``, ``check``, ``observed``, ``spec``.
    Returns ``[]`` when no invariants are declared, the result is None,
    or all checks pass.

    Result is converted to a field map via:
      1. ``result.to_dict()`` if available (the project convention), or
      2. ``dataclasses.asdict(result)`` as a fallback.
    """
    if not entry.field_invariants or result is None:
        return []
    if hasattr(result, "to_dict") and callable(result.to_dict):
        as_dict = result.to_dict()
    else:
        try:
            from dataclasses import asdict, is_dataclass
            as_dict = asdict(result) if is_dataclass(result) else {}
        except Exception:
            return []
    violations: list[dict[str, Any]] = []
    for field_name, spec in entry.field_invariants.items():
        present = field_name in as_dict
        observed = as_dict.get(field_name)
        if spec.get("required_populated") and (not present or observed is None):
            violations.append({
                "field": field_name,
                "check": "required_populated",
                "observed": None,
                "spec": True,
            })
            continue
        if not present or observed is None:
            continue
        if "range" in spec:
            lo, hi = spec["range"]
            try:
                if not (lo <= observed <= hi):
                    violations.append({
                        "field": field_name,
                        "check": "range",
                        "observed": observed,
                        "spec": [lo, hi],
                    })
            except TypeError:
                violations.append({
                    "field": field_name,
                    "check": "range",
                    "observed": repr(observed),
                    "spec": [lo, hi],
                })
        if "enum" in spec:
            allowed = spec["enum"]
            if observed not in allowed:
                violations.append({
                    "field": field_name,
                    "check": "enum",
                    "observed": observed,
                    "spec": list(allowed),
                })
        if "const" in spec:
            expected = spec["const"]
            if observed != expected:
                violations.append({
                    "field": field_name,
                    "check": "const",
                    "observed": observed,
                    "spec": expected,
                })
    return violations


def parser_info(log_code: int) -> ParserEntry | None:
    """Return the ParserEntry for a log code, or None if not registered."""
    return _registry.get(log_code)


def all_parser_info() -> list[ParserEntry]:
    """Return all registered ParserEntry objects, sorted by log_code."""
    return sorted(_registry.values(), key=lambda e: e.log_code)


def entries_for(log_code: int) -> list[ParserEntry]:
    """Every registered generation for a log code: the catch-all (if any)
    followed by each enumerated override's winner. For diagnostics and
    per-version checkout tooling."""
    out: list[ParserEntry] = []
    ca = _registry.get(log_code)
    if ca is not None:
        out.append(ca)
    out.extend(_overrides.get(log_code, {}).values())
    return out


def registered_codes() -> list[int]:
    """Return a sorted list of all registered log codes (catch-all or
    enumerated-only)."""
    return sorted(set(_registry) | set(_overrides))


def clear_registry() -> None:
    """Clear all registered parsers. For testing only."""
    _registry.clear()
    _overrides.clear()


def load_plugins(plugin_dir: str | Path | None = None) -> int:
    """Scan directory(ies) for .py plugin files and import them.

    Resolution order for plugin directory:
    1. Explicit plugin_dir argument (single path)
    2. DIAGGROK_PLUGIN_DIR environment variable (colon-separated paths)
    3. ~/.diaggrok/plugins/

    Supports colon-separated paths in DIAGGROK_PLUGIN_DIR (like PATH).
    Skips files starting with '_'. Returns total count of files loaded.
    Missing directories return 0 without error.
    Bad plugins log an exception but do not crash.
    """
    if plugin_dir is not None:
        return _load_from_dir(Path(plugin_dir))
    elif (env_dir := os.environ.get("DIAGGROK_PLUGIN_DIR")):
        total = 0
        for d in env_dir.split(":"):
            d = d.strip()
            if d:
                total += _load_from_dir(Path(d))
        return total
    else:
        return _load_from_dir(Path.home() / ".diaggrok" / "plugins")


def _load_from_dir(dirpath: Path) -> int:
    """Load all .py plugin files from a single directory."""
    if not dirpath.is_dir():
        return 0

    count = 0
    for pyfile in sorted(dirpath.glob("*.py")):
        if pyfile.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"diaggrok_plugin_{pyfile.stem}", pyfile
            )
            if spec is None or spec.loader is None:
                logger.warning("Could not load plugin spec for %s", pyfile)
                continue
            mod = importlib.util.module_from_spec(spec)
            import sys
            sys.modules[f"diaggrok_plugin_{pyfile.stem}"] = mod
            spec.loader.exec_module(mod)
            count += 1
        except Exception:
            logger.exception("Failed to load plugin %s", pyfile)
    return count
