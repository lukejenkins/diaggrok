"""Built-in parsers are auto-discovered at package import time.

Every `.py` file in this directory (except those starting with `_`) is
imported so its `@register(...)` decorators fire. This replaces the
hand-maintained import list that previously had to be edited whenever
a parser was added, renamed, or split into smaller files.

Import order is alphabetical (pkgutil.iter_modules sorts entries). The
registry rejects duplicate `log_code` registrations by default
(`replace=False` in `register()`), so order is irrelevant for
correctness — the duplicate check catches a stub shadowing a real parser
regardless of which module loads first.

Lazy mode: with ``DIAGGROK_LAZY_PARSERS=1`` in the environment when
``diaggrok`` is first imported, the sweep is skipped. Importing all ~1,000
modules costs about 1.1 s on an i5-8400, which was half of diaggpsd's live CPU.
The caller imports the parser modules it needs itself. The first registry
lookup for a code that is not registered, and any enumeration
(``registered_codes()``, ``all_parser_info()``), runs the full sweep, so a
lookup or listing can be slower, never different. ⚠️ The one gap is a
per-version override registered in a module the caller did not import. The
caller must import every module that registers its codes. Code that reads
``registry._registry`` directly (the recipes runner) sees only what is loaded.
"""
import importlib
import os
import pkgutil

#: True while a lazy process has not yet run the full sweep.
_lazy_pending = os.environ.get("DIAGGROK_LAZY_PARSERS") == "1"


def load_all() -> None:
    """Import every built-in parser module. Safe to call more than once."""
    global _lazy_pending
    _lazy_pending = False  # first, so a lookup made during the sweep cannot re-enter it
    for _modinfo in pkgutil.iter_modules(__path__):
        if not _modinfo.name.startswith("_"):
            importlib.import_module(f"{__name__}.{_modinfo.name}")


if not _lazy_pending:
    load_all()
