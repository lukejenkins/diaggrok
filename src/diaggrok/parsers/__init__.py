"""Built-in parsers are auto-discovered at package import time.

Every `.py` file in this directory (except those starting with `_`) is
imported so its `@register(...)` decorators fire. This replaces the
hand-maintained import list that previously had to be edited whenever
a parser was added, renamed, or split into smaller files.

Import order is alphabetical (pkgutil.iter_modules sorts entries). The
registry rejects duplicate `log_code` registrations by default
(`replace=False` in `register()`), so order is irrelevant for
correctness — the duplicate check catches stub-shadowing bugs like
#N regardless of which module loads first.
"""
import importlib
import pkgutil

for _modinfo in pkgutil.iter_modules(__path__):
    if not _modinfo.name.startswith("_"):
        importlib.import_module(f"{__name__}.{_modinfo.name}")
