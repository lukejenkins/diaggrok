"""Add ``apps/diagreplay`` to sys.path so ``diagreplay.py`` imports as the
top-level module ``diagreplay``. There is no ``__init__.py`` in ``apps/`` or
``apps/diagreplay/``: the module is run as a script or imported flat, not as
a package.
"""
from __future__ import annotations

import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1]
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))
