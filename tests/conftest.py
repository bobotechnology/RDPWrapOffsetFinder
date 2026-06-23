"""Pytest configuration: ensure project root is importable as top-level modules.

The project ships as flat .py files at the repo root (e.g. ``patches.py``)
rather than as an installed package, so we must add the project directory to
``sys.path`` for tests to ``import patches`` etc.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
