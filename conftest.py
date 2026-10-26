"""Корневой conftest.

Гарантирует, что корень проекта попал в ``sys.path`` — иначе ``import app``
работает только при запуске через ``python -m pytest``, а не через ``pytest``.
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
