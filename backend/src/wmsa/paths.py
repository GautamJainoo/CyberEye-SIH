"""
Path resolution utilities for WMSA.
Resolves base project directories whether invoked from root or backend directory.
"""

from __future__ import annotations

import os
from pathlib import Path


def get_base_dir() -> Path:
    """
    Finds the active base directory containing 'config/scope.yaml'.
    Supports execution from root (where backend/config/scope.yaml exists),
    directly inside backend/, or custom WMSA_BASE_DIR environment override.
    """
    env_override = os.environ.get("WMSA_BASE_DIR")
    if env_override:
        p = Path(env_override).resolve()
        if p.exists():
            return p

    cwd = Path.cwd().resolve()

    # 1. Running inside backend/
    if (cwd / "config" / "scope.yaml").exists():
        return cwd

    # 2. Running at repository root
    if (cwd / "backend" / "config" / "scope.yaml").exists():
        return cwd / "backend"

    # 3. Running from a subfolder, resolve relative to this source file
    src_parent = Path(__file__).resolve().parent.parent.parent  # .../src or .../backend/src
    if src_parent.name == "src" and (src_parent.parent / "config" / "scope.yaml").exists():
        return src_parent.parent
    if (src_parent / "config" / "scope.yaml").exists():
        return src_parent

    return cwd
