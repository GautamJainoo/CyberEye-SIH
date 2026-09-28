"""
Secure-Lens-SIH Backend API Bridge.
Imports and surfaces the real local WMSA FastAPI app.
"""

import sys
from pathlib import Path

# Add src to python path so wmsa modules are found
repo_root = Path(__file__).resolve().parent.parent
src_path = repo_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from wmsa.api import api_app as app  # noqa: E402

__all__ = ["app"]
