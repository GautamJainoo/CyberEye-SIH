"""
Secure-Lens-SIH Backend API Bridge.
Imports and surfaces the real local WMSA FastAPI app.
"""

import sys
from pathlib import Path

# Add src to python path so wmsa modules are found
backend_dir = Path(__file__).resolve().parent
src_path = backend_dir / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Automatically load environment variables from backend/.env if available
try:
    from dotenv import load_dotenv
    env_file = backend_dir / ".env"
    if env_file.exists():
        load_dotenv(env_file)
except ImportError:
    pass

from wmsa.api import api_app as app  # noqa: E402

__all__ = ["app"]
