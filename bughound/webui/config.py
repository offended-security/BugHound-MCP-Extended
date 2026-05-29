"""WebUI configuration. Isolated from `bughound.config.settings` on purpose."""

from __future__ import annotations

import os
from pathlib import Path


# Defaults: bind 127.0.0.1 only. 0.0.0.0 must be explicit.
DEFAULT_HOST: str = os.getenv("BUGHOUND_WEBUI_HOST", "127.0.0.1")
DEFAULT_PORT: int = int(os.getenv("BUGHOUND_WEBUI_PORT", "8080"))

# Static asset directory ships with the package.
STATIC_DIR: Path = Path(__file__).parent / "static"
