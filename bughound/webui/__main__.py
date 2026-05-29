"""`python -m bughound.webui` entry point.

Mirrors the `./bhound webui` subcommand so users can run the web UI
either way.
"""

from __future__ import annotations

import argparse

from bughound.webui import config
from bughound.webui.app import run


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bughound.webui",
        description="Start the BugHound web UI (read-only).",
    )
    parser.add_argument(
        "--host", default=config.DEFAULT_HOST,
        help=f"Bind address (default: {config.DEFAULT_HOST}). "
             "Use 0.0.0.0 to expose on all interfaces (no auth — be careful).",
    )
    parser.add_argument(
        "--port", type=int, default=config.DEFAULT_PORT,
        help=f"Port (default: {config.DEFAULT_PORT}).",
    )
    args = parser.parse_args()
    run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
