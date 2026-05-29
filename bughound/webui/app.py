"""aiohttp application factory + entry point for the BugHound web UI.

Hard rule: this module (and the rest of `bughound.webui`) must NEVER
import from `bughound.cli`, `bughound.server`, `bughound.stages`, or
`bughound.tools`. All pipeline access goes through `bughound.operations`.
"""

from __future__ import annotations

import asyncio
import logging
import sys

import structlog
from aiohttp import web

from bughound.core.job_manager import JobManager
from bughound.webui import config
from bughound.webui.routes import register_routes

logger = structlog.get_logger("bughound.webui")


def create_app() -> web.Application:
    """Build the aiohttp application.

    The webui owns its own JobManager — same pattern as cli.py and server.py.
    Operations always receives it as a parameter; never a module global.
    """
    app = web.Application()
    app["job_manager"] = JobManager()
    app.router.add_get("/api/health", _health)
    register_routes(app)
    # Index at "/" — served last so /api/* routes still win.
    app.router.add_get("/", _index)
    app.router.add_static("/static/", path=str(config.STATIC_DIR), show_index=False)
    return app


async def _index(request: web.Request) -> web.Response:
    """Serve the single-page app shell."""
    index_path = config.STATIC_DIR / "index.html"
    if not index_path.is_file():
        return web.Response(status=500, text="index.html missing from static dir")
    return web.FileResponse(index_path, headers={
        # Conservative CSP — only own-origin scripts/styles, no inline JS.
        "Content-Security-Policy": (
            "default-src 'self'; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self'; "
            "script-src 'self'"
        ),
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    })


async def _health(request: web.Request) -> web.Response:
    """Trivial liveness probe."""
    return web.json_response({"ok": True})


def _setup_logging() -> None:
    """Send logs to stderr — matches the MCP adapter convention."""
    logging.basicConfig(format="%(message)s", level=logging.INFO, stream=sys.stderr)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )


def _warn_if_public(host: str) -> None:
    """Loud warning if binding to a non-localhost address."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"\n  WARNING: BugHound web UI is binding to {host!r} — reachable from "
            "the network.\n  This UI has no authentication. Make sure you know "
            "what you are doing.\n",
            file=sys.stderr,
        )


async def serve(
    host: str = config.DEFAULT_HOST, port: int = config.DEFAULT_PORT
) -> None:
    """Async entry: start the server and run until cancelled.

    Used by the `./bhound webui` CLI subcommand which already owns an
    asyncio event loop. For `python -m bughound.webui`, use `run()` instead.
    """
    _setup_logging()
    _warn_if_public(host)

    app = create_app()
    # access_log=None disables aiohttp's per-request logging. Structlog can't
    # be passed directly here (aiohttp expects a stdlib logging.Logger).
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port)
    await site.start()

    logger.info("webui.start", host=host, port=port)
    print(f"  BugHound web UI ready at http://{host}:{port}  (Ctrl+C to stop)",
          file=sys.stderr)

    try:
        # Block until the task is cancelled (Ctrl+C).
        await asyncio.Event().wait()
    finally:
        logger.info("webui.stop")
        await runner.cleanup()


def run(host: str = config.DEFAULT_HOST, port: int = config.DEFAULT_PORT) -> None:
    """Sync entry: start the web UI server (blocking).

    Used by `python -m bughound.webui`. Wraps `serve()` in `asyncio.run`.
    """
    try:
        asyncio.run(serve(host=host, port=port))
    except KeyboardInterrupt:
        pass
