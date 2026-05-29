"""BugHound web UI — read-only localhost dashboard.

Third peer adapter alongside `bughound.cli` and `bughound.server`. Calls
into the canonical `bughound.operations` API only — never reaches into
`bughound.stages.*` or any other adapter.

Lazily imported by the CLI's `webui` subcommand so the CLI hot path pays
nothing when this package isn't used. Start with `./bhound webui` or
`python -m bughound.webui`.
"""
