"""Scope enforcement chokepoint.

A single, batch-friendly scope filter loaded once per stage. Used before
any active probe so we never touch out-of-scope hosts and never let
loose passive sources pollute the URL pool.

Two kinds of filtering live here:

1. ``ScopeFilter`` — workspace-level allow/deny via ``ScopeConfig`` patterns
   (``*.example.com``, ``staging.example.com``, etc.). Use this gate before
   httpx, sensitive_paths, takeover_checker, cors_checker, dir_scanner,
   ffuf — anything that sends a packet.

2. ``etld_plus_one`` / ``hostname_matches_target`` — eTLD+1 exact-suffix
   match for tightening passive sources (crt.sh, urlscan, alienvault,
   commoncrawl). Replaces loose ``"." in name`` and ``domain in url``
   substring checks that admit ``evil-target.com`` as a match for
   ``target.com``.
"""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse

import structlog
import tldextract

from bughound.core import workspace

logger = structlog.get_logger()

_HOST_RE = re.compile(r"^https?://", re.I)


def _normalize_host(value: str) -> str:
    """Strip protocol, path, port, and trailing dot. Lowercase."""
    s = value.strip().lower().rstrip(".")
    s = _HOST_RE.sub("", s)
    s = s.split("/", 1)[0]
    s = s.split(":", 1)[0]
    return s


def etld_plus_one(value: str) -> str:
    """Return the registrable domain (eTLD+1) for a host or URL.

    ``api.staging.example.co.uk`` -> ``example.co.uk``
    Returns ``""`` if extraction fails.
    """
    host = _normalize_host(value)
    if not host:
        return ""
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return ""
    return f"{ext.domain}.{ext.suffix}".lower()


def hostname_matches_target(candidate: str, target: str) -> bool:
    """True if ``candidate`` belongs to the same eTLD+1 as ``target``.

    Used for passive source filtering. Rejects ``evil-target.com`` for
    ``target.com``, accepts ``api.target.com``.
    """
    cand_root = etld_plus_one(candidate)
    target_root = etld_plus_one(target)
    if not cand_root or not target_root:
        return False
    return cand_root == target_root


class ScopeFilter:
    """Batch scope filter for a single workspace.

    Load once at the top of a stage, then call ``allow(host)`` or the
    batch variants. Keeps include/exclude patterns in memory so we don't
    re-read config.json for every URL in a 50k-URL crawl.
    """

    def __init__(
        self,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> None:
        self.include = [p.lower() for p in (include or [])]
        self.exclude = [p.lower() for p in (exclude or [])]

    @classmethod
    async def load(cls, workspace_id: str) -> "ScopeFilter":
        cfg = await workspace.get_config(workspace_id)
        if cfg is None:
            return cls()
        return cls(include=cfg.scope.include, exclude=cfg.scope.exclude)

    def allow(self, value: str) -> bool:
        """Check if a host or URL is in scope.

        Empty include list means everything is allowed (still respects excludes).
        """
        host = _normalize_host(value)
        if not host:
            return False
        for pattern in self.exclude:
            if fnmatch.fnmatch(host, pattern):
                return False
        if not self.include:
            return True
        return any(fnmatch.fnmatch(host, p) for p in self.include)

    def filter_hosts(self, hosts: list[str]) -> tuple[list[str], list[str]]:
        """Split a host list into (in_scope, dropped)."""
        in_scope: list[str] = []
        dropped: list[str] = []
        for h in hosts:
            (in_scope if self.allow(h) else dropped).append(h)
        return in_scope, dropped

    def filter_urls(
        self, urls: list[dict[str, str]],
    ) -> tuple[list[dict[str, str]], int]:
        """Filter a list of {url, source} dicts. Returns (kept, dropped_count)."""
        kept: list[dict[str, str]] = []
        dropped = 0
        for entry in urls:
            url = entry.get("url") if isinstance(entry, dict) else None
            if url and self.allow(url):
                kept.append(entry)
            else:
                dropped += 1
        return kept, dropped

    def filter_url_strings(self, urls: list[str]) -> tuple[list[str], int]:
        """Filter plain URL/host strings. Returns (kept, dropped_count)."""
        kept: list[str] = []
        dropped = 0
        for u in urls:
            if self.allow(u):
                kept.append(u)
            else:
                dropped += 1
        return kept, dropped


def hostname_of(url: str) -> str:
    """Extract the hostname from a URL. Returns "" on failure."""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""
