"""ffuf directory fuzzer wrapper.

Used in Stage 4 for deep directory brute-forcing with large wordlists.
Technology-aware wordlist selection.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "ffuf"
TIMEOUT = 600

# Common wordlist locations (checked in order).
# Order matters — assetnote wordlists are preferred (curated from real-world data).
_WORDLISTS = {
    "small": [
        "/usr/share/wordlists/assetnote/data/manual/httparchive_directories_1m_2024.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ],
    "medium": [
        "/usr/share/wordlists/assetnote/data/manual/httparchive_directories_1m_2024.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ],
    "large": [
        "/usr/share/wordlists/assetnote/data/automated/httparchive_directories_1m_2024.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
    ],
    # Parameter name fuzzing
    "params": [
        "/usr/share/wordlists/assetnote/data/manual/parameters.txt",
        "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ],
    # API route fuzzing (kiterunner-style wordlist for API endpoint names)
    "api": [
        "/usr/share/wordlists/assetnote/data/manual/api_endpoints.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    ],
}


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


def find_wordlist(size: str = "medium") -> str | None:
    """Find the first available wordlist for the given size."""
    for path in _WORDLISTS.get(size, _WORDLISTS["medium"]):
        if Path(path).is_file():
            return path
    # Fallback to any available list
    for paths in _WORDLISTS.values():
        for path in paths:
            if Path(path).is_file():
                return path
    return None


async def execute(
    target_url: str,
    *,
    wordlist: str | None = None,
    wordlist_size: str = "medium",
    match_codes: str = "200,301,302,401,403,405",
    filter_size: str | None = None,
    extensions: str | None = None,
    timeout: int = TIMEOUT,
) -> ToolResult:
    """Run ffuf against a target URL.

    target_url: base URL (FUZZ keyword appended if missing).
    wordlist: explicit wordlist path (overrides wordlist_size).
    wordlist_size: "small", "medium", or "large".
    match_codes: HTTP status codes to match.
    filter_size: filter responses of this size (removes false positives).
    extensions: comma-separated extensions to append (e.g. ".php,.html").
    timeout: overall execution timeout.

    Returns ToolResult with discovered paths.
    """
    # Resolve wordlist
    wl = wordlist or find_wordlist(wordlist_size)
    if not wl:
        result = ToolResult(
            tool=BINARY, target=target_url, success=False,
            error=tool_runner.ToolError(
                error_type=tool_runner.ToolErrorType.EXECUTION,
                message="No wordlist found. Install seclists: apt install seclists",
            ),
        )
        return result

    # Ensure FUZZ keyword
    url = target_url
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    # Temp output file
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, prefix="bughound_ffuf_",
    )
    tmp.close()
    output_file = Path(tmp.name)

    args = [
        "-u", url,
        "-w", wl,
        "-o", str(output_file),
        "-of", "json",
        "-mc", match_codes,
        "-t", "50",
        "-timeout", "10",
        "-noninteractive",
        "-s",  # silent
    ]

    if filter_size:
        args.extend(["-fs", filter_size])

    if extensions:
        args.extend(["-e", extensions])

    try:
        result = await tool_runner.run(
            BINARY, args, target=target_url, timeout=timeout,
        )
    finally:
        findings = _parse_output_file(output_file)
        if output_file.exists():
            output_file.unlink(missing_ok=True)

    # ffuf may exit non-zero but still write results
    result.success = True
    result.results = findings
    result.result_count = len(findings)
    return result


async def discover_params(
    target_url: str,
    *,
    wordlist: str | None = None,
    method: str = "GET",
    timeout: int = 90,
    threads: int = 40,
) -> ToolResult:
    """Discover hidden query/body parameter names against a single endpoint.

    Sends ``?FUZZ=bughound`` (GET) or body ``FUZZ=bughound`` (POST) and uses
    ffuf's auto-calibration so we filter out the constant baseline. A "hit"
    means the param name changed the response — i.e. the server actually
    consumed it.

    target_url: the endpoint to probe (without FUZZ).
    method: "GET" or "POST".
    """
    wl = wordlist or find_wordlist("params")
    if not wl:
        return ToolResult(
            tool=BINARY, target=target_url, success=False,
            error=tool_runner.ToolError(
                error_type=tool_runner.ToolErrorType.EXECUTION,
                message="No params wordlist found. Install seclists or assetnote params.",
            ),
        )

    method = method.upper()
    if method == "POST":
        url = target_url
        ffuf_args_method_specific = [
            "-X", "POST",
            "-d", "FUZZ=bughound",
            "-H", "Content-Type: application/x-www-form-urlencoded",
        ]
    else:
        sep = "&" if "?" in target_url else "?"
        url = f"{target_url}{sep}FUZZ=bughound"
        ffuf_args_method_specific = []

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, prefix="bughound_ffuf_param_",
    )
    tmp.close()
    output_file = Path(tmp.name)

    args = [
        "-u", url,
        "-w", wl,
        "-o", str(output_file),
        "-of", "json",
        "-mc", "all",        # auto-calibration filters baseline noise
        "-fc", "404,400",    # drop hard-fail responses outright
        "-ac",               # auto-calibrate filters from baseline FUZZ values
        "-t", str(threads),
        "-timeout", "10",
        "-noninteractive",
        "-s",
        *ffuf_args_method_specific,
    ]

    try:
        result = await tool_runner.run(
            BINARY, args, target=target_url, timeout=timeout,
        )
    finally:
        findings = _parse_output_file(output_file)
        if output_file.exists():
            output_file.unlink(missing_ok=True)

    # Convert ffuf path-style output into param-style hits.
    param_hits: list[dict[str, Any]] = []
    for item in findings:
        param_name = item.get("path", "/").lstrip("/")
        if not param_name:
            continue
        param_hits.append({
            "url": target_url,
            "param": param_name,
            "method": method,
            "status_code": item.get("status_code", 0),
            "content_length": item.get("content_length", 0),
        })

    result.success = True
    result.results = param_hits
    result.result_count = len(param_hits)
    return result


def _parse_output_file(output_file: Path) -> list[dict[str, Any]]:
    """Parse ffuf JSON output."""
    if not output_file.exists():
        return []

    try:
        text = output_file.read_text().strip()
        if not text:
            return []

        data = json.loads(text)
        raw_results = data.get("results", [])

        findings: list[dict[str, Any]] = []
        for item in raw_results:
            if not isinstance(item, dict):
                continue
            findings.append({
                "path": "/" + item.get("input", {}).get("FUZZ", ""),
                "url": item.get("url", ""),
                "status_code": item.get("status", 0),
                "content_length": item.get("length", 0),
                "content_words": item.get("words", 0),
                "content_lines": item.get("lines", 0),
                "redirect_location": item.get("redirectlocation", ""),
            })

        # Sort by status code
        findings.sort(key=lambda x: (x["status_code"], x["path"]))
        return findings

    except (json.JSONDecodeError, OSError):
        return []
