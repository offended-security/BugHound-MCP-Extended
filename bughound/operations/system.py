"""System operations: canonical tool registry, technique + pipeline listings.

This module consolidates the two previously-duplicated tool lists from
`cli.py:246-282` (27 tools, with critical flag) and `server.py:970-991`
(20 tools, no critical flag). One registry, one source of truth.

httpx is the only special case: it has its own preflight Go-vs-Python detection
in the CLI adapter (kept there as it's interactive UX). The registry still
includes httpx so coverage reports list it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from bughound.core import tool_runner


# ---------------------------------------------------------------------------
# Tool spec
# ---------------------------------------------------------------------------


class ToolSpec(BaseModel):
    """One entry in the canonical tool registry."""

    name: str
    purpose: str
    install_cmd: str
    critical: bool = False
    category: str = "other"


# Categories: recon, discovery, scanning, validation, secrets, cms, takeover, oob, oneliner
TOOL_REGISTRY: list[ToolSpec] = [
    # Critical (core scanning fails without these)
    ToolSpec(
        name="httpx",
        purpose="Live host probing (ProjectDiscovery Go version)",
        install_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        critical=True,
        category="recon",
    ),
    ToolSpec(
        name="nuclei",
        purpose="Vulnerability scanning",
        install_cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        critical=True,
        category="scanning",
    ),
    ToolSpec(
        name="katana",
        purpose="Web crawling",
        install_cmd="go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        critical=True,
        category="discovery",
    ),
    ToolSpec(
        name="subfinder",
        purpose="Subdomain discovery",
        install_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        critical=True,
        category="recon",
    ),
    # Recon
    ToolSpec(
        name="gau",
        purpose="Historical URL discovery",
        install_cmd="go install -v github.com/lc/gau/v2/cmd/gau@latest",
        category="recon",
    ),
    ToolSpec(
        name="waybackurls",
        purpose="Wayback Machine URLs",
        install_cmd="go install -v github.com/tomnomnom/waybackurls@latest",
        category="recon",
    ),
    ToolSpec(
        name="assetfinder",
        purpose="Subdomain discovery",
        install_cmd="go install -v github.com/tomnomnom/assetfinder@latest",
        category="recon",
    ),
    ToolSpec(
        name="findomain",
        purpose="Subdomain discovery",
        install_cmd="apt install findomain  OR  github.com/Edu4rdSHL/findomain",
        category="recon",
    ),
    ToolSpec(
        name="amass",
        purpose="Subdomain enumeration",
        install_cmd="go install -v github.com/owasp-amass/amass/v4/...@latest",
        category="recon",
    ),
    ToolSpec(
        name="gospider",
        purpose="Web crawling",
        install_cmd="go install -v github.com/jaeles-project/gospider@latest",
        category="discovery",
    ),
    ToolSpec(
        name="wafw00f",
        purpose="WAF detection",
        install_cmd="pip install wafw00f",
        category="recon",
    ),
    # Discovery
    ToolSpec(
        name="ffuf",
        purpose="Directory fuzzing",
        install_cmd="go install -v github.com/ffuf/ffuf/v2@latest",
        category="discovery",
    ),
    ToolSpec(
        name="arjun",
        purpose="Parameter discovery",
        install_cmd="pip install arjun",
        category="discovery",
    ),
    ToolSpec(
        name="gotator",
        purpose="Subdomain permutation",
        install_cmd="go install -v github.com/Josue87/gotator@latest",
        category="recon",
    ),
    ToolSpec(
        name="puredns",
        purpose="DNS resolution/bruteforce",
        install_cmd="go install -v github.com/d3mondev/puredns/v2@latest",
        category="recon",
    ),
    # Validation
    ToolSpec(
        name="sqlmap",
        purpose="SQLi validation",
        install_cmd="apt install sqlmap  OR  pip install sqlmap",
        category="validation",
    ),
    ToolSpec(
        name="dalfox",
        purpose="XSS validation",
        install_cmd="go install -v github.com/hahwul/dalfox/v2@latest",
        category="validation",
    ),
    # Secrets
    ToolSpec(
        name="trufflehog",
        purpose="Verified secret detection",
        install_cmd=(
            "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/"
            "main/scripts/install.sh | sh -s -- -b /usr/local/bin"
        ),
        category="secrets",
    ),
    # CMS
    ToolSpec(
        name="wpscan",
        purpose="WordPress scanning",
        install_cmd="gem install wpscan  OR  apt install wpscan",
        category="cms",
    ),
    # Takeover
    ToolSpec(
        name="subjack",
        purpose="Subdomain takeover validation",
        install_cmd="go install github.com/haccer/subjack@latest",
        category="takeover",
    ),
    # OOB
    ToolSpec(
        name="interactsh-client",
        purpose="Out-of-band interaction (SSRF/blind injection)",
        install_cmd=(
            "go install -v github.com/projectdiscovery/interactsh/cmd/"
            "interactsh-client@latest"
        ),
        category="oob",
    ),
    # One-liners
    ToolSpec(
        name="qsreplace",
        purpose="Query string replacement",
        install_cmd="go install -v github.com/tomnomnom/qsreplace@latest",
        category="oneliner",
    ),
    ToolSpec(
        name="kxss",
        purpose="XSS reflection detection",
        install_cmd="go install -v github.com/Emoe/kxss@latest",
        category="oneliner",
    ),
    ToolSpec(
        name="Gxss",
        purpose="XSS reflection + context",
        install_cmd="go install -v github.com/KathanP19/Gxss@latest",
        category="oneliner",
    ),
    ToolSpec(
        name="gf",
        purpose="URL pattern matching",
        install_cmd="go install -v github.com/tomnomnom/gf@latest",
        category="oneliner",
    ),
    ToolSpec(
        name="unfurl",
        purpose="URL component extraction",
        install_cmd="go install -v github.com/tomnomnom/unfurl@latest",
        category="oneliner",
    ),
    ToolSpec(
        name="anew",
        purpose="Unique line appending",
        install_cmd="go install -v github.com/tomnomnom/anew@latest",
        category="oneliner",
    ),
    ToolSpec(
        name="uro",
        purpose="URL deduplication",
        install_cmd="pip install uro",
        category="oneliner",
    ),
    ToolSpec(
        name="urldedupe",
        purpose="Smart URL dedup",
        install_cmd="go install -v github.com/ameenmaali/urldedupe@latest",
        category="oneliner",
    ),
    ToolSpec(
        name="bhedak",
        purpose="Upgraded qsreplace",
        install_cmd="pipx install bhedak",
        category="oneliner",
    ),
    ToolSpec(
        name="interlace",
        purpose="Parallel execution",
        install_cmd="pipx install git+https://github.com/codingo/Interlace.git",
        category="oneliner",
    ),
]


# ---------------------------------------------------------------------------
# Tool coverage check
# ---------------------------------------------------------------------------


class ToolCoverageReport(BaseModel):
    """Aggregate result of `check_tool_coverage()`."""

    installed: list[ToolSpec] = Field(default_factory=list)
    missing_critical: list[ToolSpec] = Field(default_factory=list)
    missing_optional: list[ToolSpec] = Field(default_factory=list)
    total: int = 0

    # category -> {"installed": N, "missing": N, "total": N}
    by_category: dict[str, dict[str, int]] = Field(default_factory=dict)


def check_tool_coverage() -> ToolCoverageReport:
    """Walk the canonical registry, report installed vs. missing.

    Synchronous: only inspects PATH + override map, no subprocess.
    """
    installed: list[ToolSpec] = []
    missing_critical: list[ToolSpec] = []
    missing_optional: list[ToolSpec] = []
    by_category: dict[str, dict[str, int]] = {}

    for spec in TOOL_REGISTRY:
        cat = by_category.setdefault(
            spec.category, {"installed": 0, "missing": 0, "total": 0}
        )
        cat["total"] += 1

        if tool_runner.is_available(spec.name):
            installed.append(spec)
            cat["installed"] += 1
        else:
            cat["missing"] += 1
            if spec.critical:
                missing_critical.append(spec)
            else:
                missing_optional.append(spec)

    return ToolCoverageReport(
        installed=installed,
        missing_critical=missing_critical,
        missing_optional=missing_optional,
        total=len(TOOL_REGISTRY),
        by_category=by_category,
    )


# ---------------------------------------------------------------------------
# Technique and pipeline listings
# ---------------------------------------------------------------------------


def filter_test_classes(classes: list[str] | set[str], profile: str) -> list[str]:
    """Filter test classes to those matching the given profile.

    profile: 'client', 'server', or 'both'. 'both' returns input unchanged.
    Unknown classes default to 'both' (conservative — don't silently drop).
    """
    from bughound.stages.techniques import filter_classes_by_profile

    return filter_classes_by_profile(classes, profile)


def list_techniques(profile: str | None = None) -> list[dict[str, Any]]:
    """Return all testing techniques with availability status.

    profile: 'client', 'server', or 'both' (default). Invalid → 'both'.
    """
    from bughound.stages.techniques import (
        VALID_PROFILES,
        filter_techniques_by_profile,
        list_all_techniques,
    )

    techs = list_all_techniques()
    chosen = profile if profile in VALID_PROFILES else "both"
    if chosen != "both":
        techs = filter_techniques_by_profile(techs, chosen)
    return techs


def list_pipelines() -> dict[str, Any]:
    """Return all one-liner pipelines + their tool availability summary."""
    from bughound.tools.oneliners.pipeline import _tools_used_summary, list_pipelines

    return {
        "pipelines": list_pipelines(),
        "tools_used": _tools_used_summary(),
    }
