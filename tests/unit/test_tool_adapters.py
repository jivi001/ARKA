"""Unit tests for Phase 2 tool adapters (Nuclei, ffuf, WhatWeb, Amass).

Tests schemas, validation, parsers, executors, and canonical normalization.
"""

from __future__ import annotations

import pytest

from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.state.models import new_id
from arka.app.tools.amass.definition import get_amass_tool_definition
from arka.app.tools.amass.executor import AmassToolExecutor
from arka.app.tools.amass.parser import parse_amass_json
from arka.app.tools.amass.schemas import AmassScanConfig
from arka.app.tools.ffuf.definition import get_ffuf_tool_definition
from arka.app.tools.ffuf.executor import FfufToolExecutor
from arka.app.tools.ffuf.parser import parse_ffuf_json
from arka.app.tools.ffuf.schemas import FfufScanConfig
from arka.app.tools.nuclei.definition import get_nuclei_tool_definition
from arka.app.tools.nuclei.executor import NucleiToolExecutor
from arka.app.tools.nuclei.parser import parse_nuclei_json
from arka.app.tools.nuclei.schemas import NucleiScanConfig
from arka.app.tools.schemas.tool_schemas import ToolRequest
from arka.app.tools.whatweb.definition import get_whatweb_tool_definition
from arka.app.tools.whatweb.executor import WhatWebToolExecutor
from arka.app.tools.whatweb.parser import parse_whatweb_json
from arka.app.tools.whatweb.schemas import WhatWebScanConfig

# ==============================================================================
# NUCLEI ADAPTER TESTS
# ==============================================================================


def test_nuclei_scan_config_validation() -> None:
    """Test NucleiScanConfig validates inputs and rejects invalid/dangerous values."""
    config = NucleiScanConfig(
        templates=["cves/2023", "misconfiguration"],
        tags=["cve", "misconfig"],
        severity=["high", "critical"],
        rate_limit=80,
        timeout=10,
    )
    assert config.templates == ["cves/2023", "misconfiguration"]
    assert config.requires_escalation() is True

    # Path traversal rejection
    with pytest.raises(ValueError, match="only alphanumeric relative paths allowed"):
        NucleiScanConfig(templates=["../../etc/passwd"])

    # Invalid severity rejection
    with pytest.raises(ValueError, match="Invalid severity"):
        NucleiScanConfig(severity=["extreme"])

    # Invalid tag rejection
    with pytest.raises(ValueError, match="Invalid tag"):
        NucleiScanConfig(tags=["cve;rm -rf"])


def test_nuclei_scan_config_to_argv() -> None:
    """Test safe argv generation for Nuclei."""
    config = NucleiScanConfig(
        templates=["cves"],
        severity=["medium", "high"],
        rate_limit=60,
    )
    argv = config.to_argv("https://example.com")
    assert argv[0] == "nuclei"
    assert "-target" in argv
    assert "https://example.com" in argv
    assert "-rate-limit" in argv
    assert "60" in argv
    assert "-t" in argv
    assert "cves" in argv
    assert "-severity" in argv
    assert "medium,high" in argv


def test_nuclei_parser() -> None:
    """Test parsing of Nuclei JSON/JSONL output."""
    sample_jsonl = (
        '{"template-id": "ssl-issuer", "info": {"name": "SSL Issuer", "severity": "info"}, '
        '"type": "ssl", "host": "192.168.1.10", "matched-at": "192.168.1.10:443"}\n'
        '{"template-id": "cve-2021-44228", "info": {"name": "Log4j RCE", "severity": "critical", '
        '"classification": {"cve-id": "CVE-2021-44228", "cvss-score": 10.0}}, '
        '"type": "http", "host": "192.168.1.10", "matched-at": "192.168.1.10/login"}\n'
    )
    result = parse_nuclei_json(sample_jsonl, target="192.168.1.10")
    assert result.success is True
    assert len(result.findings) == 2
    f1 = result.findings[0]
    assert f1.template_id == "ssl-issuer"
    assert f1.severity == "info"

    f2 = result.findings[1]
    assert f2.template_id == "cve-2021-44228"
    assert f2.severity == "critical"
    assert f2.cve_id == "CVE-2021-44228"
    assert f2.cvss_score == 10.0


@pytest.mark.asyncio
async def test_nuclei_executor_execution() -> None:
    """Test NucleiToolExecutor runs simulated scan and returns structured ToolResult."""
    executor = NucleiToolExecutor()
    definition = get_nuclei_tool_definition()

    req = ToolRequest(
        engagement_id=new_id(),
        task_id=new_id(),
        agent_id=new_id(),
        tool_name="nuclei",
        target="192.168.1.10",
        arguments={"severity": ["info", "low"]},
    )
    result = await executor.execute(req, definition)
    assert result.success is True
    assert result.tool_name == "nuclei"
    assert len(result.output.get("findings", [])) >= 1
    assert "ssl-issuer" in (result.raw_output or "")


@pytest.mark.asyncio
async def test_nuclei_executor_escalation_enforcement() -> None:
    """Test NucleiToolExecutor blocks unapproved high/critical severity scan."""
    executor = NucleiToolExecutor()
    definition = get_nuclei_tool_definition()

    req = ToolRequest(
        engagement_id=new_id(),
        task_id=new_id(),
        agent_id=new_id(),
        tool_name="nuclei",
        target="192.168.1.10",
        arguments={"severity": ["critical"]},
    )
    result = await executor.execute(req, definition)
    assert result.success is False
    assert "requires HIGH risk approval" in (result.error or "")


def test_nuclei_normalization() -> None:
    """Test AssetNormalizer converts NucleiResult into canonical Finding, Asset, and Service."""
    normalizer = AssetNormalizer()
    sample = (
        '{"template-id": "http-headers", "info": {"name": "Headers", "severity": "low"}, '
        '"type": "http", "host": "192.168.1.50", "matched-at": "192.168.1.50:80"}\n'
    )
    nuclei_res = parse_nuclei_json(sample, target="192.168.1.50")
    bundle = normalizer.normalize_nuclei_result(
        result=nuclei_res,
        engagement_id=new_id(),
        target="192.168.1.50",
        evidence_refs=["sha256:abc123"],
    )
    assert len(bundle.findings) == 1
    assert bundle.findings[0].title == "Headers"
    assert len(bundle.assets) == 1
    assert bundle.assets[0].address == "192.168.1.50"
    assert len(bundle.services) == 1
    assert bundle.services[0].port == 80


# ==============================================================================
# FFUF ADAPTER TESTS
# ==============================================================================


def test_ffuf_scan_config_validation() -> None:
    """Test FfufScanConfig validates arguments and rejects unauthorized wordlists."""
    config = FfufScanConfig(wordlist="common.txt", rate=25)
    assert config.wordlist == "common.txt"
    assert config.requires_escalation() is False

    # Disallowed wordlist
    with pytest.raises(ValueError, match="not in approved allowlist"):
        FfufScanConfig(wordlist="custom_shell.txt")

    # Excessive rate triggers escalation
    config_fast = FfufScanConfig(rate=80)
    assert config_fast.requires_escalation() is True


def test_ffuf_scan_config_to_argv() -> None:
    """Test safe argv generation for ffuf."""
    config = FfufScanConfig(wordlist="api-endpoints.txt", rate=30)
    argv = config.to_argv("http://192.168.1.10:8080")
    assert argv[0] == "ffuf"
    assert "-u" in argv
    assert "http://192.168.1.10:8080/FUZZ" in argv
    assert "-rate" in argv
    assert "30" in argv


def test_ffuf_parser() -> None:
    """Test parsing of ffuf JSON output."""
    sample_json = """{
      "results": [
        {"input": {"FUZZ": "admin"}, "status": 403, "length": 250, "url": "http://192.168.1.10/admin"},
        {"input": {"FUZZ": "login"}, "status": 200, "length": 3400, "url": "http://192.168.1.10/login"}
      ]
    }"""
    result = parse_ffuf_json(sample_json, target_url="http://192.168.1.10")
    assert result.success is True
    assert len(result.matches) == 2
    assert result.matches[0].path == "/admin"
    assert result.matches[0].status == 403
    assert result.matches[1].path == "/login"
    assert result.matches[1].status == 200


@pytest.mark.asyncio
async def test_ffuf_executor_execution() -> None:
    """Test FfufToolExecutor executes simulated fuzzing."""
    executor = FfufToolExecutor()
    definition = get_ffuf_tool_definition()

    req = ToolRequest(
        engagement_id=new_id(),
        task_id=new_id(),
        agent_id=new_id(),
        tool_name="ffuf",
        target="http://192.168.1.10",
        arguments={"wordlist": "common.txt", "rate": 20},
    )
    result = await executor.execute(req, definition)
    assert result.success is True
    assert result.output.get("match_count", 0) >= 1


def test_ffuf_normalization() -> None:
    """Test AssetNormalizer creates canonical Endpoint entities from ffuf."""
    normalizer = AssetNormalizer()
    sample = """{"results": [{"input": {"FUZZ": "api/v1"}, "status": 200, "url": "http://192.168.1.10/api/v1"}]}"""
    ffuf_res = parse_ffuf_json(sample, target_url="http://192.168.1.10")
    bundle = normalizer.normalize_ffuf_result(
        result=ffuf_res,
        engagement_id=new_id(),
        target="http://192.168.1.10",
        evidence_refs=["sha256:ffuf01"],
    )
    assert len(bundle.endpoints) == 1
    ep = bundle.endpoints[0]
    assert ep.path == "/api/v1"
    assert ep.host == "192.168.1.10"
    assert ep.source == "ffuf"


# ==============================================================================
# WHATWEB ADAPTER TESTS
# ==============================================================================


def test_whatweb_scan_config_validation() -> None:
    """Test WhatWebScanConfig validation."""
    config = WhatWebScanConfig(aggression=1)
    assert config.requires_escalation() is False

    config_agg = WhatWebScanConfig(aggression=3)
    assert config_agg.requires_escalation() is True


def test_whatweb_parser() -> None:
    """Test parsing WhatWeb JSON output."""
    sample_json = """[
      {
        "target": "http://192.168.1.10",
        "http_status": 200,
        "plugins": {
          "HTTPServer": {
            "version": ["1.24.0"],
            "string": ["nginx/1.24.0"],
            "cpe": ["cpe:/a:nginx:nginx:1.24.0"]
          },
          "PHP": {"version": ["8.2.10"], "cpe": ["cpe:/a:php:php:8.2.10"]}
        }
      }
    ]"""
    res = parse_whatweb_json(sample_json, target="http://192.168.1.10")
    assert res.success is True
    assert len(res.targets) == 1
    plugins = res.targets[0].plugins
    assert "HTTPServer" in plugins
    assert plugins["HTTPServer"].version == ["1.24.0"]
    assert "PHP" in plugins


@pytest.mark.asyncio
async def test_whatweb_executor_execution() -> None:
    """Test WhatWebToolExecutor execution."""
    executor = WhatWebToolExecutor()
    definition = get_whatweb_tool_definition()

    req = ToolRequest(
        engagement_id=new_id(),
        task_id=new_id(),
        agent_id=new_id(),
        tool_name="whatweb",
        target="http://192.168.1.10",
        arguments={"aggression": 1},
    )
    result = await executor.execute(req, definition)
    assert result.success is True
    assert result.output.get("target_count", 0) >= 1


def test_whatweb_normalization() -> None:
    """Test AssetNormalizer produces canonical Technology entities from WhatWeb."""
    normalizer = AssetNormalizer()
    sample = (
        """[{"target": "http://192.168.1.10", "plugins": {"WordPress": {"version": ["6.2"]}}}]"""
    )
    ww_res = parse_whatweb_json(sample, target="http://192.168.1.10")
    bundle = normalizer.normalize_whatweb_result(
        result=ww_res,
        engagement_id=new_id(),
        target="http://192.168.1.10",
        evidence_refs=["sha256:ww01"],
    )
    assert len(bundle.technologies) == 1
    assert bundle.technologies[0].name == "WordPress"
    assert bundle.technologies[0].version == "6.2"


# ==============================================================================
# AMASS ADAPTER TESTS
# ==============================================================================


def test_amass_scan_config_validation() -> None:
    """Test AmassScanConfig validation and escalation."""
    config = AmassScanConfig(mode="passive", timeout_minutes=5)
    assert config.requires_escalation() is False

    config_act = AmassScanConfig(mode="active")
    assert config_act.requires_escalation() is True

    with pytest.raises(ValueError, match="must be 'passive' or 'active'"):
        AmassScanConfig(mode="intrusive")


def test_amass_parser() -> None:
    """Test parsing of Amass JSONL output."""
    sample = (
        '{"name": "example.com", "domain": "example.com", '
        '"addresses": [{"ip": "93.184.216.34"}], "tag": "dns"}\n'
        '{"name": "api.example.com", "domain": "example.com", '
        '"addresses": [{"ip": "93.184.216.35"}], "tag": "cert"}\n'
    )
    result = parse_amass_json(sample, domain="example.com")
    assert result.success is True
    assert len(result.records) == 2
    assert result.records[1].name == "api.example.com"
    assert len(result.records[1].addresses) == 1


@pytest.mark.asyncio
async def test_amass_executor_execution() -> None:
    """Test AmassToolExecutor execution."""
    executor = AmassToolExecutor()
    definition = get_amass_tool_definition()

    req = ToolRequest(
        engagement_id=new_id(),
        task_id=new_id(),
        agent_id=new_id(),
        tool_name="amass",
        target="example.com",
        arguments={"mode": "passive"},
    )
    result = await executor.execute(req, definition)
    assert result.success is True
    assert result.output.get("record_count", 0) >= 1


def test_amass_normalization_discovered_invariant() -> None:
    """Test Amass normalization marks status as 'discovered' without scope modification."""
    normalizer = AssetNormalizer()
    sample = (
        '{"name": "dev.example.com", "domain": "example.com", '
        '"addresses": [{"ip": "93.184.216.99"}], "tag": "dns"}'
    )
    amass_res = parse_amass_json(sample, domain="example.com")
    bundle = normalizer.normalize_amass_result(
        result=amass_res,
        engagement_id=new_id(),
        target="example.com",
        evidence_refs=["sha256:amass01"],
    )
    assert len(bundle.assets) == 2  # subdomain asset + IP asset
    for a in bundle.assets:
        assert a.status == "discovered"
