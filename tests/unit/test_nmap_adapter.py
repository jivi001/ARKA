"""Unit tests for Nmap adapter argument model and tool definition (Phase 2.2.1)."""

import pytest

from arka.app.tools.nmap.definition import get_nmap_tool_definition
from arka.app.tools.nmap.schemas import NmapScanConfig


class TestNmapScanConfigArgvConstruction:
    """Verify that to_argv() produces ONLY allowlisted flags."""

    def test_default_config_argv(self):
        config = NmapScanConfig()
        argv = config.to_argv("192.168.1.10")

        assert argv[0] == "nmap"
        assert "-sV" in argv
        assert "-sC" not in argv  # default_scripts=False by default
        assert "-T2" in argv
        assert "-oX" in argv
        assert argv[argv.index("-oX") + 1] == "-"
        assert argv[-1] == "192.168.1.10"

    def test_with_ports(self):
        config = NmapScanConfig(ports="80,443,8080")
        argv = config.to_argv("10.0.0.1")

        assert "-p" in argv
        assert argv[argv.index("-p") + 1] == "80,443,8080"

    def test_with_port_range(self):
        config = NmapScanConfig(ports="1-1024")
        argv = config.to_argv("10.0.0.1")

        assert "-p" in argv
        assert argv[argv.index("-p") + 1] == "1-1024"

    def test_without_ports(self):
        config = NmapScanConfig(ports=None)
        argv = config.to_argv("10.0.0.1")

        assert "-p" not in argv

    def test_with_service_detection_disabled(self):
        config = NmapScanConfig(service_detection=False)
        argv = config.to_argv("10.0.0.1")

        assert "-sV" not in argv

    def test_with_default_scripts(self):
        config = NmapScanConfig(default_scripts=True)
        argv = config.to_argv("10.0.0.1")

        assert "-sC" in argv

    def test_timing_templates(self):
        for t in range(5):
            config = NmapScanConfig(timing_template=t)
            argv = config.to_argv("10.0.0.1")
            assert f"-T{t}" in argv

    def test_xml_output_always_present_and_stdout(self):
        config = NmapScanConfig()
        argv = config.to_argv("target.example.com")

        idx = argv.index("-oX")
        assert argv[idx + 1] == "-"

    def test_target_always_last(self):
        config = NmapScanConfig(ports="80", default_scripts=True)
        argv = config.to_argv("192.168.1.50")

        assert argv[-1] == "192.168.1.50"

    def test_only_allowlisted_flags_appear(self):
        """No unexpected flags should appear in the argv."""
        config = NmapScanConfig(
            ports="80,443",
            service_detection=True,
            default_scripts=True,
            timing_template=4,
        )
        argv = config.to_argv("10.0.0.1")

        # All flags must be from the allowlist
        allowed_flags = {"-sV", "-sC", "-p", "-oX", "-"}
        for item in argv[1:-1]:  # Skip "nmap" and target
            if item.startswith("-") and item != "-":
                assert item in allowed_flags or item.startswith("-T"), (
                    f"Unexpected flag in argv: {item}"
                )


class TestNmapScanConfigPortValidation:
    def test_valid_port_specs(self):
        valid = ["80", "80,443", "1-1024", "22,80,443,8080-9090"]
        for spec in valid:
            config = NmapScanConfig(ports=spec)
            assert config.ports == spec

    def test_invalid_port_specs_rejected(self):
        invalid = [
            "abc",
            "80;ls",
            "80|cat /etc/passwd",
            "80&whoami",
            "80$(id)",
            "80`id`",
            "80\n443",
            "../../../etc/passwd",
            "-iL /etc/hosts",
        ]
        for spec in invalid:
            with pytest.raises(ValueError):
                NmapScanConfig(ports=spec)

    def test_empty_port_spec_becomes_none(self):
        config = NmapScanConfig(ports="")
        assert config.ports is None

    def test_whitespace_port_spec_becomes_none(self):
        config = NmapScanConfig(ports="   ")
        assert config.ports is None


class TestNmapScanConfigTimingValidation:
    def test_valid_timing_range(self):
        for t in range(5):
            config = NmapScanConfig(timing_template=t)
            assert config.timing_template == t

    def test_timing_below_range_rejected(self):
        with pytest.raises(ValueError):
            NmapScanConfig(timing_template=-1)

    def test_timing_above_range_rejected(self):
        with pytest.raises(ValueError):
            NmapScanConfig(timing_template=5)


class TestNmapScanConfigRiskEscalation:
    def test_no_escalation_default_config(self):
        config = NmapScanConfig()
        assert config.requires_escalation() is False

    def test_escalation_default_scripts(self):
        config = NmapScanConfig(default_scripts=True)
        assert config.requires_escalation() is True

    def test_escalation_timing_3(self):
        config = NmapScanConfig(timing_template=3)
        assert config.requires_escalation() is True

    def test_escalation_timing_4(self):
        config = NmapScanConfig(timing_template=4)
        assert config.requires_escalation() is True

    def test_no_escalation_timing_2(self):
        config = NmapScanConfig(timing_template=2)
        assert config.requires_escalation() is False

    def test_escalation_both(self):
        config = NmapScanConfig(default_scripts=True, timing_template=4)
        assert config.requires_escalation() is True


class TestNmapToolDefinition:
    def test_definition_exists(self):
        defn = get_nmap_tool_definition()
        assert defn.name == "nmap"
        assert defn.enabled is True

    def test_definition_risk_level_medium(self):
        defn = get_nmap_tool_definition()
        from arka.app.core.state.models import RiskLevel

        assert defn.risk_level == RiskLevel.MEDIUM

    def test_definition_input_schema_fields(self):
        defn = get_nmap_tool_definition()
        props = defn.input_schema.get("properties", {})

        assert "ports" in props
        assert "service_detection" in props
        assert "default_scripts" in props
        assert "timing_template" in props

        # Verify no extra fields that could be exploited
        assert len(props) == 4

    def test_definition_no_required_arguments(self):
        defn = get_nmap_tool_definition()
        assert defn.input_schema.get("required") == []

    def test_definition_timeout(self):
        defn = get_nmap_tool_definition()
        assert defn.timeout_seconds == 600

    def test_definition_category(self):
        defn = get_nmap_tool_definition()
        assert defn.category == "reconnaissance"
