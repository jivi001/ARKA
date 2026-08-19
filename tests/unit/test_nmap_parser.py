"""Unit tests for Nmap XML parser (Phase 2.2.1)."""

from pathlib import Path

from arka.app.tools.nmap.parser import parse_nmap_xml

FIXTURES = Path(__file__).parent.parent / "fixtures" / "nmap"


class TestNmapParserBasicScan:
    def test_parse_basic_scan_single_host(self):
        xml = (FIXTURES / "basic_scan.xml").read_text()
        result = parse_nmap_xml(xml)

        assert result.success is True
        assert result.error is None
        assert len(result.hosts) == 1

        host = result.hosts[0]
        assert host.address == "192.168.1.10"
        assert host.address_type == "ipv4"
        assert host.status == "up"
        assert "webserver.example.com" in host.hostnames

    def test_parse_basic_scan_ports(self):
        xml = (FIXTURES / "basic_scan.xml").read_text()
        result = parse_nmap_xml(xml)
        host = result.hosts[0]

        assert len(host.ports) == 3

        port_22 = next(p for p in host.ports if p.port == 22)
        assert port_22.protocol == "tcp"
        assert port_22.state == "open"
        assert port_22.service is not None
        assert port_22.service.name == "ssh"
        assert port_22.service.product == "OpenSSH"
        assert port_22.service.version == "9.6"

        port_443 = next(p for p in host.ports if p.port == 443)
        assert port_443.state == "closed"

    def test_parse_basic_scan_cpe(self):
        xml = (FIXTURES / "basic_scan.xml").read_text()
        result = parse_nmap_xml(xml)
        host = result.hosts[0]

        port_22 = next(p for p in host.ports if p.port == 22)
        assert port_22.service is not None
        assert "cpe:/a:openbsd:openssh:9.6" in port_22.service.cpe

    def test_parse_basic_scan_metadata(self):
        xml = (FIXTURES / "basic_scan.xml").read_text()
        result = parse_nmap_xml(xml)

        assert result.scan_metadata.get("scanner") == "nmap"
        assert result.scan_metadata.get("version") == "7.95"
        assert result.scan_metadata.get("hosts_up") == "1"
        assert result.scan_metadata.get("hosts_total") == "1"
        assert result.scan_metadata.get("exit_status") == "success"


class TestNmapParserMultiHost:
    def test_parse_multi_host(self):
        xml = (FIXTURES / "multi_host.xml").read_text()
        result = parse_nmap_xml(xml)

        assert result.success is True
        assert len(result.hosts) == 3

        addresses = [h.address for h in result.hosts]
        assert "192.168.1.1" in addresses
        assert "192.168.1.10" in addresses
        assert "192.168.1.20" in addresses

    def test_multi_host_hostnames(self):
        xml = (FIXTURES / "multi_host.xml").read_text()
        result = parse_nmap_xml(xml)

        host_20 = next(h for h in result.hosts if h.address == "192.168.1.20")
        assert "db.internal" in host_20.hostnames
        assert "database.local" in host_20.hostnames

    def test_multi_host_metadata(self):
        xml = (FIXTURES / "multi_host.xml").read_text()
        result = parse_nmap_xml(xml)

        assert result.scan_metadata.get("hosts_up") == "3"
        assert result.scan_metadata.get("hosts_total") == "256"


class TestNmapParserScriptOutput:
    def test_parse_script_output(self):
        xml = (FIXTURES / "script_output.xml").read_text()
        result = parse_nmap_xml(xml)

        assert result.success is True
        host = result.hosts[0]
        port_80 = next(p for p in host.ports if p.port == 80)

        assert len(port_80.scripts) == 2
        script_ids = [s.script_id for s in port_80.scripts]
        assert "http-title" in script_ids
        assert "http-server-header" in script_ids

        title_script = next(s for s in port_80.scripts if s.script_id == "http-title")
        assert title_script.output == "Welcome to nginx"

    def test_parse_multiple_cpe(self):
        xml = (FIXTURES / "script_output.xml").read_text()
        result = parse_nmap_xml(xml)

        host = result.hosts[0]
        port_443 = next(p for p in host.ports if p.port == 443)
        assert port_443.service is not None
        assert len(port_443.service.cpe) == 2
        assert "cpe:/a:nginx:nginx:1.24.0" in port_443.service.cpe
        assert "cpe:/o:linux:linux_kernel" in port_443.service.cpe


class TestNmapParserEmptyResult:
    def test_parse_empty_result(self):
        xml = (FIXTURES / "empty_result.xml").read_text()
        result = parse_nmap_xml(xml)

        assert result.success is True
        assert len(result.hosts) == 0
        assert result.scan_metadata.get("hosts_up") == "0"
        assert result.scan_metadata.get("hosts_down") == "4"


class TestNmapParserMalformedXml:
    def test_malformed_xml_returns_controlled_error(self):
        xml = (FIXTURES / "malformed.xml").read_text()
        result = parse_nmap_xml(xml)

        assert result.success is False
        assert result.error is not None
        assert "Malformed XML" in result.error

    def test_completely_invalid_xml(self):
        result = parse_nmap_xml("this is not xml at all")

        assert result.success is False
        assert result.error is not None
        assert "Malformed XML" in result.error

    def test_empty_string(self):
        result = parse_nmap_xml("")

        assert result.success is False
        assert result.error is not None

    def test_bytes_input(self):
        xml = (FIXTURES / "basic_scan.xml").read_bytes()
        result = parse_nmap_xml(xml)

        assert result.success is True
        assert len(result.hosts) == 1


class TestNmapParserSafeDefaults:
    def test_missing_service_element(self):
        """Ports without <service> elements produce None service."""
        xml = (FIXTURES / "basic_scan.xml").read_text()
        result = parse_nmap_xml(xml)

        port_443 = next(p for p in result.hosts[0].ports if p.port == 443)
        assert port_443.service is None  # closed port, no service element

    def test_host_without_hostnames(self):
        """Host without hostname entries produces empty hostname list."""
        xml = (FIXTURES / "multi_host.xml").read_text()
        result = parse_nmap_xml(xml)

        host_10 = next(h for h in result.hosts if h.address == "192.168.1.10")
        assert host_10.hostnames == []

    def test_raw_xml_preserved(self):
        xml = (FIXTURES / "basic_scan.xml").read_text()
        result = parse_nmap_xml(xml)
        assert result.raw_xml == xml
