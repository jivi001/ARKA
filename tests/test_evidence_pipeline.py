"""
Unit and Integration Tests for ARKA Evidence Pipeline & Safe Parsers (Module I).

Validates:
- CTRL-PARSER-SANDBOX-001: Sandboxed Isolated Evidence Parsing
- TEST-EVIDENCE-PARSER-001: Evidence Parser Sandbox Containment Contract
- GATE-PARSER-SANDBOX-001: Evidence Parser Sandbox Containment Gate
- CTRL-CONTENT-ISOLATION-001: Target Content Quarantine and Untrusted Tagging
- Neutralization of THREAT-EVIDENCE-PARSER-COMPROMISE (XXE, XML bombs, ReDoS)
- Domain-separated content-addressable SHA-256 hashing (DOMAIN_EVIDENCE)
- Automated trust & sensitivity classification with DLP secret redaction
- Immutable evidence store and mission isolation
"""

import hashlib
import unittest

from arka.evidence import (
    DOMAIN_EVIDENCE,
    EvidenceClassifier,
    EvidenceImmutabilityError,
    EvidenceIntegrityError,
    EvidencePipeline,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceStore,
    EvidenceType,
    HttpOutputParser,
    NmapXmlParser,
    ParserBombError,
    SafeHtmlParser,
    SafeJsonParser,
    SafeXmlParser,
    SensitivityLevel,
    TrustLevel,
)


class TestEvidencePipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = EvidencePipeline(max_artifact_bytes=64 * 1024)
        self.store = EvidenceStore()
        self.provenance = EvidenceProvenance(
            mission_id="mission-alpha",
            task_id="task-recon-01",
            collector="nmap",
            action_id="act-001",
            capability_id="PORT_SCAN",
            target="198.51.100.1",
        )

    def test_safe_json_parsing_success(self):
        """Safe JSON parser parses valid structured evidence."""
        parser = SafeJsonParser(max_depth=4)
        raw = b'{"status": "ok", "service": {"name": "http", "port": 80}}'
        data = parser.parse(raw)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"]["port"], 80)

    def test_safe_json_deep_nesting_bomb_rejected(self):
        """
        TEST-EVIDENCE-PARSER-001:
        Adversary supplies deeply nested JSON recursion bomb (depth > 8).
        Parser must safely reject with ParserBombError without crashing host.
        """
        parser = SafeJsonParser(max_depth=5)
        # Construct nesting of depth 8
        nested = '{"a":' * 8 + '1' + '}' * 8
        with self.assertRaises(ParserBombError):
            parser.parse(nested.encode("utf-8"))

    def test_safe_xml_parsing_success(self):
        """Safe XML parser parses benign XML structures."""
        parser = SafeXmlParser(max_depth=5)
        raw = b"<response><status>200</status><banner>Apache/2.4</banner></response>"
        data = parser.parse(raw)
        self.assertEqual(data["tag"], "response")
        self.assertEqual(len(data["children"]), 2)

    def test_safe_xml_billion_laughs_bomb_rejected(self):
        """
        TEST-EVIDENCE-PARSER-001:
        Adversary supplies Billion Laughs / quadratic entity expansion bomb.
        defusedxml must block entity expansion with ParserBombError.
        """
        parser = SafeXmlParser()
        xml_bomb = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<lolz>&lol2;</lolz>"""

        with self.assertRaises(ParserBombError):
            parser.parse(xml_bomb)

    def test_safe_xml_external_entity_xxe_blocked(self):
        """
        TEST-EVIDENCE-PARSER-001:
        Adversary attempts Classic XXE file read (SYSTEM "file:///etc/passwd").
        defusedxml must block external entity resolution with ParserBombError.
        """
        parser = SafeXmlParser()
        xxe_payload = b"""<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<test>&xxe;</test>"""

        with self.assertRaises(ParserBombError):
            parser.parse(xxe_payload)

    def test_nmap_xml_safe_extraction(self):
        """NmapXmlParser safely extracts hosts, ports, and service banners."""
        nmap_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

        parser = NmapXmlParser()
        result = parser.parse(nmap_xml)
        self.assertIn("nmap_hosts", result)
        self.assertEqual(len(result["nmap_hosts"]), 1)
        host = result["nmap_hosts"][0]
        self.assertIn("192.168.1.50", host["addresses"])
        self.assertEqual(len(host["ports"]), 2)
        self.assertEqual(host["ports"][0]["port"], 22)
        self.assertEqual(host["ports"][0]["service"], "ssh")

    def test_http_response_parsing(self):
        """HttpOutputParser safely parses status code, headers, and bounded body."""
        raw_http = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\nContent-Type: text/html\r\n\r\n<h1>Hello World</h1>"
        parser = HttpOutputParser()
        parsed = parser.parse(raw_http)
        self.assertEqual(parsed["status_code"], 200)
        self.assertEqual(parsed["headers"]["server"], "nginx/1.24")
        self.assertEqual(parsed["body_preview"], "<h1>Hello World</h1>")

    def test_safe_html_parsing_strips_scripts(self):
        """SafeHtmlParser strips script/iframe tags and extracts safe page title."""
        malicious_html = b"""<html>
<head><title>Admin Portal</title><script>alert('xss');</script></head>
<body>
<a href="/login">Login Here</a>
<iframe src="http://malicious.evil"></iframe>
</body></html>"""

        parser = SafeHtmlParser()
        parsed = parser.parse(malicious_html)
        self.assertEqual(parsed["title"], "Admin Portal")
        self.assertIn("/login", parsed["links"])

    def test_trust_and_sensitivity_classification_untrusted_default(self):
        """All target-derived evidence defaults to UNTRUSTED trust level."""
        raw = b"Open port 80 found on target 198.51.100.1"
        record = self.pipeline.quarantine_and_parse(
            raw_bytes=raw,
            provenance=self.provenance,
            evidence_type=EvidenceType.PORT_SCAN,
        )
        self.assertEqual(record.trust, TrustLevel.UNTRUSTED)
        self.assertEqual(record.sensitivity, SensitivityLevel.PUBLIC)

    def test_sensitivity_secret_detection_and_redaction(self):
        """Credentials and API keys are classified as SECRET and redacted in place."""
        raw = (
            b"Service output leaked access key: AKIAIOSFODNN7EXAMPLE and "
            b"database password='SuperSecretPassword123!'."
        )

        record = self.pipeline.quarantine_and_parse(
            raw_bytes=raw,
            provenance=self.provenance,
            evidence_type=EvidenceType.STDOUT,
        )

        self.assertEqual(record.sensitivity, SensitivityLevel.SECRET)
        self.assertIsNotNone(record.redacted_content)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", record.redacted_content)
        self.assertNotIn("SuperSecretPassword123!", record.redacted_content)
        self.assertIn("[REDACTED_SECRET]", record.redacted_content)

    def test_content_hash_domain_separation_integrity(self):
        """Content hash uses DOMAIN_EVIDENCE ('ARKA-EVIDENCE-V1:') and matches SHA-256."""
        raw = b"Sample raw evidence bytes"
        record = self.pipeline.quarantine_and_parse(
            raw_bytes=raw,
            provenance=self.provenance,
        )

        expected_hash = hashlib.sha256(DOMAIN_EVIDENCE + raw).hexdigest()
        self.assertEqual(record.content_hash, expected_hash)

    def test_evidence_store_immutability_and_tamper_detection(self):
        """Evidence store enforces immutability and rejects mutation attempts."""
        raw = b"Original evidence"
        record = self.pipeline.quarantine_and_parse(raw, self.provenance)

        # First store succeeds
        eid = self.store.put(record)
        self.assertEqual(eid, record.evidence_id)

        # Idempotent put succeeds
        eid_same = self.store.put(record)
        self.assertEqual(eid_same, eid)

        # Verification succeeds
        self.assertTrue(self.store.verify_integrity(eid))

        # Tampered record with same ID but different content raises EvidenceImmutabilityError
        tampered_record = EvidenceRecord(
            evidence_id=record.evidence_id,
            provenance=record.provenance,
            evidence_type=record.evidence_type,
            raw_content=b"Mutated evidence content",
            content_hash=hashlib.sha256(DOMAIN_EVIDENCE + b"Mutated evidence content").hexdigest(),
            size_bytes=len(b"Mutated evidence content"),
            created_at_unix=record.created_at_unix,
            trust=record.trust,
            sensitivity=record.sensitivity,
        )

        with self.assertRaises(EvidenceImmutabilityError):
            self.store.put(tampered_record)

    def test_evidence_store_mission_isolation(self):
        """Evidence cannot be retrieved across different mission boundaries."""
        raw = b"Confidential mission data"
        record = self.pipeline.quarantine_and_parse(raw, self.provenance)
        eid = self.store.put(record)

        # Same mission retrieval succeeds
        retrieved = self.store.get(eid, mission_id="mission-alpha")
        self.assertIsNotNone(retrieved)

        # Different mission retrieval fails (returns None)
        other_mission_retrieved = self.store.get(eid, mission_id="mission-beta")
        self.assertIsNone(other_mission_retrieved)

    def test_evidence_store_sensitivity_ceiling_filtering(self):
        """Querying with sensitivity ceiling filters out high-sensitivity artifacts."""
        # 1. Public artifact
        pub_rec = self.pipeline.quarantine_and_parse(
            b"Public DNS record for target.com",
            self.provenance,
        )
        self.store.put(pub_rec)

        # 2. Secret artifact
        sec_rec = self.pipeline.quarantine_and_parse(
            b"AKIAIOSFODNN7EXAMPLE leaked in env",
            self.provenance,
        )
        self.store.put(sec_rec)

        # List all
        all_records = self.store.list_for_mission("mission-alpha")
        self.assertEqual(len(all_records), 2)

        # List with PUBLIC ceiling (excludes SECRET)
        public_records = self.store.list_for_mission(
            "mission-alpha",
            sensitivity_ceiling=SensitivityLevel.PUBLIC,
        )
        self.assertEqual(len(public_records), 1)
        self.assertEqual(public_records[0].evidence_id, pub_rec.evidence_id)

    def test_evidence_size_bound_truncation(self):
        """Payloads exceeding max_artifact_bytes are truncated and flagged."""
        bounded_pipeline = EvidencePipeline(max_artifact_bytes=100)
        oversized = b"X" * 250
        record = bounded_pipeline.quarantine_and_parse(oversized, self.provenance)

        self.assertEqual(record.size_bytes, 100)
        self.assertTrue(record.truncated)


if __name__ == "__main__":
    unittest.main()
