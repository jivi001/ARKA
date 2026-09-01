"""Unit tests for the ARKA Evidence Pipeline & Provenance Foundation (Phase 2.2.3).

Tests:
- EvidenceType enum validation and serialization
- EvidenceReference creation and provenance fields
- SHA-256 content hashing accuracy
- Defensive copying (immutability against caller mutation)
- Content-addressed deduplication (shared blobs with distinct references)
- Listing by engagement, execution, and all
- Raw blob retrieval and verification
- Secret redaction in metadata
- Integrity verification
"""

import hashlib
import json

import pytest

from arka.app.execution.evidence import EvidenceStore
from arka.app.execution.schemas import EvidenceReference, EvidenceType


@pytest.fixture
def evidence_store() -> EvidenceStore:
    return EvidenceStore()


class TestEvidenceTypeEnum:
    """Test EvidenceType enum values and properties."""

    def test_evidence_type_values(self):
        assert EvidenceType.RAW_STDOUT.value == "raw_stdout"
        assert EvidenceType.RAW_STDERR.value == "raw_stderr"
        assert EvidenceType.STRUCTURED_RESULT.value == "structured_result"
        assert EvidenceType.TOOL_ARTIFACT.value == "tool_artifact"
        assert EvidenceType.PARSED_RESULT.value == "parsed_result"

    def test_evidence_reference_default_type(self):
        ref = EvidenceReference(
            execution_id="exec-1",
            request_id="req-1",
            engagement_id="eng-1",
            task_id="task-1",
            sha256="dummyhash",
        )
        assert ref.evidence_type == EvidenceType.STRUCTURED_RESULT.value
        assert ref.tool_name == ""
        assert ref.location == "in_memory"
        assert ref.size_bytes == 0


class TestEvidenceStoreRecording:
    """Test recording evidence in EvidenceStore."""

    def test_record_string_content(self, evidence_store: EvidenceStore):
        content = "Raw tool output line 1\nRaw tool output line 2\n"
        ref = evidence_store.record_evidence(
            execution_id="exec-101",
            request_id="req-101",
            engagement_id="eng-101",
            task_id="task-101",
            content=content,
            evidence_type=EvidenceType.RAW_STDOUT.value,
            tool_name="nmap",
        )

        expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert ref.sha256 == expected_hash
        assert ref.size_bytes == len(content.encode("utf-8"))
        assert ref.tool_name == "nmap"
        assert ref.evidence_type == EvidenceType.RAW_STDOUT.value
        assert ref.execution_id == "exec-101"
        assert ref.engagement_id == "eng-101"
        assert ref.task_id == "task-101"

    def test_record_dict_content(self, evidence_store: EvidenceStore):
        content = {"ports": [80, 443], "host": "192.168.1.1"}
        ref = evidence_store.record_evidence(
            execution_id="exec-102",
            request_id="req-102",
            engagement_id="eng-102",
            task_id="task-102",
            content=content,
            evidence_type=EvidenceType.STRUCTURED_RESULT.value,
            tool_name="nmap",
        )

        expected_bytes = json.dumps(content, sort_keys=True).encode("utf-8")
        expected_hash = hashlib.sha256(expected_bytes).hexdigest()
        assert ref.sha256 == expected_hash
        assert ref.size_bytes == len(expected_bytes)

    def test_record_bytes_content(self, evidence_store: EvidenceStore):
        raw_bytes = b"\x00\x01\x02\x03\xff\xfe"
        ref = evidence_store.record_evidence(
            execution_id="exec-103",
            request_id="req-103",
            engagement_id="eng-103",
            task_id="task-103",
            content=raw_bytes,
            evidence_type=EvidenceType.TOOL_ARTIFACT.value,
        )

        expected_hash = hashlib.sha256(raw_bytes).hexdigest()
        assert ref.sha256 == expected_hash
        assert ref.size_bytes == len(raw_bytes)


class TestEvidenceStoreImmutabilityAndDefensiveCopy:
    """Test that callers cannot mutate internal EvidenceStore state."""

    def test_get_evidence_returns_defensive_copy(self, evidence_store: EvidenceStore):
        ref1 = evidence_store.record_evidence(
            execution_id="exec-201",
            request_id="req-201",
            engagement_id="eng-201",
            task_id="task-201",
            content="sample content",
            metadata={"target": "example.com", "custom_tag": "v1"},
        )

        # Mutate the returned EvidenceReference
        ref1.metadata["target"] = "TAMPERED.com"
        ref1.tool_name = "TAMPERED_TOOL"
        ref1.sha256 = "forged_sha256"

        # Fetch afresh from store
        ref2 = evidence_store.get_evidence(ref1.evidence_id)
        assert ref2 is not None
        assert ref2.metadata["target"] == "example.com"
        assert ref2.tool_name == ""
        assert ref2.sha256 != "forged_sha256"

    def test_get_raw_blob_returns_defensive_copy(self, evidence_store: EvidenceStore):
        content = b"immutable blob bytes"
        ref = evidence_store.record_evidence(
            execution_id="exec-202",
            request_id="req-202",
            engagement_id="eng-202",
            task_id="task-202",
            content=content,
        )

        blob1 = evidence_store.get_raw_blob(ref.evidence_id)
        assert blob1 == content

        # Verify blob integrity remains intact
        assert evidence_store.verify_integrity(ref.evidence_id) is True


class TestEvidenceStoreDeduplication:
    """Test content-addressed blob deduplication."""

    def test_identical_content_shares_blob_storage(self, evidence_store: EvidenceStore):
        identical_content = "Same scan output across multiple executions"

        # Execution 1
        ref1 = evidence_store.record_evidence(
            execution_id="exec-301",
            request_id="req-301",
            engagement_id="eng-301",
            task_id="task-301",
            content=identical_content,
            tool_name="nmap",
        )

        # Execution 2 (different execution, different engagement, same content)
        ref2 = evidence_store.record_evidence(
            execution_id="exec-302",
            request_id="req-302",
            engagement_id="eng-302",
            task_id="task-302",
            content=identical_content,
            tool_name="nmap",
        )

        # Distinct references with distinct IDs and execution provenance
        assert ref1.evidence_id != ref2.evidence_id
        assert ref1.execution_id == "exec-301"
        assert ref2.execution_id == "exec-302"
        assert ref1.sha256 == ref2.sha256

        # Total references = 2, but unique blobs = 1 (deduplicated)
        assert evidence_store.count == 2
        assert evidence_store.blob_count == 1

        # Both references can successfully retrieve raw blob and verify integrity
        blob1 = evidence_store.get_raw_blob(ref1.evidence_id)
        blob2 = evidence_store.get_raw_blob(ref2.evidence_id)
        assert blob1 == identical_content.encode("utf-8")
        assert blob2 == identical_content.encode("utf-8")
        assert evidence_store.verify_integrity(ref1.evidence_id) is True
        assert evidence_store.verify_integrity(ref2.evidence_id) is True


class TestEvidenceStoreListing:
    """Test querying and listing evidence references."""

    def test_list_by_engagement(self, evidence_store: EvidenceStore):
        # 2 for eng-A, 1 for eng-B
        evidence_store.record_evidence(
            execution_id="e1", request_id="r1", engagement_id="eng-A", task_id="t1", content="c1"
        )
        evidence_store.record_evidence(
            execution_id="e2", request_id="r2", engagement_id="eng-A", task_id="t2", content="c2"
        )
        evidence_store.record_evidence(
            execution_id="e3", request_id="r3", engagement_id="eng-B", task_id="t3", content="c3"
        )

        eng_a_refs = evidence_store.list_by_engagement("eng-A")
        assert len(eng_a_refs) == 2
        assert {r.execution_id for r in eng_a_refs} == {"e1", "e2"}

        eng_b_refs = evidence_store.list_by_engagement("eng-B")
        assert len(eng_b_refs) == 1
        assert eng_b_refs[0].execution_id == "e3"

        eng_c_refs = evidence_store.list_by_engagement("eng-C")
        assert len(eng_c_refs) == 0

    def test_list_by_execution(self, evidence_store: EvidenceStore):
        evidence_store.record_evidence(
            execution_id="exec-X",
            request_id="r1",
            engagement_id="eng-1",
            task_id="t1",
            content="stdout",
            evidence_type=EvidenceType.RAW_STDOUT.value,
        )
        evidence_store.record_evidence(
            execution_id="exec-X",
            request_id="r1",
            engagement_id="eng-1",
            task_id="t1",
            content={"parsed": True},
            evidence_type=EvidenceType.STRUCTURED_RESULT.value,
        )
        evidence_store.record_evidence(
            execution_id="exec-Y",
            request_id="r2",
            engagement_id="eng-1",
            task_id="t2",
            content="other stdout",
        )

        exec_x_refs = evidence_store.list_by_execution("exec-X")
        assert len(exec_x_refs) == 2
        types = {r.evidence_type for r in exec_x_refs}
        assert types == {EvidenceType.RAW_STDOUT.value, EvidenceType.STRUCTURED_RESULT.value}

    def test_list_all(self, evidence_store: EvidenceStore):
        evidence_store.record_evidence(
            execution_id="e1", request_id="r1", engagement_id="eng-1", task_id="t1", content="c1"
        )
        evidence_store.record_evidence(
            execution_id="e2", request_id="r2", engagement_id="eng-1", task_id="t2", content="c2"
        )
        all_refs = evidence_store.list_all()
        assert len(all_refs) == 2


class TestEvidenceStoreSecretRedaction:
    """Test metadata secret redaction in EvidenceStore."""

    def test_sensitive_keys_redacted_in_metadata(self, evidence_store: EvidenceStore):
        metadata = {
            "target": "10.0.0.1",
            "api_key": "secret-key-12345",
            "authorization": "Bearer token-abc-xyz",
            "password": "super-secret-password",
            "nested": {
                "private_key": "-----BEGIN PRIVATE KEY-----",
                "normal_field": "safe_value",
            },
        }

        ref = evidence_store.record_evidence(
            execution_id="exec-401",
            request_id="req-401",
            engagement_id="eng-401",
            task_id="task-401",
            content="scan output",
            metadata=metadata,
        )

        assert ref.metadata["target"] == "10.0.0.1"
        assert ref.metadata["api_key"] == "[REDACTED]"
        assert ref.metadata["authorization"] == "[REDACTED]"
        assert ref.metadata["password"] == "[REDACTED]"
        assert ref.metadata["nested"]["private_key"] == "[REDACTED]"
        assert ref.metadata["nested"]["normal_field"] == "safe_value"

    def test_raw_evidence_content_is_not_redacted(self, evidence_store: EvidenceStore):
        """Raw evidence content (e.g. SSL certificates, banners) must NOT be modified.

        Modifying raw content would corrupt cryptographic integrity.
        """
        raw_banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1 with key fingerprint"
        ref = evidence_store.record_evidence(
            execution_id="exec-402",
            request_id="req-402",
            engagement_id="eng-402",
            task_id="task-402",
            content=raw_banner,
        )

        retrieved = evidence_store.get_raw_blob(ref.evidence_id)
        assert retrieved == raw_banner.encode("utf-8")
        assert evidence_store.verify_integrity(ref.evidence_id) is True
