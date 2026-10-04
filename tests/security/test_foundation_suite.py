"""
ARKA Phase 0 Foundation Verification Test Suite
Executes verifiable unit tests for P0 Model Integrity, Traceability, Key Management,
Supply Chain CI configuration, and Cryptographic Baseline Manifest.
"""

import os
import unittest
import yaml
from security.validator.validate_security_model import (
    run_core_validation,
    compute_file_sha256,
    REPO_ROOT,
    BASE_DIR,
)


class TestFoundationSuite(unittest.TestCase):
    def test_p0_model_and_traceability_integrity(self):
        """TEST-P0-MODEL-INTEGRITY-001 & TEST-P0-TRACEABILITY-001"""
        result = run_core_validation(log=False)
        self.assertTrue(result, "P0 security model and traceability matrix must validate with 0 errors.")

    def test_supply_chain_workflow_hardening(self):
        """TEST-SUPPLY-CHAIN-001"""
        workflow_path = os.path.join(REPO_ROOT, ".github", "workflows", "security-foundation.yml")
        self.assertTrue(os.path.exists(workflow_path), "Security workflow file must exist.")

        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Enforce all 6 blocking jobs are defined
        required_jobs = [
            "ci-sec-model",
            "ci-sec-traceability",
            "ci-sec-validator",
            "ci-sec-secrets",
            "ci-sec-dependencies",
            "ci-sec-sbom",
        ]
        for job in required_jobs:
            self.assertIn(job, content, f"Workflow must define job: {job}")

        # Enforce minimal contents: read permissions
        self.assertIn("contents: read", content, "Workflow must enforce minimal contents: read permission.")

        # Enforce SHA-pinned third-party actions
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", content)
        self.assertIn("gitleaks/gitleaks-action@b04eb32d2011ea354c46f366113b2e59ba33527a", content)

        # Enforce CODEOWNERS existence
        codeowners_path = os.path.join(REPO_ROOT, ".github", "CODEOWNERS")
        self.assertTrue(os.path.exists(codeowners_path), ".github/CODEOWNERS must exist.")
        with open(codeowners_path, "r", encoding="utf-8") as f:
            co_content = f.read()
        self.assertIn("@jivi001", co_content, "CODEOWNERS must assign @jivi001 to security paths.")

    def test_baseline_manifest_verification(self):
        """TEST-P0-CI-GATE-INTEGRITY-001"""
        manifest_path = os.path.join(BASE_DIR, "baseline.manifest")
        self.assertTrue(os.path.exists(manifest_path), "security/baseline.manifest must exist.")

        with open(manifest_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        verified_count = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            self.assertEqual(len(parts), 2)
            expected_hash, rel_path = parts
            abs_path = os.path.join(BASE_DIR, rel_path)
            self.assertTrue(os.path.exists(abs_path), f"File in manifest must exist: {rel_path}")
            actual_hash = compute_file_sha256(abs_path)
            self.assertEqual(actual_hash, expected_hash, f"Hash mismatch for {rel_path}!")
            verified_count += 1

        self.assertGreaterEqual(verified_count, 20, "Manifest must contain at least 20 verified security assets.")


if __name__ == "__main__":
    unittest.main()
