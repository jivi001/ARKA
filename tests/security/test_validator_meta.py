"""
Meta-Test Suite for ARKA Security Model & Traceability Validator
Verifies that the validator actively detects and rejects known-bad security mutations:
1. Missing threat
2. Missing control
3. Missing test contract
4. Missing acceptance gate
5. Invalid phase number
6. Missing test owner
7. Non-blocking security gate
8. Weakened gate expected result
9. Deleted traceability entry
10. Invalid component reference
11. Missing key domain
12. Premature phase exit (phase complete with pending controls)
"""

import os
import unittest
from security.validator.validate_security_model import test_mutation_case, run_core_validation


class TestValidatorMeta(unittest.TestCase):
    def test_validator_on_current_baseline(self):
        """Verify that the unmutated baseline passes validation cleanly."""
        result = run_core_validation(log=False)
        self.assertTrue(result, "Baseline security model should pass validation cleanly.")

    def test_reject_missing_threat(self):
        self.assertTrue(test_mutation_case("missing_threat"))

    def test_reject_missing_control(self):
        self.assertTrue(test_mutation_case("missing_control"))

    def test_reject_missing_test(self):
        self.assertTrue(test_mutation_case("missing_test"))

    def test_reject_missing_acceptance_gate(self):
        self.assertTrue(test_mutation_case("missing_acceptance_gate"))

    def test_reject_invalid_phase(self):
        self.assertTrue(test_mutation_case("invalid_phase"))

    def test_reject_missing_owner(self):
        self.assertTrue(test_mutation_case("missing_owner"))

    def test_reject_non_blocking_gate(self):
        self.assertTrue(test_mutation_case("non_blocking_gate"))

    def test_reject_weakened_gate(self):
        self.assertTrue(test_mutation_case("weakened_gate"))

    def test_reject_deleted_trace_entry(self):
        self.assertTrue(test_mutation_case("deleted_trace_entry"))

    def test_reject_invalid_component(self):
        self.assertTrue(test_mutation_case("invalid_component"))

    def test_reject_invalid_key_domain(self):
        self.assertTrue(test_mutation_case("invalid_key_domain"))

    def test_reject_premature_phase_exit(self):
        self.assertTrue(test_mutation_case("premature_phase_exit"))


if __name__ == "__main__":
    unittest.main()
