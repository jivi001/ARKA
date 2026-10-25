"""
Unit and Integration Tests for ARKA Agent-to-Agent (A2A) Protocol (Module H).

Validates:
- CTRL-A2A-AUTH-001: Cryptographic Inter-Agent Mutual Authentication
- TEST-A2A-FORGERY-001: Inter-Agent Identity Forgery and Impersonation Rejection Contract
- GATE-A2A-AUTH-001: Agent-to-Agent Message Verification Gate
- THREAT-FORGED-A2A-MESSAGE: Neutralization of forged inter-agent messages
- Anti-replay protection (60s TTL + Nonce + MessageID)
- Strict mission isolation and zero capability transfer
"""

import time
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519
from arka.a2a import (
    A2aCapabilityForbiddenError,
    A2aExpiredError,
    A2aMessageBus,
    A2aMessageEnvelope,
    A2aMessageType,
    A2aMessenger,
    A2aMissionMismatchError,
    A2aPayloadTooLargeError,
    A2aRecipientMismatchError,
    A2aReplayError,
    A2aSignatureError,
    A2aSigner,
    A2aVerifier,
    Finding,
    TaskDelegation,
    TaskResult,
)
from arka.core.crypto.provider import DevelopmentKeyProvider, KeyDomain


class TestA2aProtocol(unittest.TestCase):
    def setUp(self):
        self.key_provider = DevelopmentKeyProvider()
        # Generate distinct keys for agents
        self.orchestrator_meta, self.orchestrator_privkey = (
            self.key_provider.generate_signing_key(KeyDomain.TOKEN_SIGNING, kid="kid-orch-01")
        )
        self.recon_meta, self.recon_privkey = self.key_provider.generate_signing_key(
            KeyDomain.TOKEN_SIGNING, kid="kid-recon-01"
        )
        self.rogue_meta, self.rogue_privkey = self.key_provider.generate_signing_key(
            KeyDomain.TOKEN_SIGNING, kid="kid-rogue-66"
        )

        self.verifier = A2aVerifier(key_provider=self.key_provider)

    def test_a2a_signature_and_verification_success(self):
        """Valid A2A finding signed by Recon agent is successfully verified."""
        signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        finding = Finding(
            asset="10.0.0.5",
            port=443,
            protocol="https",
            service="nginx",
            confidence=0.95,
            evidence_refs=["ev-001"],
            details={"ssl_cert": "valid"},
        )

        envelope = signer.sign_envelope(
            mission_id="mission-alpha",
            sender_id="agent-recon-01",
            recipient_id="agent-orchestrator-01",
            message_type=A2aMessageType.FINDING,
            payload=finding.to_dict(),
        )

        self.assertEqual(envelope.sender_id, "agent-recon-01")
        self.assertEqual(envelope.kid, "kid-recon-01")
        self.assertTrue(len(envelope.signature) > 0)

        # Verification passes
        res = self.verifier.verify_envelope(
            envelope=envelope,
            expected_mission_id="mission-alpha",
            expected_recipient_id="agent-orchestrator-01",
        )
        self.assertTrue(res.is_valid)
        self.assertEqual(res.envelope.payload["port"], 443)

    def test_a2a_forged_sender_signature_rejected(self):
        """
        TEST-A2A-FORGERY-001:
        A rogue agent attempts to forge a finding from agent-recon-01 using rogue private key.
        Verifier MUST reject the envelope with A2aSignatureError.
        """
        # Rogue agent signs using their own key but sets sender_id = 'agent-recon-01'
        # and specifies recon's kid
        rogue_signer = A2aSigner(private_key=self.rogue_privkey, kid="kid-recon-01")

        forged_envelope = rogue_signer.sign_envelope(
            mission_id="mission-alpha",
            sender_id="agent-recon-01",
            recipient_id="agent-orchestrator-01",
            message_type=A2aMessageType.FINDING,
            payload={"asset": "10.0.0.99", "port": 22},
        )

        # Verifier checks signature against kid-recon-01 from key_provider
        with self.assertRaises(A2aSignatureError):
            self.verifier.verify_envelope(
                envelope=forged_envelope,
                expected_mission_id="mission-alpha",
                expected_recipient_id="agent-orchestrator-01",
            )

    def test_a2a_tampered_payload_rejected(self):
        """Tampering with the payload body invalidates the payload hash and is rejected."""
        signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        envelope = signer.sign_envelope(
            mission_id="mission-alpha",
            sender_id="agent-recon-01",
            recipient_id="agent-orchestrator-01",
            message_type=A2aMessageType.FINDING,
            payload={"asset": "10.0.0.5", "port": 80},
        )

        # Adversary tampers with payload in transit
        envelope.payload["port"] = 8080

        with self.assertRaises(A2aSignatureError):
            self.verifier.verify_envelope(
                envelope=envelope,
                expected_mission_id="mission-alpha",
                expected_recipient_id="agent-orchestrator-01",
            )

    def test_a2a_tampered_metadata_rejected(self):
        """Tampering with envelope metadata invalidates Ed25519 signature."""
        signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        envelope = signer.sign_envelope(
            mission_id="mission-alpha",
            sender_id="agent-recon-01",
            recipient_id="agent-orchestrator-01",
            message_type=A2aMessageType.FINDING,
            payload={"asset": "10.0.0.5"},
        )

        # Adversary attempts to divert recipient
        envelope.recipient_id = "agent-exploit-01"

        with self.assertRaises(A2aSignatureError):
            self.verifier.verify_envelope(
                envelope=envelope,
                expected_mission_id="mission-alpha",
            )

    def test_a2a_replay_attack_rejected(self):
        """Replaying a valid message within the TTL window is detected and rejected."""
        signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        envelope = signer.sign_envelope(
            mission_id="mission-alpha",
            sender_id="agent-recon-01",
            recipient_id="agent-orchestrator-01",
            message_type=A2aMessageType.FINDING,
            payload={"asset": "10.0.0.5"},
        )

        # First verification succeeds
        self.verifier.verify_envelope(envelope)

        # Second verification of identical envelope must fail with A2aReplayError
        with self.assertRaises(A2aReplayError):
            self.verifier.verify_envelope(envelope)

    def test_a2a_expired_message_rejected(self):
        """Messages older than 60s TTL window are rejected."""
        signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        now = time.time()
        past_time = now - 65.0  # 65s in the past

        envelope = signer.sign_envelope(
            mission_id="mission-alpha",
            sender_id="agent-recon-01",
            recipient_id="agent-orchestrator-01",
            message_type=A2aMessageType.FINDING,
            payload={"asset": "10.0.0.5"},
            timestamp=past_time,
        )

        with self.assertRaises(A2aExpiredError) as ctx:
            self.verifier.verify_envelope(envelope, current_time=now)
        self.assertIn("expired", str(ctx.exception))

    def test_a2a_future_timestamp_rejected(self):
        """Messages with future timestamps (> 60s in the future) are rejected."""
        signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        now = time.time()
        future_time = now + 65.0  # 65s in the future

        envelope = signer.sign_envelope(
            mission_id="mission-alpha",
            sender_id="agent-recon-01",
            recipient_id="agent-orchestrator-01",
            message_type=A2aMessageType.FINDING,
            payload={"asset": "10.0.0.5"},
            timestamp=future_time,
        )

        with self.assertRaises(A2aExpiredError) as ctx:
            self.verifier.verify_envelope(envelope, current_time=now)
        self.assertIn("future", str(ctx.exception))

    def test_a2a_cross_mission_isolation_enforced(self):
        """Messages addressed to mission-A are rejected when delivered to mission-B."""
        signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        envelope = signer.sign_envelope(
            mission_id="mission-alpha",
            sender_id="agent-recon-01",
            recipient_id="agent-orchestrator-01",
            message_type=A2aMessageType.FINDING,
            payload={"asset": "10.0.0.5"},
        )

        with self.assertRaises(A2aMissionMismatchError):
            self.verifier.verify_envelope(
                envelope=envelope,
                expected_mission_id="mission-beta",
            )

    def test_a2a_recipient_mismatch_rejected(self):
        """Messages addressed to agent-A are rejected when received by agent-B."""
        signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        envelope = signer.sign_envelope(
            mission_id="mission-alpha",
            sender_id="agent-recon-01",
            recipient_id="agent-orchestrator-01",
            message_type=A2aMessageType.FINDING,
            payload={"asset": "10.0.0.5"},
        )

        with self.assertRaises(A2aRecipientMismatchError):
            self.verifier.verify_envelope(
                envelope=envelope,
                expected_recipient_id="agent-vuln-01",
            )

    def test_a2a_forbidden_capability_token_injection_rejected(self):
        """Agents cannot issue or delegate capability tokens in A2A messages."""
        signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        malicious_payload = {
            "finding": "open port",
            "capability_token": "FORGED-KERNEL-CAPABILITY-TOKEN-XYZ",
        }

        # Signer rejects
        with self.assertRaises(A2aCapabilityForbiddenError):
            signer.sign_envelope(
                mission_id="mission-alpha",
                sender_id="agent-recon-01",
                recipient_id="agent-orchestrator-01",
                message_type=A2aMessageType.FINDING,
                payload=malicious_payload,
            )

    def test_a2a_payload_size_limit_enforced(self):
        """Payloads exceeding 64 KB are rejected."""
        signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        oversized_payload = {"huge_blob": "A" * 70000}

        with self.assertRaises(A2aPayloadTooLargeError):
            signer.sign_envelope(
                mission_id="mission-alpha",
                sender_id="agent-recon-01",
                recipient_id="agent-orchestrator-01",
                message_type=A2aMessageType.FINDING,
                payload=oversized_payload,
            )

    def test_a2a_bus_directed_routing_and_isolation(self):
        """End-to-end task delegation and result return via A2aMessageBus and A2aMessenger."""
        bus = A2aMessageBus(verifier=self.verifier)

        orch_signer = A2aSigner(key_provider=self.key_provider, kid="kid-orch-01")
        recon_signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        orch_messenger = A2aMessenger(
            agent_id="agent-orch-01",
            mission_id="mission-101",
            signer=orch_signer,
            verifier=self.verifier,
            bus=bus,
        )

        recon_messenger = A2aMessenger(
            agent_id="agent-recon-01",
            mission_id="mission-101",
            signer=recon_signer,
            verifier=self.verifier,
            bus=bus,
        )

        # 1. Orchestrator delegates a task to Recon
        task = TaskDelegation(
            task_id="task-42",
            task_name="Map perimeter ports",
            capability="PORT_SCAN",
            target="scanme.nmap.org",
            parameters={"ports": "80,443"},
        )
        orch_messenger.send_task_delegation("agent-recon-01", task)

        # 2. Recon polls inbox and receives the task
        inbound_env = recon_messenger.poll_inbox_sync(timeout=1.0)
        self.assertIsNotNone(inbound_env)
        verified_task = recon_messenger.receive_and_verify(inbound_env)
        self.assertEqual(verified_task["task_id"], "task-42")
        self.assertEqual(verified_task["capability"], "PORT_SCAN")

        # 3. Recon sends TaskResult back to Orchestrator
        result = TaskResult(
            task_id="task-42",
            status="COMPLETED",
            summary="Found port 80 and 443 open.",
            findings=[{"port": 80, "state": "open"}, {"port": 443, "state": "open"}],
            evidence_refs=["ev-042"],
        )
        recon_messenger.send_task_result("agent-orch-01", result)

        # 4. Orchestrator polls inbox and receives the result
        inbound_result_env = orch_messenger.poll_inbox_sync(timeout=1.0)
        self.assertIsNotNone(inbound_result_env)
        verified_result = orch_messenger.receive_and_verify(inbound_result_env)
        self.assertEqual(verified_result["status"], "COMPLETED")
        self.assertEqual(len(verified_result["findings"]), 2)

    def test_a2a_bus_broadcast(self):
        """Broadcast message delivered to all agents on that mission except sender."""
        bus = A2aMessageBus(verifier=self.verifier)

        orch_signer = A2aSigner(key_provider=self.key_provider, kid="kid-orch-01")
        recon_signer = A2aSigner(key_provider=self.key_provider, kid="kid-recon-01")

        orch_messenger = A2aMessenger(
            agent_id="agent-orch-01",
            mission_id="mission-202",
            signer=orch_signer,
            verifier=self.verifier,
            bus=bus,
        )

        recon_messenger = A2aMessenger(
            agent_id="agent-recon-01",
            mission_id="mission-202",
            signer=recon_signer,
            verifier=self.verifier,
            bus=bus,
        )

        # Orchestrator sends broadcast status
        orch_messenger.send_status_update(
            recipient_id="BROADCAST",
            status_payload={"phase": "ACTIVE_RECON"},
        )

        # Recon receives
        recon_msg = recon_messenger.poll_inbox_sync(timeout=1.0)
        self.assertIsNotNone(recon_msg)
        self.assertEqual(recon_msg.payload["phase"], "ACTIVE_RECON")

        # Orchestrator does NOT receive its own broadcast
        orch_msg = orch_messenger.poll_inbox_sync(timeout=0.1)
        self.assertIsNone(orch_msg)


if __name__ == "__main__":
    unittest.main()
