"""
ARKA Agent-to-Agent Messenger Client.

Provides structured, typed messaging capabilities for agents.
Seamlessly integrates with A2aSigner, A2aVerifier, and A2aMessageBus.
"""

import logging
from typing import Any, Dict, List, Optional

from .bus import A2aMessageBus
from .exceptions import (
    A2aMissionMismatchError,
    A2aRecipientMismatchError,
)
from .models import (
    A2aMessageEnvelope,
    A2aMessageType,
    Finding,
    TaskDelegation,
    TaskResult,
)
from .protocol import A2aSigner, A2aVerifier

logger = logging.getLogger("arka.a2a.messenger")


class A2aMessenger:
    """
    Client interface for an agent to send and receive authenticated A2A messages.
    """

    def __init__(
        self,
        agent_id: str,
        mission_id: str,
        signer: A2aSigner,
        verifier: Optional[A2aVerifier] = None,
        bus: Optional[A2aMessageBus] = None,
    ):
        self.agent_id = agent_id
        self.mission_id = mission_id
        self.signer = signer
        self.verifier = verifier or A2aVerifier()
        self.bus = bus

        if self.bus:
            self.bus.register_agent(mission_id=self.mission_id, agent_id=self.agent_id)

    def send_message(
        self,
        recipient_id: str,
        message_type: A2aMessageType,
        payload: Dict[str, Any],
        parent_task_id: Optional[str] = None,
    ) -> A2aMessageEnvelope:
        """
        Signs and optionally publishes an A2A message envelope.
        """
        envelope = self.signer.sign_envelope(
            mission_id=self.mission_id,
            sender_id=self.agent_id,
            recipient_id=recipient_id,
            message_type=message_type,
            payload=payload,
            parent_task_id=parent_task_id,
        )

        if self.bus:
            self.bus.publish_sync(envelope, verify=False)  # Verifier can verify at consumption

        return envelope

    def send_task_delegation(
        self,
        recipient_id: str,
        task: TaskDelegation,
    ) -> A2aMessageEnvelope:
        """Sends a delegated sub-task to another agent."""
        return self.send_message(
            recipient_id=recipient_id,
            message_type=A2aMessageType.TASK_DELEGATION,
            payload=task.to_dict(),
            parent_task_id=task.task_id,
        )

    def send_task_result(
        self,
        recipient_id: str,
        result: TaskResult,
        parent_task_id: Optional[str] = None,
    ) -> A2aMessageEnvelope:
        """Sends a sub-task execution result back to coordinator."""
        return self.send_message(
            recipient_id=recipient_id,
            message_type=A2aMessageType.TASK_RESULT,
            payload=result.to_dict(),
            parent_task_id=parent_task_id or result.task_id,
        )

    def send_finding(
        self,
        recipient_id: str,
        finding: Finding,
        parent_task_id: Optional[str] = None,
    ) -> A2aMessageEnvelope:
        """Sends an assessment observation or finding to coordinator / reporting agent."""
        return self.send_message(
            recipient_id=recipient_id,
            message_type=A2aMessageType.FINDING,
            payload=finding.to_dict(),
            parent_task_id=parent_task_id,
        )

    def send_status_update(
        self,
        recipient_id: str,
        status_payload: Dict[str, Any],
        parent_task_id: Optional[str] = None,
    ) -> A2aMessageEnvelope:
        """Sends an operational status update."""
        return self.send_message(
            recipient_id=recipient_id,
            message_type=A2aMessageType.STATUS_UPDATE,
            payload=status_payload,
            parent_task_id=parent_task_id,
        )

    def receive_and_verify(self, envelope: A2aMessageEnvelope) -> Dict[str, Any]:
        """
        Verifies incoming envelope authenticity, mission binding, and recipient binding.
        Returns the verified payload dict.
        """
        self.verifier.verify_envelope(
            envelope=envelope,
            expected_mission_id=self.mission_id,
            expected_recipient_id=self.agent_id,
        )
        return envelope.payload

    def poll_inbox_sync(self, timeout: Optional[float] = None) -> Optional[A2aMessageEnvelope]:
        """Synchronously polls for the next message from the bus."""
        if not self.bus:
            return None
        return self.bus.receive_sync(
            mission_id=self.mission_id,
            agent_id=self.agent_id,
            timeout=timeout,
        )

    async def poll_inbox(self, timeout: Optional[float] = None) -> Optional[A2aMessageEnvelope]:
        """Asynchronously polls for the next message from the bus."""
        if not self.bus:
            return None
        return await self.bus.receive(
            mission_id=self.mission_id,
            agent_id=self.agent_id,
            timeout=timeout,
        )
