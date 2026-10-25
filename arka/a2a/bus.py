"""
ARKA Inter-Agent Message Bus (A2A Bus).

Provides mediated in-memory message routing between agents in an active mission.
Enforces mission boundaries, agent registration, and pre-delivery verification.
"""

import asyncio
from collections import defaultdict
import logging
import queue
import threading
from typing import Callable, Dict, List, Optional, Set

from .exceptions import (
    A2aMissionMismatchError,
    A2aRecipientMismatchError,
)
from .models import A2aMessageEnvelope
from .protocol import A2aVerifier

logger = logging.getLogger("arka.a2a.bus")


class A2aMessageBus:
    """
    Message routing fabric for multi-agent missions.
    
    Invariants enforced:
    - Messages cannot cross mission boundaries.
    - Senders cannot forge recipient identities.
    - Verification occurs prior to mailbox enqueuing.
    """

    def __init__(self, verifier: Optional[A2aVerifier] = None):
        self._verifier = verifier or A2aVerifier()
        self._lock = threading.Lock()
        # mission_id -> {agent_id -> queue.Queue[A2aMessageEnvelope]}
        self._sync_mailboxes: Dict[str, Dict[str, queue.Queue]] = defaultdict(dict)
        # mission_id -> {agent_id -> asyncio.Queue[A2aMessageEnvelope]}
        self._async_mailboxes: Dict[str, Dict[str, asyncio.Queue]] = defaultdict(dict)

    def register_agent(self, mission_id: str, agent_id: str) -> None:
        """Registers an agent for a mission, creating dedicated sync and async mailboxes."""
        with self._lock:
            if agent_id not in self._sync_mailboxes[mission_id]:
                self._sync_mailboxes[mission_id][agent_id] = queue.Queue()
            if agent_id not in self._async_mailboxes[mission_id]:
                self._async_mailboxes[mission_id][agent_id] = asyncio.Queue()
        logger.debug(f"Registered agent '{agent_id}' for mission '{mission_id}' on A2A bus.")

    def unregister_agent(self, mission_id: str, agent_id: str) -> None:
        """Unregisters an agent, removing its mailboxes."""
        with self._lock:
            if mission_id in self._sync_mailboxes:
                self._sync_mailboxes[mission_id].pop(agent_id, None)
            if mission_id in self._async_mailboxes:
                self._async_mailboxes[mission_id].pop(agent_id, None)
        logger.debug(f"Unregistered agent '{agent_id}' from mission '{mission_id}'.")

    def publish_sync(self, envelope: A2aMessageEnvelope, verify: bool = True) -> int:
        """
        Synchronously delivers an envelope to recipient mailbox(es) after verification.
        Returns the number of recipients the message was delivered to.
        """
        if verify:
            self._verifier.verify_envelope(envelope)

        mission_id = envelope.mission_id
        recipient_id = envelope.recipient_id

        delivered = 0
        with self._lock:
            mission_sync_boxes = self._sync_mailboxes.get(mission_id, {})
            mission_async_boxes = self._async_mailboxes.get(mission_id, {})

            if recipient_id == "BROADCAST":
                # Deliver to all agents in this mission except sender
                for aid, box in mission_sync_boxes.items():
                    if aid != envelope.sender_id:
                        box.put_nowait(envelope)
                        delivered += 1
                for aid, abox in mission_async_boxes.items():
                    if aid != envelope.sender_id:
                        abox.put_nowait(envelope)
            else:
                if recipient_id not in mission_sync_boxes and recipient_id not in mission_async_boxes:
                    raise A2aRecipientMismatchError(
                        f"Recipient agent '{recipient_id}' is not registered in mission '{mission_id}'."
                    )
                if recipient_id in mission_sync_boxes:
                    mission_sync_boxes[recipient_id].put_nowait(envelope)
                    delivered += 1
                if recipient_id in mission_async_boxes:
                    mission_async_boxes[recipient_id].put_nowait(envelope)

        return delivered

    async def publish(self, envelope: A2aMessageEnvelope, verify: bool = True) -> int:
        """
        Asynchronously delivers an envelope to recipient mailbox(es) after verification.
        """
        return self.publish_sync(envelope, verify=verify)

    def receive_sync(
        self,
        mission_id: str,
        agent_id: str,
        timeout: Optional[float] = None,
    ) -> Optional[A2aMessageEnvelope]:
        """Synchronously retrieves the next envelope from the agent's mailbox."""
        with self._lock:
            box = self._sync_mailboxes.get(mission_id, {}).get(agent_id)
        if not box:
            raise A2aRecipientMismatchError(
                f"Agent '{agent_id}' is not registered in mission '{mission_id}'."
            )

        try:
            return box.get(block=True, timeout=timeout)
        except queue.Empty:
            return None

    async def receive(
        self,
        mission_id: str,
        agent_id: str,
        timeout: Optional[float] = None,
    ) -> Optional[A2aMessageEnvelope]:
        """Asynchronously retrieves the next envelope from the agent's mailbox."""
        with self._lock:
            box = self._async_mailboxes.get(mission_id, {}).get(agent_id)
        if not box:
            raise A2aRecipientMismatchError(
                f"Agent '{agent_id}' is not registered in mission '{mission_id}'."
            )

        try:
            if timeout is not None:
                return await asyncio.wait_for(box.get(), timeout=timeout)
            return await box.get()
        except asyncio.TimeoutError:
            return None
