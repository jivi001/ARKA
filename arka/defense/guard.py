"""
Integrated Content Guard Facade for Prompt Injection Defense.
Implements Module F Contract: ContentGuard.
"""

from typing import Optional, Tuple

from .canary import CanaryLeakageError, CanaryTokenManager
from .detector import InjectionDetectionResult, PromptInjectionDetector
from .quarantine import QuarantinedObservation, UntrustedQuarantine
from .sanitizer import InputSanitizer


class ContentGuard:
    """
    Authoritative defense facade providing sanitization, quarantine isolation,
    injection scanning, and canary verification.
    """

    @classmethod
    def sanitize(cls, text: str, max_length: int = 32_768) -> str:
        """Strips ANSI sequences, control characters, and neutralizes injection delimiters."""
        return InputSanitizer.sanitize(text, max_length=max_length)

    @classmethod
    def quarantine(
        cls,
        text: str,
        source_label: str = "TARGET_OBSERVATION",
        max_length: int = 32_768,
    ) -> QuarantinedObservation:
        """Sanitizes and wraps untrusted data inside a secure, cryptographically hashed observation envelope."""
        return UntrustedQuarantine.isolate(text, source_label=source_label, max_length=max_length)

    @classmethod
    def scan_injection(cls, text: str) -> InjectionDetectionResult:
        """Scans input for prompt injection and jailbreak patterns."""
        return PromptInjectionDetector.scan(text)

    @classmethod
    def protect_prompt(cls, system_prompt: str, canary: Optional[str] = None) -> Tuple[str, str]:
        """Injects an ephemeral canary honey-token into the system prompt."""
        return CanaryTokenManager.inject_canary(system_prompt, canary=canary)

    @classmethod
    def verify_output(cls, output_text: str, canary: str) -> None:
        """Verifies that model output does not leak the prompt's canary token."""
        CanaryTokenManager.verify_no_leakage(output_text, canary)
