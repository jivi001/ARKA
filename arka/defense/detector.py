"""
Prompt Injection and Jailbreak Heuristic Detector.
Implements detection for THREAT-PROMPT-INJECTION (OWASP LLM01, ASI01).
"""

from dataclasses import dataclass, field
import re
from typing import List

INJECTION_PATTERNS = [
    # 1. Direct Instruction Overrides
    (r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+instructions\b", "INSTRUCTION_OVERRIDE_IGNORE"),
    (r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|above|existing)\s+(?:rules|directives|instructions|policies)\b", "INSTRUCTION_OVERRIDE_DISREGARD"),
    (r"(?i)\bforget\s+(?:all\s+|everything\s+)?(?:about\s+)?(?:your\s+(?:mission|instructions|rules|directives)|the\s+rules|safety\s+guidelines)\b", "INSTRUCTION_OVERRIDE_FORGET"),
    (r"(?i)\bSYSTEM\s*(?:[:=]|\bOVERRIDE\b)", "SYSTEM_OVERRIDE_MARKER"),
    (r"(?i)\b(?:new|updated)\s+(?:system\s+)?instructions?\s*[:=]", "NEW_INSTRUCTIONS_DECLARATION"),

    # 2. Persona & Safety Jailbreaks
    (r"(?i)\byou\s+are\s+now\s+(?:DAN|evil|unrestricted|in\s+developer\s+mode|jailbroken|without\s+rules)\b", "PERSONA_JAILBREAK"),
    (r"(?i)\bact\s+as\s+if\s+you\s+have\s+no\s+(?:rules|limits|restrictions|boundaries|ethics)\b", "RULES_BYPASS_ATTEMPT"),
    (r"(?i)\bpretend\s+(?:you\s+are|to\s+be)\s+.*(?:unrestricted|evil|without\s+limits|a\s+rogue\s+agent)\b", "ROLEPLAY_JAILBREAK"),
    (r"(?i)\bdeveloper\s+mode\s+(?:enabled|activated|on)\b", "DEVELOPER_MODE_JAILBREAK"),

    # 3. Context Boundary Smuggling & Delimiter Hijacking
    (r"(?i)\bBEGIN\s+(?:SYSTEM|ADMIN|TRUSTED|ROOT)\s+(?:CONTEXT|PROMPT|OVERRIDE)\b", "CONTEXT_BOUNDARY_SPOOFING"),
    (r"(?i)---\s*END\s+(?:SYSTEM|OPERATOR|TRUSTED)\s+(?:PROMPT|INSTRUCTIONS)\s*---", "BOUNDARY_TERMINATION_SPOOFING"),
    (r"(?i)</(?:system|instructions|policy|observation|untrusted_observation)>", "XML_TAG_HIJACKING"),
    (r"(?i)<\|im_start\|>\s*system", "CHATML_TOKEN_HIJACKING"),
    (r"(?i)\[/?INST\]", "LLAMA_INSTRUCTION_TOKEN_HIJACKING"),

    # 4. Prompt Extraction & Canary Exfiltration Attempts
    (r"(?i)\b(?:print|repeat|output|reveal|dump)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|canary\s+token)\b", "PROMPT_EXTRACTION_ATTEMPT"),
    (r"(?i)\b(?:send|exfiltrate|post|curl|wget)\s+(?:data|canary|token|secrets)\s+to\s+https?://", "EXFILTRATION_TRIGGER"),
]

COMPILED_INJECTION_PATTERNS = [(re.compile(pattern), desc) for pattern, desc in INJECTION_PATTERNS]


@dataclass
class InjectionDetectionResult:
    """Outcome of prompt injection heuristic scanning."""

    detected: bool
    risk_score: float
    matched_patterns: List[str] = field(default_factory=list)
    raw_length: int = 0


class PromptInjectionDetector:
    """
    Scans untrusted content for known prompt injection, jailbreak, and context-escaping signatures.
    """

    @classmethod
    def scan(cls, text: str) -> InjectionDetectionResult:
        if not text or not text.strip():
            return InjectionDetectionResult(detected=False, risk_score=0.0, raw_length=0)

        matched: List[str] = []
        for compiled_re, desc in COMPILED_INJECTION_PATTERNS:
            if compiled_re.search(text):
                matched.append(desc)

        # Risk score calculation: 1 match = 0.5, 2 matches = 0.8, 3+ matches = 1.0
        if not matched:
            risk_score = 0.0
        elif len(matched) == 1:
            risk_score = 0.5
        elif len(matched) == 2:
            risk_score = 0.8
        else:
            risk_score = 1.0

        return InjectionDetectionResult(
            detected=len(matched) > 0,
            risk_score=risk_score,
            matched_patterns=matched,
            raw_length=len(text),
        )
