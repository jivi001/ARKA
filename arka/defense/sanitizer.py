"""
Input Sanitizer: ANSI Stripping, Control Code Scrubbing, and Delimiter Neutralization.
Enforces CTRL-TOOL-OUTPUT-SANITIZATION-001 and TEST-TOOL-POISONING-001.
"""

import re
from typing import Dict

# ANSI and Terminal Escape Sequences
ANSI_CSI_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
ANSI_OSC_PATTERN = re.compile(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)")
ANSI_GENERAL_PATTERN = re.compile(r"\x1b[PX^_][^\x1b]*\x1b\\")

# Non-printable control characters (excluding \t \n \r)
CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Unicode Confusables & BiDi Override Characters
UNICODE_CONFUSABLES: Dict[str, str] = {
    "\u200b": "",   # zero-width space
    "\u200c": "",   # zero-width non-joiner
    "\u200d": "",   # zero-width joiner
    "\u2060": "",   # word joiner
    "\ufeff": "",   # byte order mark
    "\u00a0": " ",  # non-breaking space
    "\u202d": "",   # left-to-right override
    "\u202e": "",   # right-to-left override (spoofing defense)
    "\u202a": "",   # left-to-right embedding
    "\u202b": "",   # right-to-left embedding
    "\u202c": "",   # pop directional formatting
}

# Instruction Delimiters that could hijack LLM context boundaries
DELIMITER_REPLACEMENTS: Dict[str, str] = {
    "</untrusted_observation>": "&lt;/untrusted_observation&gt;",
    "<untrusted_observation>": "&lt;untrusted_observation&gt;",
    "</observation>": "&lt;/observation&gt;",
    "<observation>": "&lt;observation&gt;",
    "</system>": "&lt;/system&gt;",
    "<system>": "&lt;system&gt;",
    "<|im_start|>": "&lt;|im_start|&gt;",
    "<|im_end|>": "&lt;|im_end|&gt;",
    "```system": "```escaped_system",
    "[INST]": "[ESCAPED_INST]",
    "[/INST]": "[/ESCAPED_INST]",
}


class InputSanitizer:
    """
    Sanitizes raw text originating from external targets, tools, or untrusted inputs.
    """

    @classmethod
    def sanitize(cls, text: str, max_length: int = 32_768) -> str:
        """
        Executes the full sanitization pipeline:
        1. Length truncation
        2. ANSI escape sequence stripping
        3. Control character scrubbing
        4. Unicode confusable normalization
        5. Delimiter sequence neutralization
        6. Excessive whitespace collapsing
        """
        if not text:
            return ""

        # 1. Length Truncation
        truncated = False
        if len(text) > max_length:
            text = text[:max_length]
            truncated = True

        # 2. ANSI Escape Sequence Stripping (CTRL-TOOL-OUTPUT-SANITIZATION-001)
        text = ANSI_CSI_PATTERN.sub("", text)
        text = ANSI_OSC_PATTERN.sub("", text)
        text = ANSI_GENERAL_PATTERN.sub("", text)

        # 3. Control Character Scrubbing (Null bytes, Bell, Backspace, etc.)
        text = CONTROL_CHARS_PATTERN.sub("", text)

        # 4. Unicode Confusable Normalization
        for char, replacement in UNICODE_CONFUSABLES.items():
            text = text.replace(char, replacement)

        # 5. Delimiter Neutralization (Prevents context escaping)
        for delim, safe in DELIMITER_REPLACEMENTS.items():
            # Case-insensitive replacement
            text = re.sub(re.escape(delim), safe, text, flags=re.IGNORECASE)

        # 6. Excessive Whitespace Collapsing
        text = re.sub(r"\n{4,}", "\n\n\n", text)
        text = re.sub(r"[ \t]{20,}", "    ", text)

        clean = text.strip()
        if truncated:
            clean += "\n[TRUNCATED: EXCESS INPUT BOUNDED BY ARKA SECURITY POLICY]"

        return clean
