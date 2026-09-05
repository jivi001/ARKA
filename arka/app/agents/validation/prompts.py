"""Prompt templates and formatters for ARKA Validation Agent.

All prompts enforce strict JSON output adhering to Pydantic schemas.
"""

from __future__ import annotations

import json
from typing import Any

from arka.app.core.assets.models import Finding

VALIDATION_PLAN_SYSTEM_PROMPT = """\
You are ARKA's autonomous Validation Agent.
Your job is to independently verify potential cybersecurity findings and identify false positives.

RULES:
1. You may only propose actions using authorized reconnaissance/scanning tools.
2. You cannot run arbitrary shell commands or code.
3. Every verification action must be minimal, targeted, and safe.
4. Output MUST be valid JSON conforming strictly to the required schema with no commentary.

SCHEMA:
{
  "finding_id": "<string>",
  "reasoning": "<string: why this check proves or disproves the finding>",
  "actions": [
    {
      "tool_name": "<string: nmap, nuclei, ffuf, or whatweb>",
      "target": "<string: target host or URL>",
      "arguments": { "<key>": "<value>" },
      "rationale": "<string>"
    }
  ]
}
"""

VALIDATION_ASSESSMENT_SYSTEM_PROMPT = """\
You are ARKA's autonomous Validation Agent reviewing verification results.
Analyze tool results to determine whether the finding is validated or false positive.

RULES:
1. If the tool indicates vulnerability is absent/patched, status MUST be "false_positive".
2. If confirmed, status MUST be "validated".
3. If inconclusive, status MUST be "suspected".
4. Output MUST be valid JSON conforming strictly to the required schema with no commentary.


SCHEMA:
{
  "finding_id": "<string>",
  "status": "<string: validated | false_positive | suspected>",
  "confidence": <float between 0.0 and 1.0>,
  "reasoning": "<string explaining the conclusion based on evidence>"
}
"""


def format_validation_plan_prompt(finding: Finding, authorized_scope: dict[str, Any]) -> str:
    """Format user prompt for generating a validation plan."""
    return f"""\
EVALUATE CANDIDATE FINDING FOR VERIFICATION:
Finding ID: {finding.finding_id}
Title: {finding.title}
Severity: {finding.severity}
Matched At: {finding.matched_at}
Template ID: {finding.template_id}
CVE ID: {finding.cve_id}
Description: {finding.description}
Extracted Results: {json.dumps(finding.extracted_results)}

Authorized Scope:
{json.dumps(authorized_scope, indent=2, default=str)}

Propose targeted verification actions to confirm this finding or detect a false positive.
"""


def format_validation_assessment_prompt(
    finding: Finding,
    plan: dict[str, Any],
    tool_results: list[dict[str, Any]],
) -> str:
    """Format user prompt for assessing verification results."""
    return f"""\
VERIFICATION RESULTS FOR FINDING:
Finding ID: {finding.finding_id}
Title: {finding.title}
Severity: {finding.severity}
Original Matched At: {finding.matched_at}

Verification Plan:
{json.dumps(plan, indent=2, default=str)}

Tool Execution Results:
{json.dumps(tool_results, indent=2, default=str)}

Analyze these results and return the final validation status.
"""
