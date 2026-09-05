"""Prompts and schemas for ReconAgent LLM Gateway interactions.

Ensures strict JSON output formatting, model-agnostic prompting, and clear separation
between candidate reconnaissance proposals and authoritative execution boundaries.
"""

RECON_SYSTEM_PROMPT = """You are ARKA's Autonomous Reconnaissance Planning Agent (ReconAgent).
Your objective is to plan and prioritize reconnaissance actions strictly within the authorized
engagement scope.

CRITICAL OPERATIONAL INVARIANTS:
1. You have ZERO execution authority. You cannot run bash, shell, Python, Docker, or subprocess
   commands.
2. You only propose candidate actions for registered ARKA security tools (e.g. 'nmap').
3. You must output STRICT valid JSON only. Do not enclose your output in markdown explanations.
4. Any targets you propose must strictly belong to the authorized scope provided.
5. DISCOVERED DOES NOT MEAN AUTHORIZED: If a previous scan observed a new host, IP, or domain,
   it is NOT authorized for scanning unless it independently falls within the authorized scope
   definition.
6. Propose minimal, non-destructive reconnaissance actions tailored to the assessment objectives.
"""

RECON_PLAN_PROMPT_TEMPLATE = """Assessment Context:
Engagement ID: {engagement_id}
Recon Objectives: {objectives}
Authorized Scope: {authorized_scope}

Current State:
Discovered Assets: {assets}
Discovered Services: {services}
Completed Actions: {completed_actions}
Active Hypotheses: {hypotheses}
Recent Errors/Rejections: {errors}

Task:
Generate a structured reconnaissance plan containing candidate actions to achieve the objectives.
If all reconnaissance objectives have been satisfied, or if no further authorized actions
are justified, set stop_condition and return an empty list of candidate actions.

Required JSON Output Schema:
{{
    "objective": "High-level goal for this plan iteration",
    "reasoning_summary": "Summary of tactical reasoning based on current discoveries",
    "candidate_actions": [
        {{
            "tool_name": "nmap",
            "operation": "scan",
            "target": "authorized_target_ip_or_domain",
            "arguments": {{
                "ports": "80,443",
                "service_detection": true,
                "default_scripts": false,
                "timing_template": 2
            }},
            "rationale": "Reason for scanning this target with these parameters"
        }}
    ],
    "stop_condition": null
}}
"""

RECON_ANALYSIS_PROMPT_TEMPLATE = """Assessment Context:
Engagement ID: {engagement_id}
Recon Objectives: {objectives}

Tool Execution Result:
Tool: {tool_name}
Target: {target}
Success: {success}
Error: {error}
Structured Output: {output}
Evidence References: {evidence_refs}

Task:
Analyze the tool execution result. Synthesize key security findings, update hypotheses,
note any newly discovered endpoints or infrastructure, and determine if reconnaissance
objectives are met or if further actions are recommended.

Required JSON Output Schema:
{{
    "summary": "Concise summary of findings from this tool execution",
    "findings": [
        "Open port 80/tcp running nginx 1.24.0",
        "Open port 443/tcp running nginx 1.24.0 with SSL"
    ],
    "hypotheses": [
        "Web server likely hosts HTTP/HTTPS application"
    ],
    "identified_targets": [
        "192.168.1.10"
    ],
    "next_recommended_actions": [],
    "should_stop": false,
    "stop_reason": null
}}
"""
