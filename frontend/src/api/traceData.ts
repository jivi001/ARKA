/**
 * ARKA Agent Findings Trace — Verified Sample Dataset.
 *
 * Implements:
 * - 24 findings tracing the 7-stage lifecycle.
 * - Invariant: DISCOVERED != AUTHORIZED.
 * - Authoritative Rust Security Kernel decisions (ALLOW, DENY, REQUIRE_APPROVAL).
 * - Cryptographic evidence artifacts and dual-signed audit verification.
 */

import type { FindingTraceItem, LifecycleStageInfo } from '../types/findingsTrace.ts';

function buildStandardStages(
  discoveredUnix: number,
  policyDecision: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL',
  policyReason: string,
  approvalStatus: 'NOT_REQUIRED' | 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED',
  finalOutcome: 'RECORDED_VALID' | 'RECORDED_DENIED' | 'RECORDED_PENDING'
): LifecycleStageInfo[] {
  const isDenied = policyDecision === 'DENY';
  const isReqApproval = policyDecision === 'REQUIRE_APPROVAL';

  return [
    {
      id: 'discovery',
      stageNumber: 1,
      title: 'Discovery',
      shortDesc: 'Agent identified candidate target and initiated probe',
      status: 'COMPLETED',
      timestamp_unix: discoveredUnix,
      eventRef: `evt_disc_${discoveredUnix}`,
      details: 'Agent observation logged under authenticated Ed25519 session.',
    },
    {
      id: 'evidence_collection',
      stageNumber: 2,
      title: 'Evidence Collection',
      shortDesc: 'Raw network telemetry captured in rootless sandbox',
      status: 'COMPLETED',
      timestamp_unix: discoveredUnix + 12,
      eventRef: `evt_evd_${discoveredUnix + 12}`,
      details: 'Content SHA-256 hashed and isolated from execution plane.',
    },
    {
      id: 'validation',
      stageNumber: 3,
      title: 'Validation',
      shortDesc: 'Evidence structure normalized and verified',
      status: 'COMPLETED',
      timestamp_unix: discoveredUnix + 18,
      eventRef: `evt_val_${discoveredUnix + 18}`,
      details: 'Deduplicated; structural payload integrity verified.',
    },
    {
      id: 'risk_scoring',
      stageNumber: 4,
      title: 'Risk Scoring',
      shortDesc: 'Severity classified and risk model calculated',
      status: 'COMPLETED',
      timestamp_unix: discoveredUnix + 22,
      eventRef: `evt_rsk_${discoveredUnix + 22}`,
      details: 'Confidence derived from deterministic active fingerprinting.',
    },
    {
      id: 'kernel_policy_check',
      stageNumber: 5,
      title: 'Kernel Policy Check',
      shortDesc: isDenied
        ? 'Action denied by Security Kernel'
        : isReqApproval
        ? 'Approval required under Two-Person Integrity'
        : 'Permitted under active scope definition',
      status: isDenied ? 'DENIED' : isReqApproval ? 'PENDING' : 'COMPLETED',
      timestamp_unix: discoveredUnix + 26,
      eventRef: `evt_pol_${discoveredUnix + 26}`,
      details: policyReason,
    },
    {
      id: 'human_approval',
      stageNumber: 6,
      title: 'Human Approval',
      shortDesc:
        approvalStatus === 'APPROVED'
          ? 'Cryptographically sealed by human operator'
          : approvalStatus === 'PENDING'
          ? 'Awaiting operator review and action hash binding'
          : approvalStatus === 'REJECTED'
          ? 'Rejected by security operator'
          : 'Bypassed — action does not exceed risk threshold',
      status:
        approvalStatus === 'APPROVED'
          ? 'COMPLETED'
          : approvalStatus === 'PENDING'
          ? 'ACTIVE'
          : approvalStatus === 'REJECTED'
          ? 'FAILED'
          : 'NOT_REQUIRED',
      timestamp_unix: approvalStatus !== 'NOT_REQUIRED' ? discoveredUnix + 95 : undefined,
      eventRef: approvalStatus !== 'NOT_REQUIRED' ? `evt_app_${discoveredUnix + 95}` : undefined,
      details:
        approvalStatus === 'NOT_REQUIRED'
          ? 'Risk classification is below mandatory operator gate.'
          : 'Bound to normalized proposal action hash.',
    },
    {
      id: 'final_finding',
      stageNumber: 7,
      title: 'Final Finding',
      shortDesc:
        finalOutcome === 'RECORDED_DENIED'
          ? 'Recorded as verified finding (Action Denied)'
          : finalOutcome === 'RECORDED_PENDING'
          ? 'Recorded as pending authorization'
          : 'Recorded and sealed in tamper-evident audit log',
      status:
        finalOutcome === 'RECORDED_DENIED'
          ? 'DENIED'
          : finalOutcome === 'RECORDED_PENDING'
          ? 'PENDING'
          : 'COMPLETED',
      timestamp_unix: discoveredUnix + 110,
      eventRef: `evt_fin_${discoveredUnix + 110}`,
      details:
        'Dual-signed under KeyDomain::AuditSigning and appended to SQLite WAL store.',
    },
  ];
}

export const SAMPLE_FINDING_TRACE_ITEMS: FindingTraceItem[] = [
  // 1. find_01J9Y7QX1A — Exposed Management Port (From brief)
  {
    finding_id: 'find_01J9Y7QX1A',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Exposed Management Port',
    severity: 'CRITICAL',
    risk_score: 9.1,
    risk_score_scale: '9.1 / 10 — Critical',
    scoring_source: 'Active Port Fingerprint + CVSS 3.1 Base Metric',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 95,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: '10.42.18.104:8443',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'Service banner confirms HTTPS management listener on 8443 with TLS 1.3.',
    policy_decision: 'DENY',
    policy_reason:
      'Target matches an explicit exclusion rule: 10.42.18.0/24 (Production Database & HSM Subnet). Exclusions strictly override inclusions under Invariant INV-003.',
    policy_rule_id: 'RULE-EXCL-PROD-DB-01',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774017526,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774017500,
    lifecycle_stages: buildStandardStages(
      1774017500,
      'DENY',
      'Target matches explicit exclusion rule (10.42.18.0/24). Action denied fail-closed.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9A',
        filename: 'port_scan_10.42.18.104.txt',
        size_bytes: 2150,
        content_hash: 'sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
        capability: 'PORT_SCAN',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9Z',
        },
        sanitized_preview:
          '# ARKA Sanitized Raw Port Survey\nHost: 10.42.18.104\nPort: 8443/tcp\nState: OPEN\nService: ssl/https-alt\nRTT: 1.42ms\nBanner: nginx/1.24.0 (Ubuntu)',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9B',
        filename: 'nmap_service_detect.json',
        size_bytes: 4915,
        content_hash: 'sha256:7c9e8f1b2a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d88f1',
        capability: 'SERVICE_ENUMERATION',
        mime_type: 'application/json',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9C',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9Y',
        },
        sanitized_preview:
          '{\n  "service": "https",\n  "product": "Spring Boot Admin Console",\n  "version": "3.1.2",\n  "ostype": "Linux",\n  "cpe": "cpe:/a:pivotal_software:spring_boot:3.1.2"\n}',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9C',
        filename: 'tls_handshake.log',
        size_bytes: 12697,
        content_hash: 'sha256:d41d8cd98f00b204e9800998ecf8427e02cda309a993c72e0883e9b63a4b0282',
        capability: 'TCP_CONNECT',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9X',
        },
        sanitized_preview:
          'TLSv1.3 Handshake ClientHello\nCipherSuite: TLS_AES_256_GCM_SHA384\nServerHello ALPN: h2, http/1.1\nCertificate Subject: CN=admin-internal.vpc-east.internal\nIssuer: Internal Corporate Intermediate CA G3',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9A',
        sequence_number: 1402,
        timestamp_unix: 1774017512,
        event_type: 'EVIDENCE_RECORDED',
        actor_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
        previous_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        current_hash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f11aa',
        signature: 'ed25519:7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456',
        verified: true,
        summary: 'TCP probe evidence recorded under DOMAIN_EVIDENCE content hashing.',
      },
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9B',
        sequence_number: 1403,
        timestamp_unix: 1774017526,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        action_hash: 'sha256:7c9e8f1b2a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d88f1',
        previous_hash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f11aa',
        current_hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        verified: true,
        summary: 'Security Kernel evaluated proposal against ScopeDefinition; decision: DENY.',
      },
    ],
    factual_description:
      'Port 8443 was discovered open with an active HTTPS service presenting an internal certificate. Target matches an explicit CIDR exclusion rule in the active mission scope.',
    remediation_guidance:
      'Verify whether port 8443 should be accessible from the VPC perimeter. Enforce security group restrictions to block unauthorized access to the database subnet.',
  },

  // 2. find_01J9Y7QX1B — Outdated SSH Version (From brief)
  {
    finding_id: 'find_01J9Y7QX1B',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Outdated SSH Version',
    severity: 'HIGH',
    risk_score: 7.8,
    risk_score_scale: '7.8 / 10 — High',
    scoring_source: 'Banner Grabbing + CVE-2023-48795 (Terrapin)',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 92,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: '10.42.18.22:22',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'SSH identification banner indicates OpenSSH 7.4p1 with ChaCha20-Poly1305 support.',
    policy_decision: 'DENY',
    policy_reason:
      'Active mission window is restricted to HTTP/TLS attack surfaces. SSH exploitation validation is forbidden by capability baseline.',
    policy_rule_id: 'RULE-CAP-RESTRICTION-SSH',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774018226,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774018200,
    lifecycle_stages: buildStandardStages(
      1774018200,
      'DENY',
      'SSH protocol capability is denied outside authorized maintenance windows.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9D',
        filename: 'ssh_banner_10.42.18.22.txt',
        size_bytes: 840,
        content_hash: 'sha256:3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829',
        capability: 'SERVICE_ENUMERATION',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9W',
        },
        sanitized_preview:
          'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\nKeyExchange: curve25519-sha256,ecdh-sha2-nistp256\nCiphers: chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9C',
        sequence_number: 1410,
        timestamp_unix: 1774018226,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '2345678901abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:bcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890a',
        verified: true,
        summary: 'Evaluated action against SSH capability rules; decision: DENY.',
      },
    ],
    factual_description:
      'The host is running OpenSSH 7.4p1, which lacks patches for CVE-2023-48795 (Terrapin attack on ChaCha20-Poly1305 / CBC-EtM).',
    remediation_guidance:
      'Upgrade OpenSSH to version 9.6p1 or later. Disable ChaCha20-Poly1305 and EtM algorithms if upgrading cannot be performed immediately.',
    cve_id: 'CVE-2023-48795',
  },

  // 3. find_01J9Y7QX1C — Public S3 Bucket (From brief)
  {
    finding_id: 'find_01J9Y7QX1C',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Public S3 Bucket Exposure',
    severity: 'HIGH',
    risk_score: 8.4,
    risk_score_scale: '8.4 / 10 — High',
    scoring_source: 'AWS OSINT + Public Bucket Head Bucket Query',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 91,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: 's3://corp-backup-prod-us-east-1',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'ListBucket API responded with HTTP 200 containing 1,482 object keys.',
    policy_decision: 'REQUIRE_APPROVAL',
    policy_reason:
      'Inspecting object contents requires controlled validation under Two-Person Integrity to prevent inadvertent data exfiltration.',
    policy_rule_id: 'RULE-TPI-S3-INSPECTION',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774019126,
    human_approval_state: 'PENDING',
    approval_id: 'app_01J9Y78A1B2C3D4E5F6G7H8J9P',
    bound_action_hash: 'sha256:4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123',
    detected_at_unix: 1774019100,
    lifecycle_stages: buildStandardStages(
      1774019100,
      'REQUIRE_APPROVAL',
      'Action carries High Risk class: operator approval required before retrieving S3 object contents.',
      'PENDING',
      'RECORDED_PENDING'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9E',
        filename: 's3_bucket_listing.xml',
        size_bytes: 8420,
        content_hash: 'sha256:4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123',
        capability: 'HTTP_REQUEST',
        mime_type: 'application/xml',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9V',
        },
        sanitized_preview:
          '<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n  <Name>corp-backup-prod-us-east-1</Name>\n  <Prefix></Prefix>\n  <MaxKeys>10</MaxKeys>\n  <IsTruncated>true</IsTruncated>\n  <Contents>\n    <Key>database_dumps/2026-03-15.sql.gz</Key>\n    <Size>482914881</Size>\n  </Contents>\n</ListBucketResult>',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9D',
        sequence_number: 1420,
        timestamp_unix: 1774019126,
        event_type: 'APPROVAL_REQUESTED',
        actor_id: 'kernel_policy_engine',
        action_hash: 'sha256:4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123',
        previous_hash: '2345678901abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '3456789012abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:cdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
        verified: true,
        summary: 'Two-person integrity approval created and queued for human operator.',
      },
    ],
    factual_description:
      'The S3 bucket permits anonymous read access via GetBucketAcl and ListBucket, allowing unauthenticated enumeration of database backup archives.',
    remediation_guidance:
      'Enable S3 Block Public Access at the account and bucket levels. Audit IAM bucket policies to restrict access to authorized VPC endpoints.',
  },

  // 4. find_01J9Y7QX1D — Internal API Endpoint (From brief)
  {
    finding_id: 'find_01J9Y7QX1D',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Internal API Endpoint Exposure',
    severity: 'MEDIUM',
    risk_score: 5.5,
    risk_score_scale: '5.5 / 10 — Medium',
    scoring_source: 'HTTP Crawler + Path Enumeration',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 88,
    source_agent: 'VulnAnalysisAgent-02',
    agent_role: 'Vulnerability Analysis & Service Fingerprinting',
    target: 'api-internal.vpc-east.internal:8080/metrics',
    target_scope_status: 'DISCOVERED_UNAUTHORIZED',
    validation_state: 'VALIDATED',
    validation_summary: 'Prometheus metrics text format containing JVM heap and database connection pool details.',
    policy_decision: 'DENY',
    policy_reason:
      'Endpoint is located on an unauthorized internal interface not registered in the active mission scope inclusions.',
    policy_rule_id: 'RULE-DEFAULT-DENY-UNAUTHORIZED',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774020126,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774020100,
    lifecycle_stages: buildStandardStages(
      1774020100,
      'DENY',
      'Target is not part of authorized scope inclusions (Invariant: DISCOVERED != AUTHORIZED).',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9F',
        filename: 'prometheus_metrics_preview.txt',
        size_bytes: 3120,
        content_hash: 'sha256:5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef01234a',
        capability: 'HTTP_REQUEST',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9C',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9U',
        },
        sanitized_preview:
          '# HELP jvm_memory_used_bytes The amount of used memory\n# TYPE jvm_memory_used_bytes gauge\njvm_memory_used_bytes{area="heap",id="G1 Survivor Space",} 1.048576E7\nhikari_cp_connections_active{pool="MainDataSource"} 14',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9E',
        sequence_number: 1432,
        timestamp_unix: 1774020126,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '3456789012abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '4567890123abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:def1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc',
        verified: true,
        summary: 'Target out of scope; denied under default-deny policy.',
      },
    ],
    factual_description:
      'An internal management metrics endpoint was discovered accessible over HTTP port 8080 without authentication headers.',
    remediation_guidance:
      'Bind actuator and metrics listeners to 127.0.0.1 or configure Spring Security to enforce mutual TLS on management endpoints.',
  },

  // 5. Spring Boot Actuator Deserialization
  {
    finding_id: 'find_01J9Y7QX1E',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Spring Framework Deserialization Vulnerability (CVE-2024-38819)',
    severity: 'CRITICAL',
    risk_score: 9.8,
    risk_score_scale: '9.8 / 10 — Critical',
    scoring_source: 'CVE-2024-38819 + Exploit PoC Validation',
    confidence: 'CONFIRMED_EXPLOIT',
    confidence_percentage: 99,
    source_agent: 'ExploitAgent-01',
    agent_role: 'Controlled PoC Verification',
    target: '10.42.18.104:8443',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'Non-destructive probe verified arbitrary class instantiation vulnerability.',
    policy_decision: 'ALLOW',
    policy_reason:
      'Human operator signed and sealed cryptographic approval (Two-Person Integrity) for non-destructive validation PoC.',
    policy_rule_id: 'RULE-TPI-VERIFIED-POCTEST',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774022026,
    human_approval_state: 'APPROVED',
    approval_id: 'app_01J9Y78A1B2C3D4E5F6G7H8J9Q',
    bound_action_hash: 'sha256:7c9e8f1b2a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d88f1',
    detected_at_unix: 1774021920,
    lifecycle_stages: buildStandardStages(
      1774021920,
      'ALLOW',
      'Operator approved action hash byte-for-byte under Two-Person Integrity.',
      'APPROVED',
      'RECORDED_VALID'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9G',
        filename: 'deserialization_poc_response.json',
        size_bytes: 1840,
        content_hash: 'sha256:6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef01234a5b',
        capability: 'CONTROLLED_EXPLOITATION',
        mime_type: 'application/json',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9D',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9T',
        },
        sanitized_preview:
          '{\n  "status": "VULNERABLE",\n  "leak": "org.springframework.core.serializer.DefaultDeserializer",\n  "execution_safe": true,\n  "side_effects": "ZERO_MUTATION"\n}',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9F',
        sequence_number: 1440,
        timestamp_unix: 1774022026,
        event_type: 'ACTION_AUTHORIZED',
        actor_id: 'kernel_policy_engine',
        action_hash: 'sha256:7c9e8f1b2a3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d88f1',
        previous_hash: '4567890123abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '5678901234abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:ef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd',
        verified: true,
        summary: 'Action authorized following valid human operator cryptographic approval.',
      },
    ],
    factual_description:
      'Confirmed unauthenticated remote code execution via unsafe Java deserialization on Spring Actuator endpoint.',
    remediation_guidance:
      'Upgrade Spring Framework immediately to version 6.1.14+. Apply temporary WAF virtual patch blocking serialized object payloads.',
    cve_id: 'CVE-2024-38819',
  },

  // 6. Redis Unauthenticated
  {
    finding_id: 'find_01J9Y7QX1F',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Unauthenticated Redis Key-Value Store',
    severity: 'HIGH',
    risk_score: 8.2,
    risk_score_scale: '8.2 / 10 — High',
    scoring_source: 'Redis INFO Command Banner Probe',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 94,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: '10.42.18.60:6379',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'Redis responds to INFO command without requiring AUTH password.',
    policy_decision: 'DENY',
    policy_reason: 'Target is in the excluded database subnet. Active queries denied fail-closed.',
    policy_rule_id: 'RULE-EXCL-PROD-DB-01',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774023026,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774023000,
    lifecycle_stages: buildStandardStages(
      1774023000,
      'DENY',
      'Target within excluded subnet (10.42.18.0/24). Action denied by Rust Kernel.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9H',
        filename: 'redis_info_snippet.txt',
        size_bytes: 1450,
        content_hash: 'sha256:7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef01234a5b6c',
        capability: 'SERVICE_ENUMERATION',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9S',
        },
        sanitized_preview:
          '# Server\nredis_version:7.0.12\nos:Linux 5.15.0-88-generic x86_64\ntcp_port:6379\nrole:master\nconnected_clients:3',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9G',
        sequence_number: 1452,
        timestamp_unix: 1774023026,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '5678901234abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '6789012345abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:f1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde',
        verified: true,
        summary: 'Redis probe denied: target matches exclusion rule.',
      },
    ],
    factual_description:
      'Redis instance accepts unauthenticated TCP connections and returns full server information.',
    remediation_guidance:
      'Enable requirepass authentication in redis.conf and bind strictly to 127.0.0.1.',
  },

  // 7. Leaked AWS Key
  {
    finding_id: 'find_01J9Y7QX1G',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Exposed AWS Access Key ID in Client API Response',
    severity: 'CRITICAL',
    risk_score: 9.5,
    risk_score_scale: '9.5 / 10 — Critical',
    scoring_source: 'DLP Regex Filter + Response Body Inspection',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 97,
    source_agent: 'VulnAnalysisAgent-02',
    agent_role: 'Vulnerability Analysis & Service Fingerprinting',
    target: '10.42.18.45:443',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'API debug endpoint returns credentials containing an active AWS IAM key prefix.',
    policy_decision: 'ALLOW',
    policy_reason: 'Passive observation and DLP-masked record creation is authorized under Observation risk class.',
    policy_rule_id: 'RULE-OBSERVATION-ALLOW',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774023826,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774023800,
    lifecycle_stages: buildStandardStages(
      1774023800,
      'ALLOW',
      'Observation capability is permitted without human gate.',
      'NOT_REQUIRED',
      'RECORDED_VALID'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9I',
        filename: 'redacted_api_debug_response.json',
        size_bytes: 1220,
        content_hash: 'sha256:8e9f0123456789abcdef0123456789abcdef0123456789abcdef01234a5b6c7d',
        capability: 'HTTP_REQUEST',
        mime_type: 'application/json',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9C',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9R',
        },
        sanitized_preview:
          '{\n  "app_status": "DEBUG",\n  "aws_access_key": "[REDACTED_API_KEY]",\n  "environment": "production-east"\n}',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9H',
        sequence_number: 1460,
        timestamp_unix: 1774023826,
        event_type: 'EVIDENCE_RECORDED',
        actor_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9C',
        previous_hash: '6789012345abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '7890123456abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        verified: true,
        summary: 'Finding recorded with automated DLP scrubbing applied.',
      },
    ],
    factual_description:
      'HTTP response leaked credentials matching AWS access key ID format. Secret was redacted in-flight by gateway DLP before storage.',
    remediation_guidance:
      'Immediately revoke the exposed AWS credential in IAM. Disable debug endpoints in production build profiles.',
  },

  // 8. TLS 1.0 Weak Ciphers
  {
    finding_id: 'find_01J9Y7QX1H',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Deprecate TLS 1.0 / 1.1 Support',
    severity: 'LOW',
    risk_score: 3.2,
    risk_score_scale: '3.2 / 10 — Low',
    scoring_source: 'TLS Handshake Matrix Probe',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 99,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: '198.51.100.12:443',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'Server accepts ClientHello negotiated under TLSv1.0 protocol version.',
    policy_decision: 'ALLOW',
    policy_reason: 'Read-only TLS inspection allowed on authorized external endpoints.',
    policy_rule_id: 'RULE-PERIMETER-TLS-ALLOW',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774024526,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774024500,
    lifecycle_stages: buildStandardStages(
      1774024500,
      'ALLOW',
      'Passive protocol handshake evaluation authorized.',
      'NOT_REQUIRED',
      'RECORDED_VALID'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9J',
        filename: 'tls10_handshake.txt',
        size_bytes: 620,
        content_hash: 'sha256:9f0123456789abcdef0123456789abcdef0123456789abcdef01234a5b6c7d8e',
        capability: 'TCP_CONNECT',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9Q',
        },
        sanitized_preview:
          'Negotiated Protocol: TLSv1.0\nSelected Cipher: TLS_RSA_WITH_AES_128_CBC_SHA\nStatus: INSECURE_DEPRECATED_PROTOCOL',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9I',
        sequence_number: 1470,
        timestamp_unix: 1774024526,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '7890123456abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '8901234567abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1',
        verified: true,
        summary: 'TLS 1.0 finding authorized and sealed.',
      },
    ],
    factual_description:
      'The server supports TLS 1.0 with CBC cipher suites, susceptible to cryptographic downgrade and BEAST attacks.',
    remediation_guidance:
      'Disable TLS 1.0 and TLS 1.1 in web server configuration. Enforce TLS 1.2 minimum with modern AEAD ciphers.',
  },

  // 9. DNS AXFR Zone Transfer
  {
    finding_id: 'find_01J9Y7QX1I',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Unrestricted DNS Zone Transfer (AXFR)',
    severity: 'MEDIUM',
    risk_score: 6.1,
    risk_score_scale: '6.1 / 10 — Medium',
    scoring_source: 'DNS Query Response Analyzer',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 93,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: 'ns1.vpc-east.internal:53',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'Nameserver answered AXFR query returning 86 zone records.',
    policy_decision: 'DENY',
    policy_reason: 'Internal authoritative nameserver is excluded from autonomous testing scope.',
    policy_rule_id: 'RULE-EXCL-DNS-INTERNAL',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774025126,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774025100,
    lifecycle_stages: buildStandardStages(
      1774025100,
      'DENY',
      'Target nameserver belongs to protected core DNS infrastructure.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9K',
        filename: 'axfr_zone_dump_snippet.txt',
        size_bytes: 1890,
        content_hash: 'sha256:0123456789abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef',
        capability: 'DNS_LOOKUP',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9P',
        },
        sanitized_preview:
          'vpc-east.internal. IN SOA ns1.vpc-east.internal. admin.vpc-east.internal. 2026032001\nvpc-east.internal. IN NS ns1.vpc-east.internal.\nhsm01.vpc-east.internal. IN A 10.42.18.5',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9J',
        sequence_number: 1480,
        timestamp_unix: 1774025126,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '8901234567abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '9012345678abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
        verified: true,
        summary: 'DNS AXFR action rejected by scope policy.',
      },
    ],
    factual_description:
      'DNS server allows unrestricted AXFR zone transfers to unauthenticated clients, exposing complete internal host topology.',
    remediation_guidance:
      'Configure BIND/CoreDNS allow-transfer directive to restrict zone transfers exclusively to secondary nameservers.',
  },

  // 10. Hardcoded API Token in JS
  {
    finding_id: 'find_01J9Y7QX1J',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Hardcoded API Token in Client JavaScript Bundle',
    severity: 'HIGH',
    risk_score: 7.9,
    risk_score_scale: '7.9 / 10 — High',
    scoring_source: 'Static Asset Regex Analysis',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 96,
    source_agent: 'VulnAnalysisAgent-02',
    agent_role: 'Vulnerability Analysis & Service Fingerprinting',
    target: 'app.vpc-east.internal/static/main.js',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'JWT token matching internal analytics service hardcoded in compiled bundle.',
    policy_decision: 'ALLOW',
    policy_reason: 'Static code retrieval and entropy scanning authorized under standard web discovery.',
    policy_rule_id: 'RULE-WEB-DISCOVERY-ALLOW',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774026026,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774026000,
    lifecycle_stages: buildStandardStages(
      1774026000,
      'ALLOW',
      'Web asset inspection approved by Security Kernel.',
      'NOT_REQUIRED',
      'RECORDED_VALID'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9L',
        filename: 'hardcoded_jwt_snippet.js',
        size_bytes: 940,
        content_hash: 'sha256:123456789abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0',
        capability: 'WEB_DISCOVERY',
        mime_type: 'application/javascript',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9C',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9O',
        },
        sanitized_preview:
          'const ANALYTICS_CONFIG = {\n  endpoint: "https://telemetry.internal/collect",\n  apiKey: "[REDACTED_SECRET_JWT]"\n};',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9K',
        sequence_number: 1490,
        timestamp_unix: 1774026026,
        event_type: 'EVIDENCE_RECORDED',
        actor_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9C',
        previous_hash: '9012345678abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '0123456789abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123',
        verified: true,
        summary: 'Hardcoded secret evidence logged and masked.',
      },
    ],
    factual_description:
      'Client JavaScript contains hardcoded authorization header credentials for internal telemetry reporting.',
    remediation_guidance:
      'Rotate the leaked token immediately and remove authentication keys from static frontend assets.',
  },

  // 11. Grafana Unauthenticated
  {
    finding_id: 'find_01J9Y7QX1K',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Grafana Dashboard Anonymous Admin Access',
    severity: 'MEDIUM',
    risk_score: 6.7,
    risk_score_scale: '6.7 / 10 — Medium',
    scoring_source: 'HTTP Response Code & Title Extraction',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 95,
    source_agent: 'VulnAnalysisAgent-02',
    agent_role: 'Vulnerability Analysis & Service Fingerprinting',
    target: '10.42.18.88:3000',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'Grafana responds to /api/dashboards/home with HTTP 200 without session cookie.',
    policy_decision: 'DENY',
    policy_reason: 'Target is in the excluded internal monitoring subnet.',
    policy_rule_id: 'RULE-EXCL-MONITORING-01',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774026826,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774026800,
    lifecycle_stages: buildStandardStages(
      1774026800,
      'DENY',
      'Target matches exclusion rule for monitoring hosts.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9M',
        filename: 'grafana_home_api.json',
        size_bytes: 2210,
        content_hash: 'sha256:23456789abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef01',
        capability: 'HTTP_REQUEST',
        mime_type: 'application/json',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9C',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9N',
        },
        sanitized_preview:
          '{\n  "meta": {"isHome": true, "canEdit": false},\n  "dashboard": {"title": "Main Cluster Health", "panels": 18}\n}',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9L',
        sequence_number: 1500,
        timestamp_unix: 1774026826,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '0123456789abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        signature: 'ed25519:567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234',
        verified: true,
        summary: 'Grafana interaction rejected under monitoring exclusion policy.',
      },
    ],
    factual_description:
      'Grafana allows unauthenticated visitors to view cluster performance dashboards and data sources.',
    remediation_guidance:
      'Set auth.anonymous enabled = false in grafana.ini and require SSO login.',
  },

  // 12. MongoDB Default Credentials
  {
    finding_id: 'find_01J9Y7QX1L',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'MongoDB Accessible Without Authentication',
    severity: 'CRITICAL',
    risk_score: 9.0,
    risk_score_scale: '9.0 / 10 — Critical',
    scoring_source: 'MongoDB Wire Protocol Hello / IsMaster Probe',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 95,
    source_agent: 'ExploitAgent-01',
    agent_role: 'Controlled PoC Verification',
    target: '10.42.18.99:27017',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'MongoDB isMaster command returns cluster topology without requiring auth.',
    policy_decision: 'REQUIRE_APPROVAL',
    policy_reason:
      'Database validation carries Critical risk and potential operational disruption. Two-Person Integrity required.',
    policy_rule_id: 'RULE-TPI-DATABASE-PROBE',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774027526,
    human_approval_state: 'PENDING',
    approval_id: 'app_01J9Y78A1B2C3D4E5F6G7H8J9R',
    bound_action_hash: 'sha256:3456789abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef012',
    detected_at_unix: 1774027500,
    lifecycle_stages: buildStandardStages(
      1774027500,
      'REQUIRE_APPROVAL',
      'Operator gate active: action hash awaiting human approval.',
      'PENDING',
      'RECORDED_PENDING'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9N',
        filename: 'mongodb_ismaster.json',
        size_bytes: 1540,
        content_hash: 'sha256:3456789abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef012',
        capability: 'SERVICE_ENUMERATION',
        mime_type: 'application/json',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9D',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9M',
        },
        sanitized_preview:
          '{\n  "ismaster": true,\n  "maxBsonObjectSize": 16777216,\n  "ok": 1.0,\n  "version": "6.0.8"\n}',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9M',
        sequence_number: 1510,
        timestamp_unix: 1774027526,
        event_type: 'APPROVAL_REQUESTED',
        actor_id: 'kernel_policy_engine',
        action_hash: 'sha256:3456789abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef012',
        previous_hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        current_hash: '234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1',
        signature: 'ed25519:67890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345',
        verified: true,
        summary: 'Database action approval ticket generated and awaiting operator clearance.',
      },
    ],
    factual_description:
      'MongoDB accepts connections without client certificate or password authentication.',
    remediation_guidance:
      'Enable authentication in mongod.conf under security.authorization = enabled.',
  },

  // 13. Prometheus Exporter
  {
    finding_id: 'find_01J9Y7QX1M',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Exposed Node Exporter Telemetry Endpoint',
    severity: 'LOW',
    risk_score: 2.9,
    risk_score_scale: '2.9 / 10 — Low',
    scoring_source: 'Port Scan + HTTP Header Inspection',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 98,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: '10.42.18.15:9100',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'Node Exporter metrics endpoint open on port 9100.',
    policy_decision: 'DENY',
    policy_reason: 'Target is outside the authorized testing envelope.',
    policy_rule_id: 'RULE-DEFAULT-DENY',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774028026,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774028000,
    lifecycle_stages: buildStandardStages(
      1774028000,
      'DENY',
      'Port 9100 denied by scope policy.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9O',
        filename: 'node_exporter_preview.txt',
        size_bytes: 520,
        content_hash: 'sha256:456789abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0123',
        capability: 'HTTP_REQUEST',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9L',
        },
        sanitized_preview: '# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9N',
        sequence_number: 1520,
        timestamp_unix: 1774028026,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1',
        current_hash: '34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
        signature: 'ed25519:7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456',
        verified: true,
        summary: 'Node exporter action denied.',
      },
    ],
    factual_description:
      'Port 9100 exposes hardware metrics to unauthenticated hosts on the VPC network.',
    remediation_guidance:
      'Restrict access to port 9100 via AWS security groups to the Prometheus server IP only.',
  },

  // 14. Kubernetes API Anonymous
  {
    finding_id: 'find_01J9Y7QX1N',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Kubernetes Control Plane Anonymous Authentication Enabled',
    severity: 'CRITICAL',
    risk_score: 9.7,
    risk_score_scale: '9.7 / 10 — Critical',
    scoring_source: 'Kube-apiserver Discovery Response Header',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 98,
    source_agent: 'ExploitAgent-01',
    agent_role: 'Controlled PoC Verification',
    target: '10.42.18.2:6443',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'Kube-apiserver /version returns gitVersion: v1.28.2 under system:anonymous.',
    policy_decision: 'DENY',
    policy_reason: 'Target is the Kubernetes master node; explicitly excluded from intrusive assessment.',
    policy_rule_id: 'RULE-EXCL-CONTROL-PLANE',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774028826,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774028800,
    lifecycle_stages: buildStandardStages(
      1774028800,
      'DENY',
      'Control plane target denied under core exclusion rule.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9P',
        filename: 'kube_version_response.json',
        size_bytes: 980,
        content_hash: 'sha256:56789abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef01234',
        capability: 'HTTP_REQUEST',
        mime_type: 'application/json',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9D',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9K',
        },
        sanitized_preview:
          '{\n  "major": "1",\n  "minor": "28",\n  "gitVersion": "v1.28.2",\n  "platform": "linux/amd64"\n}',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9O',
        sequence_number: 1530,
        timestamp_unix: 1774028826,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12',
        current_hash: '4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123',
        signature: 'ed25519:890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567',
        verified: true,
        summary: 'Control plane action denied fail-closed.',
      },
    ],
    factual_description:
      'Kubernetes API server allows unauthenticated users to access API discovery endpoints.',
    remediation_guidance:
      'Set --anonymous-auth=false on the kube-apiserver manifest and review RBAC bindings for system:unauthenticated.',
  },

  // 15. CORS Wildcard
  {
    finding_id: 'find_01J9Y7QX1O',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Cross-Origin Resource Sharing (CORS) Misconfiguration',
    severity: 'LOW',
    risk_score: 3.8,
    risk_score_scale: '3.8 / 10 — Low',
    scoring_source: 'HTTP Preflight Option Header Probe',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 94,
    source_agent: 'VulnAnalysisAgent-02',
    agent_role: 'Vulnerability Analysis & Service Fingerprinting',
    target: 'api.vpc-east.internal/v1/auth',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'Access-Control-Allow-Origin: * reflected with credentials allowed.',
    policy_decision: 'ALLOW',
    policy_reason: 'HTTP header inspection is permitted within active target scope.',
    policy_rule_id: 'RULE-PERIMETER-HTTP-ALLOW',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774029526,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774029500,
    lifecycle_stages: buildStandardStages(
      1774029500,
      'ALLOW',
      'Permitted passive header inspection.',
      'NOT_REQUIRED',
      'RECORDED_VALID'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9Q',
        filename: 'cors_preflight_response.txt',
        size_bytes: 750,
        content_hash: 'sha256:6789abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef012345',
        capability: 'HTTP_REQUEST',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9C',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9J',
        },
        sanitized_preview:
          'HTTP/1.1 204 No Content\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\nAccess-Control-Allow-Methods: GET, POST, OPTIONS',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9P',
        sequence_number: 1540,
        timestamp_unix: 1774029526,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123',
        current_hash: '567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234',
        signature: 'ed25519:90abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678',
        verified: true,
        summary: 'CORS finding authorized and recorded.',
      },
    ],
    factual_description:
      'The API endpoint responds with Access-Control-Allow-Origin: * while specifying credentials support.',
    remediation_guidance:
      'Explicitly whitelist trusted origins rather than using a wildcard, and never combine wildcard origins with credentials.',
  },

  // 16. Subdomain Takeover
  {
    finding_id: 'find_01J9Y7QX1P',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Subdomain Takeover via Dangling CNAME',
    severity: 'HIGH',
    risk_score: 8.0,
    risk_score_scale: '8.0 / 10 — High',
    scoring_source: 'DNS Resolution + Cloud Provider Service Probe',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 95,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: 'dev-portal.vpc-east.internal',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'CNAME points to an unclaimed Azure Traffic Manager endpoint.',
    policy_decision: 'ALLOW',
    policy_reason: 'DNS lookup is an observation capability permitted by default.',
    policy_rule_id: 'RULE-OBSERVATION-ALLOW',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774030226,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774030200,
    lifecycle_stages: buildStandardStages(
      1774030200,
      'ALLOW',
      'DNS passive query authorized.',
      'NOT_REQUIRED',
      'RECORDED_VALID'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9R',
        filename: 'cname_dangling_lookup.txt',
        size_bytes: 580,
        content_hash: 'sha256:789abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0123456',
        capability: 'DNS_LOOKUP',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9I',
        },
        sanitized_preview:
          'dev-portal.vpc-east.internal. IN CNAME dev-portal-east.trafficmanager.net.\nNXDOMAIN: Host does not exist in target provider.',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9Q',
        sequence_number: 1550,
        timestamp_unix: 1774030226,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234',
        current_hash: '67890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345',
        signature: 'ed25519:0abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789',
        verified: true,
        summary: 'Dangling CNAME finding registered.',
      },
    ],
    factual_description:
      'Subdomain points to an unclaimed cloud resource that can be registered by an external adversary.',
    remediation_guidance:
      'Delete the dangling DNS CNAME record or register the corresponding Azure resource.',
  },

  // 17. Docker Daemon Socket
  {
    finding_id: 'find_01J9Y7QX1Q',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Exposed Docker Engine HTTP API Socket',
    severity: 'CRITICAL',
    risk_score: 9.9,
    risk_score_scale: '9.9 / 10 — Critical',
    scoring_source: 'Docker API /version Endpoint Banner',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 99,
    source_agent: 'ExploitAgent-01',
    agent_role: 'Controlled PoC Verification',
    target: '10.42.18.30:2375',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'Docker API /version returns ApiVersion: 1.43 without client TLS.',
    policy_decision: 'DENY',
    policy_reason: 'Target is on the excluded infrastructure subnet.',
    policy_rule_id: 'RULE-EXCL-PROD-INFRA',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774031026,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774031000,
    lifecycle_stages: buildStandardStages(
      1774031000,
      'DENY',
      'Target excluded: host-level container breakout risk.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9S',
        filename: 'docker_version_response.json',
        size_bytes: 1420,
        content_hash: 'sha256:89abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef01234567',
        capability: 'HTTP_REQUEST',
        mime_type: 'application/json',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9D',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9H',
        },
        sanitized_preview:
          '{\n  "Version": "24.0.5",\n  "ApiVersion": "1.43",\n  "MinAPIVersion": "1.12",\n  "Os": "linux"\n}',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9R',
        sequence_number: 1560,
        timestamp_unix: 1774031026,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '67890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345',
        current_hash: '7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456',
        signature: 'ed25519:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        verified: true,
        summary: 'Docker API interaction denied.',
      },
    ],
    factual_description:
      'Unauthenticated Docker socket listening on TCP port 2375 permits full root execution on the host system.',
    remediation_guidance:
      'Disable TCP listening for dockerd or configure mutual TLS with client certificate verification.',
  },

  // 18. Exposed .git
  {
    finding_id: 'find_01J9Y7QX1R',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Git Repository Metadata Directory Exposure (.git)',
    severity: 'MEDIUM',
    risk_score: 6.5,
    risk_score_scale: '6.5 / 10 — Medium',
    scoring_source: 'Web Crawler + Well-Known Path Survey',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 97,
    source_agent: 'VulnAnalysisAgent-02',
    agent_role: 'Vulnerability Analysis & Service Fingerprinting',
    target: 'staging.vpc-east.internal/.git/config',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'Web server returns HTTP 200 with raw Git configuration file.',
    policy_decision: 'ALLOW',
    policy_reason: 'Passive HTTP retrieval of web content is permitted within target scope.',
    policy_rule_id: 'RULE-PERIMETER-HTTP-ALLOW',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774031826,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774031800,
    lifecycle_stages: buildStandardStages(
      1774031800,
      'ALLOW',
      'Web discovery action authorized by Kernel.',
      'NOT_REQUIRED',
      'RECORDED_VALID'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9T',
        filename: 'git_config_snippet.txt',
        size_bytes: 420,
        content_hash: 'sha256:9abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef012345678',
        capability: 'HTTP_REQUEST',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9C',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9G',
        },
        sanitized_preview:
          '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:corp/staging-portal.git',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9S',
        sequence_number: 1570,
        timestamp_unix: 1774031826,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456',
        current_hash: '890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567',
        signature: 'ed25519:bcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890a',
        verified: true,
        summary: 'Git exposure finding registered.',
      },
    ],
    factual_description:
      'The web server serves files from the .git directory, permitting complete source code reconstruction.',
    remediation_guidance:
      'Configure the web server to deny access to hidden directories starting with a dot (location ~ /\\. { deny all; }).',
  },

  // 19. Vault Dev Mode
  {
    finding_id: 'find_01J9Y7QX1S',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'HashiCorp Vault Running in Development Mode',
    severity: 'CRITICAL',
    risk_score: 9.6,
    risk_score_scale: '9.6 / 10 — Critical',
    scoring_source: 'Vault Sys Health API Response',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 98,
    source_agent: 'ExploitAgent-01',
    agent_role: 'Controlled PoC Verification',
    target: '10.42.18.50:8200',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'Vault /v1/sys/health indicates unsealed status with in-memory storage.',
    policy_decision: 'DENY',
    policy_reason: 'Secrets infrastructure is explicitly excluded from active missions.',
    policy_rule_id: 'RULE-EXCL-KMS-VAULT',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774032626,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774032600,
    lifecycle_stages: buildStandardStages(
      1774032600,
      'DENY',
      'Vault target matches exclusion rule for KMS.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9U',
        filename: 'vault_sys_health.json',
        size_bytes: 840,
        content_hash: 'sha256:abcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0123456789',
        capability: 'HTTP_REQUEST',
        mime_type: 'application/json',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9D',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9F',
        },
        sanitized_preview:
          '{\n  "initialized": true,\n  "sealed": false,\n  "standby": false,\n  "server_time_utc": 1774032600,\n  "version": "1.15.2"\n}',
        trust_level: 'KERNEL_VERIFIED_SIGNATURE',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9T',
        sequence_number: 1580,
        timestamp_unix: 1774032626,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567',
        current_hash: '90abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678',
        signature: 'ed25519:cdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
        verified: true,
        summary: 'Vault action denied under KMS protection policy.',
      },
    ],
    factual_description:
      'Vault server is running in dev mode with known root tokens and unencrypted in-memory storage.',
    remediation_guidance:
      'Deploy production Vault cluster with Auto-Unseal and durable storage backend.',
  },

  // 20. Memcached UDP
  {
    finding_id: 'find_01J9Y7QX1T',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Open Memcached UDP Reflection Vector',
    severity: 'MEDIUM',
    risk_score: 5.8,
    risk_score_scale: '5.8 / 10 — Medium',
    scoring_source: 'UDP Probe Stats Extraction',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 91,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: '10.42.18.70:11211',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'Memcached responds to UDP stats query with 48x amplification ratio.',
    policy_decision: 'DENY',
    policy_reason: 'UDP reflection probing is restricted to prevent network flooding.',
    policy_rule_id: 'RULE-DENY-UDP-FLOOD',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774033226,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774033200,
    lifecycle_stages: buildStandardStages(
      1774033200,
      'DENY',
      'UDP reflection evaluation denied by Security Kernel.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9V',
        filename: 'memcached_stats_preview.txt',
        size_bytes: 410,
        content_hash: 'sha256:bcdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0123456789a',
        capability: 'SERVICE_ENUMERATION',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9E',
        },
        sanitized_preview: 'STAT pid 419\nSTAT uptime 482910\nSTAT version 1.6.14\nSTAT bytes 84920',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9U',
        sequence_number: 1590,
        timestamp_unix: 1774033226,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '90abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678',
        current_hash: '0abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789',
        signature: 'ed25519:def1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc',
        verified: true,
        summary: 'Memcached action denied.',
      },
    ],
    factual_description:
      'Memcached is exposed on UDP port 11211, enabling amplification denial-of-service reflection attacks.',
    remediation_guidance:
      'Disable UDP support with -U 0 flag and bind strictly to localhost.',
  },

  // 21. ElasticSearch Health
  {
    finding_id: 'find_01J9Y7QX1U',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Elasticsearch Cluster Health Endpoint Exposed',
    severity: 'LOW',
    risk_score: 3.4,
    risk_score_scale: '3.4 / 10 — Low',
    scoring_source: 'Elasticsearch REST API Response',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 97,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: '10.42.18.75:9200',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'Elasticsearch /_cluster/health returns status: green without auth.',
    policy_decision: 'ALLOW',
    policy_reason: 'Passive cluster status retrieval authorized within scope inclusions.',
    policy_rule_id: 'RULE-PERIMETER-HTTP-ALLOW',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774034026,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774034000,
    lifecycle_stages: buildStandardStages(
      1774034000,
      'ALLOW',
      'Read-only health check permitted.',
      'NOT_REQUIRED',
      'RECORDED_VALID'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9W',
        filename: 'es_cluster_health.json',
        size_bytes: 480,
        content_hash: 'sha256:cdef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0123456789ab',
        capability: 'HTTP_REQUEST',
        mime_type: 'application/json',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9D',
        },
        sanitized_preview:
          '{\n  "cluster_name": "vpc-east-logs",\n  "status": "green",\n  "number_of_nodes": 3\n}',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9V',
        sequence_number: 1600,
        timestamp_unix: 1774034026,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '0abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789',
        current_hash: '1abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        signature: 'ed25519:ef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd',
        verified: true,
        summary: 'Elasticsearch finding logged.',
      },
    ],
    factual_description:
      'Elasticsearch endpoint discloses cluster names and node topology without authentication headers.',
    remediation_guidance:
      'Enable xpack.security.enabled = true and enforce TLS encryption on HTTP layer.',
  },

  // 22. SNMP Default
  {
    finding_id: 'find_01J9Y7QX1V',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'SNMP Default Community String (public)',
    severity: 'MEDIUM',
    risk_score: 5.9,
    risk_score_scale: '5.9 / 10 — Medium',
    scoring_source: 'SNMPv2c sysDescr Walk Probe',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 96,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: '10.42.18.1:161',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'SNMPv2c responded to community string "public" with Cisco IOS XE banner.',
    policy_decision: 'DENY',
    policy_reason: 'Target is the core perimeter gateway router; excluded from automated testing.',
    policy_rule_id: 'RULE-EXCL-GATEWAY-ROUTER',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774034826,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774034800,
    lifecycle_stages: buildStandardStages(
      1774034800,
      'DENY',
      'Core router target excluded by mission scope.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9X',
        filename: 'snmp_sysdescr.txt',
        size_bytes: 380,
        content_hash: 'sha256:def0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0123456789abc',
        capability: 'SERVICE_ENUMERATION',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9C',
        },
        sanitized_preview:
          'sysDescr.0 = Cisco IOS XE Software, Version 17.09.03a\nsysName.0 = gw01.vpc-east.internal',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9W',
        sequence_number: 1610,
        timestamp_unix: 1774034826,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '1abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        current_hash: '2abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678901',
        signature: 'ed25519:f1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde',
        verified: true,
        summary: 'SNMP probe denied under core router exclusion rule.',
      },
    ],
    factual_description:
      'Perimeter gateway answers SNMP queries with standard community string "public", leaking interface maps.',
    remediation_guidance:
      'Disable SNMPv1/v2c and upgrade to SNMPv3 with authPriv encryption.',
  },

  // 23. Apache Path Traversal
  {
    finding_id: 'find_01J9Y7QX1W',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Apache HTTP Server Path Traversal (CVE-2021-41773)',
    severity: 'HIGH',
    risk_score: 8.6,
    risk_score_scale: '8.6 / 10 — High',
    scoring_source: 'CVE-2021-41773 Path Pattern Matcher',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 95,
    source_agent: 'ExploitAgent-01',
    agent_role: 'Controlled PoC Verification',
    target: '10.42.18.40:80',
    target_scope_status: 'IN_SCOPE',
    validation_state: 'VALIDATED',
    validation_summary: 'Apache 2.4.49 responds with HTTP 200 on /icons/%2e%2e/ access.',
    policy_decision: 'REQUIRE_APPROVAL',
    policy_reason:
      'Path traversal PoC requires human verification under Two-Person Integrity to prevent unintended host reads.',
    policy_rule_id: 'RULE-TPI-PATH-TRAVERSAL',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774035626,
    human_approval_state: 'PENDING',
    approval_id: 'app_01J9Y78A1B2C3D4E5F6G7H8J9S',
    bound_action_hash: 'sha256:ef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0123456789abcd',
    detected_at_unix: 1774035600,
    lifecycle_stages: buildStandardStages(
      1774035600,
      'REQUIRE_APPROVAL',
      'Action hash awaiting human operator clearance.',
      'PENDING',
      'RECORDED_PENDING'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9Y',
        filename: 'apache_traversal_test.txt',
        size_bytes: 610,
        content_hash: 'sha256:ef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0123456789abcd',
        capability: 'HTTP_REQUEST',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9D',
          sandbox: 'arka-sbx-gvisor-l2-02',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9B',
        },
        sanitized_preview:
          'GET /icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/issue HTTP/1.1\nHTTP/1.1 200 OK\nServer: Apache/2.4.49 (Unix)\nUbuntu 20.04.2 LTS \\n \\l',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9X',
        sequence_number: 1620,
        timestamp_unix: 1774035626,
        event_type: 'APPROVAL_REQUESTED',
        actor_id: 'kernel_policy_engine',
        action_hash: 'sha256:ef0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0123456789abcd',
        previous_hash: '2abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678901',
        current_hash: '3abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789012',
        signature: 'ed25519:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        verified: true,
        summary: 'Approval requested for path traversal validation.',
      },
    ],
    factual_description:
      'Apache 2.4.49 path normalization flaw permits directory traversal to files outside the document root.',
    remediation_guidance:
      'Update Apache HTTP Server to version 2.4.51 or higher immediately.',
    cve_id: 'CVE-2021-41773',
  },

  // 24. NTP Monlist
  {
    finding_id: 'find_01J9Y7QX1X',
    mission_id: 'mis_01J9Y70X9Y8Z7W6V5U4T3S2R1Q',
    title: 'Open NTP Monlist Amplification DDoS Vector',
    severity: 'LOW',
    risk_score: 2.5,
    risk_score_scale: '2.5 / 10 — Low',
    scoring_source: 'NTP Monlist Mode 7 Request Analyzer',
    confidence: 'OBSERVED_ANOMALY',
    confidence_percentage: 95,
    source_agent: 'ReconAgent-01',
    agent_role: 'Perimeter Surface Reconnaissance',
    target: '10.42.18.1:123',
    target_scope_status: 'EXCLUDED_TARGET',
    validation_state: 'VALIDATED',
    validation_summary: 'NTP server responded to mode 7 req_code 42 with last 600 clients.',
    policy_decision: 'DENY',
    policy_reason: 'Target is the core network router; excluded from automated assessment.',
    policy_rule_id: 'RULE-EXCL-GATEWAY-ROUTER',
    scope_ref: 'scope-vpc-east-v2.1',
    kernel_version: 'arka-kerneld v0.1.0',
    policy_evaluation_time_unix: 1774036426,
    human_approval_state: 'NOT_REQUIRED',
    detected_at_unix: 1774036400,
    lifecycle_stages: buildStandardStages(
      1774036400,
      'DENY',
      'Target excluded by mission boundary rules.',
      'NOT_REQUIRED',
      'RECORDED_DENIED'
    ),
    evidence_artifacts: [
      {
        id: 'evd_01J9Y75A1B2C3D4E5F6G7H8J9Z',
        filename: 'ntp_monlist_sample.txt',
        size_bytes: 340,
        content_hash: 'sha256:f0123456789abcdef01234a5b6c7d8e9f0123456789abcdef0123456789abcde',
        capability: 'SERVICE_ENUMERATION',
        mime_type: 'text/plain',
        provenance: {
          agent_id: 'agt_01J9Y74A1B2C3D4E5F6G7H8J9B',
          sandbox: 'arka-sbx-net-rootless-01',
          kernel_ticket_receipt: 'tkt_01J9Y78A1B2C3D4E5F6G7H8J9A',
        },
        sanitized_preview:
          'NTP Mode 7 (monlist) response: 42 addresses returned.\nAmplification Factor: 28.5x\nStatus: VULNERABLE',
        trust_level: 'RAW_UNTRUSTED_TARGET_OUTPUT',
      },
    ],
    audit_events: [
      {
        event_id: 'evt_01J9Y77A1B2C3D4E5F6G7H8J9Y',
        sequence_number: 1630,
        timestamp_unix: 1774036426,
        event_type: 'PROPOSAL_EVALUATED',
        actor_id: 'kernel_policy_engine',
        previous_hash: '3abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789012',
        current_hash: '4abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890123',
        signature: 'ed25519:234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1',
        verified: true,
        summary: 'NTP monlist probe denied by policy.',
      },
    ],
    factual_description:
      'NTP service on perimeter router answers monlist requests, exposing internal network time clients.',
    remediation_guidance:
      'Disable monlist queries in ntp.conf with restrict default noquery.',
  },
];
