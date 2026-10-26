import React, { useState } from 'react';
import {
  Bot,
  Database,
  CheckCheck,
  ShieldAlert,
  UserCheck2,
  FileCheck,
  ArrowRight,
  Shield,
  ExternalLink,
  Info,
  ToggleLeft,
  ToggleRight,
} from 'lucide-react';
import { LifecycleStageId } from '../../types/findingsTrace';

export interface FindingLifecycleFlowProps {
  onSelectNode?: (stageId: LifecycleStageId) => void;
  selectedStageId?: LifecycleStageId | null;
  onNavigateToAudit?: () => void;
}

interface FlowNode {
  id: LifecycleStageId;
  label: string;
  sublabel: string;
  icon: React.ElementType;
  role: string;
  authorityLevel: 'UNTRUSTED' | 'ISOLATED' | 'DETERMINISTIC_TRUSTED' | 'HUMAN_AUTHORITY' | 'IMMUTABLE_RECORD';
  badgeColor: string;
  badgeBg: string;
  badgeBorder: string;
}

const FLOW_NODES: FlowNode[] = [
  {
    id: 'discovery',
    label: 'Agent Plane',
    sublabel: 'Discovery & Proposal',
    icon: Bot,
    role: 'Untrusted AI Agent identifies attack surface and submits raw proposal.',
    authorityLevel: 'UNTRUSTED',
    badgeColor: 'var(--text-secondary)',
    badgeBg: 'var(--bg-well)',
    badgeBorder: 'var(--border-subtle)',
  },
  {
    id: 'evidence_collection',
    label: 'Evidence Pipeline',
    sublabel: 'Artifact Ingestion',
    icon: Database,
    role: 'Rootless container captures stdout, sockets, and hashes raw payloads.',
    authorityLevel: 'ISOLATED',
    badgeColor: 'var(--accent-primary)',
    badgeBg: 'var(--accent-primary-dim)',
    badgeBorder: 'var(--border-highlight)',
  },
  {
    id: 'validation',
    label: 'Safe Parsers',
    sublabel: 'Validation Engine',
    icon: CheckCheck,
    role: 'Safe parsers enforce bounds, defuse XML bombs, and reject duplicate keys.',
    authorityLevel: 'ISOLATED',
    badgeColor: 'var(--accent-primary)',
    badgeBg: 'var(--accent-primary-dim)',
    badgeBorder: 'var(--border-highlight)',
  },
  {
    id: 'kernel_policy_check',
    label: 'Security Kernel',
    sublabel: 'Policy Enforcement',
    icon: Shield,
    role: 'Authoritative Rust kernel enforces scope, exclusion rules, and replay nonces.',
    authorityLevel: 'DETERMINISTIC_TRUSTED',
    badgeColor: 'var(--status-emerald)',
    badgeBg: 'var(--status-emerald-dim)',
    badgeBorder: 'var(--status-emerald-border)',
  },
  {
    id: 'human_approval',
    label: 'Two-Person Gate',
    sublabel: 'Human Authorization',
    icon: UserCheck2,
    role: 'High/Critical proposals require human signature bound to action hash.',
    authorityLevel: 'HUMAN_AUTHORITY',
    badgeColor: 'var(--status-amber)',
    badgeBg: 'var(--status-amber-dim)',
    badgeBorder: 'var(--status-amber-border)',
  },
  {
    id: 'final_finding',
    label: 'Audit Ledger',
    sublabel: 'Verified Outcome',
    icon: FileCheck,
    role: 'Tamper-evident outcome appended to dual-signed Ed25519 audit chain.',
    authorityLevel: 'IMMUTABLE_RECORD',
    badgeColor: 'var(--status-emerald)',
    badgeBg: 'var(--status-emerald-dim)',
    badgeBorder: 'var(--status-emerald-border)',
  },
];

export const FindingLifecycleFlow: React.FC<FindingLifecycleFlowProps> = ({
  onSelectNode,
  selectedStageId,
  onNavigateToAudit,
}) => {
  const [showDataFlow, setShowDataFlow] = useState<boolean>(true);
  const [activeInspectorNode, setActiveInspectorNode] = useState<FlowNode | null>(null);

  return (
    <section
      aria-label="Finding Lifecycle Flow Process View"
      className="panel"
      style={{
        padding: '16px 18px',
        backgroundColor: 'var(--bg-surface-base)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-card)',
        boxShadow: 'var(--shadow-subtle)',
      }}
    >
      {/* Header controls & data flow toggle */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: 14,
          paddingBottom: 10,
          borderBottom: '1px solid var(--border-subtle)',
          flexWrap: 'wrap',
          gap: 10,
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <h3
              style={{
                fontSize: 13,
                fontWeight: 700,
                letterSpacing: '-0.01em',
                color: 'var(--text-primary)',
              }}
            >
              Finding Lifecycle Flow
            </h3>
            <span
              style={{
                fontSize: 10,
                fontFamily: 'var(--font-mono)',
                color: 'var(--accent-primary)',
                backgroundColor: 'var(--accent-primary-dim)',
                padding: '1px 6px',
                borderRadius: 'var(--radius-xs)',
                fontWeight: 600,
              }}
            >
              OBSERVABILITY PROCESS VIEW
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            Agent → Evidence → Validators → Rust Security Kernel → Approval Gate → Final Record
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {/* Data Flow Toggle */}
          <button
            onClick={() => setShowDataFlow((prev) => !prev)}
            className="btn-ghost"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 11,
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              padding: '4px 8px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-subtle)',
            }}
            title="Toggle data flow pathway indicators"
            aria-pressed={showDataFlow}
          >
            {showDataFlow ? (
              <ToggleRight size={18} style={{ color: 'var(--accent-primary)' }} />
            ) : (
              <ToggleLeft size={18} style={{ color: 'var(--text-muted)' }} />
            )}
            <span>Data Flow Lines</span>
          </button>

          {/* Audit Trail Link */}
          {onNavigateToAudit && (
            <button
              onClick={onNavigateToAudit}
              className="btn-ghost"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 5,
                fontSize: 11,
                color: 'var(--accent-primary)',
                fontWeight: 600,
                cursor: 'pointer',
                padding: '4px 8px',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              <span>View Audit Trail</span>
              <ExternalLink size={12} />
            </button>
          )}
        </div>
      </div>

      {/* Nodes process visualization */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
          gap: 10,
          position: 'relative',
        }}
        className="flow-nodes-container"
      >
        {FLOW_NODES.map((node, index) => {
          const NodeIcon = node.icon;
          const isSelected = selectedStageId === node.id || activeInspectorNode?.id === node.id;
          const isLast = index === FLOW_NODES.length - 1;

          return (
            <div
              key={node.id}
              onClick={() => {
                setActiveInspectorNode(node);
                if (onSelectNode) onSelectNode(node.id);
              }}
              style={{
                position: 'relative',
                padding: '12px 12px',
                backgroundColor: isSelected
                  ? 'var(--accent-primary-dim)'
                  : 'var(--bg-surface-low)',
                border: isSelected
                  ? '1.5px solid var(--accent-primary)'
                  : '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
              role="button"
              tabIndex={0}
              aria-label={`Inspect ${node.label} (${node.authorityLevel})`}
            >
              {/* Header inside node */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div
                  style={{
                    width: 26,
                    height: 26,
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--bg-surface-base)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: node.authorityLevel === 'DETERMINISTIC_TRUSTED'
                      ? 'var(--status-emerald)'
                      : node.authorityLevel === 'HUMAN_AUTHORITY'
                      ? 'var(--status-amber)'
                      : 'var(--accent-primary)',
                  }}
                >
                  <NodeIcon size={14} />
                </div>

                <span
                  style={{
                    fontSize: 8,
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    padding: '1px 5px',
                    borderRadius: 'var(--radius-xs)',
                    color: node.badgeColor,
                    backgroundColor: node.badgeBg,
                    border: `1px solid ${node.badgeBorder}`,
                  }}
                >
                  {node.authorityLevel}
                </span>
              </div>

              {/* Title & subtitle */}
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
                  {node.label}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>
                  {node.sublabel}
                </div>
              </div>

              {/* Arrow connector indicator */}
              {showDataFlow && !isLast && (
                <div
                  style={{
                    position: 'absolute',
                    right: -10,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    zIndex: 2,
                    width: 18,
                    height: 18,
                    borderRadius: '50%',
                    backgroundColor: 'var(--bg-surface-base)',
                    border: '1px solid var(--border-muted)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--accent-primary)',
                  }}
                  aria-hidden="true"
                >
                  <ArrowRight size={10} />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Selected Node Details Bar */}
      {activeInspectorNode && (
        <div
          style={{
            marginTop: 12,
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--bg-well)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'flex-start',
            gap: 10,
          }}
        >
          <Info size={15} style={{ color: 'var(--accent-primary)', marginTop: 2, flexShrink: 0 }} />
          <div style={{ flex: 1, fontSize: 11, lineHeight: 1.45 }}>
            <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
              {activeInspectorNode.label} ({activeInspectorNode.authorityLevel}):
            </span>{' '}
            <span style={{ color: 'var(--text-secondary)' }}>
              {activeInspectorNode.role}
            </span>
          </div>
          <button
            onClick={() => setActiveInspectorNode(null)}
            className="btn-ghost"
            style={{ fontSize: 11, color: 'var(--text-muted)', cursor: 'pointer', padding: 0 }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Explicit Invariant Disclaimer Footer */}
      <div
        style={{
          marginTop: 10,
          padding: '6px 10px',
          borderRadius: 'var(--radius-xs)',
          backgroundColor: 'var(--status-amber-dim)',
          border: '1px solid var(--status-amber-border)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          fontSize: 10,
          fontFamily: 'var(--font-mono)',
          color: 'var(--status-amber)',
        }}
      >
        <ShieldAlert size={13} style={{ flexShrink: 0 }} />
        <span>
          <strong>INVARIANT ENFORCED:</strong> Visual pipeline progression does not imply execution authorization.
          A finding can be verified and finalized while proposed actions remain strictly denied by the Rust Security Kernel.
        </span>
      </div>
    </section>
  );
};
