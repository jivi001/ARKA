import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  ShieldCheck,
  Clock,
  XCircle,
  CheckCircle2,
  AlertCircle,
  Eye,
  SlidersHorizontal,
} from 'lucide-react';
import { FindingTraceItem, ValidationState } from '../../types/findingsTrace';
import { FindingSeverity } from '../../types/findings';
import { ProposalDecision } from '../../types/core';
import { formatTimestamp } from '../../utils/formatting';

export interface FindingsTraceTableProps {
  findings: FindingTraceItem[];
  selectedFindingId?: string | null;
  onSelectFinding: (finding: FindingTraceItem) => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  selectedAgent: string;
  onAgentChange: (agent: string) => void;
  selectedSeverity: string;
  onSeverityChange: (severity: string) => void;
  selectedDecision: string;
  onDecisionChange: (decision: string) => void;
}

type SortField = 'severity' | 'detected_at_unix' | 'risk_score' | 'finding_id';
type SortOrder = 'asc' | 'desc';

const SEVERITY_WEIGHT: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFORMATIONAL: 1,
};

export const FindingsTraceTable: React.FC<FindingsTraceTableProps> = ({
  findings,
  selectedFindingId,
  onSelectFinding,
  searchQuery,
  onSearchChange,
  selectedAgent,
  onAgentChange,
  selectedSeverity,
  onSeverityChange,
  selectedDecision,
  onDecisionChange,
}) => {
  const [sortField, setSortField] = useState<SortField>('detected_at_unix');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 10;

  // Extract unique agents for filter
  const uniqueAgents = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((f) => set.add(f.source_agent));
    return Array.from(set);
  }, [findings]);

  // Filtering
  const filteredFindings = useMemo(() => {
    return findings.filter((item) => {
      // Search query matches ID, title, target, or CVE
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesId = item.finding_id.toLowerCase().includes(q);
        const matchesTitle = item.title.toLowerCase().includes(q);
        const matchesTarget = item.target.toLowerCase().includes(q);
        const matchesCve = item.cve_id ? item.cve_id.toLowerCase().includes(q) : false;
        if (!matchesId && !matchesTitle && !matchesTarget && !matchesCve) {
          return false;
        }
      }

      // Filter by agent
      if (selectedAgent && selectedAgent !== 'ALL' && item.source_agent !== selectedAgent) {
        return false;
      }

      // Filter by severity
      if (selectedSeverity && selectedSeverity !== 'ALL' && item.severity !== selectedSeverity) {
        return false;
      }

      // Filter by decision
      if (selectedDecision && selectedDecision !== 'ALL') {
        if (item.policy_decision !== selectedDecision) {
          return false;
        }
      }

      return true;
    });
  }, [findings, searchQuery, selectedAgent, selectedSeverity, selectedDecision]);

  // Sorting
  const sortedFindings = useMemo(() => {
    return [...filteredFindings].sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'severity':
          comparison = SEVERITY_WEIGHT[a.severity] - SEVERITY_WEIGHT[b.severity];
          break;
        case 'risk_score':
          comparison = a.risk_score - b.risk_score;
          break;
        case 'finding_id':
          comparison = a.finding_id.localeCompare(b.finding_id);
          break;
        case 'detected_at_unix':
        default:
          comparison = a.detected_at_unix - b.detected_at_unix;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });
  }, [filteredFindings, sortField, sortOrder]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(sortedFindings.length / pageSize));
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sortedFindings.slice(start, start + pageSize);
  }, [sortedFindings, currentPage]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const renderSeverityBadge = (sev: FindingSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              padding: '2px 7px',
              borderRadius: 'var(--radius-xs)',
              backgroundColor: 'var(--status-coral-dim)',
              color: 'var(--status-coral)',
              border: '1px solid var(--status-coral-border)',
            }}
          >
            <ShieldAlert size={10} />
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              padding: '2px 7px',
              borderRadius: 'var(--radius-xs)',
              backgroundColor: 'var(--status-amber-dim)',
              color: 'var(--status-amber)',
              border: '1px solid var(--status-amber-border)',
            }}
          >
            <AlertCircle size={10} />
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              fontWeight: 600,
              padding: '2px 7px',
              borderRadius: 'var(--radius-xs)',
              backgroundColor: 'var(--accent-primary-dim)',
              color: 'var(--accent-primary)',
              border: '1px solid var(--border-highlight)',
            }}
          >
            MEDIUM
          </span>
        );
      case 'LOW':
      case 'INFORMATIONAL':
      default:
        return (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              fontWeight: 600,
              padding: '2px 7px',
              borderRadius: 'var(--radius-xs)',
              backgroundColor: 'var(--bg-well)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {sev}
          </span>
        );
    }
  };

  const renderDecisionBadge = (decision: ProposalDecision) => {
    switch (decision) {
      case 'DENY':
        return (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 3,
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              padding: '2px 7px',
              borderRadius: 'var(--radius-xs)',
              backgroundColor: 'var(--status-coral-dim)',
              color: 'var(--status-coral)',
              border: '1px solid var(--status-coral-border)',
            }}
          >
            <XCircle size={10} />
            DENIED
          </span>
        );
      case 'ALLOW':
        return (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 3,
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              padding: '2px 7px',
              borderRadius: 'var(--radius-xs)',
              backgroundColor: 'var(--status-emerald-dim)',
              color: 'var(--status-emerald)',
              border: '1px solid var(--status-emerald-border)',
            }}
          >
            <CheckCircle2 size={10} />
            ALLOWED
          </span>
        );
      case 'REQUIRE_APPROVAL':
        return (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 3,
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              padding: '2px 7px',
              borderRadius: 'var(--radius-xs)',
              backgroundColor: 'var(--status-amber-dim)',
              color: 'var(--status-amber)',
              border: '1px solid var(--status-amber-border)',
            }}
          >
            <Clock size={10} />
            PENDING APPROVAL
          </span>
        );
      default:
        return (
          <span
            style={{
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              padding: '2px 6px',
              borderRadius: 'var(--radius-xs)',
              backgroundColor: 'var(--bg-well)',
              color: 'var(--text-muted)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {decision}
          </span>
        );
    }
  };

  const renderValidationBadge = (state: ValidationState) => {
    switch (state) {
      case 'VALIDATED':
        return (
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 3,
              fontSize: 10,
              fontWeight: 600,
              color: 'var(--status-emerald)',
            }}
          >
            <CheckCircle2 size={11} />
            Validated
          </span>
        );
      case 'PENDING':
        return (
          <span style={{ fontSize: 10, color: 'var(--status-amber)' }}>
            Pending
          </span>
        );
      default:
        return (
          <span style={{ fontSize: 10, color: 'var(--status-coral)' }}>
            {state}
          </span>
        );
    }
  };

  return (
    <div
      className="panel"
      style={{
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: 'var(--bg-surface-base)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-card)',
        boxShadow: 'var(--shadow-subtle)',
        overflow: 'hidden',
      }}
    >
      {/* Table Toolbar & Multi-Filters */}
      <div
        style={{
          padding: '12px 16px',
          borderBottom: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-surface-low)',
          display: 'flex',
          flexDirection: 'column',
          gap: 10,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
          <div>
            <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
              Agent Findings
            </h3>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              All findings with independent validation state and deterministic Security Kernel policy decisions.
            </div>
          </div>

          <div
            style={{
              fontSize: 11,
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-muted)',
              backgroundColor: 'var(--bg-well)',
              padding: '3px 8px',
              borderRadius: 'var(--radius-xs)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {sortedFindings.length} FINDINGS
          </div>
        </div>

        {/* Filter controls row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {/* Search Input */}
          <div
            style={{
              position: 'relative',
              flex: '1 1 200px',
              minWidth: 180,
            }}
          >
            <Search
              size={14}
              style={{
                position: 'absolute',
                left: 9,
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--text-muted)',
              }}
            />
            <input
              type="text"
              placeholder="Search by ID, title, target, CVE..."
              value={searchQuery}
              onChange={(e) => {
                onSearchChange(e.target.value);
                setCurrentPage(1);
              }}
              style={{
                width: '100%',
                padding: '5px 10px 5px 28px',
                fontSize: 12,
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-subtle)',
                backgroundColor: 'var(--bg-surface-base)',
                color: 'var(--text-primary)',
              }}
              aria-label="Search findings"
            />
          </div>

          {/* Agent Filter */}
          <select
            value={selectedAgent}
            onChange={(e) => {
              onAgentChange(e.target.value);
              setCurrentPage(1);
            }}
            style={{
              padding: '5px 8px',
              fontSize: 11,
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-subtle)',
              backgroundColor: 'var(--bg-surface-base)',
              color: 'var(--text-primary)',
            }}
            aria-label="Filter by agent"
          >
            <option value="ALL">All Agents</option>
            {uniqueAgents.map((ag) => (
              <option key={ag} value={ag}>
                {ag}
              </option>
            ))}
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => {
              onSeverityChange(e.target.value);
              setCurrentPage(1);
            }}
            style={{
              padding: '5px 8px',
              fontSize: 11,
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-subtle)',
              backgroundColor: 'var(--bg-surface-base)',
              color: 'var(--text-primary)',
            }}
            aria-label="Filter by severity"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Decision Filter */}
          <select
            value={selectedDecision}
            onChange={(e) => {
              onDecisionChange(e.target.value);
              setCurrentPage(1);
            }}
            style={{
              padding: '5px 8px',
              fontSize: 11,
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-subtle)',
              backgroundColor: 'var(--bg-surface-base)',
              color: 'var(--text-primary)',
            }}
            aria-label="Filter by policy decision"
          >
            <option value="ALL">All Policy Decisions</option>
            <option value="DENY">Denied</option>
            <option value="ALLOW">Allowed</option>
            <option value="REQUIRE_APPROVAL">Requires Approval</option>
          </select>

          {/* Reset Filters if active */}
          {(searchQuery || selectedAgent !== 'ALL' || selectedSeverity !== 'ALL' || selectedDecision !== 'ALL') && (
            <button
              onClick={() => {
                onSearchChange('');
                onAgentChange('ALL');
                onSeverityChange('ALL');
                onDecisionChange('ALL');
                setCurrentPage(1);
              }}
              className="btn-ghost"
              style={{
                fontSize: 11,
                color: 'var(--accent-primary)',
                padding: '4px 8px',
                cursor: 'pointer',
              }}
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Table Container */}
      <div style={{ overflowX: 'auto', flex: 1 }}>
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            textAlign: 'left',
            fontSize: 12,
          }}
          aria-label="Agent Findings Trace Table"
        >
          <thead>
            <tr
              style={{
                backgroundColor: 'var(--bg-surface-low)',
                borderBottom: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
                fontSize: 11,
                fontWeight: 600,
              }}
            >
              <th
                scope="col"
                onClick={() => handleSort('finding_id')}
                style={{ padding: '8px 12px', cursor: 'pointer', whiteSpace: 'nowrap' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span>Finding ID</span>
                  <ArrowUpDown size={11} />
                </div>
              </th>
              <th scope="col" style={{ padding: '8px 12px', minWidth: 200 }}>
                Title & Target
              </th>
              <th
                scope="col"
                onClick={() => handleSort('severity')}
                style={{ padding: '8px 12px', cursor: 'pointer', whiteSpace: 'nowrap' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span>Severity</span>
                  <ArrowUpDown size={11} />
                </div>
              </th>
              <th scope="col" style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                Confidence
              </th>
              <th scope="col" style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                Source Agent
              </th>
              <th scope="col" style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                Validation
              </th>
              <th scope="col" style={{ padding: '8px 12px', whiteSpace: 'nowrap' }}>
                Kernel Decision
              </th>
              <th
                scope="col"
                onClick={() => handleSort('detected_at_unix')}
                style={{ padding: '8px 12px', cursor: 'pointer', whiteSpace: 'nowrap' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span>Detected</span>
                  <ArrowUpDown size={11} />
                </div>
              </th>
              <th scope="col" style={{ padding: '8px 12px', textAlign: 'right' }}>
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {paginatedFindings.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No findings matching current filters.
                </td>
              </tr>
            ) : (
              paginatedFindings.map((item) => {
                const isSelected = selectedFindingId === item.finding_id;

                return (
                  <tr
                    key={item.finding_id}
                    onClick={() => onSelectFinding(item)}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      backgroundColor: isSelected
                        ? 'var(--accent-primary-dim)'
                        : 'transparent',
                      cursor: 'pointer',
                      transition: 'background-color 0.15s ease',
                    }}
                    className={isSelected ? 'table-row-selected' : 'table-row-hover'}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectFinding(item);
                      }
                    }}
                  >
                    {/* Finding ID */}
                    <td style={{ padding: '8px 12px' }} className="tabular-nums">
                      <span
                        style={{
                          fontSize: 11,
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 600,
                          color: isSelected ? 'var(--accent-primary)' : 'var(--text-primary)',
                        }}
                      >
                        {item.finding_id}
                      </span>
                    </td>

                    {/* Title & Target */}
                    <td style={{ padding: '8px 12px' }}>
                      <div
                        style={{
                          fontWeight: 600,
                          color: 'var(--text-primary)',
                          lineHeight: 1.3,
                        }}
                      >
                        {item.title}
                      </div>
                      <div
                        style={{
                          fontSize: 10,
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--text-muted)',
                          marginTop: 2,
                        }}
                      >
                        {item.target}
                        {item.cve_id ? ` · ${item.cve_id}` : ''}
                      </div>
                    </td>

                    {/* Severity */}
                    <td style={{ padding: '8px 12px' }}>
                      {renderSeverityBadge(item.severity)}
                    </td>

                    {/* Confidence */}
                    <td style={{ padding: '8px 12px' }}>
                      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)' }}>
                        {item.confidence_percentage}%
                      </div>
                      <div style={{ fontSize: 9, color: 'var(--text-muted)' }}>
                        {item.confidence.replace('_', ' ')}
                      </div>
                    </td>

                    {/* Source Agent */}
                    <td style={{ padding: '8px 12px' }}>
                      <span
                        style={{
                          fontSize: 11,
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        {item.source_agent}
                      </span>
                    </td>

                    {/* Validation */}
                    <td style={{ padding: '8px 12px' }}>
                      {renderValidationBadge(item.validation_state)}
                    </td>

                    {/* Policy Decision */}
                    <td style={{ padding: '8px 12px' }}>
                      {renderDecisionBadge(item.policy_decision)}
                    </td>

                    {/* Detected */}
                    <td style={{ padding: '8px 12px' }} className="tabular-nums">
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {formatTimestamp(item.detected_at_unix)}
                      </span>
                    </td>

                    {/* Actions */}
                    <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFinding(item);
                        }}
                        className="btn-ghost"
                        style={{
                          padding: '3px 7px',
                          fontSize: 11,
                          borderRadius: 'var(--radius-xs)',
                          border: '1px solid var(--border-subtle)',
                          color: isSelected ? 'var(--accent-primary)' : 'var(--text-secondary)',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          cursor: 'pointer',
                        }}
                        aria-label={`Inspect finding ${item.finding_id}`}
                      >
                        <Eye size={12} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div
        style={{
          padding: '8px 16px',
          borderTop: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-surface-low)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: 11,
          color: 'var(--text-secondary)',
        }}
      >
        <div>
          Showing {paginatedFindings.length > 0 ? (currentPage - 1) * pageSize + 1 : 0}–
          {Math.min(currentPage * pageSize, sortedFindings.length)} of {sortedFindings.length} findings
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <button
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="btn-ghost"
            style={{
              padding: '3px 8px',
              fontSize: 11,
              borderRadius: 'var(--radius-xs)',
              border: '1px solid var(--border-subtle)',
              cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
              opacity: currentPage === 1 ? 0.4 : 1,
              display: 'flex',
              alignItems: 'center',
              gap: 2,
            }}
            aria-label="Previous page"
          >
            <ChevronLeft size={13} />
            Previous
          </button>

          <span className="font-mono" style={{ padding: '0 4px' }}>
            {currentPage} / {totalPages}
          </span>

          <button
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            className="btn-ghost"
            style={{
              padding: '3px 8px',
              fontSize: 11,
              borderRadius: 'var(--radius-xs)',
              border: '1px solid var(--border-subtle)',
              cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
              opacity: currentPage === totalPages ? 0.4 : 1,
              display: 'flex',
              alignItems: 'center',
              gap: 2,
            }}
            aria-label="Next page"
          >
            Next
            <ChevronRight size={13} />
          </button>
        </div>
      </div>
    </div>
  );
};
