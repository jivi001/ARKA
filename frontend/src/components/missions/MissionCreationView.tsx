import React, { useState } from 'react';
import { Mission, StandardCapability, RiskClass } from '../../types/core';
import { AlertBanner } from '../common/AlertBanner';
import { isValidIpv4Cidr, isValidHostname, isValidPort, isTargetExcluded } from '../../utils/validation';
import { Check, AlertTriangle, Shield, CheckCircle2, ArrowRight, ArrowLeft } from 'lucide-react';

export interface MissionCreationViewProps {
  operatorId: string;
  onMissionCreated: (newMission: Mission) => void;
  onCancel: () => void;
}

export const MissionCreationView: React.FC<MissionCreationViewProps> = ({
  operatorId,
  onMissionCreated,
  onCancel,
}) => {
  // 5 Steps: 1. Metadata, 2. Authorized Scope, 3. Exclusions, 4. Capabilities & Governance, 5. Review & Seal
  const [step, setStep] = useState<number>(1);

  // Step 1: Metadata
  const [missionName, setMissionName] = useState('');
  const [description, setDescription] = useState('');
  const [mode, setMode] = useState<'AUTHORIZED_PROFESSIONAL' | 'LAB_CTF'>('AUTHORIZED_PROFESSIONAL');

  // Step 2: Scope Inclusions
  const [cidrInput, setCidrInput] = useState('');
  const [cidrList, setCidrList] = useState<string[]>(['10.42.18.0/24']);
  const [hostInput, setHostInput] = useState('');
  const [hostList, setHostList] = useState<string[]>(['*.prod-api.arka.internal', 'auth.arka-sec.cloud']);
  const [portInput, setPortInput] = useState('80, 443, 8443');

  // Step 3: Scope Exclusions
  const [excludedCidrInput, setExcludedCidrInput] = useState('');
  const [excludedCidrs, setExcludedCidrs] = useState<string[]>(['10.42.18.1/32', '10.42.18.254/32']);
  const [excludedHostInput, setExcludedHostInput] = useState('');
  const [excludedHosts, setExcludedHosts] = useState<string[]>(['k8s-master-01.internal']);
  const [excludedPortInput, setExcludedPortInput] = useState('22, 10250');
  const [exclusionRationale, setExclusionRationale] = useState('Strict isolation of default gateway, HSM enclave, and SSH management ports.');

  // Step 4: Capabilities & Governance
  const [selectedCapabilities, setSelectedCapabilities] = useState<StandardCapability[]>([
    'DNS_LOOKUP',
    'TCP_CONNECT',
    'HTTP_REQUEST',
    'PORT_SCAN',
    'SERVICE_ENUMERATION',
  ]);
  const [maxRiskClass, setMaxRiskClass] = useState<RiskClass>('MODERATE');
  const [llmBudgetUsd, setLlmBudgetUsd] = useState<number>(150);
  const [toolTimeoutSec, setToolTimeoutSec] = useState<number>(30);
  const [maxConcurrency, setMaxConcurrency] = useState<number>(8);

  // Dry-run simulator
  const [simQuery, setSimQuery] = useState('');
  const [simResult, setSimResult] = useState<{ evaluated: boolean; inScope: boolean; reason?: string } | null>(null);

  // Errors
  const [errors, setErrors] = useState<Record<string, string>>({});

  // Helper additions
  const handleAddCidr = () => {
    if (!cidrInput.trim()) return;
    if (!isValidIpv4Cidr(cidrInput.trim())) {
      setErrors((prev) => ({ ...prev, cidr: 'Invalid CIDR format (expected e.g. 192.168.1.0/24)' }));
      return;
    }
    setCidrList([...cidrList, cidrInput.trim()]);
    setCidrInput('');
    setErrors((prev) => ({ ...prev, cidr: '' }));
  };

  const handleAddHost = () => {
    if (!hostInput.trim()) return;
    if (!isValidHostname(hostInput.trim())) {
      setErrors((prev) => ({ ...prev, host: 'Invalid hostname format (e.g. target.internal or *.domain.com)' }));
      return;
    }
    setHostList([...hostList, hostInput.trim()]);
    setHostInput('');
    setErrors((prev) => ({ ...prev, host: '' }));
  };

  const handleAddExcludedCidr = () => {
    if (!excludedCidrInput.trim()) return;
    if (!isValidIpv4Cidr(excludedCidrInput.trim())) {
      setErrors((prev) => ({ ...prev, excCidr: 'Invalid CIDR format' }));
      return;
    }
    setExcludedCidrs([...excludedCidrs, excludedCidrInput.trim()]);
    setExcludedCidrInput('');
  };

  const handleAddExcludedHost = () => {
    if (!excludedHostInput.trim()) return;
    setExcludedHosts([...excludedHosts, excludedHostInput.trim()]);
    setExcludedHostInput('');
  };

  const handleTestSimulator = () => {
    if (!simQuery.trim()) return;
    const testTarget = simQuery.trim();
    // Test against exclusions first (Invariant: Exclusions strictly override inclusions)
    const excCheck = isTargetExcluded(testTarget, {
      cidr_blocks: excludedCidrs,
      hostnames: excludedHosts,
    });

    if (excCheck.excluded) {
      setSimResult({
        evaluated: true,
        inScope: false,
        reason: `DENIED BY EXCLUSION: ${excCheck.reason}`,
      });
      return;
    }

    // Check inclusions
    const inCidr = cidrList.some((cidr) => isValidIpv4Cidr(cidr));
    const inHost = hostList.some((h) => testTarget.includes(h.replace('*.', '')));
    if (inCidr || inHost) {
      setSimResult({
        evaluated: true,
        inScope: true,
        reason: 'VERIFIED IN-SCOPE: Target satisfies authorized CIDR/host rule and has no exclusion match.',
      });
    } else {
      setSimResult({
        evaluated: true,
        inScope: false,
        reason: 'DENIED (DEFAULT-DENY): Target is not in authorized CIDR or Hostname inclusion rules.',
      });
    }
  };

  const handleFinalSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!missionName.trim()) {
      setErrors((prev) => ({ ...prev, name: 'Mission name is required.' }));
      setStep(1);
      return;
    }

    const created: Mission = {
      id: `mis_${Date.now().toString(36)}`,
      name: missionName.trim(),
      state: 'CREATED',
      scope_ref: `scope_${Date.now().toString(36)}`,
      created_at_unix: Math.floor(Date.now() / 1000),
      updated_at_unix: Math.floor(Date.now() / 1000),
      created_by: operatorId,
      mode,
      description: description.trim(),
    };

    onMissionCreated(created);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header & Stepper Indicators */}
      <div className="panel" style={{ padding: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div>
            <h2 style={{ fontSize: 15, fontWeight: 700 }}>Initiate New Assessment Mission</h2>
            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              Deterministic scope configuration. Discovered assets require explicit authorization to become targets.
            </p>
          </div>
          <span className="badge badge-primary">STAGE {step} OF 5</span>
        </div>

        {/* Stepper bar */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 6 }}>
          {[
            { num: 1, label: 'Metadata' },
            { num: 2, label: 'Inclusions' },
            { num: 3, label: 'Exclusions' },
            { num: 4, label: 'Governance' },
            { num: 5, label: 'Review & Seal' },
          ].map((s) => (
            <div
              key={s.num}
              onClick={() => s.num < step && setStep(s.num)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 8px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: step === s.num ? 'var(--bg-surface-high)' : 'var(--bg-surface-base)',
                border: step === s.num ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                cursor: s.num < step ? 'pointer' : 'default',
              }}
            >
              <div
                style={{
                  width: 16,
                  height: 16,
                  borderRadius: '50%',
                  fontSize: 10,
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  backgroundColor: step > s.num ? 'var(--status-emerald)' : step === s.num ? 'var(--accent-primary)' : 'var(--bg-surface-high)',
                  color: step > s.num || step === s.num ? '#ffffff' : 'var(--text-muted)',
                }}
              >
                {step > s.num ? <Check size={10} /> : s.num}
              </div>
              <span style={{ fontSize: 11, fontWeight: step === s.num ? 600 : 400, color: step === s.num ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                {s.label}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Step 1: Metadata */}
      {step === 1 && (
        <div className="panel" style={{ padding: 16 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Step 1: Mission Metadata & Operational Mode</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div className="form-group">
              <label className="form-label" htmlFor="m-name">Mission Name *</label>
              <input
                id="m-name"
                className="form-input"
                type="text"
                value={missionName}
                onChange={(e) => setMissionName(e.target.value)}
                placeholder="e.g. Payment Gateway Security Audit (Q4)"
                required
              />
              {errors.name && <span className="form-error">{errors.name}</span>}
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="m-desc">Description & Objectives</label>
              <textarea
                id="m-desc"
                className="form-textarea"
                rows={3}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Document the purpose, scope boundaries, and compliance references for this mission."
              />
            </div>

            <div className="form-group">
              <label className="form-label">Operational Mode</label>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div
                  onClick={() => setMode('AUTHORIZED_PROFESSIONAL')}
                  style={{
                    padding: 12,
                    borderRadius: 'var(--radius-sm)',
                    border: mode === 'AUTHORIZED_PROFESSIONAL' ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                    backgroundColor: mode === 'AUTHORIZED_PROFESSIONAL' ? 'var(--accent-primary-dim)' : 'var(--bg-surface-base)',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-primary)' }}>
                    Professional Authorized Assessment
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                    Strict corporate boundary enforcement, high-friction approvals, full dual-chain cryptographic audit logging.
                  </div>
                </div>

                <div
                  onClick={() => setMode('LAB_CTF')}
                  style={{
                    padding: 12,
                    borderRadius: 'var(--radius-sm)',
                    border: mode === 'LAB_CTF' ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                    backgroundColor: mode === 'LAB_CTF' ? 'var(--accent-primary-dim)' : 'var(--bg-surface-base)',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-primary)' }}>
                    CTF / Laboratory Environment
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                    Isolated range execution. Air-gapped egress proxy, simulated target flags, rapid validation iterations.
                  </div>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 10 }}>
              <button
                className="btn btn-primary"
                onClick={() => {
                  if (!missionName.trim()) {
                    setErrors({ name: 'Mission name is required.' });
                    return;
                  }
                  setErrors({});
                  setStep(2);
                }}
              >
                Proceed to Scope Inclusions <ArrowRight size={13} />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Step 2: Scope Inclusions */}
      {step === 2 && (
        <div className="panel" style={{ padding: 16 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Step 2: Explicit Scope Inclusions</h3>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 14 }}>
            Only assets explicitly matching an inclusion rule can be authorized for probing.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {/* CIDR Blocks */}
            <div className="form-group">
              <label className="form-label">Authorized Subnets (CIDR)</label>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="text"
                  className="form-input font-mono"
                  placeholder="e.g. 10.42.18.0/24"
                  value={cidrInput}
                  onChange={(e) => setCidrInput(e.target.value)}
                />
                <button type="button" className="btn btn-secondary" onClick={handleAddCidr}>
                  Add Subnet
                </button>
              </div>
              {errors.cidr && <span className="form-error">{errors.cidr}</span>}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                {cidrList.map((cidr, idx) => (
                  <span key={idx} className="badge badge-primary font-mono" style={{ padding: '3px 8px' }}>
                    {cidr}
                    <button
                      type="button"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', marginLeft: 4, color: 'inherit' }}
                      onClick={() => setCidrList(cidrList.filter((_, i) => i !== idx))}
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            </div>

            {/* Hostnames */}
            <div className="form-group">
              <label className="form-label">Authorized Hostnames & Domains</label>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="text"
                  className="form-input font-mono"
                  placeholder="e.g. *.prod-api.arka.internal or api.example.com"
                  value={hostInput}
                  onChange={(e) => setHostInput(e.target.value)}
                />
                <button type="button" className="btn btn-secondary" onClick={handleAddHost}>
                  Add Domain
                </button>
              </div>
              {errors.host && <span className="form-error">{errors.host}</span>}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                {hostList.map((h, idx) => (
                  <span key={idx} className="badge badge-primary font-mono" style={{ padding: '3px 8px' }}>
                    {h}
                    <button
                      type="button"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', marginLeft: 4, color: 'inherit' }}
                      onClick={() => setHostList(hostList.filter((_, i) => i !== idx))}
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            </div>

            {/* Port Allowlist */}
            <div className="form-group">
              <label className="form-label" htmlFor="m-ports">Allowed Destination Ports (Comma-separated)</label>
              <input
                id="m-ports"
                type="text"
                className="form-input font-mono"
                value={portInput}
                onChange={(e) => setPortInput(e.target.value)}
                placeholder="80, 443, 8443"
              />
              <span className="form-hint">Connections to unlisted ports will be denied at the kernel socket policy level.</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
              <button className="btn btn-secondary" onClick={() => setStep(1)}>
                <ArrowLeft size={13} /> Back
              </button>
              <button className="btn btn-primary" onClick={() => setStep(3)}>
                Proceed to Scope Exclusions <ArrowRight size={13} />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Step 3: Scope Exclusions */}
      {step === 3 && (
        <div className="panel" style={{ padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <h3 style={{ fontSize: 13, fontWeight: 600 }}>Step 3: Strict Scope Exclusions</h3>
            <span className="badge badge-danger">EXCLUSIONS STRICTLY OVERRIDE INCLUSIONS</span>
          </div>

          <AlertBanner variant="warning" title="DETERMINISTIC DENY-FIRST RULE">
            Any IP, domain, or port matching an exclusion rule is instantly rejected by the kernel, regardless of any CIDR or wildcard inclusions. Default deny applies to cloud metadata IP 169.254.169.254.
          </AlertBanner>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14, marginTop: 14 }}>
            {/* Excluded Subnets */}
            <div className="form-group">
              <label className="form-label">Hard Excluded Hosts/Subnets</label>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="text"
                  className="form-input font-mono"
                  placeholder="e.g. 10.42.18.1/32 (Gateway) or 10.42.18.254/32 (HSM)"
                  value={excludedCidrInput}
                  onChange={(e) => setExcludedCidrInput(e.target.value)}
                />
                <button type="button" className="btn btn-secondary" onClick={handleAddExcludedCidr}>
                  Add Exclusion
                </button>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                {excludedCidrs.map((c, idx) => (
                  <span key={idx} className="badge badge-danger font-mono" style={{ padding: '3px 8px' }}>
                    {c}
                    <button
                      type="button"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', marginLeft: 4, color: 'inherit' }}
                      onClick={() => setExcludedCidrs(excludedCidrs.filter((_, i) => i !== idx))}
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            </div>

            {/* Excluded Domains */}
            <div className="form-group">
              <label className="form-label">Hard Excluded Hostnames</label>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="text"
                  className="form-input font-mono"
                  placeholder="e.g. k8s-master-01.internal"
                  value={excludedHostInput}
                  onChange={(e) => setExcludedHostInput(e.target.value)}
                />
                <button type="button" className="btn btn-secondary" onClick={handleAddExcludedHost}>
                  Add Excluded Host
                </button>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                {excludedHosts.map((h, idx) => (
                  <span key={idx} className="badge badge-danger font-mono" style={{ padding: '3px 8px' }}>
                    {h}
                    <button
                      type="button"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', marginLeft: 4, color: 'inherit' }}
                      onClick={() => setExcludedHosts(excludedHosts.filter((_, i) => i !== idx))}
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            </div>

            {/* Excluded Ports */}
            <div className="form-group">
              <label className="form-label" htmlFor="exc-ports">Hard Excluded Sensitive Ports</label>
              <input
                id="exc-ports"
                type="text"
                className="form-input font-mono"
                value={excludedPortInput}
                onChange={(e) => setExcludedPortInput(e.target.value)}
                placeholder="22, 10250"
              />
              <span className="form-hint">Prevents automated agents from probing SSH management or Kubernetes admin sockets.</span>
            </div>

            {/* Interactive Scope Dry-Run Simulator */}
            <div className="well" style={{ padding: 12, marginTop: 6 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                SCOPE DRY-RUN SIMULATOR (Test candidate target against ruleset)
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="text"
                  className="form-input font-mono"
                  placeholder="Enter IP to test (e.g. 10.42.18.1 or 10.42.18.104)"
                  value={simQuery}
                  onChange={(e) => setSimQuery(e.target.value)}
                />
                <button type="button" className="btn btn-secondary" onClick={handleTestSimulator}>
                  Simulate
                </button>
              </div>
              {simResult && (
                <div
                  style={{
                    marginTop: 8,
                    padding: 8,
                    borderRadius: 'var(--radius-xs)',
                    backgroundColor: simResult.inScope ? 'var(--status-emerald-dim)' : 'var(--status-coral-dim)',
                    border: `1px solid ${simResult.inScope ? 'var(--status-emerald-border)' : 'var(--status-coral-border)'}`,
                    fontSize: 11,
                    color: 'var(--text-primary)',
                  }}
                >
                  <strong style={{ color: simResult.inScope ? 'var(--status-emerald)' : 'var(--status-coral)' }}>
                    {simResult.inScope ? 'ALLOWED:' : 'DENIED:'}
                  </strong>{' '}
                  {simResult.reason}
                </div>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
              <button className="btn btn-secondary" onClick={() => setStep(2)}>
                <ArrowLeft size={13} /> Back
              </button>
              <button className="btn btn-primary" onClick={() => setStep(4)}>
                Proceed to Capabilities & Governance <ArrowRight size={13} />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Step 4: Capabilities & Governance */}
      {step === 4 && (
        <div className="panel" style={{ padding: 16 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Step 4: Permitted Capabilities & Resource Governance</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div className="form-group">
              <label className="form-label">Permitted Standard Capabilities</label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 8 }}>
                {[
                  { id: 'DNS_LOOKUP', label: 'DNS_LOOKUP (Passive/Active)', risk: 'Low' },
                  { id: 'TCP_CONNECT', label: 'TCP_CONNECT (Port Reachability)', risk: 'Moderate' },
                  { id: 'PORT_SCAN', label: 'PORT_SCAN (SYN/Connect)', risk: 'Moderate' },
                  { id: 'HTTP_REQUEST', label: 'HTTP_REQUEST (Web Enumeration)', risk: 'Moderate' },
                  { id: 'WEB_DISCOVERY', label: 'WEB_DISCOVERY (Directory Crawl)', risk: 'Moderate' },
                  { id: 'BROWSER_AUTOMATION', label: 'BROWSER_AUTOMATION (DOM Inspect)', risk: 'Moderate' },
                  { id: 'CONTROLLED_EXPLOITATION', label: 'CONTROLLED_EXPLOITATION (Safe PoC)', risk: 'Critical' },
                  { id: 'CREDENTIAL_VALIDATION', label: 'CREDENTIAL_VALIDATION (Auth Check)', risk: 'Critical' },
                ].map((cap) => {
                  const isChecked = selectedCapabilities.includes(cap.id as StandardCapability);
                  return (
                    <label
                      key={cap.id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        padding: '6px 10px',
                        borderRadius: 'var(--radius-sm)',
                        backgroundColor: isChecked ? 'var(--bg-surface-base)' : 'var(--bg-well)',
                        border: isChecked ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                        cursor: 'pointer',
                        fontSize: 11,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => {
                          if (isChecked) {
                            setSelectedCapabilities(selectedCapabilities.filter((c) => c !== cap.id));
                          } else {
                            setSelectedCapabilities([...selectedCapabilities, cap.id as StandardCapability]);
                          }
                        }}
                      />
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: 600 }}>{cap.label}</div>
                        <div style={{ fontSize: 10, color: cap.risk === 'Critical' ? 'var(--status-coral)' : 'var(--text-muted)' }}>
                          Risk: {cap.risk} {cap.risk === 'Critical' ? '(Requires 2-Person Sign)' : ''}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Resource limits */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
              <div className="form-group">
                <label className="form-label" htmlFor="m-budget">LLM Budget ($ USD)</label>
                <input
                  id="m-budget"
                  type="number"
                  className="form-input font-mono"
                  value={llmBudgetUsd}
                  onChange={(e) => setLlmBudgetUsd(Number(e.target.value))}
                  min={10}
                  max={1000}
                />
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="m-timeout">Tool Timeout (Seconds)</label>
                <input
                  id="m-timeout"
                  type="number"
                  className="form-input font-mono"
                  value={toolTimeoutSec}
                  onChange={(e) => setToolTimeoutSec(Number(e.target.value))}
                  min={5}
                  max={300}
                />
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="m-concurrency">Max Tool Concurrency</label>
                <input
                  id="m-concurrency"
                  type="number"
                  className="form-input font-mono"
                  value={maxConcurrency}
                  onChange={(e) => setMaxConcurrency(Number(e.target.value))}
                  min={1}
                  max={32}
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
              <button className="btn btn-secondary" onClick={() => setStep(3)}>
                <ArrowLeft size={13} /> Back
              </button>
              <button className="btn btn-primary" onClick={() => setStep(5)}>
                Review & Seal Scope <ArrowRight size={13} />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Step 5: Review & Seal */}
      {step === 5 && (
        <div className="panel" style={{ padding: 16 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Step 5: Review & Cryptographic Scope Seal</h3>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 14 }}>
            Verify all parameters before committing to the kernel storage engine.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="well" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 8, fontSize: 12 }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Mission Name: </span>
                <strong>{missionName}</strong> ({mode})
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Authorized Inclusions: </span>
                <span className="font-mono">{cidrList.join(', ')}</span> | Hostnames: <span className="font-mono">{hostList.join(', ')}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Strict Exclusions: </span>
                <span className="font-mono" style={{ color: 'var(--status-coral)' }}>{excludedCidrs.join(', ')}</span> | Hosts: <span className="font-mono" style={{ color: 'var(--status-coral)' }}>{excludedHosts.join(', ')}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Capabilities: </span>
                <span className="font-mono">{selectedCapabilities.join(', ')}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Governance Limits: </span>
                <span>Budget: ${llmBudgetUsd} | Timeout: {toolTimeoutSec}s | Concurrency: {maxConcurrency}</span>
              </div>
              <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 6, fontSize: 11 }}>
                <span style={{ color: 'var(--text-muted)' }}>Simulated Scope Digest: </span>
                <span className="font-mono text-primary">sha256:4f8e9a21b3c4d5e6f7a8b9c0d1e2f3a4...</span>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
              <button className="btn btn-secondary" onClick={() => setStep(4)}>
                <ArrowLeft size={13} /> Back
              </button>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-secondary" onClick={onCancel}>
                  Cancel
                </button>
                <button className="btn btn-primary" onClick={handleFinalSubmit}>
                  <CheckCircle2 size={13} /> Commit Mission & Seal Scope
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
