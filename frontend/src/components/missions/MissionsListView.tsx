import React from 'react';
import { Mission, EmergencyStopStatus } from '../../types/core';
import { Badge } from '../common/Badge';
import { formatTimestamp } from '../../utils/formatting';
import { Play, Pause, Square, Plus, Target, AlertTriangle } from 'lucide-react';

export interface MissionsListViewProps {
  missions: Mission[];
  selectedMissionId: string;
  emergencyStopStatus: EmergencyStopStatus;
  onSelectMission: (id: string) => void;
  onTransitionMission: (missionId: string, targetState: Mission['state']) => Promise<void>;
  onOpenCreateMission: () => void;
}

export const MissionsListView: React.FC<MissionsListViewProps> = ({
  missions,
  selectedMissionId,
  emergencyStopStatus,
  onSelectMission,
  onTransitionMission,
  onOpenCreateMission,
}) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Top Header */}
      <div className="panel" style={{ padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: 14, fontWeight: 700 }}>Security Assessment Missions</h2>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            Mission state machine: CREATED → ACTIVE ↔ PAUSED → COMPLETED / TERMINATED. Operator-only authorization.
          </p>
        </div>
        <button className="btn btn-primary" onClick={onOpenCreateMission}>
          <Plus size={13} /> New Mission
        </button>
      </div>

      {/* Emergency Stop warning */}
      {emergencyStopStatus.active && (
        <div
          style={{
            padding: '8px 12px',
            backgroundColor: 'var(--status-coral-dim)',
            border: '1px solid var(--status-coral-border)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 11,
            color: 'var(--status-coral)',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <AlertTriangle size={14} />
          <span>Cannot activate missions while Platform Emergency Stop is active.</span>
        </div>
      )}

      {/* Missions Table */}
      <div className="table-container">
        <table className="arka-table">
          <thead>
            <tr>
              <th>MISSION NAME</th>
              <th>MISSION ID</th>
              <th>STATE</th>
              <th>MODE</th>
              <th>SCOPE REF</th>
              <th>STARTED (UTC)</th>
              <th>OPERATOR ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {missions.map((m) => {
              const isSelected = m.id === selectedMissionId;
              const isTerminal = m.state === 'COMPLETED' || m.state === 'TERMINATED';

              return (
                <tr
                  key={m.id}
                  className={isSelected ? 'selected' : ''}
                  style={{ cursor: 'pointer' }}
                  onClick={() => onSelectMission(m.id)}
                >
                  <td style={{ fontWeight: 600 }}>{m.name}</td>
                  <td className="mono-cell" style={{ color: 'var(--text-muted)' }}>{m.id}</td>
                  <td>
                    <Badge
                      variant={
                        m.state === 'ACTIVE'
                          ? 'success'
                          : m.state === 'PAUSED'
                          ? 'warning'
                          : m.state === 'COMPLETED'
                          ? 'primary'
                          : 'neutral'
                      }
                      pulseDot={m.state === 'ACTIVE'}
                    >
                      {m.state}
                    </Badge>
                  </td>
                  <td>
                    <Badge variant="neutral">
                      {m.mode === 'AUTHORIZED_PROFESSIONAL' ? 'PRO-ASSESSMENT' : 'LAB-CTF'}
                    </Badge>
                  </td>
                  <td className="mono-cell">{m.scope_ref}</td>
                  <td>{formatTimestamp(m.created_at_unix)}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      {/* Created -> Active */}
                      {m.state === 'CREATED' && (
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: 10, padding: '2px 6px' }}
                          disabled={emergencyStopStatus.active}
                          onClick={() => onTransitionMission(m.id, 'ACTIVE')}
                          title={emergencyStopStatus.active ? 'Blocked by E-Stop' : 'Launch Mission'}
                        >
                          <Play size={10} /> Launch
                        </button>
                      )}

                      {/* Active -> Paused */}
                      {m.state === 'ACTIVE' && (
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: 10, padding: '2px 6px' }}
                          onClick={() => onTransitionMission(m.id, 'PAUSED')}
                          title="Pause Mission execution"
                        >
                          <Pause size={10} /> Pause
                        </button>
                      )}

                      {/* Paused -> Active */}
                      {m.state === 'PAUSED' && (
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: 10, padding: '2px 6px' }}
                          disabled={emergencyStopStatus.active}
                          onClick={() => onTransitionMission(m.id, 'ACTIVE')}
                          title="Resume Mission"
                        >
                          <Play size={10} /> Resume
                        </button>
                      )}

                      {/* Complete */}
                      {!isTerminal && (
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: 10, padding: '2px 6px' }}
                          onClick={() => onTransitionMission(m.id, 'COMPLETED')}
                          title="Mark assessment Completed"
                        >
                          <Square size={10} /> Complete
                        </button>
                      )}

                      {isTerminal && (
                        <span style={{ fontSize: 10, color: 'var(--text-subtle)', fontStyle: 'italic' }}>
                          Terminal State
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
