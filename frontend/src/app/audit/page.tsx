"use client";

import React, { useState } from "react";
import { 
  ScrollText, 
  Search, 
  Eye, 
  X, 
  Lock 
} from "lucide-react";

interface AuditRow {
  id: string;
  timestamp: string;
  actor: string;
  event_type: string;
  target: string;
  decision: string;
  reason: string;
  event_hash: string;
}

const SAMPLE_AUDIT_LOG: AuditRow[] = [
  {
    id: "aud-001",
    timestamp: new Date().toISOString(),
    actor: "lead_operator",
    event_type: "approval_granted",
    target: "http://127.0.0.1:3000",
    decision: "APPROVE",
    reason: "Operator confirmed exact arguments hash match",
    event_hash: "a4f891bce09f...d4e2",
  },
  {
    id: "aud-002",
    timestamp: new Date(Date.now() - 120000).toISOString(),
    actor: "ScopeGuard",
    event_type: "scope_enforcement",
    target: "http://127.0.0.1:3000/admin",
    decision: "DENY",
    reason: "Matched explicit exclusion prefix /admin",
    event_hash: "3b29ac8712df...e5a1",
  },
  {
    id: "aud-003",
    timestamp: new Date(Date.now() - 360000).toISOString(),
    actor: "PolicyEngine",
    event_type: "policy_evaluated",
    target: "http://127.0.0.1:3000/api/Users",
    decision: "ALLOW",
    reason: "Passive HTTP GET is permitted under Safe Web Profile",
    event_hash: "99ea781bc091...ff03",
  },
  {
    id: "aud-004",
    timestamp: new Date(Date.now() - 600000).toISOString(),
    actor: "lead_operator",
    event_type: "finding_confirmed",
    target: "Juice Shop SQLite Injection",
    decision: "CONFIRMED",
    reason: "Human operator confirmed epistemic stage upgrade",
    event_hash: "821fb1a09d31...cb77",
  },
];

export default function AuditLogPage() {
  const [selectedEvent, setSelectedEvent] = useState<AuditRow | null>(null);
  const [searchTerm, setSearchTerm] = useState("");

  const filteredLogs = SAMPLE_AUDIT_LOG.filter(
    (l) =>
      l.actor.toLowerCase().includes(searchTerm.toLowerCase()) ||
      l.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      l.target.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-cyan-400" />
            <span>IMMUTABLE AUDIT TRAIL</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Cryptographically sealed event ledger capturing all scope checks, policy decisions, operator approvals, and tool actions.
          </p>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400">
          <Lock className="w-3.5 h-3.5 text-emerald-400" />
          <span>PostgreSQL Append-Only Ledger</span>
        </div>
      </div>

      {/* Search Filter */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search actor, event type, or target..."
            className="w-full pl-9 pr-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0b152b] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-slate-900/50">
                <th className="p-3">Timestamp</th>
                <th className="p-3">Actor</th>
                <th className="p-3">Event Type</th>
                <th className="p-3">Target</th>
                <th className="p-3">Decision</th>
                <th className="p-3">Reason Code</th>
                <th className="p-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-900/40">
                  <td className="p-3 text-slate-400 text-[11px]">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="p-3 font-bold text-white">{log.actor}</td>
                  <td className="p-3 text-cyan-300">{log.event_type}</td>
                  <td className="p-3 text-slate-300 max-w-[200px] truncate">{log.target}</td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      log.decision === "APPROVE" || log.decision === "ALLOW" || log.decision === "CONFIRMED"
                        ? "bg-emerald-950/40 border border-emerald-500/30 text-emerald-400"
                        : "bg-rose-950/40 border border-rose-500/30 text-rose-400"
                    }`}>
                      {log.decision}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400 truncate max-w-[220px]">{log.reason}</td>
                  <td className="p-3 text-right">
                    <button
                      onClick={() => setSelectedEvent(log)}
                      className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono flex items-center gap-1 ml-auto"
                    >
                      <Eye className="w-3 h-3" /> Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-[#0b152b] p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="font-mono text-sm font-bold text-white">
                Audit Event Record #{selectedEvent.id}
              </h3>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-2.5 text-xs font-mono p-3 rounded bg-slate-900 border border-slate-800">
              <div className="flex justify-between">
                <span className="text-slate-500">Timestamp:</span>
                <span className="text-slate-200">{selectedEvent.timestamp}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Actor / Authority:</span>
                <span className="text-cyan-300 font-bold">{selectedEvent.actor}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Event Type:</span>
                <span className="text-purple-300">{selectedEvent.event_type}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Decision Outcome:</span>
                <span className="text-emerald-400 font-bold">{selectedEvent.decision}</span>
              </div>
              <div className="pt-2 border-t border-slate-800">
                <span className="text-slate-500 text-[10px] block mb-1">DETERMINISTIC REASON</span>
                <div className="text-slate-300">{selectedEvent.reason}</div>
              </div>
              <div className="pt-2 border-t border-slate-800">
                <span className="text-slate-500 text-[10px] block mb-1">CRYPTOGRAPHIC HASH (HMAC / SHA256)</span>
                <div className="text-slate-400 text-[10px] font-mono break-all">{selectedEvent.event_hash}</div>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded text-xs font-mono border border-slate-700 text-slate-300 hover:bg-slate-800"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
