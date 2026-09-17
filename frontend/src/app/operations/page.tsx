"use client";

import React, { useState } from "react";
import { 
  Bot, 
  ArrowRight, 
  Eye 
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { getEngagements, getPolicyDecisions } from "@/lib/api";
import { StatusBadge } from "@/components/ui/StatusBadge";
import type { PolicyDecision } from "@/lib/types";

export default function AutonomousOperationsPage() {
  const [selectedDecision, setSelectedDecision] = useState<PolicyDecision | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: getEngagements,
  });

  const activeEngagement = engagements?.[0];

  const { data: decisions } = useQuery({
    queryKey: ["policy-decisions", activeEngagement?.id],
    queryFn: () => (activeEngagement ? getPolicyDecisions(activeEngagement.id) : Promise.resolve([])),
    enabled: !!activeEngagement,
    refetchInterval: 4000,
  });

  const filteredDecisions = (decisions || []).filter((d) => {
    if (statusFilter === "ALL") return true;
    if (statusFilter === "ALLOWED") return d.scope_decision === "ALLOW" && d.policy_decision === "ALLOW";
    if (statusFilter === "APPROVAL_REQUIRED") return d.policy_decision === "APPROVAL_REQUIRED";
    if (statusFilter === "DENIED") return d.scope_decision === "DENY" || d.policy_decision === "DENY";
    return true;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
            <Bot className="w-5 h-5 text-purple-400" />
            <span>AUTONOMOUS OPERATIONS & TOOL REQUEST PIPELINE</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Real-time telemetry of agent proposals passing through the deterministic security control plane.
          </p>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Filter:</span>
          {(["ALL", "ALLOWED", "APPROVAL_REQUIRED", "DENIED"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-3 py-1 rounded text-xs font-mono font-bold transition-all ${
                statusFilter === s
                  ? "bg-cyan-600 text-black"
                  : "bg-slate-900 border border-slate-800 text-slate-400 hover:text-white"
              }`}
            >
              {s.replace("_", " ")}
            </button>
          ))}
        </div>
      </div>

      {/* Epistemic Architecture Chain Banner */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#0b152b] space-y-3">
        <span className="text-[11px] font-mono text-slate-400 font-bold uppercase tracking-wider block">
          Deterministic Control Plane Path (PRD Architecture)
        </span>
        <div className="flex items-center justify-between text-xs font-mono overflow-x-auto py-2 px-1">
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-purple-500/40 text-purple-300 shrink-0">
            1. Agent Reasoning
          </div>
          <ArrowRight className="w-4 h-4 text-slate-600 shrink-0 mx-2" />
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-amber-500/40 text-amber-300 shrink-0">
            2. CandidateToolRequest
          </div>
          <ArrowRight className="w-4 h-4 text-slate-600 shrink-0 mx-2" />
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-emerald-500/40 text-emerald-300 shrink-0">
            3. ScopeGuard
          </div>
          <ArrowRight className="w-4 h-4 text-slate-600 shrink-0 mx-2" />
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-cyan-500/40 text-cyan-300 shrink-0">
            4. PolicyEngine
          </div>
          <ArrowRight className="w-4 h-4 text-slate-600 shrink-0 mx-2" />
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-rose-500/40 text-rose-300 shrink-0">
            5. Gated Approval
          </div>
          <ArrowRight className="w-4 h-4 text-slate-600 shrink-0 mx-2" />
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-slate-300 shrink-0">
            6. Sandboxed Execution
          </div>
        </div>
      </div>

      {/* Decisions & Tool Requests Explorer Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0b152b] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-slate-900/50">
                <th className="p-3">Timestamp / Agent</th>
                <th className="p-3">Tool</th>
                <th className="p-3">Target</th>
                <th className="p-3">Action</th>
                <th className="p-3">Scope Decision</th>
                <th className="p-3">Policy Decision</th>
                <th className="p-3">Execution Status</th>
                <th className="p-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredDecisions && filteredDecisions.length > 0 ? (
                filteredDecisions.map((d, i) => (
                  <tr key={i} className="hover:bg-slate-900/40">
                    <td className="p-3">
                      <div className="font-bold text-purple-300">{d.agent}</div>
                      <div className="text-[10px] text-slate-500">{new Date(d.timestamp).toLocaleTimeString()}</div>
                    </td>
                    <td className="p-3 font-bold text-slate-200">{d.tool}</td>
                    <td className="p-3 text-slate-300 max-w-[200px] truncate">{d.target}</td>
                    <td className="p-3 text-slate-400">{d.action}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        d.scope_decision === "ALLOW"
                          ? "bg-emerald-950/40 border border-emerald-500/30 text-emerald-400"
                          : "bg-rose-950/40 border border-rose-500/30 text-rose-400"
                      }`}>
                        {d.scope_decision}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        d.policy_decision === "ALLOW"
                          ? "bg-emerald-950/40 border border-emerald-500/30 text-emerald-400"
                          : d.policy_decision === "APPROVAL_REQUIRED"
                          ? "bg-amber-950/40 border border-amber-500/30 text-amber-400"
                          : "bg-rose-950/40 border border-rose-500/30 text-rose-400"
                      }`}>
                        {d.policy_decision}
                      </span>
                    </td>
                    <td className="p-3">
                      <StatusBadge status={d.status} size="sm" />
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => setSelectedDecision(d)}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono flex items-center gap-1 ml-auto"
                      >
                        <Eye className="w-3 h-3" /> Breakdown
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-500 font-mono text-xs">
                    No matching operations or tool requests recorded.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Decision Detail Drawer / Modal */}
      {selectedDecision && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-[#0b152b] p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="font-mono text-sm font-bold text-white">
                Deterministic Decision Chain Breakdown
              </h3>
              <button
                onClick={() => setSelectedDecision(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div className="p-3 rounded bg-slate-900 border border-slate-800 space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-slate-500">Tool & Action:</span>
                  <span className="text-white font-bold">{selectedDecision.tool} ({selectedDecision.action})</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Target Host / URL:</span>
                  <span className="text-cyan-300">{selectedDecision.target}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Proposing Agent:</span>
                  <span className="text-purple-300 font-semibold">{selectedDecision.agent}</span>
                </div>
              </div>

              <div className="p-3 rounded bg-slate-900 border border-slate-800 space-y-2">
                <div className="text-slate-400 font-bold uppercase text-[10px]">Filter Decisions:</div>
                <div className="flex justify-between items-center">
                  <span>ScopeGuard:</span>
                  <span className="text-emerald-400 font-bold">{selectedDecision.scope_decision}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span>PolicyEngine:</span>
                  <span className="text-amber-400 font-bold">{selectedDecision.policy_decision}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span>Execution Outcome:</span>
                  <StatusBadge status={selectedDecision.status} size="sm" />
                </div>
              </div>

              {selectedDecision.rationale && (
                <div>
                  <span className="text-slate-500 text-[10px] block mb-1">DETERMINISTIC RATIONALE</span>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                    {selectedDecision.rationale}
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedDecision(null)}
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
