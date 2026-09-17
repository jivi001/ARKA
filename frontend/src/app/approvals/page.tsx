"use client";

import React, { useState } from "react";
import { 
  CheckSquare, 
  Check, 
  Ban, 
  Eye, 
  AlertOctagon, 
  FileCode2, 
  X 
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getApprovals, decideApproval } from "@/lib/api";
import { RiskBadge } from "@/components/ui/RiskBadge";
import type { ApprovalRequest } from "@/lib/types";

export default function ApprovalsCenterPage() {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<"PENDING" | "APPROVED" | "REJECTED">("PENDING");
  const [inspectApproval, setInspectApproval] = useState<ApprovalRequest | null>(null);

  const { data: approvals } = useQuery({
    queryKey: ["approvals-all", tab],
    queryFn: () => getApprovals({ status: tab }),
    refetchInterval: 5000,
  });

  const decideMutation = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "APPROVE" | "REJECT" }) =>
      decideApproval(id, decision, "lead_operator", "Authoritative human operator decision via Console"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["approvals-all"] });
      queryClient.invalidateQueries({ queryKey: ["approvals-pending-count"] });
      setInspectApproval(null);
    },
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
            <CheckSquare className="w-5 h-5 text-amber-400" />
            <span>OPERATOR APPROVAL CENTER</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Deterministic human gating for high-risk operations. Every approval is cryptographically bound to exact arguments.
          </p>
        </div>

        {/* Security Rule Badge */}
        <div className="hidden sm:flex items-center gap-2 p-2 rounded bg-amber-950/30 border border-amber-500/30 text-[11px] font-mono text-amber-300">
          <AlertOctagon className="w-4 h-4 text-amber-400 shrink-0" />
          <span>Strict Argument Hashing: Tampering with arguments invalidates approval token.</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800">
        {(["PENDING", "APPROVED", "REJECTED"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-xs font-mono font-semibold transition-all border-b-2 -mb-px ${
              tab === t
                ? "border-cyan-400 text-cyan-300 bg-slate-900/40"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t === "PENDING" ? "Pending Approvals" : t === "APPROVED" ? "Approved History" : "Rejected"}
          </button>
        ))}
      </div>

      {/* Approvals Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0b152b] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-slate-900/50">
                <th className="p-3">ID / Requested At</th>
                <th className="p-3">Agent</th>
                <th className="p-3">Tool</th>
                <th className="p-3">Exact Target</th>
                <th className="p-3">Risk Level</th>
                <th className="p-3">Arguments SHA256</th>
                <th className="p-3">Scope Ver</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {approvals && approvals.length > 0 ? (
                approvals.map((req) => (
                  <tr key={req.approval_id} className="hover:bg-slate-900/40">
                    <td className="p-3">
                      <div className="font-bold text-slate-200">{req.approval_id.slice(0, 10)}...</div>
                      <div className="text-[10px] text-slate-500">{new Date(req.requested_at).toLocaleTimeString()}</div>
                    </td>
                    <td className="p-3 text-purple-300 font-semibold">{req.agent_id}</td>
                    <td className="p-3 text-slate-200 font-bold">{req.tool_name}</td>
                    <td className="p-3 text-slate-300 max-w-[200px] truncate">{req.target}</td>
                    <td className="p-3">
                      <RiskBadge risk={req.risk_level} size="sm" />
                    </td>
                    <td className="p-3">
                      <span className="text-[10px] text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 font-mono">
                        {req.arguments_hash.slice(0, 12)}...
                      </span>
                    </td>
                    <td className="p-3 text-slate-400">v{req.scope_version}</td>
                    <td className="p-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setInspectApproval(req)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono flex items-center gap-1"
                        >
                          <Eye className="w-3 h-3" /> Inspect
                        </button>

                        {req.status === "PENDING" && (
                          <>
                            <button
                              onClick={() => decideMutation.mutate({ id: req.approval_id, decision: "APPROVE" })}
                              disabled={decideMutation.isPending}
                              className="btn-tactile px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-[10px] flex items-center gap-1"
                            >
                              <Check className="w-3 h-3" /> Approve Exact Action
                            </button>
                            <button
                              onClick={() => decideMutation.mutate({ id: req.approval_id, decision: "REJECT" })}
                              disabled={decideMutation.isPending}
                              className="btn-tactile px-2.5 py-1 rounded bg-rose-900/80 hover:bg-rose-800 text-rose-200 font-bold text-[10px] flex items-center gap-1"
                            >
                              <Ban className="w-3 h-3" /> Reject
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-500 font-mono text-xs">
                    No {tab.toLowerCase()} approval requests.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspect Arguments Modal */}
      {inspectApproval && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl rounded-xl border border-slate-700 bg-[#0b152b] p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileCode2 className="w-5 h-5 text-cyan-400" />
                <h3 className="font-mono text-sm font-bold text-white">
                  Exact Tool Request & Argument Binding (SEC-01)
                </h3>
              </div>
              <button
                onClick={() => setInspectApproval(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono p-3 rounded bg-slate-900 border border-slate-800">
              <div>
                <span className="text-slate-500 text-[10px] block">TOOL</span>
                <span className="text-white font-bold">{inspectApproval.tool_name}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">RISK LEVEL</span>
                <RiskBadge risk={inspectApproval.risk_level} size="sm" />
              </div>
              <div className="col-span-2">
                <span className="text-slate-500 text-[10px] block">TARGET URL / HOST</span>
                <span className="text-cyan-300 font-bold">{inspectApproval.target}</span>
              </div>
              <div className="col-span-2">
                <span className="text-slate-500 text-[10px] block">CRYPTOGRAPHIC ARGUMENTS SHA-256 HASH</span>
                <span className="text-emerald-400 font-bold break-all">{inspectApproval.arguments_hash}</span>
              </div>
            </div>

            <div>
              <span className="block text-xs font-mono text-slate-400 mb-1">Normalized Arguments Payload</span>
              <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 max-h-56 overflow-y-auto">
                {JSON.stringify(inspectApproval.arguments, null, 2)}
              </pre>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => setInspectApproval(null)}
                className="btn-tactile px-4 py-1.5 rounded text-xs font-mono border border-slate-700 text-slate-300 hover:bg-slate-800"
              >
                Close
              </button>
              {inspectApproval.status === "PENDING" && (
                <>
                  <button
                    onClick={() => decideMutation.mutate({ id: inspectApproval.approval_id, decision: "REJECT" })}
                    disabled={decideMutation.isPending}
                    className="btn-tactile px-4 py-1.5 rounded text-xs font-mono font-bold bg-rose-900/80 hover:bg-rose-800 text-rose-200"
                  >
                    Reject
                  </button>
                  <button
                    onClick={() => decideMutation.mutate({ id: inspectApproval.approval_id, decision: "APPROVE" })}
                    disabled={decideMutation.isPending}
                    className="btn-tactile px-4 py-1.5 rounded text-xs font-mono font-bold bg-emerald-600 hover:bg-emerald-500 text-white"
                  >
                    Approve Exact Action
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
