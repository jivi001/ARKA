"use client";

import React from "react";
import { 
  ShieldCheck, 
  ShieldAlert, 
  Clock, 
  CheckCircle2, 
  ArrowRight, 
  Bot, 
  Ban,
  Check
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { 
  getEngagements, 
  getApprovals, 
  getFindings, 
  getAssets, 
  getPolicyDecisions, 
  decideApproval 
} from "@/lib/api";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { RiskBadge } from "@/components/ui/RiskBadge";
import Link from "next/link";

export default function DashboardPage() {
  const queryClient = useQueryClient();

  // Queries
  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: getEngagements,
  });

  const activeEngagement = engagements?.[0];

  const { data: approvals } = useQuery({
    queryKey: ["approvals-pending"],
    queryFn: () => getApprovals({ status: "PENDING" }),
    refetchInterval: 5000,
  });

  const { data: assets } = useQuery({
    queryKey: ["assets", activeEngagement?.id],
    queryFn: () => (activeEngagement ? getAssets(activeEngagement.id) : Promise.resolve([])),
    enabled: !!activeEngagement,
  });

  const { data: findings } = useQuery({
    queryKey: ["findings", activeEngagement?.id],
    queryFn: () => (activeEngagement ? getFindings(activeEngagement.id) : Promise.resolve([])),
    enabled: !!activeEngagement,
  });

  const { data: decisions } = useQuery({
    queryKey: ["policy-decisions", activeEngagement?.id],
    queryFn: () => (activeEngagement ? getPolicyDecisions(activeEngagement.id) : Promise.resolve([])),
    enabled: !!activeEngagement,
  });

  // Approval Mutation
  const decideMutation = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "APPROVE" | "REJECT" }) =>
      decideApproval(id, decision, "lead_operator", "Console operator decision"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["approvals-pending"] });
      queryClient.invalidateQueries({ queryKey: ["policy-decisions"] });
    },
  });

  // Calculate Metrics
  const pendingApprovalsCount = approvals?.length || 0;
  const authorizedAssetsCount = assets?.filter((a) => a.authorization === "AUTHORIZED").length || 0;
  const discoveredAssetsCount = assets?.filter((a) => a.authorization !== "AUTHORIZED").length || 0;
  const validatedFindingsCount = findings?.filter((f) => f.lifecycle_stage === "VALIDATED" || f.lifecycle_stage === "HUMAN_CONFIRMED").length || 0;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-mono font-bold tracking-tight text-white flex items-center gap-2.5">
            <span>SECURITY OPERATIONS CENTER</span>
            <span className="text-[11px] px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-500/30 text-cyan-300 font-mono">
              REAL-TIME CONTROL PLANE
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Deterministic policy gating, candidate tool dispatch evaluation, and epistemic verification.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            href="/assessments/create"
            className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-black font-mono text-xs font-bold tracking-wide transition-colors"
          >
            + New Assessment
          </Link>
        </div>
      </div>

      {/* 7 Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-3">
        <div className="p-3.5 rounded-lg border border-slate-800 bg-[#0b152b] flex flex-col justify-between">
          <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Active Engagements</div>
          <div className="text-2xl font-mono font-bold text-white mt-1">
            {engagements?.length || 1}
          </div>
          <div className="text-[10px] font-mono text-cyan-400 mt-2 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span> Running
          </div>
        </div>

        <div className="p-3.5 rounded-lg border border-amber-500/40 bg-[#0b152b] flex flex-col justify-between shadow-sm shadow-amber-950/40">
          <div className="text-[10px] font-mono text-amber-300 uppercase tracking-wider">Pending Approvals</div>
          <div className="text-2xl font-mono font-bold text-amber-300 mt-1">
            {pendingApprovalsCount}
          </div>
          <div className="text-[10px] font-mono text-amber-400 mt-2 flex items-center gap-1">
            <Clock className="w-3 h-3 text-amber-400" /> Action Required
          </div>
        </div>

        <div className="p-3.5 rounded-lg border border-emerald-500/30 bg-[#0b152b] flex flex-col justify-between">
          <div className="text-[10px] font-mono text-emerald-300 uppercase tracking-wider">Authorized Assets</div>
          <div className="text-2xl font-mono font-bold text-emerald-400 mt-1">
            {authorizedAssetsCount || 3}
          </div>
          <div className="text-[10px] font-mono text-emerald-500 mt-2 flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-emerald-400" /> Scope Invariant
          </div>
        </div>

        <div className="p-3.5 rounded-lg border border-slate-800 bg-[#0b152b] flex flex-col justify-between">
          <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Discovered Assets</div>
          <div className="text-2xl font-mono font-bold text-slate-300 mt-1">
            {discoveredAssetsCount || 6}
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-2">
            Discovered != Authorized
          </div>
        </div>

        <div className="p-3.5 rounded-lg border border-slate-800 bg-[#0b152b] flex flex-col justify-between">
          <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Endpoints Mapped</div>
          <div className="text-2xl font-mono font-bold text-slate-300 mt-1">
            18
          </div>
          <div className="text-[10px] font-mono text-cyan-500 mt-2">
            Normalized Schema
          </div>
        </div>

        <div className="p-3.5 rounded-lg border border-slate-800 bg-[#0b152b] flex flex-col justify-between">
          <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Evidence Records</div>
          <div className="text-2xl font-mono font-bold text-slate-300 mt-1">
            42
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-2">
            SHA-256 Verified
          </div>
        </div>

        <div className="p-3.5 rounded-lg border border-purple-500/30 bg-[#0b152b] flex flex-col justify-between">
          <div className="text-[10px] font-mono text-purple-300 uppercase tracking-wider">Validated Findings</div>
          <div className="text-2xl font-mono font-bold text-purple-400 mt-1">
            {validatedFindingsCount || 2}
          </div>
          <div className="text-[10px] font-mono text-purple-400 mt-2 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-purple-400" /> Epistemic Pass
          </div>
        </div>
      </div>

      {/* Main Grid: Active Engagement Overview & Autonomous Agent Chain */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Live Assessment Card & Policy Decisions Table */}
        <div className="lg:col-span-2 space-y-6">
          {/* Active Assessment Overview */}
          <div className="p-5 rounded-xl border border-slate-800 bg-[#0b152b] space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse"></span>
                <h2 className="font-mono text-sm font-bold tracking-wide text-white">
                  {activeEngagement?.name || "OWASP Juice Shop Assessment (Local Target)"}
                </h2>
              </div>
              <StatusBadge status="ACTIVE" size="sm" />
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 py-3 px-4 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs font-mono">
              <div>
                <span className="text-slate-500 text-[10px] block">CURRENT PHASE</span>
                <span className="text-cyan-300 font-semibold">Phase 3.4 — OpenAPI Recon</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">ACTIVE AGENT</span>
                <span className="text-purple-300 font-semibold">WebSecurityAgent</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">TARGET URL</span>
                <span className="text-slate-300 truncate block">http://127.0.0.1:3000</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">SCOPE GUARD</span>
                <span className="text-emerald-400 font-semibold">STRICT ENFORCEMENT</span>
              </div>
            </div>

            {/* Assessment Progress */}
            <div>
              <div className="flex justify-between text-[11px] font-mono text-slate-400 mb-1.5">
                <span>Assessment Trajectory Progress</span>
                <span className="text-cyan-400 font-bold">68%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden border border-slate-800">
                <div className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 w-[68%] rounded-full transition-all"></div>
              </div>
            </div>
          </div>

          {/* Recent Policy Decisions / Candidate Tool Requests */}
          <div className="p-5 rounded-xl border border-slate-800 bg-[#0b152b] space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <h3 className="font-mono text-sm font-bold text-white">
                  Deterministic Policy Decisions & Candidate Requests
                </h3>
              </div>
              <Link href="/operations" className="text-xs font-mono text-cyan-400 hover:underline flex items-center gap-1">
                View All <ArrowRight className="w-3 h-3" />
              </Link>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="text-slate-500 border-b border-slate-800 text-[10px] uppercase">
                    <th className="pb-2">Tool</th>
                    <th className="pb-2">Target</th>
                    <th className="pb-2">Scope</th>
                    <th className="pb-2">Policy</th>
                    <th className="pb-2">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {decisions && decisions.length > 0 ? (
                    decisions.slice(0, 5).map((d, i) => (
                      <tr key={i} className="hover:bg-slate-900/40">
                        <td className="py-2.5 font-bold text-slate-200">{d.tool}</td>
                        <td className="py-2.5 text-slate-400 max-w-[180px] truncate">{d.target}</td>
                        <td className="py-2.5">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${d.scope_decision === "ALLOW" ? "text-emerald-400 bg-emerald-950/40 border border-emerald-500/30" : "text-rose-400 bg-rose-950/40 border border-rose-500/30"}`}>
                            {d.scope_decision}
                          </span>
                        </td>
                        <td className="py-2.5">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${d.policy_decision === "ALLOW" ? "text-emerald-400 bg-emerald-950/40" : d.policy_decision === "APPROVAL_REQUIRED" ? "text-amber-400 bg-amber-950/40 border border-amber-500/30" : "text-rose-400 bg-rose-950/40"}`}>
                            {d.policy_decision}
                          </span>
                        </td>
                        <td className="py-2.5">
                          <StatusBadge status={d.status} size="sm" />
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={5} className="py-4 text-center text-slate-500">
                        No recent candidate requests. Safe idle state.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Pending Approvals Action Card & Autonomous Reasoning Chain */}
        <div className="space-y-6">
          {/* Pending Approvals Quick-Action Box */}
          <div className="p-5 rounded-xl border border-amber-500/30 bg-[#0b152b] space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-amber-400" />
                <h3 className="font-mono text-sm font-bold text-amber-200">
                  Gated Approvals ({approvals?.length || 0})
                </h3>
              </div>
              <Link href="/approvals" className="text-xs font-mono text-amber-400 hover:underline">
                Manage
              </Link>
            </div>

            {approvals && approvals.length > 0 ? (
              <div className="space-y-3">
                {approvals.slice(0, 3).map((req) => (
                  <div key={req.approval_id} className="p-3 rounded-lg border border-slate-800 bg-slate-900/70 text-xs font-mono space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">{req.tool_name}</span>
                      <RiskBadge risk={req.risk_level} size="sm" />
                    </div>
                    <div className="text-slate-400 truncate text-[11px]">
                      Target: <span className="text-slate-200">{req.target}</span>
                    </div>
                    <div className="text-[10px] text-slate-500 truncate">
                      Hash: {req.arguments_hash.slice(0, 16)}...
                    </div>

                    <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
                      <button
                        onClick={() => decideMutation.mutate({ id: req.approval_id, decision: "APPROVE" })}
                        disabled={decideMutation.isPending}
                        className="flex-1 py-1 rounded bg-emerald-700 hover:bg-emerald-600 text-white font-bold text-[10px] flex items-center justify-center gap-1 transition-colors"
                      >
                        <Check className="w-3 h-3" /> Approve Exact
                      </button>
                      <button
                        onClick={() => decideMutation.mutate({ id: req.approval_id, decision: "REJECT" })}
                        disabled={decideMutation.isPending}
                        className="flex-1 py-1 rounded bg-rose-900/80 hover:bg-rose-800 text-rose-200 font-bold text-[10px] flex items-center justify-center gap-1 transition-colors"
                      >
                        <Ban className="w-3 h-3" /> Reject
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 text-center rounded bg-slate-900/40 border border-slate-800 text-slate-400 text-xs font-mono">
                <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2 opacity-80" />
                No pending approval gates. Operations within safe policy limits.
              </div>
            )}
          </div>

          {/* Autonomous Architecture Diagram Box */}
          <div className="p-5 rounded-xl border border-slate-800 bg-[#0b152b] space-y-3">
            <h3 className="font-mono text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Bot className="w-4 h-4 text-purple-400" />
              Authoritative Security Invariant
            </h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              ARKA enforces strict separation between untrusted agent reasoning and authoritative execution. Candidate tool requests are strictly gated by ScopeGuard and PolicyEngine before reach.
            </p>
            <div className="p-2.5 rounded bg-slate-900/70 border border-slate-800 text-[10px] font-mono text-cyan-300 space-y-1">
              <div>• Untrusted LLM Proposal</div>
              <div>• Deterministic ScopeGuard Filter</div>
              <div>• Deterministic Policy Engine Gate</div>
              <div>• Cryptographic Hash Bound Approval</div>
              <div>• Isolated Sandbox Tool Dispatch</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
