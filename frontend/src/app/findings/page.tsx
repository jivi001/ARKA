"use client";

import React, { useState } from "react";
import { 
  Bug, 
  ShieldCheck, 
  UserCheck, 
  CheckCircle2, 
  X, 
  Check, 
  Eye 
} from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getEngagements, getFindings, confirmFinding } from "@/lib/api";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { EpistemicLadder } from "@/components/ui/EpistemicLadder";
import type { Finding } from "@/lib/types";

export default function FindingsPage() {
  const queryClient = useQueryClient();
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [confirmNotes, setConfirmNotes] = useState("");

  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: getEngagements,
  });

  const activeEngagement = engagements?.[0];

  const { data: findings } = useQuery({
    queryKey: ["findings", activeEngagement?.id],
    queryFn: () => (activeEngagement ? getFindings(activeEngagement.id) : Promise.resolve([])),
    enabled: !!activeEngagement,
    refetchInterval: 5000,
  });

  const confirmMutation = useMutation({
    mutationFn: ({ id, notes }: { id: string; notes?: string }) =>
      confirmFinding(id, "lead_operator", notes),
    onSuccess: (updated) => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      setSelectedFinding(updated);
    },
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
            <Bug className="w-5 h-5 text-purple-400" />
            <span>FINDINGS & EPISTEMIC VERIFICATION</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Deterministic 5-stage epistemic validation ladder. LLM reasoning can only produce candidate hypotheses.
          </p>
        </div>

        <div className="flex items-center gap-2 p-2 rounded bg-purple-950/30 border border-purple-500/40 text-xs font-mono text-purple-300">
          <ShieldCheck className="w-4 h-4 text-purple-400 shrink-0" />
          <span>INV-4: LLM has zero authority to promote findings to VALIDATED or CONFIRMED.</span>
        </div>
      </div>

      {/* Findings Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0b152b] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-slate-900/50">
                <th className="p-3">Finding Title</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Epistemic Stage</th>
                <th className="p-3">LLM Confidence</th>
                <th className="p-3">Deterministic Check</th>
                <th className="p-3">Human Confirmation</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {findings && findings.length > 0 ? (
                findings.map((f) => (
                  <tr key={f.finding_id} className="hover:bg-slate-900/40">
                    <td className="p-3">
                      <div className="font-bold text-white">{f.title}</div>
                      <div className="text-[10px] text-slate-400 truncate max-w-[280px]">
                        Target: {f.target || "http://127.0.0.1:3000"}
                      </div>
                    </td>
                    <td className="p-3">
                      <RiskBadge risk={f.severity} size="sm" />
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold border border-slate-700 bg-slate-900 text-slate-300">
                        {f.lifecycle_stage}
                      </span>
                    </td>
                    <td className="p-3 text-slate-300">
                      {(f.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="p-3">
                      {f.deterministic_validation ? (
                        <span className="text-emerald-400 font-bold text-[10px] flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[10px]">PENDING REPLAY</span>
                      )}
                    </td>
                    <td className="p-3">
                      {f.human_confirmed_by ? (
                        <span className="text-purple-300 font-bold text-[10px] flex items-center gap-1">
                          <UserCheck className="w-3.5 h-3.5" /> {f.human_confirmed_by}
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[10px]">UNCONFIRMED</span>
                      )}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => setSelectedFinding(f)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[10px] font-mono flex items-center gap-1 ml-auto"
                      >
                        <Eye className="w-3 h-3" /> View & Validate
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500 font-mono text-xs">
                    No findings recorded.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Finding Detail Modal with Epistemic Verification */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-3xl rounded-xl border border-slate-700 bg-[#0b152b] p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Bug className="w-5 h-5 text-purple-400" />
                <h3 className="font-mono text-base font-bold text-white">
                  {selectedFinding.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Epistemic Ladder Component */}
            <EpistemicLadder
              currentStage={selectedFinding.lifecycle_stage}
              deterministicValidated={selectedFinding.deterministic_validation}
              humanConfirmedBy={selectedFinding.human_confirmed_by}
            />

            {/* Description & Technical Metadata */}
            <div className="space-y-2 text-xs font-mono">
              <span className="text-slate-400 font-bold uppercase tracking-wider block">Description</span>
              <p className="p-3 rounded bg-slate-900 border border-slate-800 text-slate-300 leading-relaxed">
                {selectedFinding.description}
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 text-[10px] block mb-1">DETECTION SOURCES</span>
                <div className="text-slate-200">
                  {selectedFinding.detection_sources?.join(", ") || "ReconAgent, OpenAPI Analyzer"}
                </div>
              </div>
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <span className="text-slate-500 text-[10px] block mb-1">REMEDIATION GUIDANCE</span>
                <div className="text-slate-200">
                  {selectedFinding.remediation || "Apply strict server-side authorization check and parameter validation."}
                </div>
              </div>
            </div>

            {/* Operator Human Confirmation Form */}
            {selectedFinding.lifecycle_stage === "VALIDATED" ? (
              <div className="p-4 rounded-lg bg-purple-950/30 border border-purple-500/40 space-y-3">
                <div className="text-xs font-mono font-bold text-purple-300 flex items-center gap-2">
                  <UserCheck className="w-4 h-4 text-purple-400" />
                  <span>Authoritative Human Confirmation Gate</span>
                </div>
                <p className="text-[11px] text-slate-300 font-mono">
                  Promote this finding from <strong>VALIDATED</strong> to the highest epistemic rank: <strong>HUMAN CONFIRMED</strong>. Deterministic replay proof has been verified. This action is permanently recorded in the immutable audit log.
                </p>
                <div>
                  <input
                    type="text"
                    value={confirmNotes}
                    onChange={(e) => setConfirmNotes(e.target.value)}
                    placeholder="Operator verification notes (e.g. verified with manual curl test and source code review)"
                    className="w-full px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white outline-none focus:border-purple-500"
                  />
                </div>
                <div className="flex justify-end">
                  <button
                    onClick={() =>
                      confirmMutation.mutate({
                        id: selectedFinding.finding_id,
                        notes: confirmNotes,
                      })
                    }
                    disabled={confirmMutation.isPending}
                    className="btn-tactile px-4 py-2 rounded bg-purple-600 hover:bg-purple-500 text-white font-mono text-xs font-bold flex items-center gap-1.5 shadow-lg shadow-purple-950 transition-colors"
                  >
                    <Check className="w-4 h-4" />
                    {confirmMutation.isPending ? "Confirming..." : "Confirm Finding as Operator"}
                  </button>
                </div>
              </div>
            ) : selectedFinding.lifecycle_stage !== "HUMAN_CONFIRMED" ? (
              <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 space-y-2 text-xs font-mono">
                <div className="text-amber-400 font-bold flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-amber-400" />
                  <span>Epistemic Invariant: Stage Gate Locked</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  This finding is currently at <strong>{selectedFinding.lifecycle_stage}</strong> stage. Invariant <em>VALIDATED != LLM_CONFIDENCE</em> dictates that findings must undergo deterministic replay validation before operator human confirmation can be performed. Arbitrary stage skipping is strictly prohibited.
                </p>
              </div>
            ) : null}

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedFinding(null)}
                className="btn-tactile px-4 py-1.5 rounded text-xs font-mono border border-slate-700 text-slate-300 hover:bg-slate-800"
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
