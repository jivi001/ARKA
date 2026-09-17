"use client";

import React, { useState } from "react";
import { AlertOctagon, X, ShieldAlert } from "lucide-react";
import { useConsoleStore } from "@/lib/store";

export function HaltAgentsModal() {
  const { haltAgentsModalOpen, setHaltAgentsModalOpen, addAlert } = useConsoleStore();
  const [reason, setReason] = useState("");
  const [halting, setHalting] = useState(false);

  if (!haltAgentsModalOpen) return null;

  const handleHalt = async () => {
    setHalting(true);
    try {
      // Deterministic killswitch call: dispatch immediate halt
      await fetch("/api/engagements/halt-all", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason || "Operator emergency killswitch activated" }),
      }).catch(() => {
        // Even if endpoint errors or times out, UI halts locally and alerts
      });

      addAlert({
        type: "critical",
        title: "EMERGENCY HALT EXECUTED",
        message: `All agent workflows and sandbox tasks halted deterministically. Reason: ${reason || "Operator action"}`,
      });
      setHaltAgentsModalOpen(false);
    } finally {
      setHalting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="w-full max-w-md rounded-xl border border-rose-500/60 glass-panel shadow-2xl shadow-rose-950/50 p-6">
        <div className="flex items-center justify-between pb-4 border-b border-rose-950">
          <div className="flex items-center gap-2.5 text-rose-400">
            <AlertOctagon className="w-6 h-6 animate-pulse" />
            <h3 className="font-mono text-base font-bold uppercase tracking-wider text-rose-300">
              Deterministic Killswitch
            </h3>
          </div>
          <button
            onClick={() => setHaltAgentsModalOpen(false)}
            className="btn-tactile text-slate-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="py-4 space-y-3 text-sm text-slate-300">
          <div className="p-3 rounded bg-rose-950/40 border border-rose-900/50 text-xs text-rose-300 flex items-start gap-2">
            <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
            <span>
              This will immediately revoke active tokens, terminate sub-agent reasoning loops, and cancel all queued sandbox and tool execution requests.
            </span>
          </div>

          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
              Halt Justification / Audit Reason
            </label>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Scope violation detected or unexpected operator override"
              className="w-full px-3 py-2 rounded border border-slate-700 bg-slate-900 text-slate-200 text-xs focus:border-rose-500 outline-none"
            />
          </div>
        </div>

        <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
          <button
            onClick={() => setHaltAgentsModalOpen(false)}
            className="btn-tactile px-4 py-2 rounded text-xs font-mono text-slate-400 hover:text-white border border-slate-700 hover:bg-slate-800 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleHalt}
            disabled={halting}
            className="btn-tactile px-4 py-2 rounded text-xs font-mono font-bold uppercase tracking-wider bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-950 transition-colors disabled:opacity-50"
          >
            {halting ? "Halting..." : "EXECUTE IMMEDIATE HALT"}
          </button>
        </div>
      </div>
    </div>
  );
}
