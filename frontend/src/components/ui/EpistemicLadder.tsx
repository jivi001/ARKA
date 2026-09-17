import React from "react";
import { Check, ShieldCheck, UserCheck, Eye, HelpCircle } from "lucide-react";
import type { EpistemicStage } from "@/lib/types";

interface EpistemicLadderProps {
  currentStage: EpistemicStage;
  deterministicValidated?: boolean;
  humanConfirmedBy?: string;
  className?: string;
}

const STAGES: { stage: EpistemicStage; label: string; desc: string; icon: React.ReactNode }[] = [
  { stage: "OBSERVED", label: "Observed", desc: "Raw Telemetry", icon: <Eye className="w-3.5 h-3.5" /> },
  { stage: "CANDIDATE", label: "Candidate", desc: "Untrusted Hypothesis", icon: <HelpCircle className="w-3.5 h-3.5" /> },
  { stage: "SUPPORTED", label: "Supported", desc: "Corroborated Telemetry", icon: <Check className="w-3.5 h-3.5" /> },
  { stage: "VALIDATED", label: "Validated", desc: "Deterministic Check", icon: <ShieldCheck className="w-3.5 h-3.5" /> },
  { stage: "HUMAN_CONFIRMED", label: "Confirmed", desc: "Operator Sign-off", icon: <UserCheck className="w-3.5 h-3.5" /> },
];

export function EpistemicLadder({
  currentStage,
  deterministicValidated = false,
  humanConfirmedBy,
  className = "",
}: EpistemicLadderProps) {
  const currentIndex = STAGES.findIndex((s) => s.stage === currentStage);

  return (
    <div className={`p-3 rounded-lg border border-slate-800 bg-[#0b152b] ${className}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] font-mono tracking-wider text-slate-400 uppercase font-semibold">
          Epistemic Verification Ladder
        </span>
        <div className="flex items-center gap-2">
          {deterministicValidated && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-950/40 text-emerald-400">
              Deterministic Verification Pass
            </span>
          )}
          {humanConfirmedBy && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-purple-500/40 bg-purple-950/40 text-purple-300">
              Confirmed by: {humanConfirmedBy}
            </span>
          )}
        </div>
      </div>

      {/* Steps visualization */}
      <div className="grid grid-cols-5 gap-2 relative">
        {STAGES.map((s, idx) => {
          const isCurrent = idx === currentIndex;
          const isPassed = idx < currentIndex;

          let badgeStyle = "border-slate-800 bg-slate-900/60 text-slate-500";
          if (isCurrent) {
            if (s.stage === "HUMAN_CONFIRMED") badgeStyle = "border-purple-500 bg-purple-950 text-purple-300 shadow-sm shadow-purple-500/20";
            else if (s.stage === "VALIDATED") badgeStyle = "border-emerald-500 bg-emerald-950 text-emerald-300 shadow-sm shadow-emerald-500/20";
            else if (s.stage === "SUPPORTED") badgeStyle = "border-cyan-500 bg-cyan-950 text-cyan-300";
            else badgeStyle = "border-amber-500 bg-amber-950 text-amber-300";
          } else if (isPassed) {
            badgeStyle = "border-emerald-700/60 bg-emerald-950/30 text-emerald-400";
          }

          return (
            <div
              key={s.stage}
              className={`flex flex-col p-2 rounded border transition-all ${badgeStyle}`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono font-bold">{idx + 1}. {s.label}</span>
                {s.icon}
              </div>
              <span className="text-[9px] text-slate-400 truncate">{s.desc}</span>
            </div>
          );
        })}
      </div>
      <div className="mt-2 text-[10px] text-slate-500 font-mono flex items-center justify-between border-t border-slate-800/80 pt-1.5">
        <span>Invariable Rule: LLM reasoning cannot promote to VALIDATED or CONFIRMED.</span>
        <span className="text-cyan-400 font-semibold">Active: {currentStage}</span>
      </div>
    </div>
  );
}
