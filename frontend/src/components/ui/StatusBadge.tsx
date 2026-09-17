import React from "react";
import { ShieldCheck, ShieldAlert, AlertTriangle, Play, CheckCircle2, UserCheck, Ban, Clock } from "lucide-react";

export type SecurityState = 
  | "AUTHORIZED" 
  | "DISCOVERED — NOT AUTHORIZED" 
  | "DENIED" 
  | "WAITING FOR APPROVAL" 
  | "EXECUTING" 
  | "VALIDATED" 
  | "HUMAN CONFIRMED"
  | "PENDING"
  | "ACTIVE"
  | "PAUSED"
  | "STOPPED";

interface StatusBadgeProps {
  status: string;
  size?: "sm" | "md";
  className?: string;
}

export function StatusBadge({ status, size = "md", className = "" }: StatusBadgeProps) {
  const norm = status.toUpperCase().trim();
  const isSm = size === "sm";

  if (norm.includes("AUTHORIZED") && !norm.includes("NOT AUTHORIZED")) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-mono uppercase tracking-wider rounded border border-emerald-500/30 bg-emerald-950/40 text-emerald-400 font-semibold ${isSm ? "px-1.5 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs"} ${className}`}>
        <ShieldCheck className={isSm ? "w-3 h-3 text-emerald-400" : "w-3.5 h-3.5 text-emerald-400"} />
        AUTHORIZED
      </span>
    );
  }

  if (norm.includes("NOT AUTHORIZED") || norm.includes("DISCOVERED")) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-mono uppercase tracking-wider rounded border border-slate-700 bg-slate-900/60 text-slate-400 font-medium ${isSm ? "px-1.5 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs"} ${className}`}>
        <ShieldAlert className={isSm ? "w-3 h-3 text-slate-400" : "w-3.5 h-3.5 text-slate-400"} />
        DISCOVERED — NOT AUTHORIZED
      </span>
    );
  }

  if (norm.includes("DENIED") || norm.includes("BLOCKED")) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-mono uppercase tracking-wider rounded border border-rose-500/40 bg-rose-950/40 text-rose-400 font-semibold ${isSm ? "px-1.5 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs"} ${className}`}>
        <Ban className={isSm ? "w-3 h-3 text-rose-400" : "w-3.5 h-3.5 text-rose-400"} />
        DENIED
      </span>
    );
  }

  if (norm.includes("APPROVAL") || norm.includes("WAITING") || norm === "PENDING") {
    return (
      <span className={`inline-flex items-center gap-1.5 font-mono uppercase tracking-wider rounded border border-amber-500/40 bg-amber-950/40 text-amber-300 font-semibold animate-pulse ${isSm ? "px-1.5 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs"} ${className}`}>
        <Clock className={isSm ? "w-3 h-3 text-amber-300" : "w-3.5 h-3.5 text-amber-300"} />
        WAITING FOR APPROVAL
      </span>
    );
  }

  if (norm.includes("EXECUTING") || norm.includes("ACTIVE") || norm.includes("RUNNING")) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-mono uppercase tracking-wider rounded border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 font-semibold ${isSm ? "px-1.5 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs"} ${className}`}>
        <Play className={isSm ? "w-3 h-3 fill-cyan-400 text-cyan-400" : "w-3.5 h-3.5 fill-cyan-400 text-cyan-400"} />
        EXECUTING
      </span>
    );
  }

  if (norm.includes("HUMAN CONFIRMED") || norm.includes("HUMAN_CONFIRMED")) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-mono uppercase tracking-wider rounded border border-purple-500/40 bg-purple-950/40 text-purple-300 font-semibold ${isSm ? "px-1.5 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs"} ${className}`}>
        <UserCheck className={isSm ? "w-3 h-3 text-purple-300" : "w-3.5 h-3.5 text-purple-300"} />
        HUMAN CONFIRMED
      </span>
    );
  }

  if (norm.includes("VALIDATED")) {
    return (
      <span className={`inline-flex items-center gap-1.5 font-mono uppercase tracking-wider rounded border border-emerald-500/40 bg-emerald-950/40 text-emerald-300 font-semibold ${isSm ? "px-1.5 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs"} ${className}`}>
        <CheckCircle2 className={isSm ? "w-3 h-3 text-emerald-300" : "w-3.5 h-3.5 text-emerald-300"} />
        VALIDATED
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1 font-mono uppercase tracking-wider rounded border border-slate-800 bg-slate-900 text-slate-400 ${isSm ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-0.5 text-xs"} ${className}`}>
      <AlertTriangle className="w-3 h-3 text-slate-500" />
      {status}
    </span>
  );
}
