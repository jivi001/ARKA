import React from "react";
import { ShieldAlert, AlertOctagon, AlertTriangle, Info } from "lucide-react";
import type { RiskLevel } from "@/lib/types";

interface RiskBadgeProps {
  risk: RiskLevel | string;
  size?: "sm" | "md";
}

export function RiskBadge({ risk, size = "md" }: RiskBadgeProps) {
  const norm = (risk || "LOW").toUpperCase();
  const isSm = size === "sm";

  const configs: Record<string, { bg: string; border: string; text: string; icon: React.ReactNode }> = {
    CRITICAL: {
      bg: "bg-rose-950/60",
      border: "border-rose-500/50",
      text: "text-rose-400",
      icon: <AlertOctagon className={isSm ? "w-3 h-3 text-rose-400" : "w-3.5 h-3.5 text-rose-400"} />,
    },
    HIGH: {
      bg: "bg-orange-950/60",
      border: "border-orange-500/50",
      text: "text-orange-400",
      icon: <ShieldAlert className={isSm ? "w-3 h-3 text-orange-400" : "w-3.5 h-3.5 text-orange-400"} />,
    },
    MEDIUM: {
      bg: "bg-amber-950/60",
      border: "border-amber-500/50",
      text: "text-amber-300",
      icon: <AlertTriangle className={isSm ? "w-3 h-3 text-amber-300" : "w-3.5 h-3.5 text-amber-300"} />,
    },
    LOW: {
      bg: "bg-emerald-950/50",
      border: "border-emerald-500/40",
      text: "text-emerald-400",
      icon: <Info className={isSm ? "w-3 h-3 text-emerald-400" : "w-3.5 h-3.5 text-emerald-400"} />,
    },
    INFO: {
      bg: "bg-slate-900/80",
      border: "border-slate-700",
      text: "text-slate-400",
      icon: <Info className={isSm ? "w-3 h-3 text-slate-400" : "w-3.5 h-3.5 text-slate-400"} />,
    },
  };

  const c = configs[norm] || configs.LOW;

  return (
    <span
      className={`inline-flex items-center gap-1 font-mono font-bold tracking-wider rounded border ${c.bg} ${c.border} ${c.text} ${
        isSm ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-0.5 text-xs"
      }`}
    >
      {c.icon}
      {norm}
    </span>
  );
}
