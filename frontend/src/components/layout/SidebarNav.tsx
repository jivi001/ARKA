"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  LayoutDashboard, 
  Target, 
  PlusCircle, 
  CheckSquare, 
  Layers, 
  Bug, 
  Network, 
  Sliders, 
  FileText, 
  ScrollText, 
  Activity,
  Bot
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { getApprovals } from "@/lib/api";

const NAV_ITEMS = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "Assessments", href: "/assessments", icon: Target },
  { name: "Create Assessment", href: "/assessments/create", icon: PlusCircle },
  { name: "Approvals Center", href: "/approvals", icon: CheckSquare, badge: "approvals" },
  { name: "Attack Surface", href: "/attack-surface", icon: Layers },
  { name: "Findings", href: "/findings", icon: Bug },
  { name: "Attack Graph", href: "/graph", icon: Network },
  { name: "Autonomous Ops", href: "/operations", icon: Bot },
  { name: "Configuration", href: "/configuration", icon: Sliders },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Audit Log", href: "/audit", icon: ScrollText },
  { name: "System Health", href: "/health", icon: Activity },
];

export function SidebarNav() {
  const pathname = usePathname();

  const { data: approvals } = useQuery({
    queryKey: ["approvals-pending-count"],
    queryFn: () => getApprovals({ status: "PENDING" }),
    refetchInterval: 5000,
  });

  const pendingCount = approvals?.length || 0;

  return (
    <aside className="w-56 border-r border-slate-800/80 bg-[#060e20] flex flex-col shrink-0 min-h-[calc(100vh-3.5rem)] select-none">
      <div className="p-3 space-y-1">
        <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold">
          Navigation
        </div>
        {NAV_ITEMS.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;

          return (
            <Link
              key={item.name}
              href={item.href}
              className={`btn-tactile flex items-center justify-between px-3 py-2 rounded text-xs font-mono transition-colors ${
                isActive
                  ? "bg-cyan-950/60 border border-cyan-500/40 text-cyan-300 font-semibold shadow-sm shadow-cyan-500/10"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 ${isActive ? "text-cyan-400" : "text-slate-500"}`} />
                <span>{item.name}</span>
              </div>
              {item.badge === "approvals" && pendingCount > 0 && (
                <span className="px-1.5 py-0.5 rounded-full bg-amber-500 text-black font-bold text-[10px] animate-pulse">
                  {pendingCount}
                </span>
              )}
            </Link>
          );
        })}
      </div>

      <div className="mt-auto p-4 border-t border-slate-800/80">
        <div className="p-2.5 rounded bg-[#0b152b] border border-slate-800 text-[10px] font-mono text-slate-400 space-y-1">
          <div className="text-slate-300 font-semibold flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            Deterministic Plane
          </div>
          <div>Invariable Control: ON</div>
          <div>SSRF Filter: ACTIVE</div>
          <div className="text-[9px] text-slate-500 pt-1 border-t border-slate-800">
            LLM has 0 Execution Authority
          </div>
        </div>
      </div>
    </aside>
  );
}
