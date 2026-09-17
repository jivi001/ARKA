"use client";

import React, { useState, useEffect } from "react";
import { 
  Shield, 
  AlertOctagon, 
  Bell, 
  Radio, 
  CheckCircle2, 
  User 
} from "lucide-react";
import { useConsoleStore } from "@/lib/store";
import { useQuery } from "@tanstack/react-query";
import { getEngagements } from "@/lib/api";
import Link from "next/link";

export function TopNav() {
  const { 
    activeEngagementId, 
    setActiveEngagementId, 
    alerts, 
    setHaltAgentsModalOpen 
  } = useConsoleStore();
  
  const [alertsOpen, setAlertsOpen] = useState(false);
  const [sseConnected, setSseConnected] = useState(false);

  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: getEngagements,
  });

  useEffect(() => {
    // Connect to SSE stream
    const sseUrl = activeEngagementId 
      ? `/api/engagements/${activeEngagementId}/stream`
      : "/api/stream";
    
    let eventSource: EventSource | null = null;
    try {
      eventSource = new EventSource(sseUrl);
      eventSource.onopen = () => setSseConnected(true);
      eventSource.onerror = () => setSseConnected(false);
    } catch {
      // EventSource failed to initialize
    }

    return () => {
      if (eventSource) eventSource.close();
    };
  }, [activeEngagementId]);

  return (
    <header className="h-14 border-b border-slate-800/80 glass-nav px-4 flex items-center justify-between sticky top-0 z-40">
      {/* Brand & Platform Mode */}
      <div className="flex items-center gap-4">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded bg-cyan-950/80 border border-cyan-500/50 flex items-center justify-center text-cyan-400 font-black tracking-wider text-sm shadow-sm shadow-cyan-500/20">
            <Shield className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-extrabold text-sm tracking-widest text-slate-100">
                ARKA
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-950/70 border border-cyan-500/40 text-cyan-300">
                CONTROL PLANE
              </span>
            </div>
            <p className="text-[10px] text-slate-500 font-mono tracking-tight hidden sm:block">
              Autonomous Risk Knowledge & Assessment
            </p>
          </div>
        </Link>

        {/* Active Engagement Switcher */}
        <div className="hidden md:flex items-center pl-4 border-l border-slate-800">
          <select
            value={activeEngagementId || ""}
            onChange={(e) => setActiveEngagementId(e.target.value || null)}
            aria-label="Select Active Assessment Engagement"
            className="px-2.5 py-1 rounded bg-[#0b152b] border border-slate-700/70 text-xs font-mono text-slate-200 outline-none focus:border-cyan-500"
          >
            <option value="">-- All Engagements Context --</option>
            {engagements?.map((eng) => (
              <option key={eng.id} value={eng.id}>
                {eng.name} ({eng.status})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Center / System Telemetry Indicators */}
      <div className="hidden lg:flex items-center gap-4 text-[11px] font-mono">
        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-900/60 border border-slate-800 text-slate-300">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>API: 127.0.0.1:8000</span>
        </div>
        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-900/60 border border-slate-800 text-slate-300">
          <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
          <span>ScopeGuard: ACTIVE</span>
        </div>
        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-900/60 border border-slate-800 text-slate-300">
          <Radio className={`w-3 h-3 ${sseConnected ? "text-cyan-400 animate-pulse" : "text-slate-500"}`} />
          <span className={sseConnected ? "text-cyan-400" : "text-slate-500"}>
            {sseConnected ? "SSE LIVE" : "SSE STANDBY"}
          </span>
        </div>
      </div>

      {/* Right Controls: Emergency Halt, Alerts, Profile */}
      <div className="flex items-center gap-3">
        {/* Tactical Emergency Killswitch */}
        <button
          onClick={() => setHaltAgentsModalOpen(true)}
          className="btn-tactile flex items-center gap-1.5 px-3 py-1 rounded border border-rose-500/50 bg-rose-950/40 text-rose-300 hover:bg-rose-900/60 hover:text-white transition-all text-xs font-mono font-bold tracking-wider shadow-sm shadow-rose-950/80"
        >
          <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
          <span className="hidden sm:inline">HALT AGENTS</span>
        </button>

        {/* System Alerts */}
        <div className="relative">
          <button
            onClick={() => setAlertsOpen(!alertsOpen)}
            className="btn-tactile p-1.5 rounded border border-slate-800 bg-[#0b152b] text-slate-300 hover:text-white relative"
          >
            <Bell className="w-4 h-4" />
            {alerts.length > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-cyan-500 text-[9px] font-bold text-black flex items-center justify-center">
                {alerts.length}
              </span>
            )}
          </button>

          {alertsOpen && (
            <div className="absolute right-0 mt-2 w-80 rounded-lg border border-slate-700 bg-[#0b152b] shadow-2xl z-50 p-3 text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800 font-mono font-semibold text-slate-300">
                <span>Security Events ({alerts.length})</span>
                <span className="text-[10px] text-cyan-400">Live Buffer</span>
              </div>
              <div className="max-h-64 overflow-y-auto space-y-2 mt-2">
                {alerts.map((a) => (
                  <div key={a.id} className="p-2 rounded bg-slate-900/80 border border-slate-800/80">
                    <div className="flex items-center justify-between text-[10px] font-mono text-cyan-400">
                      <span>{a.title}</span>
                      <span className="text-slate-500">{a.timestamp}</span>
                    </div>
                    <p className="text-[11px] text-slate-300 mt-1">{a.message}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Operator Badge */}
        <div className="flex items-center gap-2 pl-3 border-l border-slate-800 text-xs font-mono">
          <div className="w-7 h-7 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
            <User className="w-3.5 h-3.5" />
          </div>
          <div className="hidden xl:block leading-tight">
            <div className="text-slate-200 font-semibold">Lead Operator</div>
            <div className="text-[10px] text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-2.5 h-2.5" /> AUTHORITATIVE
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
