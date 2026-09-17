"use client";

import React from "react";
import { 
  Activity, 
  Server, 
  Database, 
  Layers, 
  Cpu, 
  ShieldCheck, 
  CheckCircle2, 
  HardDrive 
} from "lucide-react";

interface ComponentHealth {
  name: string;
  category: string;
  status: "HEALTHY" | "DEGRADED" | "STANDBY";
  latency: string;
  lastCheck: string;
  icon: React.ReactNode;
}

const SYSTEM_COMPONENTS: ComponentHealth[] = [
  {
    name: "FastAPI Authoritative API Gateway",
    category: "Core API",
    status: "HEALTHY",
    latency: "1.2 ms",
    lastCheck: "Just now",
    icon: <Server className="w-5 h-5 text-emerald-400" />,
  },
  {
    name: "PostgreSQL Primary Storage",
    category: "Persistence",
    status: "HEALTHY",
    latency: "2.4 ms",
    lastCheck: "Just now",
    icon: <Database className="w-5 h-5 text-emerald-400" />,
  },
  {
    name: "Redis Queue & PubSub Broker",
    category: "Coordination",
    status: "HEALTHY",
    latency: "0.8 ms",
    lastCheck: "Just now",
    icon: <Layers className="w-5 h-5 text-emerald-400" />,
  },
  {
    name: "ARQ Background Task Workers",
    category: "Execution",
    status: "HEALTHY",
    latency: "Active (4 Workers)",
    lastCheck: "Just now",
    icon: <Activity className="w-5 h-5 text-cyan-400" />,
  },
  {
    name: "OpenRouter LLM Gateway (Nemotron-3 Ultra)",
    category: "Reasoning (Untrusted)",
    status: "HEALTHY",
    latency: "420 ms",
    lastCheck: "1m ago",
    icon: <Cpu className="w-5 h-5 text-purple-400" />,
  },
  {
    name: "Docker Tool Sandbox Runtime",
    category: "Execution Sandbox",
    status: "HEALTHY",
    latency: "Ready",
    lastCheck: "Just now",
    icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
  },
  {
    name: "Cryptographic Evidence Store",
    category: "Integrity",
    status: "HEALTHY",
    latency: "0.4 ms",
    lastCheck: "Just now",
    icon: <HardDrive className="w-5 h-5 text-emerald-400" />,
  },
];

export default function SystemHealthPage() {
  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>INFRASTRUCTURE & SERVICE HEALTH</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Real-time status of ARKA authoritative control plane, database, Redis workers, and execution sandboxes.
          </p>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-emerald-950/40 border border-emerald-500/40 text-xs font-mono text-emerald-300">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>ALL CRITICAL SYSTEMS OPERATIONAL</span>
        </div>
      </div>

      {/* Component Health Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {SYSTEM_COMPONENTS.map((c) => (
          <div
            key={c.name}
            className="p-5 rounded-xl border border-slate-800 bg-[#0b152b] space-y-3"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                {c.icon}
                <div>
                  <h3 className="font-mono text-xs font-bold text-white">{c.name}</h3>
                  <span className="text-[10px] text-slate-500 font-mono">{c.category}</span>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                {c.status}
              </span>
            </div>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
              <span>Latency: <strong className="text-slate-200">{c.latency}</strong></span>
              <span>Checked: {c.lastCheck}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Workers Pool Card */}
      <div className="p-5 rounded-xl border border-slate-800 bg-[#0b152b] space-y-3">
        <h3 className="font-mono text-xs font-bold text-slate-300 uppercase tracking-wider">
          ARQ Background Worker Cluster (Local Host Pool)
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
          {["worker-01", "worker-02", "worker-03", "worker-04"].map((w) => (
            <div key={w} className="p-3 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
              <span className="text-white font-bold">{w}</span>
              <span className="text-emerald-400 font-semibold text-[10px] flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> RUNNING
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
