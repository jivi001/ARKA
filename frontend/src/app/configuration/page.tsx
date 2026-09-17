"use client";

import React, { useState } from "react";
import { 
  Sliders, 
  Cpu, 
  Bot, 
  ShieldCheck, 
  Wrench, 
  Scale, 
  Lock, 
  RefreshCw 
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { getConfiguration } from "@/lib/api";
import type { SystemConfiguration } from "@/lib/types";

export default function ConfigurationCenterPage() {
  const [activeTab, setActiveTab] = useState<"providers" | "agents" | "policy" | "tools" | "budgets" | "invariants">("providers");

  const { data: config, refetch } = useQuery<SystemConfiguration>({
    queryKey: ["system-configuration"],
    queryFn: getConfiguration,
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
            <Sliders className="w-5 h-5 text-cyan-400" />
            <span>CENTRALIZED CONFIGURATION CENTER</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Authoritative platform settings, LLM gateway models, tool registries, and deterministic policy matrices.
          </p>
        </div>

        <button
          onClick={() => refetch()}
          className="btn-tactile px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 flex items-center gap-1.5 border border-slate-700"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Reload Config
        </button>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 overflow-x-auto">
        {[
          { id: "providers" as const, label: "LLM Providers", icon: Cpu },
          { id: "agents" as const, label: "Agent Specs", icon: Bot },
          { id: "policy" as const, label: "Policy Matrix", icon: ShieldCheck },
          { id: "tools" as const, label: "Tool Registry", icon: Wrench },
          { id: "budgets" as const, label: "Resource Budgets", icon: Scale },
          { id: "invariants" as const, label: "Security Invariants", icon: Lock },
        ].map((t) => {
          const Icon = t.icon;
          const isActive = activeTab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`btn-tactile flex items-center gap-2 px-4 py-2 text-xs font-mono font-semibold transition-all border-b-2 -mb-px shrink-0 ${
                isActive
                  ? "border-cyan-400 text-cyan-300 bg-slate-900/40"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab: LLM Providers */}
      {activeTab === "providers" && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {config?.providers.map((p) => (
              <div key={p.id} className="p-5 rounded-xl border border-slate-800 bg-[#0b152b] space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-cyan-400" />
                    <span className="font-mono font-bold text-white text-sm">{p.name}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                    {p.status}
                  </span>
                </div>

                <div className="space-y-1.5 text-xs font-mono">
                  <div className="flex justify-between text-slate-400">
                    <span>Model:</span>
                    <span className="text-cyan-300 font-bold">{p.model}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Active Latency:</span>
                    <span className="text-slate-200">{p.latency_ms} ms</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>API Key Isolation:</span>
                    <span className="text-emerald-400">•••••••••••••••• (Secured in Vault)</span>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800 flex flex-wrap gap-1.5">
                  {p.capabilities.map((c) => (
                    <span key={c} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                      ✓ {c}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab: Agent Configuration */}
      {activeTab === "agents" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {config?.agents.map((ag) => (
            <div key={ag.id} className="p-5 rounded-xl border border-slate-800 bg-[#0b152b] space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Bot className="w-5 h-5 text-purple-400" />
                  <span className="font-mono font-bold text-white text-sm">{ag.name}</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-500/30">
                  {ag.enabled ? "ENABLED" : "DISABLED"}
                </span>
              </div>

              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>Max Concurrency:</span>
                  <span className="text-slate-200">{ag.concurrency}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Max Runtime:</span>
                  <span className="text-slate-200">{ag.max_runtime_sec}s</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Max Iterations:</span>
                  <span className="text-slate-200">{ag.max_iterations}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Execution Authority:</span>
                  <span className="text-rose-400 font-bold">{ag.execution_authority}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab: Policy Matrix */}
      {activeTab === "policy" && (
        <div className="rounded-xl border border-slate-800 bg-[#0b152b] overflow-hidden">
          <div className="p-4 border-b border-slate-800 bg-slate-900/40 text-xs font-mono text-slate-300">
            Deterministic Decision Matrix: Mapping of security tool operations to risk level constraints.
          </div>
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-slate-900/60">
                <th className="p-3">Security Tool</th>
                <th className="p-3">LOW Risk</th>
                <th className="p-3">MEDIUM Risk</th>
                <th className="p-3">HIGH Risk</th>
                <th className="p-3">CRITICAL Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {config?.policy_matrix.map((row) => (
                <tr key={row.tool} className="hover:bg-slate-900/40">
                  <td className="p-3 font-bold text-white">{row.tool}</td>
                  <td className="p-3">
                    <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-emerald-950/40 text-emerald-400 border border-emerald-500/30">
                      {row.low}
                    </span>
                  </td>
                  <td className="p-3">
                    <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-emerald-950/40 text-emerald-400 border border-emerald-500/30">
                      {row.medium}
                    </span>
                  </td>
                  <td className="p-3">
                    <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-amber-950/40 text-amber-300 border border-amber-500/30">
                      {row.high}
                    </span>
                  </td>
                  <td className="p-3">
                    <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-rose-950/40 text-rose-400 border border-rose-500/30">
                      {row.critical}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab: Tools */}
      {activeTab === "tools" && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {config?.tools.map((t) => (
            <div key={t.name} className="p-4 rounded-xl border border-slate-800 bg-[#0b152b] space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white text-sm">{t.name}</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                  {t.status}
                </span>
              </div>
              <p className="text-slate-400 text-[11px]">{t.description}</p>
              <div className="pt-2 border-t border-slate-800 flex justify-between text-slate-500 text-[10px]">
                <span>Risk: <strong className="text-amber-400">{t.risk}</strong></span>
                <span>Runtime: <strong className="text-slate-300">{t.runtime}</strong></span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab: Resource Budgets */}
      {activeTab === "budgets" && config && (
        <div className="p-5 rounded-xl border border-slate-800 bg-[#0b152b] space-y-4 max-w-2xl">
          <h3 className="font-mono text-sm font-bold text-white uppercase tracking-wider">
            Deterministic Resource Budgets
          </h3>
          <p className="text-xs text-slate-400 font-mono">
            Enforced at the Python / FastAPI runtime level. Sub-agents cannot increase these limits.
          </p>

          <div className="space-y-2 text-xs font-mono">
            {Object.entries(config.budgets).map(([k, v]) => (
              <div key={k} className="flex justify-between py-2 border-b border-slate-800/80">
                <span className="text-slate-400 capitalize">{k.replace(/_/g, " ")}</span>
                <span className="text-cyan-300 font-bold">{String(v)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab: Security Invariants */}
      {activeTab === "invariants" && config && (
        <div className="space-y-3 max-w-3xl">
          {Object.entries(config.invariants).map(([inv, desc]) => (
            <div key={inv} className="p-4 rounded-xl border border-slate-800 bg-[#0b152b] space-y-1">
              <div className="font-mono font-bold text-sm text-cyan-400">{inv}</div>
              <div className="text-xs text-slate-300 font-mono">{String(desc)}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
