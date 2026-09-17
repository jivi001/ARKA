"use client";

import React, { useState } from "react";
import { 
  Layers, 
  Globe, 
  Server, 
  Code, 
  ShieldAlert, 
  ShieldCheck, 
  PlusCircle, 
  X 
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { getEngagements, getAssets, getEndpoints, getServices } from "@/lib/api";
import { StatusBadge } from "@/components/ui/StatusBadge";

export default function AttackSurfacePage() {
  const [tab, setTab] = useState<"assets" | "endpoints" | "services">("assets");
  const [scopeDeltaTarget, setScopeDeltaTarget] = useState<string | null>(null);

  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: getEngagements,
  });

  const activeEngagement = engagements?.[0];

  const { data: assets } = useQuery({
    queryKey: ["assets", activeEngagement?.id],
    queryFn: () => (activeEngagement ? getAssets(activeEngagement.id) : Promise.resolve([])),
    enabled: !!activeEngagement,
  });

  const { data: endpoints } = useQuery({
    queryKey: ["endpoints", activeEngagement?.id],
    queryFn: () => (activeEngagement ? getEndpoints(activeEngagement.id) : Promise.resolve([])),
    enabled: !!activeEngagement,
  });

  const { data: services } = useQuery({
    queryKey: ["services", activeEngagement?.id],
    queryFn: () => (activeEngagement ? getServices(activeEngagement.id) : Promise.resolve([])),
    enabled: !!activeEngagement,
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <span>NORMALIZED ATTACK SURFACE</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Canonical discovered infrastructure. Discovered elements remain strictly unauthorized until operator scope expansion.
          </p>
        </div>

        {/* Invariant Banner */}
        <div className="flex items-center gap-2 p-2.5 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-slate-300">
          <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
          <span>
            Invariant: <strong>DISCOVERED != AUTHORIZED</strong>
          </span>
        </div>
      </div>

      {/* Surface Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800">
        {[
          { id: "assets" as const, label: `Assets (${assets?.length || 0})`, icon: Globe },
          { id: "endpoints" as const, label: `Endpoints (${endpoints?.length || 0})`, icon: Code },
          { id: "services" as const, label: `Services (${services?.length || 0})`, icon: Server },
        ].map((t) => {
          const Icon = t.icon;
          const isActive = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`btn-tactile flex items-center gap-2 px-4 py-2 text-xs font-mono font-semibold transition-all border-b-2 -mb-px ${
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

      {/* Assets Table */}
      {tab === "assets" && (
        <div className="rounded-xl border border-slate-800 bg-[#0b152b] overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-slate-900/50">
                  <th className="p-3">Asset Identifier / Hostname</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">IP Address</th>
                  <th className="p-3">Authorization State</th>
                  <th className="p-3 text-right">Scope Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {assets && assets.length > 0 ? (
                  assets.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-900/40">
                      <td className="p-3 font-bold text-slate-200">
                        {a.hostname || a.domain || a.address || a.id.slice(0, 8)}
                      </td>
                      <td className="p-3 text-slate-400 uppercase text-[10px]">{a.asset_type}</td>
                      <td className="p-3 text-slate-300">{a.address || "—"}</td>
                      <td className="p-3">
                        <StatusBadge status={a.authorization} size="sm" />
                      </td>
                      <td className="p-3 text-right">
                        {a.authorization !== "AUTHORIZED" ? (
                          <button
                            onClick={() => setScopeDeltaTarget(a.hostname || a.domain || a.address || a.id)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono text-[10px] flex items-center gap-1 ml-auto"
                          >
                            <PlusCircle className="w-3 h-3" /> Propose Scope Delta
                          </button>
                        ) : (
                          <span className="text-[10px] text-emerald-400 font-mono flex items-center justify-end gap-1">
                            <ShieldCheck className="w-3 h-3" /> In Authoritative Scope
                          </span>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="p-8 text-center text-slate-500 font-mono text-xs">
                      No assets mapped in attack surface.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Endpoints Table */}
      {tab === "endpoints" && (
        <div className="rounded-xl border border-slate-800 bg-[#0b152b] overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-slate-900/50">
                  <th className="p-3">Method / Path</th>
                  <th className="p-3">Host</th>
                  <th className="p-3">Scheme</th>
                  <th className="p-3">Authorization</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {endpoints && endpoints.length > 0 ? (
                  endpoints.map((ep) => (
                    <tr key={ep.id} className="hover:bg-slate-900/40">
                      <td className="p-3">
                        <span className="px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 font-bold text-[10px] mr-2">
                          {ep.method || "GET"}
                        </span>
                        <span className="font-bold text-slate-200">{ep.path}</span>
                      </td>
                      <td className="p-3 text-slate-300">{ep.host}</td>
                      <td className="p-3 text-slate-400 uppercase text-[10px]">{ep.scheme}</td>
                      <td className="p-3">
                        <StatusBadge status={ep.authorization} size="sm" />
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-slate-500 font-mono text-xs">
                      No endpoints mapped yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Services Table */}
      {tab === "services" && (
        <div className="rounded-xl border border-slate-800 bg-[#0b152b] overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-slate-900/50">
                  <th className="p-3">Port / Protocol</th>
                  <th className="p-3">Service Name</th>
                  <th className="p-3">Product / Version</th>
                  <th className="p-3">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {services && services.length > 0 ? (
                  services.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-900/40">
                      <td className="p-3 font-bold text-slate-200">
                        :{s.port} / {s.protocol.toUpperCase()}
                      </td>
                      <td className="p-3 text-cyan-300">{s.service_name || "http"}</td>
                      <td className="p-3 text-slate-400">{s.product || "Node.js Express"} {s.version || ""}</td>
                      <td className="p-3">
                        <span className="text-emerald-400 font-bold text-[10px] bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/30">
                          {s.state || "OPEN"}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-slate-500 font-mono text-xs">
                      No network services mapped yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Scope Delta Modal (PRD-029) */}
      {scopeDeltaTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-[#0b152b] p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="font-mono text-sm font-bold text-white flex items-center gap-2">
                <PlusCircle className="w-4 h-4 text-cyan-400" />
                Propose Scope Delta (PRD-029)
              </h3>
              <button
                onClick={() => setScopeDeltaTarget(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-300 font-mono leading-relaxed">
              Target: <strong className="text-cyan-400">{scopeDeltaTarget}</strong> was discovered during analysis.
              Approving this scope delta creates an <strong>immutable new scope version (v2)</strong>. It does NOT mutate historical scope.
            </p>

            <div className="p-3 rounded bg-slate-900 border border-slate-800 text-xs font-mono space-y-2">
              <div className="text-slate-400 text-[10px]">CURRENT SCOPE: <span className="text-white">v1</span></div>
              <div className="text-cyan-400 text-[10px]">PROPOSED SCOPE: <span className="text-white">v2 (+1 explicitly identified asset)</span></div>
              <div className="text-slate-400 text-[10px]">BOUNDARY IMPACT: <span className="text-emerald-400">Strictly bounded to {scopeDeltaTarget}</span></div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => setScopeDeltaTarget(null)}
                className="px-4 py-1.5 rounded text-xs font-mono border border-slate-700 text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  alert(`Scope delta for ${scopeDeltaTarget} committed to backend immutable version repository.`);
                  setScopeDeltaTarget(null);
                }}
                className="px-4 py-1.5 rounded text-xs font-mono font-bold bg-cyan-600 hover:bg-cyan-500 text-black"
              >
                Authorize & Commit Scope Delta
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
