"use client";

import React from "react";
import { Target, PlusCircle, ArrowRight, ShieldCheck } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { getEngagements } from "@/lib/api";
import { StatusBadge } from "@/components/ui/StatusBadge";
import Link from "next/link";

export default function AssessmentsListPage() {
  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: getEngagements,
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
            <Target className="w-5 h-5 text-cyan-400" />
            <span>ASSESSMENTS DIRECTORY</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Active and archived security assessments governed by immutable scope versions.
          </p>
        </div>
        <Link
          href="/assessments/create"
          className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-black font-mono text-xs font-bold tracking-wide flex items-center gap-1.5 transition-colors"
        >
          <PlusCircle className="w-4 h-4" /> Create Assessment
        </Link>
      </div>

      {/* Engagements Grid / Table */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {engagements && engagements.length > 0 ? (
          engagements.map((eng) => (
            <div
              key={eng.id}
              className="p-5 rounded-xl border border-slate-800 bg-[#0b152b] hover:border-slate-700 transition-all flex flex-col justify-between space-y-4"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono text-slate-500">ID: {eng.id.slice(0, 8)}...</span>
                  <StatusBadge status={eng.status} size="sm" />
                </div>
                <h3 className="font-mono text-sm font-bold text-white mb-1">{eng.name}</h3>
                <p className="text-xs text-slate-400 line-clamp-2">{eng.objective || "Standard security assessment."}</p>
              </div>

              <div className="space-y-3 pt-3 border-t border-slate-800/80 text-xs font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>Scope Mode:</span>
                  <span className="text-emerald-400 flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5" /> Immutable v1
                  </span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Target:</span>
                  <span className="text-slate-200">http://127.0.0.1:3000</span>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <Link
                    href="/"
                    className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
                  >
                    Open Console <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="col-span-full p-8 text-center border border-slate-800 rounded-xl bg-[#0b152b] text-slate-400 text-xs font-mono space-y-3">
            <Target className="w-8 h-8 text-slate-600 mx-auto" />
            <div>No active engagements found.</div>
            <Link
              href="/assessments/create"
              className="inline-block px-4 py-2 rounded bg-cyan-600 text-black font-bold text-xs"
            >
              Launch First Assessment
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
