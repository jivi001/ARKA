"use client";

import React, { useState, useCallback, useMemo } from "react";
import { 
  Network, 
  X, 
  Bug, 
  Globe, 
  Server, 
  Code 
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { getEngagements, getGraph } from "@/lib/api";
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { RiskBadge } from "@/components/ui/RiskBadge";

interface GraphNodeData extends Record<string, unknown> {
  label: string;
  nodeType?: string;
  authorization?: string;
  severity?: "critical" | "high" | "medium" | "low" | "info";
  lifecycle_stage?: string;
  port?: number;
  protocol?: string;
}

export default function AttackGraphPage() {
  const [selectedNode, setSelectedNode] = useState<Node<GraphNodeData> | null>(null);
  const [filterType, setFilterType] = useState<string>("all");

  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: getEngagements,
  });

  const activeEngagement = engagements?.[0];

  const { data: graphData } = useQuery({
    queryKey: ["graph", activeEngagement?.id],
    queryFn: () => (activeEngagement ? getGraph(activeEngagement.id) : Promise.resolve({ nodes: [], edges: [], stats: { assets: 0, services: 0, endpoints: 0, findings: 0 } })),
    enabled: !!activeEngagement,
  });

  // Convert raw nodes to React Flow nodes with custom styles
  const flowNodes: Node<GraphNodeData>[] = useMemo(() => {
    if (!graphData?.nodes) return [];
    return graphData.nodes
      .filter((n) => filterType === "all" || n.type === filterType)
      .map((n) => {
        let border = "#334155";
        let bg = "#0b152b";
        const text = "#f8fafc";

        if (n.type === "asset") {
          border = n.data?.authorization === "AUTHORIZED" ? "#10b981" : "#64748b";
        } else if (n.type === "service") {
          border = "#38bdf8";
        } else if (n.type === "endpoint") {
          border = "#818cf8";
        } else if (n.type === "finding") {
          border = "#ff716c";
          bg = "#1f121a";
        }

        const nodeData: GraphNodeData = {
          ...n.data,
          label: String(n.data.label || n.id),
          nodeType: n.type,
        };

        return {
          id: n.id,
          position: n.position,
          data: nodeData,
          style: {
            background: bg,
            border: `1.5px solid ${border}`,
            borderRadius: "8px",
            color: text,
            padding: "8px 12px",
            fontSize: "11px",
            fontFamily: "monospace",
            boxShadow: "0 4px 12px rgba(0, 0, 0, 0.5)",
          },
        };
      });
  }, [graphData, filterType]);

  const flowEdges: Edge[] = useMemo(() => {
    if (!graphData?.edges) return [];
    return graphData.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: e.animated,
      style: { stroke: "#475569", strokeWidth: 1.5, ...(e.style || {}) },
      labelStyle: { fill: "#94a3b8", fontSize: "10px", fontFamily: "monospace" },
    }));
  }, [graphData]);

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(node as Node<GraphNodeData>);
  }, []);

  return (
    <div className="space-y-4 max-w-7xl mx-auto h-[calc(100vh-6.5rem)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800 shrink-0">
        <div>
          <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            <span>GRAPHIFY / ATTACK RELATIONSHIP GRAPH</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Canonical topology of assets, services, exposed endpoints, and validated risk paths.
          </p>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Filter:</span>
          {(["all", "asset", "service", "endpoint", "finding"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={`px-2.5 py-1 rounded text-xs font-mono capitalize transition-colors ${
                filterType === t
                  ? "bg-cyan-600 text-black font-bold"
                  : "bg-slate-900 border border-slate-800 text-slate-400 hover:text-white"
              }`}
            >
              {t === "all" ? "All Nodes" : `${t}s`}
            </button>
          ))}
        </div>
      </div>

      {/* Main Flow Canvas & Inspector Drawer */}
      <div className="flex-1 rounded-xl border border-slate-800 bg-[#060e20] relative overflow-hidden flex">
        <div className="flex-1 h-full">
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            onNodeClick={onNodeClick}
            fitView
            attributionPosition="bottom-left"
          >
            <Background color="#1e293b" gap={20} size={1} />
            <Controls className="bg-slate-900 border border-slate-800 fill-slate-300 text-slate-300" />
          </ReactFlow>
        </div>

        {/* Node Inspector Drawer */}
        {selectedNode && (
          <div className="w-80 border-l border-slate-800 bg-[#0b152b] p-4 flex flex-col justify-between shadow-2xl z-20 overflow-y-auto">
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  {selectedNode.data.nodeType === "asset" && <Globe className="w-4 h-4 text-emerald-400" />}
                  {selectedNode.data.nodeType === "service" && <Server className="w-4 h-4 text-cyan-400" />}
                  {selectedNode.data.nodeType === "endpoint" && <Code className="w-4 h-4 text-indigo-400" />}
                  {selectedNode.data.nodeType === "finding" && <Bug className="w-4 h-4 text-rose-400" />}
                  <span className="font-mono text-xs font-bold text-white uppercase">
                    {selectedNode.data.nodeType} Inspector
                  </span>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div>
                  <span className="text-slate-500 text-[10px] block">LABEL / IDENTIFIER</span>
                  <span className="text-white font-bold">{selectedNode.data.label}</span>
                </div>

                {selectedNode.data.authorization && (
                  <div>
                    <span className="text-slate-500 text-[10px] block mb-1">AUTHORIZATION</span>
                    <StatusBadge status={selectedNode.data.authorization} size="sm" />
                  </div>
                )}

                {selectedNode.data.severity && (
                  <div>
                    <span className="text-slate-500 text-[10px] block mb-1">SEVERITY</span>
                    <RiskBadge risk={selectedNode.data.severity} size="sm" />
                  </div>
                )}

                {selectedNode.data.lifecycle_stage && (
                  <div>
                    <span className="text-slate-500 text-[10px] block">EPISTEMIC STAGE</span>
                    <span className="text-purple-300 font-bold">{selectedNode.data.lifecycle_stage}</span>
                  </div>
                )}

                {selectedNode.data.port && (
                  <div>
                    <span className="text-slate-500 text-[10px] block">PORT / PROTOCOL</span>
                    <span className="text-cyan-300 font-bold">:{selectedNode.data.port} ({selectedNode.data.protocol})</span>
                  </div>
                )}
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800">
              <div className="text-[10px] font-mono text-slate-500">
                Canonical graph node linked to PostgreSQL entity.
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
