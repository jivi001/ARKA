"use client";

import React, { useState } from "react";
import { 
  FileText, 
  Download 
} from "lucide-react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { getEngagements, generateReport } from "@/lib/api";

interface GeneratedReport {
  report_id: string;
  engagement_id: string;
  report_type: string;
  content_markdown: string;
  generated_at: string;
}

export default function ReportsPage() {
  const [reportType, setReportType] = useState<string>("executive_summary");
  const [includeEvidence, setIncludeEvidence] = useState(true);
  const [includeGraph, setIncludeGraph] = useState(true);
  const [includeRemediation, setIncludeRemediation] = useState(true);
  const [generatedReport, setGeneratedReport] = useState<GeneratedReport | null>(null);

  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: getEngagements,
  });

  const activeEngagement = engagements?.[0];

  const reportMutation = useMutation({
    mutationFn: () => {
      if (!activeEngagement) throw new Error("No active engagement found");
      return generateReport({
        engagement_id: activeEngagement.id,
        report_type: reportType,
        include_evidence: includeEvidence,
        include_graph: includeGraph,
        include_remediation: includeRemediation,
      });
    },
    onSuccess: (data) => {
      setGeneratedReport(data);
    },
  });

  const downloadMarkdown = () => {
    if (!generatedReport) return;
    const blob = new Blob([generatedReport.content_markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ARKA_Report_${generatedReport.report_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>EXECUTIVE & TECHNICAL REPORTING ENGINE</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Authoritative backend-compiled reports reflecting normalized attack surfaces, findings, and epistemic chains.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Report Generator Config */}
        <div className="p-5 rounded-xl border border-slate-800 bg-[#0b152b] space-y-4">
          <h2 className="font-mono text-xs font-bold text-slate-300 uppercase tracking-wider">
            Report Generation Parameters
          </h2>

          <div className="space-y-3 text-xs font-mono">
            <div>
              <label className="block text-slate-400 mb-1">Target Engagement</label>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-white font-bold">
                {activeEngagement?.name || "OWASP Juice Shop Assessment"}
              </div>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Report Archetype</label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-white outline-none focus:border-cyan-500"
              >
                <option value="executive_summary">Executive Summary</option>
                <option value="technical_assessment">Full Technical Assessment</option>
                <option value="finding_report">Epistemic Findings Report</option>
                <option value="evidence_appendix">Cryptographic Evidence Appendix</option>
              </select>
            </div>

            <div className="space-y-2 pt-2 border-t border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block font-bold">Artifact Sections</span>
              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeEvidence}
                  onChange={(e) => setIncludeEvidence(e.target.checked)}
                  className="accent-cyan-500"
                />
                <span>Include Normalized Evidence Chain</span>
              </label>

              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeGraph}
                  onChange={(e) => setIncludeGraph(e.target.checked)}
                  className="accent-cyan-500"
                />
                <span>Include Attack Surface Topology</span>
              </label>

              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeRemediation}
                  onChange={(e) => setIncludeRemediation(e.target.checked)}
                  className="accent-cyan-500"
                />
                <span>Include Remediation Advice</span>
              </label>
            </div>

            <button
              onClick={() => reportMutation.mutate()}
              disabled={reportMutation.isPending}
              className="w-full py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-black font-bold font-mono text-xs flex items-center justify-center gap-2 transition-colors mt-4"
            >
              <FileText className="w-4 h-4" />
              {reportMutation.isPending ? "Generating via Backend..." : "Compile Report"}
            </button>
          </div>
        </div>

        {/* Right Column: Generated Report Preview */}
        <div className="lg:col-span-2 p-5 rounded-xl border border-slate-800 bg-[#0b152b] flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="font-mono text-xs font-bold text-slate-300 uppercase tracking-wider">
              Document Preview
            </h3>
            {generatedReport && (
              <div className="flex items-center gap-2">
                <button
                  onClick={downloadMarkdown}
                  className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-mono flex items-center gap-1.5 border border-slate-700"
                >
                  <Download className="w-3.5 h-3.5" /> Download Markdown
                </button>
              </div>
            )}
          </div>

          <div className="flex-1 min-h-[400px] p-4 rounded-lg bg-slate-950 border border-slate-800/80 overflow-y-auto font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">
            {generatedReport ? (
              generatedReport.content_markdown
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-slate-600 space-y-2">
                <FileText className="w-8 h-8 opacity-40" />
                <span>Configure options and click Compile Report to fetch authoritative report from backend.</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
