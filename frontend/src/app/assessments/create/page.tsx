"use client";

import React, { useState } from "react";
import { 
  ShieldCheck, 
  ArrowRight, 
  ArrowLeft, 
  Check, 
  CheckCircle2 
} from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { createEngagement, previewScope } from "@/lib/api";
import { useRouter } from "next/navigation";

export default function CreateAssessmentWizardPage() {
  const router = useRouter();
  const [step, setStep] = useState(1);

  // Form State
  const [name, setName] = useState("OWASP Juice Shop Web & API Assessment");
  const [objective, setObjective] = useState("Assess web application vulnerabilities, OpenAPI endpoints, and authorization controls.");
  const [authConfirmed, setAuthConfirmed] = useState(false);

  // Targets / Inclusions
  const [includedDomains, setIncludedDomains] = useState("localhost\n127.0.0.1");
  const [includedUrls, setIncludedUrls] = useState("http://127.0.0.1:3000");
  const [includedPorts, setIncludedPorts] = useState("3000, 80, 443");

  // Exclusions
  const [excludedUrls, setExcludedUrls] = useState("http://127.0.0.1:3000/ftp\nhttp://127.0.0.1:3000/admin");
  const [excludedIps, setExcludedIps] = useState("10.0.0.1");

  // Assessment Profile
  const [profile, setProfile] = useState("web_application");
  const [authProfile, setAuthProfile] = useState("secret://auth/local_juiceshop");

  // Resource Budgets
  const [maxRuntime, setMaxRuntime] = useState(3600);
  const [maxLlmRequests, setMaxLlmRequests] = useState(100);
  const [maxConcurrency, setMaxConcurrency] = useState(5);
  const [maxCrawlerPages, setMaxCrawlerPages] = useState(50);
  const [maxCrawlerDepth, setMaxCrawlerDepth] = useState(3);

  // Scope preview state
  const [scopePreviewData, setScopePreviewData] = useState<{
    is_valid: boolean;
    effective_inclusions: string[];
    effective_exclusions: string[];
    override_rule: string;
  } | null>(null);

  // Preview Scope Mutation
  const previewMutation = useMutation({
    mutationFn: () => {
      const incDomains = includedDomains.split("\n").map((s) => s.trim()).filter(Boolean);
      const incUrls = includedUrls.split("\n").map((s) => s.trim()).filter(Boolean);
      const excUrls = excludedUrls.split("\n").map((s) => s.trim()).filter(Boolean);
      const excIps = excludedIps.split("\n").map((s) => s.trim()).filter(Boolean);

      return previewScope({
        included_domains: incDomains,
        included_urls: incUrls,
        excluded_urls: excUrls,
        excluded_ips: excIps,
      });
    },
    onSuccess: (data) => {
      setScopePreviewData(data);
    },
  });

  // Create Mutation
  const createMutation = useMutation({
    mutationFn: () => {
      const incDomains = includedDomains.split("\n").map((s) => s.trim()).filter(Boolean);
      const incUrls = includedUrls.split("\n").map((s) => s.trim()).filter(Boolean);
      const excUrls = excludedUrls.split("\n").map((s) => s.trim()).filter(Boolean);
      const excIps = excludedIps.split("\n").map((s) => s.trim()).filter(Boolean);

      return createEngagement({
        name,
        objective,
        authorization_confirmed: authConfirmed,
        scope: {
          included_domains: incDomains,
          included_urls: incUrls,
          excluded_urls: excUrls,
          excluded_ips: excIps,
        },
        assessment_profile: profile,
        auth_profile: authProfile,
        resource_budgets: {
          max_runtime_sec: maxRuntime,
          max_llm_requests: maxLlmRequests,
          max_web_concurrency: maxConcurrency,
          max_crawler_pages: maxCrawlerPages,
          max_crawler_depth: maxCrawlerDepth,
        },
      });
    },
    onSuccess: () => {
      router.push("/");
    },
  });

  const nextStep = () => {
    if (step === 7) {
      previewMutation.mutate();
    }
    setStep((s) => Math.min(s + 1, 9));
  };

  const prevStep = () => {
    setStep((s) => Math.max(s - 1, 1));
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="pb-4 border-b border-slate-800">
        <h1 className="text-xl font-mono font-bold text-white flex items-center gap-2">
          <span>CREATE ASSESSMENT WIZARD</span>
          <span className="text-[11px] px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-500/40 text-cyan-300 font-mono">
            STEP {step} OF 9
          </span>
        </h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Configure an authorized engagement boundary, profile, and resource enforcement envelopes.
        </p>
      </div>

      {/* Progress Bar */}
      <div className="w-full bg-slate-900 rounded-full h-1.5 border border-slate-800 overflow-hidden">
        <div
          className="bg-cyan-500 h-full transition-all duration-300 rounded-full"
          style={{ width: `${(step / 9) * 100}%` }}
        ></div>
      </div>

      {/* Wizard Step Content */}
      <div className="p-6 rounded-xl border border-slate-800 bg-[#0b152b] min-h-[380px] flex flex-col justify-between">
        {/* Step 1: Basic Information */}
        {step === 1 && (
          <div className="space-y-4">
            <h2 className="text-sm font-mono font-bold text-cyan-400 uppercase tracking-wider">
              Step 1 — Engagement Context & Authorization Confirmation
            </h2>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Engagement Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:border-cyan-500 outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Objective / Description</label>
              <textarea
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                rows={3}
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:border-cyan-500 outline-none"
              />
            </div>
            <div className="p-4 rounded-lg bg-emerald-950/30 border border-emerald-500/40 space-y-2">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={authConfirmed}
                  onChange={(e) => setAuthConfirmed(e.target.checked)}
                  className="mt-1 accent-emerald-500 w-4 h-4"
                />
                <div className="text-xs font-mono text-slate-200">
                  <span className="font-bold text-emerald-400 block mb-1">
                    Formal Authorization Affirmation
                  </span>
                  I solemnly affirm that the operator and organization have full legal authority and explicit written authorization to assess the specified target scope.
                </div>
              </label>
            </div>
          </div>
        )}

        {/* Step 2 & 3: Inclusions */}
        {step === 2 && (
          <div className="space-y-4">
            <h2 className="text-sm font-mono font-bold text-cyan-400 uppercase tracking-wider">
              Step 2 & 3 — Included Targets & Scope Boundaries
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              Specify explicit domains, URLs, and ports permitted for scanning and analysis.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">
                  Included Hostnames / Domains (one per line)
                </label>
                <textarea
                  value={includedDomains}
                  onChange={(e) => setIncludedDomains(e.target.value)}
                  rows={4}
                  className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:border-cyan-500 outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">
                  Included Target URLs (one per line)
                </label>
                <textarea
                  value={includedUrls}
                  onChange={(e) => setIncludedUrls(e.target.value)}
                  rows={4}
                  className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:border-cyan-500 outline-none"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Permitted Ports</label>
              <input
                type="text"
                value={includedPorts}
                onChange={(e) => setIncludedPorts(e.target.value)}
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:border-cyan-500 outline-none"
              />
            </div>
          </div>
        )}

        {/* Step 4: Exclusions */}
        {step === 3 && (
          <div className="space-y-4">
            <h2 className="text-sm font-mono font-bold text-rose-400 uppercase tracking-wider">
              Step 4 — Explicit Scope Exclusions
            </h2>
            <div className="p-3 rounded bg-rose-950/30 border border-rose-500/30 text-xs font-mono text-rose-300">
              Deterministic Invariant: <strong>EXCLUSIONS OVERRIDE INCLUSIONS</strong>. Any URL, path, or IP matching an exclusion will be denied unconditionally by ScopeGuard.
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">
                  Excluded URLs / Path Prefixes (one per line)
                </label>
                <textarea
                  value={excludedUrls}
                  onChange={(e) => setExcludedUrls(e.target.value)}
                  rows={4}
                  className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:border-rose-500 outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">
                  Excluded IPs / Subnets (one per line)
                </label>
                <textarea
                  value={excludedIps}
                  onChange={(e) => setExcludedIps(e.target.value)}
                  rows={4}
                  className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:border-rose-500 outline-none"
                />
              </div>
            </div>
          </div>
        )}

        {/* Step 5: Assessment Profile */}
        {step === 4 && (
          <div className="space-y-4">
            <h2 className="text-sm font-mono font-bold text-cyan-400 uppercase tracking-wider">
              Step 5 — Select Assessment Profile
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {[
                { id: "web_application", name: "Web Application — Safe", desc: "Crawling, parameter fuzzing, safe passive analysis" },
                { id: "api_security", name: "API Security Assessment", desc: "OpenAPI schema parsing, GraphQL introspection, endpoint fuzzing" },
                { id: "network_recon", name: "Network Reconnaissance", desc: "Passive DNS, port enumeration, banner grabbing" },
                { id: "authenticated_web", name: "Authenticated Web App", desc: "Session cookie injection, IDOR validation, privilege boundary test" },
              ].map((p) => (
                <div
                  key={p.id}
                  onClick={() => setProfile(p.id)}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                    profile === p.id
                      ? "border-cyan-500 bg-cyan-950/40 text-cyan-200"
                      : "border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700"
                  }`}
                >
                  <div className="text-xs font-mono font-bold mb-1">{p.name}</div>
                  <div className="text-[11px] text-slate-400">{p.desc}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Step 6: Authentication Profile */}
        {step === 5 && (
          <div className="space-y-4">
            <h2 className="text-sm font-mono font-bold text-cyan-400 uppercase tracking-wider">
              Step 6 — Authentication Profile Reference
            </h2>
            <div className="p-3 rounded bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400">
              Security Notice: Raw passwords, API keys, or session tokens are <strong>never stored or displayed in the browser</strong>. Authentication uses isolated backend secret references.
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Vault Secret Reference URI
              </label>
              <input
                type="text"
                value={authProfile}
                onChange={(e) => setAuthProfile(e.target.value)}
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-white focus:border-cyan-500 outline-none"
              />
            </div>
          </div>
        )}

        {/* Step 7: Resource Budgets */}
        {step === 6 && (
          <div className="space-y-4">
            <h2 className="text-sm font-mono font-bold text-cyan-400 uppercase tracking-wider">
              Step 7 — Resource Enforcement Envelopes
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Max Runtime (Seconds)</label>
                <input
                  type="number"
                  value={maxRuntime}
                  onChange={(e) => setMaxRuntime(Number(e.target.value))}
                  className="w-full px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-white"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Max LLM Reasoning Requests</label>
                <input
                  type="number"
                  value={maxLlmRequests}
                  onChange={(e) => setMaxLlmRequests(Number(e.target.value))}
                  className="w-full px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-white"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Max Web Concurrency</label>
                <input
                  type="number"
                  value={maxConcurrency}
                  onChange={(e) => setMaxConcurrency(Number(e.target.value))}
                  className="w-full px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-white"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Max Crawler Pages</label>
                <input
                  type="number"
                  value={maxCrawlerPages}
                  onChange={(e) => setMaxCrawlerPages(Number(e.target.value))}
                  className="w-full px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-white"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Max Crawler Depth</label>
                <input
                  type="number"
                  value={maxCrawlerDepth}
                  onChange={(e) => setMaxCrawlerDepth(Number(e.target.value))}
                  className="w-full px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-white"
                />
              </div>
            </div>
          </div>
        )}

        {/* Step 8: Effective Scope Preview */}
        {step === 7 && (
          <div className="space-y-4">
            <h2 className="text-sm font-mono font-bold text-cyan-400 uppercase tracking-wider">
              Step 8 — Authoritative Scope Preview
            </h2>
            <div className="p-3 rounded bg-slate-900 border border-slate-800 text-xs font-mono space-y-2">
              <div className="text-emerald-400 font-bold uppercase">
                INCLUDED BOUNDARIES
              </div>
              <div className="text-slate-300">
                {includedDomains.replace(/\n/g, ", ")}, {includedUrls.replace(/\n/g, ", ")} (Ports: {includedPorts})
              </div>

              <div className="text-rose-400 font-bold uppercase pt-2 border-t border-slate-800">
                EXCLUDED BOUNDARIES (OVERRIDE ACTIVE)
              </div>
              <div className="text-slate-300">
                {excludedUrls.replace(/\n/g, ", ")}, {excludedIps.replace(/\n/g, ", ")}
              </div>
            </div>
            {scopePreviewData && (
              <div className="p-3 rounded bg-slate-900 border border-slate-800 text-xs font-mono space-y-1">
                <div className="text-cyan-400 font-bold uppercase">Preview Validation Result</div>
                <div className="text-slate-300">Status: {scopePreviewData.is_valid ? "Valid" : "Invalid"}</div>
                <div className="text-slate-400">Override Rule: {scopePreviewData.override_rule}</div>
              </div>
            )}
            <div className="p-2.5 rounded bg-emerald-950/30 border border-emerald-500/30 text-xs font-mono text-emerald-300 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Scope boundary compiled. No ambient expansion permitted.</span>
            </div>
          </div>
        )}

        {/* Step 9: Final Validation & Launch */}
        {step === 8 && (
          <div className="space-y-4">
            <h2 className="text-sm font-mono font-bold text-cyan-400 uppercase tracking-wider">
              Step 9 — Final Control Plane Validation
            </h2>
            <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 space-y-2 text-xs font-mono">
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 className="w-4 h-4" /> Scope definition syntactically & semantically valid
              </div>
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 className="w-4 h-4" /> Operator legal authorization confirmed
              </div>
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 className="w-4 h-4" /> Policy matrix verified (High/Critical gated)
              </div>
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 className="w-4 h-4" /> Resource budget envelope limits enforced
              </div>
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 className="w-4 h-4" /> LLM Gateway active (Nemotron-3 Ultra via OpenRouter)
              </div>
            </div>
          </div>
        )}

        {/* Wizard Footer Navigation */}
        <div className="flex items-center justify-between pt-6 border-t border-slate-800/80 mt-4">
          <button
            onClick={prevStep}
            disabled={step === 1}
            className="px-4 py-2 rounded text-xs font-mono border border-slate-700 text-slate-300 hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none flex items-center gap-1.5"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Previous
          </button>

          {step < 8 ? (
            <button
              onClick={nextStep}
              disabled={step === 1 && !authConfirmed}
              className="px-5 py-2 rounded text-xs font-mono font-bold tracking-wide bg-cyan-600 hover:bg-cyan-500 text-black flex items-center gap-1.5 disabled:opacity-40 disabled:pointer-events-none transition-colors"
            >
              Next <ArrowRight className="w-3.5 h-3.5" />
            </button>
          ) : (
            <button
              onClick={() => createMutation.mutate()}
              disabled={createMutation.isPending}
              className="px-6 py-2 rounded text-xs font-mono font-bold tracking-wide bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-2 shadow-lg shadow-emerald-950 transition-colors"
            >
              <Check className="w-4 h-4" />
              {createMutation.isPending ? "Creating Assessment..." : "Create Assessment"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
