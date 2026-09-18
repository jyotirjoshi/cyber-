"use client";

import Link from "next/link";
import * as React from "react";

export function InteractiveSandbox() {
  const [target, setTarget] = React.useState("staging.acme.io");
  const [running, setRunning] = React.useState(false);
  const [step, setStep] = React.useState(0);

  const steps = [
    { title: "Initializing Agent", desc: "Setting up isolated container sandbox & policy bounds..." },
    { title: "Passive Asset Discovery", desc: "Discovering subdomains, open ports, and API endpoints..." },
    { title: "Human Approval Gate Paused", desc: "Found 3 subdomains & 2 exposed endpoints. Awaiting human authorization." },
    { title: "Active Scan & Exploit Validation", desc: "Running Nuclei & OWASP ZAP scanners with proof-of-concept verification..." },
    { title: "DefectDojo & Report Sync", desc: "Enriching threat intel (NVD, EPSS) & drafting advisory remediation." },
  ];

  const handleStart = (e: React.FormEvent) => {
    e.preventDefault();
    if (running) return;
    setRunning(true);
    setStep(0);

    const interval = setInterval(() => {
      setStep((prev) => {
        if (prev >= steps.length - 1) {
          clearInterval(interval);
          return prev;
        }
        return prev + 1;
      });
    }, 1800);
  };

  return (
    <section className="py-28 bg-[#040804] relative strobes-grid-bg border-b border-emerald-500/15">
      <div className="container-app max-w-5xl mx-auto">
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950 text-emerald-400 text-xs font-mono mb-3 border border-emerald-500/30">
            <span>✨ LIVE AGENTIC SIMULATOR</span>
          </div>
          <h2 className="text-3xl sm:text-5xl font-bold text-white mb-4">
            Test how Strobes validates exposure
          </h2>
          <p className="text-sm sm:text-base text-emerald-100/70 max-w-xl mx-auto">
            Type any domain below to simulate the agentic pentest workflow and human-in-the-loop approval gate.
          </p>
        </div>

        {/* Input Form Bar */}
        <form onSubmit={handleStart} className="max-w-2xl mx-auto mb-10 flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-xs font-mono text-emerald-500/60">
              https://
            </span>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="staging.example.com"
              className="w-full bg-[#081208] border border-emerald-500/40 rounded-lg pl-20 pr-4 py-3 text-sm font-mono text-white placeholder:text-emerald-500/30 focus:outline-none focus:border-emerald-400 focus:ring-1 focus:ring-emerald-400"
            />
          </div>
          <button
            type="submit"
            disabled={running && step < steps.length - 1}
            className="bg-emerald-500 hover:bg-emerald-400 text-black font-bold px-6 py-3 rounded-lg text-sm transition-all shadow-lg shadow-emerald-500/20 active:scale-95 disabled:opacity-50"
          >
            {running && step < steps.length - 1 ? "Validating Target..." : "Run Validation →"}
          </button>
        </form>

        {/* Live Simulation Output Box */}
        {running && (
          <div className="rounded-xl bg-[#081008] border border-emerald-500/30 p-6 font-mono text-xs shadow-2xl animate-fade-in">
            <div className="flex items-center justify-between pb-4 border-b border-emerald-500/20 mb-4">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                <span className="font-bold text-white">Target: {target}</span>
              </div>
              <span className="text-emerald-400/60">
                Step {step + 1} of {steps.length}
              </span>
            </div>

            {/* Step progress bar */}
            <div className="w-full bg-emerald-950 h-1.5 rounded-full mb-6 overflow-hidden">
              <div
                className="bg-emerald-400 h-full transition-all duration-500"
                style={{ width: `${((step + 1) / steps.length) * 100}%` }}
              />
            </div>

            {/* Current Step Description */}
            <div className="p-4 rounded-lg bg-[#0c180d] border border-emerald-500/30 space-y-2">
              <div className="text-emerald-300 font-bold flex items-center justify-between">
                <span>{steps[step].title}</span>
                {step === 2 && (
                  <span className="px-2 py-0.5 rounded bg-amber-500 text-black font-bold text-[10px] animate-pulse">
                    STOP → HUMAN APPROVAL GATE
                  </span>
                )}
              </div>
              <p className="text-emerald-200/70 font-sans text-xs">{steps[step].desc}</p>
            </div>

            {step === steps.length - 1 && (
              <div className="mt-6 p-4 rounded-lg bg-emerald-950/80 border border-emerald-500/50 flex flex-col sm:flex-row items-center justify-between gap-4">
                <div>
                  <div className="text-sm font-bold text-white">Validation Completed Successfully!</div>
                  <div className="text-xs text-emerald-300/70">
                    Full security assessment report generated & DefectDojo synced.
                  </div>
                </div>
                <Link
                  href="/dashboard"
                  className="bg-white text-black hover:bg-emerald-300 font-bold px-4 py-2 rounded text-xs transition-colors shrink-0"
                >
                  Open Full Dashboard →
                </Link>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
