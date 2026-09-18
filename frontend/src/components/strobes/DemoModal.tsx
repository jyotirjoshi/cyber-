"use client";

import { useRouter } from "next/navigation";
import * as React from "react";

interface DemoModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function DemoModal({ isOpen, onClose }: DemoModalProps) {
  const router = useRouter();
  const [name, setName] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [target, setTarget] = React.useState("staging.example.com");
  const [objective, setObjective] = React.useState(
    "Assess the security posture and validate exploitable vulnerabilities"
  );
  const [loading, setLoading] = React.useState(false);
  const [submitted, setSubmitted] = React.useState(false);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    setTimeout(() => {
      setLoading(false);
      setSubmitted(true);
      setTimeout(() => {
        onClose();
        setSubmitted(false);
        router.push(`/register?email=${encodeURIComponent(email)}&target=${encodeURIComponent(target)}`);
      }, 1500);
    }, 1000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-lg rounded-2xl bg-[#081008] border border-emerald-500/40 p-6 sm:p-8 shadow-[0_25px_70px_rgba(0,0,0,0.9),0_0_40px_rgba(34,197,94,0.2)]">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 w-8 h-8 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 flex items-center justify-center hover:bg-emerald-900/50 transition-colors"
        >
          ✕
        </button>

        {!submitted ? (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-mono font-bold tracking-widest text-emerald-400 uppercase">
                STRIBES AGENTIC PENTEST DEMO
              </span>
            </div>
            <h3 className="text-2xl font-bold text-white mb-2">Book a Live Pentest</h3>
            <p className="text-xs text-emerald-100/70 mb-6 font-sans">
              Enter your target details to test our AI agents against reachable vulnerabilities with human-in-the-loop validation.
            </p>

            <form onSubmit={handleSubmit} className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-emerald-300 font-semibold mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Jane Doe"
                  className="w-full bg-[#050b05] border border-emerald-500/30 rounded-lg px-3.5 py-2.5 text-white placeholder:text-emerald-500/30 focus:outline-none focus:border-emerald-400"
                />
              </div>

              <div>
                <label className="block text-emerald-300 font-semibold mb-1">Work Email</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="jane@company.com"
                  className="w-full bg-[#050b05] border border-emerald-500/30 rounded-lg px-3.5 py-2.5 text-white placeholder:text-emerald-500/30 focus:outline-none focus:border-emerald-400"
                />
              </div>

              <div>
                <label className="block text-emerald-300 font-semibold mb-1">Target Host / Domain</label>
                <input
                  type="text"
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="staging.company.com"
                  className="w-full bg-[#050b05] border border-emerald-500/30 rounded-lg px-3.5 py-2.5 text-white placeholder:text-emerald-500/30 focus:outline-none focus:border-emerald-400"
                />
              </div>

              <div>
                <label className="block text-emerald-300 font-semibold mb-1">Assessment Objective</label>
                <textarea
                  rows={2}
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                  className="w-full bg-[#050b05] border border-emerald-500/30 rounded-lg px-3.5 py-2.5 text-white placeholder:text-emerald-500/30 focus:outline-none focus:border-emerald-400 font-sans"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-black font-bold text-sm transition-all shadow-lg shadow-emerald-500/20 active:scale-95 flex items-center justify-center gap-2 mt-2"
              >
                {loading ? (
                  <span>Preparing Sandbox...</span>
                ) : (
                  <>
                    <span>Request Pentest Demo</span>
                    <span>→</span>
                  </>
                )}
              </button>
            </form>
          </div>
        ) : (
          <div className="py-8 text-center space-y-4">
            <div className="w-12 h-12 rounded-full bg-emerald-500/20 border border-emerald-400 text-emerald-400 text-2xl mx-auto flex items-center justify-center animate-bounce">
              ✓
            </div>
            <h3 className="text-xl font-bold text-white">Pentest Request Confirmed!</h3>
            <p className="text-xs text-emerald-200/70 font-sans max-w-sm mx-auto">
              Redirecting you to the live console dashboard to initialize your assessment...
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
