"use client";

import Link from "next/link";
import * as React from "react";
import { DemoModal } from "./DemoModal";

export function Hero() {
  const [isDemoOpen, setIsDemoOpen] = React.useState(false);

  return (
    <>
      <section className="relative min-h-screen pt-32 pb-20 overflow-hidden strobes-grid-bg flex flex-col justify-center items-center">
        {/* Background ambient glowing gradient blur */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-emerald-500/15 rounded-full blur-[140px] pointer-events-none" />
        <div className="absolute bottom-10 left-1/2 -translate-x-1/2 w-full max-w-7xl h-px bg-gradient-to-r from-transparent via-emerald-500/20 to-transparent pointer-events-none" />

        <div className="container-app relative z-10 text-center max-w-4xl mx-auto flex flex-col items-center">
          {/* Top Agentic Pill Badge */}
          <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-emerald-950/60 border border-emerald-500/40 shadow-[0_0_15px_rgba(34,197,94,0.2)] mb-8 backdrop-blur-md">
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-xs font-mono font-bold tracking-widest text-emerald-400 uppercase">
              LIVE &nbsp; AGENTIC VALIDATION PLATFORM
            </span>
          </div>

          {/* Main Headline */}
          <h1 className="text-4xl sm:text-6xl md:text-7xl font-bold tracking-tight text-white leading-[1.1] mb-6">
            Adversarial exposure validation that{" "}
            <span className="text-emerald-400 drop-shadow-[0_0_25px_rgba(34,197,94,0.5)]">
              proves what’s exploitable
            </span>
          </h1>

          {/* Subtitle */}
          <p className="text-base sm:text-xl text-emerald-100/70 max-w-2xl mx-auto mb-10 leading-relaxed font-normal">
            Strobes’ agents validate findings the way an attacker would, so you fix what’s
            actually reachable, not what a scanner guessed.
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto mb-12">
            <button
              onClick={() => setIsDemoOpen(true)}
              className="w-full sm:w-auto bg-white text-black hover:bg-emerald-300 font-semibold px-7 py-3.5 rounded-md text-base transition-all flex items-center justify-center gap-2 shadow-lg shadow-white/10 hover:shadow-emerald-500/25 active:scale-95 group cursor-pointer"
            >
              <span>Book a Live Pentest</span>
              <span className="group-hover:translate-x-1 transition-transform">→</span>
            </button>
            <Link
              href="/register"
              className="w-full sm:w-auto bg-emerald-950/40 hover:bg-emerald-900/50 text-white font-medium px-7 py-3.5 rounded-md text-base border border-emerald-500/40 hover:border-emerald-400 transition-all flex items-center justify-center shadow-[0_0_15px_rgba(34,197,94,0.15)] hover:shadow-[0_0_25px_rgba(34,197,94,0.3)] active:scale-95"
            >
              Start Free Trial
            </Link>
          </div>

          {/* Bottom Ratings Line */}
          <div className="flex items-center justify-center gap-2 text-xs font-mono text-emerald-500/80">
            <span>4.6/5 82</span>
            <span>·</span>
            <span>4.6/5 Gartner Peer Insights</span>
          </div>
        </div>
      </section>

      <DemoModal isOpen={isDemoOpen} onClose={() => setIsDemoOpen(false)} />
    </>
  );
}
