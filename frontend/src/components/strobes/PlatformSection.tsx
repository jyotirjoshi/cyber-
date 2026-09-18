"use client";

import * as React from "react";

export function PlatformSection() {
  return (
    <section className="py-28 bg-[#030603] relative border-b border-emerald-500/15">
      <div className="container-app">
        {/* Section Header */}
        <div className="max-w-3xl mb-16">
          <div className="flex items-center gap-2 text-xs font-mono tracking-widest text-emerald-400 uppercase mb-4">
            <span className="w-6 h-px bg-emerald-400" />
            <span>THE PLATFORM</span>
          </div>
          <h2 className="text-4xl sm:text-6xl font-bold tracking-tight text-white mb-6">
            One platform for every exposure problem
          </h2>
          <p className="text-base sm:text-lg text-emerald-100/70 leading-relaxed">
            Strobes covers the full CTEM lifecycle, from assessment through validation. It
            proves what’s actually exploitable at every layer, instead of just flagging it.
          </p>
        </div>

        {/* 3 Column Feature Cards Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Card 1: ASSESS */}
          <div className="flex flex-col justify-between rounded-2xl bg-gradient-to-b from-[#091a0c] to-[#040a05] border border-emerald-500/30 p-6 shadow-xl hover:border-emerald-400/60 transition-all group">
            <div>
              {/* Connectors List Inside Glass Box */}
              <div className="space-y-3 mb-8">
                {/* Connector 1 */}
                <div className="p-3 rounded-xl bg-[#0b2210]/60 border border-emerald-500/30 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-xs">
                      🖧
                    </div>
                    <div>
                      <div className="text-[10px] text-emerald-400/60 font-mono">Network VA · Infra</div>
                      <div className="text-xs font-bold text-white">Qualys</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-500/40">
                    LIVE
                  </span>
                </div>

                {/* Connector 2 */}
                <div className="p-3 rounded-xl bg-[#0b2210]/60 border border-emerald-500/30 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-xs">
                      🌐
                    </div>
                    <div>
                      <div className="text-[10px] text-emerald-400/60 font-mono">DAST · Web & API</div>
                      <div className="text-xs font-bold text-white">Burp Suite</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-500/40">
                    LIVE
                  </span>
                </div>

                {/* Connector 3 */}
                <div className="p-3 rounded-xl bg-[#0b2210]/60 border border-emerald-500/30 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-xs">
                      📦
                    </div>
                    <div>
                      <div className="text-[10px] text-emerald-400/60 font-mono">SCA · Dependencies</div>
                      <div className="text-xs font-bold text-white">Snyk</div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-500/40">
                    LIVE
                  </span>
                </div>

                <div className="text-center pt-1 text-[11px] font-mono text-emerald-400/70">
                  + 47 MORE CONNECTORS SYNCING
                </div>
              </div>
            </div>

            {/* Bottom Category Label */}
            <div className="pt-4 border-t border-emerald-500/20 flex items-center justify-between text-xs font-mono tracking-wider text-emerald-400 uppercase">
              <span>ASSESS</span>
              <span className="text-emerald-500/40 group-hover:translate-x-1 transition-transform">→</span>
            </div>
          </div>

          {/* Card 2: PENTEST */}
          <div className="flex flex-col justify-between rounded-2xl bg-gradient-to-b from-[#091a0c] to-[#040a05] border border-emerald-500/30 p-6 shadow-xl hover:border-emerald-400/60 transition-all group">
            <div>
              {/* Agent Exploit Box */}
              <div className="p-4 rounded-xl bg-[#0b2210]/80 border border-emerald-500/40 space-y-3 mb-8">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-emerald-400/60 uppercase">JUST NOW</span>
                  <span className="text-xs font-bold text-emerald-300 flex items-center gap-1">
                    <span>✨</span> Exploit Agent
                  </span>
                </div>
                <p className="text-xs font-sans text-emerald-100 leading-relaxed">
                  Auth bypass on <code className="text-emerald-400 bg-black/40 px-1 rounded">/api/v2/orders</code> — IDOR chained into SQLi, reproduced end to end.
                </p>
                <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-500/20 text-red-400 border border-red-500/40 text-[10px] font-mono font-bold">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" />
                  <span>Confirmed exploitable</span>
                </div>

                <div className="p-2.5 rounded bg-black/40 border border-emerald-500/20 text-[10px] font-mono text-emerald-400/70">
                  ATTACHED TO FINDING:
                  <div className="text-emerald-300 font-bold mt-0.5">
                    PoC · replay script · CVSS 9.1
                  </div>
                </div>
              </div>
            </div>

            {/* Bottom Category Label */}
            <div className="pt-4 border-t border-emerald-500/20 flex items-center justify-between text-xs font-mono tracking-wider text-emerald-400 uppercase">
              <span>PENTEST</span>
              <span className="text-emerald-500/40 group-hover:translate-x-1 transition-transform">→</span>
            </div>
          </div>

          {/* Card 3: VALIDATE */}
          <div className="flex flex-col justify-between rounded-2xl bg-gradient-to-b from-[#091a0c] to-[#040a05] border border-emerald-500/30 p-6 shadow-xl hover:border-emerald-400/60 transition-all group">
            <div>
              {/* Coverage Chart Box */}
              <div className="p-4 rounded-xl bg-[#0b2210]/80 border border-emerald-500/40 space-y-3 mb-8">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-emerald-400/60 uppercase">AUTONOMOUS RUN</span>
                  <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                    REPORT READY · 24H
                  </span>
                </div>

                <div>
                  <div className="text-xs font-bold text-white">Coverage · external surface</div>
                  <div className="text-2xl font-bold text-emerald-400 font-mono">100%</div>
                  <div className="text-[10px] text-emerald-400/60">
                    ↑ full surface · exec summary & tickets included
                  </div>
                </div>

                {/* Bar Chart Bars */}
                <div className="pt-4 flex items-end justify-between gap-1.5 h-20 border-t border-emerald-500/20">
                  {[20, 35, 45, 60, 75, 90, 100].map((height, i) => (
                    <div key={i} className="flex-1 flex flex-col items-center gap-1">
                      <div
                        className="w-full bg-gradient-to-t from-emerald-600 to-green-400 rounded-t shadow-[0_0_8px_rgba(34,197,94,0.4)]"
                        style={{ height: `${height}%` }}
                      />
                    </div>
                  ))}
                </div>
                <div className="flex justify-between text-[9px] font-mono text-emerald-500/50">
                  <span>0H</span>
                  <span>8H</span>
                  <span>16H</span>
                  <span>24H</span>
                </div>
              </div>
            </div>

            {/* Bottom Category Label */}
            <div className="pt-4 border-t border-emerald-500/20 flex items-center justify-between text-xs font-mono tracking-wider text-emerald-400 uppercase">
              <span>VALIDATE</span>
              <span className="text-emerald-500/40 group-hover:translate-x-1 transition-transform">→</span>
            </div>
          </div>

        </div>
      </div>
    </section>
  );
}
