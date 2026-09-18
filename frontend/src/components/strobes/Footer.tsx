"use client";

import Link from "next/link";
import * as React from "react";

export function Footer() {
  return (
    <footer className="bg-[#020402] border-t border-emerald-500/15 py-16 text-emerald-100/70 text-xs font-mono">
      <div className="container-app">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-10 mb-12">
          {/* Brand Col */}
          <div className="md:col-span-2 space-y-4">
            <Link href="/" className="flex items-center gap-2">
              <div className="w-7 h-7 rounded bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold">
                ⚡
              </div>
              <span className="text-lg font-bold text-white tracking-tight">strobes</span>
            </Link>
            <p className="text-xs text-emerald-100/60 max-w-sm leading-relaxed font-sans">
              Adversarial exposure validation that proves what's exploitable. AI agents validating findings the way an attacker would.
            </p>
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-emerald-950/80 border border-emerald-500/30 text-[11px] text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>All Systems Operational</span>
            </div>
          </div>

          {/* Col 1 */}
          <div>
            <div className="text-xs font-bold text-white uppercase tracking-wider mb-4">Platform</div>
            <ul className="space-y-2.5 text-emerald-400/70">
              <li><Link href="#platform" className="hover:text-emerald-300 transition-colors">Agentic Pentest</Link></li>
              <li><Link href="#platform" className="hover:text-emerald-300 transition-colors">Continuous CTEM</Link></li>
              <li><Link href="#platform" className="hover:text-emerald-300 transition-colors">Exploit Validation</Link></li>
              <li><Link href="#platform" className="hover:text-emerald-300 transition-colors">DefectDojo Sync</Link></li>
            </ul>
          </div>

          {/* Col 2 */}
          <div>
            <div className="text-xs font-bold text-white uppercase tracking-wider mb-4">Solutions</div>
            <ul className="space-y-2.5 text-emerald-400/70">
              <li><Link href="/dashboard" className="hover:text-emerald-300 transition-colors">Web Application</Link></li>
              <li><Link href="/dashboard" className="hover:text-emerald-300 transition-colors">Cloud Infrastructure</Link></li>
              <li><Link href="/dashboard" className="hover:text-emerald-300 transition-colors">API & Webhooks</Link></li>
              <li><Link href="/dashboard" className="hover:text-emerald-300 transition-colors">Red Teaming</Link></li>
            </ul>
          </div>

          {/* Col 3 */}
          <div>
            <div className="text-xs font-bold text-white uppercase tracking-wider mb-4">Company</div>
            <ul className="space-y-2.5 text-emerald-400/70">
              <li><Link href="/dashboard" className="hover:text-emerald-300 transition-colors">Console Login</Link></li>
              <li><Link href="#pricing" className="hover:text-emerald-300 transition-colors">Pricing</Link></li>
              <li><Link href="/docs" className="hover:text-emerald-300 transition-colors">Documentation</Link></li>
              <li><Link href="/" className="hover:text-emerald-300 transition-colors">Privacy Policy</Link></li>
            </ul>
          </div>
        </div>

        <div className="pt-8 border-t border-emerald-500/10 flex flex-col sm:flex-row items-center justify-between gap-4 text-emerald-500/50">
          <div>© {new Date().getFullYear()} Strobes Security Inc. All rights reserved.</div>
          <div className="flex items-center gap-6">
            <Link href="/dashboard" className="hover:text-emerald-400">Security</Link>
            <Link href="/dashboard" className="hover:text-emerald-400">Terms</Link>
            <Link href="/dashboard" className="hover:text-emerald-400">Privacy</Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
