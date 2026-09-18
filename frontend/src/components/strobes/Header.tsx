"use client";

import Link from "next/link";
import * as React from "react";
import { DemoModal } from "./DemoModal";

export function Header() {
  const [scrolled, setScrolled] = React.useState(false);
  const [isDemoOpen, setIsDemoOpen] = React.useState(false);

  React.useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <>
      <header
        className={`fixed top-0 left-0 right-0 z-40 transition-all duration-300 ${
          scrolled
            ? "bg-[#030603]/90 backdrop-blur-md border-b border-emerald-500/20 py-3 shadow-lg shadow-black/40"
            : "bg-transparent py-5"
        }`}
      >
        <div className="container-app flex items-center justify-between">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-mono font-bold text-lg group-hover:border-emerald-400 group-hover:bg-emerald-500/20 transition-all shadow-[0_0_12px_rgba(34,197,94,0.3)]">
              ⚡
            </div>
            <span className="text-xl font-bold tracking-tight text-white group-hover:text-emerald-300 transition-colors">
              strobes
            </span>
          </Link>

          {/* Navigation items */}
          <nav className="hidden md:flex items-center gap-7 text-sm font-medium text-emerald-100/70">
            <div className="relative group cursor-pointer hover:text-white transition-colors flex items-center gap-1">
              <span>Platform</span>
              <span className="text-xs opacity-60">⌄</span>
            </div>
            <div className="relative group cursor-pointer hover:text-white transition-colors flex items-center gap-1">
              <span>Solutions</span>
              <span className="text-xs opacity-60">⌄</span>
            </div>
            <div className="relative group cursor-pointer hover:text-white transition-colors flex items-center gap-1">
              <span>Resources</span>
              <span className="text-xs opacity-60">⌄</span>
            </div>
            <div className="relative group cursor-pointer hover:text-white transition-colors flex items-center gap-1">
              <span>Customers</span>
              <span className="text-xs opacity-60">⌄</span>
            </div>
            <div className="relative group cursor-pointer hover:text-white transition-colors flex items-center gap-1">
              <span>Company</span>
              <span className="text-xs opacity-60">⌄</span>
            </div>
            <Link href="#pricing" className="hover:text-white transition-colors">
              Pricing
            </Link>
          </nav>

          {/* Right CTA */}
          <div className="flex items-center gap-4">
            <Link
              href="/login"
              className="hidden sm:inline-flex items-center text-sm font-medium text-emerald-400 hover:text-emerald-300 transition-colors"
            >
              Console Sign In
            </Link>
            <button
              onClick={() => setIsDemoOpen(true)}
              className="bg-white text-black hover:bg-emerald-300 font-semibold px-4 py-2 rounded-md text-sm transition-all shadow-md shadow-white/10 hover:shadow-emerald-500/20 active:scale-95 cursor-pointer"
            >
              Book a Demo
            </button>
          </div>
        </div>
      </header>

      <DemoModal isOpen={isDemoOpen} onClose={() => setIsDemoOpen(false)} />
    </>
  );
}
