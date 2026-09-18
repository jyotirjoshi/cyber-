"use client";

import * as React from "react";

const LOGOS = [
  { name: "SAMSUNG", style: "font-bold tracking-widest text-lg" },
  { name: "paloalto NETWORKS", style: "font-bold text-base tracking-tight" },
  { name: "Flipkart 🛍️", style: "font-bold text-lg" },
  { name: "Tricentis", style: "font-semibold tracking-wide text-lg" },
  { name: "airtel", style: "font-bold italic text-lg" },
  { name: "ZOHO", style: "font-black tracking-widest text-lg" },
];

export function LogosMarquee() {
  return (
    <section className="py-12 border-t border-b border-emerald-500/15 bg-[#030603]/90 relative overflow-hidden">
      <div className="container-app text-center mb-6">
        <span className="text-xs font-mono tracking-[0.25em] text-emerald-500/70 uppercase">
          CHOSEN BY TEAMS WHO CAN'T AFFORD TO GET IT WRONG
        </span>
      </div>

      {/* Marquee Row */}
      <div className="flex overflow-hidden select-none [mask-image:linear-gradient(to_right,transparent,black_10%,black_90%,transparent)]">
        <div className="flex shrink-0 items-center justify-around gap-16 animate-marquee min-w-full">
          {LOGOS.concat(LOGOS).map((logo, idx) => (
            <div
              key={idx}
              className="flex items-center justify-center grayscale opacity-60 hover:grayscale-0 hover:opacity-100 hover:text-emerald-400 transition-all cursor-pointer text-white font-mono"
            >
              <span className={logo.style}>{logo.name}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
