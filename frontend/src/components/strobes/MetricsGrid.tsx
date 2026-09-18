"use client";

import * as React from "react";

const METRICS = [
  {
    value: "<5%",
    title: "False-positive rate",
    desc: "False-positive rate. Every finding ships with a working proof of concept.",
    highlight: true,
  },
  {
    value: "60%",
    title: "Faster MTTR",
    desc: "Faster MTTR. Teams remediate proven risk first, not scanner noise.",
  },
  {
    value: "40x",
    title: "Faster pentests",
    desc: "Faster than manual pentesting. A full assessment in hours, not weeks.",
  },
  {
    value: "70%",
    title: "Lower cost",
    desc: "Lower cost than a traditional pentest, same depth of coverage.",
  },
];

export function MetricsGrid() {
  return (
    <section className="py-24 bg-[#030603] relative border-b border-emerald-500/15">
      <div className="container-app">
        <div className="text-center mb-16">
          <span className="text-xs font-mono tracking-[0.3em] text-emerald-400 uppercase">
            THIS IS WHAT VALIDATED LOOKS LIKE
          </span>
        </div>

        {/* 4 Column Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {METRICS.map((item, idx) => (
            <div
              key={idx}
              className="relative pt-6 border-t border-emerald-500/30 hover:border-emerald-400 transition-colors group"
            >
              <div
                className={`text-5xl sm:text-6xl font-bold tracking-tight mb-4 transition-transform group-hover:-translate-y-1 ${
                  item.highlight
                    ? "text-emerald-400 drop-shadow-[0_0_20px_rgba(34,197,94,0.4)]"
                    : "text-white"
                }`}
              >
                {item.value}
              </div>
              <p className="text-sm text-emerald-100/70 leading-relaxed font-sans">
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
