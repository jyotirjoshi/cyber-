import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#040704",
        surface: "#091009",
        "surface-2": "#0f1a0f",
        line: "#182818",
        fg: "#e6f4e6",
        muted: "#8bac8b",
        faint: "#4e6a4e",
        strobes: {
          green: "#4ade80",
          emerald: "#10b981",
          bright: "#22c55e",
          dark: "#052e16",
          darker: "#021a0d",
          border: "rgba(34, 197, 94, 0.2)",
          glow: "rgba(34, 197, 94, 0.35)",
        },
        primary: {
          DEFAULT: "#22c55e",
          hover: "#4ade80",
          fg: "#000000",
          muted: "#052e16",
        },
        sev: {
          critical: "#ff4d5e",
          high: "#ff8a3d",
          medium: "#ffcc33",
          low: "#3ea6ff",
          info: "#8bac8b",
        },
        ok: "#22c55e",
        warn: "#ffcc33",
        danger: "#ff4d5e",
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "Liberation Mono",
          "monospace",
        ],
      },
      borderRadius: {
        lg: "0.625rem",
        xl: "0.875rem",
        "2xl": "1.25rem",
      },
      boxShadow: {
        card: "0 1px 2px rgba(0,0,0,0.6), 0 1px 3px rgba(0,0,0,0.4)",
        panel: "0 8px 30px rgba(0,0,0,0.5)",
        "green-glow": "0 0 25px rgba(34, 197, 94, 0.25), inset 0 0 15px rgba(34, 197, 94, 0.1)",
        "green-badge": "0 0 12px rgba(34, 197, 94, 0.4)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        marquee: {
          "0%": { transform: "translateX(0%)" },
          "100%": { transform: "translateX(-50%)" },
        },
        "pulse-glow": {
          "0%, 100%": { opacity: "0.6", filter: "drop-shadow(0 0 8px rgba(34, 197, 94, 0.8))" },
          "50%": { opacity: "1", filter: "drop-shadow(0 0 16px rgba(34, 197, 94, 1))" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-6px)" },
        },
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(1000%)" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.4s cubic-bezier(0.16, 1, 0.3, 1)",
        marquee: "marquee 30s linear infinite",
        "pulse-glow": "pulse-glow 3s infinite ease-in-out",
        float: "float 4s ease-in-out infinite",
        scanline: "scanline 8s linear infinite",
      },
    },
  },
  plugins: [],
};

export default config;
