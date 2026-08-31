import type { Config } from "tailwindcss";

/**
 * Cynux design tokens. Screens are built by composing the primitives in
 * src/components/ui against these semantic colors, so independently-authored
 * screens stay visually consistent. Dark console theme.
 */
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0a0e16",
        surface: "#111725",
        "surface-2": "#171f30",
        line: "#242e42",
        fg: "#e6ebf4",
        muted: "#8b97ab",
        faint: "#5b6678",
        primary: {
          DEFAULT: "#4f8cff",
          hover: "#6b9dff",
          fg: "#ffffff",
          muted: "#1b2c4d",
        },
        // Severity scale (Severity enum). Also used for risk/priority accents.
        sev: {
          critical: "#ff4d5e",
          high: "#ff8a3d",
          medium: "#ffcc33",
          low: "#3ea6ff",
          info: "#8b97ab",
        },
        ok: "#33d69f",
        warn: "#ffcc33",
        danger: "#ff4d5e",
      },
      fontFamily: {
        sans: [
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
      },
      boxShadow: {
        card: "0 1px 2px rgba(0,0,0,0.4), 0 1px 3px rgba(0,0,0,0.2)",
        panel: "0 8px 30px rgba(0,0,0,0.35)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        pulse: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.4" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.2s ease-out",
      },
    },
  },
  plugins: [],
};

export default config;
