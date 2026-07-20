import type { Config } from "tailwindcss";

// Mirrors frontend/tailwind.config.ts so the landing reads as the same product.
// Keep these tokens in sync if the platform theme shifts.
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        base:     "#0B1631",
        surface:  "#0E1A3A",
        surface2: "#13234C",
        line:     "#1E3061",
        accent:   "#00E5FF",
        accent2:  "#7B61FF",
        positive: "#00E08F",
        warning:  "#F4A12C",
        danger:   "#FF4B6E",
        muted:    "#A6B0CF",
        text:     "#E6ECFF",
      },
      fontFamily: {
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
        sans: ["Inter", "ui-sans-serif", "system-ui"],
      },
      boxShadow: {
        cyber: "0 0 0 1px rgba(0,229,255,.22), 0 8px 28px -8px rgba(0,229,255,.15)",
        glow:  "0 0 18px rgba(0,229,255,.25)",
        glowLg:"0 0 60px rgba(0,229,255,.18)",
      },
      backgroundImage: {
        "hex-grid":
          "radial-gradient(circle at 1px 1px, rgba(0,229,255,0.06) 1px, transparent 0)",
        "hero-glow":
          "radial-gradient(800px 400px at 50% 0%, rgba(0,229,255,0.18), transparent 70%)",
      },
      backgroundSize: { hex: "18px 18px" },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4,0,0.6,1) infinite",
      },
    },
  },
  plugins: [],
};

export default config;
