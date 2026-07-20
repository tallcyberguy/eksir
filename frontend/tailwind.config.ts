import type { Config } from "tailwindcss";

// Colors are CSS-variable-backed so theme switching (dark/darker/light) works
// without a full rebuild. Each CSS var holds space-separated R G B channels so
// Tailwind's opacity modifier (e.g. bg-base/40) resolves correctly.
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        base:     "rgb(var(--c-base)     / <alpha-value>)",
        surface:  "rgb(var(--c-surface)  / <alpha-value>)",
        surface2: "rgb(var(--c-surface2) / <alpha-value>)",
        line:     "rgb(var(--c-line)     / <alpha-value>)",
        accent:   "rgb(var(--c-accent)   / <alpha-value>)",
        accent2:  "rgb(var(--c-accent2)  / <alpha-value>)",
        positive: "rgb(var(--c-positive) / <alpha-value>)",
        warning:  "rgb(var(--c-warning)  / <alpha-value>)",
        danger:   "rgb(var(--c-danger)   / <alpha-value>)",
        muted:    "rgb(var(--c-muted)    / <alpha-value>)",
        text:     "rgb(var(--c-text)     / <alpha-value>)",
      },
      fontFamily: {
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
        sans: ["Inter", "ui-sans-serif", "system-ui"],
      },
      boxShadow: {
        cyber: "0 0 0 1px rgba(0,229,255,.22), 0 8px 28px -8px rgba(0,229,255,.15)",
        glow:  "0 0 18px rgba(0,229,255,.25)",
      },
      backgroundImage: {
        "hex-grid":
          "radial-gradient(circle at 1px 1px, var(--c-hex-dot) 1px, transparent 0)",
      },
      backgroundSize: { hex: "18px 18px" },
      typography: ({ theme }: any) => ({
        cyber: {
          css: {
            "--tw-prose-body":          theme("colors.text"),
            "--tw-prose-headings":      theme("colors.text"),
            "--tw-prose-lead":          theme("colors.muted"),
            "--tw-prose-links":         theme("colors.accent"),
            "--tw-prose-bold":          theme("colors.text"),
            "--tw-prose-counters":      theme("colors.muted"),
            "--tw-prose-bullets":       theme("colors.line"),
            "--tw-prose-hr":            theme("colors.line"),
            "--tw-prose-quotes":        theme("colors.muted"),
            "--tw-prose-quote-borders": theme("colors.line"),
            "--tw-prose-captions":      theme("colors.muted"),
            "--tw-prose-code":          theme("colors.accent"),
            "--tw-prose-pre-code":      theme("colors.text"),
            "--tw-prose-pre-bg":        theme("colors.base"),
            "--tw-prose-th-borders":    theme("colors.line"),
            "--tw-prose-td-borders":    theme("colors.line"),
            "h2": { marginTop: "1.4em", marginBottom: "0.6em", fontSize: "1.1em" },
            "h3": { marginTop: "1.2em", marginBottom: "0.4em", fontSize: "1em",
                    textTransform: "uppercase", letterSpacing: "0.06em",
                    color: theme("colors.muted"), fontWeight: "600" },
            "p":  { marginTop: "0.6em", marginBottom: "0.6em" },
            "ul,ol": { marginTop: "0.4em", marginBottom: "0.6em" },
            "li": { marginTop: "0.2em", marginBottom: "0.2em" },
            "code": { backgroundColor: theme("colors.base"),
                      padding: "1px 5px", borderRadius: "3px",
                      border: `1px solid ${theme("colors.line")}` },
            "code::before": { content: "''" },
            "code::after":  { content: "''" },
            "pre":  { fontSize: "0.78em", lineHeight: "1.45",
                      border: `1px solid ${theme("colors.line")}`,
                      borderRadius: "0.5rem" },
            "table": { fontSize: "0.85em" },
            "th": { color: theme("colors.muted"),
                    fontSize: "0.7rem", textTransform: "uppercase",
                    letterSpacing: "0.06em" },
            "a": { textDecoration: "none" },
            "a:hover": { textDecoration: "underline" },
            "blockquote": { fontStyle: "normal", color: theme("colors.muted") },
            "blockquote p:first-of-type::before": { content: "''" },
            "blockquote p:last-of-type::after":  { content: "''" },
          },
        },
      }),
    },
  },
  plugins: [require("@tailwindcss/typography")],
};

export default config;
