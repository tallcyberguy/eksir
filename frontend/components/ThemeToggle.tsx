"use client";

import { useTheme, type Theme } from "./ThemeProvider";
import { Moon, Sun, Zap } from "lucide-react";

const ICONS: Record<Theme, React.ReactNode> = {
  dark:   <Moon size={15}/>,
  darker: <Zap  size={15}/>,
  light:  <Sun  size={15}/>,
};
const LABELS: Record<Theme, string> = {
  dark:   "Dark",
  darker: "Cyber",
  light:  "Light",
};

export function ThemeToggle() {
  const { theme, cycle } = useTheme();
  return (
    <button
      onClick={cycle}
      title={`Theme: ${LABELS[theme]} — click to cycle`}
      className="flex items-center gap-2 px-3 py-2 rounded-md text-muted hover:text-text hover:bg-surface w-full text-sm transition-colors"
    >
      <span className="text-accent">{ICONS[theme]}</span>
      <span>{LABELS[theme]}</span>
    </button>
  );
}
