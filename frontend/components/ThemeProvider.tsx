"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";

export type Theme = "dark" | "darker" | "light";
const THEMES: Theme[] = ["dark", "darker", "light"];
const KEY = "eksir-theme";

interface ThemeCtx { theme: Theme; setTheme: (t: Theme) => void; cycle: () => void; }
const Ctx = createContext<ThemeCtx>({ theme: "dark", setTheme: () => {}, cycle: () => {} });

export function useTheme() { return useContext(Ctx); }

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>("dark");

  // Read from localStorage after mount (SSR-safe)
  useEffect(() => {
    const stored = localStorage.getItem(KEY) as Theme | null;
    if (stored && THEMES.includes(stored)) apply(stored, setThemeState);
  }, []);

  const setTheme = useCallback((t: Theme) => apply(t, setThemeState), []);
  const cycle    = useCallback(() => {
    setThemeState(prev => {
      const next = THEMES[(THEMES.indexOf(prev) + 1) % THEMES.length];
      apply(next, setThemeState);
      return next;
    });
  }, []);

  return <Ctx.Provider value={{ theme, setTheme, cycle }}>{children}</Ctx.Provider>;
}

function apply(t: Theme, setState: (t: Theme) => void) {
  const root = document.documentElement;
  root.setAttribute("data-theme", t);
  // Keep .dark class in sync so any dark: tailwind variants work on non-light themes
  if (t === "light") root.classList.remove("dark");
  else               root.classList.add("dark");
  localStorage.setItem(KEY, t);
  setState(t);
}
