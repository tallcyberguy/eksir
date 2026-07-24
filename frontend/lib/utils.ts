import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) { return twMerge(clsx(inputs)); }

export const severityPill = (s: string) => {
  switch (s?.toLowerCase()) {
    case "critical": return "pill pill-critical";
    case "high":     return "pill pill-high";
    case "medium":   return "pill pill-medium";
    case "low":      return "pill pill-low";
    default:         return "pill pill-low";
  }
};

export const statusPill = (s: string) => {
  switch (s?.toLowerCase()) {
    case "closed":            return "pill pill-resolved";
    case "awaiting_review":   return "pill pill-medium";
    case "failed":            return "pill pill-critical";
    case "received":
    case "parsed":
    case "enriching":
    case "awaiting_synthesis":return "pill pill-high";
    default:                  return "pill pill-low";
  }
};

export const verdictPill = (v: string) => {
  switch ((v || "").toUpperCase()) {
    case "TP":           return "pill pill-critical";
    case "FP":           return "pill pill-resolved";
    case "BENIGN":       return "pill pill-medium";
    case "INCONCLUSIVE": return "pill pill-high";
    default:             return "pill pill-low";
  }
};

// Entity risk (0-100, confirmed-TP history). Bands mirror severity coloring.
export const riskPill = (risk: number) => {
  if (risk >= 70) return "pill pill-critical";
  if (risk >= 40) return "pill pill-high";
  return "pill pill-medium";
};

// Defang an IOC token (URL / IP / domain / email) so it renders inert and un-clickable.
// Apply ONLY to individual IOC values or autolink anchor text — never to whole report
// prose (it breaks every '.'). Breaks the scheme (http->hxxp), all dots, and '@'.
export function defang(v: string): string {
  return String(v ?? "")
    .replace(/http(s?):\/\//gi, "hxxp$1://")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[at]");
}
