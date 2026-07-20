"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { ShieldX, ShieldAlert, ShieldCheck, HelpCircle } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Parse + render an LLM analyst report.
 *
 * The LLM always emits this canonical preamble:
 *
 *     ## Alert Analysis — <rule>
 *     **Recommendation: <TP|FP|BENIGN>** | Confidence: <HIGH|MEDIUM|LOW>
 *
 * We pull those values out and render them as prominent pills at the top,
 * then render the rest of the markdown below — with the duplicate
 * "Alert Analysis" header and "Recommendation:" line stripped from the body.
 */
export function LLMReport({ markdown }: { markdown: string }) {
  const { recommendation, confidence, body } = parseReport(markdown);

  return (
    <div>
      {(recommendation || confidence) && (
        <div className="flex items-center gap-2 flex-wrap mb-4">
          {recommendation && <RecommendationPill value={recommendation}/>}
          {confidence && (
            <span className={cn("pill", confidencePillClass(confidence))}>
              confidence {confidence}
            </span>
          )}
        </div>
      )}

      <article className="prose prose-cyber prose-sm max-w-none">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{body}</ReactMarkdown>
      </article>
    </div>
  );
}

// ── Parsing ───────────────────────────────────────────────────────────

function parseReport(md: string): { recommendation?: string; confidence?: string; body: string } {
  if (!md) return { body: "" };

  const recRe  = /\*\*\s*Recommendation:\s*([A-Z][A-Z _\-]+?)\s*\*\*/i;
  const confRe = /Confidence:\s*([A-Z][A-Z]+)/i;
  const titleRe = /^##\s+Alert Analysis.*$/m;

  const recMatch  = md.match(recRe);
  const confMatch = md.match(confRe);

  // Strip the H2 header + the Recommendation line entirely from the body so
  // we don't render them twice. Also strip the leading "### Summary" since
  // it's redundant after our pill row.
  let body = md;
  body = body.replace(titleRe, "");
  // Strip the entire line that contains the Recommendation declaration.
  body = body.replace(/^.*\*\*\s*Recommendation:[^\n]*$/im, "");
  // Strip the final "Please provide your final verdict: ..." prompt — the
  // verdict buttons live in the parent UI now.
  body = body.replace(/Please provide your final verdict:[\s\S]*$/i, "");
  // Collapse blank-line runs that the stripping left behind.
  body = body.replace(/\n{3,}/g, "\n\n").trim();

  return {
    recommendation: recMatch?.[1]?.trim().toUpperCase(),
    confidence:     confMatch?.[1]?.trim().toUpperCase(),
    body,
  };
}

// ── Pill renderers ─────────────────────────────────────────────────────

function RecommendationPill({ value }: { value: string }) {
  const v = value.toUpperCase();
  const klass =
    /TRUE\s*POSITIVE|^TP$/.test(v)    ? "pill-critical" :
    /FALSE\s*POSITIVE|^FP$/.test(v)   ? "pill-resolved" :
    /BENIGN/.test(v)                  ? "pill-medium"   :
    /INCONCLUSIVE/.test(v)            ? "pill-high"     :
    "pill-low";

  const Icon =
    /TRUE\s*POSITIVE|^TP$/.test(v) ? ShieldX :
    /BENIGN/.test(v)               ? ShieldCheck :
    /FALSE\s*POSITIVE|^FP$/.test(v)? ShieldCheck :
    /INCONCLUSIVE/.test(v)         ? ShieldAlert :
    HelpCircle;

  return (
    <span className={cn("pill inline-flex items-center gap-1.5 text-xs", klass)}>
      <Icon size={12}/> Recommendation: {v}
    </span>
  );
}

function confidencePillClass(c: string): string {
  switch (c.toUpperCase()) {
    case "HIGH":   return "pill-critical";
    case "MEDIUM": return "pill-high";
    case "LOW":    return "pill-low";
    default:       return "pill-low";
  }
}
