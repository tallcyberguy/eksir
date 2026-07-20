"use client";

import { Target, Flame, ChevronDown } from "lucide-react";

/** enrichment["scores"] as written by backend pipeline/scoring.py. */
export interface Scores {
  confidence?: number | null;        // 0-100, epistemic certainty of the verdict
  threat?: number | null;            // 0-100, EFFECTIVE threat (inherent × P(malicious))
  threat_inherent?: number | null;   // 0-100, "if real, how bad"
  p_malicious?: number | null;
  confidence_band?: string | null;   // low | medium | high
  contributions?: {
    confidence?: Record<string, number>;
    threat?: Record<string, number>;
  };
}

const isNum = (v: unknown): v is number => typeof v === "number" && !Number.isNaN(v);

/** True once the pipeline has written scores (post-synthesis). Lets callers hide
 *  the block entirely for older / pre-scoring incidents instead of an empty card. */
export function hasScores(scores?: Scores | null): boolean {
  return !!scores && (isNum(scores.confidence) || isNum(scores.threat));
}

/** Effective-threat colour band: grey ≤33, amber 34-66, red ≥67. */
function threatTone(n: number) {
  if (n >= 67) return { text: "text-danger",  bg: "bg-danger/10",  border: "border-danger/40",  label: "high" };
  if (n >= 34) return { text: "text-warning", bg: "bg-warning/10", border: "border-warning/40", label: "elevated" };
  return { text: "text-muted", bg: "bg-muted/10", border: "border-muted/40", label: "low" };
}

function confBandLabel(scores: Scores): string {
  if (scores.confidence_band) return scores.confidence_band;
  const c = scores.confidence ?? 0;
  return c >= 75 ? "high" : c >= 50 ? "medium" : "low";
}

/* ── D · compact chips for list rows + the case header ────────────────────── */
export function ScoreChips({ confidence, threat }: { confidence?: number | null; threat?: number | null }) {
  if (!isNum(confidence) && !isNum(threat)) {
    return <span className="text-muted text-xs">—</span>;
  }
  const t = isNum(threat) ? threatTone(threat) : null;
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap">
      {isNum(confidence) && (
        <span title={`Confidence ${confidence}/100 — how sure of the verdict`}
              className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-mono
                         bg-accent/10 text-accent border border-accent/40">
          <Target size={11} aria-hidden/>{confidence}
        </span>
      )}
      {isNum(threat) && t && (
        <span title={`Threat ${threat}/100 (effective)`}
              className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-mono border ${t.bg} ${t.text} ${t.border}`}>
          <Flame size={11} aria-hidden/>{threat}
        </span>
      )}
    </span>
  );
}

/* ── A · detail tiles + "why this score" breakdown ───────────────────────── */
const CONF_LABELS: Record<string, string> = {
  llm_band_prior: "model band",
  exact_match: "exact-match prior",
  n_way: "n-way agreement",
  ioc_history: "IOC track record",
  ti_agreement: "threat intel",
  ti_contradiction: "threat intel (conflicts)",
  ti_clean: "threat intel checked clean",
  similar_support: "similar cases",
};
const CONF_CAPS: Record<string, string> = {
  _cap_no_priors: "no prior-case evidence",
  _cap_inconclusive: "inconclusive verdict",
  _cap_sensitive_dismiss: "sensitive rule",
};
const THREAT_LABELS: Record<string, string> = {
  severity_base: "severity base",
  ti_reputation: "threat intel",
  attack_shape: "attack chain",
  asset_criticality: "asset criticality",
};

function pts(v: number) {
  const n = Math.round(v * 100);
  return (n >= 0 ? "+" : "") + n;
}

export function ScoreTiles({ scores: raw }: { scores?: Scores | null }) {
  if (!hasScores(raw)) return null;      // caller decides the empty state
  const scores = raw as Scores;
  const conf = scores.confidence ?? 0;
  const threat = scores.threat ?? 0;
  const t = threatTone(threat);
  const cContrib = scores.contributions?.confidence ?? {};
  const tContrib = scores.contributions?.threat ?? {};

  const confRows = Object.entries(cContrib).filter(([k]) => !k.startsWith("_cap_"));
  const capRows = Object.entries(cContrib).filter(([k]) => k.startsWith("_cap_"));

  const threatWhy =
    Object.entries(tContrib)
      .filter(([k]) => k in THREAT_LABELS)
      .map(([k, v]) => `${THREAT_LABELS[k]} ${Math.round(v)}`)
      .join(" + ") + (isNum(scores.p_malicious) ? ` × P ${scores.p_malicious}` : "");

  return (
    <div className="space-y-2.5">
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-md bg-surface2/40 border border-line/60 px-2.5 py-2">
          <div className="flex items-center gap-1 text-[11px] text-muted">
            <Target size={12} aria-hidden/>confidence
            <span className="ml-auto text-[9px] uppercase tracking-wider px-1 py-0.5 rounded bg-accent/10 text-accent border border-accent/40">
              {confBandLabel(scores)}
            </span>
          </div>
          <div className="mt-1 flex items-baseline gap-1">
            <span className="text-2xl leading-none font-semibold text-accent tabular-nums">{conf}</span>
            <span className="text-muted text-[10px]">/100</span>
          </div>
        </div>
        <div className="rounded-md bg-surface2/40 border border-line/60 px-2.5 py-2">
          <div className="flex items-center gap-1 text-[11px] text-muted">
            <Flame size={12} aria-hidden/>threat
            <span className={`ml-auto text-[9px] uppercase tracking-wider px-1 py-0.5 rounded border ${t.bg} ${t.text} ${t.border}`}>
              {t.label}
            </span>
          </div>
          <div className="mt-1 flex items-baseline gap-1">
            <span className={`text-2xl leading-none font-semibold tabular-nums ${t.text}`}>{threat}</span>
            <span className="text-muted text-[10px]">/100</span>
          </div>
          {isNum(scores.threat_inherent) && (
            <div className="text-[10px] text-muted mt-1">{scores.threat_inherent} if real</div>
          )}
        </div>
      </div>

      <details>
        <summary className="flex items-center gap-1 text-[11px] text-muted cursor-pointer select-none list-none [&::-webkit-details-marker]:hidden">
          <ChevronDown size={12} aria-hidden/>
          why this score
        </summary>
        <div className="mt-1.5 space-y-0.5">
          {confRows.map(([k, v]) => (
            <div key={k} className="flex justify-between gap-2 text-[11px] text-text/80">
              <span>{CONF_LABELS[k] ?? k}</span>
              <span className={`tabular-nums shrink-0 ${v < 0 ? "text-danger" : "text-accent"}`}>{pts(v)}</span>
            </div>
          ))}
          {capRows.map(([k, v]) => (
            <div key={k} className="flex justify-between gap-2 text-[11px] text-muted">
              <span>capped: {CONF_CAPS[k] ?? k.replace("_cap_", "")}</span>
              <span className="tabular-nums shrink-0">≤{Math.round(v * 100)}</span>
            </div>
          ))}
          {threatWhy && (
            <div className="text-[11px] text-muted leading-relaxed border-t border-line/60 mt-1 pt-1">
              threat: {threatWhy} → <span className={`tabular-nums ${t.text}`}>{threat}</span>
            </div>
          )}
        </div>
      </details>
    </div>
  );
}
