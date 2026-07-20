"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { Panel } from "@/components/ui/Panel";
import { api } from "@/lib/api";
import { ExternalLink, Database } from "lucide-react";

/** Shape of one similarity hit as returned by the orchestrator's _step_dedup.
 *  Keys mirror what `store.AlertStore.search_similar` writes into Qdrant payloads. */
interface SimHit {
  alert_id:        string;
  cosine?:         number;      // TRUE dense cosine in [0,1] — the displayed "% match"
  score?:          number;      // RRF fusion score — recall/ordering only, NOT a %
  adjusted_score?: number;      // reranker ordering score in [0,1] — NOT displayed as %
  verdict?:        string;      // "TP" | "FP" | "benign" | ...
  verdict_reason?: string;
  rule_name?:      string;
  customer?:       string;
  human_verified?: boolean;
  timestamp?:      string;
}

interface Resolved {
  id: string;
  case_number: string;
  title: string;
  customer: string | null;
  verdict: string | null;
}

interface Props {
  enrichment: any | null | undefined;
}

const verdictClass = (v: string | null | undefined): string => {
  switch ((v || "").toLowerCase()) {
    case "tp":      return "text-danger border-danger/40 bg-danger/10";
    case "fp":      return "text-positive border-positive/40 bg-positive/10";
    case "benign":  return "text-warning border-warning/40 bg-warning/10";
    default:        return "text-muted border-line bg-base";
  }
};

const isRecent = (ts?: string, days = 90): boolean => {
  if (!ts) return false;
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return false;
  return (Date.now() - t) / 86_400_000 <= days;
};

export function SimilarCasesPanel({ enrichment }: Props) {
  // Collect every alert_id we might want to resolve: similar_top5 + exact_match + n_way.matches.
  // De-dup so we don't pay for the same lookup twice.
  const hits: SimHit[] = useMemo(() => {
    if (!enrichment) return [];
    const out: SimHit[] = [];
    if (enrichment.exact_match) out.push({ ...enrichment.exact_match });
    if (enrichment.n_way?.matches) {
      for (const m of enrichment.n_way.matches) out.push({ ...m });
    }
    for (const s of (enrichment.similar_top5 || [])) out.push({ ...s });

    // De-dup by alert_id, keep first (exact_match wins over similar).
    const seen = new Set<string>();
    return out.filter(h => {
      if (!h.alert_id || seen.has(h.alert_id)) return false;
      seen.add(h.alert_id);
      return true;
    });
  }, [enrichment]);

  const [resolved, setResolved] = useState<Record<string, Resolved>>({});
  const [loading,  setLoading]  = useState(false);

  useEffect(() => {
    if (hits.length === 0) { setResolved({}); return; }
    let cancelled = false;
    setLoading(true);
    api.lookupByQdrantIds(hits.map(h => h.alert_id))
       .then(r => { if (!cancelled) setResolved(r || {}); })
       .catch(() => { if (!cancelled) setResolved({}); })
       .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [hits]);

  if (hits.length === 0) return null;

  return (
    <Panel title="Similar cases">
      <div className="flex items-center gap-2 text-[11px] text-muted mb-3">
        <Database size={12} className="text-accent"/>
        <span>
          {hits.length} match{hits.length === 1 ? "" : "es"} from the vector DB
          {loading && <span className="text-muted/60 ml-2 italic">resolving links…</span>}
        </span>
      </div>

      <div className="overflow-x-auto -mx-2">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[10px] uppercase tracking-[0.16em] text-muted">
              <th className="text-left font-medium py-2 px-2">Verdict</th>
              <th className="text-left font-medium py-2 px-2 w-20">Score</th>
              <th className="text-left font-medium py-2 px-2">Source</th>
              <th className="text-left font-medium py-2 px-2">Reason</th>
            </tr>
          </thead>
          <tbody>
            {hits.map(h => {
              const r = resolved[h.alert_id];
              // Display the TRUE dense cosine as the "% match" (fall back to the
              // RRF score only for legacy rows without a cosine). Ordering is done
              // server-side by adjusted_score; we render in the given order.
              const cos = typeof h.cosine === "number"
                            ? h.cosine
                            : (typeof h.score === "number" ? h.score : 0);
              const cosClamped = Math.max(0, Math.min(1, cos));
              const pct = Math.round(cosClamped * 100);
              const weak = cos < 0.75;        // cosine-based weak threshold
              const nearDup = cos >= 0.97;    // essentially the same prior alert
              const recent = isRecent(h.timestamp);
              const rowDim = weak ? "opacity-50" : "";
              return (
                <tr key={h.alert_id}
                    className={`border-t border-line/60 align-top hover:bg-surface2/30 transition-colors ${rowDim}`}>
                  <td className="py-2.5 px-2">
                    <span className={`inline-flex px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider
                                       rounded border ${verdictClass(h.verdict)}`}>
                      {h.verdict || "?"}
                    </span>
                  </td>
                  <td className="py-2.5 px-2 font-mono text-xs">
                    <div className="text-text font-semibold">{pct}%</div>
                    <div className="text-muted text-[10px]">cos {cosClamped.toFixed(3)}</div>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {nearDup && (
                        <span className="text-[9px] px-1 py-0.5 rounded bg-accent/15 text-accent border border-accent/30"
                              title="≥0.97 cosine — essentially the same prior alert.">near-dup</span>
                      )}
                      {h.human_verified && (
                        <span className="text-[9px] px-1 py-0.5 rounded bg-positive/15 text-positive border border-positive/30"
                              title="Prior verdict confirmed by a human analyst.">✓ verified</span>
                      )}
                      {recent && (
                        <span className="text-[9px] px-1 py-0.5 rounded bg-surface2 text-muted border border-line"
                              title="Prior case is within the last 90 days.">recent</span>
                      )}
                      {weak && (
                        <span className="text-[9px] px-1 py-0.5 rounded text-muted/70 border border-line uppercase tracking-wider"
                              title="Cosine < 0.75 — likely a boilerplate collision, not a real semantic match.">weak</span>
                      )}
                    </div>
                  </td>
                  <td className="py-2.5 px-2">
                    {r ? (
                      <Link href={`/incidents/${r.id}`}
                            className="group inline-flex items-center gap-1.5 text-accent hover:underline">
                        <span className="font-mono text-xs">{r.case_number}</span>
                        <ExternalLink size={11} className="opacity-60 group-hover:opacity-100"/>
                      </Link>
                    ) : (
                      <span className="font-mono text-[10px] text-muted/70" title={h.alert_id}>
                        {h.alert_id.slice(0, 8)}…
                      </span>
                    )}
                    <div className="text-[10px] text-muted mt-0.5">
                      {r?.title || h.rule_name || "—"}
                      {(r?.customer || h.customer) && (
                        <span className="text-muted/60"> · {r?.customer || h.customer}</span>
                      )}
                    </div>
                  </td>
                  <td className="py-2.5 px-2 text-xs text-muted leading-relaxed max-w-md">
                    {h.verdict_reason || <em className="text-muted/50">no reason recorded</em>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="mt-3 text-[10px] text-muted/70 leading-relaxed">
        Matches with no link were either created by another tool (SKILL workflow), are outside your
        tenant scope, or have been deleted from ISOC. They remain in the vector DB for similarity but
        can't be navigated to.
      </p>
    </Panel>
  );
}
