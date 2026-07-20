"use client";

import { useMemo, useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, RefreshCw } from "lucide-react";

type Badge = { key: string; label: string; tone: string };
type Analyst = {
  analyst_id: string;
  analyst_name: string;
  cases: number;
  median_minutes: number | null;
  flip_rate: number;
  accuracy: number;
  speed: number;
  score: number;
  badges: Badge[];
};
type Leaderboard = {
  window_days: number;
  generated_at: string;
  team: { cases: number; median_minutes: number | null; flip_rate: number; analyst_count: number };
  analysts: Analyst[];
  provisional: { analyst_id: string; analyst_name: string; cases: number }[];
  highlights: string[];
};

const WINDOWS = [7, 14, 30, 90];
const TONE: Record<string, string> = {
  positive: "bg-positive/15 text-positive",
  accent: "bg-accent/15 text-accent",
  warning: "bg-warning/15 text-warning",
};
const RANK_RING = ["ring-1 ring-yellow-400/50", "ring-1 ring-slate-300/40", "ring-1 ring-amber-700/40"];
type SortKey = "score" | "cases" | "accuracy" | "speed";

function pct(x: number | null | undefined) {
  return x == null ? "—" : `${Math.round(x * 100)}%`;
}
function dur(min: number | null | undefined) {
  if (min == null) return "—";
  if (min < 60) return `${Math.round(min)}m`;
  const h = Math.floor(min / 60);
  return h < 24 ? `${h}h ${Math.round(min % 60)}m` : `${Math.floor(h / 24)}d ${h % 24}h`;
}
function initials(name: string) {
  return name.split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((s) => s[0]?.toUpperCase()).join("");
}

function Kpi({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="rounded border border-line bg-surface/40 px-4 py-3">
      <div className="text-[11px] tracking-widest uppercase text-muted">{label}</div>
      <div className={`text-xl font-semibold tabular-nums mt-1 ${accent ?? "text-text"}`}>{value}</div>
    </div>
  );
}

export default function AnalyticsPage() {
  const [windowDays, setWindowDays] = useState(30);
  const [sort, setSort] = useState<SortKey>("score");
  const [q, setQ] = useState("");
  const { data, isLoading, mutate } = useSWR<Leaderboard>(
    `analytics.${windowDays}`,
    () => api.analytics.leaderboard(windowDays),
  );

  const ranked = useMemo(() => {
    const list = (data?.analysts ?? []).filter((a) =>
      a.analyst_name.toLowerCase().includes(q.toLowerCase()),
    );
    return [...list].sort((a, b) => b[sort] - a[sort]);
  }, [data, sort, q]);

  const empty = data && data.analysts.length === 0 && data.provisional.length === 0;

  return (
    <div className="max-w-5xl space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex gap-1">
          {WINDOWS.map((w) => (
            <button key={w} onClick={() => setWindowDays(w)}
              className={`px-3 py-1 rounded text-sm ${windowDays === w ? "bg-accent/20 text-text" : "text-muted hover:text-text"}`}>
              {w}d
            </button>
          ))}
        </div>
        <button onClick={() => mutate()} className="text-muted hover:text-text flex items-center gap-1.5 text-sm" title="Refresh">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {isLoading || !data ? (
        <div className="flex items-center gap-2 text-muted text-sm py-8">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Kpi label="Cases signed off" value={String(data.team.cases)} />
            <Kpi label="Median resolution" value={dur(data.team.median_minutes)} />
            <Kpi label="Team flip rate" value={pct(data.team.flip_rate)} accent={data.team.flip_rate ? "text-warning" : "text-positive"} />
            <Kpi label="Analysts active" value={String(data.team.analyst_count)} />
          </div>

          {empty ? (
            <Panel title="Leaderboard">
              <div className="text-sm text-muted py-6 text-center">
                No signed-off cases in this window yet. The leaderboard fills in as analysts
                approve cases at the gate.
              </div>
            </Panel>
          ) : (
            <Panel title="Leaderboard">
              <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
                <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search analyst…"
                  className="bg-surface border border-line rounded px-2 py-1 text-sm text-text w-48" />
                <div className="flex gap-1 text-xs">
                  {(["score", "cases", "accuracy", "speed"] as SortKey[]).map((k) => (
                    <button key={k} onClick={() => setSort(k)}
                      className={`px-2 py-1 rounded capitalize ${sort === k ? "bg-accent/20 text-text" : "text-muted hover:text-text"}`}>
                      {k}
                    </button>
                  ))}
                </div>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[11px] tracking-widest uppercase text-muted text-left">
                    <th className="font-normal py-1.5 w-10">#</th>
                    <th className="font-normal py-1.5">Analyst</th>
                    <th className="font-normal py-1.5 text-right">Cases</th>
                    <th className="font-normal py-1.5 text-right">Median</th>
                    <th className="font-normal py-1.5 text-right">Accuracy</th>
                    <th className="font-normal py-1.5 text-right">Score</th>
                    <th className="font-normal py-1.5">Badges</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {ranked.map((a, i) => (
                    <tr key={a.analyst_id} className="text-text">
                      <td className="py-2 tabular-nums text-muted">{i + 1}</td>
                      <td className="py-2">
                        <span className="inline-flex items-center gap-2">
                          <span className={`w-7 h-7 rounded-full bg-surface2 grid place-items-center text-[10px] font-mono ${i < 3 ? RANK_RING[i] : ""}`}>
                            {initials(a.analyst_name)}
                          </span>
                          {a.analyst_name}
                        </span>
                      </td>
                      <td className="py-2 text-right tabular-nums">{a.cases}</td>
                      <td className="py-2 text-right tabular-nums text-muted">{dur(a.median_minutes)}</td>
                      <td className="py-2 text-right tabular-nums">{pct(a.accuracy)}</td>
                      <td className="py-2 text-right tabular-nums font-semibold">{a.score.toFixed(1)}</td>
                      <td className="py-2">
                        <span className="flex flex-wrap gap-1">
                          {a.badges.map((b) => (
                            <span key={b.key} className={`text-[10px] rounded px-1.5 py-0.5 ${TONE[b.tone] ?? TONE.accent}`}>
                              {b.label}
                            </span>
                          ))}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {data.provisional.length > 0 && (
                <p className="text-[11px] text-muted mt-3">
                  Building track record:{" "}
                  {data.provisional.map((p) => `${p.analyst_name} (${p.cases})`).join(", ")} — need{" "}
                  {5} signed-off cases to rank.
                </p>
              )}
              <p className="text-[11px] text-muted mt-1">
                “Accuracy” = 1 − reversal rate. Speed is the lowest-weighted factor by design.
              </p>
            </Panel>
          )}

          {data.highlights.length > 0 && (
            <Panel title="Highlights">
              <ul className="space-y-1 text-sm text-text">
                {data.highlights.map((h, i) => (
                  <li key={i} className="text-muted">• {h}</li>
                ))}
              </ul>
            </Panel>
          )}
        </>
      )}
    </div>
  );
}
