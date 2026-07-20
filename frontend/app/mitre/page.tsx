"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, RefreshCw } from "lucide-react";

type Technique = { id: string; name: string; count: number };
type Tactic = {
  tactic_id: string;
  name: string;
  order: number;
  technique_count: number;
  occurrence_count: number;
  techniques: Technique[];
};
type Coverage = {
  attack_version: string;
  window_days: number;
  confirmed_only: boolean;
  incident_count: number;
  technique_count: number;
  occurrence_count: number;
  tactic_count: number;
  covered_tactic_count: number;
  tactics: Tactic[];
  unmapped: { id: string; count: number }[];
};

const WINDOWS = [30, 90, 180, 365];

// Static class strings (Tailwind keeps them) for a 4-step heat ramp by count.
const HEAT = [
  "bg-surface/40 text-muted border-line",
  "bg-accent/15 text-text border-accent/30",
  "bg-accent/30 text-text border-accent/50",
  "bg-accent/50 text-text border-accent/70",
  "bg-accent/70 text-text border-accent",
];

function heatClass(count: number, max: number): string {
  if (count <= 0 || max <= 0) return HEAT[0];
  const step = Math.ceil((count / max) * 4);
  return HEAT[Math.min(4, Math.max(1, step))];
}

function Kpi({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="rounded border border-line bg-surface/40 px-4 py-3">
      <div className="text-[11px] tracking-widest uppercase text-muted">{label}</div>
      <div className={`text-xl font-semibold tabular-nums mt-1 ${accent ?? "text-text"}`}>{value}</div>
    </div>
  );
}

export default function MITREPage() {
  const [windowDays, setWindowDays] = useState(90);
  const [confirmedOnly, setConfirmedOnly] = useState(true);
  const { data, isLoading, mutate } = useSWR<Coverage>(
    `mitre.${windowDays}.${confirmedOnly}`,
    () => api.mitre.coverage(windowDays, confirmedOnly),
  );

  const maxCount = data
    ? Math.max(1, ...data.tactics.flatMap((t) => t.techniques.map((tk) => tk.count)))
    : 1;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="flex gap-1">
            {WINDOWS.map((w) => (
              <button
                key={w}
                onClick={() => setWindowDays(w)}
                className={`px-3 py-1 rounded text-sm ${
                  windowDays === w ? "bg-accent/20 text-text" : "text-muted hover:text-text"
                }`}
              >
                {w}d
              </button>
            ))}
          </div>
          <label className="flex items-center gap-2 text-sm text-muted cursor-pointer select-none">
            <input
              type="checkbox"
              checked={confirmedOnly}
              onChange={(e) => setConfirmedOnly(e.target.checked)}
              className="accent-accent"
            />
            Confirmed (TP) only
          </label>
        </div>
        <button
          onClick={() => mutate()}
          className="text-muted hover:text-text flex items-center gap-1.5 text-sm"
          title="Refresh"
        >
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
            <Kpi
              label="Tactics covered"
              value={`${data.covered_tactic_count} / ${data.tactic_count}`}
              accent={data.covered_tactic_count ? "text-accent" : "text-muted"}
            />
            <Kpi label="Techniques" value={String(data.technique_count)} />
            <Kpi label="Occurrences" value={String(data.occurrence_count)} />
            <Kpi label="Incidents" value={String(data.incident_count)} />
          </div>

          <Panel
            title={`ATT&CK coverage — ${
              data.confirmed_only ? "confirmed true positives" : "all analyzed"
            }`}
          >
            {data.incident_count === 0 ? (
              <div className="text-sm text-muted py-2">
                No {data.confirmed_only ? "confirmed (TP)" : "analyzed"} incidents in this window.
                {data.confirmed_only && " Untick “Confirmed only” to include pending/inconclusive cases."}
              </div>
            ) : (
              <div className="overflow-x-auto pb-2">
                <div className="flex gap-2 min-w-max">
                  {data.tactics.map((t) => (
                    <div key={t.tactic_id} className="w-[150px] shrink-0">
                      <div className="mb-1.5">
                        <div className="text-[11px] font-medium text-text leading-tight h-7">
                          {t.name}
                        </div>
                        <div className="text-[10px] text-muted tabular-nums">
                          {t.technique_count} tech · {t.occurrence_count}×
                        </div>
                      </div>
                      <div className="space-y-1">
                        {t.techniques.length === 0 ? (
                          <div className="h-1 rounded bg-line/40" />
                        ) : (
                          t.techniques.map((tk) => (
                            <div
                              key={tk.id}
                              title={`${tk.id} ${tk.name} — ${tk.count} incident(s)`}
                              className={`rounded border px-1.5 py-1 text-[10px] leading-tight ${heatClass(
                                tk.count,
                                maxCount,
                              )}`}
                            >
                              <div className="flex items-center justify-between gap-1">
                                <span className="font-mono">{tk.id}</span>
                                <span className="tabular-nums opacity-80">{tk.count}</span>
                              </div>
                              <div className="truncate opacity-80">{tk.name}</div>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <p className="text-[11px] text-muted mt-3">
              Derived from L2 verdict techniques · ATT&CK {data.attack_version} · heat = incident
              count per technique.
            </p>
          </Panel>

          {data.unmapped.length > 0 && (
            <Panel title="Unmapped techniques">
              <div className="flex flex-wrap gap-1.5">
                {data.unmapped.map((u) => (
                  <span
                    key={u.id}
                    className="text-[11px] font-mono text-muted border border-line rounded px-1.5 py-0.5"
                    title="Not in the curated ATT&CK seed — drop data/attack_enterprise.json to map it."
                  >
                    {u.id} · {u.count}
                  </span>
                ))}
              </div>
            </Panel>
          )}
        </>
      )}
    </div>
  );
}
