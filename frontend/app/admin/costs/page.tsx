"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, RefreshCw, PiggyBank } from "lucide-react";

type ModelRow = {
  model: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  avg_latency_ms: number | null;
  is_local: boolean;
};
type DayRow = { day: string; cost_usd: number; calls: number; tokens: number };
type IncRow = { incident_id: string; case_number: string | null; cost_usd: number; calls: number };
type CostDashboard = {
  window_days: number;
  generated_at?: string;
  total_cost_usd: number;
  total_tokens: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_calls: number;
  avg_cost_per_call_usd: number;
  byok_savings_usd: number;
  by_model: ModelRow[];
  by_day: DayRow[];
  top_incidents: IncRow[];
  pricing_note: string;
};

const WINDOWS = [7, 14, 30, 90];

function usd(n: number): string {
  if (!n) return "$0.00";
  return n < 1 ? `$${n.toFixed(4)}` : `$${n.toFixed(2)}`;
}
function tokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return `${n}`;
}

function Kpi({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded border border-line bg-surface/40 px-4 py-3">
      <div className="text-[11px] tracking-widest uppercase text-muted">{label}</div>
      <div className="text-xl font-semibold text-text tabular-nums mt-1">{value}</div>
      {sub && <div className="text-[11px] text-muted mt-0.5">{sub}</div>}
    </div>
  );
}

export default function CostDashboardPage() {
  const [windowDays, setWindowDays] = useState(30);
  const { data, isLoading, mutate } = useSWR<CostDashboard>(
    `admin.costs.${windowDays}`,
    () => api.costs.dashboard(windowDays),
  );

  const maxDay = Math.max(0.000001, ...(data?.by_day ?? []).map((d) => d.cost_usd));

  return (
    <div className="max-w-4xl space-y-5">
      {/* Window selector */}
      <div className="flex items-center justify-between">
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
          {/* KPI strip */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Kpi label="Total spend" value={usd(data.total_cost_usd)} sub={`last ${data.window_days}d`} />
            <Kpi label="LLM calls" value={data.total_calls.toLocaleString()} />
            <Kpi
              label="Tokens"
              value={tokens(data.total_tokens)}
              sub={`${tokens(data.total_input_tokens)} in · ${tokens(data.total_output_tokens)} out`}
            />
            <Kpi label="Avg / call" value={usd(data.avg_cost_per_call_usd)} />
            <Kpi label="BYOK savings" value={usd(data.byok_savings_usd)} sub="self-hosted" />
          </div>

          {/* Per-day spend */}
          <Panel title="Daily spend">
            {data.by_day.length === 0 ? (
              <div className="text-sm text-muted py-2">No LLM calls in this window.</div>
            ) : (
              <div className="flex items-end gap-1 h-40 pt-2">
                {data.by_day.map((d) => (
                  <div key={d.day} className="flex-1 flex flex-col items-center justify-end group" title={`${d.day}: ${usd(d.cost_usd)} · ${d.calls} calls`}>
                    <div
                      className="w-full bg-accent/50 group-hover:bg-accent rounded-t"
                      style={{ height: `${Math.max(2, (d.cost_usd / maxDay) * 100)}%` }}
                    />
                    <div className="text-[9px] text-muted mt-1 rotate-0 truncate w-full text-center">
                      {d.day.slice(5)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          {/* Per-model */}
          <Panel title="Spend by model">
            {data.by_model.length === 0 ? (
              <div className="text-sm text-muted py-2">No data.</div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[11px] tracking-widest uppercase text-muted text-left">
                    <th className="font-normal py-1.5">Model</th>
                    <th className="font-normal py-1.5 text-right">Calls</th>
                    <th className="font-normal py-1.5 text-right">Tokens</th>
                    <th className="font-normal py-1.5 text-right">Avg latency</th>
                    <th className="font-normal py-1.5 text-right">Cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {data.by_model.map((m) => (
                    <tr key={m.model} className="text-text">
                      <td className="py-1.5 font-mono">
                        {m.model}
                        {m.is_local && (
                          <span className="ml-2 text-[10px] text-positive border border-positive/40 rounded px-1">
                            self-hosted
                          </span>
                        )}
                      </td>
                      <td className="py-1.5 text-right tabular-nums">{m.calls.toLocaleString()}</td>
                      <td className="py-1.5 text-right tabular-nums">
                        {tokens(m.input_tokens + m.output_tokens)}
                      </td>
                      <td className="py-1.5 text-right tabular-nums text-muted">
                        {m.avg_latency_ms != null ? `${m.avg_latency_ms}ms` : "—"}
                      </td>
                      <td className="py-1.5 text-right tabular-nums">{usd(m.cost_usd)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>

          {/* Top incidents */}
          {data.top_incidents.length > 0 && (
            <Panel title="Most expensive cases">
              <table className="w-full text-sm">
                <tbody className="divide-y divide-line">
                  {data.top_incidents.map((t) => (
                    <tr key={t.incident_id} className="text-text">
                      <td className="py-1.5 font-mono">{t.case_number ?? t.incident_id.slice(0, 8)}</td>
                      <td className="py-1.5 text-right tabular-nums text-muted">{t.calls} calls</td>
                      <td className="py-1.5 text-right tabular-nums">{usd(t.cost_usd)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          )}

          <p className="text-[11px] text-muted flex items-center gap-1.5">
            <PiggyBank size={12} /> {data.pricing_note}
          </p>
        </>
      )}
    </div>
  );
}
