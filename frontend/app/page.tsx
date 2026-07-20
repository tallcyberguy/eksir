"use client";

import { useEffect, useMemo, useState } from "react";
import useSWR from "../lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  PieChart, Pie, Cell,
  XAxis, YAxis, ResponsiveContainer, Tooltip, Legend, CartesianGrid,
} from "recharts";
import { Edit3, Save, RotateCcw, Building2, X, Plus, EyeOff } from "lucide-react";
import { Responsive, WidthProvider, type Layouts } from "react-grid-layout";

// react-grid-layout styles. These come from the library and Tailwind doesn't
// touch them — they handle the drag/resize handles and the placeholder.
import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";

const ResponsiveGridLayout = WidthProvider(Responsive);

// ── Colour tokens (must stay in sync with CSS vars in globals.css) ──────
const C = {
  positive: "#00E08F",
  danger:   "#FF4B6E",
  warning:  "#F4A12C",
  accent:   "#00E5FF",
  accent2:  "#7B61FF",
  muted:    "#A6B0CF",
  surface:  "#0E1A3A",
  line:     "#1E3061",
};
const SEVERITY_COLORS: Record<string,string> = {
  critical: C.danger, high: C.warning, medium: C.accent, low: C.muted,
};
const STATUS_COLORS: Record<string,string> = {
  closed: C.positive, awaiting_review: C.accent, failed: C.danger,
  received: C.warning, enriching: C.warning, awaiting_synthesis: C.warning,
};
const TOOLTIP_STYLE = {
  contentStyle: { background: "var(--chart-bg)", border: "1px solid var(--chart-bdr)", borderRadius: "6px", fontSize: "12px" },
  cursor: { fill: "rgb(var(--c-surface2) / 0.5)" },
};

// ── Small reusable bits ─────────────────────────────────────────────────
// The wrapping Panel already renders the title above the card, so KPIs don't
// re-render the label. Keep the prop accepted (callers still pass it) but no-op
// it visually — the value + sub line are all that's shown inside.
function KPI({ value, sub, color = "text-accent" }: {
  label?: string; value: string | number; sub?: string; color?: string;
}) {
  return (
    <div className="h-full flex flex-col justify-center gap-1">
      <div className={`font-mono font-bold text-3xl leading-tight ${color}`}>{value}</div>
      {sub && <div className="text-[11px] text-muted">{sub}</div>}
    </div>
  );
}

function TopNList({ items, valueKey, labelKey, color }: {
  items: Record<string,any>[]; valueKey: string; labelKey: string; color: string;
}) {
  if (!items?.length) return <p className="text-xs text-muted">No data.</p>;
  const max = Math.max(...items.map(r => r[valueKey] as number), 1);
  return (
    <div className="space-y-2 max-h-full overflow-y-auto">
      {items.map((r, i) => (
        <div key={i} className="flex items-center gap-3">
          <span className="font-mono text-[10px] text-muted w-4 text-right">{i + 1}</span>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between mb-0.5">
              <span className="text-xs text-text truncate max-w-[70%]" title={r[labelKey]}>{r[labelKey]}</span>
              <span className="font-mono text-xs text-muted ml-2 shrink-0">{r[valueKey]}</span>
            </div>
            <div className="h-1 rounded-full bg-surface2">
              <div className="h-1 rounded-full transition-all"
                   style={{ width: `${(r[valueKey] / max) * 100}%`, background: color }}/>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Panel renderers (one per draggable card) ───────────────────────────
const PANELS: Record<string, { title: string; render: (s: any) => React.ReactNode }> = {
  "kpi-incidents": {
    title: "Total Incidents",
    render: (s) => <KPI label="Total Incidents" value={s.total_incidents ?? 0} sub="last 30 days" color="text-danger"/>,
  },
  "kpi-iocs": {
    title: "Unique Indicators",
    render: (s) => <KPI label="Unique Indicators" value={s.unique_iocs ?? 0} sub="last 30 days" color="text-warning"/>,
  },
  "kpi-tp": {
    title: "True Positives",
    render: (s) => <KPI value={s.true_positive_count ?? 0}
                        sub="last 30 days" color="text-danger"/>,
  },
  "kpi-fp-count": {
    title: "False Positives",
    render: (s) => <KPI value={s.false_positive_count ?? 0}
                        sub="last 30 days" color="text-warning"/>,
  },
  "kpi-llm-cost": {
    title: "LLM Cost (this month)",
    render: (s) => <KPI
      value={s.llm_cost_month_usd > 0 ? `$${s.llm_cost_month_usd.toFixed(2)}` : "—"}
      sub={`${(s.llm_call_count_month ?? 0).toLocaleString()} calls`}
      color="text-accent2"/>,
  },
  "kpi-sla": {
    title: "Avg. SLA",
    render: (s) => <KPI label="Avg. SLA"
                        value={s.avg_sla_minutes ? `${Math.round(s.avg_sla_minutes)} min` : "—"}
                        sub="close time, last 30 days" color="text-positive"/>,
  },
  "kpi-fp-rate": {
    title: "False Positive Rate",
    render: (s) => {
      const fpRate = (s.total_closed ?? 0) > 0
        ? ((s.false_positive_count / s.total_closed) * 100).toFixed(1) + "%"
        : "—";
      return <KPI label="False Positive Rate" value={fpRate}
                  sub={`${s.false_positive_count ?? 0} of ${s.total_closed ?? 0} closed`}
                  color="text-accent2"/>;
    },
  },
  "tpfp-area": {
    title: "True vs False Positives",
    render: (s) => {
      const data = (s.verdict_series ?? []).map((d: any) => ({
        date: d.date?.slice(5), TP: d.TP || 0, FP: d.FP || 0, benign: d.benign || 0,
      }));
      if (!data.length) return <p className="text-xs text-muted">No closed verdicts in this window.</p>;
      return (
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <defs>
              <linearGradient id="gradTP" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={C.positive} stopOpacity={0.35}/>
                <stop offset="95%" stopColor={C.positive} stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="gradFP" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={C.danger}   stopOpacity={0.35}/>
                <stop offset="95%" stopColor={C.danger}   stopOpacity={0}/>
              </linearGradient>
            </defs>
            <XAxis dataKey="date" stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false}/>
            <YAxis stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false}/>
            <Tooltip {...TOOLTIP_STYLE}/>
            <Legend wrapperStyle={{ fontSize: 11, paddingTop: 4 }}/>
            <Area type="monotone" dataKey="TP" name="True Positive"  stroke={C.positive} strokeWidth={2} fill="url(#gradTP)" dot={false}/>
            <Area type="monotone" dataKey="FP" name="False Positive" stroke={C.danger}   strokeWidth={2} fill="url(#gradFP)" dot={false}/>
          </AreaChart>
        </ResponsiveContainer>
      );
    },
  },
  "status-donut": {
    title: "Incident Status",
    render: (s) => {
      const data = Object.entries(s.status_breakdown ?? {})
        .map(([k, v]) => ({ name: k.replace(/_/g," "), value: v as number,
                            color: STATUS_COLORS[k] || C.muted }))
        .filter(d => d.value > 0);
      if (!data.length) return <p className="text-xs text-muted">No data.</p>;
      return (
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} innerRadius={42} outerRadius={68} paddingAngle={3} dataKey="value" nameKey="name">
              {data.map((d, i) => <Cell key={i} fill={d.color}/>)}
            </Pie>
            <Tooltip {...TOOLTIP_STYLE}/>
            <Legend layout="vertical" align="right" verticalAlign="middle"
                    wrapperStyle={{ fontSize: 10 }}
                    formatter={(v) => <span style={{ color: C.muted }}>{v}</span>}/>
          </PieChart>
        </ResponsiveContainer>
      );
    },
  },
  "monthly-bar": {
    title: "Monthly Incidents",
    render: (s) => (
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={s.monthly_cases ?? []} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
          <XAxis dataKey="month" stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false}
                 tickFormatter={(m: string) => m?.slice(5, 7) ?? m}/>
          <YAxis stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false}/>
          <Tooltip {...TOOLTIP_STYLE}/>
          <Bar dataKey="incidents" fill={C.accent} radius={[4,4,0,0]}/>
        </BarChart>
      </ResponsiveContainer>
    ),
  },
  "severity-donut": {
    title: "Incident Severities",
    render: (s) => {
      const data = ["critical","high","medium","low"].map(k => ({
        name: k.charAt(0).toUpperCase() + k.slice(1),
        value: s.severity_breakdown?.[k] ?? 0,
        color: SEVERITY_COLORS[k],
      })).filter(d => d.value > 0);
      if (!data.length) return <p className="text-xs text-muted">No data.</p>;
      return (
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} innerRadius={42} outerRadius={68} paddingAngle={3} dataKey="value" nameKey="name">
              {data.map((d, i) => <Cell key={i} fill={d.color}/>)}
            </Pie>
            <Tooltip {...TOOLTIP_STYLE}/>
            <Legend layout="vertical" align="right" verticalAlign="middle"
                    wrapperStyle={{ fontSize: 11 }}
                    formatter={(v, entry: any) => (
                      <span style={{ color: entry.payload.color }}>
                        {v}: <strong>{entry.payload.value}</strong>
                      </span>
                    )}/>
          </PieChart>
        </ResponsiveContainer>
      );
    },
  },
  "top-iocs": {
    title: "Top 10 Indicators",
    render: (s) => <TopNList items={s.top_indicators ?? []} labelKey="value" valueKey="count" color={C.warning}/>,
  },
  "top-rules": {
    title: "Top 10 Alert Rules",
    render: (s) => <TopNList items={s.top_rules ?? []} labelKey="rule" valueKey="count" color={C.accent2}/>,
  },

  // ── SLA charts ────────────────────────────────────────────────────
  "sla-trend": {
    title: "SLA Trend — Overall (avg, minutes)",
    render: (s) => {
      // Overall average close-time per day. Single line — the "is our SLA
      // getting better or worse" view managers care about. Severity breakdown
      // lives in the sibling sla-by-sev panel below.
      const data = (s.sla_trend ?? []).map((d: any) => ({
        date: d.date?.slice(5),
        overall: d.overall ?? null,
        count:   d.count   ?? 0,
      }));
      if (!data.length) return <p className="text-xs text-muted">No closed incidents in this window.</p>;
      return (
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.line} vertical={false}/>
            <XAxis dataKey="date" stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false}/>
            <YAxis stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false} axisLine={false}
                   tickFormatter={(v: number) => v >= 60 ? `${(v/60).toFixed(1)}h` : `${v}m`}/>
            <Tooltip {...TOOLTIP_STYLE}
                     formatter={(v: any, _n: any, p: any) =>
                       v == null ? "—"
                                 : [`${Math.round(v)} min`, `${p?.payload?.count ?? 0} closed`]}/>
            <Line type="monotone" dataKey="overall" name="Avg close time"
                  stroke={C.accent} strokeWidth={2} dot={{ r: 3, fill: C.accent }}
                  connectNulls/>
          </LineChart>
        </ResponsiveContainer>
      );
    },
  },
  "mttr-percentiles": {
    title: "Resolution time — p50 / p90",
    render: (s) => {
      const data = (s._trends?.mttr_trend ?? []).map((d: any) => ({
        date: d.date?.slice(5), p50: d.p50, p90: d.p90,
      }));
      if (!data.length) return <p className="text-xs text-muted">No closed incidents in this window.</p>;
      return (
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.line} vertical={false}/>
            <XAxis dataKey="date" stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false}/>
            <YAxis stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false} axisLine={false}
                   tickFormatter={(v: number) => v >= 60 ? `${(v/60).toFixed(1)}h` : `${v}m`}/>
            <Tooltip {...TOOLTIP_STYLE}
                     formatter={(v: any) => v == null ? "—" : `${Math.round(v)} min`}/>
            <Legend formatter={(v) => <span style={{ color: C.muted, fontSize: 11 }}>{v}</span>}/>
            <Line type="monotone" dataKey="p50" name="Median (p50)" stroke={C.positive}
                  strokeWidth={2} dot={false} connectNulls/>
            <Line type="monotone" dataKey="p90" name="p90 (slowest 10%)" stroke={C.warning}
                  strokeWidth={2} strokeDasharray="4 2" dot={false} connectNulls/>
          </LineChart>
        </ResponsiveContainer>
      );
    },
  },
  "source-volume": {
    title: "Alert volume by source",
    render: (s) => {
      const tv = s._trends?.source_volume;
      const sources: string[] = tv?.sources ?? [];
      const data = (tv?.series ?? []).map((d: any) => ({ ...d, date: d.date?.slice(5) }));
      if (!data.length) return <p className="text-xs text-muted">No incidents in this window.</p>;
      const palette = [C.accent, C.accent2, C.positive, C.warning, C.danger, C.muted, C.line];
      return (
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.line} vertical={false}/>
            <XAxis dataKey="date" stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false}/>
            <YAxis stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false}/>
            <Tooltip {...TOOLTIP_STYLE}/>
            <Legend formatter={(v) => <span style={{ color: C.muted, fontSize: 11 }}>{v}</span>}/>
            {sources.map((src, i) => (
              <Area key={src} type="monotone" dataKey={src} name={src} stackId="1"
                    stroke={palette[i % palette.length]} fill={palette[i % palette.length]}
                    fillOpacity={0.22} strokeWidth={1.5}/>
            ))}
          </AreaChart>
        </ResponsiveContainer>
      );
    },
  },
  "sla-dist": {
    title: "SLA Distribution",
    render: (s) => {
      const data = s.sla_distribution ?? [];
      if (!data.length || data.every((d: any) => d.count === 0)) {
        return <p className="text-xs text-muted">No closed incidents.</p>;
      }
      return (
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.line} vertical={false}/>
            <XAxis dataKey="bucket" stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false} interval={0}/>
            <YAxis stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false}/>
            <Tooltip {...TOOLTIP_STYLE}/>
            <Bar dataKey="count" fill={C.accent2} radius={[4,4,0,0]}/>
          </BarChart>
        </ResponsiveContainer>
      );
    },
  },
  "sla-by-sev": {
    title: "SLA Trend by Priority (avg, minutes)",
    render: (s) => {
      // Same time series as sla-trend but split per severity. Cast to any[]
      // here because sla_trend is typed loose (dict[str, Any]) on the backend.
      const data: any[] = (s.sla_trend ?? []).map((d: any) => ({
        date: d.date?.slice(5),
        critical: d.critical ?? null,
        high:     d.high     ?? null,
        medium:   d.medium   ?? null,
        low:      d.low      ?? null,
      }));
      if (!data.length) return <p className="text-xs text-muted">No closed incidents in this window.</p>;
      // Only legend severities that actually have at least one data point — keeps the chart honest.
      const present = (["critical","high","medium","low"] as const).filter(
        (k) => data.some((d: any) => d[k] != null),
      );
      if (!present.length) return <p className="text-xs text-muted">No closed incidents by severity.</p>;
      return (
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.line} vertical={false}/>
            <XAxis dataKey="date" stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false}/>
            <YAxis stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false} axisLine={false}
                   tickFormatter={(v: number) => v >= 60 ? `${(v/60).toFixed(1)}h` : `${v}m`}/>
            <Tooltip {...TOOLTIP_STYLE}
                     formatter={(v: any) => v == null ? "—" : `${Math.round(v)} min`}/>
            <Legend wrapperStyle={{ fontSize: 11, paddingTop: 4 }}/>
            {present.map((k) => (
              <Line key={k} type="monotone" dataKey={k}
                    name={k.charAt(0).toUpperCase() + k.slice(1)}
                    stroke={SEVERITY_COLORS[k]} strokeWidth={2} dot={false}
                    connectNulls/>
            ))}
          </LineChart>
        </ResponsiveContainer>
      );
    },
  },

  // ── New opt-in panels ──────────────────────────────────────────────
  "daily-incidents": {
    title: "Daily Incidents (last 30 days)",
    render: (s) => {
      const data = (s.daily_incidents ?? []).map((d: any) => ({
        date: d.date?.slice(5), count: d.count ?? 0,
      }));
      if (!data.length) return <p className="text-xs text-muted">No incidents in this window.</p>;
      return (
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <defs>
              <linearGradient id="gradDaily" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={C.accent} stopOpacity={0.4}/>
                <stop offset="95%" stopColor={C.accent} stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke={C.line} vertical={false}/>
            <XAxis dataKey="date" stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false}/>
            <YAxis stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false}/>
            <Tooltip {...TOOLTIP_STYLE}/>
            <Area type="monotone" dataKey="count" name="Incidents"
                  stroke={C.accent} strokeWidth={2} fill="url(#gradDaily)" dot={false}/>
          </AreaChart>
        </ResponsiveContainer>
      );
    },
  },
  "fp-rate-trend": {
    title: "FP Rate — 6-month trend",
    render: (s) => {
      // Show months that actually had closed incidents. A month with 0 closed
      // would lie as "0%" — drop it instead.
      const data = (s.fp_rate_trend ?? [])
        .filter((d: any) => d.closed > 0)
        .map((d: any) => ({ month: d.month?.slice(0, 7), rate: d.rate }));
      if (!data.length) return <p className="text-xs text-muted">No closed incidents in the last 6 months.</p>;
      return (
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.line} vertical={false}/>
            <XAxis dataKey="month" stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false}
                   tickFormatter={(m: string) => m?.slice(5) ?? m}/>
            <YAxis stroke={C.muted} tick={{ fontSize: 10 }} tickLine={false} axisLine={false}
                   tickFormatter={(v: number) => `${v}%`}/>
            <Tooltip {...TOOLTIP_STYLE}
                     formatter={(v: any) => v == null ? "—" : `${v}%`}/>
            <Line type="monotone" dataKey="rate" name="FP rate"
                  stroke={C.warning} strokeWidth={2} dot={{ r: 3, fill: C.warning }}/>
          </LineChart>
        </ResponsiveContainer>
      );
    },
  },
  "verdict-donut": {
    title: "Verdict Breakdown",
    render: (s) => {
      // Build from verdict_series (which has per-day TP/FP/benign counts) by
      // summing across all days. Same source the area chart uses.
      const totals: Record<string, number> = { TP: 0, FP: 0, benign: 0, pending: 0 };
      for (const row of (s.verdict_series ?? [])) {
        for (const k of Object.keys(totals)) totals[k] += row[k] ?? 0;
      }
      const colors: Record<string, string> = {
        TP: C.danger, FP: C.warning, benign: C.positive, pending: C.muted,
      };
      const data = Object.entries(totals)
        .map(([k, v]) => ({ name: k, value: v, color: colors[k] }))
        .filter(d => d.value > 0);
      if (!data.length) return <p className="text-xs text-muted">No verdicts yet.</p>;
      return (
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} innerRadius={42} outerRadius={68} paddingAngle={3} dataKey="value" nameKey="name">
              {data.map((d, i) => <Cell key={i} fill={d.color}/>)}
            </Pie>
            <Tooltip {...TOOLTIP_STYLE}/>
            <Legend layout="vertical" align="right" verticalAlign="middle"
                    wrapperStyle={{ fontSize: 10 }}
                    formatter={(v) => <span style={{ color: C.muted }}>{v}</span>}/>
          </PieChart>
        </ResponsiveContainer>
      );
    },
  },
  "llm-tokens": {
    title: "LLM Token Usage (this month)",
    render: (s) => {
      const input  = s.llm_input_tokens_month  ?? 0;
      const output = s.llm_output_tokens_month ?? 0;
      if (input === 0 && output === 0) {
        return <p className="text-xs text-muted">No LLM activity this month.</p>;
      }
      return (
        <div className="h-full grid grid-cols-2 gap-4 items-center">
          <div className="flex flex-col gap-1">
            <div className="text-[10px] uppercase tracking-widest text-muted">Input tokens</div>
            <div className="font-mono font-bold text-2xl text-accent">{input.toLocaleString()}</div>
          </div>
          <div className="flex flex-col gap-1">
            <div className="text-[10px] uppercase tracking-widest text-muted">Output tokens</div>
            <div className="font-mono font-bold text-2xl text-accent2">{output.toLocaleString()}</div>
          </div>
        </div>
      );
    },
  },
};

// ── Default layout (matches the original static dashboard, plus the 3 SLA charts) ──
// Coordinates use a 12-column grid with row height 50px. `h` × 50 + (h-1)*margin =
// effective pixel height. KPI cards are h=2 (~120 px), charts h=5 (~265 px), lists h=6.
const DEFAULT_LAYOUTS: Layouts = {
  lg: [
    // KPI strip — 6 cards × 2 cols = 12 col grid
    { i: "kpi-incidents",  x: 0,  y: 0,  w: 2, h: 2 },
    { i: "kpi-tp",         x: 2,  y: 0,  w: 2, h: 2 },
    { i: "kpi-fp-count",   x: 4,  y: 0,  w: 2, h: 2 },
    { i: "kpi-fp-rate",    x: 6,  y: 0,  w: 2, h: 2 },
    { i: "kpi-sla",        x: 8,  y: 0,  w: 2, h: 2 },
    { i: "kpi-llm-cost",   x: 10, y: 0,  w: 2, h: 2 },
    // Trend bands (Feature 6)
    { i: "mttr-percentiles", x: 0, y: 2, w: 6, h: 5 },
    { i: "source-volume",    x: 6, y: 2, w: 6, h: 5 },
    // Operational charts
    { i: "daily-incidents",x: 0,  y: 7,  w: 6, h: 5 },
    { i: "fp-rate-trend",  x: 6,  y: 7,  w: 6, h: 5 },
    { i: "verdict-donut",  x: 0,  y: 12, w: 6, h: 5 },
    { i: "severity-donut", x: 6,  y: 12, w: 6, h: 5 },
    // SLA cluster
    { i: "sla-trend",      x: 0,  y: 17, w: 12, h: 5 },
    { i: "sla-by-sev",     x: 0,  y: 22, w: 6, h: 5 },
    { i: "sla-dist",       x: 6,  y: 22, w: 6, h: 5 },
    // Volume + lists + LLM
    { i: "tpfp-area",      x: 0,  y: 27, w: 8, h: 5 },
    { i: "status-donut",   x: 8,  y: 27, w: 4, h: 5 },
    { i: "monthly-bar",    x: 0,  y: 32, w: 6, h: 5 },
    { i: "kpi-iocs",       x: 6,  y: 32, w: 2, h: 2 },
    { i: "llm-tokens",     x: 8,  y: 32, w: 4, h: 2 },
    { i: "top-iocs",       x: 0,  y: 37, w: 6, h: 7 },
    { i: "top-rules",      x: 6,  y: 37, w: 6, h: 7 },
  ],
};

// ── Dashboard page ─────────────────────────────────────────────────────
export default function Dashboard() {
  const { data: stats } = useSWR("stats-30d", () => api.stats("30d"));
  const { data: trends } = useSWR("trends-30d", () => api.dashboardTrends("30d"));
  const { data: layoutResp, mutate: mutateLayout } = useSWR("dashboard-layout",
    () => api.dashboardLayout.get());
  const [me, setMe] = useState<any>(null);
  useEffect(() => { api.me().then(setMe).catch(() => {}); }, []);

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<Layouts | null>(null);

  // Effective layout for rendering: draft (while editing) > stored > built-in default
  const effectiveLayouts: Layouts = draft ?? layoutResp?.layout ?? DEFAULT_LAYOUTS;
  const sourceLabel = layoutResp?.source === "user"   ? "personal"
                    : layoutResp?.source === "tenant" ? "tenant default"
                    : "platform default";

  const onCustomize = () => { setDraft(structuredClone(effectiveLayouts)); setEditing(true); };
  const onCancel    = () => { setDraft(null); setEditing(false); };
  const onSaveMe    = async () => {
    if (!draft) return;
    await api.dashboardLayout.putMine(draft);
    await mutateLayout();
    setDraft(null); setEditing(false);
  };
  const onResetMe   = async () => {
    await api.dashboardLayout.deleteMine();
    await mutateLayout();
    setDraft(null); setEditing(false);
  };
  const onSaveTenant = async () => {
    if (!draft || !layoutResp?.tenant_id) return;
    await api.dashboardLayout.putTenant(layoutResp.tenant_id, draft);
    // Tenant save doesn't change the user's own override, but refresh for source label.
    await mutateLayout();
    setEditing(false);
  };

  const isAdmin = me?.role === "admin";

  // Which panels render = whatever's in the active layout's lg array. Hiding
  // a panel = removing its layout row. Showing = appending a row to the bottom.
  // We don't keep a separate `hidden` list — the layout is the source of truth.
  const visibleIds = (effectiveLayouts.lg ?? []).map(item => item.i);
  const hiddenIds  = Object.keys(PANELS).filter(id => !visibleIds.includes(id));

  // Bring a hidden panel back. Appends to the bottom of every breakpoint with
  // a sensible default size, then lets react-grid-layout's compaction tidy it.
  const showPanel = (id: string) => {
    if (!editing) return;
    const def = PANELS[id]; if (!def) return;
    const defaultSize = id.startsWith("kpi-") ? { w: 2, h: 2 }
                      : id === "llm-tokens"   ? { w: 4, h: 2 }
                      : id.includes("donut")  ? { w: 6, h: 5 }
                      : id.startsWith("top-") ? { w: 6, h: 7 }
                      : { w: 6, h: 5 };
    const current = effectiveLayouts.lg ?? [];
    const maxY = current.reduce((m, it) => Math.max(m, it.y + it.h), 0);
    const next: Layouts = {
      ...effectiveLayouts,
      lg: [...current, { i: id, x: 0, y: maxY, ...defaultSize }],
    };
    setDraft(next);
  };

  // Hide a panel: drop it from every breakpoint. The grid re-flows.
  const hidePanel = (id: string) => {
    if (!editing) return;
    const next: Layouts = Object.fromEntries(
      Object.entries(effectiveLayouts).map(([bp, items]: [string, any]) =>
        [bp, (items as any[]).filter((it: any) => it.i !== id)],
      ),
    ) as Layouts;
    setDraft(next);
  };

  return (
    <div className="space-y-3">
      {/* Top bar: status + edit controls */}
      <div className="flex items-center justify-between gap-3">
        <div className="text-[10px] uppercase tracking-widest text-muted">
          Layout: <span className="text-text/70">{sourceLabel}</span>
        </div>
        <div className="flex items-center gap-2">
          {!editing ? (
            <button onClick={onCustomize}
                    className="inline-flex items-center gap-1.5 text-xs text-muted hover:text-accent px-2 py-1 rounded-md border border-line">
              <Edit3 size={13}/> Customize
            </button>
          ) : (
            <>
              <span className="text-[10px] uppercase tracking-widest text-accent">editing</span>
              {hiddenIds.length > 0 && (
                <AddPanelMenu hiddenIds={hiddenIds} onPick={showPanel}/>
              )}
              <button onClick={onResetMe}
                      className="inline-flex items-center gap-1.5 text-xs text-muted hover:text-warning px-2 py-1 rounded-md border border-line">
                <RotateCcw size={13}/> Reset to tenant default
              </button>
              {isAdmin && layoutResp?.tenant_id && (
                <button onClick={onSaveTenant}
                        className="inline-flex items-center gap-1.5 text-xs text-warning hover:brightness-125 px-2 py-1 rounded-md border border-warning/40">
                  <Building2 size={13}/> Save as tenant default
                </button>
              )}
              <button onClick={onSaveMe}
                      className="inline-flex items-center gap-1.5 text-xs text-accent hover:brightness-125 px-2 py-1 rounded-md border border-accent/60 bg-accent/10">
                <Save size={13}/> Save
              </button>
              <button onClick={onCancel}
                      className="inline-flex items-center gap-1.5 text-xs text-muted hover:text-text px-2 py-1 rounded-md border border-line">
                <X size={13}/> Cancel
              </button>
            </>
          )}
        </div>
      </div>

      <ResponsiveGridLayout
        className={`layout ${editing ? "editing" : ""}`}
        layouts={effectiveLayouts}
        breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480 }}
        cols={{ lg: 12, md: 12, sm: 6, xs: 4 }}
        rowHeight={50}
        margin={[16, 16]}
        containerPadding={[0, 0]}
        isDraggable={editing}
        isResizable={editing}
        onLayoutChange={(_curr, all) => { if (editing) setDraft(all); }}
        draggableCancel=".no-drag"
      >
        {visibleIds.map(id => {
          const def = PANELS[id];
          if (!def) return null;
          return (
            <div key={id} className={editing ? "ring-1 ring-accent/30 rounded-lg relative" : "relative"}>
              {editing && (
                <button
                  onClick={() => hidePanel(id)}
                  className="no-drag absolute top-1 right-1 z-10 p-1 rounded bg-base/80 border border-line text-muted hover:text-danger hover:border-danger/40"
                  title="Hide this panel">
                  <EyeOff size={12}/>
                </button>
              )}
              <Panel title={def.title} className="h-full overflow-hidden">
                {def.render({ ...(stats || {}), _trends: trends })}
              </Panel>
            </div>
          );
        })}
      </ResponsiveGridLayout>
    </div>
  );
}

// Dropdown of currently-hidden panels. Picking one calls onPick(id) which
// re-inserts the panel into the layout draft. Only mounted while editing.
function AddPanelMenu({ hiddenIds, onPick }: {
  hiddenIds: string[]; onPick: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button onClick={() => setOpen(o => !o)}
              className="inline-flex items-center gap-1.5 text-xs text-accent hover:brightness-125 px-2 py-1 rounded-md border border-accent/40">
        <Plus size={13}/> Add panel ({hiddenIds.length})
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-30 min-w-[220px] max-h-[320px] overflow-y-auto
                        bg-base border border-line rounded-md shadow-lg p-1">
          {hiddenIds.map(id => (
            <button key={id}
              onClick={() => { setOpen(false); onPick(id); }}
              className="block w-full text-left px-3 py-1.5 text-xs hover:bg-accent/10 rounded">
              {PANELS[id]?.title ?? id}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
