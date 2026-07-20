"use client";

import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/api";
import { Panel, StatCard } from "@/components/ui/Panel";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
  PieChart, Pie, Cell,
  LineChart, Line, CartesianGrid,
  AreaChart, Area,
} from "recharts";
import { Download, FileText, Send, Trash2, Plus, RefreshCw, Upload } from "lucide-react";

const VERDICT_COLORS: Record<string, string> = {
  TP: "#FF4B6E",
  FP: "#F4A12C",
  benign: "#00E08F",
  pending: "#A6B0CF",
};
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#FF4B6E",
  high: "#F4A12C",
  medium: "#00E5FF",
  low: "#A6B0CF",
};
const CHART_STYLE = { background: "#0E1A3A", border: "1px solid #1E3061" };

const now = new Date();
const THIS_YEAR  = now.getFullYear();
const THIS_MONTH = now.getMonth() + 1;

const MONTHS = [
  "Jan","Feb","Mar","Apr","May","Jun",
  "Jul","Aug","Sep","Oct","Nov","Dec",
];
const YEARS = [THIS_YEAR - 1, THIS_YEAR];

export default function ReportsPage() {
  const [tab, setTab] = useState<"overview" | "reports">("overview");

  return (
    <div className="space-y-6">
      {/* ── Tab bar ── */}
      <div className="flex items-center gap-1 border-b border-line">
        {(["overview", "reports"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm capitalize -mb-px border-b-2 transition-colors ${
              tab === t
                ? "border-accent text-foreground"
                : "border-transparent text-muted hover:text-foreground"
            }`}
          >
            {t === "overview" ? "Overview" : "Branded Reports"}
          </button>
        ))}
      </div>

      {tab === "overview" ? <OverviewTab /> : <ReportsTab />}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Overview — the existing month-at-a-glance analytics dashboard
// ════════════════════════════════════════════════════════════════════════
function OverviewTab() {
  const [year,     setYear]     = useState(THIS_YEAR);
  const [month,    setMonth]    = useState(THIS_MONTH);
  const [customer, setCustomer] = useState<string>("");

  const [customers, setCustomers] = useState<any[]>([]);
  const [summary,   setSummary]   = useState<any | null>(null);
  const [loading,   setLoading]   = useState(false);

  useEffect(() => {
    api.reports.customers().then(setCustomers).catch(() => {});
  }, []);

  const load = useCallback(() => {
    setLoading(true);
    api.reports.monthly(year, month, customer || undefined)
      .then(setSummary)
      .catch(() => setSummary(null))
      .finally(() => setLoading(false));
  }, [year, month, customer]);

  useEffect(() => { load(); }, [load]);

  const exportCsv = () => {
    const url = api.reports.exportCsvUrl(year, month, customer || undefined);
    const token = typeof window !== "undefined" ? window.localStorage.getItem("isoc.token") : null;
    fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
      .then(r => r.blob())
      .then(blob => {
        const href = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = href;
        a.download = `isoc-${year}-${String(month).padStart(2,"0")}${customer ? `-${customer}` : ""}.csv`;
        a.click();
        URL.revokeObjectURL(href);
      });
  };

  const verdictData = summary
    ? ["TP","FP","benign","pending"].map(k => ({ name: k, value: summary[k] ?? 0 })).filter(d => d.value > 0)
    : [];

  const severityData = summary
    ? Object.entries(summary.severity_breakdown ?? {}).map(([name, value]) => ({ name, value }))
    : [];

  const topCustomers = customers.slice(0, 10);

  return (
    <div className="space-y-6">
      {/* ── Controls ── */}
      <div className="flex flex-wrap items-center gap-3">
        <select
          className="bg-surface border border-line rounded px-3 py-1.5 text-sm text-foreground"
          value={year}
          onChange={e => setYear(Number(e.target.value))}
        >
          {YEARS.map(y => <option key={y} value={y}>{y}</option>)}
        </select>

        <select
          className="bg-surface border border-line rounded px-3 py-1.5 text-sm text-foreground"
          value={month}
          onChange={e => setMonth(Number(e.target.value))}
        >
          {MONTHS.map((m, i) => <option key={i+1} value={i+1}>{m}</option>)}
        </select>

        <select
          className="bg-surface border border-line rounded px-3 py-1.5 text-sm text-foreground min-w-[160px]"
          value={customer}
          onChange={e => setCustomer(e.target.value)}
        >
          <option value="">All customers</option>
          {customers.map(c => (
            <option key={c.customer} value={c.customer}>{c.customer}</option>
          ))}
        </select>

        <button
          onClick={exportCsv}
          className="ml-auto flex items-center gap-2 px-4 py-1.5 rounded bg-accent text-white text-sm hover:bg-accent/80 transition-colors"
        >
          <Download size={14}/> Export CSV
        </button>
      </div>

      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <StatCard label="Total Incidents"  value={summary.total}           accent="text-foreground"/>
          <StatCard label="True Positives"   value={summary.tp}              accent="text-danger"/>
          <StatCard label="False Positives"  value={summary.fp}              accent="text-warning"/>
          <StatCard label="FP Rate"          value={`${summary.fp_rate}%`}   accent="text-warning"/>
          <StatCard label="Avg SLA"
                    value={summary.avg_sla_minutes ? `${Math.round(summary.avg_sla_minutes)} min` : "—"}
                    accent="text-positive"/>
          <StatCard label="LLM Cost"
                    value={summary.llm_total_cost_usd > 0 ? `$${summary.llm_total_cost_usd.toFixed(2)}` : "—"}
                    accent="text-muted"/>
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <Panel title={`Daily Incidents — ${MONTHS[month-1]} ${year}`} className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={summary.daily_series}>
                <defs>
                  <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#00E5FF" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#00E5FF" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E3061"/>
                <XAxis dataKey="date" stroke="#A6B0CF" tickFormatter={d => d?.slice(8)} tick={{fontSize:11}}/>
                <YAxis stroke="#A6B0CF" tick={{fontSize:11}} allowDecimals={false}/>
                <Tooltip contentStyle={CHART_STYLE} cursor={{fill:"#13234C"}}/>
                <Area type="monotone" dataKey="incidents" stroke="#00E5FF" fill="url(#areaGrad)" strokeWidth={2}/>
              </AreaChart>
            </ResponsiveContainer>
          </Panel>

          <Panel title="FP Rate — 6-month trend" className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={summary.fp_trend}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E3061"/>
                <XAxis dataKey="month" stroke="#A6B0CF" tickFormatter={m => m?.slice(5)} tick={{fontSize:11}}/>
                <YAxis stroke="#A6B0CF" unit="%" tick={{fontSize:11}} domain={[0,"auto"]}/>
                <Tooltip contentStyle={CHART_STYLE} formatter={(v: any) => [`${v}%`, "FP Rate"]}/>
                <Line type="monotone" dataKey="fp_rate" stroke="#F4A12C" strokeWidth={2} dot={{r:3, fill:"#F4A12C"}}/>
              </LineChart>
            </ResponsiveContainer>
          </Panel>
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <Panel title="Verdict Breakdown" className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={verdictData} innerRadius={60} outerRadius={95} paddingAngle={2} dataKey="value" label={({name, percent}) => `${name} ${(percent*100).toFixed(0)}%`} labelLine={false}>
                  {verdictData.map((d, i) => (
                    <Cell key={i} fill={VERDICT_COLORS[d.name] || "#A6B0CF"}/>
                  ))}
                </Pie>
                <Tooltip contentStyle={CHART_STYLE}/>
                <Legend/>
              </PieChart>
            </ResponsiveContainer>
          </Panel>

          <Panel title="Severity Breakdown" className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityData} innerRadius={60} outerRadius={95} paddingAngle={2} dataKey="value" label={({name, percent}) => `${name} ${(percent*100).toFixed(0)}%`} labelLine={false}>
                  {severityData.map((d, i) => (
                    <Cell key={i} fill={SEVERITY_COLORS[d.name] || "#A6B0CF"}/>
                  ))}
                </Pie>
                <Tooltip contentStyle={CHART_STYLE}/>
                <Legend/>
              </PieChart>
            </ResponsiveContainer>
          </Panel>
        </div>
      )}

      <Panel title="Top Customers by Case Volume (all-time)" className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={topCustomers} layout="vertical" margin={{left: 16}}>
            <XAxis type="number" stroke="#A6B0CF" tick={{fontSize:11}} allowDecimals={false}/>
            <YAxis type="category" dataKey="customer" stroke="#A6B0CF" tick={{fontSize:11}} width={120}/>
            <Tooltip contentStyle={CHART_STYLE} cursor={{fill:"#13234C"}}/>
            <Legend/>
            <Bar dataKey="tp"     name="TP"     fill="#FF4B6E" stackId="a" radius={0}/>
            <Bar dataKey="fp"     name="FP"     fill="#F4A12C" stackId="a" radius={0}/>
            <Bar dataKey="benign" name="Benign" fill="#00E08F" stackId="a" radius={[0,4,4,0]}/>
          </BarChart>
        </ResponsiveContainer>
      </Panel>

      {summary && (summary.llm_input_tokens > 0 || summary.llm_output_tokens > 0) && (
        <Panel title={`LLM Token Usage — ${MONTHS[month-1]} ${year}`}>
          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 rounded-md bg-surface/60 border border-line">
              <p className="text-xs text-muted uppercase tracking-wider mb-1">Input tokens</p>
              <p className="font-mono text-xl text-foreground">{summary.llm_input_tokens.toLocaleString()}</p>
            </div>
            <div className="p-4 rounded-md bg-surface/60 border border-line">
              <p className="text-xs text-muted uppercase tracking-wider mb-1">Output tokens</p>
              <p className="font-mono text-xl text-foreground">{summary.llm_output_tokens.toLocaleString()}</p>
            </div>
          </div>
        </Panel>
      )}

      {loading && (
        <p className="text-sm text-muted text-center animate-pulse">Loading…</p>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Branded Reports — templates, branding, generate, schedules, history
// ════════════════════════════════════════════════════════════════════════
const INPUT = "bg-surface border border-line rounded px-3 py-1.5 text-sm text-foreground";
const BTN = "flex items-center gap-2 px-3 py-1.5 rounded text-sm transition-colors disabled:opacity-40";

function ReportsTab() {
  const [templates, setTemplates] = useState<any[]>([]);
  const [tenants,   setTenants]   = useState<{ id: string; name: string }[]>([]);
  const [msg,       setMsg]       = useState<string | null>(null);

  useEffect(() => {
    api.reports.templates().then(setTemplates).catch(() => {});
    api.reports.tenants().then(setTenants).catch(() => {});
  }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(null), 4000); };

  return (
    <div className="space-y-6">
      {msg && (
        <div className="px-4 py-2 rounded bg-surface border border-accent/50 text-sm text-foreground">{msg}</div>
      )}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <GeneratePanel templates={templates} tenants={tenants} onDone={flash} />
        <BrandingPanel tenants={tenants} onDone={flash} />
      </div>
      <SchedulesPanel templates={templates} tenants={tenants} onDone={flash} />
      <HistoryPanel tenants={tenants} onDone={flash} />
    </div>
  );
}

function tenantName(tenants: { id: string; name: string }[], id: string | null) {
  if (!id) return "All customers";
  return tenants.find(t => t.id === id)?.name ?? id.slice(0, 8);
}

// ── Generate (on-demand) ──────────────────────────────────────────────────
function GeneratePanel({ templates, tenants, onDone }: any) {
  const [template, setTemplate] = useState("monthly_ops");
  const [tenantId, setTenantId] = useState("");
  const [year, setYear]   = useState(THIS_YEAR);
  const [month, setMonth] = useState(THIS_MONTH);
  const [busy, setBusy]   = useState(false);

  const generate = async () => {
    setBusy(true);
    try {
      const r = await api.reports.generate({
        template_key: template,
        tenant_id: tenantId || undefined,
        year, month,
      });
      onDone(`Generated “${r.title}” (draft). See History below.`);
    } catch (e: any) {
      onDone(`Generate failed: ${e.message ?? e}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Generate a report">
      <div className="space-y-3">
        <label className="block text-xs text-muted uppercase tracking-wider">Template</label>
        <select className={`${INPUT} w-full`} value={template} onChange={e => setTemplate(e.target.value)}>
          {templates.map((t: any) => <option key={t.key} value={t.key}>{t.title}</option>)}
        </select>
        <p className="text-xs text-muted">{templates.find((t: any) => t.key === template)?.description}</p>

        <label className="block text-xs text-muted uppercase tracking-wider">Customer</label>
        <select className={`${INPUT} w-full`} value={tenantId} onChange={e => setTenantId(e.target.value)}>
          <option value="">All customers</option>
          {tenants.map((t: any) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>

        <div className="flex gap-3">
          <select className={INPUT} value={year} onChange={e => setYear(Number(e.target.value))}>
            {YEARS.map(y => <option key={y} value={y}>{y}</option>)}
          </select>
          <select className={INPUT} value={month} onChange={e => setMonth(Number(e.target.value))}>
            {MONTHS.map((m, i) => <option key={i+1} value={i+1}>{m}</option>)}
          </select>
          <button onClick={generate} disabled={busy}
                  className={`${BTN} ml-auto bg-accent text-white hover:bg-accent/80`}>
            <FileText size={14}/> {busy ? "Generating…" : "Generate"}
          </button>
        </div>
      </div>
    </Panel>
  );
}

// ── Branding (B2) ───────────────────────────────────────────────────────────
function BrandingPanel({ tenants, onDone }: any) {
  const [tenantId, setTenantId] = useState("");
  const [accent, setAccent]     = useState("#00D4FF");
  const [display, setDisplay]   = useState("");
  const [hasLogo, setHasLogo]   = useState(false);
  const [logoUrl, setLogoUrl]   = useState<string | null>(null);
  const [file, setFile]         = useState<File | null>(null);
  const [busy, setBusy]         = useState(false);

  useEffect(() => {
    setFile(null);
    if (logoUrl) { URL.revokeObjectURL(logoUrl); setLogoUrl(null); }
    if (!tenantId) { setAccent("#00D4FF"); setDisplay(""); setHasLogo(false); return; }
    api.reports.branding(tenantId).then(b => {
      setAccent(b.accent_color || "#00D4FF");
      setDisplay(b.display_name || "");
      setHasLogo(!!b.has_logo);
      if (b.has_logo) api.reports.brandingLogoUrl(tenantId).then(setLogoUrl).catch(() => {});
    }).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantId]);

  const save = async () => {
    if (!tenantId) { onDone("Pick a customer first."); return; }
    setBusy(true);
    try {
      const form = new FormData();
      form.set("tenant_id", tenantId);
      form.set("accent_color", accent);
      form.set("display_name", display);
      if (file) form.set("logo", file);
      await api.reports.putBranding(form);
      onDone("Branding saved.");
      if (file) {
        const url = await api.reports.brandingLogoUrl(tenantId).catch(() => null);
        setLogoUrl(url); setHasLogo(!!url); setFile(null);
      }
    } catch (e: any) {
      onDone(`Save failed: ${e.message ?? e}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Customer branding">
      <div className="space-y-3">
        <select className={`${INPUT} w-full`} value={tenantId} onChange={e => setTenantId(e.target.value)}>
          <option value="">Select a customer…</option>
          {tenants.map((t: any) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>

        {tenantId && (
          <>
            <div className="flex items-center gap-3">
              <label className="text-xs text-muted uppercase tracking-wider w-24">Accent</label>
              <input type="color" value={accent} onChange={e => setAccent(e.target.value)}
                     className="h-8 w-12 bg-surface border border-line rounded"/>
              <input className={`${INPUT} flex-1`} value={accent} onChange={e => setAccent(e.target.value)}/>
            </div>
            <div className="flex items-center gap-3">
              <label className="text-xs text-muted uppercase tracking-wider w-24">Display name</label>
              <input className={`${INPUT} flex-1`} value={display} placeholder="(defaults to tenant name)"
                     onChange={e => setDisplay(e.target.value)}/>
            </div>
            <div className="flex items-center gap-3">
              <label className="text-xs text-muted uppercase tracking-wider w-24">Logo</label>
              <label className={`${BTN} bg-surface border border-line cursor-pointer`}>
                <Upload size={14}/> {file ? file.name : "Choose PNG/JPEG/SVG"}
                <input type="file" accept="image/png,image/jpeg,image/svg+xml" className="hidden"
                       onChange={e => setFile(e.target.files?.[0] ?? null)}/>
              </label>
              {(logoUrl || hasLogo) && logoUrl && (
                // eslint-disable-next-line @next/next/no-img-element
                <img src={logoUrl} alt="logo" className="h-8 bg-white rounded px-1"/>
              )}
            </div>
            <button onClick={save} disabled={busy} className={`${BTN} bg-accent text-white hover:bg-accent/80`}>
              {busy ? "Saving…" : "Save branding"}
            </button>
          </>
        )}
      </div>
    </Panel>
  );
}

// ── Schedules ────────────────────────────────────────────────────────────
function SchedulesPanel({ templates, tenants, onDone }: any) {
  const [rows, setRows]     = useState<any[]>([]);
  const [template, setTemplate] = useState("monthly_ops");
  const [cadence, setCadence]   = useState("monthly");
  const [tenantId, setTenantId] = useState("");

  const load = useCallback(() => { api.reports.schedules().then(setRows).catch(() => setRows([])); }, []);
  useEffect(() => { load(); }, [load]);

  const create = async () => {
    try {
      await api.reports.createSchedule({ template_key: template, cadence, tenant_id: tenantId || undefined });
      onDone("Schedule created."); load();
    } catch (e: any) { onDone(`Failed: ${e.message ?? e}`); }
  };
  const toggle = async (r: any) => { await api.reports.updateSchedule(r.id, { enabled: !r.enabled }); load(); };
  const remove = async (r: any) => { await api.reports.deleteSchedule(r.id); load(); };

  return (
    <Panel title="Scheduled reports (generate to draft — never auto-sent)">
      <div className="flex flex-wrap items-end gap-3 mb-4">
        <select className={INPUT} value={template} onChange={e => setTemplate(e.target.value)}>
          {templates.map((t: any) => <option key={t.key} value={t.key}>{t.title}</option>)}
        </select>
        <select className={INPUT} value={cadence} onChange={e => setCadence(e.target.value)}>
          <option value="monthly">Monthly</option>
          <option value="weekly">Weekly</option>
        </select>
        <select className={INPUT} value={tenantId} onChange={e => setTenantId(e.target.value)}>
          <option value="">All customers</option>
          {tenants.map((t: any) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
        <button onClick={create} className={`${BTN} bg-accent text-white hover:bg-accent/80`}>
          <Plus size={14}/> Add schedule
        </button>
      </div>

      {rows.length === 0 ? (
        <p className="text-sm text-muted">No schedules yet.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-muted text-xs uppercase tracking-wider text-left border-b border-line">
              <th className="py-2">Template</th><th>Customer</th><th>Cadence</th><th>Next run</th><th>Status</th><th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id} className="border-b border-line/50">
                <td className="py-2">{templates.find((t: any) => t.key === r.template_key)?.title ?? r.template_key}</td>
                <td>{tenantName(tenants, r.tenant_id)}</td>
                <td className="capitalize">{r.cadence}</td>
                <td className="text-muted">{r.next_run_at ? new Date(r.next_run_at).toLocaleString() : "—"}</td>
                <td>
                  <button onClick={() => toggle(r)}
                          className={`px-2 py-0.5 rounded text-xs ${r.enabled ? "bg-positive/20 text-positive" : "bg-muted/20 text-muted"}`}>
                    {r.enabled ? "enabled" : "paused"}
                  </button>
                </td>
                <td className="text-right">
                  <button onClick={() => remove(r)} className="text-muted hover:text-danger p-1"><Trash2 size={14}/></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

// ── History (preview / download / gated send) ──────────────────────────────
function HistoryPanel({ tenants, onDone }: any) {
  const [rows, setRows] = useState<any[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(() => { api.reports.generated().then(setRows).catch(() => setRows([])); }, []);
  useEffect(() => { load(); }, [load]);

  const preview = async (id: string) => {
    try {
      const url = await api.reports.reportHtmlUrl(id);
      window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (e: any) { onDone(`Preview failed: ${e.message ?? e}`); }
  };
  const downloadPdf = async (r: any) => {
    setBusyId(r.id);
    try {
      const url = await api.reports.reportPdfUrl(r.id);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${r.template_key}-${(r.period_end || "").slice(0,10)}.pdf`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 30_000);
    } catch (e: any) { onDone(`PDF unavailable: ${e.message ?? e}`); }
    finally { setBusyId(null); }
  };
  const send = async (r: any) => {
    if (!window.confirm(`Email this report to ${tenantName(tenants, r.tenant_id)}? This sends to the customer.`)) return;
    setBusyId(r.id);
    try {
      await api.reports.sendReport(r.id);
      onDone("Report sent."); load();
    } catch (e: any) { onDone(`Send failed: ${e.message ?? e}`); }
    finally { setBusyId(null); }
  };

  return (
    <Panel
      title="History"
      right={<button onClick={load} className="text-muted hover:text-foreground"><RefreshCw size={13}/></button>}
    >
      {rows.length === 0 ? (
        <p className="text-sm text-muted">No reports generated yet.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-muted text-xs uppercase tracking-wider text-left border-b border-line">
              <th className="py-2">Report</th><th>Customer</th><th>Status</th><th>Created</th><th className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id} className="border-b border-line/50">
                <td className="py-2">{r.title}</td>
                <td>{tenantName(tenants, r.tenant_id)}</td>
                <td>
                  <span className={`px-2 py-0.5 rounded text-xs ${
                    r.status === "sent" ? "bg-positive/20 text-positive"
                    : r.status === "failed" ? "bg-danger/20 text-danger"
                    : "bg-warning/20 text-warning"}`}>
                    {r.status}
                  </span>
                </td>
                <td className="text-muted">{r.created_at ? new Date(r.created_at).toLocaleString() : "—"}</td>
                <td className="text-right whitespace-nowrap">
                  <button onClick={() => preview(r.id)} disabled={r.status === "failed"}
                          className="text-muted hover:text-foreground p-1 disabled:opacity-30" title="Preview HTML">
                    <FileText size={14}/>
                  </button>
                  <button onClick={() => downloadPdf(r)} disabled={busyId === r.id || r.status === "failed"}
                          className="text-muted hover:text-foreground p-1 disabled:opacity-30" title="Download PDF">
                    <Download size={14}/>
                  </button>
                  <button onClick={() => send(r)}
                          disabled={busyId === r.id || r.status === "sent" || r.status === "failed" || !r.tenant_id}
                          className="text-muted hover:text-accent p-1 disabled:opacity-30" title="Send to customer (gated)">
                    <Send size={14}/>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
