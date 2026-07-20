"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { Panel } from "@/components/ui/Panel";
import { ExclusionsPanel } from "@/components/threat-iocs/ExclusionsPanel";
import { SuggestionsPanel } from "@/components/threat-iocs/SuggestionsPanel";
import { api } from "@/lib/api";
import {
  Radar, RefreshCcw, Globe, Link2, Server, Search, Hash,
  CheckCircle2, AlertTriangle, Loader2, Plus, Trash2, ToggleLeft, ToggleRight,
  Download, ChevronDown,
} from "lucide-react";

type Stats = { total: number; by_type: Record<string, number>; last_sync: string | null };
type Feed  = {
  id: string; name: string; url: string; kind_hint: string; enabled: boolean;
  format?: string;
  last_sync_at: string | null; last_sync_status: string | null;
  last_sync_error: string | null; last_sync_count: number | null;
  last_sync_new_count: number | null;
};
type Reputation = { score: number; band: string; sources: number; corroboration: number; recency: number };
type Ioc = {
  id: string; value: string; ioc_type: string;
  first_seen_at: string | null; last_seen_at: string | null;
  sources: string[];
  reputation?: Reputation;
};

const BAND_STYLE: Record<string, string> = {
  high: "text-danger border-danger/40 bg-danger/10",
  medium: "text-warning border-warning/40 bg-warning/10",
  low: "text-muted border-line bg-surface/40",
};

function RepBadge({ rep }: { rep?: Reputation }) {
  if (!rep) return <span className="text-muted">—</span>;
  return (
    <span
      title={`corroboration ${rep.sources} feed(s) · recency ${(rep.recency * 100).toFixed(0)}%`}
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-mono ${BAND_STYLE[rep.band] ?? BAND_STYLE.low}`}
    >
      {rep.band.toUpperCase()} · {(rep.score * 100).toFixed(0)}
    </span>
  );
}

type Tab = "iocs" | "feeds" | "exclusions";

// Export analyst-confirmed IOCs (verdict=TP, not excluded) as STIX 2.1 / CSV.
function ExportMenu() {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    if (open) document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  async function download(format: "stix" | "csv") {
    setBusy(format); setErr(null);
    try {
      const blob = await api.threatIntel.exportIocs(format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `eksir-confirmed-iocs-${new Date().toISOString().slice(0, 10)}.${format === "stix" ? "json" : "csv"}`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      setOpen(false);
    } catch (e: any) {
      setErr(e?.message || "Export failed");
    } finally { setBusy(null); }
  }

  return (
    <div ref={ref} className="relative">
      <button onClick={() => setOpen(o => !o)}
              title="Export analyst-confirmed IOCs (verdict = True Positive)"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm
                         bg-surface/60 border border-line text-text hover:border-accent/40">
        <Download size={14}/> Export
        <ChevronDown size={12} className="text-muted"/>
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-2 w-64 bg-surface border border-line rounded-md shadow-cyber z-50 overflow-hidden">
          <div className="px-3 py-2 text-[11px] text-muted border-b border-line/60">
            Confirmed indicators (verdict = TP, not excluded)
          </div>
          <button disabled={!!busy} onClick={() => download("stix")}
                  className="w-full text-left px-3 py-2 text-sm text-text hover:bg-accent/10 disabled:opacity-50 flex items-center justify-between">
            <span>STIX 2.1 bundle</span>
            <span className="text-[10px] text-muted">{busy === "stix" ? "…" : ".json"}</span>
          </button>
          <button disabled={!!busy} onClick={() => download("csv")}
                  className="w-full text-left px-3 py-2 text-sm text-text hover:bg-accent/10 disabled:opacity-50 flex items-center justify-between">
            <span>CSV</span>
            <span className="text-[10px] text-muted">{busy === "csv" ? "…" : ".csv"}</span>
          </button>
          {err && <div className="px-3 py-2 text-xs text-danger border-t border-line/60">{err}</div>}
        </div>
      )}
    </div>
  );
}

export default function ThreatIocsPage() {
  const [tab, setTab] = useState<Tab>("iocs");
  const [stats, setStats] = useState<Stats | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);

  const loadStats = useCallback(async () => {
    try { setStats(await api.threatIntel.stats()); } catch {}
  }, []);

  useEffect(() => { loadStats(); }, [loadStats]);

  async function syncNow() {
    setSyncing(true); setSyncMsg(null);
    try {
      const r = await api.threatIntel.triggerSync();
      setSyncMsg(`Queued — job ${r.job_id?.slice(0,8) || "?"}. New counts appear once the worker finishes (typically under a minute).`);
      // Refresh stats a few times so the UI catches up when the worker finishes.
      [3000, 8000, 20000, 45000].forEach(ms => setTimeout(loadStats, ms));
    } catch (e: any) {
      setSyncMsg(`Sync failed: ${e.message || e}`);
    } finally { setSyncing(false); }
  }

  return (
    <div className="space-y-5">
      <header className="flex items-center gap-3">
        <Radar size={20} className="text-accent"/>
        <h1 className="text-text font-semibold text-lg">Threat Intelligence</h1>
        <div className="ml-auto flex items-center gap-2">
          <ExportMenu/>
          <button onClick={syncNow} disabled={syncing}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm
                             bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20
                             disabled:opacity-40">
            {syncing ? <Loader2 size={14} className="animate-spin"/> : <RefreshCcw size={14}/>}
            {syncing ? "Queuing…" : "Sync now"}
          </button>
        </div>
      </header>

      <StatsBar stats={stats}/>

      {syncMsg && (
        <div className="text-xs text-muted border border-line bg-surface/50 rounded-md px-3 py-2">
          {syncMsg}
        </div>
      )}

      <div className="flex gap-6 border-b border-line text-sm">
        <TabButton active={tab==="iocs"}       onClick={()=>setTab("iocs")}>Indicators</TabButton>
        <TabButton active={tab==="feeds"}      onClick={()=>setTab("feeds")}>Feeds</TabButton>
        <TabButton active={tab==="exclusions"} onClick={()=>setTab("exclusions")}>Exclusions</TabButton>
      </div>

      {tab === "iocs"       && <IocsPanel/>}
      {tab === "feeds"      && <FeedsPanel onAnyChange={loadStats}/>}
      {tab === "exclusions" && (
        <div className="space-y-5">
          <SuggestionsPanel/>
          <ExclusionsPanel/>
        </div>
      )}
    </div>
  );
}

function TabButton({ active, children, onClick }: { active: boolean; children: React.ReactNode; onClick: ()=>void }) {
  return (
    <button onClick={onClick}
            className={`pb-2 -mb-px border-b-2 ${active
              ? "border-accent text-text"
              : "border-transparent text-muted hover:text-text"}`}>
      {children}
    </button>
  );
}

function StatsBar({ stats }: { stats: Stats | null }) {
  const fmt = (n: number) => n.toLocaleString();
  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
      <StatTile icon={Radar}  label="Total IOCs"    value={stats ? fmt(stats.total) : "—"}/>
      <StatTile icon={Server} label="IPs"           value={stats ? fmt(stats.by_type?.ip || 0) : "—"} accent="warning"/>
      <StatTile icon={Globe}  label="Domains"       value={stats ? fmt(stats.by_type?.domain || 0) : "—"} accent="positive"/>
      <StatTile icon={Link2}  label="URLs"          value={stats ? fmt(stats.by_type?.url || 0) : "—"} accent="accent2"/>
      <StatTile icon={Hash}   label="Hashes"        value={stats ? fmt(stats.by_type?.hash || 0) : "—"} accent="danger"/>
      <StatTile icon={CheckCircle2} label="Last sync"
                value={stats?.last_sync ? new Date(stats.last_sync).toLocaleString() : "never"}
                small/>
    </div>
  );
}

function StatTile({ icon: Icon, label, value, accent, small }: {
  icon: any; label: string; value: string; accent?: string; small?: boolean;
}) {
  const color = accent === "warning"  ? "text-warning"
              : accent === "positive" ? "text-positive"
              : accent === "accent2"  ? "text-accent2"
              :                          "text-accent";
  return (
    <div className="panel p-4">
      <div className={`flex items-center gap-2 ${color} mb-2`}>
        <Icon size={14}/>
        <span className="text-[10px] uppercase tracking-[0.16em] text-muted">{label}</span>
      </div>
      <div className={`font-mono font-semibold ${small ? "text-sm" : "text-2xl"} text-text`}>
        {value}
      </div>
    </div>
  );
}

// ── Indicators ───────────────────────────────────────────────────────────
function IocsPanel() {
  const [q, setQ]               = useState("");
  const [type, setType]         = useState("");
  const [data, setData]         = useState<{ total: number; items: Ioc[] } | null>(null);
  const [loading, setLoading]   = useState(false);
  const [offset, setOffset]     = useState(0);
  const limit = 100;

  // Debounce + refetch on input change.
  useEffect(() => {
    const t = setTimeout(async () => {
      setLoading(true);
      try { setData(await api.threatIntel.listIocs({ q, ioc_type: type, limit, offset })); }
      finally { setLoading(false); }
    }, 300);
    return () => clearTimeout(t);
  }, [q, type, offset]);

  return (
    <Panel title="Indicators">
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted"/>
          <input value={q} onChange={e=>{ setQ(e.target.value); setOffset(0); }}
                 placeholder="Search by value (substring)…"
                 className="w-full bg-base border border-line rounded-md pl-9 pr-3 py-2 text-sm
                            focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40"/>
        </div>
        <select value={type} onChange={e=>{ setType(e.target.value); setOffset(0); }}
                className="bg-base border border-line rounded-md px-3 py-2 text-sm
                           focus:border-accent focus:outline-none">
          <option value="">All types</option>
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="hash">Hash</option>
        </select>
        {loading && <Loader2 size={14} className="animate-spin text-muted"/>}
      </div>

      <div className="overflow-x-auto -mx-2">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[10px] uppercase tracking-[0.16em] text-muted">
              <th className="text-left font-medium py-2 px-2 w-20">Type</th>
              <th className="text-left font-medium py-2 px-2">Value</th>
              <th className="text-left font-medium py-2 px-2 w-28">Score</th>
              <th className="text-left font-medium py-2 px-2">First seen</th>
              <th className="text-left font-medium py-2 px-2">Last seen</th>
              <th className="text-left font-medium py-2 px-2">Feeds</th>
            </tr>
          </thead>
          <tbody>
            {(data?.items || []).map(i => (
              <tr key={i.id} className="border-t border-line/60 hover:bg-surface2/30">
                <td className="py-2 px-2">
                  <span className="text-[10px] uppercase tracking-wider text-accent font-mono">{i.ioc_type}</span>
                </td>
                <td className="py-2 px-2 font-mono break-all text-text">{i.value}</td>
                <td className="py-2 px-2"><RepBadge rep={i.reputation} /></td>
                <td className="py-2 px-2 text-xs text-muted">
                  {i.first_seen_at ? new Date(i.first_seen_at).toLocaleDateString() : "—"}
                </td>
                <td className="py-2 px-2 text-xs text-muted">
                  {i.last_seen_at ? new Date(i.last_seen_at).toLocaleDateString() : "—"}
                </td>
                <td className="py-2 px-2 text-[10px] text-muted font-mono">
                  {(i.sources || []).length} feed{(i.sources||[]).length === 1 ? "" : "s"}
                </td>
              </tr>
            ))}
            {data && data.items.length === 0 && (
              <tr><td colSpan={6} className="py-8 text-center text-muted">
                {q || type ? "No indicators match the filters." : "No indicators yet — hit Sync now."}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      {data && data.total > limit && (
        <div className="flex items-center justify-between mt-4 text-xs text-muted">
          <span>
            {offset + 1}–{Math.min(offset + limit, data.total)} of {data.total.toLocaleString()}
          </span>
          <div className="flex gap-2">
            <button onClick={()=>setOffset(Math.max(0, offset - limit))}
                    disabled={offset === 0}
                    className="px-3 py-1 border border-line rounded-md hover:border-accent disabled:opacity-30">
              Previous
            </button>
            <button onClick={()=>setOffset(offset + limit)}
                    disabled={offset + limit >= data.total}
                    className="px-3 py-1 border border-line rounded-md hover:border-accent disabled:opacity-30">
              Next
            </button>
          </div>
        </div>
      )}
    </Panel>
  );
}

// ── Feeds ────────────────────────────────────────────────────────────────
function FeedsPanel({ onAnyChange }: { onAnyChange: () => void }) {
  const [feeds, setFeeds]   = useState<Feed[] | null>(null);
  const [err, setErr]       = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);

  const reload = useCallback(async () => {
    try { setFeeds(await api.threatIntel.listFeeds()); setErr(null); }
    catch (e: any) { setErr(e.message || "Failed to load feeds"); }
  }, []);

  useEffect(() => { reload(); }, [reload]);

  async function toggleEnabled(f: Feed) {
    try { await api.threatIntel.patchFeed(f.id, { enabled: !f.enabled }); reload(); onAnyChange(); }
    catch (e: any) { setErr(e.message); }
  }
  async function remove(f: Feed) {
    if (!confirm(`Delete feed "${f.name}"? This removes the feed but keeps the IOCs it contributed.`)) return;
    try { await api.threatIntel.deleteFeed(f.id); reload(); }
    catch (e: any) { setErr(e.message); }
  }

  return (
    <Panel title="Feeds">
      <div className="flex items-center gap-3 mb-4">
        <p className="text-xs text-muted">
          One row per upstream feed. Disable to skip during the daily sync. The IOCs a disabled feed
          previously contributed remain in the DB.
        </p>
        <button onClick={()=>setShowAdd(v=>!v)}
                className="ml-auto inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md
                           border border-line hover:border-accent text-text">
          <Plus size={14}/> Add feed
        </button>
      </div>

      {err && (
        <div className="text-sm text-danger border border-danger/40 bg-danger/10 rounded-md px-3 py-2 mb-3">
          <AlertTriangle size={12} className="inline mr-1.5"/>{err}
        </div>
      )}

      {showAdd && <AddFeedForm onDone={()=>{ setShowAdd(false); reload(); }}/>}

      <div className="overflow-x-auto -mx-2">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[10px] uppercase tracking-[0.16em] text-muted">
              <th className="text-left font-medium py-2 px-2">Name</th>
              <th className="text-left font-medium py-2 px-2">Type</th>
              <th className="text-left font-medium py-2 px-2">Status</th>
              <th className="text-left font-medium py-2 px-2">Last sync</th>
              <th className="text-left font-medium py-2 px-2">IOCs (last run)</th>
              <th className="text-left font-medium py-2 px-2 w-20">Enabled</th>
              <th className="text-left font-medium py-2 px-2 w-10"></th>
            </tr>
          </thead>
          <tbody>
            {(feeds || []).map(f => (
              <tr key={f.id} className="border-t border-line/60 align-top">
                <td className="py-2 px-2">
                  <div className="text-text flex items-center gap-2">
                    {f.name}
                    {f.format === "taxii" && (
                      <span className="text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded border border-accent/40 text-accent bg-accent/10">
                        TAXII
                      </span>
                    )}
                  </div>
                  <div className="font-mono text-[10px] text-muted truncate max-w-md" title={f.url}>
                    {f.url}
                  </div>
                </td>
                <td className="py-2 px-2">
                  <span className="text-[10px] uppercase tracking-wider text-accent font-mono">
                    {f.kind_hint}
                  </span>
                </td>
                <td className="py-2 px-2">
                  {f.last_sync_status === "ok" && (
                    <span className="text-positive text-xs">ok</span>
                  )}
                  {f.last_sync_status === "error" && (
                    <span className="text-danger text-xs" title={f.last_sync_error || ""}>error</span>
                  )}
                  {!f.last_sync_status && (
                    <span className="text-muted text-xs italic">never</span>
                  )}
                </td>
                <td className="py-2 px-2 text-xs text-muted">
                  {f.last_sync_at ? new Date(f.last_sync_at).toLocaleString() : "—"}
                </td>
                <td className="py-2 px-2 font-mono text-xs">
                  {f.last_sync_count?.toLocaleString() || "—"}
                  {typeof f.last_sync_new_count === "number" && (
                    <span className="text-positive ml-2">+{f.last_sync_new_count}</span>
                  )}
                </td>
                <td className="py-2 px-2">
                  <button onClick={()=>toggleEnabled(f)} title={f.enabled ? "Disable" : "Enable"}>
                    {f.enabled
                      ? <ToggleRight size={20} className="text-positive hover:opacity-80"/>
                      : <ToggleLeft size={20} className="text-muted hover:text-text"/>}
                  </button>
                </td>
                <td className="py-2 px-2">
                  <button onClick={()=>remove(f)} className="text-muted hover:text-danger" title="Delete feed">
                    <Trash2 size={14}/>
                  </button>
                </td>
              </tr>
            ))}
            {feeds && feeds.length === 0 && (
              <tr><td colSpan={7} className="py-8 text-center text-muted">No feeds configured.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function AddFeedForm({ onDone }: { onDone: () => void }) {
  const [feedType, setFeedType] = useState<"http" | "taxii">("http");
  const [name, setName] = useState("");
  const [url, setUrl]   = useState("");
  const [kind, setKind] = useState("auto");
  const [authType, setAuthType] = useState<"none" | "token" | "basic">("none");
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr]   = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      if (feedType === "taxii") {
        const auth =
          authType === "token" ? { type: "token", token: token.trim() } :
          authType === "basic" ? { type: "basic", username: username.trim(), password } :
          { type: "none" };
        await api.threatIntel.createFeed({
          name: name.trim(), url: url.trim(), kind_hint: "auto",
          parser_config: { format: "taxii", version: "2.1", auth },
        });
      } else {
        await api.threatIntel.createFeed({ name: name.trim(), url: url.trim(), kind_hint: kind });
      }
      onDone();
    } catch (e: any) {
      setErr(e.message || "Could not create feed");
    } finally { setBusy(false); }
  }

  const inp = "mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:border-accent focus:outline-none";
  const lbl = "text-[10px] uppercase tracking-wider text-muted";

  return (
    <form onSubmit={submit} className="space-y-3 mb-4 p-3 rounded-md border border-line/60 bg-base/50">
      <div className="grid sm:grid-cols-[150px_1fr] gap-2">
        <div>
          <label className={lbl}>Feed type</label>
          <select value={feedType} onChange={e=>setFeedType(e.target.value as any)} className={inp}>
            <option value="http">HTTP (list / CSV)</option>
            <option value="taxii">TAXII 2.1</option>
          </select>
        </div>
        <div>
          <label className={lbl}>Name</label>
          <input value={name} onChange={e=>setName(e.target.value)} required placeholder="My feed" className={inp}/>
        </div>
      </div>

      <div>
        <label className={lbl}>{feedType === "taxii" ? "Collection URL" : "URL"}</label>
        <input value={url} onChange={e=>setUrl(e.target.value)} required
               placeholder={feedType === "taxii" ? "https://server/taxii2/…/collections/<id>/" : "https://…"}
               className={inp + " font-mono"}/>
      </div>

      {feedType === "http" ? (
        <div className="sm:w-40">
          <label className={lbl}>Type hint</label>
          <select value={kind} onChange={e=>setKind(e.target.value)} className={inp}>
            <option value="auto">Auto</option>
            <option value="ip">IP</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="hash">Hash</option>
          </select>
        </div>
      ) : (
        <div className="grid sm:grid-cols-[150px_1fr] gap-2 items-start">
          <div>
            <label className={lbl}>Auth</label>
            <select value={authType} onChange={e=>setAuthType(e.target.value as any)} className={inp}>
              <option value="none">None</option>
              <option value="token">Bearer token</option>
              <option value="basic">Basic</option>
            </select>
          </div>
          {authType === "token" && (
            <div>
              <label className={lbl}>Token</label>
              <input value={token} onChange={e=>setToken(e.target.value)} type="password"
                     placeholder="API token" className={inp + " font-mono"}/>
            </div>
          )}
          {authType === "basic" && (
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className={lbl}>Username</label>
                <input value={username} onChange={e=>setUsername(e.target.value)} className={inp}/>
              </div>
              <div>
                <label className={lbl}>Password</label>
                <input value={password} onChange={e=>setPassword(e.target.value)} type="password" className={inp}/>
              </div>
            </div>
          )}
        </div>
      )}

      <div className="flex items-center gap-3">
        <button type="submit" disabled={busy}
                className="px-4 py-1.5 rounded-md text-sm bg-accent/10 border border-accent/40 text-accent
                           hover:bg-accent/20 disabled:opacity-40">
          {busy ? "Saving…" : "Add feed"}
        </button>
        {err && <div className="text-xs text-danger">{err}</div>}
      </div>
    </form>
  );
}
