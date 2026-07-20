"use client";

import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Search, X, ChevronLeft, ChevronRight, Loader2, ChevronDown, ChevronUp, RefreshCw } from "lucide-react";

interface AuditEntry {
  id: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  tenant_id: string | null;
  tenant_name: string | null;
  diff: any;
  ts: string | null;
  actor_email: string | null;
  user_id: string | null;
}

// ── Colour for the action prefix (auth.*, incident.*, pipeline.*, …) ────
function actionColor(action: string): string {
  const prefix = action.split(".")[0];
  switch (prefix) {
    case "auth":      return "text-accent";
    case "user":      return "text-positive";
    case "webhook":   return "text-positive";
    case "autoclose": return "text-positive";
    case "incident":  return "text-warning";
    case "v1":        return "text-danger";
    case "pipeline":  return "text-danger";
    default:          return "text-muted";
  }
}

// ── Detail row inside an expanded entry ───────────────────────────────────
function DetailRow({ k, v }: { k: string; v: any }) {
  if (v === null || v === undefined || v === "") return null;
  return (
    <div className="grid grid-cols-[120px_1fr] gap-2 text-xs">
      <span className="text-muted uppercase tracking-wider text-[10px]">{k}</span>
      <span className="text-text font-mono break-all">{typeof v === "string" ? v : JSON.stringify(v)}</span>
    </div>
  );
}

// ── Single row ────────────────────────────────────────────────────────────
function AuditRow({ entry }: { entry: AuditEntry }) {
  const [open, setOpen] = useState(false);
  const ts = entry.ts ? new Date(entry.ts) : null;
  return (
    <div className="border-b border-line/40">
      <button
        onClick={() => setOpen(!open)}
        className="w-full grid grid-cols-[150px_180px_180px_140px_1fr_24px] gap-3 items-center px-3 py-2 hover:bg-surface/40 transition-colors text-left"
      >
        <span className="text-[11px] text-muted font-mono whitespace-nowrap">
          {ts ? ts.toLocaleString() : "—"}
        </span>
        <span className={`text-xs font-mono ${actionColor(entry.action)} truncate`}>{entry.action}</span>
        <span className="text-xs text-muted truncate">{entry.actor_email || <em className="text-muted/60">system</em>}</span>
        <span className="text-xs truncate">
          {entry.tenant_name
            ? <span className="text-text">{entry.tenant_name}</span>
            : <em className="text-muted/50">platform</em>}
        </span>
        <span className="text-xs text-text truncate">
          {entry.target_type && (
            <>
              <span className="text-muted">{entry.target_type}</span>
              {entry.target_id && <span className="font-mono text-[10px] text-muted/60"> · {entry.target_id.slice(0, 8)}</span>}
            </>
          )}
        </span>
        {open ? <ChevronUp size={14} className="text-muted"/> : <ChevronDown size={14} className="text-muted"/>}
      </button>

      {open && (
        <div className="bg-base px-3 pb-3 pt-2 border-t border-line/40 space-y-1">
          <DetailRow k="ID"          v={entry.id}/>
          <DetailRow k="Target ID"   v={entry.target_id}/>
          <DetailRow k="Tenant"      v={entry.tenant_name ? `${entry.tenant_name} (${entry.tenant_id})` : null}/>
          <DetailRow k="User ID"     v={entry.user_id}/>
          {entry.diff && (
            <div className="grid grid-cols-[120px_1fr] gap-2 text-xs">
              <span className="text-muted uppercase tracking-wider text-[10px]">Diff</span>
              <pre className="text-text font-mono text-[11px] bg-surface/60 border border-line rounded-md p-2 overflow-x-auto whitespace-pre-wrap">
                {JSON.stringify(entry.diff, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────
export default function AuditPage() {
  const [items,   setItems]   = useState<AuditEntry[]>([]);
  const [total,   setTotal]   = useState(0);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState<string | null>(null);
  const [facets,  setFacets]  = useState<{ actions: any[]; target_types: any[] }>({ actions: [], target_types: [] });
  const [tenants, setTenants] = useState<{ id: string; name: string }[]>([]);

  // filters
  const [q,       setQ]       = useState("");
  const [action,  setAction]  = useState("");
  const [actor,   setActor]   = useState("");
  const [target,  setTarget]  = useState("");
  const [tenant,  setTenant]  = useState("");
  const [since,   setSince]   = useState("");
  const [until,   setUntil]   = useState("");
  const [page,    setPage]    = useState(1);
  const pageSize = 50;

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await api.audit.list({
        q: q || undefined,
        action: action || undefined,
        actor: actor || undefined,
        target_type: target || undefined,
        tenant_id: tenant || undefined,
        since: since ? new Date(since).toISOString() : undefined,
        until: until ? new Date(until).toISOString() : undefined,
        page,
        page_size: pageSize,
      });
      setItems(r.items); setTotal(r.total);
    } catch (e: any) {
      setError(e.message);
    } finally { setLoading(false); }
  }, [q, action, actor, target, tenant, since, until, page]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    api.audit.facets().then(setFacets).catch(() => {});
    // Use /auth/scope (already exists) — it returns the tenants the viewer
    // can see, so the dropdown options match what the audit query will return.
    api.scope().then(s => setTenants(s.tenants.map(t => ({ id: t.id, name: t.name }))))
              .catch(() => {});
  }, []);

  function clearFilters() {
    setQ(""); setAction(""); setActor(""); setTarget(""); setTenant("");
    setSince(""); setUntil(""); setPage(1);
  }

  const hasFilters = q || action || actor || target || tenant || since || until;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-5">
      {/* Filters */}
      <Panel title="Audit Log">
        <div className="grid grid-cols-1 md:grid-cols-6 gap-2 mb-3">
          <div className="md:col-span-2 relative">
            <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted"/>
            <input
              value={q}
              onChange={e => { setQ(e.target.value); setPage(1); }}
              placeholder="Search action, email, diff JSON…"
              className="w-full bg-base border border-line rounded-md pl-8 pr-2 py-1.5 text-sm focus:outline-none focus:border-accent"
            />
          </div>
          <select
            value={action}
            onChange={e => { setAction(e.target.value); setPage(1); }}
            className="bg-base border border-line rounded-md px-2 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
          >
            <option value="">All actions</option>
            {facets.actions.map(a => (
              <option key={a.value} value={a.value}>{a.value} ({a.count})</option>
            ))}
          </select>
          <select
            value={target}
            onChange={e => { setTarget(e.target.value); setPage(1); }}
            className="bg-base border border-line rounded-md px-2 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
          >
            <option value="">All targets</option>
            {facets.target_types.map(t => (
              <option key={t.value} value={t.value}>{t.value} ({t.count})</option>
            ))}
          </select>
          <select
            value={tenant}
            onChange={e => { setTenant(e.target.value); setPage(1); }}
            className="bg-base border border-line rounded-md px-2 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
          >
            <option value="">All tenants</option>
            {tenants.map(t => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
          <input
            value={actor}
            onChange={e => { setActor(e.target.value); setPage(1); }}
            placeholder="Actor email"
            className="bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent"
          />
          <input
            type="datetime-local"
            value={since}
            onChange={e => { setSince(e.target.value); setPage(1); }}
            placeholder="Since"
            className="bg-base border border-line rounded-md px-2 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
          />
          <input
            type="datetime-local"
            value={until}
            onChange={e => { setUntil(e.target.value); setPage(1); }}
            placeholder="Until"
            className="bg-base border border-line rounded-md px-2 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
          />
        </div>

        <div className="flex items-center gap-3 mb-3">
          <span className="text-xs text-muted">
            {loading ? "Loading…" : `${total.toLocaleString()} ${total === 1 ? "entry" : "entries"}`}
            {hasFilters && total > 0 && <span className="ml-1 text-accent">(filtered)</span>}
          </span>
          {hasFilters && (
            <button
              onClick={clearFilters}
              className="flex items-center gap-1 text-xs text-muted hover:text-danger"
            >
              <X size={12}/> Clear filters
            </button>
          )}
          <button
            onClick={load}
            className="ml-auto flex items-center gap-1 text-xs text-muted hover:text-accent"
            title="Refresh"
          >
            {loading ? <Loader2 size={12} className="animate-spin"/> : <RefreshCw size={12}/>}
            Refresh
          </button>
        </div>

        {error && (
          <div className="text-sm text-danger border border-danger/40 bg-danger/10 rounded-md p-2 mb-3">{error}</div>
        )}

        {/* Header */}
        <div className="grid grid-cols-[150px_180px_180px_140px_1fr_24px] gap-3 px-3 py-1.5 text-[10px] uppercase tracking-wider text-muted border-b border-line/60">
          <span>Timestamp</span>
          <span>Action</span>
          <span>Actor</span>
          <span>Tenant</span>
          <span>Target</span>
          <span></span>
        </div>

        {/* Rows */}
        <div className="text-sm">
          {items.length === 0 && !loading && (
            <p className="text-muted text-center py-8 text-sm">No audit entries match the filters.</p>
          )}
          {items.map(entry => <AuditRow key={entry.id} entry={entry}/>)}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-3 mt-4 text-xs">
            <button
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
              className="flex items-center gap-1 px-2 py-1 border border-line rounded-md hover:border-accent disabled:opacity-30"
            >
              <ChevronLeft size={12}/> Prev
            </button>
            <span className="text-muted">Page {page} of {totalPages}</span>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage(page + 1)}
              className="flex items-center gap-1 px-2 py-1 border border-line rounded-md hover:border-accent disabled:opacity-30"
            >
              Next <ChevronRight size={12}/>
            </button>
          </div>
        )}
      </Panel>
    </div>
  );
}
