"use client";

import { useCallback, useEffect, useState } from "react";
import { Panel } from "@/components/ui/Panel";
import { api } from "@/lib/api";
import {
  AlertTriangle, Plus, Search, Loader2, Trash2, ToggleLeft, ToggleRight,
} from "lucide-react";

type Exclusion = {
  id: string;
  value: string;
  ioc_type: string;
  notes: string | null;
  enabled: boolean;
  created_at: string | null;
  updated_at: string | null;
};

const TYPES = [
  { value: "ip",     label: "IP (exact)" },
  { value: "cidr",   label: "CIDR (range)" },
  { value: "domain", label: "Domain (+ subdomains)" },
  { value: "hash",   label: "Hash (md5/sha1/sha256/sha512)" },
];

export function ExclusionsPanel() {
  const [q, setQ]       = useState("");
  const [type, setType] = useState("");
  const [data, setData] = useState<{ total: number; items: Exclusion[] } | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr]   = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [offset, setOffset]   = useState(0);
  const limit = 100;

  const reload = useCallback(async () => {
    setLoading(true); setErr(null);
    try {
      setData(await api.exclusions.list({ q, ioc_type: type, limit, offset }));
    } catch (e: any) {
      setErr(e.message || "Failed to load exclusions");
    } finally { setLoading(false); }
  }, [q, type, offset]);

  // Debounce search; immediate on type/page change.
  useEffect(() => {
    const t = setTimeout(reload, 300);
    return () => clearTimeout(t);
  }, [reload]);

  async function toggleEnabled(r: Exclusion) {
    try { await api.exclusions.patch(r.id, { enabled: !r.enabled }); reload(); }
    catch (e: any) { setErr(e.message); }
  }
  async function remove(r: Exclusion) {
    if (!confirm(`Delete exclusion "${r.value}"?`)) return;
    try { await api.exclusions.remove(r.id); reload(); }
    catch (e: any) { setErr(e.message); }
  }

  return (
    <Panel title="Exclusions">
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="relative flex-1 min-w-[220px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted"/>
          <input value={q} onChange={e=>{ setQ(e.target.value); setOffset(0); }}
                 placeholder="Search value or notes…"
                 className="w-full bg-base border border-line rounded-md pl-9 pr-3 py-2 text-sm
                            focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40"/>
        </div>
        <select value={type} onChange={e=>{ setType(e.target.value); setOffset(0); }}
                className="bg-base border border-line rounded-md px-3 py-2 text-sm
                           focus:border-accent focus:outline-none">
          <option value="">All types</option>
          {TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
        {loading && <Loader2 size={14} className="animate-spin text-muted"/>}
        <button onClick={()=>setShowAdd(v=>!v)}
                className="ml-auto inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md
                           border border-line hover:border-accent text-text">
          <Plus size={14}/> Add exclusion
        </button>
      </div>

      <p className="text-xs text-muted mb-3 leading-relaxed">
        Exclusions suppress an IOC from triage and threat-intel matching. The LLM is still told
        what was excluded (and why) so it can question the judgement. Use this for DMZ ranges,
        public DNS resolvers, signed binary hashes, vendor reference URLs, etc.
      </p>

      {err && (
        <div className="text-sm text-danger border border-danger/40 bg-danger/10 rounded-md px-3 py-2 mb-3">
          <AlertTriangle size={12} className="inline mr-1.5"/>{err}
        </div>
      )}

      {showAdd && <AddForm onDone={() => { setShowAdd(false); reload(); }}/>}

      <div className="overflow-x-auto -mx-2">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[10px] uppercase tracking-[0.16em] text-muted">
              <th className="text-left font-medium py-2 px-2 w-24">Type</th>
              <th className="text-left font-medium py-2 px-2">Value</th>
              <th className="text-left font-medium py-2 px-2">Notes</th>
              <th className="text-left font-medium py-2 px-2 w-32">Created</th>
              <th className="text-left font-medium py-2 px-2 w-20">Enabled</th>
              <th className="text-left font-medium py-2 px-2 w-10"></th>
            </tr>
          </thead>
          <tbody>
            {(data?.items || []).map(r => (
              <tr key={r.id} className="border-t border-line/60 align-top hover:bg-surface2/30">
                <td className="py-2 px-2">
                  <span className="text-[10px] uppercase tracking-wider text-accent font-mono">
                    {r.ioc_type}
                  </span>
                </td>
                <td className="py-2 px-2 font-mono text-text break-all">{r.value}</td>
                <td className="py-2 px-2 text-xs text-muted">
                  {r.notes || <em className="text-muted/50">—</em>}
                </td>
                <td className="py-2 px-2 text-xs text-muted">
                  {r.created_at ? new Date(r.created_at).toLocaleDateString() : "—"}
                </td>
                <td className="py-2 px-2">
                  <button onClick={()=>toggleEnabled(r)} title={r.enabled ? "Disable" : "Enable"}>
                    {r.enabled
                      ? <ToggleRight size={20} className="text-positive hover:opacity-80"/>
                      : <ToggleLeft size={20} className="text-muted hover:text-text"/>}
                  </button>
                </td>
                <td className="py-2 px-2">
                  <button onClick={()=>remove(r)} className="text-muted hover:text-danger"
                          title="Delete">
                    <Trash2 size={14}/>
                  </button>
                </td>
              </tr>
            ))}
            {data && data.items.length === 0 && (
              <tr><td colSpan={6} className="py-8 text-center text-muted">
                {q || type ? "No exclusions match the filters."
                           : "No exclusions yet — add one to start filtering noisy IOCs."}
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

function AddForm({ onDone }: { onDone: () => void }) {
  const [type, setType]   = useState("ip");
  const [value, setValue] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy]   = useState(false);
  const [err, setErr]     = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      await api.exclusions.create({
        value: value.trim(),
        ioc_type: type,
        notes: notes.trim() || undefined,
      });
      onDone();
    } catch (e: any) {
      setErr(e.message || "Could not create exclusion");
    } finally { setBusy(false); }
  }

  const placeholder = type === "ip"     ? "8.8.8.8"
                    : type === "cidr"   ? "10.0.0.0/8"
                    : type === "domain" ? "internal.example.com"
                    : type === "hash"   ? "e3b0c44298fc1c149afbf4c8996fb92427ae41e4…"
                    : "";

  return (
    <form onSubmit={submit}
          className="grid sm:grid-cols-[140px_1.5fr_2fr_auto] gap-2 items-end mb-4 p-3 rounded-md
                     border border-line/60 bg-base/50">
      <div>
        <label className="text-[10px] uppercase tracking-wider text-muted">Type</label>
        <select value={type} onChange={e=>setType(e.target.value)}
                className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm
                           focus:border-accent focus:outline-none">
          {TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
      </div>
      <div>
        <label className="text-[10px] uppercase tracking-wider text-muted">Value</label>
        <input value={value} onChange={e=>setValue(e.target.value)} required
               placeholder={placeholder}
               className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm font-mono
                          focus:border-accent focus:outline-none"/>
      </div>
      <div>
        <label className="text-[10px] uppercase tracking-wider text-muted">Notes (optional)</label>
        <input value={notes} onChange={e=>setNotes(e.target.value)}
               placeholder="Why this is excluded — e.g. 'Acme DMZ', 'Google DNS'"
               className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm
                          focus:border-accent focus:outline-none"/>
      </div>
      <button type="submit" disabled={busy}
              className="px-4 py-1.5 rounded-md text-sm bg-accent/10 border border-accent/40 text-accent
                         hover:bg-accent/20 disabled:opacity-40">
        {busy ? "Saving…" : "Add"}
      </button>
      {err && <div className="sm:col-span-4 text-xs text-danger">{err}</div>}
    </form>
  );
}
