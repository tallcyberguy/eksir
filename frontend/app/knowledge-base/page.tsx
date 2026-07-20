"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { BookOpen, Trash2, Search, Plus } from "lucide-react";

const KB_TYPES = [
  { v: "runbook", label: "Runbook" },
  { v: "allowlist", label: "Allowlist" },
  { v: "asset_inventory", label: "Asset inventory" },
  { v: "incident_report", label: "Incident report" },
];

const TYPE_PILL: Record<string, string> = {
  runbook: "pill-medium",
  allowlist: "pill-resolved",
  asset_inventory: "pill-high",
  incident_report: "pill-critical",
};

export default function KnowledgeBasePage() {
  const { data: me } = useSWR("me", () => api.me());
  const isAdmin = me?.role === "admin";

  const [typeFilter, setTypeFilter] = useState("");
  const { data, mutate } = useSWR(`kb.list.${typeFilter}`, () =>
    api.knowledgeBase.list(typeFilter ? { type: typeFilter } : {})
  );
  const items = data?.items || [];

  const blank = { type: "runbook", title: "", content: "", customer: "", rule_name: "", tags: "" };
  const [form, setForm] = useState(blank);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Retrieval preview
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<any[] | null>(null);
  const [searching, setSearching] = useState(false);

  async function create() {
    setBusy(true); setErr(null);
    try {
      await api.knowledgeBase.create({
        type: form.type,
        title: form.title,
        content: form.content,
        customer: form.customer || undefined,
        rule_name: form.rule_name || undefined,
        tags: form.tags ? form.tags.split(",").map((t) => t.trim()).filter(Boolean) : undefined,
      });
      setForm(blank);
      await mutate();
    } catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  }

  async function remove(kbId: string, title: string) {
    if (!confirm(`Delete KB entry "${title}"?`)) return;
    await api.knowledgeBase.remove(kbId);
    await mutate();
  }

  async function runSearch() {
    if (q.trim().length < 2) return;
    setSearching(true);
    try { setHits((await api.knowledgeBase.search({ q, top_k: 5 })).items); }
    catch { setHits([]); }
    finally { setSearching(false); }
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <BookOpen size={20} className="text-accent" />
        <h1 className="text-lg font-semibold text-text">Knowledge Base</h1>
        <span className="text-xs text-muted">
          Runbooks, allowlists & asset context the analysis pipeline retrieves at enrichment time.
        </span>
      </div>

      <div className="grid lg:grid-cols-3 gap-5">
        {/* ── Entries list ─────────────────────────────────────────── */}
        <Panel title={`Entries (${items.length})`} className="lg:col-span-2">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-[10px] uppercase tracking-wider text-muted">Filter</span>
            <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}
                    className="bg-base border border-line rounded-md px-2 py-1 text-xs">
              <option value="">all types</option>
              {KB_TYPES.map((t) => <option key={t.v} value={t.v}>{t.label}</option>)}
            </select>
          </div>
          <div className="space-y-2">
            {items.map((e: any) => (
              <div key={e.kb_id} className="border border-line/60 rounded-md p-3">
                <div className="flex items-start gap-2 flex-wrap">
                  <span className={`pill text-[9px] ${TYPE_PILL[e.type] || "pill-medium"}`}>{e.type}</span>
                  <span className="text-sm font-semibold text-text">{e.title}</span>
                  {e.customer && <span className="pill pill-medium text-[9px]">{e.customer}</span>}
                  {e.rule_name && <span className="text-[10px] text-muted font-mono">rule: {e.rule_name}</span>}
                  {isAdmin && (
                    <button onClick={() => remove(e.kb_id, e.title)}
                            className="ml-auto text-muted hover:text-danger" title="Delete">
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>
                <p className="mt-1.5 text-xs text-text/80 leading-relaxed whitespace-pre-wrap line-clamp-4">
                  {e.content}
                </p>
                {Array.isArray(e.tags) && e.tags.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {e.tags.map((t: string, i: number) => (
                      <span key={i} className="pill pill-medium text-[9px]">{t}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {items.length === 0 && (
              <div className="py-8 text-center text-muted text-sm">
                No knowledge-base entries yet.
                {isAdmin ? " Add a runbook on the right →" : " Ask an admin to add runbooks."}
              </div>
            )}
          </div>
        </Panel>

        {/* ── Create + search ──────────────────────────────────────── */}
        <div className="space-y-5">
          {isAdmin && (
            <Panel title="New entry" icon={<Plus size={14} className="text-accent" />}>
              <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mb-1">Type</label>
              <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}
                      className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm">
                {KB_TYPES.map((t) => <option key={t.v} value={t.v}>{t.label}</option>)}
              </select>
              <Field label="Title" v={form.title} on={(v) => setForm({ ...form, title: v })} />
              <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mt-3 mb-1">Content</label>
              <textarea value={form.content} onChange={(e) => setForm({ ...form, content: e.target.value })}
                        rows={6} placeholder="The text the pipeline embeds + retrieves."
                        className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60" />
              <Field label="Customer (blank = global)" v={form.customer} on={(v) => setForm({ ...form, customer: v })} />
              <Field label="Rule name (optional)" v={form.rule_name} on={(v) => setForm({ ...form, rule_name: v })} />
              <Field label="Tags (comma-separated)" v={form.tags} on={(v) => setForm({ ...form, tags: v })} />
              <button onClick={create} disabled={busy || !form.title.trim() || !form.content.trim()}
                      className="mt-4 w-full px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
                {busy ? "Indexing…" : "Add to knowledge base"}
              </button>
              {err && <div className="mt-3 text-sm text-danger">{err}</div>}
            </Panel>
          )}

          <Panel title="Test retrieval" icon={<Search size={14} className="text-accent" />}>
            <div className="text-[11px] text-muted mb-2">
              Preview what the pipeline would surface for a query.
            </div>
            <div className="flex gap-2">
              <input value={q} onChange={(e) => setQ(e.target.value)}
                     onKeyDown={(e) => e.key === "Enter" && runSearch()}
                     placeholder="e.g. brute force lockout runbook"
                     className="flex-1 bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60" />
              <button onClick={runSearch} disabled={searching || q.trim().length < 2}
                      className="px-3 py-1.5 rounded-md bg-surface2 border border-line text-sm hover:border-accent/60 disabled:opacity-40">
                {searching ? "…" : "Search"}
              </button>
            </div>
            {hits !== null && (
              <div className="mt-3 space-y-2">
                {hits.length === 0 && <div className="text-xs text-muted">No matches.</div>}
                {hits.map((h: any, i: number) => (
                  <div key={i} className="border border-line/50 rounded-md p-2 text-xs">
                    <div className="flex items-center gap-2">
                      <span className={`pill text-[9px] ${TYPE_PILL[h.type] || "pill-medium"}`}>{h.type}</span>
                      <span className="font-semibold text-text">{h.title}</span>
                      <span className="ml-auto font-mono text-[10px] text-accent">score {h.score}</span>
                    </div>
                    <p className="mt-1 text-text/70 line-clamp-2">{h.content}</p>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function Field({ label, v, on }: { label: string; v: string; on: (s: string) => void }) {
  return (
    <div className="mt-3">
      <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mb-1">{label}</label>
      <input value={v} onChange={(e) => on(e.target.value)}
             className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60" />
    </div>
  );
}
