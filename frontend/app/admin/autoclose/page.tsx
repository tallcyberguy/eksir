"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Trash2, Plus } from "lucide-react";

const MATCH_FIELDS = [
  "rule_name", "customer", "src_ip", "dst_ip", "dst_port",
  "application", "src_zone", "dst_zone", "url_category", "dst_asn",
] as const;

type MatchKey = (typeof MATCH_FIELDS)[number];

export default function AutoclosePage() {
  const { data, mutate } = useSWR("admin.autoclose", () => api.admin.listAutoclose());
  const rows = data || [];
  const [form, setForm] = useState({
    rule_id: "", customer: "", verdict: "FP" as "FP"|"benign", reason: "",
    match: {} as Record<string, string>,
  });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string|null>(null);

  async function create() {
    setBusy(true); setErr(null);
    try {
      const cleanMatch: Record<string, any> = {};
      for (const [k, v] of Object.entries(form.match)) {
        if (v && v.trim()) {
          cleanMatch[k] = k === "dst_port" && /^\d+$/.test(v) ? parseInt(v) : v.trim();
        }
      }
      await api.admin.createAutoclose({
        rule_id: form.rule_id,
        customer: form.customer || undefined,
        match: cleanMatch,
        verdict: form.verdict,
        reason: form.reason,
        enabled: true,
      });
      setForm({ rule_id: "", customer: "", verdict: "FP", reason: "", match: {} });
      await mutate();
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  async function toggleEnabled(id: string, enabled: boolean) {
    await api.admin.patchAutoclose(id, { enabled: !enabled });
    await mutate();
  }

  async function remove(id: string, rule_id: string) {
    if (!confirm(`Delete rule "${rule_id}"?`)) return;
    await api.admin.deleteAutoclose(id);
    await mutate();
  }

  return (
    <div className="grid lg:grid-cols-3 gap-5">
      <Panel title={`Auto-close rules (${rows.length})`} className="lg:col-span-2">
        <table className="w-full text-sm">
          <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
            <tr className="text-left">
              <th className="py-2 pr-3">Rule ID</th>
              <th className="py-2 pr-3">Customer</th>
              <th className="py-2 pr-3">Match</th>
              <th className="py-2 pr-3">Verdict</th>
              <th className="py-2 pr-3">Source</th>
              <th className="py-2 pr-3">State</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r: any) => (
              <tr key={r.id} className="border-t border-line/60 align-top">
                <td className="py-2 pr-3 font-mono text-accent">{r.rule_id}</td>
                <td className="py-2 pr-3 text-muted">{r.customer || "any"}</td>
                <td className="py-2 pr-3 max-w-[34ch]">
                  <div className="font-mono text-[11px] text-muted whitespace-pre-wrap">
                    {Object.entries(r.match || {}).map(([k,v]) => `${k}=${v}`).join("\n") || "—"}
                  </div>
                  {r.reason && <div className="text-[11px] text-muted mt-1">{r.reason}</div>}
                </td>
                <td className="py-2 pr-3">
                  <span className={`pill ${r.verdict === "FP" ? "pill-resolved" : "pill-medium"}`}>{r.verdict}</span>
                </td>
                <td className="py-2 pr-3 text-muted text-xs">{r.source}</td>
                <td className="py-2 pr-3">
                  <button onClick={()=>toggleEnabled(r.id, r.enabled)}
                          className={`pill ${r.enabled ? "pill-resolved" : "pill-low"}`}>
                    {r.enabled ? "on" : "off"}
                  </button>
                </td>
                <td className="py-2 pr-3 text-right">
                  <button onClick={() => remove(r.id, r.rule_id)}
                          className="text-muted hover:text-danger" title="Delete">
                    <Trash2 size={14}/>
                  </button>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan={7} className="py-6 text-center text-muted">
                No rules yet. Rules from <code className="font-mono">auto_close_rules.yaml</code> are loaded by the SKILL workflow at boot; UI-created rules are stored in Postgres and merged at evaluation time.
              </td></tr>
            )}
          </tbody>
        </table>
      </Panel>

      <Panel title="New rule" icon={<Plus size={14} className="text-accent"/>}>
        <Field label="Rule ID"  v={form.rule_id}  on={v=>setForm({...form, rule_id: v})}
               hint="kebab-case, unique. e.g. contoso-google-as15169-dmz"/>
        <Field label="Customer" v={form.customer} on={v=>setForm({...form, customer: v})}
               hint="optional — leave empty for any-tenant rule"/>
        <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mt-3 mb-1">Verdict</label>
        <select value={form.verdict}
                onChange={e=>setForm({...form, verdict: e.target.value as "FP"|"benign"})}
                className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm">
          <option value="FP">FP</option>
          <option value="benign">benign</option>
        </select>

        <div className="mt-4 text-[10px] tracking-[0.18em] text-muted uppercase mb-1">Match conditions</div>
        <div className="space-y-1.5">
          {MATCH_FIELDS.map(k => (
            <div key={k} className="flex items-center gap-2">
              <span className="text-[11px] text-muted font-mono w-28 shrink-0">{k}</span>
              <input
                value={form.match[k] || ""}
                onChange={e=>setForm({...form, match: {...form.match, [k]: e.target.value}})}
                placeholder="(any)"
                className="flex-1 bg-base border border-line rounded-md px-2 py-1 text-xs focus:outline-none focus:border-accent/60"/>
            </div>
          ))}
        </div>

        <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mt-4 mb-1">Reason</label>
        <textarea rows={3} value={form.reason} onChange={e=>setForm({...form, reason: e.target.value})}
                  className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60"
                  placeholder="English explanation written for the analyst report."/>

        <button onClick={create} disabled={busy || !form.rule_id || !form.reason}
                className="mt-4 w-full px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
          {busy ? "Saving…" : "Create rule"}
        </button>
        {err && <div className="mt-3 text-sm text-danger">{err}</div>}
      </Panel>
    </div>
  );
}

function Field({ label, v, on, hint }:{label:string;v:string;on:(s:string)=>void;hint?:string}) {
  return (
    <div className="mt-3">
      <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mb-1">{label}</label>
      <input value={v} onChange={e=>on(e.target.value)}
             className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60"/>
      {hint && <div className="text-[10px] text-muted mt-1">{hint}</div>}
    </div>
  );
}
