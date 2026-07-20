"use client";

import { useState } from "react";
import Link from "next/link";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Trash2, Plus, Users, FileText, ChevronRight, Building2 } from "lucide-react";

const TIERS = [
  { v: "host",   label: "Host",   hint: "Platform operator — sees everything" },
  { v: "mssp",   label: "MSSP",   hint: "Managed provider — sees own + child tenants" },
  { v: "client", label: "Client", hint: "End customer — sees own data only" },
];

function tierClass(t: string) {
  return t === "host"   ? "pill-resolved"
       : t === "mssp"   ? "pill-medium"
       :                  "pill-low";
}

export default function TenantsPage() {
  const { data, mutate } = useSWR("admin.tenants", () => api.admin.listTenants());
  const rows = data || [];

  const [form, setForm] = useState({ name: "", tier: "client", parent_id: "", tier_label: "" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function create() {
    setBusy(true); setErr(null);
    try {
      await api.admin.createTenant({
        name: form.name.trim(),
        tier: form.tier,
        parent_id: form.parent_id || null,
        tier_label: form.tier_label || undefined,
      });
      setForm({ name: "", tier: "client", parent_id: "", tier_label: "" });
      await mutate();
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  async function remove(id: string, name: string, count: number) {
    const note = count ? `\n\nWARNING: ${count} incidents are linked to this tenant. They will become unassigned (visible only to admins).` : "";
    if (!confirm(`Delete tenant "${name}"?${note}`)) return;
    try {
      await api.admin.deleteTenant(id);
      await mutate();
    } catch (e: any) { alert(e.message); }
  }

  // Pre-sort: HOST > MSSP > CLIENT, then alpha
  const tierOrder: Record<string, number> = { host: 0, mssp: 1, client: 2 };
  const sorted = [...rows].sort((a, b) =>
    (tierOrder[a.tier] - tierOrder[b.tier]) || a.name.localeCompare(b.name)
  );

  return (
    <div className="grid lg:grid-cols-3 gap-5">
      {/* List */}
      <Panel title={`Tenants (${rows.length})`} icon={<Building2 size={14} className="text-accent"/>} className="lg:col-span-2">
        {rows.length === 0 && (
          <p className="text-xs text-muted italic">No tenants yet. Create one on the right.</p>
        )}
        <table className="w-full text-sm">
          <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
            <tr className="text-left">
              <th className="py-2 pr-3">Name</th>
              <th className="py-2 pr-3">Tier</th>
              <th className="py-2 pr-3">Parent</th>
              <th className="py-2 pr-3 text-right">Cases</th>
              <th className="py-2 pr-3 text-right">Members</th>
              <th className="py-2 pr-3 text-right">Children</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((r: any) => (
              <tr key={r.id} className="border-t border-line/60 hover:bg-surface/40">
                <td className="py-2 pr-3">
                  <Link href={`/admin/tenants/${r.id}`} className="font-mono text-accent hover:underline flex items-center gap-1">
                    {r.name} <ChevronRight size={12} className="opacity-60"/>
                  </Link>
                  <div className="text-[10px] font-mono text-muted">{r.slug}</div>
                </td>
                <td className="py-2 pr-3">
                  <span className={`pill ${tierClass(r.tier)}`}>{r.tier}</span>
                  {r.tier_label && <span className="ml-1 text-[10px] text-muted">{r.tier_label}</span>}
                </td>
                <td className="py-2 pr-3 text-muted">{r.parent_name || "—"}</td>
                <td className="py-2 pr-3 text-right font-mono text-text">{r.incident_count}</td>
                <td className="py-2 pr-3 text-right font-mono text-text">{r.member_count}</td>
                <td className="py-2 pr-3 text-right font-mono text-muted">{r.child_count}</td>
                <td className="py-2 pr-3 text-right">
                  <button onClick={() => remove(r.id, r.name, r.incident_count)}
                          className="text-muted hover:text-danger" title="Delete">
                    <Trash2 size={14}/>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      {/* Create */}
      <Panel title="Create tenant" icon={<Plus size={14} className="text-accent"/>}>
        <label className="block mb-3 text-xs uppercase tracking-wider text-muted">
          Name
          <input value={form.name} onChange={e => setForm({...form, name: e.target.value})}
                 placeholder="Acme Corp"
                 className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent"/>
        </label>

        <label className="block mb-3 text-xs uppercase tracking-wider text-muted">
          Tier
          <select value={form.tier} onChange={e => setForm({...form, tier: e.target.value})}
                  className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent">
            {TIERS.map(t => <option key={t.v} value={t.v}>{t.label} — {t.hint}</option>)}
          </select>
        </label>

        <label className="block mb-3 text-xs uppercase tracking-wider text-muted">
          Parent tenant (optional)
          <select value={form.parent_id} onChange={e => setForm({...form, parent_id: e.target.value})}
                  className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent">
            <option value="">none (top-level)</option>
            {rows.filter((r: any) => r.tier !== "client").map((r: any) => (
              <option key={r.id} value={r.id}>{r.name} ({r.tier})</option>
            ))}
          </select>
        </label>

        <label className="block mb-4 text-xs uppercase tracking-wider text-muted">
          Tier label (optional)
          <input value={form.tier_label} onChange={e => setForm({...form, tier_label: e.target.value})}
                 placeholder="e.g. Platinum / Gold"
                 className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent"/>
        </label>

        <button onClick={create} disabled={busy || !form.name.trim()}
                className="w-full px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
          {busy ? "Creating…" : "Create tenant"}
        </button>
        {err && <p className="mt-3 text-sm text-danger">{err}</p>}

        <div className="mt-5 text-[11px] text-muted leading-relaxed border-t border-line/60 pt-3">
          New tenants are auto-created when an incident arrives with a new <code>customer</code>.
          Use this form to set up MSSP/HOST tenants up-front, or to organise the hierarchy.
        </div>
      </Panel>
    </div>
  );
}
