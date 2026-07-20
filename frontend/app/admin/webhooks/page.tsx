"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Trash2, Plus, Copy, Check } from "lucide-react";

export default function WebhooksPage() {
  const { data, mutate } = useSWR("admin.webhooks", () => api.admin.listWebhooks());
  const rows = data || [];
  const [form, setForm] = useState({ name: "", customer_default: "", source_product: "qradar", ip_allowlist: "" });
  const [secret, setSecret] = useState<{ id: string; name: string; secret: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function create() {
    setBusy(true); setErr(null);
    try {
      const ips = form.ip_allowlist.split(",").map(s => s.trim()).filter(Boolean);
      const r = await api.admin.createWebhook({
        name: form.name,
        customer_default: form.customer_default || undefined,
        source_product: form.source_product || undefined,
        ip_allowlist: ips.length ? ips : undefined,
      });
      setSecret({ id: r.id, name: r.name, secret: r.hmac_secret_shown_once });
      setForm({ name: "", customer_default: "", source_product: "qradar", ip_allowlist: "" });
      await mutate();
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  async function toggleEnabled(id: string, enabled: boolean) {
    await api.admin.patchWebhook(id, { enabled: !enabled });
    await mutate();
  }

  async function remove(id: string, name: string) {
    if (!confirm(`Delete webhook source "${name}"? Any SIEM using this secret will start failing.`)) return;
    await api.admin.deleteWebhook(id);
    await mutate();
  }

  return (
    <div className="grid lg:grid-cols-3 gap-5">
      <Panel title={`Webhook sources (${rows.length})`} className="lg:col-span-2">
        <table className="w-full text-sm">
          <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
            <tr className="text-left">
              <th className="py-2 pr-3">Name</th>
              <th className="py-2 pr-3">Customer</th>
              <th className="py-2 pr-3">Source</th>
              <th className="py-2 pr-3">Endpoint</th>
              <th className="py-2 pr-3">State</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r: any) => (
              <tr key={r.id} className="border-t border-line/60">
                <td className="py-2 pr-3 font-mono text-accent">{r.name}</td>
                <td className="py-2 pr-3 text-muted">{r.customer_default || "—"}</td>
                <td className="py-2 pr-3 text-muted">{r.source_product || "—"}</td>
                <td className="py-2 pr-3 font-mono text-xs text-muted truncate max-w-[28ch]">
                  /v1/ingest/{r.id.slice(0,8)}…
                </td>
                <td className="py-2 pr-3">
                  <button onClick={()=>toggleEnabled(r.id, r.enabled)}
                          className={`pill ${r.enabled ? "pill-resolved" : "pill-low"}`}>
                    {r.enabled ? "enabled" : "disabled"}
                  </button>
                </td>
                <td className="py-2 pr-3 text-right">
                  <button onClick={() => remove(r.id, r.name)}
                          className="text-muted hover:text-danger" title="Delete">
                    <Trash2 size={14}/>
                  </button>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan={6} className="py-6 text-center text-muted">No webhook sources yet.</td></tr>
            )}
          </tbody>
        </table>
      </Panel>

      <div className="space-y-5">
        <Panel title="New webhook source" icon={<Plus size={14} className="text-accent"/>}>
          <Field label="Name"             v={form.name}             on={v=>setForm({...form, name: v})} hint="e.g. QRadar CONTOSO"/>
          <Field label="Customer default" v={form.customer_default} on={v=>setForm({...form, customer_default: v})}/>
          <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mt-3 mb-1">Source product</label>
          <select value={form.source_product} onChange={e=>setForm({...form, source_product: e.target.value})}
                  className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm">
            <option value="qradar">QRadar</option>
            <option value="wazuh">Wazuh</option>
            <option value="fortigate">FortiGate</option>
            <option value="sentinelone">SentinelOne</option>
            <option value="syslog">Syslog</option>
          </select>
          <Field label="IP allowlist" v={form.ip_allowlist} on={v=>setForm({...form, ip_allowlist: v})}
                 hint="comma-separated CIDRs or IPs (optional)"/>
          <button onClick={create} disabled={busy || !form.name}
                  className="mt-4 w-full px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
            {busy ? "Creating…" : "Create"}
          </button>
          {err && <div className="mt-3 text-sm text-danger">{err}</div>}
        </Panel>

        {secret && <SecretReveal sec={secret} onDismiss={()=>setSecret(null)}/>}
      </div>
    </div>
  );
}

function SecretReveal({ sec, onDismiss }:{sec:{id:string;name:string;secret:string};onDismiss:()=>void}) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(sec.secret).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }
  return (
    <Panel title="HMAC secret — shown ONCE" className="border-warning/40">
      <div className="text-xs text-warning uppercase tracking-wider mb-2">
        Copy this now. It cannot be retrieved later.
      </div>
      <div className="bg-base border border-warning/40 rounded-md p-3 font-mono text-xs break-all">
        {sec.secret}
      </div>
      <div className="mt-3 flex items-center gap-2">
        <button onClick={copy} className="inline-flex items-center gap-1.5 text-xs text-accent hover:underline">
          {copied ? <><Check size={12}/> copied</> : <><Copy size={12}/> copy</>}
        </button>
        <button onClick={onDismiss} className="ml-auto text-xs text-muted hover:text-text">I have it, dismiss</button>
      </div>
      <div className="mt-4 text-[11px] text-muted leading-relaxed">
        Source ID: <code className="font-mono">{sec.id}</code><br/>
        Sender computes: <code className="font-mono">hmac_sha256(secret, f"{`{ts}.${'{body}'}`}")</code><br/>
        Send headers: <code className="font-mono">X-EKSIR-Timestamp</code> + <code className="font-mono">X-EKSIR-Signature</code>
      </div>
    </Panel>
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
