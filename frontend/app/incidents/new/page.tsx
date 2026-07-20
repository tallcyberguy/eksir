"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Panel } from "@/components/ui/Panel";
import { api } from "@/lib/api";

export default function NewInvestigation() {
  const router = useRouter();
  const [raw, setRaw] = useState("");
  const [customer, setCustomer] = useState("");
  const [customers, setCustomers] = useState<{ name: string; count: number }[]>([]);
  const [hint, setHint] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState<string|null>(null);

  useEffect(() => {
    api.listCustomers().then(setCustomers).catch(() => {});
  }, []);

  async function submit() {
    const cleaned = raw.trim();
    if (cleaned.length < 20) {
      setErr("Alert text looks empty or too short — paste the full alert payload.");
      return;
    }
    setBusy(true); setErr(null);
    try {
      const r = await api.pasteAlert(cleaned, customer || undefined, hint || undefined);
      router.push(`/incidents/${r.incident_id}`);
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  return (
    <div className="grid lg:grid-cols-3 gap-5">
      <Panel title="Paste raw alert" className="lg:col-span-2">
        <textarea
          value={raw}
          onChange={e => setRaw(e.target.value)}
          rows={22}
          className="w-full bg-base border border-line rounded-md p-3 font-mono text-sm
                     focus:outline-none focus:border-accent/60 focus:shadow-cyber"
          placeholder="Paste a QRadar / Wazuh / FortiGate / SentinelOne / Syslog alert here…"/>
      </Panel>

      <Panel title="Options">
        <label className="block mb-3 text-xs uppercase tracking-wider text-muted">
          Customer (optional)
          <input
            list="customers-list"
            value={customer}
            onChange={e => setCustomer(e.target.value)}
            placeholder={customers.length ? "Pick existing or type new…" : "Type customer name…"}
            className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60"
          />
          <datalist id="customers-list">
            {customers.map(c => (
              <option key={c.name} value={c.name} />
            ))}
          </datalist>
        </label>
        <label className="block mb-5 text-xs uppercase tracking-wider text-muted">
          Source hint (optional)
          <select value={hint} onChange={e=>setHint(e.target.value)}
                  className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60">
            <option value="">auto-detect</option>
            <option value="qradar">QRadar</option>
            <option value="wazuh">Wazuh</option>
            <option value="fortigate">FortiGate</option>
            <option value="sentinelone">SentinelOne</option>
            <option value="syslog">Syslog</option>
          </select>
        </label>
        <button onClick={submit} disabled={busy || raw.trim().length < 20}
                className="w-full px-3 py-2 rounded-md bg-accent/10 border border-accent/40
                           text-accent hover:bg-accent/20 disabled:opacity-40">
          {busy ? "Running pipeline…" : "Start investigation"}
        </button>
        {err && <div className="mt-3 text-sm text-danger">{err}</div>}

        <div className="mt-6 text-xs text-muted leading-relaxed">
          Pipeline runs in the background:<br/>
          parse → auto-close → vector match → enrichment → decision gate → LLM (only if needed).
        </div>
      </Panel>
    </div>
  );
}
