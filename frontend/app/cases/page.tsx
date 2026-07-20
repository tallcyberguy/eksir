"use client";

import { useState } from "react";
import Link from "next/link";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Search, X, FileText, Send, CheckCircle2, Edit3 } from "lucide-react";

const STATUSES = ["draft", "reviewed", "sent"] as const;

function statusPill(s: string) {
  if (s === "sent")     return "pill pill-resolved";
  if (s === "reviewed") return "pill pill-medium";
  return "pill pill-low";
}

function statusIcon(s: string) {
  if (s === "sent")     return <Send size={11}/>;
  if (s === "reviewed") return <CheckCircle2 size={11}/>;
  return <Edit3 size={11}/>;
}

export default function CasesPage() {
  const [q,       setQ]      = useState("");
  const [status,  setStatus] = useState("");
  const [customer, setCustomer] = useState("");

  const params: Record<string, string | number> = { page_size: 100 };
  if (q)        params.q        = q;
  if (status)   params.status   = status;
  if (customer) params.customer = customer;

  const swrKey = "cases:" + JSON.stringify(params);
  const { data, isLoading } = useSWR(swrKey, () => api.cases.list(params));
  const rows: any[] = data || [];

  const hasFilters = q || status || customer;

  return (
    <div className="space-y-4">
      <div className="panel p-3">
        <div className="flex flex-wrap gap-2 items-center">
          <div className="relative flex-1 min-w-[200px]">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted"/>
            <input
              className="w-full bg-base border border-line rounded-md pl-8 pr-3 py-1.5 text-sm text-text
                         placeholder:text-muted focus:outline-none focus:border-accent"
              placeholder="Search title or case number…"
              value={q}
              onChange={e => setQ(e.target.value)}
            />
          </div>

          <input
            className="bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text
                       placeholder:text-muted focus:outline-none focus:border-accent w-44"
            placeholder="Customer…"
            value={customer}
            onChange={e => setCustomer(e.target.value)}
          />

          <select
            value={status}
            onChange={e => setStatus(e.target.value)}
            className={`bg-base border border-line rounded-md px-2.5 py-1.5 text-sm focus:outline-none focus:border-accent
                        ${status ? "text-text border-accent/50" : "text-muted"}`}
          >
            <option value="">Status</option>
            {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>

          {hasFilters && (
            <button
              onClick={() => { setQ(""); setStatus(""); setCustomer(""); }}
              className="flex items-center gap-1 px-2.5 py-1.5 text-sm text-muted hover:text-danger border border-line/60 rounded-md"
            >
              <X size={13}/> Clear
            </button>
          )}
        </div>
      </div>

      <Panel
        title={isLoading ? "Customer cases — loading…" : `Customer cases — ${rows.length}${rows.length === 100 ? "+" : ""} results`}
        icon={<FileText size={14} className="text-accent"/>}
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
              <tr className="text-left">
                <th className="py-2 pr-4">Case</th>
                <th className="py-2 pr-4">Title</th>
                <th className="py-2 pr-4">Customer</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">Locale</th>
                <th className="py-2 pr-4">Source incident</th>
                <th className="py-2 pr-4 whitespace-nowrap">Updated</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r: any) => (
                <tr key={r.id} className="border-t border-line/60 hover:bg-surface/60">
                  <td className="py-2 pr-4 font-mono text-accent">
                    <Link href={`/cases/${r.id}`}>{r.case_number}</Link>
                  </td>
                  <td className="py-2 pr-4 max-w-[34ch] truncate" title={r.title}>
                    {r.title || <span className="text-muted italic">untitled</span>}
                  </td>
                  <td className="py-2 pr-4 text-muted">{r.tenant_name || "—"}</td>
                  <td className="py-2 pr-4">
                    <span className={`${statusPill(r.status)} inline-flex items-center gap-1`}>
                      {statusIcon(r.status)}{r.status}
                    </span>
                  </td>
                  <td className="py-2 pr-4 text-muted font-mono text-xs uppercase">{r.locale}</td>
                  <td className="py-2 pr-4">
                    <Link href={`/incidents/${r.source_incident_id}`}
                          className="font-mono text-xs text-muted hover:text-accent">
                      {r.source_case_number || "—"}
                    </Link>
                  </td>
                  <td className="py-2 pr-4 text-muted text-xs whitespace-nowrap">
                    {new Date(r.updated_at).toLocaleString()}
                  </td>
                </tr>
              ))}
              {!isLoading && rows.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-muted">
                    {hasFilters
                      ? "No cases match the current filters."
                      : "No customer cases yet — open an incident and click 'Create case'."}
                  </td>
                </tr>
              )}
              {isLoading && (
                <tr><td colSpan={7} className="py-10 text-center text-muted">Loading…</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
