"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import useSWR from "@/lib/swr-shim";
import { api, type EntitySummary } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { riskPill } from "@/lib/utils";
import {
  Search, X, ChevronLeft, ChevronRight,
  Monitor, User, Globe, FileDigit, Fingerprint,
} from "lucide-react";

const TYPES = ["device", "user", "network_endpoint", "file", "observable"];
const PAGE_SIZES = [25, 50, 100];

const KIND_ICON: Record<string, any> = {
  device: Monitor, user: User, network_endpoint: Globe, file: FileDigit, observable: Fingerprint,
};
const KIND_LABEL: Record<string, string> = {
  device: "Host", user: "User", network_endpoint: "IP", file: "File", observable: "Observable",
};

export default function EntitiesPage() {
  const [q, setQ] = useState("");
  const [entityType, setEntityType] = useState("");
  const [customer, setCustomer] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  const params = useMemo(() => {
    const p: Record<string, string | number> = { page, page_size: pageSize };
    if (q) p.q = q;
    if (entityType) p.entity_type = entityType;
    if (customer) p.customer = customer;
    return p;
  }, [q, entityType, customer, page, pageSize]);

  const swrKey = "entities:" + JSON.stringify(params);
  const { data, isLoading } = useSWR(swrKey, () => api.listEntities(params));
  const rows: EntitySummary[] = data?.items || [];
  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  // Any filter change resets to page 1.
  const onFilter = (fn: () => void) => { fn(); setPage(1); };
  const active = !!(q || entityType || customer);
  const reset = () => { setQ(""); setEntityType(""); setCustomer(""); setPage(1); };

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="panel p-3">
        <div className="flex flex-wrap gap-2 items-center">
          <div className="relative flex-1 min-w-[200px]">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted pointer-events-none"/>
            <input
              className="w-full bg-base border border-line rounded-md pl-8 pr-3 py-1.5 text-sm text-text
                         placeholder:text-muted focus:outline-none focus:border-accent"
              placeholder="Search host / user / IP / hash…"
              value={q}
              onChange={e => onFilter(() => setQ(e.target.value))}
            />
          </div>
          <input
            className="bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text
                       placeholder:text-muted focus:outline-none focus:border-accent w-36"
            placeholder="Customer…"
            value={customer}
            onChange={e => onFilter(() => setCustomer(e.target.value))}
          />
          <select
            value={entityType}
            onChange={e => onFilter(() => setEntityType(e.target.value))}
            className={`bg-base border border-line rounded-md px-2.5 py-1.5 text-sm focus:outline-none focus:border-accent
                        ${entityType ? "text-text border-accent/50" : "text-muted"}`}
          >
            <option value="">All types</option>
            {TYPES.map(t => <option key={t} value={t}>{KIND_LABEL[t] ?? t}</option>)}
          </select>
          {active && (
            <button
              onClick={reset}
              className="flex items-center gap-1 px-2.5 py-1.5 text-sm text-muted hover:text-danger border border-line/60 rounded-md"
            >
              <X size={13}/> Clear
            </button>
          )}
        </div>
      </div>

      {/* Results table */}
      <Panel title={isLoading ? "Entities — loading…" : `Entities — ${total} total`}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
              <tr className="text-left">
                <th className="py-2 pr-4">Entity</th>
                <th className="py-2 pr-4">Type</th>
                <th className="py-2 pr-4">Customer</th>
                <th className="py-2 pr-4">Incidents</th>
                <th className="py-2 pr-4">Risk</th>
                <th className="py-2 pr-4 whitespace-nowrap">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(e => {
                const Icon = KIND_ICON[e.entity_type] ?? Fingerprint;
                return (
                  <tr key={e.id} className="border-t border-line/60 hover:bg-surface/60">
                    <td className="py-2 pr-4">
                      <Link
                        href={`/entities/${e.id}`}
                        className="inline-flex items-center gap-2 text-accent hover:underline min-w-0 max-w-[46ch]"
                      >
                        <Icon size={13} className="text-muted shrink-0"/>
                        <span className="font-mono truncate" title={e.display_name}>{e.display_name}</span>
                      </Link>
                    </td>
                    <td className="py-2 pr-4 text-muted">{KIND_LABEL[e.entity_type] ?? e.entity_type}</td>
                    <td className="py-2 pr-4 text-muted">{e.customer ?? "global"}</td>
                    <td className="py-2 pr-4">{e.incident_count}</td>
                    <td className="py-2 pr-4">
                      {e.risk_score != null ? (
                        <span
                          className={riskPill(e.risk_score)}
                          title="Confirmed-TP history, decayed (30-day half-life)"
                        >
                          {Math.round(e.risk_score)}
                        </span>
                      ) : (
                        <span className="text-muted text-xs">—</span>
                      )}
                    </td>
                    <td className="py-2 pr-4 text-muted text-xs whitespace-nowrap">
                      {new Date(e.last_seen).toLocaleString()}
                    </td>
                  </tr>
                );
              })}
              {!isLoading && rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-muted">
                    {active
                      ? "No entities match the current filters."
                      : "No entities yet — ingest alerts or run scripts/backfill_entities_from_db.py."}
                  </td>
                </tr>
              )}
              {isLoading && (
                <tr><td colSpan={6} className="py-10 text-center text-muted">Loading…</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination footer */}
        {total > 0 && (
          <div className="flex items-center justify-between gap-3 pt-3 mt-3 border-t border-line/60 text-xs">
            <div className="text-muted">
              Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
            </div>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 text-muted">
                Page size
                <select
                  value={pageSize}
                  onChange={e => { setPageSize(Number(e.target.value)); setPage(1); }}
                  className="bg-base border border-line rounded-md px-2 py-1 text-text"
                >
                  {PAGE_SIZES.map(n => <option key={n} value={n}>{n}</option>)}
                </select>
              </label>
              <Pager page={page} pageCount={pageCount} onChange={setPage}/>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}

function Pager({ page, pageCount, onChange }: {
  page: number; pageCount: number; onChange: (p: number) => void;
}) {
  if (pageCount <= 1) return null;
  return (
    <div className="flex items-center gap-1">
      <button
        onClick={() => onChange(Math.max(1, page - 1))}
        disabled={page <= 1}
        className="p-1 rounded border border-line disabled:opacity-40 hover:border-accent"
      >
        <ChevronLeft size={13}/>
      </button>
      <span className="px-2 text-muted">{page} / {pageCount}</span>
      <button
        onClick={() => onChange(Math.min(pageCount, page + 1))}
        disabled={page >= pageCount}
        className="p-1 rounded border border-line disabled:opacity-40 hover:border-accent"
      >
        <ChevronRight size={13}/>
      </button>
    </div>
  );
}
