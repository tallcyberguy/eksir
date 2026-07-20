"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, RefreshCw } from "lucide-react";

type TenantRow = {
  tenant_id: string;
  name: string | null;
  slug: string | null;
  tier: string | null;
  tier_label: string | null;
  open: number;
  open_urgent: number;
  awaiting_signoff: number;
  total: number;
  closed: number;
};
type Overview = {
  window_days: number;
  tenant_count: number;
  total_open: number;
  total_awaiting_signoff: number;
  total_urgent: number;
  tenants: TenantRow[];
};

const WINDOWS = [7, 14, 30, 90];

function Kpi({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="rounded border border-line bg-surface/40 px-4 py-3">
      <div className="text-[11px] tracking-widest uppercase text-muted">{label}</div>
      <div className={`text-xl font-semibold tabular-nums mt-1 ${accent ?? "text-text"}`}>{value}</div>
    </div>
  );
}

export default function MSSPPage() {
  const [windowDays, setWindowDays] = useState(30);
  const { data, isLoading, mutate } = useSWR<Overview>(`mssp.${windowDays}`, () => api.mssp.overview(windowDays));

  return (
    <div className="max-w-4xl space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex gap-1">
          {WINDOWS.map((w) => (
            <button
              key={w}
              onClick={() => setWindowDays(w)}
              className={`px-3 py-1 rounded text-sm ${
                windowDays === w ? "bg-accent/20 text-text" : "text-muted hover:text-text"
              }`}
            >
              {w}d
            </button>
          ))}
        </div>
        <button onClick={() => mutate()} className="text-muted hover:text-text flex items-center gap-1.5 text-sm" title="Refresh">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {isLoading || !data ? (
        <div className="flex items-center gap-2 text-muted text-sm py-8">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Kpi label="Tenants" value={String(data.tenant_count)} />
            <Kpi label="Open cases" value={String(data.total_open)} />
            <Kpi
              label="At the gate"
              value={String(data.total_awaiting_signoff)}
              accent={data.total_awaiting_signoff ? "text-yellow-400" : "text-text"}
            />
            <Kpi
              label="Urgent open"
              value={String(data.total_urgent)}
              accent={data.total_urgent ? "text-danger" : "text-text"}
            />
          </div>

          <Panel title="Tenants">
            {data.tenants.length === 0 ? (
              <div className="text-sm text-muted py-2">No tenants in scope.</div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[11px] tracking-widest uppercase text-muted text-left">
                    <th className="font-normal py-1.5">Tenant</th>
                    <th className="font-normal py-1.5 text-right">Open</th>
                    <th className="font-normal py-1.5 text-right">Urgent</th>
                    <th className="font-normal py-1.5 text-right">At gate</th>
                    <th className="font-normal py-1.5 text-right">Total</th>
                    <th className="font-normal py-1.5 text-right">Closed</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {data.tenants.map((t) => (
                    <tr key={t.tenant_id} className="text-text">
                      <td className="py-1.5">
                        {t.name ?? t.slug ?? t.tenant_id.slice(0, 8)}
                        {t.tier_label && (
                          <span className="ml-2 text-[10px] text-accent border border-accent/40 rounded px-1">
                            {t.tier_label}
                          </span>
                        )}
                      </td>
                      <td className="py-1.5 text-right tabular-nums">{t.open || ""}</td>
                      <td className="py-1.5 text-right tabular-nums text-danger">{t.open_urgent || ""}</td>
                      <td className="py-1.5 text-right tabular-nums text-yellow-400">{t.awaiting_signoff || ""}</td>
                      <td className="py-1.5 text-right tabular-nums text-muted">{t.total}</td>
                      <td className="py-1.5 text-right tabular-nums text-muted">{t.closed}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <p className="text-[11px] text-muted mt-2">
              Open / urgent / at-the-gate are live; total / closed are within the selected window.
            </p>
          </Panel>
        </>
      )}
    </div>
  );
}
