"use client";

import { useEffect } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, RefreshCw, Activity, AlertTriangle } from "lucide-react";

type Container = {
  name: string;
  image: string | null;
  state: string | null;   // running | exited | ...
  status: string | null;  // "Up 3 hours (healthy)"
  health: string | null;  // healthy | unhealthy | starting | null
  restarts: number | null;
  cpu_pct: number | null;
  mem_used_mb: number | null;
  mem_limit_mb: number | null;
};
type Overview = { docker_ok: boolean; reason?: string; containers: Container[] };

function Kpi({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded border border-line bg-surface/40 px-4 py-3">
      <div className="text-[11px] tracking-widest uppercase text-muted">{label}</div>
      <div className={`text-xl font-semibold tabular-nums mt-1 ${tone || "text-text"}`}>{value}</div>
    </div>
  );
}

function healthTone(c: Container): string {
  if (c.state !== "running") return "text-danger";
  if (c.health === "unhealthy") return "text-danger";
  if (c.health === "starting") return "text-warning";
  return "text-positive";
}
function healthLabel(c: Container): string {
  if (c.state !== "running") return c.state || "stopped";
  return c.health || "running";
}
function mb(n: number | null): string {
  if (n == null) return "—";
  return n >= 1024 ? `${(n / 1024).toFixed(1)} GB` : `${Math.round(n)} MB`;
}

export default function PerformancePage() {
  const { data, isLoading, mutate } = useSWR<Overview>(
    "admin.performance",
    () => api.performance.overview(),
  );
  // The swr-shim has no refreshInterval option, so poll manually every 5s.
  useEffect(() => {
    const t = setInterval(() => mutate(), 5000);
    return () => clearInterval(t);
  }, [mutate]);

  const containers = data?.containers || [];
  const up = containers.filter((c) => c.state === "running").length;
  const unhealthy = containers.filter((c) => c.state === "running" && c.health === "unhealthy").length;
  const stopped = containers.filter((c) => c.state !== "running").length;

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <Activity size={16} className="text-accent" />
        <h1 className="text-sm font-semibold text-text">Container performance</h1>
        <button onClick={() => mutate()} title="Refresh"
                className="ml-auto text-muted hover:text-accent">
          <RefreshCw size={14} />
        </button>
      </div>

      {isLoading && !data && (
        <div className="flex items-center gap-2 text-sm text-muted"><Loader2 size={14} className="animate-spin" /> Loading…</div>
      )}

      {data && !data.docker_ok && (
        <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 px-4 py-3 text-sm">
          <AlertTriangle size={16} className="text-warning shrink-0 mt-0.5" />
          <div>
            <div className="text-warning font-medium">Container monitoring unavailable</div>
            <div className="text-muted mt-0.5">
              {data.reason || "The docker-socket-proxy is not reachable."} Start the
              <code className="mx-1 bg-base border border-line rounded px-1">docker-socket-proxy</code>
              service (it ships with the compose stack) to see live container stats.
            </div>
          </div>
        </div>
      )}

      {data?.docker_ok && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <Kpi label="Containers up" value={`${up}`} tone="text-positive" />
            <Kpi label="Unhealthy" value={`${unhealthy}`} tone={unhealthy ? "text-danger" : "text-text"} />
            <Kpi label="Stopped" value={`${stopped}`} tone={stopped ? "text-warning" : "text-text"} />
          </div>

          <Panel title="Containers">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
                  <tr className="text-left">
                    <th className="py-2 pr-3">Container</th>
                    <th className="py-2 pr-3">Health</th>
                    <th className="py-2 pr-3">CPU</th>
                    <th className="py-2 pr-3">Memory</th>
                    <th className="py-2 pr-3">Restarts</th>
                    <th className="py-2 pr-3">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {containers.map((c) => {
                    const memPct = c.mem_used_mb != null && c.mem_limit_mb
                      ? Math.min(100, (c.mem_used_mb / c.mem_limit_mb) * 100) : null;
                    return (
                      <tr key={c.name} className="border-t border-line/60">
                        <td className="py-2 pr-3 font-mono">{c.name}</td>
                        <td className="py-2 pr-3">
                          <span className={healthTone(c)}>{healthLabel(c)}</span>
                        </td>
                        <td className="py-2 pr-3 tabular-nums">{c.cpu_pct != null ? `${c.cpu_pct}%` : "—"}</td>
                        <td className="py-2 pr-3">
                          <div className="flex items-center gap-2">
                            <span className="tabular-nums whitespace-nowrap">{mb(c.mem_used_mb)}</span>
                            {memPct != null && (
                              <span className="h-1.5 w-16 rounded-full bg-base overflow-hidden">
                                <span className={`block h-full ${memPct > 85 ? "bg-danger" : "bg-accent"}`}
                                      style={{ width: `${memPct}%` }} />
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-2 pr-3 tabular-nums">
                          <span className={c.restarts ? "text-warning" : "text-muted"}>{c.restarts ?? "—"}</span>
                        </td>
                        <td className="py-2 pr-3 text-muted text-xs max-w-[22ch] truncate" title={c.status || ""}>
                          {c.status || "—"}
                        </td>
                      </tr>
                    );
                  })}
                  {containers.length === 0 && (
                    <tr><td colSpan={6} className="py-6 text-center text-muted">No containers reported.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </Panel>
          <p className="text-[11px] text-muted">
            Live snapshot, refreshed every 5s. Read-only via the docker-socket-proxy; no container control from here.
          </p>
        </>
      )}
    </div>
  );
}
