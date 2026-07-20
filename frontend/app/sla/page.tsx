"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, RefreshCw, Check } from "lucide-react";

type Sev = {
  severity: string;
  target_minutes: number | null;
  closed: number;
  on_time: number;
  breached: number;
  avg_resolution_minutes: number | null;
  breach_rate: number;
};
type Overdue = { case_number: string | null; severity: string; age_minutes: number; target_minutes: number };
type Breach = {
  case_number: string | null;
  severity: string;
  resolution_minutes: number;
  target_minutes: number;
  closed_at: string;
};
type RespSev = {
  severity: string;
  target_minutes: number | null;
  responded: number;
  on_time: number;
  breached: number;
  avg_response_minutes: number | null;
  breach_rate: number;
};
type Awaiting = { case_number: string | null; severity: string; age_minutes: number; target_minutes: number };
type RespBreach = {
  case_number: string | null;
  severity: string;
  response_minutes: number;
  target_minutes: number;
};
type ResponseDash = {
  total_responded: number;
  on_time: number;
  breached: number;
  breach_rate: number;
  on_time_rate: number;
  avg_response_minutes: number | null;
  by_severity: RespSev[];
  awaiting_overdue: Awaiting[];
  recent_breaches: RespBreach[];
};
type SlaDash = {
  window_days: number;
  total_closed: number;
  on_time: number;
  breached: number;
  breach_rate: number;
  on_time_rate: number;
  avg_resolution_minutes: number | null;
  by_severity: Sev[];
  open_overdue: Overdue[];
  recent_breaches: Breach[];
  response?: ResponseDash; // absent when talking to a pre-response-SLA backend
};

const WINDOWS = [7, 14, 30, 90];
const SEV_COLOR: Record<string, string> = {
  critical: "text-danger",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-muted",
};

function dur(m: number | null): string {
  if (m == null) return "—";
  if (m >= 1440) return `${(m / 1440).toFixed(m % 1440 ? 1 : 0)}d`;
  if (m >= 60) return `${(m / 60).toFixed(m % 60 ? 1 : 0)}h`;
  return `${m}m`;
}
function pct(r: number): string {
  return `${(r * 100).toFixed(1)}%`;
}

function Kpi({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded border border-line bg-surface/40 px-4 py-3">
      <div className="text-[11px] tracking-widest uppercase text-muted">{label}</div>
      <div className="text-xl font-semibold text-text tabular-nums mt-1">{value}</div>
      {sub && <div className="text-[11px] text-muted mt-0.5">{sub}</div>}
    </div>
  );
}

function TargetCell({
  sev, current, dkey, drafts, setDrafts, saving, onSave, isAdmin,
}: {
  sev: string; current: number | null; dkey: string;
  drafts: Record<string, number>; setDrafts: (f: (d: Record<string, number>) => Record<string, number>) => void;
  saving: string | null; onSave: (dkey: string, sev: string) => void; isAdmin: boolean;
}) {
  if (!isAdmin) return <>{dur(current)}</>;
  return (
    <span className="inline-flex items-center gap-1 justify-end">
      <input
        type="number"
        defaultValue={current ?? ""}
        onChange={(e) => setDrafts((d) => ({ ...d, [dkey]: parseInt(e.target.value) || 0 }))}
        className="w-20 bg-base border border-line rounded px-2 py-0.5 text-right text-sm focus:outline-none focus:border-accent/60"
      />
      <span className="text-[10px] text-muted">min</span>
      {drafts[dkey] != null && drafts[dkey] !== current && (
        <button onClick={() => onSave(dkey, sev)} className="text-positive hover:opacity-80" title="Save target">
          {saving === dkey ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
        </button>
      )}
    </span>
  );
}

export default function SLAPage() {
  const [windowDays, setWindowDays] = useState(30);
  const { data, isLoading, mutate } = useSWR<SlaDash>(`sla.${windowDays}`, () => api.sla.dashboard(windowDays));
  const { data: me } = useSWR<any>("me", () => api.me());
  const isAdmin = me?.role === "admin";

  // drafts keyed "resp:<sev>" / "res:<sev>" so the two target editors don't collide.
  const [drafts, setDrafts] = useState<Record<string, number>>({});
  const [saving, setSaving] = useState<string | null>(null);

  async function saveTarget(dkey: string, sev: string) {
    const v = drafts[dkey];
    if (!v || v < 1) return;
    setSaving(dkey);
    try {
      const body = dkey.startsWith("resp:")
        ? { severity: sev, response_target_minutes: v }
        : { severity: sev, target_minutes: v };
      await api.sla.saveTarget(body);
      setDrafts((d) => {
        const n = { ...d };
        delete n[dkey];
        return n;
      });
      await mutate();
    } finally {
      setSaving(null);
    }
  }

  const resp = data?.response;

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
          <p className="text-[11px] text-muted">
            24/7 wall-clock SLA. <b>Response</b> = time to first analyst response (claim);
            <b> resolution</b> = time to close. Targets are per severity, admin-editable.
          </p>

          {/* Response SLA — the headline for a 24/7 MSSP */}
          {resp && (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <Kpi label="Response on-time" value={pct(resp.on_time_rate)} sub={`${resp.on_time}/${resp.total_responded}`} />
                <Kpi label="Response breached" value={String(resp.breached)} sub={pct(resp.breach_rate)} />
                <Kpi label="Avg response" value={dur(resp.avg_response_minutes)} />
                <Kpi label="Awaiting > target" value={String(resp.awaiting_overdue.length)} />
              </div>

              <Panel title="Response SLA — time to first response">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-[11px] tracking-widest uppercase text-muted text-left">
                      <th className="font-normal py-1.5">Severity</th>
                      <th className="font-normal py-1.5 text-right">Target</th>
                      <th className="font-normal py-1.5 text-right">Responded</th>
                      <th className="font-normal py-1.5 text-right">On-time</th>
                      <th className="font-normal py-1.5 text-right">Breached</th>
                      <th className="font-normal py-1.5 text-right">Avg</th>
                      <th className="font-normal py-1.5 text-right">Breach %</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {resp.by_severity.map((s) => (
                      <tr key={s.severity} className="text-text">
                        <td className={`py-1.5 font-medium capitalize ${SEV_COLOR[s.severity] ?? ""}`}>{s.severity}</td>
                        <td className="py-1.5 text-right tabular-nums">
                          <TargetCell
                            sev={s.severity} current={s.target_minutes} dkey={`resp:${s.severity}`}
                            drafts={drafts} setDrafts={setDrafts} saving={saving} onSave={saveTarget} isAdmin={isAdmin}
                          />
                        </td>
                        <td className="py-1.5 text-right tabular-nums">{s.responded}</td>
                        <td className="py-1.5 text-right tabular-nums text-positive">{s.on_time}</td>
                        <td className="py-1.5 text-right tabular-nums text-danger">{s.breached || ""}</td>
                        <td className="py-1.5 text-right tabular-nums text-muted">{dur(s.avg_response_minutes)}</td>
                        <td className="py-1.5 text-right tabular-nums">{pct(s.breach_rate)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Panel>

              {resp.awaiting_overdue.length > 0 && (
                <Panel title="Awaiting response — past target now">
                  <table className="w-full text-sm">
                    <tbody className="divide-y divide-line">
                      {resp.awaiting_overdue.map((o, i) => (
                        <tr key={o.case_number ?? i} className="text-text">
                          <td className="py-1.5 font-mono">{o.case_number ?? "—"}</td>
                          <td className={`py-1.5 capitalize ${SEV_COLOR[o.severity] ?? ""}`}>{o.severity}</td>
                          <td className="py-1.5 text-right tabular-nums text-danger">{dur(o.age_minutes)} unclaimed</td>
                          <td className="py-1.5 text-right tabular-nums text-muted">target {dur(o.target_minutes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Panel>
              )}
            </>
          )}

          {/* Resolution SLA */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Kpi label="Resolution on-time" value={pct(data.on_time_rate)} sub={`${data.on_time}/${data.total_closed} closed`} />
            <Kpi label="Resolution breached" value={String(data.breached)} sub={pct(data.breach_rate)} />
            <Kpi label="Avg resolution" value={dur(data.avg_resolution_minutes)} />
            <Kpi label="Open & overdue" value={String(data.open_overdue.length)} />
          </div>

          <Panel title="Resolution SLA — time to close">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[11px] tracking-widest uppercase text-muted text-left">
                  <th className="font-normal py-1.5">Severity</th>
                  <th className="font-normal py-1.5 text-right">Target</th>
                  <th className="font-normal py-1.5 text-right">Closed</th>
                  <th className="font-normal py-1.5 text-right">On-time</th>
                  <th className="font-normal py-1.5 text-right">Breached</th>
                  <th className="font-normal py-1.5 text-right">Avg</th>
                  <th className="font-normal py-1.5 text-right">Breach %</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.by_severity.map((s) => (
                  <tr key={s.severity} className="text-text">
                    <td className={`py-1.5 font-medium capitalize ${SEV_COLOR[s.severity] ?? ""}`}>{s.severity}</td>
                    <td className="py-1.5 text-right tabular-nums">
                      <TargetCell
                        sev={s.severity} current={s.target_minutes} dkey={`res:${s.severity}`}
                        drafts={drafts} setDrafts={setDrafts} saving={saving} onSave={saveTarget} isAdmin={isAdmin}
                      />
                    </td>
                    <td className="py-1.5 text-right tabular-nums">{s.closed}</td>
                    <td className="py-1.5 text-right tabular-nums text-positive">{s.on_time}</td>
                    <td className="py-1.5 text-right tabular-nums text-danger">{s.breached || ""}</td>
                    <td className="py-1.5 text-right tabular-nums text-muted">{dur(s.avg_resolution_minutes)}</td>
                    <td className="py-1.5 text-right tabular-nums">{pct(s.breach_rate)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {isAdmin && (
              <p className="text-[11px] text-muted mt-2">Edit a target and click ✓ to save (admin).</p>
            )}
          </Panel>

          {data.open_overdue.length > 0 && (
            <Panel title="Open & overdue (resolution)">
              <table className="w-full text-sm">
                <tbody className="divide-y divide-line">
                  {data.open_overdue.map((o, i) => (
                    <tr key={o.case_number ?? i} className="text-text">
                      <td className="py-1.5 font-mono">{o.case_number ?? "—"}</td>
                      <td className={`py-1.5 capitalize ${SEV_COLOR[o.severity] ?? ""}`}>{o.severity}</td>
                      <td className="py-1.5 text-right tabular-nums text-danger">{dur(o.age_minutes)} old</td>
                      <td className="py-1.5 text-right tabular-nums text-muted">target {dur(o.target_minutes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          )}

          {data.recent_breaches.length > 0 && (
            <Panel title="Recent breaches (resolution)">
              <table className="w-full text-sm">
                <tbody className="divide-y divide-line">
                  {data.recent_breaches.map((b, i) => (
                    <tr key={`${b.case_number}-${i}`} className="text-text">
                      <td className="py-1.5 font-mono">{b.case_number ?? "—"}</td>
                      <td className={`py-1.5 capitalize ${SEV_COLOR[b.severity] ?? ""}`}>{b.severity}</td>
                      <td className="py-1.5 text-right tabular-nums">
                        {dur(b.resolution_minutes)} <span className="text-muted">vs {dur(b.target_minutes)}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          )}
        </>
      )}
    </div>
  );
}
