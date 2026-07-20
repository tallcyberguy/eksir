"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, RefreshCw, Hand, Undo2, Clock, ArrowRight, AlertTriangle } from "lucide-react";

type QItem = {
  id: string;
  case_number: string;
  title: string;
  severity: string;
  status: string | null;
  tenant_id: string | null;
  customer: string | null;
  assignee_id: string | null;
  bucket: "mine" | "unassigned";
  sla_due_at: string;
  sla_remaining_seconds: number;
  sla_state: "green" | "amber" | "breached";
  proposed_actions: string[];
  asset: string | null;
  created_at: string;
};
type QData = {
  items: QItem[];
  total: number;
  counts: { mine: number; unassigned: number; all: number };
  next_up_id: string | null;
  generated_at: string;
};

const SEV_STYLE: Record<string, string> = {
  critical: "text-danger border-danger/40",
  high: "text-danger border-danger/30",
  medium: "text-warning border-warning/40",
  low: "text-muted border-line",
};
const PILL_STYLE: Record<string, string> = {
  green: "text-positive border-positive/40 bg-positive/10",
  amber: "text-warning border-warning/40 bg-warning/10",
  breached: "text-danger border-danger/40 bg-danger/10",
};
const SNOOZE_PRESETS: [string, number][] = [["15m", 15], ["1h", 60], ["4h", 240], ["1d", 1440]];
const TABS: { key: string; label: string }[] = [
  { key: "all", label: "All" },
  { key: "me", label: "Mine" },
  { key: "unassigned", label: "Unassigned" },
];

function fmtRemaining(sec: number): string {
  const overdue = sec < 0;
  let s = Math.abs(Math.round(sec));
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60);
  const parts = d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
  return overdue ? `overdue ${parts}` : parts;
}

export function QueueView() {
  const router = useRouter();
  // Land on the unclaimed worklist — clicking an item claims it for you (below).
  const [tab, setTab] = useState("unassigned");
  const [severity, setSeverity] = useState("");
  const [period, setPeriod] = useState("all");
  const assignee = tab === "me" ? "me" : tab === "unassigned" ? "unassigned" : undefined;

  const key = `queue.${tab}.${severity}.${period}`;
  const { data, isLoading, mutate } = useSWR<QData>(key, () =>
    api.queue.list({ assignee, severity: severity || undefined, period }),
  );

  // Poll every 15s (shim doesn't auto-revalidate) + a 1s tick to decrement SLA
  // pills, anchored to the client time at data load (no server clock skew).
  const loadedAt = useRef<number>(Date.now());
  const [, forceTick] = useState(0);
  useEffect(() => { loadedAt.current = Date.now(); }, [data]);
  useEffect(() => {
    const poll = setInterval(() => mutate(), 15000);
    const tick = setInterval(() => forceTick((n) => n + 1), 1000);
    return () => { clearInterval(poll); clearInterval(tick); };
  }, [mutate]);

  const [busy, setBusy] = useState<Record<string, boolean>>({});
  const [conflict, setConflict] = useState<string | null>(null);
  const [snoozeFor, setSnoozeFor] = useState<string | null>(null);

  const elapsed = () => (Date.now() - loadedAt.current) / 1000;

  // Clicking an unassigned incident claims it for the current analyst, then opens
  // it. If someone else won the race (or it's already owned) we still open it —
  // the claim just no-ops. Assigned items open without touching ownership.
  async function openIncident(it: QItem) {
    if (it.bucket === "unassigned") {
      try { await api.queue.claim(it.id); } catch { /* race/owned — open anyway */ }
    }
    router.push(`/incidents/${it.id}`);
  }

  async function doClaim(id: string) {
    setBusy((b) => ({ ...b, [id]: true }));
    setConflict(null);
    try {
      const r = await api.queue.claim(id);
      if (r.status === 409) setConflict(id);
      await mutate();
    } finally {
      setBusy((b) => ({ ...b, [id]: false }));
    }
  }
  async function doRelease(id: string) {
    setBusy((b) => ({ ...b, [id]: true }));
    try { await api.queue.release(id); await mutate(); }
    finally { setBusy((b) => ({ ...b, [id]: false })); }
  }
  async function doSnooze(id: string, minutes: number) {
    setSnoozeFor(null);
    setBusy((b) => ({ ...b, [id]: true }));
    try { await api.queue.snooze(id, minutes); await mutate(); }
    finally { setBusy((b) => ({ ...b, [id]: false })); }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex gap-1">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`px-3 py-1 rounded text-sm flex items-center gap-1.5 ${
                tab === t.key ? "bg-accent/20 text-text" : "text-muted hover:text-text"
              }`}
            >
              {t.label}
              {data && (
                <span className="text-[10px] tabular-nums text-muted">
                  {t.key === "me" ? data.counts.mine : t.key === "unassigned" ? data.counts.unassigned : data.counts.all}
                </span>
              )}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}
            className="bg-surface border border-line rounded px-2 py-1 text-sm text-text">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={period} onChange={(e) => setPeriod(e.target.value)}
            className="bg-surface border border-line rounded px-2 py-1 text-sm text-text">
            <option value="all">All time</option>
            <option value="24h">24h</option>
            <option value="7d">7d</option>
            <option value="30d">30d</option>
          </select>
          {data?.next_up_id && (
            <Link href={`/incidents/${data.next_up_id}`}
              className="btn btn-primary text-sm flex items-center gap-1.5">
              Next up <ArrowRight size={14} />
            </Link>
          )}
          <button onClick={() => mutate()} className="text-muted hover:text-text flex items-center gap-1.5 text-sm" title="Refresh">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      <Panel title="Worklist">
        {isLoading || !data ? (
          <div className="flex items-center gap-2 text-muted text-sm py-8">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : data.items.length === 0 ? (
          <div className="text-sm text-muted py-6 text-center">
            Nothing here. {tab === "me" ? "You have no claimed cases." : "Queue is clear."}
          </div>
        ) : (
          <ul className="divide-y divide-line">
            {data.items.map((it) => {
              const remaining = it.sla_remaining_seconds - elapsed();
              const state = remaining < 0 ? "breached" : it.sla_state;
              return (
                <li key={it.id} className="py-2.5 flex items-start gap-3">
                  <span className={`mt-0.5 text-[10px] uppercase font-mono border rounded px-1.5 py-0.5 ${SEV_STYLE[it.severity] ?? SEV_STYLE.low}`}>
                    {it.severity}
                  </span>
                  <div className="min-w-0 flex-1">
                    <a
                      href={`/incidents/${it.id}`}
                      onClick={(e) => { e.preventDefault(); openIncident(it); }}
                      title={it.bucket === "unassigned" ? "Claim & open — assigns this incident to you" : "Open incident"}
                      className="text-sm text-text hover:text-accent break-words cursor-pointer"
                    >
                      <span className="font-mono text-muted mr-2">{it.case_number}</span>{it.title}
                    </a>
                    <div className="flex items-center gap-2 mt-1 text-[11px] text-muted flex-wrap">
                      <span className={`border rounded px-1.5 py-0.5 inline-flex items-center gap-1 ${PILL_STYLE[state]}`}>
                        <Clock size={11} /> {fmtRemaining(remaining)}
                      </span>
                      {it.asset && <span className="font-mono">{it.asset}</span>}
                      {it.customer && <span>· {it.customer}</span>}
                      {it.bucket === "mine" && <span className="text-accent">· mine</span>}
                      {it.proposed_actions.map((a) => (
                        <span key={a} className="border border-line rounded px-1 text-[10px] font-mono">{a}</span>
                      ))}
                    </div>
                    {conflict === it.id && (
                      <div className="mt-1 text-[11px] text-danger flex items-center gap-1">
                        <AlertTriangle size={11} /> Another analyst claimed this first.
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {it.bucket === "unassigned" ? (
                      <button disabled={busy[it.id]} onClick={() => doClaim(it.id)}
                        className="text-xs flex items-center gap-1 border border-line rounded px-2 py-1 text-text hover:bg-surface2/40 disabled:opacity-50">
                        <Hand size={12} /> Claim
                      </button>
                    ) : (
                      <button disabled={busy[it.id]} onClick={() => doRelease(it.id)}
                        className="text-xs flex items-center gap-1 border border-line rounded px-2 py-1 text-muted hover:text-text disabled:opacity-50">
                        <Undo2 size={12} /> Release
                      </button>
                    )}
                    <div className="relative">
                      <button disabled={busy[it.id]} onClick={() => setSnoozeFor(snoozeFor === it.id ? null : it.id)}
                        className="text-xs flex items-center gap-1 border border-line rounded px-2 py-1 text-muted hover:text-text disabled:opacity-50">
                        <Clock size={12} /> Snooze
                      </button>
                      {snoozeFor === it.id && (
                        <div className="absolute right-0 mt-1 z-10 bg-surface border border-line rounded shadow-cyber flex">
                          {SNOOZE_PRESETS.map(([lbl, mins]) => (
                            <button key={mins} onClick={() => doSnooze(it.id, mins)}
                              className="px-2 py-1 text-xs text-text hover:bg-surface2/50">{lbl}</button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
        {data && (
          <p className="text-[11px] text-muted mt-2">
            Claim / release / snooze affect ownership + scheduling only — never the analyst verdict.
          </p>
        )}
      </Panel>
    </div>
  );
}
