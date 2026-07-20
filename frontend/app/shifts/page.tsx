"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import {
  Clock, AlertTriangle, Loader2, FileText, Check, Flag, Users, Inbox, Activity, Pencil, X,
} from "lucide-react";

type Item = {
  id: string; case_number: string | null; title: string; severity: string;
  status: string; verdict: string | null; customer: string | null;
  assignee: string; bucket: string; at_gate: boolean; age_hours: number; note: string;
  handoff_note: string | null; auto_note: string;
};
type Handoff = {
  generated_at: string; window_hours: number; on_duty: string | null;
  summary: { ingested: number; closed: number; auto_resolved: number; signed_off: number; escalations: number };
  counts: { open: number; at_gate: number; unassigned: number;
    by_bucket: Record<string, number>; by_severity: Record<string, number> };
  items: Item[];
};

const SEV: Record<string, string> = {
  critical: "text-danger bg-danger/10 border-danger/20",
  high: "text-warning bg-warning/10 border-warning/20",
  medium: "text-accent bg-accent/10 border-accent/20",
  low: "text-muted bg-surface2/40 border-line",
};
const BUCKET: Record<string, { label: string; cls: string }> = {
  gate: { label: "At gate", cls: "text-warning bg-warning/10 border-warning/20" },
  review: { label: "Review", cls: "text-accent bg-accent/10 border-accent/20" },
  in_progress: { label: "In progress", cls: "text-positive bg-positive/10 border-positive/20" },
  new: { label: "New", cls: "text-muted bg-surface2/40 border-line" },
};
const WINDOWS = [
  { v: 8, label: "8h shift" }, { v: 12, label: "12h shift" }, { v: 24, label: "24h" },
];

// Editable per-incident handoff note. Click to edit; saves to the incident and
// refreshes the board. When the analyst hasn't written one, the auto-generated
// note shows muted as a placeholder — writing over it persists the analyst note.
function HandoffNoteCell({ item, onSaved }: { item: Item; onSaved: () => void }) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(item.handoff_note ?? "");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function save() {
    setSaving(true);
    setErr(null);
    try {
      await api.patchIncident(item.id, { handoff_note: text.trim() || null });
      setEditing(false);
      onSaved();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setSaving(false);
    }
  }

  if (editing) {
    return (
      <div className="space-y-1.5" onClick={(e) => e.stopPropagation()}>
        <textarea
          autoFocus
          rows={3}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Note for the next analyst…"
          className="w-full bg-base border border-line rounded-md p-2 text-xs text-text resize-none focus:outline-none focus:border-accent"
        />
        <div className="flex items-center gap-2">
          <button onClick={save} disabled={saving}
            className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded border border-accent/40 text-accent hover:bg-accent/10 disabled:opacity-40">
            {saving ? <Loader2 size={11} className="animate-spin" /> : <Check size={11} />} Save
          </button>
          <button onClick={() => { setEditing(false); setText(item.handoff_note ?? ""); }}
            className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded border border-line text-muted hover:text-text">
            <X size={11} /> Cancel
          </button>
          {err && <span className="text-[11px] text-danger">{err}</span>}
        </div>
      </div>
    );
  }

  const hasNote = !!item.handoff_note;
  return (
    <button
      onClick={() => setEditing(true)}
      title="Edit handoff note for the next analyst"
      className="group flex items-start gap-1.5 text-left w-full hover:text-text"
    >
      <span className={hasNote ? "text-text whitespace-pre-wrap" : "text-muted italic"}>
        {hasNote ? item.handoff_note : item.auto_note}
      </span>
      <Pencil size={11} className="mt-0.5 shrink-0 text-muted opacity-0 group-hover:opacity-100" />
    </button>
  );
}

export default function ShiftsPage() {
  const [windowHours, setWindowHours] = useState(12);
  const [filter, setFilter] = useState<string>("all");
  const [copied, setCopied] = useState(false);
  const h = useSWR<Handoff>(`shifts:handoff:${windowHours}`, () => api.shifts.handoff(windowHours));

  async function copyReport() {
    const md = await api.shifts.handoffMarkdown(windowHours);
    if (md) {
      await navigator.clipboard.writeText(md);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  const data = h.data;
  const items = (data?.items ?? []).filter((it) =>
    filter === "all" ? true : filter === "gate" ? it.at_gate : it.severity === filter);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-accent text-sm font-mono tracking-wider">
            <Clock size={15} /> SHIFT HANDOFF
          </div>
          <h1 className="text-2xl font-semibold text-text mt-1">Hand off a clean board.</h1>
          <p className="text-muted text-sm mt-1">
            What the next analyst needs to pick up, ranked — gate items first. Built live from
            the incident board; nothing here changes state.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <select value={windowHours} onChange={(e) => setWindowHours(Number(e.target.value))}
            className="bg-surface border border-line rounded px-2 py-2 text-xs text-text">
            {WINDOWS.map((w) => <option key={w.v} value={w.v}>{w.label}</option>)}
          </select>
          <button onClick={copyReport} disabled={!data}
            className="btn btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50">
            {copied ? <Check size={14} /> : <FileText size={14} />}
            {copied ? "Copied" : "Copy report"}
          </button>
        </div>
      </div>

      {h.error ? (
        <div className="rounded-lg border border-line bg-surface/40 p-8 flex flex-col items-center gap-3 text-center">
          <AlertTriangle size={22} className="text-danger" />
          <div className="text-sm text-text">Couldn&apos;t load the handoff board.</div>
          <div className="text-[11px] text-muted font-mono">{h.error.message}</div>
          <button onClick={() => h.mutate()} className="text-xs border border-line rounded px-3 py-1.5 text-text hover:bg-surface2/40">Retry</button>
        </div>
      ) : h.isLoading || !data ? (
        <div className="flex items-center gap-2 text-muted text-sm py-16 justify-center">
          <Loader2 size={16} className="animate-spin" /> Loading handoff…
        </div>
      ) : (
        <>
          {/* This-shift summary */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {[
              { label: "Ingested", value: data.summary.ingested, icon: Inbox, color: "text-accent" },
              { label: "Closed", value: data.summary.closed, icon: Check, color: "text-positive" },
              { label: "Auto-resolved", value: data.summary.auto_resolved, icon: Activity, color: "text-positive" },
              { label: "Analyst-signed", value: data.summary.signed_off, icon: Users, color: "text-text" },
              { label: "At gate", value: data.summary.escalations, icon: Flag, color: "text-warning" },
            ].map((s) => (
              <div key={s.label} className="rounded-lg border border-line bg-surface/40 p-4">
                <div className="flex items-center gap-1.5 text-muted text-[11px] uppercase tracking-wider">
                  <s.icon size={12} /> {s.label}
                </div>
                <div className={`text-2xl font-semibold mt-1 ${s.color}`}>{s.value}</div>
              </div>
            ))}
          </div>

          {/* Active shift strip */}
          <div className="rounded-lg border border-line bg-surface/40 px-5 py-3 flex flex-wrap items-center gap-x-8 gap-y-2">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-positive animate-pulse" />
              <span className="text-xs text-muted">On duty</span>
              <span className="text-sm text-text font-medium">{data.on_duty ?? "—"}</span>
            </div>
            <div className="text-xs text-muted">
              Open <span className="text-text font-semibold">{data.counts.open}</span> ·
              Unassigned <span className="text-text font-semibold">{data.counts.unassigned}</span> ·
              At gate <span className="text-warning font-semibold">{data.counts.at_gate}</span>
            </div>
            <div className="text-[11px] text-muted ml-auto">
              Generated {new Date(data.generated_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            </div>
          </div>

          {/* Open handoff items */}
          <div className="rounded-lg border border-line bg-surface/40 overflow-hidden">
            <div className="px-5 py-3 border-b border-line flex flex-wrap items-center gap-3">
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-text">Open items for the next shift</div>
                <div className="text-[11px] text-muted">{items.length} shown · gate items first, then severity, then age</div>
              </div>
              <div className="flex gap-1.5 flex-wrap">
                {["all", "gate", "critical", "high", "medium", "low"].map((f) => (
                  <button key={f} onClick={() => setFilter(f)}
                    className={`text-xs px-2.5 py-1 rounded border capitalize ${
                      filter === f ? "bg-accent/15 text-text border-accent/30" : "text-muted border-line hover:text-text"}`}>
                    {f}
                  </button>
                ))}
              </div>
            </div>
            {items.length === 0 ? (
              <div className="px-5 py-10 text-center text-sm text-muted">
                {data.counts.open === 0 ? "Clean board — nothing open. 🎉" : "No items match this filter."}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-line/60 text-[11px] uppercase tracking-wider text-muted">
                      <th className="text-left px-5 py-2.5 font-medium">Priority</th>
                      <th className="text-left px-5 py-2.5 font-medium">Incident</th>
                      <th className="text-left px-5 py-2.5 font-medium">Stage</th>
                      <th className="text-left px-5 py-2.5 font-medium">Assignee</th>
                      <th className="text-left px-5 py-2.5 font-medium">Age</th>
                      <th className="text-left px-5 py-2.5 font-medium">Handoff note</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((it) => (
                      <tr key={it.id} className="border-b border-line/30 hover:bg-surface2/20">
                        <td className="px-5 py-3">
                          <span className={`text-xs font-medium px-2 py-0.5 rounded border ${SEV[it.severity] ?? SEV.low}`}>
                            {it.severity}
                          </span>
                        </td>
                        <td className="px-5 py-3">
                          <a href={`/incidents/${it.id}`} className="text-text font-medium hover:text-accent">
                            {it.case_number ?? it.id.slice(0, 8)}
                          </a>
                          {it.customer && <span className="text-muted text-xs ml-2">{it.customer}</span>}
                          <div className="text-xs text-muted truncate max-w-md">{it.title}</div>
                        </td>
                        <td className="px-5 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded border ${(BUCKET[it.bucket] ?? BUCKET.new).cls}`}>
                            {(BUCKET[it.bucket] ?? BUCKET.new).label}
                          </span>
                        </td>
                        <td className="px-5 py-3">
                          <span className={it.assignee === "unassigned" ? "text-muted italic text-xs" : "text-text text-xs"}>
                            {it.assignee}
                          </span>
                        </td>
                        <td className="px-5 py-3 text-xs text-muted">{it.age_hours}h</td>
                        <td className="px-5 py-3 text-xs max-w-xs">
                          <HandoffNoteCell item={it} onSaved={() => h.mutate()} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
