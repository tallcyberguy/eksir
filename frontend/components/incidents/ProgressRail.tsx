"use client";

import { useState } from "react";
import { Panel } from "@/components/ui/Panel";
import { cn, verdictPill } from "@/lib/utils";
import { deriveStages, type Ev, type Stage } from "@/lib/stages";
import {
  CheckCircle2, XCircle, AlertTriangle, Loader2, CircleDot, MinusCircle, ShieldCheck, ShieldX,
  MessageSquare, Send,
} from "lucide-react";

// Friendly labels for proposed-action kinds shown at the gate.
const ACTION_LABEL: Record<string, string> = {
  blocklist_ioc: "Block IOC",
  isolate_host: "Isolate host",
  collect_file: "Collect file",
  create_case: "Create customer case",
};

type Props = {
  events: Ev[];
  incident: any;
  busy: boolean;
  onApprove: (actionIds: string[], notes?: string) => Promise<void> | void;
  onReject: (reason: string, requeue: boolean) => Promise<void> | void;
  onMessage: (message: string) => Promise<void> | void;
};

/** Right-rail vertical progress line: every pipeline/persona stage with live
 * status + a per-stage summary, and inline Approve/Reject at the human gate. */
export function ProgressRail({ events, incident, busy, onApprove, onReject, onMessage }: Props) {
  const stages = deriveStages(events, { includePending: true });
  const atGate = incident?.status === "awaiting_signoff";
  const stageData = incident?.enrichment?.stages || {};

  return (
    <div className="space-y-4">
      <Panel title="Pipeline">
        <ol className="space-y-1">
          {stages.map((s, i) => (
            <StageRow
              key={s.key}
              stage={s}
              summary={summarize(s.key, stageData, incident)}
              last={i === stages.length - 1}
            />
          ))}
        </ol>
      </Panel>

      {atGate && (
        <GatePanel incident={incident} busy={busy} onApprove={onApprove} onReject={onReject} onMessage={onMessage} />
      )}
    </div>
  );
}

function StageRow({ stage, summary, last }: { stage: Stage; summary: string | null; last: boolean }) {
  return (
    <li className="flex gap-2.5">
      <div className="flex flex-col items-center">
        <StatusIcon status={stage.status} />
        {!last && <span className={cn("w-px flex-1 my-1", stage.status === "pending" ? "bg-line/40" : "bg-line")} />}
      </div>
      <div className="pb-2.5 min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "text-sm",
              stage.status === "error" ? "text-danger"
                : stage.status === "warn" ? "text-warning"
                : stage.status === "pending" ? "text-muted/60"
                : stage.status === "skipped" ? "text-muted/50 line-through"
                : "text-text",
            )}
          >
            {stage.label}
          </span>
          {stage.duration_ms != null && (
            <span className="ml-auto text-[10px] text-muted font-mono shrink-0">{stage.duration_ms} ms</span>
          )}
        </div>
        {summary && <div className="text-[11px] text-muted leading-snug mt-0.5">{summary}</div>}
      </div>
    </li>
  );
}

function StatusIcon({ status }: { status: Stage["status"] }) {
  const sz = 15;
  if (status === "running") return <Loader2 size={sz} className="text-accent animate-spin shrink-0" />;
  if (status === "ok") return <CheckCircle2 size={sz} className="text-positive shrink-0" />;
  if (status === "warn") return <AlertTriangle size={sz} className="text-warning shrink-0" />;
  if (status === "error") return <XCircle size={sz} className="text-danger shrink-0" />;
  if (status === "skipped") return <MinusCircle size={sz} className="text-muted/40 shrink-0" />;
  return <CircleDot size={sz} className="text-muted/40 shrink-0" />;
}

/** One-line summary per stage, pulled from incident.enrichment.stages. */
function summarize(key: string, stages: any, incident: any): string | null {
  const d = stages?.[key];
  if (key === "l1" && d) return `${d.obvious_disposition || "?"} · sev ${d.initial_severity || "?"}`;
  if (key === "l2" && d) {
    const mitre = (d.mitre_techniques || []).slice(0, 4).join(", ");
    return `${d.verdict || "?"} / ${d.confidence || "?"}${mitre ? ` · ${mitre}` : ""}`;
  }
  if (key === "hunt" && d) return `spread: ${d.spread_assessment || "?"} · ${(d.queries || []).length} queries`;
  if (key === "forensics" && d) return `scope: ${d.scope || "?"}`;
  if (key === "synthesis") {
    const p = incident?.enrichment?.proposal;
    if (p) return `proposed ${p.proposed_verdict} (${p.confidence || "?"})`;
  }
  return null;
}

// ── Human gate ──────────────────────────────────────────────────────────────
function GatePanel({ incident, busy, onApprove, onReject, onMessage }: Omit<Props, "events">) {
  const proposal = incident?.enrichment?.proposal || {};
  const actions: any[] = incident?.enrichment?.proposed_actions || [];
  const chat: any[] = incident?.enrichment?.manager_chat || [];
  // Autonomy guardrails (3.9): pre-check only non-escalate actions. `escalate`
  // (containment / low-confidence) stays UNchecked so it needs an explicit click.
  // Actions without an autonomy field (legacy) default to checked.
  const [selected, setSelected] = useState<Set<string>>(
    new Set(actions.filter((a) => a.autonomy !== "escalate").map((a) => a.id)),
  );
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState("");
  const [requeue, setRequeue] = useState(true);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);

  async function send() {
    const m = draft.trim();
    if (!m) return;
    setSending(true);
    try { await onMessage(m); setDraft(""); }
    finally { setSending(false); }
  }

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  return (
    <Panel title="Analyst sign-off" className="border-warning/40">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-[10px] uppercase tracking-wider text-muted">Proposed verdict</span>
        <span className={verdictPill(proposal.proposed_verdict)}>{proposal.proposed_verdict || "—"}</span>
        {proposal.confidence && <span className="text-[11px] text-muted">conf {proposal.confidence}</span>}
      </div>
      {proposal.reasoning && (
        <p className="text-xs text-text/80 leading-relaxed mb-3">{proposal.reasoning}</p>
      )}

      {actions.length > 0 && (
        <div className="mb-3">
          <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
            Proposed response actions
          </div>
          <ul className="space-y-1.5">
            {actions.map((a) => (
              <li key={a.id} className="flex items-start gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={selected.has(a.id)}
                  onChange={() => toggle(a.id)}
                  disabled={busy || a.status === "executed"}
                  className="mt-0.5 accent-accent"
                />
                <span className="leading-snug">
                  <span className="font-mono text-warning">{ACTION_LABEL[a.kind] ?? a.kind}</span>{" "}
                  {a.autonomy && (
                    <span
                      title={a.autonomy_reason}
                      className={`text-[9px] rounded px-1 border ${
                        a.autonomy === "auto"
                          ? "text-positive border-positive/40"
                          : a.autonomy === "escalate"
                            ? "text-danger border-danger/40"
                            : "text-muted border-line"
                      }`}
                    >
                      {a.autonomy === "auto" ? "auto-eligible" : a.autonomy}
                    </span>
                  )}{" "}
                  <span className="text-muted">{Object.values(a.params || {}).join(" · ")}</span>
                  {a.status === "executed" && <span className="text-positive"> ✓ done</span>}
                  {a.status === "failed" && <span className="text-danger"> — failed</span>}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Talk to the manager — revise the proposal or re-task hunt/forensics */}
      <div className="mb-3 border-t border-line/40 pt-3">
        <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted mb-1.5">
          <MessageSquare size={12} /> Manager
        </div>
        {chat.length > 0 && (
          <div className="space-y-1.5 mb-2 max-h-56 overflow-y-auto pr-1">
            {chat.map((m: any, i: number) => (
              <div key={i} className={cn("text-xs leading-snug", m.role === "analyst" ? "text-text" : "text-accent")}>
                <span className="text-[10px] uppercase tracking-wider text-muted/70 mr-1">
                  {m.role === "analyst" ? "You" : "Mgr"}
                </span>
                {m.text}
              </div>
            ))}
          </div>
        )}
        <div className="flex items-end gap-1.5">
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) send(); }}
            placeholder="Ask the manager to change blocks, re-task forensics/hunt…"
            rows={2}
            disabled={sending || busy}
            className="flex-1 bg-base border border-line rounded-md px-2 py-1.5 text-xs focus:outline-none focus:border-accent disabled:opacity-50"
          />
          <button
            onClick={send}
            disabled={sending || busy || !draft.trim()}
            title="Send (⌘/Ctrl+Enter)"
            className="p-2 rounded-md border border-line text-muted hover:border-accent hover:text-accent disabled:opacity-40"
          >
            {sending ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
          </button>
        </div>
        {sending && <div className="text-[10px] text-muted mt-1">Manager working… (may re-run a hunt/forensics)</div>}
      </div>

      {!rejecting ? (
        <div className="flex items-center gap-2">
          <button
            onClick={() => onApprove(Array.from(selected))}
            disabled={busy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm bg-positive/10 border border-positive/40 text-positive hover:bg-positive/20 disabled:opacity-40"
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
            Approve & commit
          </button>
          <button
            onClick={() => setRejecting(true)}
            disabled={busy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm border border-line text-muted hover:border-danger hover:text-danger disabled:opacity-40"
          >
            <ShieldX size={14} /> Reject
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Why are you rejecting this proposal?"
            rows={2}
            className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-xs focus:outline-none focus:border-accent"
          />
          <label className="flex items-center gap-1.5 text-[11px] text-muted">
            <input type="checkbox" checked={requeue} onChange={(e) => setRequeue(e.target.checked)} className="accent-accent" />
            Re-run analysis (otherwise drop to manual review)
          </label>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onReject(reason || "rejected by analyst", requeue)}
              disabled={busy}
              className="px-3 py-1.5 rounded-md text-sm bg-danger/10 border border-danger/40 text-danger hover:bg-danger/20 disabled:opacity-40"
            >
              Confirm reject
            </button>
            <button onClick={() => setRejecting(false)} disabled={busy} className="text-xs text-muted hover:text-text">
              Cancel
            </button>
          </div>
        </div>
      )}
    </Panel>
  );
}
