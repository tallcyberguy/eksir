"use client";

import { useEffect, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { LLMReport } from "@/components/incidents/LLMReport";
import { DeobfuscationPanel } from "@/components/incidents/DeobfuscationPanel";
import { PipelineTimeline } from "@/components/incidents/PipelineTimeline";
import { ProgressRail } from "@/components/incidents/ProgressRail";
import { V1Actions, BlocklistButton, ExcludeButton } from "@/components/incidents/V1Actions";
import { V1ActionsLog } from "@/components/incidents/V1ActionsLog";
import { DefenderActions } from "@/components/incidents/DefenderActions";
import { SimilarCasesPanel } from "@/components/incidents/SimilarCasesPanel";
import { EntitiesPanel } from "@/components/incidents/Entities";
import { RelatedIncidentsPanel } from "@/components/incidents/RelatedIncidentsPanel";
import { ScoreTiles, hasScores } from "@/components/incidents/Scores";
import { LLMCallsPanel } from "@/components/incidents/LLMCallsPanel";
import { IncidentForensicsPanel } from "@/components/incidents/IncidentForensicsPanel";
import { HuntPanel } from "@/components/incidents/HuntPanel";
import { AttackPathPanel } from "@/components/incidents/AttackPathPanel";
import { IncidentCollaboration } from "@/components/incidents/IncidentCollaboration";
import { defang, severityPill, statusPill, verdictPill } from "@/lib/utils";
import type { IncidentEntityLink, ClusterSummary } from "@/lib/api";
import { Pencil, Check, X, FileText, UserPlus, UserCheck, ArrowUpCircle } from "lucide-react";

type Tab = "summary"|"details"|"technical"|"timeline"|"attack-path"|"hunt"|"actions"|"forensics"|"llm";

const SEVERITIES = ["critical","high","medium","low"];
const SOURCE_PRODUCTS = ["qradar","wazuh","sentinelone","splunk","defender","elastic","other"];

// ── Inline text editor ────────────────────────────────────────────────────
function InlineText({
  value, onSave, placeholder = "—", className = "",
}: { value: string|null|undefined; onSave: (v: string) => Promise<void>; placeholder?: string; className?: string }) {
  const [editing, setEditing] = useState(false);
  const [draft,   setDraft]   = useState(value || "");
  const [saving,  setSaving]  = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  function start() { setDraft(value || ""); setEditing(true); setTimeout(() => inputRef.current?.focus(), 0); }
  function cancel() { setEditing(false); }

  async function save() {
    if (draft === (value || "")) { setEditing(false); return; }
    setSaving(true);
    try { await onSave(draft); setEditing(false); }
    finally { setSaving(false); }
  }

  if (editing) return (
    <span className="inline-flex items-center gap-1">
      <input
        ref={inputRef}
        value={draft}
        onChange={e => setDraft(e.target.value)}
        onKeyDown={e => { if (e.key === "Enter") save(); if (e.key === "Escape") cancel(); }}
        disabled={saving}
        className={`bg-base border border-accent/60 rounded px-2 py-0.5 text-sm focus:outline-none ${className}`}
      />
      <button onClick={save}   disabled={saving} className="text-positive hover:brightness-125"><Check size={14}/></button>
      <button onClick={cancel} disabled={saving} className="text-muted hover:text-danger"><X size={14}/></button>
    </span>
  );

  return (
    <span
      className={`group inline-flex items-center gap-1.5 cursor-pointer hover:text-accent transition-colors ${className}`}
      onClick={start}
    >
      <span>{value || <span className="text-muted italic">{placeholder}</span>}</span>
      <Pencil size={11} className="opacity-0 group-hover:opacity-60 transition-opacity shrink-0"/>
    </span>
  );
}

// ── Inline select editor ──────────────────────────────────────────────────
function InlineSelect({
  value, options, onSave, renderValue,
}: { value: string|null|undefined; options: string[]; onSave: (v: string) => Promise<void>; renderValue?: (v: string) => React.ReactNode }) {
  const [editing, setSaving_] = useState(false);
  const [saving,  setSaving]  = useState(false);

  async function pick(v: string) {
    if (v === value) { setSaving_(false); return; }
    setSaving(true);
    try { await onSave(v); }
    finally { setSaving(false); setSaving_(false); }
  }

  if (editing) return (
    <span className="inline-flex items-center gap-1">
      <select
        autoFocus
        defaultValue={value || ""}
        onChange={e => pick(e.target.value)}
        onBlur={() => setSaving_(false)}
        disabled={saving}
        className="bg-base border border-accent/60 rounded px-1 py-0.5 text-sm focus:outline-none"
      >
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </span>
  );

  return (
    <span
      className="group inline-flex items-center gap-1.5 cursor-pointer"
      onClick={() => setSaving_(true)}
    >
      {renderValue ? renderValue(value || "") : <span>{value || "—"}</span>}
      <Pencil size={11} className="opacity-0 group-hover:opacity-60 transition-opacity shrink-0"/>
    </span>
  );
}

// ── Sidecar row with optional inline edit ────────────────────────────────
function EditableRow({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <div className="text-[10px] uppercase tracking-wider text-muted shrink-0">{k}</div>
      <div className="text-right text-text">{children}</div>
    </div>
  );
}

export default function IncidentDetail() {
  const { id } = useParams<{id: string}>();
  const router = useRouter();
  const [inc, setInc] = useState<any>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [iocs, setIocs] = useState<any[]>([]);
  const [entities, setEntities] = useState<IncidentEntityLink[]>([]);
  const [cluster, setCluster] = useState<ClusterSummary | null>(null);
  const [tab, setTab] = useState<Tab>("summary");
  const [busy, setBusy] = useState(false);
  const [pendingVerdict, setPendingVerdict] = useState<null | "TP" | "FP" | "benign">(null);
  const [me, setMe] = useState<any>(null);

  async function refresh() {
    const [i, tl, io, ent, cl] = await Promise.all([
      api.getIncident(id),
      api.getTimeline(id),
      api.getIOCs(id),
      // Non-core panel: its endpoint is the newest / most deploy-fragile leg, so
      // it must never block the core incident view — degrade to an empty list.
      api.getIncidentEntities(id).catch(() => [] as IncidentEntityLink[]),
      // Correlation cluster (Phase 2a) — same isolation posture; degrade to null.
      api.getIncidentCluster(id).catch(() => null),
    ]);
    setInc(i); setTimeline(tl); setIocs(io); setEntities(ent); setCluster(cl);
  }

  useEffect(() => {
    refresh().catch(() => {});
    const t = setInterval(() => { refresh().catch(() => {}); }, 3500);
    return () => clearInterval(t);
  }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { api.me().then(setMe).catch(() => {}); }, []);

  if (!inc) return <div className="text-muted">Loading…</div>;

  async function patch(fields: Record<string, any>) {
    await api.patchIncident(id, fields);
    await refresh();
  }

  // Assign to self — stamps claimed_at (the response-SLA anchor) on first claim.
  async function assignSelf() {
    setBusy(true);
    try { await api.assignIncident(id); await refresh(); }
    finally { setBusy(false); }
  }

  // Escalate to L2 (an L1 hands off a case they can't action). Surfaces to L2
  // via the "Escalated" filter on the incidents list.
  async function escalate() {
    const note = window.prompt("Escalate to L2 (optional note, why):") ?? undefined;
    setBusy(true);
    try { await api.escalateIncident(id, note || undefined); await refresh(); }
    finally { setBusy(false); }
  }
  async function deescalate() {
    setBusy(true);
    try { await api.deescalateIncident(id); await refresh(); }
    finally { setBusy(false); }
  }

  // Verdict click opens a modal to capture the analyst's "why" (optional) —
  // that reason is indexed to Qdrant so future identical alerts retrieve it.
  async function confirmVerdict(reason: string) {
    const v = pendingVerdict;
    if (!v) return;
    setBusy(true);
    try {
      await patch({ verdict: v, verdict_reason: reason.trim() || undefined });
      setPendingVerdict(null);
    } finally { setBusy(false); }
  }

  async function regen() {
    setBusy(true);
    try { await api.regenerate(id); await refresh(); }
    finally { setBusy(false); }
  }

  async function approve(actionIds: string[], notes?: string) {
    setBusy(true);
    try { await api.approveIncident(id, { approve_action_ids: actionIds, notes }); await refresh(); }
    finally { setBusy(false); }
  }

  async function reject(reason: string, requeue: boolean) {
    setBusy(true);
    try { await api.rejectIncident(id, { reason, requeue }); await refresh(); }
    finally { setBusy(false); }
  }

  async function manager(message: string) {
    await api.managerMessage(id, message);
    await refresh();
  }

  async function createCase() {
    setBusy(true);
    try {
      const c = await api.cases.create({ source_incident_id: id });
      router.push(`/cases/${c.id}`);
    } catch (e: any) {
      alert(`Could not create case: ${e.message}`);
    } finally { setBusy(false); }
  }

  return (
    <div className="flex gap-5 items-start">
      <div className="flex-1 min-w-0 space-y-5">
      {pendingVerdict && (
        <VerdictModal
          verdict={pendingVerdict}
          busy={busy}
          onConfirm={confirmVerdict}
          onCancel={() => setPendingVerdict(null)}
        />
      )}
      {/* Header */}
      <div className="panel p-5">
        <div className="flex items-center gap-3 mb-2 text-sm flex-wrap">
          <span className="font-mono text-accent">{inc.case_number}</span>

          {/* Editable severity */}
          <InlineSelect
            value={inc.severity}
            options={SEVERITIES}
            onSave={v => patch({ severity: v })}
            renderValue={v => <span className={severityPill(v)}>{v}</span>}
          />

          <span className={statusPill(inc.status)}>{inc.status}</span>
          <span className={verdictPill(inc.verdict)}>{inc.verdict}</span>
          <span className="ml-auto text-muted text-xs">Created {new Date(inc.created_at).toLocaleString()}</span>

          {/* Ownership — assigning stamps claimed_at, the response-SLA anchor */}
          {me && inc.assignee_id === me.id ? (
            <span
              className="flex items-center gap-1 px-2.5 py-1 text-xs text-positive"
              title={inc.claimed_at
                ? `Responded ${new Date(inc.claimed_at).toLocaleString()}`
                : "Assigned to you"}
            >
              <UserCheck size={12}/> Assigned to you
            </span>
          ) : (
            <button
              onClick={assignSelf}
              disabled={busy}
              title={inc.assignee_id
                ? "Take over — assign to yourself (starts the response SLA clock)"
                : "Assign to yourself (starts the response SLA clock)"}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-line text-xs text-muted hover:border-accent hover:text-accent disabled:opacity-40 transition-colors"
            >
              <UserPlus size={12}/> {inc.assignee_id ? "Take over" : "Assign to me"}
            </button>
          )}

          {/* L1 → L2 escalation */}
          {inc.escalated_at ? (
            <span
              className="flex items-center gap-1 px-2.5 py-1 rounded-md text-xs bg-warning/10 text-warning border border-warning/40"
              title={`Escalated to L2${inc.escalation_note ? `: ${inc.escalation_note}` : ""}`}
            >
              <ArrowUpCircle size={12}/> Escalated to L2
              <button onClick={deescalate} disabled={busy} title="Clear escalation"
                      className="ml-1 text-muted hover:text-danger disabled:opacity-40"><X size={11}/></button>
            </span>
          ) : (
            <button
              onClick={escalate}
              disabled={busy}
              title="Escalate this incident to an L2 analyst"
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-line text-xs text-muted hover:border-warning hover:text-warning disabled:opacity-40 transition-colors"
            >
              <ArrowUpCircle size={12}/> Escalate to L2
            </button>
          )}

          <button
            onClick={createCase}
            disabled={busy}
            title="Promote this incident into a customer-facing notification case"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-line text-xs text-muted hover:border-accent hover:text-accent disabled:opacity-40 transition-colors"
          >
            <FileText size={12}/> Create case
          </button>
        </div>

        {/* Editable title */}
        <h1 className="text-xl font-semibold">
          <InlineText
            value={inc.title}
            placeholder="untitled"
            onSave={v => patch({ title: v })}
            className="w-full"
          />
        </h1>
      </div>

      {/* Tabs */}
      <div className="flex gap-6 border-b border-line text-sm">
        {(["summary","details","technical","timeline","attack-path","hunt","actions","forensics","llm"] as Tab[]).map(t => (
          <button key={t}
                  onClick={()=>setTab(t)}
                  className={`pb-2 -mb-px border-b-2 ${tab===t
                    ? "border-accent text-text"
                    : "border-transparent text-muted hover:text-text"}`}>
            {t === "llm" ? "LLM Calls" : t === "attack-path" ? "Attack Path" : t.charAt(0).toUpperCase()+t.slice(1)}
            {t==="timeline" && timeline.length>0 && <span className="ml-1.5 text-[10px] text-accent">{timeline.length}</span>}
          </button>
        ))}
      </div>

      {tab==="summary" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <Panel title="Incident Analysis" className="lg:col-span-2">
            {inc.status === "awaiting_review" && (
              <div className="flex items-center gap-2 flex-wrap mb-5 pb-4 border-b border-line/60">
                <span className="text-[10px] uppercase tracking-wider text-muted mr-1">Set verdict:</span>
                <button onClick={()=>setPendingVerdict("TP")}     disabled={busy} className="pill pill-critical hover:brightness-125">TP</button>
                <button onClick={()=>setPendingVerdict("FP")}     disabled={busy} className="pill pill-resolved hover:brightness-125">FP</button>
                <button onClick={()=>setPendingVerdict("benign")} disabled={busy} className="pill pill-medium hover:brightness-125">Benign</button>
                <button onClick={regen} disabled={busy} className="ml-auto text-xs underline text-muted hover:text-accent">
                  Regenerate report
                </button>
              </div>
            )}
            {inc.llm_report_markdown
              ? <LLMReport markdown={inc.llm_report_markdown}/>
              : inc.short_circuit
                  ? <div className="text-sm text-muted">
                      <div className="flex items-start gap-3 flex-wrap">
                        <div className="flex-1 min-w-0">
                          Short-circuited by <b className="text-text">{inc.short_circuit.gate}</b> — no LLM call needed.
                        </div>
                        <button onClick={regen} disabled={busy}
                                className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs
                                           bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20
                                           disabled:opacity-40"
                                title="Bypass the short-circuit and run the deep model on this incident.">
                          ⚡ Run deep analysis
                        </button>
                      </div>
                      <pre className="mt-3 bg-base border border-line rounded-md p-3 text-xs overflow-x-auto">
                        {JSON.stringify(inc.short_circuit, null, 2)}
                      </pre>
                      <p className="mt-2 text-[11px] text-muted/70 leading-relaxed">
                        The automated gate decided this incident didn't need an LLM report.
                        If you disagree, force a deep analysis — bypasses the fast tier and
                        every short-circuit gate, runs the deep model with the full briefing.
                        Audit-logged as an analyst bypass.
                      </p>
                    </div>
                  : <div className="text-sm text-muted">Pipeline still running…</div>}
          </Panel>

          <div className="space-y-5">
          <Panel title="Sidecar">
            {hasScores(inc.enrichment?.scores) && (
              <div className="mb-3 pb-3 border-b border-line/60">
                <ScoreTiles scores={inc.enrichment.scores}/>
              </div>
            )}
            <div className="space-y-3 text-sm">
              <EditableRow k="Customer">
                <InlineText
                  value={inc.customer}
                  placeholder="unknown"
                  onSave={v => patch({ customer: v })}
                />
              </EditableRow>

              <EditableRow k="Rule">
                <InlineText
                  value={inc.rule_name}
                  placeholder="—"
                  onSave={v => patch({ rule_name: v })}
                />
              </EditableRow>

              <EditableRow k="Source">
                <InlineSelect
                  value={inc.source_product}
                  options={SOURCE_PRODUCTS}
                  onSave={v => patch({ source_product: v })}
                />
              </EditableRow>

              {!hasScores(inc.enrichment?.scores) && (
                <EditableRow k="Confidence">
                  <span className="text-text">{inc.confidence || "—"}</span>
                </EditableRow>
              )}

              <EditableRow k="LLM tokens">
                <span className="text-text">
                  {inc.llm_input_tokens ? `${inc.llm_input_tokens} in / ${inc.llm_output_tokens} out` : "—"}
                </span>
              </EditableRow>

              <EditableRow k="Model">
                <span className="text-text">{inc.llm_model_used || "—"}</span>
              </EditableRow>

              <EditableRow k="Vector DB">
                {inc.qdrant_alert_id
                  ? <span className="font-mono text-xs break-all text-positive">indexed · {String(inc.qdrant_alert_id).slice(0,8)}…</span>
                  : inc.status === "awaiting_review"
                      ? <span className="text-muted text-xs italic">pending verdict</span>
                      : inc.status === "closed"
                          ? <span className="text-warning text-xs">not indexed</span>
                          : <span className="text-muted text-xs">—</span>}
              </EditableRow>

              <EditableRow k="Prior cases">
                <SimilarCasesValue enrichment={inc.enrichment}/>
              </EditableRow>
            </div>

            {inc.verdict_reason && (
              <div className="mt-3 border-t border-line/60 pt-3">
                <div className="text-[10px] uppercase tracking-wider text-muted mb-1">Analyst rationale</div>
                <p className="text-xs text-text/90 leading-relaxed whitespace-pre-wrap">{inc.verdict_reason}</p>
              </div>
            )}

            {!inc.qdrant_alert_id && inc.status === "awaiting_review" && (
              <div className="mt-4 text-[11px] text-muted leading-relaxed border-t border-line/60 pt-3">
                The vector DB only receives analyst-verified verdicts. Once you set TP/FP/Benign above,
                this case is indexed and will short-circuit future identical alerts.
              </div>
            )}
            <SimilarCasesDetail enrichment={inc.enrichment}/>
          </Panel>

          <EntitiesPanel entities={entities}/>
          <RelatedIncidentsPanel cluster={cluster}/>
          <SimilarCasesPanel enrichment={inc.enrichment}/>
          <IncidentCollaboration incidentId={inc.id}/>
          </div>

          <div className="lg:col-span-3">
            <DeobfuscationPanel enrichment={inc.enrichment}/>
          </div>
        </div>
      )}

      {tab==="technical" && (
        <Panel title="IOCs">
          <table className="w-full text-sm">
            <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
              <tr className="text-left"><th>Type</th><th>Value</th><th>Tenant</th><th></th></tr>
            </thead>
            <tbody>
              {iocs.map((r:any)=>(
                <tr key={r.id} className="border-t border-line/60">
                  <td className="py-2 pr-3 text-muted">{r.ioc_type}</td>
                  <td className="py-2 pr-3 font-mono">{defang(r.value)}</td>
                  <td className="py-2 pr-3 text-muted">{r.tenant || "—"}</td>
                  <td className="py-2">
                    <div className="flex items-center gap-1.5">
                      <BlocklistButton incidentId={inc.id} iocType={r.ioc_type} value={r.value}/>
                      <ExcludeButton incidentId={inc.id} iocType={r.ioc_type} value={r.value} customer={inc.customer}/>
                    </div>
                  </td>
                </tr>
              ))}
              {iocs.length===0 && <tr><td colSpan={4} className="py-6 text-center text-muted">No IOCs extracted.</td></tr>}
            </tbody>
          </table>
        </Panel>
      )}

      {tab==="timeline" && <PipelineTimeline events={timeline}/>}

      {tab==="details" && (
        <Panel title="Normalized fields">
          <pre className="text-xs bg-base border border-line rounded-md p-3 overflow-x-auto">
            {JSON.stringify(inc.normalized, null, 2)}
          </pre>
        </Panel>
      )}

      {tab==="actions" && (
        <div className="space-y-5">
          <V1ActionsLog incidentId={inc.id} enrichment={inc.enrichment}/>
          <V1Actions
            incidentId={inc.id}
            iocs={iocs.map((r:any) => ({ ioc_type: r.ioc_type, value: r.value }))}
            isV1Customer={!!(inc.customer && ["acme"].includes(inc.customer.toLowerCase()))}
          />
          {inc.normalized?.source_product === "microsoft_defender" && (
            <DefenderActions incidentId={inc.id} alertId={inc.normalized?.alert_id} />
          )}
        </div>
      )}

      {tab==="hunt" && (
        <HuntPanel incidentId={inc.id} caseNumber={inc.case_number} enrichment={inc.enrichment}/>
      )}

      {tab==="hunt" && (
        <HuntPanel incidentId={inc.id} caseNumber={inc.case_number} enrichment={inc.enrichment}/>
      )}

      {tab==="forensics" && <IncidentForensicsPanel incidentId={inc.id}/>}

      {tab==="attack-path" && <AttackPathPanel incidentId={inc.id}/>}

      {tab==="llm" && <LLMCallsPanel incidentId={inc.id}/>}
      </div>

      {/* Right-rail progress line — persists across tabs; advances via the 3.5s poll */}
      <aside className="hidden xl:block w-[340px] shrink-0 sticky top-4">
        <ProgressRail
          events={timeline}
          incident={inc}
          busy={busy}
          onApprove={approve}
          onReject={reject}
          onMessage={manager}
          canApprove={me?.role === "admin" || me?.role === "analyst"}
        />
      </aside>
    </div>
  );
}

function SimilarCasesValue({ enrichment }: { enrichment: any }) {
  if (!enrichment) return <span className="text-muted text-xs">—</span>;
  const exact = enrichment.exact_match;
  const nway  = enrichment.n_way;
  const sim: any[] = enrichment.similar_top5 || [];

  if (exact) {
    const v = exact.verdict || "?";
    const cls = v === "TP" ? "text-danger" : v === "FP" ? "text-positive" : "text-warning";
    return <span className={`text-xs font-mono ${cls}`}>exact · {v} ({Math.round((exact.score||0)*100)}%)</span>;
  }
  if (nway) {
    const v = nway.verdict || "?";
    const cls = v === "TP" ? "text-danger" : v === "FP" ? "text-positive" : "text-warning";
    return <span className={`text-xs font-mono ${cls}`}>{nway.agreement} agree · {v}</span>;
  }
  if (sim.length === 0) return <span className="text-muted text-xs">none</span>;

  const counts: Record<string,number> = {};
  sim.forEach(s => { const v = s.verdict||"?"; counts[v] = (counts[v]||0)+1; });
  const parts = Object.entries(counts).map(([v,n]) => `${n} ${v}`).join(" / ");
  return <span className="text-xs text-muted font-mono">{sim.length} cases · {parts}</span>;
}

function SimilarCasesDetail({ enrichment }: { enrichment: any }) {
  if (!enrichment) return null;
  const exact = enrichment.exact_match;
  const nway  = enrichment.n_way;
  const sim: any[] = enrichment.similar_top5 || [];
  if (!exact && !nway && sim.length === 0) return null;

  const verdictCls = (v: string) =>
    v === "TP" ? "text-danger" : v === "FP" ? "text-positive" : v === "benign" ? "text-warning" : "text-muted";

  return (
    <div className="mt-4 border-t border-line/60 pt-3 space-y-2">
      {exact && (
        <div className="text-[11px] leading-relaxed">
          <span className="uppercase tracking-wider text-muted text-[10px]">Exact match </span>
          <span className={`font-semibold ${verdictCls(exact.verdict)}`}>{exact.verdict}</span>
          <span className="text-muted"> · {Math.round((exact.score||0)*100)}% · </span>
          <span className="font-mono text-[10px] text-muted">{String(exact.alert_id||"").slice(0,8)}</span>
          {exact.verdict_reason && (
            <p className="text-muted mt-0.5 line-clamp-2">{exact.verdict_reason}</p>
          )}
        </div>
      )}
      {nway && !exact && (
        <div className="text-[11px] leading-relaxed">
          <span className="uppercase tracking-wider text-muted text-[10px]">N-way </span>
          <span className={`font-semibold ${verdictCls(nway.verdict)}`}>{nway.agreement} × {nway.verdict}</span>
          {(nway.matches||[]).slice(0,3).map((m:any) => (
            <div key={m.alert_id} className="text-[10px] text-muted font-mono">
              {String(m.alert_id||"").slice(0,8)} · {Math.round((m.score||0)*100)}%
            </div>
          ))}
        </div>
      )}
      {!exact && !nway && sim.length > 0 && (
        <div className="space-y-1">
          <div className="text-[10px] uppercase tracking-wider text-muted">Top similar</div>
          {sim.slice(0,5).map((s:any) => {
            const adjusted = typeof s.adjusted_score === "number" ? s.adjusted_score : (s.score || 0);
            const weak = adjusted < 0.6;
            return (
              <div key={s.alert_id} className={`flex items-center gap-2 text-[11px] ${weak ? "opacity-50" : ""}`}>
                <span className={`font-semibold w-8 ${verdictCls(s.verdict)}`}>{s.verdict}</span>
                <span className="text-muted font-mono text-[10px]">{Math.round(adjusted*100)}%</span>
                {weak && <span className="text-[9px] uppercase tracking-wider text-muted/70" title="Low cosine — likely boilerplate match">weak</span>}
                <span className="text-muted line-clamp-1 flex-1 text-[10px]">{s.verdict_reason?.slice(0,60)}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Verdict reason modal ────────────────────────────────────────────────────
const VERDICT_CHIPS: Record<string, string[]> = {
  TP:     ["confirmed malicious", "active C2 / beaconing", "credential compromise", "policy violation"],
  FP:     ["false-positive IOC (e.g. version string)", "benign admin activity", "known scanner", "tuning needed"],
  benign: ["expected admin activity", "known-good asset", "sanctioned tool", "test / maintenance"],
};

function VerdictModal({
  verdict, busy, onConfirm, onCancel,
}: {
  verdict: "TP" | "FP" | "benign";
  busy: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const [reason, setReason] = useState("");
  const label = verdict === "benign" ? "Benign" : verdict;
  const chipCls =
    verdict === "TP" ? "pill-critical" : verdict === "FP" ? "pill-resolved" : "pill-medium";

  function addChip(c: string) {
    setReason((r) => (r.trim() ? `${r.trim()}; ${c}` : c));
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
         onClick={onCancel}>
      <div className="w-full max-w-lg bg-surface border border-line rounded-lg shadow-cyber p-5"
           onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-[10px] uppercase tracking-wider text-muted">Set verdict</span>
          <span className={`pill ${chipCls}`}>{label}</span>
        </div>
        <p className="text-[11px] text-muted leading-relaxed mb-3">
          Why? This rationale is saved to the case memory (Qdrant) — future identical
          alerts retrieve it instead of the model&apos;s report. Optional, but recommended.
        </p>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          rows={3}
          autoFocus
          placeholder="e.g. FP — 3.0.0.0 is a .NET assembly version, not an IP."
          className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60"
        />
        <div className="mt-2 flex flex-wrap gap-1.5">
          {(VERDICT_CHIPS[verdict] || []).map((c) => (
            <button key={c} onClick={() => addChip(c)}
                    className="pill pill-medium text-[10px] hover:brightness-125">+ {c}</button>
          ))}
        </div>
        <div className="mt-4 flex items-center justify-end gap-2">
          <button onClick={onCancel} disabled={busy}
                  className="px-3 py-1.5 rounded-md text-sm text-muted hover:text-text disabled:opacity-40">
            Cancel
          </button>
          <button onClick={() => onConfirm(reason)} disabled={busy}
                  className="px-3 py-1.5 rounded-md text-sm bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
            {busy ? "Saving…" : `Confirm ${label}`}
          </button>
        </div>
      </div>
    </div>
  );
}
