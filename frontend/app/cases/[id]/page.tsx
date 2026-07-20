"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import {
  ArrowLeft, Save, Send, CheckCircle2, Edit3, RotateCcw, ExternalLink,
  Sparkles, Loader2, Eye, FileCode,
} from "lucide-react";
import dynamic from "next/dynamic";
import { PreviewModal } from "@/components/cases/PreviewModal";
import { AttachedIncidents } from "@/components/cases/AttachedIncidents";
import { CaseCollaboration } from "@/components/cases/CaseCollaboration";
import { SendModal } from "@/components/cases/SendModal";

// TinyMCE touches window/document — load the editor client-only.
const HtmlEditModal = dynamic(
  () => import("@/components/cases/HtmlEditModal").then((m) => m.HtmlEditModal),
  { ssr: false },
);

const LOCALES = ["en", "tr", "de", "fr", "es"];

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

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();

  const [c, setC]         = useState<any>(null);
  const [draft, setDraft] = useState<any>(null);
  const [busy, setBusy]   = useState(false);
  const [generating, setGenerating] = useState(false);
  const [autoTriedRef] = useState({ done: false });   // first-load auto-trigger guard
  const [previewOpen, setPreviewOpen] = useState(false);
  const [sendOpen, setSendOpen]       = useState(false);
  const [htmlEditOpen, setHtmlEditOpen] = useState(false);
  const [htmlInitial, setHtmlInitial]   = useState("");
  const [smtpConfigured, setSmtpConfigured] = useState<boolean | null>(null);
  const [err, setErr]     = useState<string | null>(null);
  const [info, setInfo]   = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await api.cases.get(id);
      setC(data);
      // Reset the draft to the server's truth on every refresh
      setDraft({
        title: data.title || "",
        locale: data.locale || "en",
        incident_analysis:       data.incident_analysis || "",
        attack_type_label:       data.attack_type_label || "",
        critical_impact_summary: data.critical_impact_summary || "",
        actions_taken:           (data.actions_taken || []).join("\n"),
        recommended_actions:     (data.recommended_actions || []).join("\n"),
        threat_intel_summary:    data.threat_intel_summary || "",
      });
    } catch (e: any) {
      setErr(e.message);
    }
  }, [id]);

  useEffect(() => { refresh(); }, [refresh]);

  // Check SMTP configured once on mount — the Send button reflects this.
  useEffect(() => {
    api.cases.smtpStatus()
      .then(s => setSmtpConfigured(s.configured))
      .catch(() => setSmtpConfigured(false));
  }, []);

  // First-load auto-trigger: when the case loads and all customer-facing
  // fields are still empty (i.e. fresh case), fire the LLM once. Mutating the
  // sentinel object before the call prevents re-firing on subsequent refreshes.
  // IMPORTANT: must sit ABOVE the early return below, or React's hook-count
  // changes between renders and the component crashes.
  useEffect(() => {
    if (!c || autoTriedRef.done) return;
    if (c.status === "sent") return;
    const fieldsEmpty =
      !c.incident_analysis &&
      !c.attack_type_label &&
      !c.critical_impact_summary &&
      !c.threat_intel_summary &&
      (!c.recommended_actions || c.recommended_actions.length === 0);
    if (!fieldsEmpty || generating) return;

    autoTriedRef.done = true;
    setGenerating(true); setErr(null); setInfo(null);
    api.cases.generate(id)
      .then(() => { setInfo("Generated with LLM."); return refresh(); })
      .catch((e: any) => setErr(`LLM generation failed: ${e.message}`))
      .finally(() => setGenerating(false));
  }, [c]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!c || !draft) return <div className="text-muted">Loading…</div>;

  const readOnly = c.status === "sent";

  async function save() {
    setBusy(true); setErr(null); setInfo(null);
    try {
      // Convert the one-per-line textareas to lists.
      const toLines = (s: any) =>
        String(s || "").split("\n").map((x: string) => x.trim()).filter(Boolean);
      await api.cases.patch(id, {
        title: draft.title || null,
        locale: draft.locale,
        incident_analysis: draft.incident_analysis || null,
        attack_type_label: draft.attack_type_label || null,
        critical_impact_summary: draft.critical_impact_summary || null,
        actions_taken: toLines(draft.actions_taken),
        recommended_actions: toLines(draft.recommended_actions),
        threat_intel_summary: draft.threat_intel_summary || null,
      });
      setInfo("Saved.");
      await refresh();
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  async function transition(next: "draft" | "reviewed") {
    setBusy(true); setErr(null); setInfo(null);
    try {
      await api.cases.setStatus(id, next);
      await refresh();
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  async function regenerate() {
    const edited = c.body_source === "edited";
    if (edited && !window.confirm(
      "This case has manual HTML edits. Regenerating will discard them and rewrite the fields. Continue?"
    )) return;
    setGenerating(true); setErr(null); setInfo(null);
    try {
      await api.cases.generate(id, edited);
      setInfo("Generated with LLM.");
      await refresh();
    } catch (e: any) { setErr(`LLM generation failed: ${e.message}`); }
    finally          { setGenerating(false); }
  }

  async function openHtmlEditor() {
    setErr(null); setInfo(null);
    try {
      // previewHtml returns the current edited HTML if any, else the rendered notification.
      const html = await api.cases.previewHtml(id);
      setHtmlInitial(html);
      setHtmlEditOpen(true);
    } catch (e: any) { setErr(`Could not load HTML: ${e.message}`); }
  }

  async function saveHtml(html: string) {
    setBusy(true); setErr(null); setInfo(null);
    try {
      await api.cases.saveBody(id, html);
      setInfo("HTML saved — overrides the generated content until you regenerate.");
      setHtmlEditOpen(false);
      await refresh();
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  return (
    <div className="space-y-5">
      {/* Breadcrumb */}
      <div className="flex items-center gap-3 text-sm">
        <Link href="/cases" className="flex items-center gap-1 text-muted hover:text-accent">
          <ArrowLeft size={14}/> Cases
        </Link>
        <span className="text-muted">/</span>
        <span className="font-mono text-accent">{c.case_number}</span>
      </div>

      {/* Header card */}
      <div className="panel p-5">
        <div className="flex items-center gap-3 flex-wrap text-sm mb-2">
          <span className="font-mono text-accent">{c.case_number}</span>
          <span className={`${statusPill(c.status)} inline-flex items-center gap-1`}>
            {statusIcon(c.status)} {c.status}
          </span>
          <span className="text-muted text-xs uppercase font-mono">{c.locale}</span>
          {c.body_source === "edited" && (
            <span className="pill pill-medium inline-flex items-center gap-1"
                  title="The notification uses analyst-edited HTML; Regenerate will discard it.">
              <FileCode size={11}/> HTML edited
            </span>
          )}
          <span className="ml-auto text-muted text-xs">
            Created {new Date(c.created_at).toLocaleString()}
          </span>
        </div>
        <h1 className="text-xl font-semibold">
          {c.title || <span className="text-muted italic">untitled</span>}
        </h1>
        <div className="text-xs text-muted mt-2">
          For tenant <span className="font-mono text-text">{c.tenant_name || "—"}</span>
          {" · "}
          Source incident{" "}
          <Link href={`/incidents/${c.source_incident_id}`}
                className="font-mono text-accent hover:underline inline-flex items-center gap-0.5">
            {c.source_case_number} <ExternalLink size={10}/>
          </Link>
          {c.sent_at && (
            <> · Sent {new Date(c.sent_at).toLocaleString()} to{" "}
               <span className="font-mono text-text">{c.sent_recipients_to}</span></>
          )}
        </div>
      </div>

      {/* Action strip */}
      <div className="panel p-3 flex items-center gap-2 flex-wrap">
        {c.status === "draft" && (
          <button onClick={() => transition("reviewed")} disabled={busy}
                  className="pill pill-medium hover:brightness-125 inline-flex items-center gap-1">
            <CheckCircle2 size={12}/> Mark reviewed
          </button>
        )}
        {(c.status === "reviewed" || c.status === "sent") && (
          <button onClick={() => transition("draft")} disabled={busy}
                  className="pill pill-low hover:brightness-125 inline-flex items-center gap-1">
            <RotateCcw size={12}/> Re-open to draft
          </button>
        )}
        <span className="text-xs text-muted ml-2">
          {readOnly
            ? "Case has been sent — re-open to edit."
            : generating
              ? "Generating customer-facing content with the LLM…"
              : "Edit below, then save. Preview and send will land in later phases."}
        </span>
        <button onClick={() => setPreviewOpen(true)} disabled={generating}
                title="Show the customer-facing HTML preview."
                className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-line text-muted hover:border-accent hover:text-accent disabled:opacity-40 text-sm">
          <Eye size={14}/> Preview
        </button>
        <button onClick={openHtmlEditor} disabled={generating || readOnly}
                title="Edit the final notification HTML (WYSIWYG)."
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-line text-muted hover:border-accent hover:text-accent disabled:opacity-40 text-sm">
          <FileCode size={14}/> Edit HTML
        </button>
        <button onClick={regenerate} disabled={busy || generating || readOnly}
                title="Re-run the customer-facing LLM. Overwrites all six text fields."
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-line text-muted hover:border-accent hover:text-accent disabled:opacity-40 text-sm">
          {generating ? <Loader2 size={14} className="animate-spin"/> : <Sparkles size={14}/>}
          {generating ? "Generating…" : "Regenerate with LLM"}
        </button>
        <button onClick={save} disabled={busy || generating || readOnly}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40 text-sm">
          <Save size={14}/> Save changes
        </button>
        {c.status === "reviewed" && (
          <button onClick={() => setSendOpen(true)} disabled={busy || generating}
                  title={smtpConfigured === false
                    ? "SMTP not configured on this deployment"
                    : !c.tenant_notification_email
                      ? "This tenant has no notification_email — configure in Admin → Tenants"
                      : "Send the rendered HTML to the customer's configured address"}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-danger/10 border border-danger/40 text-danger hover:bg-danger/20 disabled:opacity-40 text-sm">
            <Send size={14}/> Send to customer
          </button>
        )}
      </div>
      {err  && <div className="text-sm text-danger border border-danger/40 bg-danger/10 rounded-md p-2">{err}</div>}
      {info && <div className="text-sm text-positive border border-positive/40 bg-positive/10 rounded-md p-2">{info}</div>}

      {/* Editor + attached incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2">
      <Panel title="Customer-facing content">
        <fieldset disabled={readOnly} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Field label="Title" hint="Headline customers see in the email subject and notification body.">
              <input
                value={draft.title}
                onChange={e => setDraft({...draft, title: e.target.value})}
                className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent"/>
            </Field>
            <Field label="Locale" hint="Language for the customer notification.">
              <select
                value={draft.locale}
                onChange={e => setDraft({...draft, locale: e.target.value})}
                className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent">
                {LOCALES.map(l => <option key={l} value={l}>{l}</option>)}
              </select>
            </Field>
            <Field label="Attack type label" hint="Short label, e.g. 'Command Injection Vulnerability'.">
              <input
                value={draft.attack_type_label}
                onChange={e => setDraft({...draft, attack_type_label: e.target.value})}
                className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent"/>
            </Field>
            <div/>
          </div>

          <Field label="Incident analysis (paragraph)"
                 hint="Plain-language summary of what happened — your customer's IT lead will read this.">
            <textarea
              value={draft.incident_analysis}
              onChange={e => setDraft({...draft, incident_analysis: e.target.value})}
              rows={6}
              className="w-full bg-base border border-line rounded-md p-3 text-sm focus:outline-none focus:border-accent"/>
          </Field>

          <Field label="Critical impact summary"
                 hint="The 'red banner' content. What's the worst-case if this isn't addressed?">
            <textarea
              value={draft.critical_impact_summary}
              onChange={e => setDraft({...draft, critical_impact_summary: e.target.value})}
              rows={4}
              className="w-full bg-base border border-line rounded-md p-3 text-sm focus:outline-none focus:border-accent"/>
          </Field>

          <Field label="Actions we took"
                 hint="One per line — what the SOC already DID for the customer (block/isolate/collect). Pre-filled from the analyst-approved response actions; regenerate after approving to refresh.">
            <textarea
              value={draft.actions_taken}
              onChange={e => setDraft({...draft, actions_taken: e.target.value})}
              rows={4}
              placeholder={"Blocked the malicious sender IP at the perimeter.\nIsolated the affected host from the network."}
              className="w-full bg-base border border-line rounded-md p-3 text-sm font-mono focus:outline-none focus:border-accent"/>
          </Field>

          <Field label="Recommended actions"
                 hint="One per line. Each line becomes a bullet in the customer notification.">
            <textarea
              value={draft.recommended_actions}
              onChange={e => setDraft({...draft, recommended_actions: e.target.value})}
              rows={5}
              placeholder={"Apply the patch from vendor X\nBlock IP Y at the perimeter firewall\nReview logs for the last 48h"}
              className="w-full bg-base border border-line rounded-md p-3 text-sm font-mono focus:outline-none focus:border-accent"/>
          </Field>

          <Field label="Threat intelligence summary"
                 hint="IOC context, attribution if any, prior cases — pitched at non-analysts.">
            <textarea
              value={draft.threat_intel_summary}
              onChange={e => setDraft({...draft, threat_intel_summary: e.target.value})}
              rows={4}
              className="w-full bg-base border border-line rounded-md p-3 text-sm focus:outline-none focus:border-accent"/>
          </Field>
        </fieldset>
      </Panel>
        </div>

        <div className="space-y-5">
          <AttachedIncidents
            caseId={id}
            attached={c.attached_incidents || []}
            sourceIncidentId={c.source_incident_id}
            readOnly={readOnly}
            onChange={refresh}
          />
          <CaseCollaboration caseId={id} />
        </div>
      </div>

      <PreviewModal caseId={id} open={previewOpen} onClose={() => setPreviewOpen(false)}/>
      <SendModal
        caseId={id}
        to={c.tenant_notification_email || ""}
        cc={c.tenant_notification_email_cc}
        subject={c.notification_subject || c.title || ""}
        smtpConfigured={smtpConfigured === true}
        tenantConfigured={!!c.tenant_notification_email}
        open={sendOpen}
        onClose={() => setSendOpen(false)}
        onSent={refresh}
      />
      {htmlEditOpen && (
        <HtmlEditModal
          initialHtml={htmlInitial}
          busy={busy}
          onSave={saveHtml}
          onClose={() => setHtmlEditOpen(false)}
        />
      )}
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <div className="text-[10px] uppercase tracking-wider text-muted mb-1">{label}</div>
      {children}
      {hint && <div className="text-[11px] text-muted mt-1">{hint}</div>}
    </label>
  );
}
