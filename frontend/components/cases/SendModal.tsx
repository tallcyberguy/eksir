"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { X, Send, Loader2, AlertTriangle, CheckCircle2 } from "lucide-react";

interface Props {
  caseId: string;
  to: string;            // tenant.notification_email
  cc: string | null;     // tenant.notification_email_cc (comma-separated)
  subject: string;       // = title or source incident title
  smtpConfigured: boolean;
  tenantConfigured: boolean;   // notification_email present
  open: boolean;
  onClose: () => void;
  onSent: () => void;
}

export function SendModal({
  caseId, to, cc, subject, smtpConfigured, tenantConfigured, open, onClose, onSent,
}: Props) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [subj, setSubj] = useState(subject);
  // Reset to the derived subject whenever the modal (re)opens for a case.
  useEffect(() => { if (open) setSubj(subject); }, [open, subject]);

  if (!open) return null;

  const canSend = smtpConfigured && tenantConfigured && !busy && subj.trim().length > 0;
  const blockReason = !smtpConfigured
    ? "SMTP is not configured on this deployment — set SMTP_HOST in the backend .env."
    : !tenantConfigured
      ? "This tenant has no notification_email — set one in Admin → Tenants."
      : null;

  async function doSend() {
    setBusy(true); setErr(null);
    try {
      await api.cases.send(caseId, subj.trim());
      onSent();
      onClose();
    } catch (e: any) {
      setErr(e.message);
    } finally { setBusy(false); }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="bg-surface border border-line rounded-xl shadow-cyber w-full max-w-lg p-6 space-y-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-2">
          <Send size={16} className="text-accent"/>
          <h3 className="text-text font-semibold">Send to customer</h3>
          <button onClick={onClose} className="ml-auto text-muted hover:text-text" title="Close (Esc)">
            <X size={16}/>
          </button>
        </div>

        {blockReason && (
          <div className="flex gap-2 items-start p-3 rounded-md border border-warning/40 bg-warning/10 text-warning text-sm">
            <AlertTriangle size={14} className="shrink-0 mt-0.5"/>
            <span>{blockReason}</span>
          </div>
        )}

        <p className="text-xs text-muted">
          Recipients are derived from the tenant configuration — change them under <code className="font-mono text-accent">Admin → Tenants</code>. The subject is prefilled; edit it below if needed.
        </p>

        {/* Locked recipients; editable subject */}
        <Field label="To">{to || <em className="text-muted/60">unset</em>}</Field>
        <Field label="Cc">{cc || <em className="text-muted/60">(none)</em>}</Field>
        <div className="grid grid-cols-[60px_1fr] gap-3 items-center">
          <span className="text-[10px] uppercase tracking-wider text-muted">Subject</span>
          <input
            value={subj}
            onChange={e => setSubj(e.target.value)}
            spellCheck={false}
            placeholder="Email subject"
            className="font-mono text-sm text-text border border-line/60 bg-base rounded-md px-2 py-1 w-full focus:border-accent focus:outline-none"
          />
        </div>

        {err && <p className="text-sm text-danger">{err}</p>}

        <div className="flex gap-3 justify-end pt-2">
          <button onClick={onClose} className="px-4 py-1.5 text-sm text-muted border border-line rounded-md hover:border-accent">
            Cancel
          </button>
          <button onClick={doSend} disabled={!canSend}
                  className="flex items-center gap-1.5 px-4 py-1.5 text-sm rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
            {busy ? <Loader2 size={14} className="animate-spin"/> : <CheckCircle2 size={14}/>}
            {busy ? "Sending…" : "Confirm & send"}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[60px_1fr] gap-3 items-baseline">
      <span className="text-[10px] uppercase tracking-wider text-muted">{label}</span>
      <div className="font-mono text-sm text-text border border-line/60 bg-base rounded-md px-2 py-1 truncate" title={typeof children === "string" ? children : undefined}>
        {children}
      </div>
    </div>
  );
}
