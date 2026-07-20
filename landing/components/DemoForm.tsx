"use client";

import { useState } from "react";
import { Loader2, CheckCircle2, AlertTriangle, ArrowRight } from "lucide-react";

type Status = "idle" | "sending" | "ok" | "err";

export function DemoForm() {
  const [status, setStatus] = useState<Status>("idle");
  const [err, setErr] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setStatus("sending"); setErr(null);

    const fd = new FormData(e.currentTarget);
    const payload = {
      name:    String(fd.get("name") || "").trim(),
      email:   String(fd.get("email") || "").trim(),
      company: String(fd.get("company") || "").trim(),
      role:    String(fd.get("role") || "").trim(),
      message: String(fd.get("message") || "").trim(),
      // Honeypot — bots fill every field. If this is non-empty, server drops it silently.
      website: String(fd.get("website") || ""),
    };

    try {
      const r = await fetch("/api/demo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        throw new Error(body.error || `Request failed (${r.status})`);
      }
      setStatus("ok");
    } catch (e: any) {
      setStatus("err");
      setErr(e.message || "Something went wrong.");
    }
  }

  if (status === "ok") {
    return (
      <div className="panel p-8 text-center">
        <CheckCircle2 size={36} className="text-positive mx-auto mb-3"/>
        <h2 className="text-xl font-semibold text-text">Got it — talk soon.</h2>
        <p className="text-muted mt-2 max-w-md mx-auto">
          We'll be in touch within one business day to schedule your walkthrough.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} className="panel p-7 space-y-5">
      <div className="grid sm:grid-cols-2 gap-4">
        <Field label="Full name"  name="name"    required autoComplete="name"/>
        <Field label="Work email" name="email"   required type="email" autoComplete="email"/>
        <Field label="Company"    name="company" required autoComplete="organization"/>
        <Field label="Role"       name="role"             autoComplete="organization-title"
               placeholder="SOC manager, Analyst…"/>
      </div>

      <div>
        <label className="text-xs uppercase tracking-wider text-muted">What would you like to see?</label>
        <textarea name="message" rows={4}
                  placeholder="Tell us about your stack or a workflow you'd like to walk through."
                  className="mt-1 w-full bg-base border border-line rounded-md px-3 py-2 text-sm text-text
                             focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40
                             placeholder:text-muted/50"/>
      </div>

      {/* Honeypot — visually hidden, ignored by humans, filled by bots. */}
      <input type="text" name="website" tabIndex={-1} autoComplete="off"
             className="hidden" aria-hidden="true"/>

      {status === "err" && err && (
        <div className="flex gap-2 items-start p-3 rounded-md border border-danger/40 bg-danger/10 text-danger text-sm">
          <AlertTriangle size={14} className="shrink-0 mt-0.5"/>
          <span>{err}</span>
        </div>
      )}

      <button type="submit" disabled={status === "sending"}
              className="btn btn-primary w-full sm:w-auto">
        {status === "sending"
          ? <><Loader2 size={16} className="animate-spin"/> Sending…</>
          : <>Request demo <ArrowRight size={16}/></>}
      </button>

      <p className="text-xs text-muted/70">
        By submitting, you agree we may email you about EKSIR. We won't share your details.
      </p>
    </form>
  );
}

function Field(props: React.InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const { label, ...rest } = props;
  return (
    <div>
      <label className="text-xs uppercase tracking-wider text-muted">{label}</label>
      <input {...rest}
             className="mt-1 w-full bg-base border border-line rounded-md px-3 py-2 text-sm text-text
                        focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40
                        placeholder:text-muted/50"/>
    </div>
  );
}
