"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import {
  ChevronDown, ChevronRight, Copy, Check, AlertTriangle, Cpu, Loader2, Clock,
} from "lucide-react";

interface LLMCall {
  id: string;
  purpose: string | null;
  model: string;
  provider: string | null;
  status: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  latency_ms: number | null;
  prompt_hash: string | null;
  created_at: string | null;
  system_prompt: string | null;
  user_prompt: string | null;
  response_text: string | null;
  error: string | null;
}

const PURPOSE_LABEL: Record<string, string> = {
  analyst_fast:        "Fast classifier",
  analyst_deep:        "Deep synthesis",
  analyst_deep_forced: "Deep synthesis (analyst-forced)",
  customer_brief:      "Customer brief",
};

const PURPOSE_TONE: Record<string, string> = {
  analyst_fast:        "bg-accent2/10 border-accent2/40 text-accent2",
  analyst_deep:        "bg-accent/10 border-accent/40 text-accent",
  analyst_deep_forced: "bg-warning/10 border-warning/40 text-warning",
  customer_brief:      "bg-positive/10 border-positive/40 text-positive",
};

export function LLMCallsPanel({ incidentId }: { incidentId: string }) {
  const [calls, setCalls] = useState<LLMCall[] | null>(null);
  const [err, setErr]     = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setErr(null);
    api.getLLMCalls(incidentId)
       .then(r => { if (!cancelled) setCalls(r); })
       .catch((e: any) => { if (!cancelled) setErr(e.message || "Failed to load LLM calls"); });
    return () => { cancelled = true; };
  }, [incidentId]);

  if (err) {
    return (
      <Panel title="LLM Calls">
        <div className="text-sm text-danger border border-danger/40 bg-danger/10 rounded-md px-3 py-2">
          <AlertTriangle size={12} className="inline mr-1.5"/>{err}
          {err.toLowerCase().includes("forbidden") && (
            <p className="text-xs text-muted mt-2">
              Admin role required — prompts can include customer data and analyst reasoning.
            </p>
          )}
        </div>
      </Panel>
    );
  }

  if (calls === null) {
    return (
      <Panel title="LLM Calls">
        <div className="text-sm text-muted flex items-center gap-2">
          <Loader2 size={14} className="animate-spin"/> Loading…
        </div>
      </Panel>
    );
  }

  if (calls.length === 0) {
    return (
      <Panel title="LLM Calls">
        <p className="text-sm text-muted">
          No LLM calls recorded for this incident. (Either the pipeline short-circuited
          before any LLM ran, or transcript logging is disabled via{" "}
          <code className="font-mono text-accent">ISOC_LOG_LLM_TRANSCRIPTS=false</code>.)
        </p>
      </Panel>
    );
  }

  return (
    <Panel title="LLM Calls">
      <p className="text-xs text-muted mb-4 leading-relaxed">
        Full audit trail of every LLM call this incident triggered — system prompt,
        rendered briefing, and the model's response. Captured for GRC + debug.
        Use{" "}
        <code className="font-mono text-accent">ISOC_LOG_LLM_TRANSCRIPTS=false</code>
        {" "}to stop persisting prompt bodies (metadata is always kept).
      </p>
      <div className="space-y-3">
        {calls.map((c, idx) => (
          <LLMCallCard key={c.id} call={c} index={idx + 1}/>
        ))}
      </div>
    </Panel>
  );
}

function LLMCallCard({ call, index }: { call: LLMCall; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const purposeLabel = (call.purpose && PURPOSE_LABEL[call.purpose]) || call.purpose || "unknown";
  const purposeTone  = (call.purpose && PURPOSE_TONE[call.purpose])
                       || "bg-surface2/40 border-line text-muted";
  const isError      = call.status && call.status !== "ok";

  return (
    <div className="border border-line/60 rounded-md bg-base/40">
      <button onClick={()=>setExpanded(v=>!v)}
              className="w-full flex items-center gap-3 px-3 py-2.5 hover:bg-surface2/30 transition-colors text-left">
        {expanded ? <ChevronDown size={14} className="text-muted"/> : <ChevronRight size={14} className="text-muted"/>}
        <span className="font-mono text-xs text-muted w-6">#{index}</span>
        <span className={`px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider
                          rounded border ${purposeTone}`}>
          {purposeLabel}
        </span>
        <span className="text-sm text-text font-mono">{call.model}</span>
        {isError && (
          <span className="text-[10px] uppercase tracking-wider text-danger border border-danger/40 bg-danger/10 px-2 py-0.5 rounded">
            {call.status}
          </span>
        )}
        <div className="ml-auto flex items-center gap-4 text-xs text-muted">
          {typeof call.input_tokens === "number" && (
            <span className="flex items-center gap-1" title="input → output tokens">
              <Cpu size={12}/>
              <span className="font-mono">{call.input_tokens}→{call.output_tokens ?? "?"}</span>
            </span>
          )}
          {typeof call.latency_ms === "number" && (
            <span className="flex items-center gap-1" title="latency">
              <Clock size={12}/>
              <span className="font-mono">{(call.latency_ms / 1000).toFixed(1)}s</span>
            </span>
          )}
          {call.created_at && (
            <span className="font-mono hidden sm:inline">
              {new Date(call.created_at).toLocaleTimeString()}
            </span>
          )}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-line/60 px-3 py-3 space-y-3">
          {call.error && (
            <div className="text-sm text-danger border border-danger/40 bg-danger/10 rounded-md px-3 py-2">
              <AlertTriangle size={12} className="inline mr-1.5"/>{call.error}
            </div>
          )}
          <PromptBlock label="System prompt" body={call.system_prompt}/>
          <PromptBlock label="User prompt (rendered briefing)" body={call.user_prompt}/>
          <PromptBlock label="Response"      body={call.response_text}/>
          <div className="text-[10px] text-muted/70 flex flex-wrap gap-x-4 gap-y-1 pt-1">
            <span>prompt_hash: <code className="font-mono">{call.prompt_hash?.slice(0,12)}…</code></span>
            {call.provider && <span>provider: <code className="font-mono">{call.provider}</code></span>}
            <span>id: <code className="font-mono">{call.id}</code></span>
          </div>
        </div>
      )}
    </div>
  );
}

function PromptBlock({ label, body }: { label: string; body: string | null }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    if (!body) return;
    try { await navigator.clipboard.writeText(body); setCopied(true); setTimeout(()=>setCopied(false), 1500); }
    catch {}
  }
  if (body === null) {
    return (
      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted mb-1">{label}</div>
        <div className="text-xs text-muted/60 italic font-mono px-3 py-2 bg-base border border-line/60 rounded-md">
          not stored (transcript logging disabled)
        </div>
      </div>
    );
  }
  if (body === "") {
    return (
      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted mb-1">{label}</div>
        <div className="text-xs text-muted/60 italic font-mono px-3 py-2 bg-base border border-line/60 rounded-md">
          (empty)
        </div>
      </div>
    );
  }
  return (
    <div>
      <div className="flex items-center mb-1">
        <span className="text-[10px] uppercase tracking-wider text-muted">{label}</span>
        <button onClick={copy} className="ml-auto text-xs text-muted hover:text-accent inline-flex items-center gap-1">
          {copied ? <Check size={11} className="text-positive"/> : <Copy size={11}/>}
          {copied ? "copied" : "copy"}
        </button>
      </div>
      <pre className="text-[11px] font-mono text-text/90 bg-base border border-line/60 rounded-md
                      px-3 py-2 max-h-96 overflow-auto whitespace-pre-wrap break-words leading-relaxed">
        {body}
      </pre>
    </div>
  );
}
