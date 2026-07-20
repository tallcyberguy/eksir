"use client";

import { useEffect, useState } from "react";
import { Panel } from "@/components/ui/Panel";
import { ForensicsReport } from "@/components/forensics/ForensicsReport";
import { FileTypeSelector, type FileTypeHint } from "@/components/forensics/FileTypeSelector";
import { api } from "@/lib/api";
import { Play, FileWarning, Activity, Download } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Incident-scoped forensics panel.
 *
 *  - Lists all forensics jobs tied to this incident (most recent first).
 *  - Provides upload + enqueue forms for STATIC and DYNAMIC scoped to the incident
 *    (incident_id is passed so the job's IOCs/verdict flow back into the incident's
 *    enrichment via the worker's `_attach_to_incident` step).
 *  - Auto-opens the most recent completed job in a detail view.
 */
export function IncidentForensicsPanel({ incidentId }: { incidentId: string }) {
  const [jobs, setJobs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<any|null>(null);
  const [error, setError] = useState<string|null>(null);

  async function refresh() {
    try {
      const list = await api.listJobs(undefined, incidentId);
      setJobs(list);
      // Auto-select most recent completed job if nothing currently selected
      const newest = list.find(j => j.status === "completed");
      if (!selected && newest) setSelected(newest);
      setError(null);
    } catch (e: any) {
      setError(e?.message || "load failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { refresh(); /* eslint-disable-next-line */ }, [incidentId]);

  // Poll while any job is queued/running
  useEffect(() => {
    if (!jobs.some(j => j.status === "queued" || j.status === "running")) return;
    const t = setInterval(refresh, 2500);
    return () => clearInterval(t);
  }, [jobs]);

  return (
    <div className="space-y-5">
      <div className="grid md:grid-cols-3 gap-5">
        <Panel title="Run forensics" className="md:col-span-1">
          <p className="text-xs text-muted leading-relaxed mb-3">
            Upload a file artifact for static analysis. Results are attached to
            this incident automatically — extracted IOCs and the LLM verdict
            flow into the incident's enrichment.
          </p>
          <RunForm incidentId={incidentId} onSubmitted={refresh}/>
        </Panel>

        <Panel title={`Prior runs (${jobs.length})`} className="md:col-span-2">
          {loading && <div className="text-sm text-muted">Loading…</div>}
          {error   && <div className="text-sm text-danger">Failed to load: {error}</div>}
          {!loading && !error && jobs.length === 0 && (
            <div className="text-sm text-muted">No forensics runs attached to this incident yet.</div>
          )}
          {!loading && !error && jobs.length > 0 && (
            <ul className="divide-y divide-line/60">
              {jobs.map(j => (
                <li key={j.id}
                    className={cn("py-2 px-1 cursor-pointer hover:bg-surface/60 -mx-1 rounded-md",
                                  selected?.id === j.id && "bg-surface")}
                    onClick={() => setSelected(j)}>
                  <div className="flex items-center gap-3">
                    <KindIcon kind={j.kind}/>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-mono text-text">{shortFile(j.ioc_or_file)}</span>
                        <StatusPill status={j.status}/>
                        {j.result?.synthesis?.verdict && (
                          <VerdictBadge verdict={j.result.synthesis.verdict}/>
                        )}
                      </div>
                      <div className="text-[10px] text-muted mt-0.5">
                        {(j.finished_at || j.started_at || j.id).slice(0,19).replace("T", " ")}
                        {" · "}
                        <span className="font-mono">{j.id.slice(0,8)}</span>
                      </div>
                    </div>
                    {j.status === "completed" && (
                      <a href={api.reportMarkdownUrl(j.id)} target="_blank" rel="noopener"
                         onClick={e => e.stopPropagation()}
                         className="text-muted hover:text-accent">
                        <Download size={14}/>
                      </a>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      {/* Selected job detail */}
      {selected && selected.status === "completed" && selected.result && (
        <div>
          {selected.kind === "static" && <ForensicsReport jobId={selected.id} data={selected.result}/>}
          {selected.kind === "triage" && (
            <Panel title="Triage result">
              <pre className="text-[11px] font-mono overflow-x-auto max-h-[60vh]">{JSON.stringify(selected.result, null, 2)}</pre>
            </Panel>
          )}
          {selected.kind === "dynamic" && (
            <Panel title="Dynamic analysis (historical)" className="border-warning/40">
              <div className="text-sm text-warning mb-2">
                This job ran under the legacy in-platform sandbox, which has been
                removed for safety. The result is shown read-only from the JSONB
                column. Future dynamic analyses will use an external sandbox
                (Hybrid Analysis / any.run / Triage).
              </div>
              <pre className="text-[11px] font-mono overflow-x-auto max-h-[60vh]">{JSON.stringify(selected.result, null, 2)}</pre>
            </Panel>
          )}
        </div>
      )}
      {selected && selected.status === "failed" && (
        <Panel title="Job failed" className="border-danger/40">
          <div className="text-sm text-danger">{selected.error || "no detail"}</div>
        </Panel>
      )}
    </div>
  );
}


function RunForm({ incidentId, onSubmitted }: { incidentId: string; onSubmitted: () => void }) {
  const [file, setFile]      = useState<File|null>(null);
  const [typeHint, setTypeH] = useState<FileTypeHint>(null);
  const [busy, setBusy]      = useState(false);
  const [err, setErr]        = useState<string|null>(null);

  async function submit() {
    if (!file) return;
    setBusy(true);
    setErr(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const qs = new URLSearchParams({ incident_id: incidentId });
      if (typeHint) qs.set("file_type_hint", typeHint);
      const url = `${process.env.NEXT_PUBLIC_API_BASE ?? "/api"}/v1/forensics/static?${qs.toString()}`;
      const t = window.localStorage.getItem("isoc.token");
      const r = await fetch(url, {
        method: "POST",
        body: fd,
        headers: t ? { Authorization: `Bearer ${t}` } : {},
      });
      if (!r.ok) { setErr(await r.text()); return; }
      setFile(null);
      onSubmitted();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <input type="file" onChange={e => setFile(e.target.files?.[0] || null)}
             className="text-xs file:mr-2 file:px-2.5 file:py-1 file:rounded-md file:border-0 file:bg-accent/10 file:text-accent file:hover:bg-accent/20 w-full"/>
      <FileTypeSelector value={typeHint} onChange={setTypeH} compact/>
      <button onClick={submit} disabled={!file || busy}
              className="w-full px-3 py-1.5 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40 inline-flex items-center justify-center gap-1.5">
        <Play size={12}/> {busy ? "Submitting…" : "Run static analysis"}
      </button>
      {err && <div className="text-xs text-danger">{err}</div>}
    </div>
  );
}

function KindIcon({ kind }: { kind: string }) {
  if (kind === "static")  return <FileWarning size={14} className="text-warning shrink-0"/>;
  if (kind === "dynamic") return <Activity    size={14} className="text-danger shrink-0"/>;
  return <span className="w-3.5 h-3.5 rounded-full bg-muted/30 shrink-0"/>;
}

function StatusPill({ status }: { status: string }) {
  const k =
    status === "completed" ? "pill-resolved" :
    status === "failed"    ? "pill-critical" :
    status === "running"   ? "pill-high"     :
    "pill-low";
  return <span className={cn("pill text-[10px]", k)}>{status}</span>;
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const v = String(verdict).toUpperCase();
  const k =
    v === "CRITICAL" || v === "HIGH" ? "pill-critical" :
    v === "MEDIUM" ? "pill-high" :
    v === "LOW"    ? "pill-resolved" :
    "pill-low";
  return <span className={cn("pill text-[10px]", k)}>{v}</span>;
}

function shortFile(p: string) {
  const parts = String(p || "").split("/");
  return parts[parts.length - 1] || p;
}
