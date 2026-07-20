"use client";

import { useEffect, useState } from "react";
import { Panel } from "@/components/ui/Panel";
import { TriageReport } from "@/components/forensics/TriageReport";
import { ForensicsReport } from "@/components/forensics/ForensicsReport";
import { FileTypeSelector, type FileTypeHint } from "@/components/forensics/FileTypeSelector";
import { api } from "@/lib/api";

type Tab = "triage" | "static";

export default function ForensicsPage() {
  const [tab, setTab] = useState<Tab>("triage");

  return (
    <div className="space-y-5">
      <div className="flex gap-6 border-b border-line text-sm">
        {(["triage","static"] as Tab[]).map(t => (
          <button key={t}
                  onClick={()=>setTab(t)}
                  className={`pb-2 -mb-px border-b-2 ${tab===t
                    ? "border-accent text-text"
                    : "border-transparent text-muted hover:text-text"}`}>
            {t === "triage" ? "Triage (fast lookup)" : "Static analysis (REMnux)"}
          </button>
        ))}
      </div>

      {tab === "triage" && <TriagePanel/>}
      {tab === "static" && <StaticPanel/>}
    </div>
  );
}

// ── Triage panel (unchanged, references existing TriageReport) ──────
function TriagePanel() {
  const [ioc, setIoc]   = useState("");
  const [type, setType] = useState("");
  const [job, setJob]   = useState<any>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      const j = await api.triage(ioc, type || undefined);
      setJob(j);
      const t = setInterval(async () => {
        const u = await api.getJob(j.id);
        setJob(u);
        if (u.status === "completed" || u.status === "failed") clearInterval(t);
      }, 1500);
    } finally { setBusy(false); }
  }

  return (
    <div className="grid md:grid-cols-3 gap-5">
      <Panel title="IOC lookup" className="md:col-span-1">
        <label className="block text-xs uppercase tracking-wider text-muted mb-1">IOC</label>
        <input value={ioc} onChange={e=>setIoc(e.target.value)}
               placeholder="IP / SHA256 / domain / URL"
               className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm font-mono focus:outline-none focus:border-accent/60"/>
        <label className="block text-xs uppercase tracking-wider text-muted mt-3 mb-1">Type (optional)</label>
        <select value={type} onChange={e=>setType(e.target.value)}
                className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm">
          <option value="">auto-detect</option>
          <option value="ip">ip</option>
          <option value="hash">hash</option>
          <option value="domain">domain</option>
          <option value="url">url</option>
        </select>
        <button onClick={run} disabled={busy || !ioc}
                className="mt-4 w-full px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
          {busy ? "Querying…" : "Run triage"}
        </button>
        <div className="mt-3 text-xs text-muted leading-relaxed">
          Runs <code>triage.py</code> against MalwareBazaar, ThreatFox, URLhaus, VirusTotal, AbuseIPDB, OTX.
          Cached for 5 minutes per IOC.
        </div>
      </Panel>

      <div className="md:col-span-2 space-y-3">
        {!job && <Panel title="Result"><div className="text-sm text-muted">Submit an IOC to see results.</div></Panel>}
        {job && job.status !== "completed" && (
          <Panel title="Result">
            <div className="text-sm">
              Job <span className="font-mono text-accent">{job.id.slice(0,8)}</span> — status <b>{job.status}</b>
              {job.status === "queued"  && <span className="text-muted"> · waiting for worker</span>}
              {job.status === "running" && <span className="text-muted"> · querying sources in parallel</span>}
            </div>
            {job.error && <div className="mt-3 text-sm text-danger">{job.error}</div>}
          </Panel>
        )}
        {job && job.status === "completed" && <TriageReport data={job.result}/>}
        {job && job.status === "failed" && (
          <Panel title="Result"><div className="text-sm text-danger">Job failed: {job.error || "no detail"}</div></Panel>
        )}
      </div>
    </div>
  );
}

// ── Static panel — file-type-aware tool wave + LLM synthesis ───────
function StaticPanel() {
  return (
    <ForensicsJobPanel
      endpoint="/forensics/static"
      kind="static"
      verb="Upload & analyze"
      typeSelector
      description={
        <>
          Runs a <b>file-type-aware</b> static tool wave on the uploaded artifact.
          Auto-detects whether the file is PE / Office / PDF / ELF / script / archive and
          dispatches the right tools (e.g. olevba+oledump for Office docs, pdfid+pdf-parser
          for PDFs, peframe+capa+pescan for PEs). Use the type chips below to override
          auto-detect. Hash is auto-triaged against VT/MalwareBazaar/ThreatFox in
          parallel. Results are synthesized by the LLM into a verdict (LOW / MEDIUM /
          HIGH / CRITICAL).
        </>
      }
      Renderer={ForensicsReport}
    />
  );
}


// ── Shared panel: upload → enqueue → poll → render + recent runs ────
// Static-only since dynamic was removed. The shape is preserved so we can
// re-introduce a parallel kind later (e.g. an external-sandbox path that
// hands off to Hybrid Analysis / any.run) without a big rewrite.
function ForensicsJobPanel({ endpoint, verb, typeSelector, description, Renderer, kind }:{
  endpoint: string;
  verb: string;
  typeSelector?: boolean;
  description: React.ReactNode;
  Renderer: React.ComponentType<{ jobId: string; data: any }>;
  kind: "static";
}) {
  const [file, setFile] = useState<File|null>(null);
  const [typeHint, setTypeHint] = useState<FileTypeHint>(null);
  const [busy, setBusy] = useState(false);
  const [job, setJob] = useState<any>(null);
  const [pollErr, setPollErr] = useState<string|null>(null);

  // Recent runs list — all jobs of this kind, scoped per backend.
  const [recent, setRecent] = useState<any[]>([]);
  const [recentErr, setRecentErr] = useState<string|null>(null);

  async function refreshRecent() {
    try {
      const list = await api.listJobs(kind);
      setRecent(list);
      setRecentErr(null);
    } catch (e: any) {
      setRecentErr(e?.message || "load failed");
    }
  }

  useEffect(() => { refreshRecent(); }, [kind]);

  // Re-refresh recent list whenever any tracked job transitions, so users
  // see verdicts update on the sidebar without manual reload.
  useEffect(() => {
    if (job?.status === "completed" || job?.status === "failed") {
      refreshRecent();
    }
  }, [job?.status]);

  // Polling lifecycle. Tied to job.id so a fresh submission cancels prior polls.
  useEffect(() => {
    if (!job?.id) return;
    if (job.status === "completed" || job.status === "failed") return;
    let cancelled = false;
    const tick = async () => {
      try {
        const u = await api.getJob(job.id);
        if (cancelled) return;
        setJob(u);
        if (u.status !== "completed" && u.status !== "failed") setTimeout(tick, 2000);
      } catch (e: any) {
        if (!cancelled) {
          setPollErr(e?.message || "poll failed");
          setTimeout(tick, 5000);
        }
      }
    };
    tick();
    return () => { cancelled = true; };
  }, [job?.id, job?.status]);

  async function submit() {
    if (!file) return;
    setBusy(true);
    setPollErr(null);
    const fd = new FormData();
    fd.append("file", file);
    const qs = new URLSearchParams();
    if (typeHint) qs.set("file_type_hint", typeHint);
    const url = `${process.env.NEXT_PUBLIC_API_BASE ?? "/api"}/v1${endpoint}${qs.toString() ? `?${qs.toString()}` : ""}`;
    const t = window.localStorage.getItem("isoc.token");
    const r = await fetch(url, {
      method: "POST",
      body: fd,
      headers: t ? { Authorization: `Bearer ${t}` } : {},
    });
    setBusy(false);
    if (r.ok) {
      setJob(await r.json());
      refreshRecent();
    } else {
      setJob({ error: await r.text(), status: "failed" });
    }
  }

  async function openPastJob(id: string) {
    setPollErr(null);
    setBusy(true);
    try {
      const u = await api.getJob(id);
      setJob(u);
    } catch (e: any) {
      setPollErr(e?.message || "open failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      {/* Top row: upload (1/3) + recent runs (2/3) */}
      <div className="grid md:grid-cols-3 gap-5">
        {/* Upload card */}
        <Panel title="Static upload" className="md:col-span-1">
          <p className="text-xs text-muted leading-relaxed">{description}</p>
          <div className="mt-4 space-y-3">
            <input type="file" onChange={e => setFile(e.target.files?.[0] || null)}
                   className="text-sm file:mr-3 file:px-3 file:py-1.5 file:rounded-md file:border-0 file:bg-accent/10 file:text-accent file:hover:bg-accent/20"/>
            {typeSelector && (
              <FileTypeSelector value={typeHint} onChange={setTypeHint}/>
            )}
            <button onClick={submit} disabled={!file || busy}
                    className="px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40 w-full">
              {busy ? "Uploading…" : verb}
            </button>
            {file && (
              <div className="text-[11px] text-muted font-mono break-all">
                {file.name} · {(file.size / 1024).toFixed(1)} KB
              </div>
            )}
          </div>
        </Panel>

        {/* Recent runs list */}
        <Panel title={`Recent ${kind} runs (${recent.length})`} className="md:col-span-2">
          <RecentRunsList
            jobs={recent}
            selectedId={job?.id}
            error={recentErr}
            onSelect={openPastJob}
            onRefresh={refreshRecent}
          />
        </Panel>
      </div>

      {/* Bottom: selected/just-submitted result, full width */}
      {!job && (
        <Panel title="Result">
          <div className="text-sm text-muted">Upload a new sample or pick a past run above.</div>
        </Panel>
      )}
      {job && job.status && job.status !== "completed" && job.status !== "failed" && (
        <Panel title="Result">
          <div className="text-sm">
            Job <span className="font-mono text-accent">{(job.id || "").slice(0,8)}</span> —{" "}
            <b>{job.status}</b>
            {job.status === "queued"  && <span className="text-muted"> · waiting for worker</span>}
            {job.status === "running" && <span className="text-muted"> · running tool wave + LLM synthesis</span>}
          </div>
          <ProgressBar status={job.status}/>
          {pollErr && <div className="text-xs text-warning mt-2">poll: {pollErr}</div>}
        </Panel>
      )}
      {job && job.status === "failed" && (
        <Panel title="Result" className="border-danger/40">
          <div className="text-sm text-danger">Job failed: {job.error || "no detail"}</div>
        </Panel>
      )}
      {job && job.status === "completed" && job.result && (
        <Renderer jobId={job.id} data={job.result}/>
      )}
    </div>
  );
}

// ── Recent runs list (used by the Static panel) ─────────────────────
function RecentRunsList({ jobs, selectedId, error, onSelect, onRefresh }:{
  jobs: any[];
  selectedId?: string | null;
  error: string | null;
  onSelect: (id: string) => void;
  onRefresh: () => void;
}) {
  if (error) return (
    <div className="text-sm text-danger">
      Failed to load past runs: {error}
      <button onClick={onRefresh} className="ml-2 underline">retry</button>
    </div>
  );
  if (jobs.length === 0) return (
    <div className="text-sm text-muted">
      No prior runs yet. Submit a file to start.
    </div>
  );
  return (
    <ul className="divide-y divide-line/60 max-h-[40vh] overflow-y-auto -mx-1">
      {jobs.map(j => {
        const fname = shortFile(j.ioc_or_file);
        const verdict = j.result?.synthesis?.verdict;
        const fileType = j.result?._file_type;
        const dt = (j.finished_at || j.started_at || j.created_at || "").slice(0, 19).replace("T", " ");
        const isSelected = selectedId === j.id;
        return (
          <li key={j.id}
              onClick={() => onSelect(j.id)}
              className={`py-2 px-2 cursor-pointer rounded-md transition-colors ${
                isSelected ? "bg-surface" : "hover:bg-surface/60"
              }`}>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-mono text-text truncate max-w-[55%]" title={fname}>
                {fname}
              </span>
              <StatusPill status={j.status}/>
              {verdict && <VerdictBadge verdict={verdict}/>}
              {fileType && fileType !== "unknown" && (
                <span className="text-[9px] text-muted font-mono opacity-70">{fileType}</span>
              )}
              {j.incident_id && (
                <span className="text-[9px] text-accent2 opacity-70">attached</span>
              )}
            </div>
            <div className="text-[10px] text-muted mt-0.5 font-mono">
              {dt} · {String(j.id).slice(0, 8)}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

// ── tiny shared bits (mirrored from IncidentForensicsPanel) ──────────
function StatusPill({ status }: { status: string }) {
  const k =
    status === "completed" ? "pill-resolved" :
    status === "failed"    ? "pill-critical" :
    status === "running"   ? "pill-high"     :
    "pill-low";
  return <span className={`pill text-[10px] ${k}`}>{status}</span>;
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const v = String(verdict).toUpperCase();
  const k =
    v === "CRITICAL" || v === "HIGH" ? "pill-critical" :
    v === "MEDIUM" ? "pill-high" :
    v === "LOW"    ? "pill-resolved" :
    "pill-low";
  return <span className={`pill text-[10px] ${k}`}>{v}</span>;
}

function shortFile(p: string) {
  const parts = String(p || "").split("/");
  return parts[parts.length - 1] || p;
}

function ProgressBar({ status }: { status: string }) {
  const pct = status === "queued" ? 15 : status === "running" ? 60 : 100;
  return (
    <div className="mt-3 h-1 rounded-full bg-surface2 overflow-hidden">
      <div className="h-1 bg-accent transition-all" style={{ width: `${pct}%` }}/>
    </div>
  );
}
