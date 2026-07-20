"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import useSWR from "@/lib/swr-shim";
import { api, type BatchImportJob, type BatchImportPreview } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import {
  Loader2, Plus, Trash2, RefreshCw, AlertTriangle, CheckCircle2,
  PlayCircle, PauseCircle, FlaskConical, RadioTower,
  Upload, FileUp, ListChecks, Ban, CheckCircle,
} from "lucide-react";

type Source = {
  id: string; provider: string; label: string; identifier: string; customer: string | null;
  enabled: boolean; interval_seconds: number; min_severity: string | null; max_items: number;
  consecutive_errors: number; last_error: string | null;
  health?: string; stale?: boolean;
  last_poll_ms?: number | null; last_poll_count?: number | null; total_ingested?: number;
  last_poll_at: string | null; last_success_at: string | null; created_at: string | null;
};

const HEALTH_STYLE: Record<string, string> = {
  ok: "text-positive", error: "text-danger", stale: "text-warning",
  pending: "text-muted", disabled: "text-muted",
};
type Provider = {
  key: string; label: string; identifier_label: string; region_options: string[];
};

const SEVERITIES = ["", "low", "medium", "high", "critical"];

function ago(iso: string | null): string {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function AddForm({ providers, onAdded }: { providers: Provider[]; onAdded: () => void }) {
  const connectorsSWR = useSWR<{ connectors: any[] }>(
    "admin:connectors-for-sources", api.connectors.list);
  const [provider, setProvider] = useState(providers[0]?.key ?? "");

  // Credential rows already saved in the Connectors tab for the chosen provider.
  const credRows = useMemo(
    () => (connectorsSWR.data?.connectors ?? []).filter((c: any) => c.provider === provider),
    [connectorsSWR.data, provider]);
  const credOptions = useMemo(() => {
    const opts = credRows.map((c: any) => ({
      value: c.identifier as string,
      label: `${c.identifier}${c.region ? ` · ${c.region}` : ""}`
        + `${c.has_key ? "" : " · no key"}${c.enabled ? "" : " · disabled"}`,
    }));
    if (!opts.some((o) => o.value === "default")) {
      opts.push({ value: "default", label: "default (global / env key)" });
    }
    return opts;
  }, [credRows]);

  const [identifier, setIdentifier] = useState("default");
  const [customer, setCustomer] = useState("");
  const [interval, setIntervalSec] = useState(300);
  const [minSeverity, setMinSeverity] = useState("");
  const [maxItems, setMaxItems] = useState(100);
  const [enabled, setEnabled] = useState(false);
  const [fieldMapText, setFieldMapText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [warn, setWarn] = useState<string | null>(null);

  // Default the credential to the provider's first saved row (or "default").
  useEffect(() => {
    setIdentifier(credRows[0]?.identifier ?? "default");
  }, [provider, credRows.length]); // eslint-disable-line react-hooks/exhaustive-deps

  async function add() {
    let fieldMap: Record<string, string> | null = null;
    if (fieldMapText.trim()) {
      try { fieldMap = JSON.parse(fieldMapText); }
      catch { setErr("Field mapping must be valid JSON"); return; }
    }
    setBusy(true); setErr(null); setWarn(null);
    try {
      const res: any = await api.connectors.sources.create({
        provider,
        identifier: identifier.trim() || "default",
        customer: customer.trim() || null,
        interval_seconds: interval,
        min_severity: minSeverity || null,
        max_items: maxItems,
        enabled,
        field_map: fieldMap,
      });
      if (res?.credentials_found === false) {
        setWarn(`Source created, but no credentials resolved for ${provider}/${identifier}. `
          + `Add them in the Connectors tab (the identifier must match).`);
      }
      setCustomer(""); setMinSeverity(""); setEnabled(false); setFieldMapText("");
      onAdded();
    } catch (e: any) {
      setErr(e?.message ?? "failed to add source");
    } finally {
      setBusy(false);
    }
  }

  if (providers.length === 0) {
    return (
      <Panel title="Add a source">
        <div className="text-sm text-muted py-2">
          No pull-capable connectors yet. A provider appears here once it has a live ingestion adapter.
        </div>
      </Panel>
    );
  }

  return (
    <Panel title="Add a source">
      <div className="grid sm:grid-cols-2 gap-3">
        <label className="text-xs text-muted">
          Connector
          <select value={provider} onChange={(e) => setProvider(e.target.value)}
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text">
            {providers.map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}
          </select>
        </label>
        <label className="text-xs text-muted">
          Credentials <span className="opacity-60">(from the Connectors tab — no key entered here)</span>
          <select value={identifier} onChange={(e) => setIdentifier(e.target.value)}
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text">
            {credOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          {credRows.length === 0 && (
            <span className="mt-1 block text-[11px] text-warning">
              No saved credentials for this connector — add them under <b>Connectors</b> first, or use “default”.
            </span>
          )}
        </label>
        <label className="text-xs text-muted">
          Attribute incidents to customer <span className="opacity-60">(optional — tenant tag)</span>
          <input value={customer} onChange={(e) => setCustomer(e.target.value)}
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text" />
        </label>
        <label className="text-xs text-muted">
          Poll interval (seconds)
          <input type="number" min={30} max={86400} value={interval}
            onChange={(e) => setIntervalSec(Number(e.target.value))}
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text font-mono" />
        </label>
        <label className="text-xs text-muted">
          Minimum severity <span className="opacity-60">(floor — drops below)</span>
          <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text">
            {SEVERITIES.map((s) => <option key={s} value={s}>{s || "none (all severities)"}</option>)}
          </select>
        </label>
        <label className="text-xs text-muted">
          Max items per poll
          <input type="number" min={1} max={1000} value={maxItems}
            onChange={(e) => setMaxItems(Number(e.target.value))}
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text font-mono" />
        </label>
        <label className="text-xs text-muted sm:col-span-2">
          Field mapping <span className="opacity-60">(optional JSON — only for sources without a built-in parser)</span>
          <textarea value={fieldMapText} onChange={(e) => setFieldMapText(e.target.value)} rows={3}
            placeholder='{"rule_name":"rule.name","severity":"event.severity","src_ip":"source.ip","hostname":"host.name"}'
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-xs text-text font-mono" />
        </label>
      </div>
      <div className="flex items-center justify-between mt-3">
        <label className="text-xs text-muted flex items-center gap-1.5">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enable immediately
        </label>
        <div className="flex items-center gap-3">
          {err && <span className="text-xs text-danger">{err}</span>}
          <button onClick={add} disabled={busy}
            className="btn btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50">
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />} Add source
          </button>
        </div>
      </div>
      {warn && (
        <div className="mt-2 flex items-start gap-1.5 text-[11px] text-warning">
          <AlertTriangle size={12} className="mt-0.5 shrink-0" /> <span>{warn}</span>
        </div>
      )}
    </Panel>
  );
}

function PreviewPanel() {
  const [raw, setRaw] = useState("");
  const [fieldMapText, setFieldMapText] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<{ detected_source: string; normalized: any } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function run() {
    let fieldMap: Record<string, string> | null = null;
    if (fieldMapText.trim()) {
      try { fieldMap = JSON.parse(fieldMapText); }
      catch { setErr("Field mapping must be valid JSON"); return; }
    }
    setBusy(true); setErr(null); setRes(null);
    let payload: unknown = raw;
    try { payload = JSON.parse(raw); } catch { /* not JSON — send as text */ }
    try {
      setRes(await api.connectors.sources.preview(payload, null, fieldMap));
    } catch (e: any) {
      setErr(e?.message ?? "preview failed");
    } finally {
      setBusy(false);
    }
  }

  const n = res?.normalized ?? {};
  const FIELDS: [string, any][] = [
    ["source", res?.detected_source], ["rule_name", n.rule_name], ["severity", n.severity_label],
    ["hostname", n.hostname], ["username", n.username], ["src_ip", n.src_ip],
    ["mitre", n.mitre_technique], ["category", n.threat_category],
  ];

  return (
    <Panel title="Preview normalization (read-only)">
      <p className="text-xs text-muted mb-2">
        Paste one raw alert (JSON or text) to see how it normalizes before enabling a source.
        Creates no incident.
      </p>
      <textarea value={raw} onChange={(e) => setRaw(e.target.value)} rows={5}
        placeholder='{"id":"WB-...","model":"...","severity":"high", ...}'
        className="w-full bg-surface border border-line rounded px-2 py-1 text-xs text-text font-mono" />
      <textarea value={fieldMapText} onChange={(e) => setFieldMapText(e.target.value)} rows={2}
        placeholder='optional field mapping JSON, e.g. {"rule_name":"rule.name","severity":"event.severity"}'
        className="mt-2 w-full bg-surface border border-line rounded px-2 py-1 text-xs text-text font-mono" />
      <div className="flex items-center justify-between mt-2">
        {err ? <span className="text-xs text-danger">{err}</span> : <span />}
        <button onClick={run} disabled={busy || !raw.trim()}
          className="text-xs border border-line rounded px-2 py-1 text-text hover:bg-surface2/40 disabled:opacity-50 flex items-center gap-1.5">
          {busy ? <Loader2 size={12} className="animate-spin" /> : <FlaskConical size={12} />} Preview
        </button>
      </div>
      {res && (
        <div className="mt-3 grid sm:grid-cols-2 gap-x-4 gap-y-1">
          {FIELDS.map(([k, v]) => (
            <div key={k} className="flex items-baseline gap-2 text-xs">
              <span className="text-muted w-20 shrink-0">{k}</span>
              <span className="text-text font-mono truncate">{v ?? "—"}</span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function PollingTab() {
  const sourcesSWR = useSWR<{ sources: Source[]; polling_enabled?: boolean }>(
    "admin:sources", api.connectors.sources.list);
  const providersSWR = useSWR<{ providers: Provider[] }>(
    "admin:source-providers", api.connectors.sources.providers);
  const [busy, setBusy] = useState<Record<string, boolean>>({});
  const [note, setNote] = useState<Record<string, string>>({});

  const sources = sourcesSWR.data?.sources ?? [];
  const providers = providersSWR.data?.providers ?? [];
  const healthCounts = sources.reduce<Record<string, number>>((acc, s) => {
    const k = s.health ?? "pending";
    acc[k] = (acc[k] ?? 0) + 1;
    return acc;
  }, {});

  async function toggle(s: Source) {
    setBusy((b) => ({ ...b, [s.id]: true }));
    try {
      await api.connectors.sources.update(s.id, { enabled: !s.enabled });
      sourcesSWR.mutate();
    } finally {
      setBusy((b) => ({ ...b, [s.id]: false }));
    }
  }
  async function pollNow(s: Source) {
    setBusy((b) => ({ ...b, [s.id]: true }));
    setNote((x) => ({ ...x, [s.id]: "" }));
    try {
      await api.connectors.sources.pollNow(s.id);
      setNote((x) => ({ ...x, [s.id]: "Queued — polls within ~60s" }));
    } catch (e: any) {
      setNote((x) => ({ ...x, [s.id]: e?.message ?? "failed" }));
    } finally {
      setBusy((b) => ({ ...b, [s.id]: false }));
    }
  }
  async function del(s: Source) {
    if (!confirm(`Delete source ${s.label} (${s.identifier})?`)) return;
    await api.connectors.sources.remove(s.id);
    sourcesSWR.mutate();
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-muted">
        Pull alerts directly from a console on a schedule, instead of forwarding by email. Each source
        polls its connector API, and every new alert enters the same pipeline a webhook alert does and
        parks at the analyst gate. The server flag <span className="font-mono">pull_ingest_enabled</span>{" "}
        must also be on for polling to run.
      </p>

      {sourcesSWR.data && sourcesSWR.data.polling_enabled === false && (
        <div className="flex items-start gap-2 rounded border border-warning/40 bg-warning/10 px-3 py-2 text-xs text-warning">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" />
          <span>
            Polling is <b>off</b> — sources are saved but the cron won’t run. Set{" "}
            <span className="font-mono">pull_ingest_enabled=true</span> and restart the worker.
          </span>
        </div>
      )}

      {sourcesSWR.isLoading ? (
        <div className="flex items-center gap-2 text-muted text-sm py-6">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : sourcesSWR.error ? (
        <Panel title="Sources">
          <div className="flex flex-col items-center gap-3 py-6 text-center">
            <AlertTriangle size={22} className="text-danger" />
            <div className="text-sm text-text">Couldn’t load sources.</div>
            <div className="text-[11px] text-muted font-mono">{sourcesSWR.error.message}</div>
            <button onClick={() => sourcesSWR.mutate()} className="btn btn-primary text-sm">Retry</button>
          </div>
        </Panel>
      ) : (
        <>
          {sources.length > 0 && (
            <div className="text-[11px] font-mono flex items-center gap-3 flex-wrap">
              <span className="text-muted">{sources.length} sources</span>
              {["ok", "error", "stale", "pending", "disabled"]
                .filter((k) => healthCounts[k])
                .map((k) => (
                  <span key={k} className={HEALTH_STYLE[k] ?? "text-muted"}>
                    {healthCounts[k]} {k}
                  </span>
                ))}
            </div>
          )}
          <Panel title={`Configured sources (${sources.length})`}>
            {sources.length === 0 ? (
              <div className="text-sm text-muted py-2">None yet — add one below.</div>
            ) : (
              <ul className="divide-y divide-line">
                {sources.map((s) => (
                  <li key={s.id} className="py-2.5 flex items-start gap-3">
                    <RadioTower size={15} className="mt-0.5 text-muted shrink-0" />
                    <div className="min-w-0 flex-1">
                      <div className="text-sm text-text flex items-center gap-2 flex-wrap">
                        {s.label}
                        <span className="text-muted font-mono text-xs">{s.identifier}</span>
                        {s.customer && <span className="text-[10px] text-accent">{s.customer}</span>}
                        {s.enabled
                          ? <span className="text-[10px] text-positive">● enabled</span>
                          : <span className="text-[10px] text-warning">○ disabled</span>}
                      </div>
                      <div className="text-[11px] text-muted mt-1 flex items-center gap-3 flex-wrap font-mono">
                        <span>every {s.interval_seconds}s</span>
                        <span>min sev: {s.min_severity ?? "any"}</span>
                        <span>≤{s.max_items}/poll</span>
                      </div>
                      <div className="text-[11px] mt-1 flex items-center gap-3 flex-wrap">
                        <span className={`inline-flex items-center gap-1 ${HEALTH_STYLE[s.health ?? "pending"] ?? "text-muted"}`}>
                          {s.health === "ok"
                            ? <CheckCircle2 size={11} />
                            : <AlertTriangle size={11} />}
                          {s.health ?? "pending"}
                        </span>
                        <span className="text-muted">last ok {ago(s.last_success_at)}</span>
                        {s.consecutive_errors > 0 && (
                          <span className="text-danger">{s.consecutive_errors} error(s)</span>
                        )}
                        {(s.last_poll_count != null || s.last_poll_ms != null) && (
                          <span className="text-muted font-mono">
                            {s.last_poll_count ?? 0} pulled{s.last_poll_ms != null ? ` · ${s.last_poll_ms}ms` : ""}
                          </span>
                        )}
                        {!!s.total_ingested && (
                          <span className="text-muted font-mono">{s.total_ingested} total</span>
                        )}
                      </div>
                      {s.last_error && (
                        <div className="text-[11px] text-danger/80 font-mono truncate mt-0.5">{s.last_error}</div>
                      )}
                      {note[s.id] && <div className="text-[11px] text-accent mt-0.5">{note[s.id]}</div>}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button onClick={() => toggle(s)} disabled={busy[s.id]}
                        title={s.enabled ? "Disable" : "Enable"}
                        className="text-muted hover:text-text disabled:opacity-50">
                        {s.enabled ? <PauseCircle size={15} /> : <PlayCircle size={15} />}
                      </button>
                      <button onClick={() => pollNow(s)} disabled={busy[s.id] || !s.enabled}
                        title="Poll now"
                        className="text-muted hover:text-text disabled:opacity-30">
                        {busy[s.id] ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                      </button>
                      <button onClick={() => del(s)} className="text-muted hover:text-danger" title="Delete">
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <AddForm providers={providers} onAdded={() => sourcesSWR.mutate()} />
          <PreviewPanel />
        </>
      )}
    </div>
  );
}

// ── Batch / historical import ────────────────────────────────────────────
const IMPORT_FORMATS = ["auto", "jsonl", "csv", "json"];

function fieldRow(k: string, v: any) {
  return (
    <div className="flex items-baseline gap-2 text-xs">
      <span className="text-muted w-20 shrink-0">{k}</span>
      <span className="text-text font-mono truncate">{v ?? "—"}</span>
    </div>
  );
}

function ImportPanel({ onStarted }: { onStarted: () => void }) {
  const [mode, setMode] = useState<"upload" | "path">("upload");
  const [file, setFile] = useState<File | null>(null);
  const [serverPath, setServerPath] = useState("");
  const [customer, setCustomer] = useState("");
  const [sourceHint, setSourceHint] = useState("");
  const [fmt, setFmt] = useState("auto");
  const [fieldMapText, setFieldMapText] = useState("");
  const [dedupe, setDedupe] = useState(true);

  const [preview, setPreview] = useState<BatchImportPreview | null>(null);
  const [busy, setBusy] = useState<"preview" | "start" | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // undefined = JSON parse error (abort); null = empty; object = parsed map
  function readFieldMap(): Record<string, string> | null | undefined {
    if (!fieldMapText.trim()) return null;
    try { return JSON.parse(fieldMapText); }
    catch { setErr("Field mapping must be valid JSON"); return undefined; }
  }

  function buildForm(dryRun: boolean, fm: Record<string, string> | null): FormData {
    const fd = new FormData();
    if (file) fd.append("file", file);
    fd.append("customer", customer);
    fd.append("source_hint", sourceHint);
    fd.append("fmt", fmt);
    if (fm) fd.append("field_map", JSON.stringify(fm));
    fd.append("dedupe", String(dedupe));
    fd.append("dry_run", String(dryRun));
    return fd;
  }

  function pathBody(fm: Record<string, string> | null) {
    return {
      server_path: serverPath.trim(),
      customer: customer.trim() || null,
      source_hint: sourceHint.trim() || null,
      fmt,
      field_map: fm,
      dedupe,
    };
  }

  const canSubmit = mode === "upload" ? !!file : serverPath.trim().length > 0;

  async function doPreview() {
    const fm = readFieldMap();
    if (fm === undefined) return;
    setBusy("preview"); setErr(null); setPreview(null);
    try {
      const res = mode === "upload"
        ? await api.ingest.batch.uploadPreview(buildForm(true, fm))
        : await api.ingest.batch.pathPreview(pathBody(fm));
      setPreview(res);
    } catch (e: any) { setErr(e?.message ?? "preview failed"); }
    finally { setBusy(null); }
  }

  async function doStart() {
    const fm = readFieldMap();
    if (fm === undefined) return;
    setBusy("start"); setErr(null);
    try {
      if (mode === "upload") await api.ingest.batch.uploadStart(buildForm(false, fm));
      else await api.ingest.batch.pathStart(pathBody(fm));
      setFile(null); setServerPath(""); setPreview(null);
      onStarted();
    } catch (e: any) { setErr(e?.message ?? "import failed"); }
    finally { setBusy(null); }
  }

  return (
    <Panel title="Import a file">
      <p className="text-xs text-muted mb-3">
        Stream a history / replay file into the pipeline. Each record becomes an incident that runs the
        same triage + enrichment and parks at the analyst gate — nothing is auto-closed or sent. Supports
        JSONL / NDJSON, CSV / TSV, and a JSON array. Re-importing the same file is de-duplicated.
      </p>

      <div className="flex items-center gap-1 mb-3 text-xs">
        <button onClick={() => { setMode("upload"); setPreview(null); }}
          className={`px-2 py-1 rounded border ${mode === "upload" ? "border-accent text-accent" : "border-line text-muted"}`}>
          Upload file
        </button>
        <button onClick={() => { setMode("path"); setPreview(null); }}
          className={`px-2 py-1 rounded border ${mode === "path" ? "border-accent text-accent" : "border-line text-muted"}`}>
          Server path
        </button>
      </div>

      <div className="grid sm:grid-cols-2 gap-3">
        {mode === "upload" ? (
          <label className="text-xs text-muted sm:col-span-2">
            File
            <input type="file"
              onChange={(e) => { setFile(e.target.files?.[0] ?? null); setPreview(null); }}
              className="mt-1 w-full text-sm text-text file:mr-2 file:rounded file:border file:border-line file:bg-surface file:px-2 file:py-1 file:text-xs file:text-text" />
            {file && (
              <span className="mt-1 block text-[11px] text-muted font-mono">
                {file.name} · {(file.size / 1024).toFixed(0)} KB
              </span>
            )}
          </label>
        ) : (
          <label className="text-xs text-muted sm:col-span-2">
            Server path <span className="opacity-60">(a file placed under the /workspace volume)</span>
            <input value={serverPath} onChange={(e) => { setServerPath(e.target.value); setPreview(null); }}
              placeholder="imports/acme-90d.jsonl"
              className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text font-mono" />
          </label>
        )}

        <label className="text-xs text-muted">
          Format
          <select value={fmt} onChange={(e) => setFmt(e.target.value)}
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text">
            {IMPORT_FORMATS.map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
        </label>
        <label className="text-xs text-muted">
          Attribute to customer <span className="opacity-60">(optional)</span>
          <input value={customer} onChange={(e) => setCustomer(e.target.value)}
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text" />
        </label>
        <label className="text-xs text-muted">
          Source hint <span className="opacity-60">(optional — routes the parser)</span>
          <input value={sourceHint} onChange={(e) => setSourceHint(e.target.value)}
            placeholder="wazuh / sentinel_one / …"
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text font-mono" />
        </label>
        <label className="text-xs text-muted flex items-center gap-1.5 mt-5">
          <input type="checkbox" checked={dedupe} onChange={(e) => setDedupe(e.target.checked)} />
          De-duplicate identical records
        </label>
        <label className="text-xs text-muted sm:col-span-2">
          Field mapping <span className="opacity-60">(optional JSON — for files without a built-in parser)</span>
          <textarea value={fieldMapText} onChange={(e) => setFieldMapText(e.target.value)} rows={2}
            placeholder='{"rule_name":"rule.name","severity":"event.severity","src_ip":"source.ip"}'
            className="mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-xs text-text font-mono" />
        </label>
      </div>

      <div className="flex items-center justify-between mt-3">
        {err ? <span className="text-xs text-danger">{err}</span> : <span />}
        <div className="flex items-center gap-2">
          <button onClick={doPreview} disabled={!canSubmit || busy !== null}
            className="text-xs border border-line rounded px-2 py-1 text-text hover:bg-surface2/40 disabled:opacity-50 flex items-center gap-1.5">
            {busy === "preview" ? <Loader2 size={12} className="animate-spin" /> : <FlaskConical size={12} />} Preview
          </button>
          <button onClick={doStart} disabled={!canSubmit || busy !== null}
            className="btn btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50">
            {busy === "start" ? <Loader2 size={14} className="animate-spin" /> : <FileUp size={14} />} Start import
          </button>
        </div>
      </div>

      {preview && (
        <div className="mt-3 border-t border-line pt-3">
          <div className="text-xs text-text mb-2">
            <b>{preview.count.toLocaleString()}</b>{preview.capped ? "+" : ""} record{preview.count === 1 ? "" : "s"} detected
            {preview.capped && <span className="text-muted"> (count capped)</span>}
            <span className="text-muted"> — first {preview.preview.length}:</span>
          </div>
          <div className="space-y-2">
            {preview.preview.map((p, i) => {
              const n = p.normalized ?? {};
              return (
                <div key={i} className="grid sm:grid-cols-2 gap-x-4 gap-y-1 border border-line rounded px-2 py-1.5">
                  {fieldRow("source", p.detected_source)}
                  {fieldRow("rule_name", n.rule_name)}
                  {fieldRow("severity", n.severity_label)}
                  {fieldRow("hostname", n.hostname)}
                  {fieldRow("src_ip", n.src_ip)}
                  {fieldRow("category", n.threat_category)}
                </div>
              );
            })}
            {preview.preview.length === 0 && (
              <div className="text-xs text-muted">No records parsed from this file.</div>
            )}
          </div>
        </div>
      )}
    </Panel>
  );
}

function ImportStatusBadge({ status }: { status: BatchImportJob["status"] }) {
  if (status === "completed")
    return <span className="text-[10px] text-positive inline-flex items-center gap-1"><CheckCircle size={11} /> completed</span>;
  if (status === "failed")
    return <span className="text-[10px] text-danger inline-flex items-center gap-1"><Ban size={11} /> failed</span>;
  if (status === "running")
    return <span className="text-[10px] text-accent inline-flex items-center gap-1"><Loader2 size={11} className="animate-spin" /> running</span>;
  return <span className="text-[10px] text-warning">queued</span>;
}

function ImportJobsPanel({ jobs, loading, error, onRetry }: {
  jobs: BatchImportJob[]; loading: boolean; error: Error | undefined; onRetry: () => void;
}) {
  if (loading) {
    return (
      <Panel title="Import history">
        <div className="flex items-center gap-2 text-muted text-sm py-4">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      </Panel>
    );
  }
  if (error) {
    return (
      <Panel title="Import history">
        <div className="flex flex-col items-center gap-3 py-6 text-center">
          <AlertTriangle size={22} className="text-danger" />
          <div className="text-sm text-text">Couldn’t load import jobs.</div>
          <div className="text-[11px] text-muted font-mono">{error.message}</div>
          <button onClick={onRetry} className="btn btn-primary text-sm">Retry</button>
        </div>
      </Panel>
    );
  }
  return (
    <Panel title={`Import history (${jobs.length})`}>
      {jobs.length === 0 ? (
        <div className="text-sm text-muted py-2">No imports yet.</div>
      ) : (
        <ul className="divide-y divide-line">
          {jobs.map((j) => {
            const pct = j.total ? Math.min(100, Math.round((j.processed / j.total) * 100)) : null;
            const active = j.status === "running" || j.status === "queued";
            return (
              <li key={j.id} className="py-2.5 flex items-start gap-3">
                <ListChecks size={15} className="mt-0.5 text-muted shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="text-sm text-text flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs truncate">{j.filename}</span>
                    <ImportStatusBadge status={j.status} />
                    {j.customer && <span className="text-[10px] text-accent">{j.customer}</span>}
                    <span className="text-[10px] text-muted font-mono">{j.fmt}</span>
                  </div>
                  <div className="mt-1 h-1.5 w-full rounded bg-surface2/60 overflow-hidden">
                    <div
                      className={`h-full ${j.status === "failed" ? "bg-danger" : "bg-accent"} ${active && pct === null ? "animate-pulse" : ""}`}
                      style={{ width: `${pct ?? (active ? 40 : 100)}%` }}
                    />
                  </div>
                  <div className="text-[11px] text-muted mt-1 flex items-center gap-3 flex-wrap font-mono">
                    <span className="text-positive">{j.created} created</span>
                    {j.skipped > 0 && <span>{j.skipped} skipped</span>}
                    {j.failed > 0 && <span className="text-danger">{j.failed} failed</span>}
                    <span>{j.processed}{j.total ? ` / ${j.total}` : ""} processed</span>
                  </div>
                  {j.error && (
                    <div className="text-[11px] text-danger/80 font-mono truncate mt-0.5">{j.error}</div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

function ImportTab() {
  const jobsSWR = useSWR<{ jobs: BatchImportJob[] }>("admin:import-jobs", api.ingest.batch.jobs);
  // Poll while the tab is open so a running import's progress advances live.
  useEffect(() => {
    const t = setInterval(() => jobsSWR.mutate(), 2500);
    return () => clearInterval(t);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="space-y-4">
      <ImportPanel onStarted={() => jobsSWR.mutate()} />
      <ImportJobsPanel
        jobs={jobsSWR.data?.jobs ?? []}
        loading={jobsSWR.isLoading}
        error={jobsSWR.error}
        onRetry={() => jobsSWR.mutate()}
      />
    </div>
  );
}

function TabBtn({ active, onClick, icon, children }: {
  active: boolean; onClick: () => void; icon: ReactNode; children: ReactNode;
}) {
  return (
    <button onClick={onClick}
      className={`px-3 py-1.5 text-sm flex items-center gap-1.5 border-b-2 -mb-px ${active ? "border-accent text-text" : "border-transparent text-muted hover:text-text"}`}>
      {icon} {children}
    </button>
  );
}

export default function SourcesPage() {
  const [tab, setTab] = useState<"polling" | "import">("polling");
  return (
    <div className="max-w-3xl space-y-4">
      <div className="flex items-center gap-1 border-b border-line">
        <TabBtn active={tab === "polling"} onClick={() => setTab("polling")} icon={<RadioTower size={14} />}>
          Live polling
        </TabBtn>
        <TabBtn active={tab === "import"} onClick={() => setTab("import")} icon={<Upload size={14} />}>
          Import
        </TabBtn>
      </div>
      {tab === "polling" ? <PollingTab /> : <ImportTab />}
    </div>
  );
}
