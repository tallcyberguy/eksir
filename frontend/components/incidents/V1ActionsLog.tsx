"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import {
  ShieldBan, WifiOff, Wifi, FolderSearch, CheckCircle2, XCircle,
  Loader2, RefreshCw, Download,
} from "lucide-react";

type V1Action = {
  action: string;
  ts: string;
  actor?: string;
  payload?: {
    status?: string;
    task_id?: string | null;
    error?: string | null;
    endpoint_name?: string | null;
    agent_guid?: string | null;
    file_path?: string | null;
    value?: string | null;
    ioc_type?: string | null;
    [k: string]: any;
  };
};

const KIND_ICON: Record<string, any> = {
  blocklist_ioc: ShieldBan,
  blocklist: ShieldBan,
  isolate: WifiOff,
  isolate_host: WifiOff,
  restore: Wifi,
  collect_file: FolderSearch,
};
const KIND_LABEL: Record<string, string> = {
  blocklist_ioc: "Block IOC", blocklist: "Block IOC",
  isolate: "Isolate", isolate_host: "Isolate",
  restore: "Restore", collect_file: "Collect file",
};

function target(p: V1Action["payload"]): string {
  if (!p) return "—";
  return (
    p.file_path || p.value || p.endpoint_name || p.agent_guid || "—"
  );
}

export function V1ActionsLog({ incidentId, enrichment }: { incidentId: string; enrichment: any }) {
  const actions: V1Action[] = enrichment?.v1_actions || [];
  if (actions.length === 0) return null;

  return (
    <Panel title="Vision One actions run">
      <div className="space-y-2">
        {actions.map((a, i) => (
          <ActionRow key={i} incidentId={incidentId} a={a} />
        ))}
      </div>
      <p className="text-[11px] text-muted mt-3">
        Collected files are stored in Trend Vision One as a password-protected archive —
        use “Check status” to fetch the download link once the task completes.
      </p>
    </Panel>
  );
}

function ActionRow({ incidentId, a }: { incidentId: string; a: V1Action }) {
  const Icon = KIND_ICON[a.action] ?? FolderSearch;
  const label = KIND_LABEL[a.action] ?? a.action;
  const failed = a.payload?.status === "failed";
  const taskId = a.payload?.task_id || null;

  const [task, setTask] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function check() {
    if (!taskId) return;
    setBusy(true); setErr(null);
    try {
      setTask(await api.v1.getTask(incidentId, taskId));
    } catch (e: any) {
      setErr(e.message);
    } finally { setBusy(false); }
  }

  const download = task?.resourceLocation || task?.resourcelocation;
  const taskStatus = task?.status;

  return (
    <div className="border border-line/60 rounded-md p-2.5 text-sm">
      <div className="flex items-center gap-2 flex-wrap">
        {failed
          ? <XCircle size={14} className="text-danger shrink-0" />
          : <Icon size={14} className="text-muted shrink-0" />}
        <span className="text-text font-medium">{label}</span>
        <span className="font-mono text-xs text-muted break-all">{target(a.payload)}</span>
        <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded border ${
          failed ? "text-danger border-danger/40" : "text-positive border-positive/40"}`}>
          {a.payload?.status || "—"}
        </span>
        {taskId && (
          <button onClick={check} disabled={busy}
            className="ml-auto flex items-center gap-1 text-[11px] px-2 py-0.5 border border-line rounded hover:border-accent disabled:opacity-40">
            {busy ? <Loader2 size={11} className="animate-spin" /> : <RefreshCw size={11} />}
            Check status
          </button>
        )}
      </div>
      <div className="mt-1 text-[11px] text-muted flex items-center gap-2 flex-wrap">
        {a.actor && <span>{a.actor}</span>}
        <span>· {new Date(a.ts).toLocaleString()}</span>
        {taskId && <span className="font-mono">· task {taskId}</span>}
      </div>
      {failed && a.payload?.error && (
        <p className="mt-1 text-[11px] text-danger break-words">{a.payload.error}</p>
      )}
      {err && <p className="mt-1 text-[11px] text-danger">{err}</p>}
      {task && (
        <div className="mt-2 text-[11px] text-muted border-t border-line/40 pt-2 flex items-center gap-3 flex-wrap">
          <span>V1 task: <span className="text-text">{taskStatus || "unknown"}</span></span>
          {download && (
            <a href={download} target="_blank" rel="noreferrer"
              className="flex items-center gap-1 text-accent hover:underline">
              <Download size={11} /> Download archive
            </a>
          )}
          {download && <span>· archive is password-protected (Vision One)</span>}
        </div>
      )}
    </div>
  );
}
