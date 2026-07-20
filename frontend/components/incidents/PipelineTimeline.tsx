"use client";

import { Panel } from "@/components/ui/Panel";
import { cn } from "@/lib/utils";
import { STAGE_ORDER } from "@/lib/stages";
import {
  CheckCircle2, XCircle, AlertTriangle, Loader2, CircleDot, ChevronRight,
} from "lucide-react";

type Ev = {
  id: string;
  ts: string;
  actor: string;
  event_type: string;
  display: string | null;
  level?: string;        // running | ok | warn | error | info
  step?: string | null;  // canonical stage key
  duration_ms?: number | null;
};

type Stage = {
  key: string;
  label: string;
  status: "running" | "ok" | "warn" | "error" | "pending";
  duration_ms: number | null;
  ts: string;
  details: Ev[];
};

/**
 * NightBeacon-style stage checklist. Walks the chronological event stream:
 * a `*_running` event opens a stage; its `*_done`/`*_failed` closes it; any
 * other event in between (and any untagged event) nests as a detail line under
 * the currently-open stage. Falls back to a flat list for legacy events with
 * no step/level metadata.
 */
export function PipelineTimeline({ events }: { events: Ev[] }) {
  const hasStages = events.some((e) => e.step || (e.level && e.level !== "info"));
  if (!hasStages) return <FlatTimeline events={events} />;

  const labelFor = (k: string) =>
    STAGE_ORDER.find((s) => s.key === k)?.label || k;

  // Build stages by walking the ordered stream.
  const stageMap = new Map<string, Stage>();
  let openKey: string | null = null;

  for (const e of events) {
    const lvl = e.level || "info";
    const isRunning = lvl === "running";
    const isDone = lvl === "ok" && (e.event_type.endsWith("_done") || e.step === "complete");
    const isFailed = lvl === "error" && (e.event_type.endsWith("_failed") || e.event_type === "pipeline_failed");
    const stageKey: string = e.step || openKey || "misc";

    if (!stageMap.has(stageKey)) {
      stageMap.set(stageKey, {
        key: stageKey, label: labelFor(stageKey), status: "pending",
        duration_ms: null, ts: e.ts, details: [],
      });
    }
    const stage = stageMap.get(stageKey)!;

    if (isRunning) {
      openKey = stageKey;
      if (stage.status === "pending") stage.status = "running";
    } else if (isDone) {
      stage.status = stage.status === "warn" ? "warn" : "ok";
      stage.duration_ms = e.duration_ms ?? stage.duration_ms;
      if (stageKey === openKey) openKey = null;
    } else if (isFailed) {
      stage.status = "error";
      stage.duration_ms = e.duration_ms ?? stage.duration_ms;
      if (stageKey === openKey) openKey = null;
    } else {
      // detail event — bump stage to warn if this is a warning
      if (lvl === "warn" && stage.status !== "error") stage.status = "warn";
      stage.details.push(e);
    }
  }

  const stages = Array.from(stageMap.values());
  // Order by canonical sequence, unknown stages appended in arrival order.
  stages.sort((a, b) => {
    const ia = STAGE_ORDER.findIndex((s) => s.key === a.key);
    const ib = STAGE_ORDER.findIndex((s) => s.key === b.key);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });

  const done = stages.filter((s) => s.status === "ok" || s.status === "warn").length;
  const failed = stages.some((s) => s.status === "error");
  const totalMs = stages.reduce((a, s) => a + (s.duration_ms || 0), 0);

  return (
    <Panel title="Pipeline">
      <div className="flex items-center gap-3 mb-4 text-xs">
        <span className={cn("pill", failed ? "pill-critical" : "pill-resolved")}>
          {failed ? "failed" : `${done}/${stages.length} stages`}
        </span>
        {totalMs > 0 && <span className="text-muted font-mono">{(totalMs / 1000).toFixed(1)}s total</span>}
      </div>

      <ol className="space-y-2.5">
        {stages.map((s) => (
          <li key={s.key} className="border border-line/50 rounded-md">
            <div className="flex items-center gap-2.5 px-3 py-2">
              <StatusIcon status={s.status} />
              <span className={cn("text-sm", s.status === "error" ? "text-danger" : s.status === "warn" ? "text-warning" : "text-text")}>
                {s.label}
              </span>
              {s.duration_ms != null && (
                <span className="text-[11px] text-muted font-mono ml-auto">{s.duration_ms} ms</span>
              )}
            </div>
            {s.details.length > 0 && (
              <ul className="border-t border-line/40 px-3 py-1.5 space-y-1">
                {s.details.map((d) => (
                  <li key={d.id} className="flex items-start gap-1.5 text-xs">
                    <ChevronRight size={12} className={cn("mt-0.5 shrink-0",
                      d.level === "warn" ? "text-warning" : d.level === "error" ? "text-danger" : "text-muted")}/>
                    <span className={cn("leading-snug",
                      d.level === "warn" ? "text-warning" : d.level === "error" ? "text-danger" : "text-text/80")}>
                      {d.display || d.event_type}
                    </span>
                    <span className="ml-auto shrink-0 text-[10px] text-muted/60 font-mono">
                      {new Date(d.ts).toLocaleTimeString()}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ol>
    </Panel>
  );
}

function StatusIcon({ status }: { status: Stage["status"] }) {
  if (status === "running") return <Loader2 size={15} className="text-accent animate-spin shrink-0"/>;
  if (status === "ok")      return <CheckCircle2 size={15} className="text-positive shrink-0"/>;
  if (status === "warn")    return <AlertTriangle size={15} className="text-warning shrink-0"/>;
  if (status === "error")   return <XCircle size={15} className="text-danger shrink-0"/>;
  return <CircleDot size={15} className="text-muted/50 shrink-0"/>;
}

function FlatTimeline({ events }: { events: Ev[] }) {
  return (
    <Panel title="Timeline">
      <ol className="space-y-3 relative pl-6">
        <span className="absolute left-2 top-2 bottom-2 w-px bg-line"/>
        {events.map((e) => (
          <li key={e.id} className="relative">
            <span className="absolute -left-4 top-1.5 w-2.5 h-2.5 rounded-full bg-accent shadow-glow"/>
            <div className="text-xs text-muted">{new Date(e.ts).toLocaleString()} — {e.actor}</div>
            <div className="text-sm">{e.display || e.event_type}</div>
          </li>
        ))}
      </ol>
    </Panel>
  );
}
