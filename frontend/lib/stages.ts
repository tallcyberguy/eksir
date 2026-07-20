// Canonical pipeline stage order + the event→stage derivation, shared by the
// timeline tab (PipelineTimeline) and the right-rail progress line (ProgressRail).
// Mirrors the backend orchestrator STAGE_LABELS + the persona stages.

export type Ev = {
  id: string;
  ts: string;
  actor: string;
  event_type: string;
  display: string | null;
  level?: string; // running | ok | warn | error | info
  step?: string | null; // canonical stage key
  duration_ms?: number | null;
};

export type StageStatus = "running" | "ok" | "warn" | "error" | "pending" | "skipped";

export type Stage = {
  key: string;
  label: string;
  status: StageStatus;
  duration_ms: number | null;
  ts: string;
  details: Ev[];
};

export const STAGE_ORDER: { key: string; label: string }[] = [
  { key: "parse", label: "Parse & normalize" },
  { key: "auto_close_pre", label: "Auto-close check" },
  { key: "dedup", label: "RAG retrieve (similar cases)" },
  { key: "enrich", label: "Enrichment" },
  { key: "decision", label: "Decision gate" },
  { key: "l1", label: "L1 triage" },
  { key: "l2", label: "L2 analysis" },
  { key: "hunt", label: "Threat hunt" },
  { key: "forensics", label: "Forensics" },
  { key: "synthesis", label: "Manager & gate" },
  { key: "complete", label: "Pipeline complete" },
];

const labelFor = (k: string) => STAGE_ORDER.find((s) => s.key === k)?.label || k;

/**
 * Walk the chronological event stream into stages. A `*_running` event opens a
 * stage; `*_done`/`*_failed` closes it; `*_skipped` marks it skipped; any other
 * event nests as a detail under the currently-open stage.
 *
 * includePending=true returns the full canonical STAGE_ORDER with not-yet-seen
 * stages as "pending" (for the forward-looking progress rail). Otherwise returns
 * only stages that produced events (for the timeline tab).
 */
export function deriveStages(events: Ev[], opts: { includePending?: boolean } = {}): Stage[] {
  const map = new Map<string, Stage>();
  let openKey: string | null = null;

  for (const e of events) {
    const lvl = e.level || "info";
    const isRunning = lvl === "running";
    const isDone = lvl === "ok" && (e.event_type.endsWith("_done") || e.step === "complete");
    const isFailed =
      lvl === "error" && (e.event_type.endsWith("_failed") || e.event_type === "pipeline_failed");
    const isSkipped = e.event_type.endsWith("_skipped");
    const key: string = e.step || openKey || "misc";

    if (!map.has(key)) {
      map.set(key, {
        key,
        label: labelFor(key),
        status: "pending",
        duration_ms: null,
        ts: e.ts,
        details: [],
      });
    }
    const st = map.get(key)!;

    if (isRunning) {
      openKey = key;
      if (st.status === "pending" || st.status === "skipped") st.status = "running";
    } else if (isDone) {
      st.status = st.status === "warn" ? "warn" : "ok";
      st.duration_ms = e.duration_ms ?? st.duration_ms;
      if (key === openKey) openKey = null;
    } else if (isFailed) {
      st.status = "error";
      st.duration_ms = e.duration_ms ?? st.duration_ms;
      if (key === openKey) openKey = null;
    } else if (isSkipped) {
      if (st.status === "pending") st.status = "skipped";
    } else {
      if (lvl === "warn" && st.status !== "error") st.status = "warn";
      st.details.push(e);
    }
  }

  if (opts.includePending) {
    const list: Stage[] = STAGE_ORDER.map(
      (s) =>
        map.get(s.key) || {
          key: s.key,
          label: s.label,
          status: "pending" as StageStatus,
          duration_ms: null,
          ts: "",
          details: [],
        },
    );
    for (const [k, v] of map) {
      if (!STAGE_ORDER.find((s) => s.key === k)) list.push(v);
    }
    return list;
  }

  const list = Array.from(map.values());
  list.sort((a, b) => {
    const ia = STAGE_ORDER.findIndex((s) => s.key === a.key);
    const ib = STAGE_ORDER.findIndex((s) => s.key === b.key);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });
  return list;
}
