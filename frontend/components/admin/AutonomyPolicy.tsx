"use client";

import { useEffect, useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, Lock, RotateCcw, Save } from "lucide-react";

type Eff = {
  blast_radius: string;
  auto: number;
  review: number;
  escalation: number;
  source: string;
  reason: string | null;
  is_effect: boolean;
};
type Policy = { actions: Record<string, Eff>; defaults: Record<string, number[]> };

const BR_STYLE: Record<string, string> = {
  read: "text-positive border-positive/40",
  low: "text-positive border-positive/30",
  med: "text-warning border-warning/40",
  high: "text-warning border-warning/50",
  critical: "text-danger border-danger/50",
};

function Row({ kind, eff, onSaved }: { kind: string; eff: Eff; onSaved: () => void }) {
  const [auto, setAuto] = useState(eff.auto);
  const [review, setReview] = useState(eff.review);
  const [esc, setEsc] = useState(eff.escalation);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { setAuto(eff.auto); setReview(eff.review); setEsc(eff.escalation); }, [eff]);

  const ordered = esc <= review && review <= auto;
  const dirty = auto !== eff.auto || review !== eff.review || esc !== eff.escalation;

  async function save() {
    if (!ordered) { setErr("Need escalation ≤ review ≤ auto"); return; }
    setBusy(true); setErr(null);
    try { await api.autonomy.setPolicy(kind, { auto, review, escalation: esc }); onSaved(); }
    catch (e: any) { setErr(e?.message ?? "save failed"); }
    finally { setBusy(false); }
  }
  async function reset() {
    setBusy(true); setErr(null);
    try { await api.autonomy.resetPolicy(kind); onSaved(); }
    finally { setBusy(false); }
  }

  return (
    <div className="flex items-center gap-3 py-2 border-t border-line/60 text-sm flex-wrap">
      <div className="w-40 shrink-0">
        <span className="font-mono text-text">{kind}</span>
        <span className={`ml-2 text-[10px] border rounded px-1 ${BR_STYLE[eff.blast_radius] ?? "text-muted border-line"}`}>
          {eff.blast_radius}
        </span>
      </div>
      {eff.is_effect ? (
        <div className="flex items-center gap-1.5 text-[11px] text-danger">
          <Lock size={12} /> always analyst-gated (escalate) — thresholds don't apply
        </div>
      ) : (
        <>
          {([["auto", auto, setAuto], ["review", review, setReview], ["escalation", esc, setEsc]] as const).map(
            ([lbl, val, set]) => (
              <label key={lbl} className="flex items-center gap-1 text-[11px] text-muted">
                {lbl}
                <input type="number" min={0} max={2} step={0.05} value={val}
                  onChange={(e) => set(parseFloat(e.target.value))}
                  className="w-16 bg-surface border border-line rounded px-1 py-0.5 text-text tabular-nums" />
              </label>
            ),
          )}
          <span className="text-[10px] text-muted">src: {eff.source}</span>
          <button onClick={save} disabled={busy || !dirty || !ordered}
            className="text-xs flex items-center gap-1 border border-line rounded px-2 py-1 text-text hover:bg-surface2/40 disabled:opacity-40">
            {busy ? <Loader2 size={12} className="animate-spin" /> : <Save size={12} />} Save
          </button>
          {eff.source === "db" && (
            <button onClick={reset} disabled={busy}
              className="text-xs flex items-center gap-1 text-muted hover:text-text disabled:opacity-40" title="Reset to default">
              <RotateCcw size={12} />
            </button>
          )}
          {err && <span className="text-[11px] text-danger">{err}</span>}
        </>
      )}
    </div>
  );
}

export function AutonomyPolicy() {
  const { data, isLoading, mutate } = useSWR<Policy>("admin:autonomy-policy", api.autonomy.policy);
  return (
    <Panel title="Autonomy guardrails — recommendation policy">
      <p className="text-xs text-muted mb-3">
        These thresholds decide the auto / review / escalate <em>badge</em> on each proposed action.
        v1 is recommendation-only — nothing auto-executes. Containment kinds (isolate / blocklist /
        collect) are always escalate and analyst-gated regardless of these values.
      </p>
      {isLoading || !data ? (
        <div className="flex items-center gap-2 text-muted text-sm py-6">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : (
        <div>
          {Object.entries(data.actions)
            .sort((a, b) => Number(b[1].is_effect) - Number(a[1].is_effect))
            .map(([kind, eff]) => (
              <Row key={kind} kind={kind} eff={eff} onSaved={() => mutate()} />
            ))}
        </div>
      )}
    </Panel>
  );
}
