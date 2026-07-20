"use client";

import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, ChevronRight } from "lucide-react";

type Technique = { id: string; name: string; evidence: string; step: number };
type Stage = { tactic_id: string; name: string; order: number; techniques: Technique[] };
type Path = {
  synthesized: boolean;
  technique_count: number;
  tactic_count: number;
  stages: Stage[];
  unmapped: { id: string; evidence: string }[];
};

export function AttackPathPanel({ incidentId }: { incidentId: string }) {
  const { data, isLoading } = useSWR<Path>(`attack-path.${incidentId}`, () =>
    api.attackGraph.incidentPath(incidentId),
  );

  if (isLoading || !data) {
    return (
      <Panel title="Attack Path">
        <div className="flex items-center gap-2 text-muted text-sm py-6">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      </Panel>
    );
  }

  if (!data.synthesized || data.stages.length === 0) {
    return (
      <Panel title="Attack Path">
        <div className="text-sm text-muted py-6 text-center">
          No attack path — this incident wasn’t deep-synthesized. Short-circuited / auto-closed
          incidents carry no MITRE technique chain.
        </div>
      </Panel>
    );
  }

  return (
    <Panel title="Attack Path">
      <div className="text-[11px] text-muted mb-3">
        {data.technique_count} techniques across {data.tactic_count} tactics — kill chain left → right
        (ATT&CK tactic order).
      </div>
      <div className="overflow-x-auto pb-2">
        <div className="flex items-stretch gap-1 min-w-max">
          {data.stages.map((s, i) => (
            <div key={s.tactic_id} className="flex items-stretch gap-1">
              <div className="w-[180px] shrink-0 rounded border border-line bg-surface/40 p-2">
                <div className="text-[10px] uppercase tracking-wider text-accent mb-1.5">{s.name}</div>
                <div className="space-y-1.5">
                  {s.techniques.map((t) => (
                    <div key={t.id} className="rounded border border-line/60 bg-surface px-1.5 py-1">
                      <div className="text-[11px] font-mono text-text">{t.id}</div>
                      <div className="text-[10px] text-muted leading-tight">{t.name}</div>
                      {t.evidence && (
                        <div className="text-[10px] text-text/70 mt-1 leading-snug border-l border-accent/40 pl-1.5">
                          {t.evidence}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
              {i < data.stages.length - 1 && (
                <div className="flex items-center text-muted">
                  <ChevronRight size={16} />
                </div>
              )}
            </div>
          ))}

          {data.unmapped.length > 0 && (
            <div className="flex items-stretch gap-1">
              <div className="flex items-center text-muted"><ChevronRight size={16} /></div>
              <div className="w-[160px] shrink-0 rounded border border-dashed border-line bg-surface/20 p-2">
                <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">Unmapped</div>
                <div className="space-y-1">
                  {data.unmapped.map((u) => (
                    <div key={u.id} className="text-[11px] font-mono text-muted">{u.id}</div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
      <p className="text-[11px] text-muted mt-3">
        Reconstructed from the L2 verdict’s technique chain — read-only, no action.
      </p>
    </Panel>
  );
}
