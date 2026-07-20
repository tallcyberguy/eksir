"use client";

import Link from "next/link";
import type { ClusterSummary } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { ScoreChips } from "@/components/incidents/Scores";
import { severityPill, verdictPill } from "@/lib/utils";
import { Waypoints } from "lucide-react";

/** True once the incident belongs to a cluster with a sibling (i.e. > 1 member).
 *  A single-member cluster is just this incident, so we hide the panel entirely
 *  (matches HuntPanel/EntitiesPanel returning null on empty). */
export function hasCluster(cluster?: ClusterSummary | null): boolean {
  return !!cluster && cluster.member_count > 1;
}

export function RelatedIncidentsPanel({ cluster }: { cluster?: ClusterSummary | null }) {
  if (!hasCluster(cluster)) return null;

  return (
    <Panel
      title="Related incidents"
      icon={<Waypoints size={14} className="text-accent" />}
      right={
        <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border border-line text-muted">
          {cluster!.member_count} in cluster
        </span>
      }
    >
      <div className="space-y-2">
        {cluster!.members.map((m) => (
          <div key={m.incident_id} className="flex flex-col gap-1 border-t border-line/60 pt-2 first:border-t-0 first:pt-0">
            <div className="flex items-center gap-2 min-w-0">
              <Link
                href={`/incidents/${m.incident_id}`}
                title={m.title}
                className="font-mono text-xs text-accent hover:underline shrink-0"
              >
                {m.case_number}
              </Link>
              {m.is_seed && (
                <span className="shrink-0 text-[9px] uppercase tracking-wider px-1 py-0.5 rounded bg-accent/10 text-accent border border-accent/40"
                      title="Oldest member — the cluster seed.">
                  seed
                </span>
              )}
              <span className="ml-auto shrink-0">
                <ScoreChips confidence={m.confidence_score} threat={m.threat_score} />
              </span>
            </div>
            <div className="flex items-center gap-2 min-w-0">
              <span className="text-xs text-text/90 truncate min-w-0" title={m.title}>{m.title}</span>
              <span className="ml-auto flex items-center gap-1.5 shrink-0">
                <span className={severityPill(m.severity)}>{m.severity}</span>
                <span className={verdictPill(m.verdict)}>{m.verdict}</span>
              </span>
            </div>
            {m.shared_entity && (
              <div className="text-[10px] text-muted truncate" title={m.shared_entity}>
                shared · {m.shared_entity}
              </div>
            )}
          </div>
        ))}
      </div>
    </Panel>
  );
}
