"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { api, type EntityDetail } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { ScoreChips } from "@/components/incidents/Scores";
import { riskPill, severityPill, statusPill, verdictPill } from "@/lib/utils";
import { Monitor, User, Globe, FileDigit, Fingerprint } from "lucide-react";

const KIND_ICON: Record<string, any> = {
  device: Monitor,
  user: User,
  network_endpoint: Globe,
  file: FileDigit,
  observable: Fingerprint,
};

export default function EntityDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [ent, setEnt] = useState<EntityDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // One-shot fetch — entities are backfilled, no live pipeline to poll.
  useEffect(() => {
    let alive = true;
    api.getEntity(id)
      .then((e) => { if (alive) setEnt(e); })
      .catch((e: any) => { if (alive) setErr(e.message); });
    return () => { alive = false; };
  }, [id]);

  if (err) return <div className="text-danger text-sm">{err}</div>;
  if (!ent) return <div className="text-muted">Loading…</div>;

  const Icon = KIND_ICON[ent.entity_type] ?? Fingerprint;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="panel p-5">
        <div className="flex items-center gap-3 mb-2 text-sm flex-wrap">
          <span className="inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border border-line text-muted">
            <Icon size={12} className="text-accent" />
            {ent.entity_type}
          </span>
          {ent.risk_score != null && (
            <span
              className={riskPill(ent.risk_score)}
              title="Confirmed-TP history, decayed (30-day half-life)"
            >
              risk {Math.round(ent.risk_score)}
            </span>
          )}
          <span className="text-muted">{ent.customer || "global"}</span>
          <span className="ml-auto text-muted text-xs">
            {ent.first_seen && <>First seen {new Date(ent.first_seen).toLocaleString()}</>}
            {ent.last_seen && <> · Last seen {new Date(ent.last_seen).toLocaleString()}</>}
          </span>
        </div>
        <h1 className="text-xl font-semibold font-mono break-all">{ent.display_name}</h1>
        <div className="mt-1 font-mono text-xs text-muted break-all">{ent.canonical_key}</div>
      </div>

      {/* Attributes */}
      <Panel title="Attributes">
        <pre className="text-xs bg-base border border-line rounded-md p-3 overflow-x-auto">
          {JSON.stringify(ent.attributes ?? {}, null, 2)}
        </pre>
      </Panel>

      {/* Incidents */}
      <Panel title={`Incidents (${ent.incident_count})`}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
              <tr className="text-left">
                <th className="py-2 pr-4">Case</th>
                <th className="py-2 pr-4">Title</th>
                <th className="py-2 pr-4">Role</th>
                <th className="py-2 pr-4">Severity</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">Verdict</th>
                <th className="py-2 pr-4">Scores</th>
                <th className="py-2 pr-4 whitespace-nowrap">Created</th>
              </tr>
            </thead>
            <tbody>
              {ent.incidents.map((r) => (
                <tr key={r.incident_id} className="border-t border-line/60 hover:bg-surface/60">
                  <td className="py-2 pr-4 font-mono text-accent">
                    <Link href={`/incidents/${r.incident_id}`}>{r.case_number}</Link>
                  </td>
                  <td className="py-2 pr-4 max-w-[34ch] truncate" title={r.title}>{r.title}</td>
                  <td className="py-2 pr-4 text-muted">{r.role || "—"}</td>
                  <td className="py-2 pr-4"><span className={severityPill(r.severity)}>{r.severity}</span></td>
                  <td className="py-2 pr-4"><span className={statusPill(r.status)}>{r.status?.replace(/_/g, " ")}</span></td>
                  <td className="py-2 pr-4"><span className={verdictPill(r.verdict || "")}>{r.verdict || "pending"}</span></td>
                  <td className="py-2 pr-4"><ScoreChips confidence={r.confidence_score} threat={r.threat_score}/></td>
                  <td className="py-2 pr-4 text-muted text-xs whitespace-nowrap">
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
              {ent.incidents.length === 0 && (
                <tr><td colSpan={8} className="py-10 text-center text-muted">No linked incidents in scope.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
