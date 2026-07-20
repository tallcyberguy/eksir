"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Crosshair, Download, Loader2, ServerCog } from "lucide-react";

interface HuntQuery {
  platform?: string;
  query?: string;
  rationale?: string;
}

interface HuntStage {
  spread_assessment?: string;
  executed?: boolean;
  affected_hosts?: string[];
  reasoning?: string;
  queries?: HuntQuery[];
  evidence_count?: number;
}

const PLATFORM_LABEL: Record<string, string> = {
  tmv1: "Vision One (TMV1)",
  s1ql: "S1QL",
  sigma: "Sigma",
  kql: "KQL",
};

const SPREAD_LABEL: Record<string, { text: string; cls: string }> = {
  lateral_confirmed: { text: "Lateral spread confirmed", cls: "text-danger border-danger/40" },
  isolated: { text: "Isolated — no spread", cls: "text-positive border-positive/40" },
  unknown: { text: "Spread unknown", cls: "text-muted border-line" },
};

export function HuntPanel({
  incidentId,
  caseNumber,
  enrichment,
}: {
  incidentId: string;
  caseNumber?: string;
  enrichment: any;
}) {
  const hunt: HuntStage | undefined = enrichment?.stages?.hunt;
  const [downloading, setDownloading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!hunt) {
    return (
      <Panel title="Threat Hunt">
        <p className="text-sm text-muted">
          No hunt has run for this incident. Ask the Incident Manager at the sign-off gate to
          run a hunt (e.g. “check if this spread”) to build detection queries and — when the live
          endpoint-activity search is enabled — search for spread.
        </p>
      </Panel>
    );
  }

  const spread = SPREAD_LABEL[hunt.spread_assessment || "unknown"] || SPREAD_LABEL.unknown;
  const hasEvidence = (hunt.evidence_count || 0) > 0;

  async function download() {
    setDownloading(true);
    setErr(null);
    try {
      await api.downloadHuntEvidence(incidentId, caseNumber);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setDownloading(false);
    }
  }

  return (
    <Panel
      title="Threat Hunt"
      icon={<Crosshair size={14} className="text-accent" />}
      right={
        hasEvidence ? (
          <button
            onClick={download}
            disabled={downloading}
            title="Download the raw matched endpoint-activity records"
            className="flex items-center gap-1.5 text-xs px-2.5 py-1 border border-line rounded-md hover:border-accent disabled:opacity-40"
          >
            {downloading ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
            Evidence log ({hunt.evidence_count})
          </button>
        ) : undefined
      }
    >
      <div className="space-y-4">
        {/* Verdict row */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-xs rounded px-2 py-0.5 border ${spread.cls}`}>{spread.text}</span>
          <span className="text-[11px] text-muted flex items-center gap-1">
            <ServerCog size={11} />
            {hunt.executed ? "live search executed" : "query-building only (no live search)"}
          </span>
        </div>

        {/* Affected hosts */}
        {hunt.affected_hosts && hunt.affected_hosts.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
              Affected hosts
            </div>
            <div className="flex flex-wrap gap-1.5">
              {hunt.affected_hosts.map((h, i) => (
                <span key={i} className="font-mono text-xs bg-base border border-line rounded px-2 py-0.5">
                  {h}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Reasoning */}
        {hunt.reasoning && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">Analysis</div>
            <p className="text-sm text-text/80 leading-relaxed whitespace-pre-wrap">
              {hunt.reasoning}
            </p>
          </div>
        )}

        {/* Queries run */}
        {hunt.queries && hunt.queries.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
              Queries ({hunt.queries.length})
            </div>
            <div className="space-y-2">
              {hunt.queries.map((q, i) => (
                <div key={i} className="border border-line/60 rounded-md p-2.5 bg-base">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] uppercase tracking-wider text-accent">
                      {PLATFORM_LABEL[(q.platform || "").toLowerCase()] || q.platform || "query"}
                    </span>
                  </div>
                  <pre className="text-xs font-mono text-text overflow-x-auto whitespace-pre-wrap">
                    {q.query}
                  </pre>
                  {q.rationale && <p className="text-[11px] text-muted mt-1.5">{q.rationale}</p>}
                </div>
              ))}
            </div>
          </div>
        )}

        {err && <p className="text-xs text-danger">{err}</p>}
      </div>
    </Panel>
  );
}
