"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Search, Plus, X, Loader2, Link2 } from "lucide-react";

interface Attached {
  incident_id: string;
  case_number: string;
  title: string | null;
  severity: string | null;
  rule_name: string | null;
  source_product?: string | null;
  attached_at?: string | null;
}

interface Candidate {
  incident_id: string;
  case_number: string;
  title: string | null;
  severity: string | null;
  rule_name: string | null;
}

interface Props {
  caseId: string;
  attached: Attached[];
  sourceIncidentId: string;
  readOnly: boolean;
  onChange: () => void;
}

function sevPill(s: string | null) {
  const sev = (s || "").toLowerCase();
  if (sev === "critical") return "pill pill-critical";
  if (sev === "high")     return "pill pill-warning";
  if (sev === "medium")   return "pill pill-medium";
  return "pill pill-low";
}

export function AttachedIncidents({ caseId, attached, sourceIncidentId, readOnly, onChange }: Props) {
  const [q, setQ] = useState("");
  const [results, setResults] = useState<Candidate[]>([]);
  const [searching, setSearching] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);

  // Debounced search — fire 300ms after the user stops typing
  useEffect(() => {
    if (timerRef.current) window.clearTimeout(timerRef.current);
    timerRef.current = window.setTimeout(async () => {
      setSearching(true); setErr(null);
      try {
        const rows = await api.cases.relatedIncidents(caseId, q || undefined);
        setResults(rows);
      } catch (e: any) { setErr(e.message); }
      finally { setSearching(false); }
    }, 300);
    return () => { if (timerRef.current) window.clearTimeout(timerRef.current); };
  }, [q, caseId]);

  async function attach(c: Candidate) {
    setBusyId(c.incident_id); setErr(null);
    try {
      await api.cases.attachIncident(caseId, c.incident_id);
      onChange();
      // Optimistically remove from candidates to give instant feedback
      setResults(results.filter(r => r.incident_id !== c.incident_id));
    } catch (e: any) { setErr(e.message); }
    finally { setBusyId(null); }
  }

  async function detach(incidentId: string) {
    if (!confirm("Detach this incident from the case?")) return;
    setBusyId(incidentId); setErr(null);
    try {
      await api.cases.detachIncident(caseId, incidentId);
      onChange();
    } catch (e: any) { setErr(e.message); }
    finally { setBusyId(null); }
  }

  return (
    <Panel title={`Attached incidents (${attached.length})`} icon={<Link2 size={14} className="text-accent"/>}>
      {/* Already-attached list */}
      <div className="space-y-1.5">
        {attached.map(a => {
          const isSource = a.incident_id === sourceIncidentId;
          return (
            <div key={a.incident_id}
                 className="flex items-center gap-2 border border-line/60 rounded-md px-3 py-2 text-sm">
              <Link href={`/incidents/${a.incident_id}`} className="font-mono text-accent hover:underline shrink-0">
                {a.case_number}
              </Link>
              {a.severity && <span className={`${sevPill(a.severity)} shrink-0`}>{a.severity}</span>}
              <span className="text-text truncate flex-1" title={a.title || ""}>{a.title || "—"}</span>
              {isSource ? (
                <span className="text-[10px] uppercase tracking-wider text-muted shrink-0">source</span>
              ) : !readOnly && (
                <button onClick={() => detach(a.incident_id)} disabled={busyId === a.incident_id}
                        title="Detach"
                        className="text-muted hover:text-danger disabled:opacity-40">
                  {busyId === a.incident_id ? <Loader2 size={12} className="animate-spin"/> : <X size={14}/>}
                </button>
              )}
            </div>
          );
        })}
      </div>

      {/* Search + attach (hidden when readOnly) */}
      {!readOnly && (
        <div className="mt-4 pt-4 border-t border-line/60">
          <div className="text-[10px] uppercase tracking-wider text-muted mb-2">
            Attach related incident
          </div>
          <div className="relative mb-2">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted"/>
            <input
              value={q}
              onChange={e => setQ(e.target.value)}
              placeholder="Search same-tenant incidents by title, rule, case number…"
              className="w-full bg-base border border-line rounded-md pl-8 pr-3 py-1.5 text-sm focus:outline-none focus:border-accent"
            />
            {searching && (
              <Loader2 size={12} className="absolute right-3 top-1/2 -translate-y-1/2 animate-spin text-muted"/>
            )}
          </div>

          {err && <p className="text-xs text-danger mb-2">{err}</p>}

          <div className="space-y-1 max-h-72 overflow-y-auto">
            {results.length === 0 && !searching && (
              <p className="text-xs text-muted italic px-2 py-3 text-center">
                {q ? "No matching incidents" : "No other same-tenant incidents to attach"}
              </p>
            )}
            {results.map(r => (
              <button key={r.incident_id}
                      onClick={() => attach(r)}
                      disabled={busyId === r.incident_id}
                      className="w-full text-left flex items-center gap-2 px-2 py-1.5 text-xs rounded hover:bg-surface/60 disabled:opacity-40">
                {busyId === r.incident_id
                  ? <Loader2 size={12} className="animate-spin shrink-0"/>
                  : <Plus size={12} className="text-accent shrink-0"/>}
                <span className="font-mono text-accent shrink-0">{r.case_number}</span>
                {r.severity && <span className={`${sevPill(r.severity)} shrink-0`}>{r.severity}</span>}
                <span className="text-text truncate flex-1">{r.title || r.rule_name || "—"}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}
