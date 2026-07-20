"use client";

import { useCallback, useEffect, useState } from "react";
import { Panel } from "@/components/ui/Panel";
import { api } from "@/lib/api";
import { AlertTriangle, Check, Loader2, Sparkles, X } from "lucide-react";

type Suggestion = {
  id: string;
  value: string;
  ioc_type: string;
  customer: string | null;
  fp_count: number;
  distinct_rules: number;
  seen_rules: string[];
  distinct_incidents: number;
  last_rule_name: string | null;
  confidence: number;
  status: string;
  last_seen_at: string | null;
};

/**
 * Feature F8 review queue. Surfaces exclusions the platform LEARNED from
 * repeated analyst FP/Benign verdicts on the same IOC for the same customer.
 * Nothing is auto-applied — an admin approves a suggestion into a real scoped
 * exclusion, or dismisses it. Human-in-the-loop by design.
 */
export function SuggestionsPanel() {
  const [items, setItems] = useState<Suggestion[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const res = await api.exclusions.suggestions({ status: "pending", ready_only: true });
      setItems(res.items);
    } catch (e: any) {
      setErr(e.message || "Failed to load suggestions");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  async function approve(s: Suggestion) {
    setBusyId(s.id);
    setErr(null);
    try {
      await api.exclusions.approveSuggestion(s.id);
      reload();
    } catch (e: any) {
      setErr(e.message || "Approve failed");
    } finally {
      setBusyId(null);
    }
  }
  async function dismiss(s: Suggestion) {
    setBusyId(s.id);
    setErr(null);
    try {
      await api.exclusions.dismissSuggestion(s.id);
      reload();
    } catch (e: any) {
      setErr(e.message || "Dismiss failed");
    } finally {
      setBusyId(null);
    }
  }

  // Hide the panel entirely when there's nothing to review.
  if (items !== null && items.length === 0 && !loading && !err) return null;

  return (
    <Panel
      title="Suggested exclusions (auto-tuned)"
      icon={<Sparkles size={14} className="text-accent" />}
    >
      <p className="text-xs text-muted mb-3 leading-relaxed">
        Learned from repeated <b>FP / Benign</b> verdicts on the same IOC for the same customer.
        Guardrails exclude anything that ever rode a TP or that threat intel flagged malicious.
        Approving creates a real customer-scoped exclusion — nothing is applied automatically.
      </p>

      {err && (
        <div className="text-sm text-danger border border-danger/40 bg-danger/10 rounded-md px-3 py-2 mb-3">
          <AlertTriangle size={12} className="inline mr-1.5" />
          {err}
        </div>
      )}

      {loading && !items && (
        <div className="py-6 text-center text-muted">
          <Loader2 size={16} className="animate-spin inline" />
        </div>
      )}

      <div className="space-y-2">
        {(items || []).map((s) => (
          <div
            key={s.id}
            className="flex items-center gap-3 flex-wrap border border-line/60 rounded-md px-3 py-2"
          >
            <span className="text-[10px] uppercase tracking-wider text-accent font-mono w-14">
              {s.ioc_type}
            </span>
            <span className="font-mono text-sm text-text break-all flex-1 min-w-[160px]">
              {s.value}
            </span>
            {s.customer && (
              <span className="pill pill-medium text-[10px]">{s.customer}</span>
            )}
            <span className="pill pill-high text-[10px]" title="Confidence 0–100">
              conf {s.confidence}
            </span>
            <span
              className="text-[11px] text-muted"
              title={`Rules: ${(s.seen_rules || []).join(", ")}`}
            >
              {s.fp_count} FP · {s.distinct_rules} rule(s)
            </span>
            <div className="flex items-center gap-1.5 ml-auto">
              <button
                onClick={() => approve(s)}
                disabled={busyId === s.id}
                className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded-md
                           bg-positive/10 border border-positive/40 text-positive
                           hover:bg-positive/20 disabled:opacity-40"
              >
                <Check size={12} /> Approve
              </button>
              <button
                onClick={() => dismiss(s)}
                disabled={busyId === s.id}
                className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded-md
                           border border-line text-muted hover:text-danger hover:border-danger/40
                           disabled:opacity-40"
              >
                <X size={12} /> Dismiss
              </button>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}
