"use client";

import { useState } from "react";
import { Binary, ChevronDown, ChevronRight, ShieldAlert } from "lucide-react";
import { Panel } from "@/components/ui/Panel";
import { cn } from "@/lib/utils";

/**
 * Renders enrichment.deobfuscation produced by pipeline/deobfuscate.py:
 *
 *   - obfuscation score + band (heuristic, NOT an ML verdict)
 *   - decoded payload layers (collapsible, monospace)
 *   - IOCs surfaced ONLY after decoding (chips)
 *   - YARA-Forge matches on decoded payloads (populated by the worker scan)
 *
 * Renders nothing when there is no deobfuscation data (the common case).
 */
export function DeobfuscationPanel({ enrichment }: { enrichment: any }) {
  const deob = enrichment?.deobfuscation;
  if (!deob || typeof deob !== "object") return null;

  const obf = deob.obfuscation || {};
  const artifacts: any[] = arr(deob.artifacts);
  const decodedIocs: any[] = arr(deob.decoded_iocs);
  const yara: any[] = arr(deob.yara_matches);
  const newIocs = decodedIocs.filter((d) => d.new);

  // Nothing meaningful to show.
  if (
    artifacts.length === 0 &&
    newIocs.length === 0 &&
    yara.length === 0 &&
    Number(obf.score || 0) < 0.4
  ) {
    return null;
  }

  const band = String(obf.band || "none");

  return (
    <Panel
      title="Deobfuscation & Payload Analysis"
      className={band === "heavy" ? "border-danger/40" : band === "moderate" ? "border-warning/40" : ""}
    >
      {/* ── Score header ──────────────────────────────────────────── */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <span className={cn("pill inline-flex items-center gap-1.5 text-[10px]", bandKlass(band))}>
          <ShieldAlert size={12} /> obfuscation {band}
        </span>
        <span className="pill pill-medium text-[10px] font-mono" title="Heuristic score 0–1: symbol-density + obfuscation markers + entropy blend. Not an ML verdict.">
          score {fmt(obf.score)}
        </span>
        <span className="pill pill-medium text-[10px] font-mono">
          {obf.encoded_layers ?? artifacts.length} layer(s) decoded
        </span>
        {newIocs.length > 0 && (
          <span className="pill pill-critical text-[10px]">{newIocs.length} hidden IOC(s)</span>
        )}
        {yara.length > 0 && (
          <span className="pill pill-critical text-[10px]">{yara.length} YARA hit(s)</span>
        )}
      </div>
      <p className="text-[11px] text-muted leading-relaxed mb-4">
        Encoded payloads were decoded deterministically (base64 / PowerShell <code>-EncodedCommand</code> /
        hex / escapes). IOCs surfaced by decoding are merged into triage automatically. The obfuscation
        score is a transparent heuristic, not an ML classifier.
      </p>

      {/* ── IOCs surfaced only after decoding ─────────────────────── */}
      {newIocs.length > 0 && (
        <div className="mb-4">
          <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
            IOCs surfaced only after decoding
          </div>
          <div className="flex flex-col gap-1">
            {newIocs.slice(0, 30).map((d, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <span className="pill pill-high text-[9px] uppercase">{d.type}</span>
                <span className="font-mono text-warning break-all">{defang(String(d.value))}</span>
                <span className="text-[10px] text-muted">via {d.encoding}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── YARA matches on decoded payloads ──────────────────────── */}
      {yara.length > 0 && (
        <div className="mb-4">
          <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
            YARA-Forge matches on decoded payloads
          </div>
          <div className="space-y-1.5">
            {yara.slice(0, 20).map((m, i) => (
              <div key={i} className="flex items-center gap-3 text-sm">
                <span className="pill pill-critical text-[10px] font-mono">{m.rule}</span>
                {m.namespace && <span className="text-xs text-muted font-mono">{m.namespace}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Decoded payload layers ────────────────────────────────── */}
      {artifacts.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
            Decoded payload layers ({artifacts.length})
          </div>
          <div className="space-y-2">
            {artifacts.slice(0, 25).map((a, i) => (
              <PayloadLayer key={a.sha256 || i} artifact={a} />
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

function PayloadLayer({ artifact }: { artifact: any }) {
  const [open, setOpen] = useState(false);
  const full = String(artifact.decoded_text || artifact.snippet || "");
  const snippet = String(artifact.snippet || "");
  const hasMore = full.length > snippet.length;

  return (
    <div className="border border-line/60 rounded-md p-2.5">
      <div className="flex items-center gap-2 flex-wrap mb-1.5 text-[11px]">
        <Binary size={12} className="text-accent2" />
        <span className="pill pill-medium text-[9px] font-mono">{artifact.encoding}</span>
        <span className="text-muted">layer {artifact.layer}</span>
        <span className="text-muted">· {artifact.size} bytes</span>
        <span className="text-muted">· from <code>{artifact.source_field}</code></span>
        {artifact.sha256 && (
          <span className="ml-auto font-mono text-[9px] text-muted/70" title={artifact.sha256}>
            {String(artifact.sha256).slice(0, 12)}…
          </span>
        )}
      </div>
      <pre className="text-[10.5px] bg-base border border-line rounded p-2 overflow-x-auto font-mono whitespace-pre-wrap break-all text-text/90">
        {open ? full : snippet}
      </pre>
      {hasMore && (
        <button
          onClick={() => setOpen((v) => !v)}
          className="mt-1.5 inline-flex items-center gap-1 text-[11px] text-muted hover:text-accent"
        >
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          {open ? "Collapse" : `Show full (${full.length} chars)`}
        </button>
      )}
    </div>
  );
}

// ── helpers ──────────────────────────────────────────────────────────
function bandKlass(band: string) {
  if (band === "heavy") return "pill-critical";
  if (band === "moderate") return "pill-high";
  if (band === "low") return "pill-medium";
  return "pill-resolved";
}

function fmt(n: any): string {
  const v = Number(n);
  return Number.isFinite(v) ? v.toFixed(2) : "—";
}

function arr(v: any): any[] {
  return Array.isArray(v) ? v : [];
}

function defang(v: string): string {
  return String(v)
    .replace(/^http(s?):\/\//, "hxxp$1://")
    .replace(/\.(?=[A-Za-z])/g, "[.]");
}
