"use client";

import { useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api } from "@/lib/api";
import { Sparkles, X, Send, Loader2, AlertTriangle } from "lucide-react";

type Action = { key: string; label: string; scope: string };
type Pos = { x: number; y: number };

const POS_KEY = "eksir.copilot.pos";
const BTN = 52; // launcher size (px)

function clamp(p: Pos): Pos {
  if (typeof window === "undefined") return p;
  return {
    x: Math.min(Math.max(8, p.x), window.innerWidth - BTN - 8),
    y: Math.min(Math.max(8, p.y), window.innerHeight - BTN - 8),
  };
}

function defaultPos(): Pos {
  if (typeof window === "undefined") return { x: 24, y: 24 };
  return { x: window.innerWidth - BTN - 24, y: window.innerHeight - BTN - 24 };
}

// Markdown-styled wrapper for a copilot answer (no typography plugin assumed).
const MD =
  "text-sm text-text space-y-2 [&_h2]:font-semibold [&_h3]:font-semibold [&_ul]:list-disc " +
  "[&_ul]:pl-5 [&_ol]:list-decimal [&_ol]:pl-5 [&_li]:my-0.5 [&_code]:font-mono [&_code]:text-accent " +
  "[&_strong]:font-semibold [&_a]:text-accent [&_a]:underline";

export function CopilotDock() {
  const pathname = usePathname();
  const incidentId = (pathname.match(/^\/incidents\/([0-9a-f-]{8,})/i) || [])[1];

  const [pos, setPos] = useState<Pos>({ x: 24, y: 24 });
  const [open, setOpen] = useState(false);
  const [actions, setActions] = useState<Action[]>([]);
  const [action, setAction] = useState("summarize");
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [configured, setConfigured] = useState<boolean | null>(null);

  const drag = useRef<{ dx: number; dy: number; moved: boolean } | null>(null);

  // Restore persisted position.
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(POS_KEY);
      setPos(clamp(raw ? JSON.parse(raw) : defaultPos()));
    } catch { setPos(defaultPos()); }
  }, []);

  // Lazy-load actions + demo status when first opened.
  useEffect(() => {
    if (!open || actions.length) return;
    api.copilot.actions().then((r) => setActions(r.actions)).catch(() => {});
    api.copilot.status().then((r) => setConfigured(r.configured)).catch(() => setConfigured(null));
  }, [open, actions.length]);

  function onPointerDown(e: React.PointerEvent) {
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
    drag.current = { dx: e.clientX - pos.x, dy: e.clientY - pos.y, moved: false };
  }
  function onPointerMove(e: React.PointerEvent) {
    if (!drag.current) return;
    const next = clamp({ x: e.clientX - drag.current.dx, y: e.clientY - drag.current.dy });
    if (Math.abs(next.x - pos.x) + Math.abs(next.y - pos.y) > 4) drag.current.moved = true;
    setPos(next);
  }
  function onPointerUp() {
    if (!drag.current) return;
    if (!drag.current.moved) setOpen((o) => !o);
    else try { window.localStorage.setItem(POS_KEY, JSON.stringify(pos)); } catch { /* */ }
    drag.current = null;
  }

  const selected = actions.find((a) => a.key === action);
  const needsIncident = selected?.scope === "incident" && !incidentId;
  const needsQuestion = selected?.scope === "general" && !question.trim();

  async function ask() {
    if (busy || needsIncident || needsQuestion) return;
    setBusy(true); setAnswer(null); setBlocked(false);
    try {
      const r = await api.copilot.ask({
        action,
        incident_id: incidentId,
        question: question.trim() || undefined,
      });
      setAnswer(r.answer);
      setBlocked(r.blocked);
    } catch (e: any) {
      setAnswer(`**Error:** ${e?.message ?? "request failed"}`);
    } finally {
      setBusy(false);
    }
  }

  // Panel opens above the launcher, right-aligned to it, clamped on-screen.
  const panelStyle: React.CSSProperties = {
    left: Math.min(Math.max(8, pos.x - 360 + BTN), (typeof window !== "undefined" ? window.innerWidth : 800) - 388),
    top: Math.max(8, pos.y - 440),
  };

  return (
    <>
      {open && (
        <div style={panelStyle}
          className="fixed z-50 w-[380px] max-h-[420px] flex flex-col rounded-lg border border-line bg-base shadow-cyber overflow-hidden">
          <div className="flex items-center justify-between px-3 py-2 border-b border-line bg-surface/60">
            <div className="flex items-center gap-2 text-sm text-text">
              <Sparkles size={15} className="text-accent" /> EKSIR Copilot
              {configured === false && (
                <span className="text-[10px] bg-warning/15 text-warning rounded px-1.5 py-0.5">Demo mode</span>
              )}
            </div>
            <button onClick={() => setOpen(false)} className="text-muted hover:text-text"><X size={15} /></button>
          </div>

          <div className="px-3 py-2 space-y-2 border-b border-line">
            <select value={action} onChange={(e) => { setAction(e.target.value); setAnswer(null); }}
              className="w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text">
              {actions.map((a) => (
                <option key={a.key} value={a.key}>{a.label}{a.scope === "incident" ? " (this incident)" : ""}</option>
              ))}
            </select>
            <textarea value={question} onChange={(e) => setQuestion(e.target.value)}
              placeholder={selected?.scope === "general" ? "Ask about an indicator, technique, or term…" : "Optional: add a question…"}
              rows={2}
              className="w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text resize-none" />
            {needsIncident && (
              <div className="text-[11px] text-warning">Open an incident to use this action.</div>
            )}
            <button onClick={ask} disabled={busy || needsIncident || needsQuestion}
              className="btn btn-primary text-sm w-full flex items-center justify-center gap-1.5 disabled:opacity-50">
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />} Ask
            </button>
          </div>

          <div className="px-3 py-2 overflow-y-auto flex-1">
            {blocked && (
              <div className="mb-2 text-[11px] text-danger flex items-center gap-1">
                <AlertTriangle size={12} /> Response withheld by the egress contract.
              </div>
            )}
            {answer ? (
              <div className={MD}><ReactMarkdown remarkPlugins={[remarkGfm]}>{answer}</ReactMarkdown></div>
            ) : (
              <div className="text-[11px] text-muted">
                Read-only assistant — Copilot explains and suggests; it never changes a verdict or fires an action.
              </div>
            )}
          </div>
        </div>
      )}

      <button
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        style={{ left: pos.x, top: pos.y, width: BTN, height: BTN }}
        title="Ask Copilot (drag to move)"
        className="fixed z-50 rounded-full bg-accent text-base shadow-cyber grid place-items-center touch-none cursor-grab active:cursor-grabbing hover:brightness-110">
        <Sparkles size={22} />
      </button>
    </>
  );
}
