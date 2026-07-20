"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { X, ExternalLink, Copy, Check, Loader2 } from "lucide-react";

interface Props {
  caseId: string;
  open: boolean;
  onClose: () => void;
}

export function PreviewModal({ caseId, open, onClose }: Props) {
  const [html, setHtml] = useState<string | null>(null);
  const [err, setErr]   = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Fetch fresh HTML each time the modal opens
  useEffect(() => {
    if (!open) return;
    setHtml(null); setErr(null); setCopied(false);
    api.cases.previewHtml(caseId)
      .then(setHtml)
      .catch(e => setErr(e.message));
  }, [open, caseId]);

  // Close on Esc
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  function openInNewTab() {
    if (!html) return;
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const w = window.open(url, "_blank");
    // Best-effort cleanup once the new tab has loaded its own copy.
    setTimeout(() => URL.revokeObjectURL(url), 30_000);
    if (!w) alert("Pop-up was blocked — allow pop-ups for this page.");
  }

  async function copyHtml() {
    if (!html) return;
    try {
      await navigator.clipboard.writeText(html);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e: any) {
      alert(`Copy failed: ${e.message}`);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="bg-surface border border-line rounded-xl shadow-cyber w-full max-w-3xl h-[85vh] flex flex-col overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center gap-3 px-5 py-3 border-b border-line/60">
          <h2 className="text-sm uppercase tracking-[0.18em] text-muted">Notification preview</h2>
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={copyHtml}
              disabled={!html}
              className="flex items-center gap-1.5 px-3 py-1 text-xs border border-line rounded-md hover:border-accent hover:text-accent disabled:opacity-40"
            >
              {copied ? <Check size={12} className="text-positive"/> : <Copy size={12}/>}
              {copied ? "Copied" : "Copy HTML"}
            </button>
            <button
              onClick={openInNewTab}
              disabled={!html}
              className="flex items-center gap-1.5 px-3 py-1 text-xs border border-line rounded-md hover:border-accent hover:text-accent disabled:opacity-40"
            >
              <ExternalLink size={12}/> Open in new tab
            </button>
            <button
              onClick={onClose}
              className="ml-1 p-1 text-muted hover:text-danger rounded"
              title="Close (Esc)"
            >
              <X size={16}/>
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-hidden bg-base">
          {err && (
            <div className="p-6 text-sm text-danger">{err}</div>
          )}
          {!html && !err && (
            <div className="h-full flex items-center justify-center text-muted text-sm">
              <Loader2 size={14} className="animate-spin mr-2"/> Loading preview…
            </div>
          )}
          {html && (
            <iframe
              title="Customer notification preview"
              srcDoc={html}
              sandbox=""
              className="w-full h-full bg-white"
            />
          )}
        </div>
      </div>
    </div>
  );
}
