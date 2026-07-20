"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import {
  Search, Loader2, Save, Play, Trash2, AlertTriangle, Crosshair, Clock, Sparkles,
} from "lucide-react";

type Translated = {
  s1ql: string; kql: string; sigma: string; explanation: string;
  time_range?: string; status?: string; detail?: string;
};
type Saved = {
  id: string; name: string; nl_query: string; translated: Translated;
  language: string; time_range: string | null; last_run_at: string | null;
};

const LANGS: { key: "s1ql" | "kql" | "sigma"; label: string }[] = [
  { key: "s1ql", label: "S1QL" },
  { key: "kql", label: "KQL" },
  { key: "sigma", label: "Sigma" },
];
const RANGES: { v: string; label: string }[] = [
  { v: "1h", label: "Last 1 hour" }, { v: "4h", label: "Last 4 hours" },
  { v: "24h", label: "Last 24 hours" }, { v: "7d", label: "Last 7 days" },
  { v: "30d", label: "Last 30 days" },
];
const EXAMPLES = [
  "Suspicious PowerShell with encoded commands in the last 4 hours",
  "New external RDP logins this week",
  "Processes spawned by Office apps writing to startup folders",
];

export default function HuntPage() {
  const [question, setQuestion] = useState("");
  const [translating, setTranslating] = useState(false);
  const [translated, setTranslated] = useState<Translated | null>(null);
  const [lang, setLang] = useState<"s1ql" | "kql" | "sigma">("s1ql");
  const [range, setRange] = useState("24h");
  const [selected, setSelected] = useState<string | null>(null);
  const [runMsg, setRunMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const saved = useSWR<{ hunts: Saved[] }>("hunt:saved", api.hunt.listSaved);

  async function translate(q?: string) {
    const text = (q ?? question).trim();
    if (!text || translating) return;
    if (q) setQuestion(q);
    setTranslating(true); setRunMsg(null); setSelected(null);
    try {
      const t: Translated = await api.hunt.translate(text, range);
      setTranslated(t);
      // default to the first dialect that actually produced a query
      const first = LANGS.find((l) => t[l.key])?.key ?? "s1ql";
      setLang(first);
    } catch (e: any) {
      setTranslated({ s1ql: "", kql: "", sigma: "", explanation: "", status: "error", detail: e?.message });
    } finally {
      setTranslating(false);
    }
  }

  function loadSaved(h: Saved) {
    setSelected(h.id);
    setQuestion(h.nl_query);
    setTranslated(h.translated);
    setLang((h.language as any) || "s1ql");
    if (h.time_range) setRange(h.time_range);
    setRunMsg(null);
  }

  async function save() {
    if (!translated) return;
    const name = window.prompt("Name this hunt:", question.slice(0, 60));
    if (!name) return;
    setBusy(true);
    try {
      await api.hunt.createSaved({ name, nl_query: question, translated, language: lang, time_range: range });
      saved.mutate();
    } finally { setBusy(false); }
  }

  async function run() {
    setBusy(true); setRunMsg(null);
    try {
      if (selected) {
        const r = await api.hunt.runSaved(selected);
        setRunMsg(r.message);
        saved.mutate();
      } else {
        setRunMsg("Live execution against SentinelOne is a fast-follow — copy the query into your console to run it.");
      }
    } finally { setBusy(false); }
  }

  async function del(id: string) {
    if (!confirm("Delete this saved hunt?")) return;
    await api.hunt.deleteSaved(id);
    if (selected === id) setSelected(null);
    saved.mutate();
  }

  const query = translated ? translated[lang] : "";
  const blocked = translated?.status === "error" || translated?.status === "empty";

  return (
    <div className="space-y-5">
      {/* Hero */}
      <div>
        <div className="flex items-center gap-2 text-accent text-sm font-mono tracking-wider">
          <Crosshair size={15} /> EKSIR HUNT
        </div>
        <h1 className="text-3xl font-semibold text-text mt-1">Hunt at the speed of thought.</h1>
        <p className="text-muted text-sm mt-2 max-w-2xl">
          Ask in plain English and we&apos;ll translate it to S1QL, KQL, and Sigma. Save the
          questions that matter — execution against SentinelOne is a fast-follow.
        </p>
      </div>

      {/* NL input */}
      <div className="flex gap-2">
        <div className="flex-1 flex items-center gap-2 bg-surface border border-line rounded-lg px-3">
          <Search size={16} className="text-muted shrink-0" />
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && translate()}
            placeholder="e.g. Show me suspicious sudo from contractors in the last 4 hours"
            className="flex-1 bg-transparent py-3 text-sm text-text outline-none"
          />
        </div>
        <button onClick={() => translate()} disabled={translating || !question.trim()}
          className="btn btn-primary px-5 flex items-center gap-1.5 disabled:opacity-50">
          {translating ? <Loader2 size={15} className="animate-spin" /> : <Sparkles size={15} />} Translate
        </button>
      </div>
      <div>
        <div className="text-[10px] uppercase tracking-widest text-muted mb-1.5">Try one of these</div>
        <div className="flex gap-2 flex-wrap">
          {EXAMPLES.map((ex) => (
            <button key={ex} onClick={() => translate(ex)}
              className="text-xs text-muted hover:text-text border border-line rounded-full px-3 py-1.5 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-accent" /> {ex}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-5">
        {/* Saved hunts rail */}
        <div className="rounded-lg border border-line bg-surface/40 p-3">
          <div className="text-xs uppercase tracking-widest text-accent mb-3">Saved hunts</div>
          {saved.isLoading ? (
            <div className="flex items-center gap-2 text-muted text-xs py-4"><Loader2 size={12} className="animate-spin" /> Loading…</div>
          ) : saved.error ? (
            <div className="flex flex-col items-center gap-2 py-6 text-center">
              <AlertTriangle size={18} className="text-danger" />
              <div className="text-xs text-text">Couldn&apos;t load saved hunts.</div>
              <div className="text-[10px] text-muted font-mono">{saved.error.message}</div>
              <button onClick={() => saved.mutate()} className="text-xs border border-line rounded px-2 py-1 text-text hover:bg-surface2/40">Retry</button>
            </div>
          ) : !saved.data?.hunts.length ? (
            <div className="text-xs text-muted py-2">No saved hunts yet. Translate a question, then Save.</div>
          ) : (
            <ul className="space-y-1">
              {saved.data.hunts.map((h) => (
                <li key={h.id}>
                  <div className={`group flex items-start gap-1 rounded px-2 py-1.5 cursor-pointer ${selected === h.id ? "bg-accent/15" : "hover:bg-surface2/40"}`}
                    onClick={() => loadSaved(h)}>
                    <div className="min-w-0 flex-1">
                      <div className="text-xs text-text truncate">{h.name}</div>
                      <div className="text-[10px] text-muted truncate">{h.nl_query}</div>
                    </div>
                    <button onClick={(e) => { e.stopPropagation(); del(h.id); }}
                      className="text-muted hover:text-danger opacity-0 group-hover:opacity-100"><Trash2 size={12} /></button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Editor + results */}
        <div className="space-y-3">
          <div className="rounded-lg border border-line bg-surface/40 overflow-hidden">
            <div className="flex items-center justify-between px-3 py-2 border-b border-line">
              <div className="flex gap-1">
                {LANGS.map((l) => (
                  <button key={l.key} onClick={() => setLang(l.key)}
                    className={`px-2.5 py-1 rounded text-xs ${lang === l.key ? "bg-accent/20 text-text" : "text-muted hover:text-text"}`}>
                    {l.label}
                  </button>
                ))}
                <div className="ml-2 flex items-center gap-1 text-muted">
                  <Clock size={13} />
                  <select value={range} onChange={(e) => setRange(e.target.value)}
                    className="bg-surface border border-line rounded px-1.5 py-1 text-xs text-text">
                    {RANGES.map((r) => <option key={r.v} value={r.v}>{r.label}</option>)}
                  </select>
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={save} disabled={!translated || busy}
                  className="text-xs flex items-center gap-1 border border-line rounded px-2.5 py-1 text-text hover:bg-surface2/40 disabled:opacity-40">
                  <Save size={13} /> Save
                </button>
                <button onClick={run} disabled={!translated || busy}
                  className="btn btn-primary text-xs flex items-center gap-1 disabled:opacity-40">
                  {busy ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />} Run hunt
                </button>
              </div>
            </div>
            <pre className="px-4 py-3 text-[13px] font-mono text-text whitespace-pre-wrap min-h-[180px] overflow-x-auto">
              {translating ? "// translating…"
                : blocked ? `// ${translated?.detail || "No query produced. Try rephrasing."}`
                : query ? query
                : "// Ask a question above to generate a hunt query."}
            </pre>
            {translated?.explanation && !blocked && (
              <div className="px-4 py-2 border-t border-line text-[11px] text-muted">{translated.explanation}</div>
            )}
          </div>

          <div className="rounded-lg border border-line bg-surface/40 p-4">
            <div className="text-sm text-text mb-1">Hunt results</div>
            <div className="text-xs text-muted">
              {runMsg ?? "Press Run to translate-and-save. Live results stream here once the SentinelOne adapter ships."}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
