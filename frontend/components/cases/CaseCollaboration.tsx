"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Eye, EyeOff, Send } from "lucide-react";

type MUser = { id: string; full_name: string | null; email: string };

const handleOf = (u: MUser) => (u.email || "").split("@")[0];
const labelOf = (u: MUser) => u.full_name || u.email;

function timeAgo(iso?: string | null): string {
  if (!iso) return "";
  const secs = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

// Render a comment body with @mentions highlighted (no dangerouslySetInnerHTML).
function renderBody(body: string) {
  const parts = body.split(/(@[A-Za-z0-9._-]+)/g);
  return parts.map((p, i) =>
    p.startsWith("@") ? (
      <span key={i} className="text-accent font-medium">{p}</span>
    ) : (
      <span key={i}>{p}</span>
    ),
  );
}

export function CaseCollaboration({ caseId }: { caseId: string }) {
  const [meId, setMeId] = useState<string | null>(null);
  const [comments, setComments] = useState<any[]>([]);
  const [watchers, setWatchers] = useState<any[]>([]);
  const [users, setUsers] = useState<MUser[]>([]);
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [menu, setMenu] = useState<{ open: boolean; query: string }>({ open: false, query: "" });
  const taRef = useRef<HTMLTextAreaElement>(null);

  const load = useCallback(() => {
    api.cases.comments(caseId).then(setComments).catch(() => {});
    api.cases.watchers(caseId).then(setWatchers).catch(() => {});
  }, [caseId]);

  useEffect(() => {
    api.me().then((u) => setMeId(u?.id ?? null)).catch(() => {});
    api.cases.mentionableUsers(caseId).then(setUsers).catch(() => {});
    load();
  }, [caseId, load]);

  const amWatching = meId != null && watchers.some((w) => w.user_id === meId);

  async function toggleWatch() {
    try {
      if (amWatching && meId) await api.cases.removeWatcher(caseId, meId);
      else await api.cases.addWatcher(caseId);
      api.cases.watchers(caseId).then(setWatchers).catch(() => {});
    } catch {
      /* non-fatal */
    }
  }

  async function submit() {
    const text = body.trim();
    if (!text) return;
    setBusy(true);
    try {
      await api.cases.addComment(caseId, text);
      setBody("");
      setMenu({ open: false, query: "" });
      load();
    } finally {
      setBusy(false);
    }
  }

  function onBodyChange(v: string) {
    setBody(v);
    const el = taRef.current;
    const pos = el ? el.selectionStart : v.length;
    const m = /(?:^|\s)@([A-Za-z0-9._-]*)$/.exec(v.slice(0, pos));
    setMenu(m ? { open: true, query: m[1].toLowerCase() } : { open: false, query: "" });
  }

  function insertMention(u: MUser) {
    const el = taRef.current;
    const pos = el ? el.selectionStart : body.length;
    const before = body.slice(0, pos).replace(/@([A-Za-z0-9._-]*)$/, `@${handleOf(u)} `);
    setBody(before + body.slice(pos));
    setMenu({ open: false, query: "" });
    el?.focus();
  }

  const matches = menu.open
    ? users
        .filter(
          (u) =>
            handleOf(u).includes(menu.query) || labelOf(u).toLowerCase().includes(menu.query),
        )
        .slice(0, 6)
    : [];

  return (
    <Panel title="Collaboration">
      {/* Watchers + watch toggle */}
      <div className="flex items-center justify-between gap-2 mb-3 pb-3 border-b border-line">
        <div className="text-xs text-muted truncate">
          {watchers.length
            ? `Watching: ${watchers.map((w) => w.full_name || w.email).join(", ")}`
            : "No watchers yet"}
        </div>
        <button
          onClick={toggleWatch}
          className="flex items-center gap-1.5 shrink-0 px-2.5 py-1 rounded text-xs border border-line hover:border-accent text-foreground transition-colors"
        >
          {amWatching ? <EyeOff size={13} /> : <Eye size={13} />}
          {amWatching ? "Unwatch" : "Watch"}
        </button>
      </div>

      {/* Comment thread */}
      <div className="space-y-3 max-h-96 overflow-auto pr-1">
        {comments.length === 0 && <p className="text-sm text-muted">No comments yet.</p>}
        {comments.map((c) => (
          <div key={c.id} className="text-sm">
            <div className="flex items-baseline gap-2">
              <span className="font-medium text-foreground">
                {c.author?.full_name || c.author?.email || "Unknown"}
              </span>
              <span className="text-xs text-muted">{timeAgo(c.created_at)}</span>
            </div>
            <div className="whitespace-pre-wrap text-foreground/90 mt-0.5">{renderBody(c.body)}</div>
          </div>
        ))}
      </div>

      {/* Add comment (with @mention autocomplete) */}
      <div className="relative mt-3">
        <textarea
          ref={taRef}
          value={body}
          onChange={(e) => onBodyChange(e.target.value)}
          placeholder="Comment… type @ to mention a teammate"
          rows={3}
          className="w-full bg-base border border-line rounded-md p-2.5 text-sm focus:outline-none focus:border-accent"
        />
        {menu.open && matches.length > 0 && (
          <div className="absolute z-20 left-2 bottom-16 w-64 bg-surface border border-line rounded-md shadow-lg overflow-hidden">
            {matches.map((u) => (
              <button
                key={u.id}
                onClick={() => insertMention(u)}
                className="w-full text-left px-3 py-1.5 text-sm hover:bg-base flex items-center justify-between gap-2"
              >
                <span className="text-foreground truncate">{labelOf(u)}</span>
                <span className="text-xs text-muted shrink-0">@{handleOf(u)}</span>
              </button>
            ))}
          </div>
        )}
        <div className="flex justify-end mt-2">
          <button
            onClick={submit}
            disabled={busy || !body.trim()}
            className="flex items-center gap-2 px-3 py-1.5 rounded bg-accent text-white text-sm hover:bg-accent/80 transition-colors disabled:opacity-40"
          >
            <Send size={13} /> {busy ? "Posting…" : "Comment"}
          </button>
        </div>
      </div>
    </Panel>
  );
}
