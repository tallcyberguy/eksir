"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Bell } from "lucide-react";
import { api } from "@/lib/api";

export function NotificationBell() {
  const router = useRouter();
  const [count, setCount] = useState(0);
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<any[]>([]);
  const ref = useRef<HTMLDivElement>(null);

  const refreshCount = useCallback(() => {
    api.notifications.unreadCount().then((r) => setCount(r.count)).catch(() => {});
  }, []);

  useEffect(() => {
    refreshCount();
    const t = setInterval(refreshCount, 30_000);
    return () => clearInterval(t);
  }, [refreshCount]);

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    if (open) document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  function toggle() {
    const next = !open;
    setOpen(next);
    if (next) api.notifications.list(false, 15).then(setItems).catch(() => {});
  }

  async function openItem(n: any) {
    try {
      if (!n.read) await api.notifications.markRead(n.id);
    } catch {
      /* non-fatal */
    }
    setOpen(false);
    refreshCount();
    if (n.link) router.push(n.link);
  }

  async function markAll() {
    await api.notifications.markAllRead().catch(() => {});
    setItems(items.map((i) => ({ ...i, read: true })));
    setCount(0);
  }

  return (
    <div ref={ref} className="relative">
      <button
        onClick={toggle}
        aria-label="Notifications"
        className="relative w-9 h-9 grid place-items-center rounded-md hover:bg-surface/60 text-muted hover:text-foreground transition-colors"
      >
        <Bell size={18} />
        {count > 0 && (
          <span className="absolute top-1 right-1 min-w-[16px] h-4 px-1 rounded-full bg-danger text-white text-[10px] leading-4 text-center">
            {count > 9 ? "9+" : count}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 bg-surface border border-line rounded-md shadow-cyber overflow-hidden z-50">
          <div className="flex items-center justify-between px-3 py-2 border-b border-line/60">
            <span className="text-sm text-text">Notifications</span>
            <button onClick={markAll} className="text-xs text-accent hover:underline">
              Mark all read
            </button>
          </div>
          <div className="max-h-96 overflow-auto">
            {items.length === 0 && (
              <p className="px-3 py-6 text-sm text-muted text-center">Nothing yet.</p>
            )}
            {items.map((n) => (
              <button
                key={n.id}
                onClick={() => openItem(n)}
                className={`w-full text-left px-3 py-2 border-b border-line/40 hover:bg-base transition-colors ${
                  n.read ? "" : "bg-accent/5"
                }`}
              >
                <div className="flex items-start gap-2">
                  {!n.read && <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-accent shrink-0" />}
                  <div className="min-w-0">
                    <div className="text-sm text-text truncate">{n.title}</div>
                    {n.body && <div className="text-xs text-muted line-clamp-2">{n.body}</div>}
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
