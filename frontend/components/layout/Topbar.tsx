"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, useRef, useEffect } from "react";
import { Plus, Search, LogOut, ChevronDown, ShieldCheck } from "lucide-react";
import { api, setToken, setActiveScope } from "@/lib/api";
import { TenantSwitcher } from "@/components/layout/TenantSwitcher";
import { NotificationBell } from "@/components/layout/NotificationBell";

interface Props {
  user?: { email?: string; full_name?: string; role?: string } | null;
}

export function Topbar({ user }: Props) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const menuRef = useRef<HTMLDivElement>(null);

  function submitSearch(e: React.FormEvent) {
    e.preventDefault();
    const q = search.trim();
    if (!q) return;
    router.push(`/incidents?q=${encodeURIComponent(q)}`);
    setSearch("");
  }

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setOpen(false);
    };
    if (open) document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  async function logout() {
    await api.logout();    // best-effort: revokes the session server-side (never throws)
    setToken(null);
    setActiveScope(null);  // don't leak the next user's session into a stale scope
    router.replace("/login");
  }

  const label = user?.full_name || user?.email || "Account";
  const initial = (user?.full_name || user?.email || "?").charAt(0).toUpperCase();

  return (
    <header className="h-14 border-b border-line bg-base/70 backdrop-blur px-6 flex items-center gap-4 sticky top-0 z-40">
      <form onSubmit={submitSearch} className="flex-1 max-w-xl relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search incidents — case number, title, rule… (Enter to search)"
          className="w-full bg-surface/80 border border-line rounded-md pl-9 pr-3 py-1.5 text-sm
                     placeholder:text-muted focus:outline-none focus:border-accent/60 focus:shadow-cyber"
        />
      </form>
      <Link href="/incidents/new"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-sm
                       bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20">
        <Plus size={14}/> New investigation
      </Link>

      <TenantSwitcher/>

      <NotificationBell/>

      <div ref={menuRef} className="relative">
        <button
          onClick={() => setOpen(!open)}
          className="flex items-center gap-2 px-2 py-1 rounded-md hover:bg-surface/60 transition-colors"
        >
          <div className="w-8 h-8 rounded-full bg-surface2 border border-line grid place-items-center font-mono text-xs text-accent">
            {initial}
          </div>
          <ChevronDown size={12} className="text-muted"/>
        </button>

        {open && (
          <div className="absolute right-0 top-full mt-2 w-56 bg-surface border border-line rounded-md shadow-cyber overflow-hidden z-50">
            <div className="px-3 py-2 border-b border-line/60">
              <div className="text-sm text-text truncate">{label}</div>
              {user?.email && user?.full_name && (
                <div className="text-[11px] text-muted truncate">{user.email}</div>
              )}
              {user?.role && (
                <div className="text-[10px] uppercase tracking-wider text-accent mt-0.5">{user.role}</div>
              )}
            </div>
            <Link
              href="/account/security"
              onClick={() => setOpen(false)}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-text hover:bg-surface/60 transition-colors"
            >
              <ShieldCheck size={14}/> Security
            </Link>
            <button
              onClick={logout}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-text hover:bg-danger/10 hover:text-danger transition-colors border-t border-line/60"
            >
              <LogOut size={14}/> Sign out
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
