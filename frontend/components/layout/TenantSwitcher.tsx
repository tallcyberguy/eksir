"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Building2, Check, ChevronDown, Globe } from "lucide-react";
import { api, getActiveScope, setActiveScope } from "@/lib/api";

interface Tenant {
  id: string;
  name: string;
  tier: string;
  slug: string;
}

function tierColor(t: string) {
  return t === "host" ? "text-positive" : t === "mssp" ? "text-warning" : "text-muted";
}

export function TenantSwitcher() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<{ is_unlimited: boolean; tenants: Tenant[] } | null>(null);
  const [active, setActive] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const ref = useRef<HTMLDivElement>(null);

  // Load scope once
  useEffect(() => {
    api.scope()
      .then(s => {
        setData(s);
        // Drop a stale active scope if it's no longer in the user's list
        const cur = getActiveScope();
        if (cur && !s.is_unlimited && !s.tenants.some(t => t.id === cur)) {
          setActiveScope(null);
          setActive(null);
        } else {
          setActive(cur);
        }
      })
      .catch(() => {});
  }, []);

  // Close on outside click
  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    if (open) document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  if (!data) return null;
  // Hide entirely unless the user has multiple choices (or is admin/HOST)
  if (!data.is_unlimited && data.tenants.length <= 1) return null;

  const activeTenant = active ? data.tenants.find(t => t.id === active) : null;
  const label = activeTenant ? activeTenant.name : (data.is_unlimited ? "All tenants" : "All my tenants");

  function pick(tenantId: string | null) {
    setActiveScope(tenantId);
    setActive(tenantId);
    setOpen(false);
    setFilter("");
    // Reload to refetch all scoped data with the new header
    router.refresh();
    // SWR/useEffect-driven data won't auto-refresh from refresh(); a hard reload is the
    // simplest way to make every page-level query pick up the new X-Tenant-Scope header.
    if (typeof window !== "undefined") window.location.reload();
  }

  const filtered = filter.trim()
    ? data.tenants.filter(t =>
        t.name.toLowerCase().includes(filter.toLowerCase()) ||
        t.slug.toLowerCase().includes(filter.toLowerCase()))
    : data.tenants;

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-md border border-line bg-surface/40 hover:border-accent/60 text-sm transition-colors"
        title="Switch tenant context"
      >
        {activeTenant
          ? <Building2 size={14} className={tierColor(activeTenant.tier)}/>
          : <Globe size={14} className="text-accent"/>}
        <span className="text-text max-w-[160px] truncate">{label}</span>
        <ChevronDown size={12} className="text-muted"/>
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 bg-surface border border-line rounded-md shadow-cyber overflow-hidden z-50">
          <div className="p-2 border-b border-line/60">
            <input
              autoFocus
              value={filter}
              onChange={e => setFilter(e.target.value)}
              placeholder="Search tenant…"
              className="w-full bg-base border border-line rounded px-2 py-1 text-sm text-text focus:outline-none focus:border-accent"
            />
          </div>

          <div className="max-h-[60vh] overflow-y-auto">
            {/* "All" option */}
            <button
              onClick={() => pick(null)}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm hover:bg-surface2 text-left"
            >
              <Globe size={14} className="text-accent shrink-0"/>
              <span className="flex-1">
                <span className="text-text">{data.is_unlimited ? "All tenants" : "All my tenants"}</span>
                <div className="text-[10px] text-muted">
                  {data.is_unlimited
                    ? "No filter — sees every tenant"
                    : "Default — sees own scope + descendants"}
                </div>
              </span>
              {!active && <Check size={12} className="text-positive shrink-0"/>}
            </button>

            <div className="border-t border-line/40"/>

            {filtered.length === 0 && (
              <p className="p-3 text-xs text-muted italic text-center">No tenants match.</p>
            )}
            {filtered.map(t => (
              <button
                key={t.id}
                onClick={() => pick(t.id)}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm hover:bg-surface2 text-left"
              >
                <Building2 size={14} className={`${tierColor(t.tier)} shrink-0`}/>
                <span className="flex-1">
                  <span className="text-text">{t.name}</span>
                  <div className="text-[10px] text-muted">
                    <span className="uppercase tracking-wider">{t.tier}</span> · <span className="font-mono">{t.slug}</span>
                  </div>
                </span>
                {active === t.id && <Check size={12} className="text-positive shrink-0"/>}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
