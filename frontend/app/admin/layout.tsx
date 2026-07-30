"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

const TABS = [
  { href: "/admin",             label: "Overview" },
  { href: "/admin/users",       label: "Users" },
  { href: "/admin/roles",       label: "Roles" },
  { href: "/admin/webhooks",    label: "Webhook sources" },
  { href: "/admin/autoclose",   label: "Auto-close rules" },
  { href: "/admin/connectors",  label: "Connectors" },
  { href: "/admin/sources",     label: "Sources" },
  { href: "/admin/autonomy",    label: "Autonomy" },
  { href: "/admin/costs",       label: "Costs" },
  { href: "/admin/performance", label: "Performance" },
  { href: "/admin/settings",    label: "Settings" },
];

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { data: me, isLoading } = useSWR("me", () => api.me());

  // Client-side gate: Administration is admin-only. Non-admins see a notice
  // instead of the tabs/pages (which would only 403 on every API call anyway).
  // Not a security boundary; the backend enforces every admin route.
  if (isLoading) {
    return <div className="text-sm text-muted">Loading…</div>;
  }
  if (me?.role !== "admin") {
    return (
      <div className="max-w-lg rounded-md border border-line bg-surface px-5 py-6">
        <div className="text-text font-semibold mb-1">Access restricted</div>
        <p className="text-sm text-muted">
          Administration is available to admins only. Ask an administrator if you need access.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <nav className="flex gap-6 border-b border-line text-sm">
        {TABS.map(t => {
          const active = t.href === "/admin" ? pathname === t.href : pathname.startsWith(t.href);
          return (
            <Link key={t.href} href={t.href}
                  className={cn("pb-2 -mb-px border-b-2",
                    active ? "border-accent text-text" : "border-transparent text-muted hover:text-text"
                  )}>
              {t.label}
            </Link>
          );
        })}
      </nav>
      {children}
    </div>
  );
}
