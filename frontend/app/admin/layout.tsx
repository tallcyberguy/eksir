"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
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
  { href: "/admin/settings",    label: "Settings" },
];

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
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
