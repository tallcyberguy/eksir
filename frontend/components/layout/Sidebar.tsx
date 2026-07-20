"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard, Boxes, BellRing, Fingerprint, Settings2,
  Wrench, BarChart3, ChevronDown, ScrollText, Radar, BookOpen, Timer, Building2, Grid3x3, ListChecks, Trophy, Crosshair,
  Globe, ClipboardCheck, Network,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ThemeToggle } from "@/components/ThemeToggle";
import { LiveQueueBadge } from "@/components/layout/LiveQueueBadge";

type Item = { label: string; href: string; icon: any; section: "ops"|"response"|"settings" };

const NAV: Item[] = [
  { section: "ops",      label: "Dashboard",   href: "/",            icon: LayoutDashboard },
  { section: "ops",      label: "Queue",       href: "/queue",       icon: ListChecks },
  { section: "ops",      label: "Cases",       href: "/cases",       icon: Boxes },
  { section: "ops",      label: "Incidents",   href: "/incidents",   icon: BellRing },
  { section: "ops",      label: "Forensics",   href: "/forensics",   icon: Fingerprint },
  { section: "ops",      label: "IOCs",        href: "/threat-iocs", icon: Radar },
  { section: "ops",      label: "Entities",    href: "/entities",    icon: Network },
  { section: "ops",      label: "Hunt",        href: "/hunt",        icon: Crosshair },
  { section: "ops",      label: "Attack Surface", href: "/easm",     icon: Globe },
  { section: "ops",      label: "ATT&CK Coverage", href: "/mitre",   icon: Grid3x3 },
  { section: "ops",      label: "Knowledge Base", href: "/knowledge-base", icon: BookOpen },
  { section: "ops",      label: "MSSP",        href: "/mssp",        icon: Building2 },
  { section: "response", label: "Actions",     href: "/actions",     icon: Settings2 },
  { section: "response", label: "Shift Handoff", href: "/shifts",    icon: ClipboardCheck },
  { section: "response", label: "SLA",         href: "/sla",         icon: Timer },
  { section: "response", label: "Team Analytics", href: "/analytics", icon: Trophy },
  { section: "response", label: "Reports",     href: "/reports",     icon: BarChart3 },
  { section: "settings", label: "Audit Log",   href: "/audit",       icon: ScrollText },
  { section: "settings", label: "Administration", href: "/admin",    icon: Wrench },
];

function Group({ title, items, pathname }:{title:string; items:Item[]; pathname:string}) {
  return (
    <div className="mt-6">
      <div className="px-4 mb-2 text-[10px] tracking-[0.18em] text-muted uppercase">{title}</div>
      <ul className="space-y-1 px-2">
        {items.map(({ label, href, icon: Icon }) => {
          const active = pathname === href || (href !== "/" && pathname.startsWith(href));
          return (
            <li key={href}>
              <Link
                href={href}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition",
                  active
                    ? "bg-surface2 text-text shadow-cyber"
                    : "text-muted hover:text-text hover:bg-surface"
                )}
              >
                <Icon size={18} />
                <span>{label}</span>
                {label === "Queue" && <LiveQueueBadge />}
                {(label === "Incidents" || label === "Actions") && (
                  <ChevronDown size={14} className="ml-auto opacity-50" />
                )}
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function Sidebar() {
  const pathname = usePathname();
  return (
    <aside className="w-64 shrink-0 border-r border-line bg-base/80 backdrop-blur min-h-screen">
      <div className="px-5 py-5 flex items-center gap-2">
        <div className="w-8 h-8 rounded-md overflow-hidden shrink-0">
          <img src="/icon.svg" alt="EKSIR" width={32} height={32} className="w-full h-full"/>
        </div>
        <div>
          <div className="font-mono font-semibold tracking-wider text-text">EKSIR</div>
          <div className="text-[10px] text-muted">Security Operations</div>
        </div>
      </div>
      <Group title="Threat Ops" items={NAV.filter(n => n.section==="ops")}      pathname={pathname}/>
      <Group title="Response"   items={NAV.filter(n => n.section==="response")} pathname={pathname}/>
      <Group title="Settings"   items={NAV.filter(n => n.section==="settings")} pathname={pathname}/>
      <div className="mt-4 px-4 pb-4 border-t border-line/40 pt-4">
        <ThemeToggle/>
      </div>
    </aside>
  );
}
