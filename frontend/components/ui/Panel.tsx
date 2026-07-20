import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export function Panel({
  title, icon, right, children, className,
}: {
  title?: string; icon?: ReactNode; right?: ReactNode;
  children: ReactNode; className?: string;
}) {
  return (
    <section className={cn("panel p-5", className)}>
      {(title || icon || right) && (
        <header className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            {icon}
            {title && <h3 className="text-[10px] tracking-[0.18em] text-muted uppercase">{title}</h3>}
          </div>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

export function StatCard({
  label, value, delta, accent = "text-accent",
}: { label: string; value: string | number; delta?: string; accent?: string }) {
  return (
    <Panel>
      <div className="text-[10px] tracking-[0.18em] text-muted uppercase mb-3">{label}</div>
      <div className={cn("stat-figure", accent)}>{value}</div>
      {delta && <div className="text-xs text-muted mt-2">{delta}</div>}
    </Panel>
  );
}
