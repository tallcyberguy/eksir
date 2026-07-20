"use client";

import Link from "next/link";
import type { IncidentEntityLink } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import {
  Monitor, User, Globe, FileDigit, Fingerprint, Boxes,
} from "lucide-react";

const KIND_ICON: Record<string, any> = {
  device: Monitor,
  user: User,
  network_endpoint: Globe,
  file: FileDigit,
  observable: Fingerprint,
};

const KIND_LABEL: Record<string, string> = {
  device: "device",
  user: "user",
  network_endpoint: "network",
  file: "file",
  observable: "observable",
};

/** True once at least one entity is linked. Lets callers hide the panel entirely
 *  (matches HuntPanel/V1ActionsLog returning null on empty). */
export function hasEntities(list?: IncidentEntityLink[] | null): boolean {
  return Array.isArray(list) && list.length > 0;
}

export function EntitiesPanel({ entities }: { entities?: IncidentEntityLink[] | null }) {
  if (!hasEntities(entities)) return null;

  return (
    <Panel title="Entities" icon={<Boxes size={14} className="text-accent" />}>
      <div className="space-y-2">
        {entities!.map((e) => {
          const Icon = KIND_ICON[e.entity_type] ?? Fingerprint;
          const label = KIND_LABEL[e.entity_type] ?? e.entity_type;
          return (
            <div key={e.entity_id} className="flex items-center gap-2 min-w-0">
              <Icon size={14} className="text-muted shrink-0" />
              <Link
                href={`/entities/${e.entity_id}`}
                title={e.display_name}
                className="font-mono text-xs truncate text-accent hover:underline"
              >
                {e.display_name}
              </Link>
              <span className="ml-auto shrink-0 text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border border-line text-muted">
                {e.role || label}
              </span>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
