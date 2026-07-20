"use client";

import { useEffect } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";

// Small pill next to the sidebar "Queue" item: how many cases the current
// analyst has claimed. Polls every 30s (the shim doesn't auto-revalidate).
export function LiveQueueBadge() {
  const { data, mutate } = useSWR<any>("queue.badge.me", () => api.queue.list({ assignee: "me" }));
  useEffect(() => {
    const id = setInterval(() => mutate(), 30000);
    return () => clearInterval(id);
  }, [mutate]);
  const mine = data?.counts?.mine ?? 0;
  if (!mine) return null;
  return (
    <span className="ml-auto text-[10px] tabular-nums bg-accent/20 text-accent rounded px-1.5 py-0.5">
      {mine}
    </span>
  );
}
