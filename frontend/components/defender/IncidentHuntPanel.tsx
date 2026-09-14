"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { KqlHuntPanel } from "./KqlHuntPanel";

// Gates the hunt panel on whether THIS incident's customer has Defender credentials,
// not on the alert's source_product. A phishing or SIEM alert about a user still
// needs Defender sign-in and device telemetry, and gating on the alert's origin
// would hide the panel exactly when an analyst most needs it.
export function IncidentHuntPanel({ incidentId }: { incidentId: string }) {
  const [configured, setConfigured] = useState<boolean | null>(null);

  useEffect(() => {
    let live = true;
    api.defender
      .status(incidentId)
      .then((s) => live && setConfigured(s.configured))
      .catch(() => live && setConfigured(false));
    return () => {
      live = false;
    };
  }, [incidentId]);

  // Render nothing until we know, and nothing at all when this customer has no
  // Defender tenant, because an always-failing panel is worse than no panel.
  if (!configured) return null;

  return (
    <KqlHuntPanel
      run={(kql, max) => api.defender.hunt(incidentId, kql, max)}
      downloadCsv={(kql, max) => api.defender.huntCsv(incidentId, kql, max)}
    />
  );
}
