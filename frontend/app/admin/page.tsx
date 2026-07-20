"use client";

import Link from "next/link";
import { Panel } from "@/components/ui/Panel";

export default function AdminOverview() {
  return (
    <div className="grid lg:grid-cols-2 gap-5">
      <Panel title="Tenants">
        <p className="text-sm text-muted mb-3">
          Manage MSSPs and customer tenants, set the hierarchy, and invite users with
          per-tenant roles. Each user only sees the incidents of tenants they belong to.
        </p>
        <Link href="/admin/tenants" className="text-sm text-accent hover:underline">Manage tenants →</Link>
      </Panel>
      <Panel title="Users">
        <p className="text-sm text-muted mb-3">
          Add analyst / viewer accounts. Bcrypt password hashing, JWT sessions.
        </p>
        <Link href="/admin/users" className="text-sm text-accent hover:underline">Manage users →</Link>
      </Panel>
      <Panel title="Webhook sources">
        <p className="text-sm text-muted mb-3">
          SIEM and SOAR integrations that POST alerts to EKSIR. HMAC-signed.
          Secret is shown once at creation.
        </p>
        <Link href="/admin/webhooks" className="text-sm text-accent hover:underline">Manage webhook sources →</Link>
      </Panel>
      <Panel title="Auto-close rules">
        <p className="text-sm text-muted mb-3">
          Deterministic FP / benign patterns evaluated before the LLM. Mirrors the YAML used by the SKILL workflow.
        </p>
        <Link href="/admin/autoclose" className="text-sm text-accent hover:underline">Manage rules →</Link>
      </Panel>
      <Panel title="LLM backends">
        <p className="text-sm text-muted">
          Virtual model mapping lives in <code className="font-mono">config/litellm.config.yaml</code>.
          A read-only usage view will land here in a follow-up.
        </p>
      </Panel>
    </div>
  );
}
