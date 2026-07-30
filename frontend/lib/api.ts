// Thin fetch client. JWT is stored in localStorage and attached as Bearer.
// In production the backend is reachable at NEXT_PUBLIC_API_BASE (e.g. /api).

const BASE = process.env.NEXT_PUBLIC_API_BASE ?? "/api";
const SCOPE_KEY = "eksir.activeScope";

function token(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem("isoc.token");
}

export function setToken(v: string | null) {
  if (typeof window === "undefined") return;
  if (v) window.localStorage.setItem("isoc.token", v);
  else   window.localStorage.removeItem("isoc.token");
}

export function getActiveScope(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(SCOPE_KEY);
}

export function setActiveScope(tenantId: string | null) {
  if (typeof window === "undefined") return;
  if (tenantId) window.localStorage.setItem(SCOPE_KEY, tenantId);
  else          window.localStorage.removeItem(SCOPE_KEY);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: HeadersInit = { "Content-Type": "application/json", ...(init.headers || {}) };
  const t = token();
  if (t) (headers as Record<string,string>)["Authorization"] = `Bearer ${t}`;
  const scope = getActiveScope();
  if (scope) (headers as Record<string,string>)["X-Tenant-Scope"] = scope;

  const res = await fetch(`${BASE}/v1${path}`, { ...init, headers });
  if (res.status === 401) {
    setToken(null);
    if (typeof window !== "undefined") window.location.assign("/login");
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${body || res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// Like request() but never throws on non-2xx — the caller inspects status.
// Used by the queue claim path so a 409 (lost race) renders an inline banner
// instead of an uncaught error.
async function rawFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers: HeadersInit = { "Content-Type": "application/json", ...(init.headers || {}) };
  const t = token();
  if (t) (headers as Record<string, string>)["Authorization"] = `Bearer ${t}`;
  const scope = getActiveScope();
  if (scope) (headers as Record<string, string>)["X-Tenant-Scope"] = scope;
  return fetch(`${BASE}/v1${path}`, { ...init, headers });
}

// Auth endpoints (login / login-mfa): never auto-redirect on 401 — the login
// page renders the error inline. The generic request() bounces to /login on a
// 401, which is wrong in the middle of signing in.
async function authRequest<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}/v1${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text || res.statusText}`);
  }
  return (await res.json()) as T;
}

// Multipart request — like request() but lets the browser set the multipart
// Content-Type (with boundary). Used by batch-import upload (POST) and report
// branding upload (PUT).
async function requestForm<T>(path: string, form: FormData, method = "POST"): Promise<T> {
  const headers: Record<string, string> = {};
  const t = token();
  if (t) headers["Authorization"] = `Bearer ${t}`;
  const scope = getActiveScope();
  if (scope) headers["X-Tenant-Scope"] = scope;
  const res = await fetch(`${BASE}/v1${path}`, { method, body: form, headers });
  if (res.status === 401) {
    setToken(null);
    if (typeof window !== "undefined") window.location.assign("/login");
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${body || res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// Fetch a binary/HTML endpoint WITH auth (Bearer + tenant scope) and return an
// object URL. Needed because <img>/<iframe>/download links can't carry the
// Authorization header. Caller owns the URL and should URL.revokeObjectURL it.
async function requestBlobUrl(path: string): Promise<string> {
  const headers: Record<string, string> = {};
  const t = token();
  if (t) headers["Authorization"] = `Bearer ${t}`;
  const scope = getActiveScope();
  if (scope) headers["X-Tenant-Scope"] = scope;
  const res = await fetch(`${BASE}/v1${path}`, { headers });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${body || res.statusText}`);
  }
  return URL.createObjectURL(await res.blob());
}

// ── Batch / historical import ────────────────────────────────────────────────
export interface BatchImportJob {
  id: string;
  filename: string;
  customer: string | null;
  source_hint: string | null;
  fmt: string;
  dedupe: boolean;
  status: "queued" | "running" | "completed" | "failed";
  total: number | null;
  processed: number;
  created: number;
  skipped: number;
  failed: number;
  error: string | null;
  created_at: string | null;
  updated_at: string | null;
}
export interface BatchImportPreview {
  preview: { detected_source: string; normalized: any }[];
  count: number;
  capped: boolean;
}

// ── Entities (device / user / network_endpoint / file / observable) ──────────
// Shapes mirror backend/isoc_api/schemas.py (see entity read-API contract).
export interface IncidentEntityLink {
  role: string;
  entity_id: string;
  entity_type: string;
  canonical_key: string;
  display_name: string;
  customer: string | null;
  risk_score: number | null;
  first_seen: string;
  last_seen: string;
}

export interface EntityIncidentRef {
  incident_id: string;
  case_number: string;
  title: string;
  severity: string;
  status: string;
  verdict: string | null;
  role: string;
  created_at: string;
  closed_at: string | null;
  confidence_score: number | null;
  threat_score: number | null;
}

export interface EntityDetail {
  id: string;
  entity_type: string;
  customer: string | null;
  display_name: string;
  canonical_key: string;
  attributes: Record<string, any> | null;
  risk_score: number | null;
  first_seen: string;
  last_seen: string;
  incident_count: number;
  incidents: EntityIncidentRef[];
}

// ── Incident correlation cluster (Phase 2a) ──────────────────────────────────
// Shapes mirror backend/isoc_api/schemas.py (ClusterMember / ClusterSummary).
export interface ClusterMember {
  incident_id: string;
  case_number: string;
  title: string;
  severity: string;
  status: string;
  verdict: string;
  created_at: string;
  confidence_score: number | null;
  threat_score: number | null;
  is_seed: boolean;
  shared_entity: string | null;
}

export interface ClusterSummary {
  id: string;
  cluster_key: string | null;
  title: string | null;
  status: string;
  member_count: number;
  seed_incident_id: string | null;
  members: ClusterMember[];
}

export interface EntitySummary {
  id: string;
  customer: string | null;
  entity_type: string;
  canonical_key: string;
  display_name: string;
  attributes: Record<string, any> | null;
  risk_score: number | null;
  first_seen: string;
  last_seen: string;
  incident_count: number;
}

// GET a paginated list endpoint that returns items + an X-Total-Count header,
// surfaced as { items, total } (same shape / header contract as listIncidents).
async function listWithTotal<T>(
  path: string,
  params: Record<string, string | number | boolean> = {},
): Promise<{ items: T[]; total: number }> {
  const qs = new URLSearchParams(
    Object.entries(params).map(([k, v]) => [k, String(v)]),
  ).toString();
  const headers: HeadersInit = { "Content-Type": "application/json" };
  const t = token();
  if (t) (headers as Record<string, string>)["Authorization"] = `Bearer ${t}`;
  const scope = getActiveScope();
  if (scope) (headers as Record<string, string>)["X-Tenant-Scope"] = scope;
  const res = await fetch(`${BASE}/v1${path}${qs ? "?" + qs : ""}`, { headers });
  if (res.status === 401) {
    setToken(null);
    if (typeof window !== "undefined") window.location.assign("/login");
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${body || res.statusText}`);
  }
  const items = (await res.json()) as T[];
  const total = parseInt(res.headers.get("X-Total-Count") || String(items.length), 10);
  return { items, total };
}

export const api = {
  login: (email: string, password: string) =>
    authRequest<{ mfa_required?: boolean; mfa_token?: string; token?: string; user?: any }>(
      "/auth/login", { email, password }),
  // Second step when the account has MFA enabled: exchange the challenge token
  // + 6-digit code for a full session.
  loginMfa: (mfa_token: string, code: string) =>
    authRequest<{ token: string; user: any }>("/auth/login/mfa", { mfa_token, code }),
  // Best-effort: bumps the server-side token_version (revokes the session), then
  // the caller clears local state. Never throws.
  logout: () => rawFetch("/auth/logout", { method: "POST" }).then(() => {}).catch(() => {}),
  mfa: {
    enroll:   () => request<{ secret: string; otpauth_uri: string; qr_data_uri: string }>("/auth/mfa/enroll", { method: "POST" }),
    activate: (code: string) =>
      request<any>("/auth/mfa/activate", { method: "POST", body: JSON.stringify({ code }) }),
    disable:  (code: string) =>
      request<any>("/auth/mfa/disable", { method: "POST", body: JSON.stringify({ code }) }),
  },
  me: () => request<any>("/auth/me"),
  // Self-service password change. Returns a fresh { token, user }: the server
  // revokes every OTHER session but keeps this one alive, so swap the stored token.
  changePassword: (current_password: string, new_password: string) =>
    request<{ token: string; user: any }>("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }),

  // Dashboard layout (drag-drop) — hierarchy: user override > tenant default > built-in
  dashboardLayout: {
    get:        () => request<{ layout: any; source: string; tenant_id: string | null }>("/me/dashboard-layout"),
    putMine:    (layout: any) =>
      request<any>("/me/dashboard-layout", { method: "PUT", body: JSON.stringify({ layout }) }),
    deleteMine: () =>
      request<any>("/me/dashboard-layout", { method: "DELETE" }),
    putTenant:  (tenantId: string, layout: any) =>
      request<any>(`/admin/tenants/${tenantId}/dashboard-layout`,
                   { method: "PUT", body: JSON.stringify({ layout }) }),
  },

  scope: () => request<{
    is_unlimited: boolean;
    tenants: { id: string; name: string; tier: string; slug: string }[];
  }>("/auth/scope"),

  // Dashboard
  stats: (window: string = "30d") =>
    request<any>(`/dashboard/stats?window=${window}`),
  // Trend time-series (MTTR p50/p90, per-source volume, verdict mix) — Feature 6.
  dashboardTrends: (window: string = "30d") =>
    request<any>(`/dashboard/trends?window=${window}`),

  // Incidents
  //
  // Returns `{ items, total }` so callers can drive pagination off the total
  // count from the X-Total-Count response header. We do a raw fetch here
  // (instead of going through `request()`) because that helper hides headers.
  listIncidents: async (params: Record<string, string | number | boolean> = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params).map(([k, v]) => [k, String(v)])
    ).toString();
    const headers: HeadersInit = { "Content-Type": "application/json" };
    const t = token();
    if (t) (headers as Record<string,string>)["Authorization"] = `Bearer ${t}`;
    const scope = getActiveScope();
    if (scope) (headers as Record<string,string>)["X-Tenant-Scope"] = scope;
    const res = await fetch(`${BASE}/v1/incidents${qs ? "?" + qs : ""}`, { headers });
    if (res.status === 401) {
      setToken(null);
      if (typeof window !== "undefined") window.location.assign("/login");
    }
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`API ${res.status}: ${body || res.statusText}`);
    }
    const items = await res.json() as any[];
    const total = parseInt(res.headers.get("X-Total-Count") || String(items.length), 10);
    return { items, total };
  },
  // Admin-only incident lifecycle
  archiveIncident: (id: string) =>
    request<any>(`/incidents/${id}/archive`, { method: "POST" }),
  restoreIncident: (id: string) =>
    request<any>(`/incidents/${id}/restore`, { method: "POST" }),
  purgeIncident:   (id: string, force = false) =>
    request<any>(`/incidents/${id}${force ? "?force=true" : ""}`, { method: "DELETE" }),
  // Bulk action — see backend POST /incidents/bulk-action
  bulkIncidentAction: (ids: string[], action: string, value?: any) =>
    request<{ action: string; affected: string[]; skipped: { id: string; reason: string }[] }>(
      "/incidents/bulk-action",
      { method: "POST", body: JSON.stringify({ ids, action, value }) },
    ),
  // CSV export URL builder — caller uses <a href> with this. Authoritative
  // because the token has to go in the Authorization header, not the URL,
  // so callers do a fetch + blob-download dance (helper below).
  exportIncidentsCsv: async (params: Record<string, string | number | boolean> = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params).map(([k, v]) => [k, String(v)])
    ).toString();
    const headers: HeadersInit = {};
    const t = token();
    if (t) (headers as Record<string,string>)["Authorization"] = `Bearer ${t}`;
    const scope = getActiveScope();
    if (scope) (headers as Record<string,string>)["X-Tenant-Scope"] = scope;
    const res = await fetch(`${BASE}/v1/incidents/export.csv${qs ? "?" + qs : ""}`, { headers });
    if (!res.ok) throw new Error(`CSV export failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incidents-${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
  listCustomers: () =>
    request<{ name: string; count: number }[]>("/incidents/customers"),
  // Threat-hunt evidence log (raw matched endpoint-activity records). Auth goes
  // in the header, so — like the CSV export — fetch + blob-download.
  downloadHuntEvidence: async (id: string, caseNumber?: string) => {
    const headers: HeadersInit = {};
    const t = token();
    if (t) (headers as Record<string,string>)["Authorization"] = `Bearer ${t}`;
    const scope = getActiveScope();
    if (scope) (headers as Record<string,string>)["X-Tenant-Scope"] = scope;
    const res = await fetch(`${BASE}/v1/incidents/${id}/hunt-evidence`, { headers });
    if (!res.ok) throw new Error(`Hunt evidence download failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hunt-evidence-${caseNumber || id}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
  getIncident: (id: string)      => request<any>(`/incidents/${id}`),
  getTimeline: (id: string)      => request<any[]>(`/incidents/${id}/timeline`),
  getIOCs:     (id: string)      => request<any[]>(`/incidents/${id}/iocs`),
  getIncidentEntities: (id: string) => request<IncidentEntityLink[]>(`/incidents/${id}/entities`),
  // Correlation cluster (Phase 2a) — 200 null when the incident is unclustered.
  getIncidentCluster: (id: string) => request<ClusterSummary | null>(`/incidents/${id}/cluster`),
  getLLMCalls: (id: string)      => request<any[]>(`/incidents/${id}/llm-calls`),

  // Incident collaboration (feature 8 mirror): comments, @mentions, watchers.
  incidentComments:        (id: string) => request<any[]>(`/incidents/${id}/comments`),
  addIncidentComment:      (id: string, body: string) =>
    request<any>(`/incidents/${id}/comments`, { method: "POST", body: JSON.stringify({ body }) }),
  incidentMentionableUsers: (id: string) =>
    request<{ id: string; full_name: string | null; email: string }[]>(`/incidents/${id}/mentionable-users`),
  incidentWatchers:        (id: string) => request<any[]>(`/incidents/${id}/watchers`),
  addIncidentWatcher:      (id: string, userId?: string) =>
    request<any>(`/incidents/${id}/watchers`, { method: "POST", body: JSON.stringify({ user_id: userId }) }),
  removeIncidentWatcher:   (id: string, userId: string) =>
    request<void>(`/incidents/${id}/watchers/${userId}`, { method: "DELETE" }),

  // Entity list (search + pagination) — returns { items, total } via X-Total-Count.
  listEntities: (params: Record<string, string | number | boolean> = {}) =>
    listWithTotal<EntitySummary>("/entities", params),
  // Entity pivot page — one-shot fetch, no polling.
  getEntity: (id: string) => request<EntityDetail>(`/entities/${id}`),
  patchIncident: (id: string, body: any) =>
    request<any>(`/incidents/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  // Assign an incident (default: to self) and stamp the response-SLA anchor
  // (claimed_at) on first claim. Omit assignee_id to take it yourself.
  assignIncident: (id: string, assignee_id?: string | null) =>
    request<{ assignee_id: string; claimed_at: string | null; first_claim: boolean }>(
      `/incidents/${id}/assign`,
      { method: "POST", body: JSON.stringify({ assignee_id: assignee_id ?? null }) },
    ),
  regenerate: (id: string) =>
    request<any>(`/incidents/${id}/regenerate-report`, { method: "POST" }),
  // Human gate: approve the manager's proposed verdict (+ checked response
  // actions) or reject it (optionally re-running synthesis).
  approveIncident: (id: string, body: { verdict?: string; approve_action_ids?: string[]; notes?: string }) =>
    request<any>(`/incidents/${id}/approve`, { method: "POST", body: JSON.stringify(body) }),
  rejectIncident: (id: string, body: { reason: string; requeue?: boolean }) =>
    request<any>(`/incidents/${id}/reject`, { method: "POST", body: JSON.stringify(body) }),
  // Converse with the Incident Manager at the gate (revise proposal / re-task agents).
  managerMessage: (id: string, message: string) =>
    request<any>(`/incidents/${id}/manager`, { method: "POST", body: JSON.stringify({ message }) }),
  // Analyst-direct IOC exclusion from the Technical-tab IOC table.
  excludeIoc: (id: string, body: { ioc_type: string; value: string; scope: "customer" | "global"; notes?: string }) =>
    request<{ status: string; ioc_type: string; value: string; customer: string | null }>(
      `/incidents/${id}/iocs/exclude`, { method: "POST", body: JSON.stringify(body) }),
  // Resolve a batch of Qdrant point IDs → in-scope incidents.
  // Reply shape: { "<qdrant_id>": { id, case_number, title, customer, verdict } }
  lookupByQdrantIds: (qdrant_ids: string[]) =>
    request<Record<string, { id: string; case_number: string; title: string;
                             customer: string | null; verdict: string | null }>>(
      "/incidents/lookup-by-qdrant-ids",
      { method: "POST", body: JSON.stringify({ qdrant_ids }) },
    ),

  // Alerts
  pasteAlert: (raw_text: string, customer?: string, source_hint?: string) =>
    request<any>("/alerts/paste", {
      method: "POST",
      body: JSON.stringify({ raw_text, customer, source_hint }),
    }),

  // ── Exclusions (analyst allowlist) ─────────────────────────────────
  exclusions: {
    stats: () => request<{ total: number; enabled: number; by_type: Record<string, number> }>(
      "/exclusions/stats"),
    list: (params: { q?: string; ioc_type?: string; limit?: number; offset?: number } = {}) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== "")
                              .map(([k, v]) => [k, String(v)])
      ).toString();
      return request<{ total: number; limit: number; offset: number; items: any[] }>(
        `/exclusions${qs ? "?" + qs : ""}`);
    },
    create: (body: { value: string; ioc_type: string; notes?: string; enabled?: boolean; customer?: string }) =>
      request<any>("/exclusions", { method: "POST", body: JSON.stringify(body) }),
    patch:  (id: string, body: Partial<{ value: string; ioc_type: string; notes: string; enabled: boolean }>) =>
      request<any>(`/exclusions/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    remove: (id: string) =>
      request<void>(`/exclusions/${id}`, { method: "DELETE" }),
    // F8 auto-tuned suggestion review queue.
    suggestions: (params: { status?: string; ready_only?: boolean } = {}) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== "")
                              .map(([k, v]) => [k, String(v)])
      ).toString();
      return request<{ items: any[]; count: number }>(`/exclusions/suggestions${qs ? "?" + qs : ""}`);
    },
    approveSuggestion: (id: string) =>
      request<any>(`/exclusions/suggestions/${id}/approve`, { method: "POST" }),
    dismissSuggestion: (id: string) =>
      request<any>(`/exclusions/suggestions/${id}/dismiss`, { method: "POST" }),
  },

  // ── Knowledge base (runbooks / allowlists / asset inventory) ───────
  knowledgeBase: {
    list: (params: { customer?: string; type?: string; limit?: number } = {}) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== "")
                              .map(([k, v]) => [k, String(v)])
      ).toString();
      return request<{ total: number; items: any[] }>(`/knowledge-base${qs ? "?" + qs : ""}`);
    },
    search: (params: { q: string; customer?: string; rule_name?: string; top_k?: number }) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== "")
                              .map(([k, v]) => [k, String(v)])
      ).toString();
      return request<{ total: number; items: any[] }>(`/knowledge-base/search?${qs}`);
    },
    create: (body: {
      type: string; title: string; content: string;
      customer?: string; rule_name?: string; tags?: string[];
    }) => request<any>("/knowledge-base", { method: "POST", body: JSON.stringify(body) }),
    remove: (kbId: string) =>
      request<void>(`/knowledge-base/${kbId}`, { method: "DELETE" }),
  },

  // ── Threat intelligence (IOC feeds) ────────────────────────────────
  threatIntel: {
    stats:  () => request<{ total: number; by_type: Record<string, number>; last_sync: string | null }>(
      "/threat-intel/stats"),
    listIocs: (params: { q?: string; ioc_type?: string; limit?: number; offset?: number } = {}) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== "")
                              .map(([k, v]) => [k, String(v)])
      ).toString();
      return request<{ total: number; limit: number; offset: number; items: any[] }>(
        `/threat-intel/iocs${qs ? "?" + qs : ""}`);
    },
    listFeeds:   () => request<any[]>("/threat-intel/feeds"),
    createFeed:  (body: { name: string; url: string; kind_hint?: string; enabled?: boolean; parser_config?: any }) =>
      request<any>("/threat-intel/feeds", { method: "POST", body: JSON.stringify(body) }),
    patchFeed:   (id: string, body: Partial<{ name: string; url: string; kind_hint: string; enabled: boolean }>) =>
      request<any>(`/threat-intel/feeds/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    deleteFeed:  (id: string) =>
      request<void>(`/threat-intel/feeds/${id}`, { method: "DELETE" }),
    triggerSync: () =>
      request<{ status: string; job_id: string | null }>("/threat-intel/sync", { method: "POST" }),
    // Download analyst-confirmed IOCs (TP, not excluded) as a STIX 2.1 bundle or
    // CSV. Uses rawFetch so the Bearer + tenant-scope headers are attached and
    // the binary body isn't JSON-parsed.
    exportIocs: async (format: "stix" | "csv", windowDays?: number): Promise<Blob> => {
      const qs = new URLSearchParams({ format });
      if (windowDays) qs.set("window_days", String(windowDays));
      const res = await rawFetch(`/threat-intel/export?${qs.toString()}`, { method: "GET" });
      if (!res.ok) throw new Error(`Export failed: API ${res.status}`);
      return res.blob();
    },
  },

  // Forensics
  triage: (ioc: string, type?: string, incident_id?: string) =>
    request<any>(`/forensics/triage${incident_id ? `?incident_id=${incident_id}` : ""}`, {
      method: "POST",
      body: JSON.stringify({ ioc, type }),
    }),
  getJob: (job_id: string) => request<any>(`/forensics/jobs/${job_id}`),
  listJobs: (kind?: string, incident_id?: string) => {
    const qs = new URLSearchParams();
    if (kind)        qs.set("kind", kind);
    if (incident_id) qs.set("incident_id", incident_id);
    const qsStr = qs.toString();
    return request<any[]>(`/forensics/jobs${qsStr ? `?${qsStr}` : ""}`);
  },
  reportMarkdownUrl: (job_id: string) =>
    `${process.env.NEXT_PUBLIC_API_BASE ?? "/api"}/v1/forensics/jobs/${job_id}/report.md`,

  // ── Vision One actions ─────────────────────────────────────────────
  v1: {
    searchEndpoints: (incidentId: string, q: string) =>
      request<any>(`/v1actions/${incidentId}/endpoints?q=${encodeURIComponent(q)}`),
    getEndpoint: (incidentId: string, endpointId: string) =>
      request<any>(`/v1actions/${incidentId}/endpoints/${endpointId}`),
    addToBlocklist: (incidentId: string, body: {
      ioc_type: string; value: string; description?: string;
      scan_action?: string; risk_level?: string;
    }) =>
      request<any>(`/v1actions/${incidentId}/blocklist`, {
        method: "POST", body: JSON.stringify(body),
      }),
    isolate: (incidentId: string, body: { endpoint_name: string; justification: string }) =>
      request<any>(`/v1actions/${incidentId}/isolate`, {
        method: "POST", body: JSON.stringify(body),
      }),
    restore: (incidentId: string, body: { endpoint_name: string; justification: string }) =>
      request<any>(`/v1actions/${incidentId}/restore`, {
        method: "POST", body: JSON.stringify(body),
      }),
    collectFile: (incidentId: string, body: {
      file_path: string; justification: string;
      agent_guid?: string; endpoint_name?: string;
    }) =>
      request<any>(`/v1actions/${incidentId}/collect`, {
        method: "POST", body: JSON.stringify(body),
      }),
    getTask: (incidentId: string, taskId: string) =>
      request<any>(`/v1actions/${incidentId}/tasks/${taskId}`),
  },

  // ── Microsoft Defender actions ─────────────────────────────────────
  defender: {
    isolate: (incidentId: string, body: { machine_id: string; justification: string; isolation_type?: string }) =>
      request<any>(`/defenderactions/${incidentId}/isolate`, {
        method: "POST", body: JSON.stringify(body),
      }),
    unisolate: (incidentId: string, body: { machine_id: string; justification: string }) =>
      request<any>(`/defenderactions/${incidentId}/unisolate`, {
        method: "POST", body: JSON.stringify(body),
      }),
    scan: (incidentId: string, body: { machine_id: string; justification: string; scan_type?: string }) =>
      request<any>(`/defenderactions/${incidentId}/scan`, {
        method: "POST", body: JSON.stringify(body),
      }),
    updateAlert: (incidentId: string, body: {
      alert_id: string; justification: string;
      status?: string; classification?: string; determination?: string;
    }) =>
      request<any>(`/defenderactions/${incidentId}/update-alert`, {
        method: "POST", body: JSON.stringify(body),
      }),
    disableUser: (incidentId: string, body: { user_id: string; justification: string }) =>
      request<any>(`/defenderactions/${incidentId}/disable-user`, {
        method: "POST", body: JSON.stringify(body),
      }),
    enableUser: (incidentId: string, body: { user_id: string; justification: string }) =>
      request<any>(`/defenderactions/${incidentId}/enable-user`, {
        method: "POST", body: JSON.stringify(body),
      }),
  },

  // ── Customer notification cases ───────────────────────────────────
  // (UI calls them "cases"; backend route is /customer-cases to avoid
  // a name collision with the legacy /incidents file that's still called
  // routes/cases.py.)
  cases: {
    list: (params: Record<string, string | number | undefined> = {}) => {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== "" && v !== null) qs.set(k, String(v));
      }
      return request<any[]>(`/customer-cases${qs.toString() ? "?" + qs : ""}`);
    },
    get:    (id: string) => request<any>(`/customer-cases/${id}`),
    create: (body: { source_incident_id: string; locale?: string }) =>
      request<any>("/customer-cases", { method: "POST", body: JSON.stringify(body) }),
    patch:  (id: string, body: any) =>
      request<any>(`/customer-cases/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    setStatus: (id: string, status: "draft" | "reviewed") =>
      request<any>(`/customer-cases/${id}/status`, {
        method: "POST", body: JSON.stringify({ status }),
      }),
    generate: (id: string, force = false) =>
      request<any>(`/customer-cases/${id}/llm-generate`, { method: "POST", body: JSON.stringify({ force }) }),
    saveBody: (id: string, html: string) =>
      request<any>(`/customer-cases/${id}/body`, { method: "POST", body: JSON.stringify({ html }) }),

    // Bundling (Phase-CC4)
    relatedIncidents: (id: string, q?: string) => {
      const qs = q ? `?q=${encodeURIComponent(q)}` : "";
      return request<any[]>(`/customer-cases/${id}/related-incidents${qs}`);
    },
    attachIncident: (id: string, incidentId: string) =>
      request<any>(`/customer-cases/${id}/incidents`, {
        method: "POST", body: JSON.stringify({ incident_id: incidentId }),
      }),
    detachIncident: (id: string, incidentId: string) =>
      request<void>(`/customer-cases/${id}/incidents/${incidentId}`, { method: "DELETE" }),

    // Collaboration (feature 8): comments, @mentions, watchers
    comments:       (id: string) => request<any[]>(`/customer-cases/${id}/comments`),
    addComment:     (id: string, body: string) =>
      request<any>(`/customer-cases/${id}/comments`, { method: "POST", body: JSON.stringify({ body }) }),
    mentionableUsers: (id: string) =>
      request<{ id: string; full_name: string | null; email: string }[]>(`/customer-cases/${id}/mentionable-users`),
    watchers:       (id: string) => request<any[]>(`/customer-cases/${id}/watchers`),
    addWatcher:     (id: string, userId?: string) =>
      request<any>(`/customer-cases/${id}/watchers`, { method: "POST", body: JSON.stringify({ user_id: userId }) }),
    removeWatcher:  (id: string, userId: string) =>
      request<void>(`/customer-cases/${id}/watchers/${userId}`, { method: "DELETE" }),

    // SMTP send (Phase-CC5)
    smtpStatus: () => request<{ configured: boolean }>("/customer-cases/smtp-status"),
    send:       (id: string, subject?: string) =>
      request<any>(`/customer-cases/${id}/send`, { method: "POST", body: JSON.stringify({ subject }) }),

    // Returns the rendered HTML as a string (the endpoint sends text/html, not JSON,
    // so we bypass the JSON-only `request` helper).
    previewHtml: async (id: string): Promise<string> => {
      const headers: Record<string, string> = {};
      const t = typeof window !== "undefined" ? window.localStorage.getItem("isoc.token") : null;
      if (t) headers["Authorization"] = `Bearer ${t}`;
      const scope = typeof window !== "undefined" ? window.localStorage.getItem("eksir.activeScope") : null;
      if (scope) headers["X-Tenant-Scope"] = scope;
      const res = await fetch(`${BASE}/v1/customer-cases/${id}/preview`, { headers });
      if (!res.ok) throw new Error(`Preview failed: HTTP ${res.status}`);
      return res.text();
    },
  },

  // ── Notifications (B1, feature 8) ──────────────────────────────────
  notifications: {
    list: (unreadOnly = false, limit = 30) =>
      request<any[]>(`/notifications?unread_only=${unreadOnly}&limit=${limit}`),
    unreadCount: () => request<{ count: number }>("/notifications/unread-count"),
    markRead: (id: string) => request<any>(`/notifications/${id}/read`, { method: "POST" }),
    markAllRead: () => request<{ ok: boolean }>("/notifications/read-all", { method: "POST" }),
  },

  // ── Audit log ─────────────────────────────────────────────────────
  audit: {
    list: (params: Record<string, string | number | undefined> = {}) => {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== "" && v !== null) qs.set(k, String(v));
      }
      return request<{
        total: number; page: number; page_size: number; items: any[];
      }>(`/audit${qs.toString() ? "?" + qs : ""}`);
    },
    get:    (id: string) => request<any>(`/audit/${id}`),
    facets: () => request<{ actions: any[]; target_types: any[] }>("/audit/facets"),
  },

  // ── Vision One ops (case-independent, per-tenant) ─────────────────
  v1ops: {
    status:           () => request<any>("/v1ops/status"),
    searchEndpoints:  (customer: string, q: string) =>
      request<any>(`/v1ops/endpoints?customer=${encodeURIComponent(customer)}&q=${encodeURIComponent(q)}`),
    getEndpoint:      (customer: string, id: string) =>
      request<any>(`/v1ops/endpoints/${id}?customer=${encodeURIComponent(customer)}`),
    addToBlocklist:   (body: {
      customer: string; ioc_type: string; value: string; description?: string;
      scan_action?: string; risk_level?: string;
    }) => request<any>("/v1ops/blocklist", { method: "POST", body: JSON.stringify(body) }),
    isolate:          (body: { customer: string; endpoint_name: string; justification: string }) =>
      request<any>("/v1ops/isolate", { method: "POST", body: JSON.stringify(body) }),
    restore:          (body: { customer: string; endpoint_name: string; justification: string }) =>
      request<any>("/v1ops/restore", { method: "POST", body: JSON.stringify(body) }),
    collectFile:      (body: {
      customer: string; file_path: string; justification: string;
      agent_guid?: string; endpoint_name?: string;
    }) =>
      request<any>("/v1ops/collect", { method: "POST", body: JSON.stringify(body) }),
    getTask:          (customer: string, id: string) =>
      request<any>(`/v1ops/tasks/${id}?customer=${encodeURIComponent(customer)}`),
    history:          (limit = 25) => request<any[]>(`/v1ops/history?limit=${limit}`),
  },

  // ── Microsoft Defender ops (case-independent, per-tenant) ─────────
  defenderops: {
    status:           () => request<any>("/defenderops/status"),
    searchMachines:   (customer: string, q: string) =>
      request<any>(`/defenderops/machines?customer=${encodeURIComponent(customer)}&q=${encodeURIComponent(q)}`),
    isolate:          (body: {
      customer: string; machine_id: string; justification: string; isolation_type?: string;
    }) => request<any>("/defenderops/isolate", { method: "POST", body: JSON.stringify(body) }),
    unisolate:        (body: { customer: string; machine_id: string; justification: string }) =>
      request<any>("/defenderops/unisolate", { method: "POST", body: JSON.stringify(body) }),
    scan:             (body: {
      customer: string; machine_id: string; justification: string; scan_type?: string;
    }) => request<any>("/defenderops/scan", { method: "POST", body: JSON.stringify(body) }),
    addToBlocklist:   (body: {
      customer: string; indicator_value: string; indicator_type: string;
      justification: string; action?: string; severity?: string;
    }) => request<any>("/defenderops/blocklist", { method: "POST", body: JSON.stringify(body) }),
    disableUser:      (body: { customer: string; user_id: string; justification: string }) =>
      request<any>("/defenderops/disable-user", { method: "POST", body: JSON.stringify(body) }),
    enableUser:       (body: { customer: string; user_id: string; justification: string }) =>
      request<any>("/defenderops/enable-user", { method: "POST", body: JSON.stringify(body) }),
    history:          (limit = 25) => request<any[]>(`/defenderops/history?limit=${limit}`),
  },

  // ── Reports ───────────────────────────────────────────────────────
  reports: {
    customers: (year?: number, month?: number) => {
      const qs = new URLSearchParams();
      if (year)  qs.set("year",  String(year));
      if (month) qs.set("month", String(month));
      return request<any[]>(`/reports/customers${qs.toString() ? "?" + qs : ""}`);
    },
    monthly: (year: number, month: number, customer?: string) => {
      const qs = new URLSearchParams({ year: String(year), month: String(month) });
      if (customer) qs.set("customer", customer);
      return request<any>(`/reports/monthly?${qs}`);
    },
    exportCsvUrl: (year: number, month: number, customer?: string) => {
      const base = process.env.NEXT_PUBLIC_API_BASE ?? "/api";
      const qs = new URLSearchParams({ year: String(year), month: String(month) });
      if (customer) qs.set("customer", customer);
      return `${base}/v1/reports/export/csv?${qs}`;
    },

    // ── Feature 7: branded automated reports ──────────────────────────
    templates: () => request<any[]>("/reports/templates"),
    tenants: () => request<{ id: string; name: string }[]>("/reports/tenants"),

    branding: (tenantId: string) =>
      request<any>(`/reports/branding?tenant_id=${tenantId}`),
    putBranding: (form: FormData) => requestForm<any>("/reports/branding", form, "PUT"),
    brandingLogoUrl: (tenantId: string) => requestBlobUrl(`/reports/branding/${tenantId}/logo`),

    generate: (b: { template_key: string; tenant_id?: string; year?: number; month?: number }) =>
      request<any>("/reports/generate", { method: "POST", body: JSON.stringify(b) }),

    generated: (tenantId?: string, limit = 50) => {
      const qs = new URLSearchParams({ limit: String(limit) });
      if (tenantId) qs.set("tenant_id", tenantId);
      return request<any[]>(`/reports/generated?${qs}`);
    },
    reportHtmlUrl: (id: string) => requestBlobUrl(`/reports/generated/${id}/html`),
    reportPdfUrl: (id: string) => requestBlobUrl(`/reports/generated/${id}/pdf`),
    sendReport: (id: string, subject?: string) =>
      request<any>(`/reports/generated/${id}/send`, {
        method: "POST",
        body: JSON.stringify({ subject }),
      }),

    schedules: () => request<any[]>("/reports/schedules"),
    createSchedule: (b: { template_key: string; cadence: string; tenant_id?: string }) =>
      request<any>("/reports/schedules", { method: "POST", body: JSON.stringify(b) }),
    updateSchedule: (id: string, b: any) =>
      request<any>(`/reports/schedules/${id}`, { method: "PUT", body: JSON.stringify(b) }),
    deleteSchedule: (id: string) =>
      request<void>(`/reports/schedules/${id}`, { method: "DELETE" }),
  },

  // ── Admin ──────────────────────────────────────────────────────────
  admin: {
    // Users
    listUsers: () => request<any[]>("/admin/users"),
    // password omitted → the server generates a temp one and returns it once in
    // `temp_password` (and emails it to the new user).
    createUser: (b: { email: string; password?: string; role?: string; full_name?: string }) =>
      request<any>("/admin/users", { method: "POST", body: JSON.stringify(b) }),
    updateUser: (id: string, b: { role?: string; status?: string; full_name?: string }) =>
      request<any>(`/admin/users/${id}`, { method: "PATCH", body: JSON.stringify(b) }),
    // Returns { temp_password } once; also emails the new credentials to the user.
    resetPassword: (id: string) =>
      request<{ temp_password: string }>(`/admin/users/${id}/reset-password`, { method: "POST" }),
    deleteUser: (id: string) =>
      request<void>(`/admin/users/${id}`, { method: "DELETE" }),

    // Webhook sources
    listWebhooks: () => request<any[]>("/admin/webhook-sources"),
    createWebhook: (b: {
      name: string;
      customer_default?: string;
      source_product?: string;
      ip_allowlist?: string[];
    }) =>
      request<any>("/admin/webhook-sources", { method: "POST", body: JSON.stringify(b) }),
    patchWebhook: (id: string, b: any) =>
      request<any>(`/admin/webhook-sources/${id}`, { method: "PATCH", body: JSON.stringify(b) }),
    deleteWebhook: (id: string) =>
      request<void>(`/admin/webhook-sources/${id}`, { method: "DELETE" }),

    // Tenants
    listTenants:  () => request<any[]>("/admin/tenants"),
    createTenant: (b: { name: string; tier?: string; parent_id?: string | null; tier_label?: string }) =>
      request<any>("/admin/tenants", { method: "POST", body: JSON.stringify(b) }),
    patchTenant:  (id: string, b: any) =>
      request<any>(`/admin/tenants/${id}`, { method: "PATCH", body: JSON.stringify(b) }),
    deleteTenant: (id: string) =>
      request<void>(`/admin/tenants/${id}`, { method: "DELETE" }),

    // Tenant memberships
    listMembers:  (tenantId: string) =>
      request<any[]>(`/admin/tenants/${tenantId}/members`),
    addMember:    (tenantId: string, b: { email: string; role?: string; full_name?: string; password?: string }) =>
      request<any>(`/admin/tenants/${tenantId}/members`, { method: "POST", body: JSON.stringify(b) }),
    patchMember:  (tenantId: string, membershipId: string, b: { role: string }) =>
      request<any>(`/admin/tenants/${tenantId}/members/${membershipId}`, { method: "PATCH", body: JSON.stringify(b) }),
    removeMember: (tenantId: string, membershipId: string) =>
      request<void>(`/admin/tenants/${tenantId}/members/${membershipId}`, { method: "DELETE" }),

    // Auto-close rules
    listAutoclose: () => request<any[]>("/admin/auto-close-rules"),
    createAutoclose: (b: {
      rule_id: string;
      customer?: string;
      match: Record<string, any>;
      verdict: "FP" | "benign";
      reason: string;
      enabled?: boolean;
    }) =>
      request<any>("/admin/auto-close-rules", { method: "POST", body: JSON.stringify(b) }),
    patchAutoclose: (id: string, b: any) =>
      request<any>(`/admin/auto-close-rules/${id}`, { method: "PATCH", body: JSON.stringify(b) }),
    deleteAutoclose: (id: string) =>
      request<void>(`/admin/auto-close-rules/${id}`, { method: "DELETE" }),

    // LLM Settings
    getLLMSettings: () => request<{
      has_config: boolean;
      endpoint_url: string;
      api_key_masked: string;
      model_name: string;
      temperature: number;
      max_tokens: number;
      updated_at: string | null;
      updated_by_email: string | null;
    }>("/admin/settings/llm"),
    saveLLMSettings: (b: {
      endpoint_url: string;
      api_key?: string | null;
      model_name: string;
      temperature: number;
      max_tokens: number;
    }) =>
      request<any>("/admin/settings/llm", { method: "PUT", body: JSON.stringify(b) }),
    testLLMSettings: (overrides?: { endpoint_url?: string; api_key?: string; model_name?: string }) =>
      request<{ success: boolean; model: string; latency_ms: number; response_preview: string }>(
        "/admin/settings/llm/test",
        { method: "POST", body: JSON.stringify(overrides ?? {}) },
      ),
    resetLLMSettings: () =>
      request<void>("/admin/settings/llm", { method: "DELETE" }),

    // Integration credentials (EDR/XDR API keys — ADR-0003/0005)
    listIntegrations: () => request<Array<{
      id: string;
      provider: string;
      identifier: string;
      label: string | null;
      enabled: boolean;
      region: string | null;
      base_url: string | null;
      api_key_masked: string;
      has_key: boolean;
      updated_at: string | null;
      updated_by_email: string | null;
    }>>("/admin/settings/integrations"),
    createIntegration: (b: {
      provider: string;
      identifier: string;
      label?: string | null;
      enabled?: boolean;
      region?: string | null;
      base_url?: string | null;
      api_key?: string | null;
    }) =>
      request<any>("/admin/settings/integrations", { method: "POST", body: JSON.stringify(b) }),
    updateIntegration: (id: string, b: any) =>
      request<any>(`/admin/settings/integrations/${id}`, { method: "PATCH", body: JSON.stringify(b) }),
    deleteIntegration: (id: string) =>
      request<void>(`/admin/settings/integrations/${id}`, { method: "DELETE" }),

    // BYOK — per-tenant LLM provider overrides (Settings → Deployment & AI)
    listBYOK: () => request<Array<{
      tenant_id: string;
      provider: string;
      base_url: string | null;
      model: string | null;
      has_api_key: boolean;
      enabled: boolean;
      last_rotated_at: string | null;
      updated_at: string | null;
    }>>("/admin/byok"),
    upsertBYOK: (b: {
      tenant_id: string;
      provider: string;
      base_url?: string | null;
      model?: string | null;
      api_key?: string | null;
      enabled?: boolean;
    }) =>
      request<any>("/admin/byok", { method: "PUT", body: JSON.stringify(b) }),
    deleteBYOK: (tenantId: string) =>
      request<void>(`/admin/byok/${tenantId}`, { method: "DELETE" }),
  },

  // Cost Dashboard — imputed LLM spend (admin)
  costs: {
    dashboard: (windowDays: number) =>
      request<any>(`/costs/dashboard?window_days=${windowDays}`),
  },

  // SLA Tracking — per-severity resolution SLA
  sla: {
    dashboard: (windowDays: number) =>
      request<any>(`/sla/dashboard?window_days=${windowDays}`),
    targets: () => request<any>("/sla/targets"),
    saveTarget: (b: { severity: string; target_minutes?: number; response_target_minutes?: number }) =>
      request<any>("/sla/targets", { method: "PUT", body: JSON.stringify(b) }),
  },

  // MSSP Dashboard — multi-tenant overview
  mssp: {
    overview: (windowDays: number) =>
      request<any>(`/mssp/overview?window_days=${windowDays}`),
  },

  // MITRE ATT&CK Coverage — tactic × technique density from incident verdicts
  mitre: {
    coverage: (windowDays: number, confirmedOnly: boolean) =>
      request<any>(
        `/mitre/coverage?window_days=${windowDays}&confirmed_only=${confirmedOnly}`,
      ),
  },

  // Hunt (3.13) — NL→query translate + saved hunts (translate-only)
  hunt: {
    translate: (question: string, time_range?: string) =>
      request<any>("/hunt/translate", { method: "POST", body: JSON.stringify({ question, time_range }) }),
    listSaved: () => request<{ hunts: any[] }>("/hunt/saved"),
    createSaved: (b: { name: string; nl_query: string; translated: any; language: string; time_range?: string }) =>
      request<any>("/hunt/saved", { method: "POST", body: JSON.stringify(b) }),
    deleteSaved: (id: string) => request<void>(`/hunt/saved/${id}`, { method: "DELETE" }),
    runSaved: (id: string) => request<any>(`/hunt/saved/${id}/run`, { method: "POST" }),
  },

  // Connectors framework (3.11) — catalog + status + test (admin)
  connectors: {
    catalog: () => request<{ connectors: any[] }>("/connectors/catalog"),
    list: () => request<{ connectors: any[]; catalog: any[] }>("/connectors"),
    test: (id: string) =>
      request<{ ok: boolean | null; status: string; detail: string }>(
        `/connectors/${id}/test`, { method: "POST" },
      ),
    // Pull ingestion sources (scheduled console poll → RECEIVED incident).
    sources: {
      list: () => request<{ sources: any[] }>("/connectors/sources"),
      providers: () => request<{ providers: any[] }>("/connectors/sources/providers"),
      create: (body: Record<string, any>) =>
        request<any>("/connectors/sources", { method: "POST", body: JSON.stringify(body) }),
      update: (id: string, body: Record<string, any>) =>
        request<any>(`/connectors/sources/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
      remove: (id: string) =>
        request<void>(`/connectors/sources/${id}`, { method: "DELETE" }),
      pollNow: (id: string) =>
        request<{ queued: boolean }>(`/connectors/sources/${id}/poll-now`, { method: "POST" }),
      preview: (raw: unknown, customer?: string | null, field_map?: Record<string, string> | null) =>
        request<{ detected_source: string; normalized: any }>(
          "/connectors/sources/preview",
          { method: "POST", body: JSON.stringify({ raw, customer: customer ?? null, field_map: field_map ?? null }) },
        ),
    },
  },

  // Batch / historical import (Sources → Import tab). Admin only.
  ingest: {
    batch: {
      // Upload mode: FormData with `file` + fields (dry_run toggles preview vs start).
      uploadStart: (form: FormData) =>
        requestForm<{ job: BatchImportJob }>("/ingest/batch/upload", form),
      uploadPreview: (form: FormData) =>
        requestForm<BatchImportPreview>("/ingest/batch/upload", form),
      // Server-path mode: JSON body pointing at a file under the workspace volume.
      pathStart: (body: Record<string, any>) =>
        request<{ job: BatchImportJob }>("/ingest/batch/path", {
          method: "POST",
          body: JSON.stringify(body),
        }),
      pathPreview: (body: Record<string, any>) =>
        request<BatchImportPreview>("/ingest/batch/path", {
          method: "POST",
          body: JSON.stringify({ ...body, dry_run: true }),
        }),
      jobs: () => request<{ jobs: BatchImportJob[] }>("/ingest/batch/jobs"),
      job: (id: string) => request<{ job: BatchImportJob }>(`/ingest/batch/jobs/${id}`),
    },
  },

  // Attack Graph (3.15) — per-incident kill-chain path
  attackGraph: {
    incidentPath: (id: string) => request<any>(`/attack-graph/incident/${id}`),
  },

  // Shift Handoff (Phase 3) — read-only handoff board from live state
  shifts: {
    handoff: (windowHours = 12) => request<any>(`/shifts/handoff?window_hours=${windowHours}`),
    handoffMarkdown: async (windowHours = 12): Promise<string> => {
      const res = await rawFetch(`/shifts/handoff.md?window_hours=${windowHours}`);
      return res.ok ? res.text() : "";
    },
  },

  // EASM (Phase 3) — external asset register + on-demand recon (read-only)
  easm: {
    assets: () => request<{ assets: any[] }>("/easm/assets"),
    overview: () => request<any>("/easm/overview"),
    add: (b: { value: string; asset_type?: string; tags?: string[]; notes?: string }) =>
      request<any>("/easm/assets", { method: "POST", body: JSON.stringify(b) }),
    scan: (id: string) => request<any>(`/easm/assets/${id}/scan`, { method: "POST" }),
    portscan: (id: string) => request<any>(`/easm/assets/${id}/portscan`, { method: "POST" }),
    remove: (id: string) => request<void>(`/easm/assets/${id}`, { method: "DELETE" }),
  },

  // Investigation Queue (3.6) — claimable, SLA-ranked worklist
  queue: {
    list: (p: { severity?: string; assignee?: string; tenant?: string; period?: string } = {}) => {
      const entries = Object.entries(p).filter(([, v]) => v != null && v !== "") as [string, string][];
      const qs = new URLSearchParams(entries).toString();
      return request<any>(`/queue${qs ? `?${qs}` : ""}`);
    },
    claim: async (id: string): Promise<{ ok: boolean; status: number; owner_id?: string }> => {
      const res = await rawFetch(`/queue/${id}/claim`, { method: "POST" });
      let body: any = {};
      try { body = await res.json(); } catch { /* empty */ }
      return { ok: res.ok, status: res.status, owner_id: body?.owner_id ?? body?.detail?.owner_id };
    },
    release: (id: string) => request<any>(`/queue/${id}/release`, { method: "POST" }),
    snooze: (id: string, minutes: number) =>
      request<any>(`/queue/${id}/snooze`, { method: "POST", body: JSON.stringify({ minutes }) }),
  },

  // Team Analytics (3.5) — per-analyst leaderboard
  analytics: {
    leaderboard: (windowDays: number) =>
      request<any>(`/analytics/leaderboard?window_days=${windowDays}`),
  },

  // RBAC (3.10) — roles & permissions (admin)
  rbac: {
    listRoles: () => request<any>("/rbac/roles"),
    getRole: (id: string) => request<any>(`/rbac/roles/${id}`),
    listPermissions: () => request<any>("/rbac/permissions"),
    createRole: (b: { name: string; description?: string; permission_ids: string[] }) =>
      request<any>("/rbac/roles", { method: "POST", body: JSON.stringify(b) }),
    updateRole: (id: string, b: { name: string; description?: string; permission_ids: string[] }) =>
      request<any>(`/rbac/roles/${id}`, { method: "PATCH", body: JSON.stringify(b) }),
    deleteRole: (id: string) => request<any>(`/rbac/roles/${id}`, { method: "DELETE" }),
    assignUserRole: (userId: string, roleId: string) =>
      request<any>(`/rbac/users/${userId}/roles`, { method: "POST", body: JSON.stringify({ role_id: roleId }) }),
    removeUserRole: (userId: string, roleId: string) =>
      request<any>(`/rbac/users/${userId}/roles/${roleId}`, { method: "DELETE" }),
  },

  // Autonomy guardrails (3.9) — recommendation policy editor (admin)
  autonomy: {
    policy: () => request<any>("/autonomy/policy"),
    setPolicy: (kind: string, b: { blast_radius?: string; auto: number; review: number; escalation: number; reason?: string }) =>
      request<any>(`/autonomy/policy/${kind}`, { method: "PUT", body: JSON.stringify(b) }),
    resetPolicy: (kind: string) => request<any>(`/autonomy/policy/${kind}`, { method: "DELETE" }),
  },

  // AI Copilot (3.8) — read-only contextual actions
  copilot: {
    status: () => request<{ configured: boolean }>("/copilot/status"),
    actions: () => request<{ actions: { key: string; label: string; scope: string }[] }>("/copilot/actions"),
    ask: (b: { action: string; incident_id?: string; question?: string }) =>
      request<{ answer: string; model: string; status: string; blocked: boolean }>(
        "/copilot/ask", { method: "POST", body: JSON.stringify(b) },
      ),
  },
};
