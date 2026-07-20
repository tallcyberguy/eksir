"use client";

import { useState, useEffect } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { CheckCircle, AlertTriangle, Loader2, Eye, EyeOff, Zap, RotateCcw, Plus, Trash2, Pencil, X } from "lucide-react";

// Shared input class matching the rest of the admin UI
const INPUT = "w-full bg-base border border-line rounded-md px-3 py-2 text-sm text-text font-mono focus:outline-none focus:border-accent/60 placeholder:text-muted/50";
const INPUT_SM = "w-40 bg-base border border-line rounded-md px-3 py-2 text-sm text-text font-mono focus:outline-none focus:border-accent/60";

type LLMSettings = {
  has_config: boolean;
  endpoint_url: string;
  api_key_masked: string;
  model_name: string;
  temperature: number;
  max_tokens: number;
  updated_at: string | null;
  updated_by_email: string | null;
};

const DEFAULT_FORM = {
  endpoint_url: "",
  api_key: "",
  model_name: "",
  temperature: 0.2,
  max_tokens: 4096,
};

export default function LLMSettingsPage() {
  const { data, mutate, isLoading } = useSWR<LLMSettings>(
    "admin.llm-settings",
    () => api.admin.getLLMSettings(),
  );

  const [form, setForm] = useState(DEFAULT_FORM);
  const [showKey, setShowKey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [reverting, setReverting] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    latency_ms?: number;
    model?: string;
    error?: string;
  } | null>(null);

  // Populate form once data loads
  useEffect(() => {
    if (!data) return;
    setForm((prev) => ({
      ...prev,
      endpoint_url: data.endpoint_url,
      model_name: data.model_name,
      temperature: data.temperature,
      max_tokens: data.max_tokens,
      api_key: "", // always blank — user must retype to change
    }));
  }, [data]);

  function set<K extends keyof typeof form>(k: K, v: (typeof form)[K]) {
    setForm((prev) => ({ ...prev, [k]: v }));
    setSaved(false);
    setTestResult(null);
  }

  async function handleSave() {
    setBusy(true);
    setErr(null);
    setSaved(false);
    try {
      await api.admin.saveLLMSettings({
        endpoint_url: form.endpoint_url,
        api_key: form.api_key.trim() || null,
        model_name: form.model_name,
        temperature: form.temperature,
        max_tokens: form.max_tokens,
      });
      setSaved(true);
      setForm((prev) => ({ ...prev, api_key: "" }));
      await mutate();
    } catch (e: any) {
      setErr(e.message ?? "Save failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    setErr(null);
    try {
      // Always pass current form values so the test uses what you see,
      // not what was last saved.
      const r = await api.admin.testLLMSettings({
        endpoint_url: form.endpoint_url || undefined,
        api_key: form.api_key.trim() || undefined,
        model_name: form.model_name || undefined,
      });
      setTestResult({ success: true, latency_ms: r.latency_ms, model: r.model });
    } catch (e: any) {
      setTestResult({ success: false, error: e.message ?? "Connection failed" });
    } finally {
      setTesting(false);
    }
  }

  async function handleRevert() {
    if (!confirm(
      "Revert to environment defaults?\n\nThis deletes the custom LLM config and routes all calls back through the LiteLLM proxy (tiered isoc-fast / isoc-deep → Claude)."
    )) return;
    setReverting(true);
    setErr(null);
    setSaved(false);
    setTestResult(null);
    try {
      await api.admin.resetLLMSettings();
      await mutate();
    } catch (e: any) {
      setErr(e.message ?? "Revert failed");
    } finally {
      setReverting(false);
    }
  }

  return (
    <div className="max-w-2xl space-y-5">
      <IntegrationsPanel />
      <BYOKPanel />
      <Panel title="LLM Configuration">
        {isLoading ? (
          <div className="flex items-center gap-2 text-muted text-sm py-4">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : (
          <div className="space-y-5 pt-1">

            {/* Current state banner */}
            {data && (
              <div className="rounded border border-line bg-surface/50 px-4 py-3 text-xs text-muted space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full flex-none ${data.has_config ? "bg-positive" : "bg-warning"}`} />
                  <span>
                    {data.has_config
                      ? "Using admin-configured endpoint"
                      : "Using environment variable defaults"}
                  </span>
                </div>
                {data.has_config && (
                  <>
                    <div>Current key: <span className="font-mono text-text">{data.api_key_masked}</span></div>
                    {data.updated_by_email && (
                      <div>
                        Last updated by <span className="text-text">{data.updated_by_email}</span>
                        {data.updated_at && <> on {new Date(data.updated_at).toLocaleString()}</>}
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* Endpoint URL */}
            <div className="space-y-1.5">
              <label className="text-xs tracking-widest uppercase text-muted">Endpoint URL</label>
              <input
                type="text"
                value={form.endpoint_url}
                onChange={(e) => set("endpoint_url", e.target.value)}
                placeholder="http://litellm:4000"
                className={INPUT}
              />
              <p className="text-[11px] text-muted">
                Base URL of your LiteLLM proxy or local model server.{" "}
                <code className="bg-surface2 px-0.5 rounded">/v1</code> is appended automatically if not present.
                {" "}Examples:{" "}
                <code className="bg-surface2 px-0.5 rounded">http://litellm:4000</code>
                {" · "}
                <code className="bg-surface2 px-0.5 rounded">http://host.docker.internal:11434</code> (Ollama)
              </p>
            </div>

            {/* API Key */}
            <div className="space-y-1.5">
              <label className="text-xs tracking-widest uppercase text-muted">API Key</label>
              <div className="relative">
                <input
                  type={showKey ? "text" : "password"}
                  value={form.api_key}
                  onChange={(e) => set("api_key", e.target.value)}
                  placeholder={data?.has_config ? "Leave blank to keep current key" : "sk-…"}
                  className={INPUT + " pr-10"}
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => setShowKey((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-text"
                  title={showKey ? "Hide" : "Show"}
                >
                  {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              <p className="text-[11px] text-muted">
                Stored encrypted at rest. Leave blank to keep the existing key.
              </p>
            </div>

            {/* Model name */}
            <div className="space-y-1.5">
              <label className="text-xs tracking-widest uppercase text-muted">Model</label>
              <input
                type="text"
                value={form.model_name}
                onChange={(e) => set("model_name", e.target.value)}
                placeholder="seneca-cyber"
                className={INPUT}
              />
              <p className="text-[11px] text-muted">
                Ollama model name, virtual name from{" "}
                <code className="bg-surface2 px-0.5 rounded">litellm.config.yaml</code>, or a
                direct provider model (e.g.{" "}
                <code className="bg-surface2 px-0.5 rounded">gpt-4o</code>,{" "}
                <code className="bg-surface2 px-0.5 rounded">claude-sonnet-4-5</code>).
              </p>
            </div>

            {/* Temperature */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs tracking-widest uppercase text-muted">Temperature</label>
                <span className="text-sm font-mono text-text tabular-nums">
                  {form.temperature.toFixed(2)}
                </span>
              </div>
              <input
                type="range"
                min={0}
                max={2}
                step={0.05}
                value={form.temperature}
                onChange={(e) => set("temperature", parseFloat(e.target.value))}
                className="w-full accent-accent"
              />
              <div className="flex justify-between text-[10px] text-muted">
                <span>0 — deterministic</span>
                <span>1 — balanced</span>
                <span>2 — creative</span>
              </div>
            </div>

            {/* Max tokens */}
            <div className="space-y-1.5">
              <label className="text-xs tracking-widest uppercase text-muted">Max Tokens</label>
              <input
                type="number"
                min={1}
                max={65536}
                step={256}
                value={form.max_tokens}
                onChange={(e) => set("max_tokens", parseInt(e.target.value, 10) || 4096)}
                className={INPUT_SM}
              />
              <p className="text-[11px] text-muted">
                Maximum tokens the model may generate per call (1–65536).
              </p>
            </div>

            {/* Error / success feedback */}
            {err && (
              <div className="flex items-center gap-2 text-danger text-sm">
                <AlertTriangle size={14} /> {err}
              </div>
            )}
            {saved && (
              <div className="flex items-center gap-2 text-positive text-sm">
                <CheckCircle size={14} /> Settings saved.
              </div>
            )}

            {/* Test connection result */}
            {testResult && (
              <div className={`rounded border px-4 py-3 text-sm space-y-1 ${
                testResult.success
                  ? "border-positive/40 bg-positive/5 text-positive"
                  : "border-danger/40 bg-danger/5 text-danger"
              }`}>
                {testResult.success ? (
                  <>
                    <div className="flex items-center gap-2 font-medium">
                      <CheckCircle size={14} /> Connection OK
                    </div>
                    <div className="text-xs text-muted">
                      Model: <span className="text-text font-mono">{testResult.model}</span>
                      {" · "}
                      Latency: <span className="text-text font-mono">{testResult.latency_ms} ms</span>
                    </div>
                  </>
                ) : (
                  <div className="flex items-center gap-2">
                    <AlertTriangle size={14} /> {testResult.error}
                  </div>
                )}
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={handleSave}
                disabled={busy || !form.endpoint_url || !form.model_name}
                className="btn btn-primary"
              >
                {busy && <Loader2 size={14} className="animate-spin" />}
                {busy ? "Saving…" : "Save"}
              </button>

              <button
                onClick={handleTest}
                disabled={testing || busy}
                className="btn btn-ghost flex items-center gap-1.5"
                title="Test the values currently in the form (before saving)"
              >
                {testing ? <Loader2 size={14} className="animate-spin" /> : <Zap size={14} />}
                {testing ? "Testing…" : "Test connection"}
              </button>

              {data?.has_config && (
                <button
                  onClick={handleRevert}
                  disabled={reverting || busy}
                  className="btn btn-ghost flex items-center gap-1.5 ml-auto text-muted hover:text-danger"
                  title="Delete custom config and route back through LiteLLM (Claude)"
                >
                  {reverting ? <Loader2 size={14} className="animate-spin" /> : <RotateCcw size={14} />}
                  {reverting ? "Reverting…" : "Revert to environment defaults"}
                </button>
              )}
            </div>

          </div>
        )}
      </Panel>
    </div>
  );
}

// ── Integration API keys (EDR/XDR credentials — ADR-0003/0005) ─────────────
type Integration = {
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
};

const V1_REGIONS = ["us", "eu", "jp", "au", "sg", "in", "mea"];
const BLANK_INTEG = {
  provider: "vision_one",
  identifier: "",
  label: "",
  region: "eu",
  base_url: "",
  api_key: "",
  enabled: true,
};

function IntegrationsPanel() {
  const { data, mutate, isLoading } = useSWR<Integration[]>(
    "admin.integrations",
    () => api.admin.listIntegrations(),
  );

  const [form, setForm] = useState<typeof BLANK_INTEG>(BLANK_INTEG);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [showKey, setShowKey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function set<K extends keyof typeof form>(k: K, v: (typeof form)[K]) {
    setForm((p) => ({ ...p, [k]: v }));
    setErr(null);
  }
  function resetForm() {
    setForm(BLANK_INTEG);
    setEditingId(null);
    setShowKey(false);
    setErr(null);
  }
  function startEdit(r: Integration) {
    setEditingId(r.id);
    setForm({
      provider: r.provider,
      identifier: r.identifier,
      label: r.label ?? "",
      region: r.region ?? "eu",
      base_url: r.base_url ?? "",
      api_key: "",
      enabled: r.enabled,
    });
    setShowKey(false);
    setErr(null);
  }

  async function save() {
    if (!form.identifier.trim()) {
      setErr("Identifier is required (customer for Vision One, console host for SentinelOne).");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const body = {
        provider: form.provider,
        identifier: form.identifier.trim(),
        label: form.label.trim() || null,
        enabled: form.enabled,
        region: form.provider === "vision_one" ? form.region : null,
        base_url: form.provider === "sentinelone" ? form.base_url.trim() || null : null,
        api_key: form.api_key.trim() || null,
      };
      if (editingId) await api.admin.updateIntegration(editingId, body);
      else await api.admin.createIntegration(body);
      resetForm();
      await mutate();
    } catch (e: any) {
      setErr(e.message ?? "Save failed");
    } finally {
      setBusy(false);
    }
  }

  async function remove(r: Integration) {
    if (!confirm(`Delete ${r.provider} integration "${r.identifier}"? This cannot be undone.`)) return;
    try {
      await api.admin.deleteIntegration(r.id);
      if (editingId === r.id) resetForm();
      await mutate();
    } catch (e: any) {
      setErr(e.message ?? "Delete failed");
    }
  }

  const isV1 = form.provider === "vision_one";

  return (
    <Panel title="Integration API Keys">
      <div className="space-y-5 pt-1">
        <p className="text-[11px] text-muted">
          EDR/XDR credentials for auto-enrichment (Trend Micro Vision One, SentinelOne).
          Stored encrypted at rest; admin-only. For Vision One, identifier{" "}
          <code className="bg-surface2 px-0.5 rounded">default</code> is the global fallback.
        </p>

        {/* Existing integrations */}
        {isLoading ? (
          <div className="flex items-center gap-2 text-muted text-sm py-2">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : (data && data.length > 0) ? (
          <div className="rounded border border-line divide-y divide-line">
            {data.map((r) => (
              <div key={r.id} className="flex items-center gap-3 px-3 py-2 text-sm">
                <span
                  className={`w-2 h-2 rounded-full flex-none ${r.enabled ? "bg-positive" : "bg-muted/40"}`}
                  title={r.enabled ? "enabled" : "disabled"}
                />
                <div className="min-w-0 flex-1">
                  <div className="text-text truncate">
                    <span className="font-mono">{r.provider}</span>
                    {" · "}
                    <span className="font-mono">{r.identifier}</span>
                    {r.region && <span className="text-muted"> · {r.region}</span>}
                    {r.base_url && <span className="text-muted"> · {r.base_url}</span>}
                  </div>
                  <div className="text-[11px] text-muted">
                    key <span className="font-mono text-text">{r.api_key_masked}</span>
                    {r.label && <> · {r.label}</>}
                    {r.updated_by_email && <> · by {r.updated_by_email}</>}
                  </div>
                </div>
                <button onClick={() => startEdit(r)} className="text-muted hover:text-text" title="Edit">
                  <Pencil size={14} />
                </button>
                <button onClick={() => remove(r)} className="text-muted hover:text-danger" title="Delete">
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-sm text-muted">No integrations configured yet.</div>
        )}

        {/* Add / edit form */}
        <div className="rounded border border-line bg-surface/40 p-4 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs tracking-widest uppercase text-muted">
              {editingId ? "Edit integration" : "Add integration"}
            </span>
            {editingId && (
              <button onClick={resetForm} className="text-muted hover:text-text flex items-center gap-1 text-xs">
                <X size={12} /> cancel
              </button>
            )}
          </div>

          <div className="flex gap-3">
            <div className="space-y-1.5 flex-1">
              <label className="text-xs tracking-widest uppercase text-muted">Provider</label>
              <select value={form.provider} onChange={(e) => set("provider", e.target.value as any)} className={INPUT_SM + " w-full"}>
                <option value="vision_one">vision_one</option>
                <option value="sentinelone">sentinelone</option>
              </select>
            </div>
            {isV1 ? (
              <div className="space-y-1.5 flex-1">
                <label className="text-xs tracking-widest uppercase text-muted">Region</label>
                <select value={form.region} onChange={(e) => set("region", e.target.value)} className={INPUT_SM + " w-full"}>
                  {V1_REGIONS.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
            ) : (
              <div className="space-y-1.5 flex-[2]">
                <label className="text-xs tracking-widest uppercase text-muted">Console host</label>
                <input type="text" value={form.base_url} onChange={(e) => set("base_url", e.target.value)}
                       placeholder="euce1-105.sentinelone.net" className={INPUT} />
              </div>
            )}
          </div>

          <div className="space-y-1.5">
            <label className="text-xs tracking-widest uppercase text-muted">Identifier</label>
            <input type="text" value={form.identifier} onChange={(e) => set("identifier", e.target.value)}
                   placeholder={isV1 ? "customer name (or 'default' for global)" : "console host (same as above)"}
                   className={INPUT} />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs tracking-widest uppercase text-muted">API Key</label>
            <div className="relative">
              <input type={showKey ? "text" : "password"} value={form.api_key} onChange={(e) => set("api_key", e.target.value)}
                     placeholder={editingId ? "Leave blank to keep current key" : "paste API key…"}
                     className={INPUT + " pr-10"} autoComplete="new-password" />
              <button type="button" onClick={() => setShowKey((v) => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-text"
                      title={showKey ? "Hide" : "Show"}>
                {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
            <p className="text-[11px] text-muted">Stored encrypted at rest. Leave blank when editing to keep the existing key.</p>
          </div>

          <div className="flex gap-3">
            <div className="space-y-1.5 flex-1">
              <label className="text-xs tracking-widest uppercase text-muted">Label (optional)</label>
              <input type="text" value={form.label} onChange={(e) => set("label", e.target.value)}
                     placeholder="e.g. EU console 105" className={INPUT} />
            </div>
            <label className="flex items-center gap-2 text-sm text-text self-end pb-2">
              <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} className="accent-accent" />
              Enabled
            </label>
          </div>

          {err && (
            <div className="flex items-center gap-2 text-danger text-sm">
              <AlertTriangle size={14} /> {err}
            </div>
          )}

          <button onClick={save} disabled={busy} className="btn btn-primary flex items-center gap-1.5">
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
            {busy ? "Saving…" : editingId ? "Update integration" : "Add integration"}
          </button>
        </div>
      </div>
    </Panel>
  );
}

// ── BYOK — per-tenant LLM provider overrides (Deployment & AI) ──────────────
type BYOK = {
  tenant_id: string;
  provider: string;
  base_url: string | null;
  model: string | null;
  has_api_key: boolean;
  enabled: boolean;
  last_rotated_at: string | null;
  updated_at: string | null;
};

const BYOK_PROVIDERS = ["openai", "anthropic", "azure_openai", "ollama", "vllm", "litellm", "custom"];
const BYOK_NEEDS_BASE_URL = new Set(["azure_openai", "ollama", "vllm", "litellm", "custom"]);
const BYOK_NEEDS_KEY = new Set(["openai", "anthropic", "azure_openai"]);
const BLANK_BYOK = { tenant_id: "", provider: "openai", base_url: "", model: "", api_key: "", enabled: true };

function BYOKPanel() {
  const { data, mutate, isLoading } = useSWR<BYOK[]>("admin.byok", () => api.admin.listBYOK());
  const { data: tenants } = useSWR<Array<{ id: string; name: string }>>(
    "admin.tenants-for-byok",
    () => api.admin.listTenants(),
  );

  const [form, setForm] = useState<typeof BLANK_BYOK>(BLANK_BYOK);
  const [editing, setEditing] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const tenantName = (id: string) => tenants?.find((t) => t.id === id)?.name ?? id;

  function set<K extends keyof typeof form>(k: K, v: (typeof form)[K]) {
    setForm((p) => ({ ...p, [k]: v }));
    setErr(null);
  }
  function resetForm() {
    setForm(BLANK_BYOK);
    setEditing(false);
    setShowKey(false);
    setErr(null);
  }
  function startEdit(r: BYOK) {
    setEditing(true);
    setForm({
      tenant_id: r.tenant_id,
      provider: r.provider,
      base_url: r.base_url ?? "",
      model: r.model ?? "",
      api_key: "",
      enabled: r.enabled,
    });
    setShowKey(false);
    setErr(null);
  }

  async function save() {
    if (!form.tenant_id) {
      setErr("Pick a tenant.");
      return;
    }
    if (BYOK_NEEDS_BASE_URL.has(form.provider) && !form.base_url.trim()) {
      setErr(`${form.provider} requires a base URL.`);
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await api.admin.upsertBYOK({
        tenant_id: form.tenant_id,
        provider: form.provider,
        base_url: form.base_url.trim() || null,
        model: form.model.trim() || null,
        api_key: form.api_key.trim() || null,
        enabled: form.enabled,
      });
      resetForm();
      await mutate();
    } catch (e: any) {
      setErr(e.message ?? "Save failed");
    } finally {
      setBusy(false);
    }
  }

  async function remove(r: BYOK) {
    if (!confirm(`Remove the BYOK override for "${tenantName(r.tenant_id)}"?`)) return;
    try {
      await api.admin.deleteBYOK(r.tenant_id);
      if (editing && form.tenant_id === r.tenant_id) resetForm();
      await mutate();
    } catch (e: any) {
      setErr(e.message ?? "Delete failed");
    }
  }

  const needsBaseUrl = BYOK_NEEDS_BASE_URL.has(form.provider);
  const needsKey = BYOK_NEEDS_KEY.has(form.provider);

  return (
    <Panel title="Deployment & AI — BYOK">
      <div className="space-y-5 pt-1">
        <p className="text-[11px] text-muted">
          Per-tenant LLM provider override. An <span className="text-text">enabled</span> credential
          routes that tenant&apos;s synthesis to its own endpoint/model, overriding the global LLM
          configuration below. Keys are stored encrypted and never shown again.
        </p>

        {/* Existing overrides */}
        {isLoading ? (
          <div className="flex items-center gap-2 text-muted text-sm py-2">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : data && data.length > 0 ? (
          <div className="rounded border border-line divide-y divide-line">
            {data.map((r) => (
              <div key={r.tenant_id} className="flex items-center gap-3 px-3 py-2 text-sm">
                <span
                  className={`w-2 h-2 rounded-full flex-none ${r.enabled ? "bg-positive" : "bg-muted/40"}`}
                  title={r.enabled ? "enabled" : "disabled"}
                />
                <div className="min-w-0 flex-1">
                  <div className="text-text truncate">
                    {tenantName(r.tenant_id)}
                    {" · "}
                    <span className="font-mono">{r.provider}</span>
                    {r.model && <span className="text-muted"> · {r.model}</span>}
                    {r.base_url && <span className="text-muted"> · {r.base_url}</span>}
                  </div>
                  <div className="text-[11px] text-muted">
                    key <span className="font-mono text-text">{r.has_api_key ? "set" : "not set"}</span>
                    {r.last_rotated_at && <> · rotated {new Date(r.last_rotated_at).toLocaleDateString()}</>}
                  </div>
                </div>
                <button onClick={() => startEdit(r)} className="text-muted hover:text-text" title="Edit">
                  <Pencil size={14} />
                </button>
                <button onClick={() => remove(r)} className="text-muted hover:text-danger" title="Remove">
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-sm text-muted">
            No per-tenant overrides — all tenants use the global LLM configuration.
          </div>
        )}

        {/* Add / edit form */}
        <div className="rounded border border-line bg-surface/40 p-4 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs tracking-widest uppercase text-muted">
              {editing ? "Edit override" : "Add override"}
            </span>
            {editing && (
              <button onClick={resetForm} className="text-muted hover:text-text flex items-center gap-1 text-xs">
                <X size={12} /> cancel
              </button>
            )}
          </div>

          <div className="flex gap-3">
            <div className="space-y-1.5 flex-1">
              <label className="text-xs tracking-widest uppercase text-muted">Tenant</label>
              <select
                value={form.tenant_id}
                onChange={(e) => set("tenant_id", e.target.value)}
                disabled={editing}
                className={INPUT_SM + " w-full disabled:opacity-60"}
              >
                <option value="">— select tenant —</option>
                {(tenants ?? []).map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5 flex-1">
              <label className="text-xs tracking-widest uppercase text-muted">Provider</label>
              <select
                value={form.provider}
                onChange={(e) => set("provider", e.target.value)}
                className={INPUT_SM + " w-full"}
              >
                {BYOK_PROVIDERS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs tracking-widest uppercase text-muted">
              Base URL{" "}
              {needsBaseUrl ? (
                <span className="text-danger">*</span>
              ) : (
                <span className="text-muted/60">(optional)</span>
              )}
            </label>
            <input
              type="text"
              value={form.base_url}
              onChange={(e) => set("base_url", e.target.value)}
              placeholder={needsBaseUrl ? "http://ollama:11434" : "blank = provider default"}
              className={INPUT}
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs tracking-widest uppercase text-muted">
              Model <span className="text-muted/60">(optional)</span>
            </label>
            <input
              type="text"
              value={form.model}
              onChange={(e) => set("model", e.target.value)}
              placeholder="e.g. claude-opus-4-8, llama3.1:8b — blank = global/env model"
              className={INPUT}
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs tracking-widest uppercase text-muted">
              API Key{" "}
              {needsKey ? (
                <span className="text-danger">*</span>
              ) : (
                <span className="text-muted/60">(optional)</span>
              )}
            </label>
            <div className="relative">
              <input
                type={showKey ? "text" : "password"}
                value={form.api_key}
                onChange={(e) => set("api_key", e.target.value)}
                placeholder={editing ? "Leave blank to keep current key" : "paste API key…"}
                className={INPUT + " pr-10"}
                autoComplete="new-password"
              />
              <button
                type="button"
                onClick={() => setShowKey((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-text"
                title={showKey ? "Hide" : "Show"}
              >
                {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
            <p className="text-[11px] text-muted">
              Stored encrypted at rest. Leave blank when editing to keep the existing key.
            </p>
          </div>

          <label className="flex items-center gap-2 text-sm text-text">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => set("enabled", e.target.checked)}
              className="accent-accent"
            />
            Enabled
          </label>

          {err && (
            <div className="flex items-center gap-2 text-danger text-sm">
              <AlertTriangle size={14} /> {err}
            </div>
          )}

          <button onClick={save} disabled={busy} className="btn btn-primary flex items-center gap-1.5">
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
            {busy ? "Saving…" : editing ? "Update override" : "Add override"}
          </button>
        </div>
      </div>
    </Panel>
  );
}
