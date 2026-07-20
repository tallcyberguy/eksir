"use client";

import { useMemo, useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, Plug, Trash2, CheckCircle2, XCircle, CircleDashed, Plus, AlertTriangle } from "lucide-react";

type FieldSpec = {
  key: string; label: string; type: string; required: boolean; secret: boolean;
  help: string | null; placeholder: string | null; options: string[]; docs_url: string | null;
};
type OAuthHints = {
  token_url: string; authorize_url: string | null; scopes: string[]; supported_in_hosted: boolean;
};
type Spec = {
  key: string; label: string; category: string; capabilities: string[];
  fields: string[]; region_options: string[]; identifier_label: string;
  adapter_status: string; docs_url: string | null;
  // ADR-0006 typed superset — drives the self-describing "Add connector" form (P1b).
  field_specs?: FieldSpec[]; capability_verbs?: string[];
  auth_shape?: string; oauth_hints?: OAuthHints | null; parser_source?: string | null;
};
type Connector = {
  id: string; provider: string; identifier: string; label: string | null;
  enabled: boolean; region: string | null; base_url: string | null; has_key: boolean;
  label_catalog: string; category: string; capabilities: string[]; adapter_status: string;
};
type ListResp = { connectors: Connector[]; catalog: Spec[] };

const CAT_STYLE: Record<string, string> = {
  edr: "text-danger border-danger/40",
  ti: "text-accent border-accent/40",
  recon: "text-warning border-warning/40",
};
const CAP_STYLE: Record<string, string> = {
  enrich: "bg-positive/15 text-positive",
  hunt: "bg-accent/15 text-accent",
  respond: "bg-danger/15 text-danger",
};

const FIELD_LABEL: Record<string, string> = {
  api_key: "API key", // pragma: allowlist secret
  client_id: "Client ID",
  client_secret: "Client secret", // pragma: allowlist secret
  oauth_tenant_id: "Azure tenant ID",
  base_url: "Base URL / host",
  region: "Region",
};
const SECRET_FIELDS = new Set(["api_key", "client_secret"]);
const FIELD_PLACEHOLDER: Record<string, string> = {
  base_url: "e.g. euce1-105.sentinelone.net or api.eu-1.crowdstrike.com",
};

// Legacy fallback: synthesize a FieldSpec from a bare field name when the backend
// catalog predates field_specs. Once the connectors branch is deployed this is unused.
function legacyFieldSpec(f: string, spec?: Spec): FieldSpec {
  return {
    key: f,
    label: FIELD_LABEL[f] ?? f,
    type: SECRET_FIELDS.has(f) ? "secret" : f === "region" ? "select" : "text",
    required: true,
    secret: SECRET_FIELDS.has(f),
    help: null,
    placeholder: FIELD_PLACEHOLDER[f] ?? null,
    options: f === "region" ? spec?.region_options ?? [] : [],
    docs_url: null,
  };
}

const INPUT_CLS = "mt-1 w-full bg-surface border border-line rounded px-2 py-1 text-sm text-text";

function AddForm({ catalog, onAdded }: { catalog: Spec[]; onAdded: () => void }) {
  const [provider, setProvider] = useState(catalog[0]?.key ?? "");
  const spec = useMemo(() => catalog.find((c) => c.key === provider), [catalog, provider]);
  const [identifier, setIdentifier] = useState("default");
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Self-describing: render from the typed field_specs the catalog ships (ADR-0006 P1b);
  // fall back to the legacy string field names for safety on an older backend.
  const fieldSpecs: FieldSpec[] = useMemo(() => {
    if (spec?.field_specs?.length) return spec.field_specs;
    return (spec?.fields ?? []).map((f) => legacyFieldSpec(f, spec));
  }, [spec]);

  const set = (f: string, v: string) => setValues((s) => ({ ...s, [f]: v }));

  async function add() {
    for (const fs of fieldSpecs) {
      const v = (values[fs.key] ?? "").trim();
      if (fs.required && !v) { setErr(`${fs.label} is required`); return; }
      if (v && fs.type === "select" && fs.options.length && !fs.options.includes(v)) {
        setErr(`${fs.label} must be one of: ${fs.options.join(", ")}`); return;
      }
    }
    setBusy(true); setErr(null);
    try {
      const payload: Record<string, any> = {
        provider, identifier: identifier.trim() || "default", enabled: true,
      };
      for (const fs of fieldSpecs) {
        const v = (values[fs.key] ?? "").trim();
        if (v) payload[fs.key] = v;
      }
      await api.admin.createIntegration(payload as any);
      setValues({}); setIdentifier("default");
      onAdded();
    } catch (e: any) {
      setErr(e?.message ?? "failed to add");
    } finally {
      setBusy(false);
    }
  }

  // Plain function (not a component) so inputs don't remount + lose focus per keystroke.
  function renderInput(fs: FieldSpec) {
    const v = values[fs.key] ?? "";
    if (fs.type === "select") {
      return (
        <select value={v} onChange={(e) => set(fs.key, e.target.value)} className={INPUT_CLS}>
          <option value="">Select…</option>
          {fs.options.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
      );
    }
    if (fs.type === "textarea") {
      return (
        <textarea value={v} onChange={(e) => set(fs.key, e.target.value)} rows={4}
          placeholder={fs.placeholder ?? ""} className={`${INPUT_CLS} font-mono`} />
      );
    }
    return (
      <input
        type={fs.secret ? "password" : fs.type === "number" ? "number" : "text"}
        value={v}
        onChange={(e) => set(fs.key, e.target.value)}
        placeholder={fs.placeholder ?? ""}
        className={`${INPUT_CLS} ${fs.secret || fs.type === "number" ? "font-mono" : ""}`} />
    );
  }

  return (
    <Panel title="Add connector credentials">
      <div className="grid sm:grid-cols-2 gap-3">
        <label className="text-xs text-muted">
          Connector
          <select value={provider} onChange={(e) => { setProvider(e.target.value); setValues({}); setErr(null); }}
            className={INPUT_CLS}>
            {catalog.map((c) => (
              <option key={c.key} value={c.key}>
                {c.label} {c.adapter_status === "planned" ? "· (no live adapter yet)" : ""}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          {spec?.identifier_label ?? "Identifier"} <span className="opacity-60">(or “default”)</span>
          <input value={identifier} onChange={(e) => setIdentifier(e.target.value)} className={INPUT_CLS} />
        </label>
        {fieldSpecs.map((fs) => (
          <label key={fs.key} className={`text-xs text-muted ${fs.type === "secret" || fs.type === "textarea" ? "sm:col-span-2" : ""}`}>
            {fs.label}
            {!fs.required && <span className="opacity-60"> (optional)</span>}
            {fs.secret && <span className="opacity-60"> (write-only — stored encrypted)</span>}
            {renderInput(fs)}
            {fs.help && <span className="block mt-0.5 text-[10px] opacity-70">{fs.help}</span>}
            {fs.docs_url && (
              <a href={fs.docs_url} target="_blank" rel="noreferrer"
                className="block mt-0.5 text-[10px] text-accent underline">docs</a>
            )}
          </label>
        ))}
      </div>
      {spec?.auth_shape === "oauth_client_creds" && spec?.oauth_hints && (
        <div className="mt-2 text-[10px] text-muted">
          OAuth2 client credentials · token endpoint{" "}
          <span className="font-mono">{spec.oauth_hints.token_url}</span>
        </div>
      )}
      <div className="flex items-center justify-between mt-3">
        {err ? <span className="text-xs text-danger">{err}</span> : <span />}
        <button onClick={add} disabled={busy}
          className="btn btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50">
          {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />} Add
        </button>
      </div>
    </Panel>
  );
}

function TestResult({ r }: { r: { ok: boolean | null; status: string; detail: string } }) {
  const icon = r.ok === true ? <CheckCircle2 size={13} className="text-positive" />
    : r.ok === false ? <XCircle size={13} className="text-danger" />
    : <CircleDashed size={13} className="text-muted" />;
  return <span className="inline-flex items-center gap-1 text-[11px] text-muted">{icon} {r.detail}</span>;
}

export default function ConnectorsPage() {
  const { data, error, isLoading, mutate } = useSWR<ListResp>("admin:connectors", api.connectors.list);
  const [busy, setBusy] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<Record<string, any>>({});

  async function test(id: string) {
    setBusy((b) => ({ ...b, [id]: true }));
    try {
      const res = await api.connectors.test(id);
      setResults((r) => ({ ...r, [id]: res }));
    } catch (e: any) {
      setResults((r) => ({ ...r, [id]: { ok: false, status: "error", detail: e?.message } }));
    } finally {
      setBusy((b) => ({ ...b, [id]: false }));
    }
  }
  async function del(c: Connector) {
    if (!confirm(`Delete ${c.label_catalog} (${c.identifier})?`)) return;
    await api.admin.deleteIntegration(c.id);
    mutate();
  }

  return (
    <div className="max-w-3xl space-y-4">
      <p className="text-xs text-muted">
        Register per-customer EDR/XDR &amp; intel credentials. Capabilities are declarative
        (register-only) — only connectors marked <span className="text-positive">live</span> execute
        today; the rest store credentials for when their adapter ships.
      </p>

      {isLoading ? (
        <div className="flex items-center gap-2 text-muted text-sm py-6">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : error ? (
        <Panel title="Connectors">
          <div className="flex flex-col items-center gap-3 py-6 text-center">
            <AlertTriangle size={22} className="text-danger" />
            <div className="text-sm text-text">Couldn’t load connectors.</div>
            <div className="text-[11px] text-muted font-mono">{error.message}</div>
            <button onClick={() => mutate()} className="btn btn-primary text-sm">Retry</button>
          </div>
        </Panel>
      ) : !data ? null : (
        <>
          <Panel title={`Configured connectors (${data.connectors.length})`}>
            {data.connectors.length === 0 ? (
              <div className="text-sm text-muted py-2">None yet — add one below.</div>
            ) : (
              <ul className="divide-y divide-line">
                {data.connectors.map((c) => (
                  <li key={c.id} className="py-2.5 flex items-start gap-3">
                    <Plug size={15} className="mt-0.5 text-muted shrink-0" />
                    <div className="min-w-0 flex-1">
                      <div className="text-sm text-text flex items-center gap-2 flex-wrap">
                        {c.label_catalog}
                        <span className="text-muted font-mono text-xs">{c.identifier}</span>
                        <span className={`text-[10px] border rounded px-1 uppercase ${CAT_STYLE[c.category] ?? "text-muted border-line"}`}>{c.category}</span>
                        {c.adapter_status === "live"
                          ? <span className="text-[10px] text-positive">● live</span>
                          : <span className="text-[10px] text-muted">○ planned</span>}
                        {!c.enabled && <span className="text-[10px] text-warning">disabled</span>}
                      </div>
                      <div className="flex items-center gap-1 mt-1 flex-wrap">
                        {c.capabilities.map((cap) => (
                          <span key={cap} className={`text-[10px] rounded px-1.5 py-0.5 ${CAP_STYLE[cap] ?? "bg-surface text-muted"}`}>{cap}</span>
                        ))}
                        {!c.has_key && <span className="text-[10px] text-danger">no key</span>}
                      </div>
                      {results[c.id] && <div className="mt-1"><TestResult r={results[c.id]} /></div>}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button onClick={() => test(c.id)} disabled={busy[c.id]}
                        className="text-xs border border-line rounded px-2 py-1 text-text hover:bg-surface2/40 disabled:opacity-50">
                        {busy[c.id] ? <Loader2 size={12} className="animate-spin" /> : "Test"}
                      </button>
                      <button onClick={() => del(c)} className="text-muted hover:text-danger" title="Delete"><Trash2 size={13} /></button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <AddForm catalog={data.catalog} onAdded={() => mutate()} />
        </>
      )}
    </div>
  );
}
