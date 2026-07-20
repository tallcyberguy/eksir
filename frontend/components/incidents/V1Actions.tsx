"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import {
  ShieldBan, ServerCrash, Wifi, WifiOff, FolderSearch, EyeOff,
  Search, Loader2, CheckCircle2, XCircle, ChevronDown, ChevronUp,
} from "lucide-react";

interface Props {
  incidentId: string;
  iocs: { ioc_type: string; value: string }[];
  isV1Customer: boolean;  // show endpoint actions only for V1 tenants
}

type ActionStatus = "idle" | "busy" | "ok" | "err";

interface ActionResult {
  action: string;
  target: string;
  status: ActionStatus;
  message?: string;
  data?: any;
}

// ── Confirm dialog ───────────────────────────────────────────────────────

function ConfirmModal({
  title, description, onConfirm, onCancel, requireText,
}: {
  title: string;
  description: string;
  onConfirm: (text: string) => void;
  onCancel: () => void;
  requireText?: boolean;
}) {
  const [text, setText] = useState("");
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-surface border border-line rounded-xl shadow-cyber w-full max-w-md p-6 space-y-4">
        <h3 className="text-text font-semibold">{title}</h3>
        <p className="text-sm text-muted">{description}</p>
        {requireText && (
          <textarea
            className="w-full bg-base border border-line rounded-md p-2 text-sm text-text resize-none focus:outline-none focus:border-accent"
            rows={3}
            placeholder="Justification (required)…"
            value={text}
            onChange={e => setText(e.target.value)}
          />
        )}
        <div className="flex gap-3 justify-end">
          <button onClick={onCancel}
                  className="px-4 py-1.5 text-sm text-muted border border-line rounded-md hover:border-accent">
            Cancel
          </button>
          <button
            onClick={() => onConfirm(text)}
            disabled={requireText && !text.trim()}
            className="px-4 py-1.5 text-sm bg-danger/90 text-text rounded-md hover:bg-danger disabled:opacity-40">
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Endpoint search panel ────────────────────────────────────────────────

function EndpointSearch({ incidentId }: { incidentId: string }) {
  const [q, setQ]           = useState("");
  const [busy, setBusy]     = useState(false);
  const [results, setRes]   = useState<any[]>([]);
  const [err, setErr]       = useState<string | null>(null);
  const [expanded, setExp]  = useState<string | null>(null);

  async function search() {
    if (!q.trim()) return;
    setBusy(true); setErr(null);
    try {
      const r = await api.v1.searchEndpoints(incidentId, q.trim());
      setRes(r.items || []);
      if ((r.items || []).length === 0) setErr("No endpoints found");
    } catch (e: any) {
      setErr(e.message);
    } finally { setBusy(false); }
  }

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <input
          className="flex-1 bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
          placeholder="Hostname or IP…"
          value={q}
          onChange={e => setQ(e.target.value)}
          onKeyDown={e => e.key === "Enter" && search()}
        />
        <button onClick={search} disabled={busy || !q.trim()}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-line rounded-md hover:border-accent disabled:opacity-40">
          {busy ? <Loader2 size={14} className="animate-spin"/> : <Search size={14}/>}
          Search
        </button>
      </div>
      {err && <p className="text-xs text-danger">{err}</p>}
      {results.map(ep => (
        <div key={ep.agentGuid || ep.endpointName}
             className="border border-line rounded-md overflow-hidden">
          <button
            onClick={() => setExp(expanded === ep.agentGuid ? null : ep.agentGuid)}
            className="w-full flex items-center justify-between px-3 py-2 text-sm hover:bg-surface2">
            <span className="font-mono text-text">{ep.endpointName || ep.displayName || ep.agentGuid}</span>
            <div className="flex items-center gap-2 text-muted text-xs">
              <span>{ep.osName || "—"}</span>
              {expanded === ep.agentGuid ? <ChevronUp size={12}/> : <ChevronDown size={12}/>}
            </div>
          </button>
          {expanded === ep.agentGuid && (
            <div className="bg-base px-3 pb-3 pt-1 text-xs text-muted space-y-1 border-t border-line/60">
              <EpRow k="Agent GUID"    v={ep.agentGuid}/>
              <EpRow k="OS"           v={ep.osName}/>
              <EpRow k="IP"           v={(ep.ip || []).join(", ")}/>
              <EpRow k="Last seen"    v={ep.eppAgentLastConnectedDateTime}/>
              <EpRow k="EPP status"   v={ep.eppAgentStatus}/>
              <EpRow k="EDR status"   v={ep.edrSensorStatus}/>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function EpRow({ k, v }: { k: string; v: any }) {
  return v ? (
    <div className="flex gap-2">
      <span className="w-24 shrink-0 uppercase tracking-wider text-[10px]">{k}</span>
      <span className="font-mono text-text break-all">{String(v)}</span>
    </div>
  ) : null;
}

// ── Response action button ────────────────────────────────────────────────

function ActionButton({
  icon: Icon, label, colorClass = "border-line hover:border-accent",
  confirmTitle, confirmDesc, requireJustification = true,
  onExecute,
}: {
  icon: any; label: string; colorClass?: string;
  confirmTitle: string; confirmDesc: string;
  requireJustification?: boolean;
  onExecute: (justification: string) => Promise<void>;
}) {
  const [showConfirm, setShow] = useState(false);
  const [status, setStatus]   = useState<ActionStatus>("idle");
  const [msg, setMsg]         = useState<string | null>(null);

  async function run(text: string) {
    setShow(false);
    setStatus("busy");
    try {
      await onExecute(text);
      setStatus("ok");
      setMsg("Done");
    } catch (e: any) {
      setStatus("err");
      setMsg(e.message);
    }
  }

  return (
    <>
      {showConfirm && (
        <ConfirmModal
          title={confirmTitle}
          description={confirmDesc}
          requireText={requireJustification}
          onConfirm={run}
          onCancel={() => setShow(false)}
        />
      )}
      <button
        onClick={() => { setStatus("idle"); setMsg(null); setShow(true); }}
        disabled={status === "busy"}
        className={`flex items-center gap-2 px-3 py-2 text-sm border rounded-md ${colorClass} disabled:opacity-40 w-full`}>
        {status === "busy"   && <Loader2 size={14} className="animate-spin"/>}
        {status === "ok"     && <CheckCircle2 size={14} className="text-positive"/>}
        {status === "err"    && <XCircle size={14} className="text-danger"/>}
        {status === "idle"   && <Icon size={14}/>}
        <span className="flex-1 text-left">{label}</span>
        {msg && <span className="text-[11px] text-muted">{msg}</span>}
      </button>
    </>
  );
}

// ── Blocklist button (also exported for IOC table) ───────────────────────

export function BlocklistButton({
  incidentId, iocType, value,
}: {
  incidentId: string; iocType: string; value: string;
}) {
  const [showConfirm, setShow] = useState(false);
  const [status, setStatus]   = useState<ActionStatus>("idle");

  const typeMap: Record<string, string> = {
    "ipv4": "ip", "ipv6": "ip", "ip": "ip",
    "domain": "domain", "url": "url",
    "sha256": "fileSha256", "sha1": "fileSha1",
    "email": "senderMailAddress",
  };
  const v1Type = typeMap[iocType.toLowerCase()] || "ip";

  async function block(justification: string) {
    setShow(false);
    setStatus("busy");
    try {
      await api.v1.addToBlocklist(incidentId, {
        ioc_type: v1Type as any,
        value,
        description: justification,
        scan_action: "block",
        risk_level: "high",
      });
      setStatus("ok");
    } catch {
      setStatus("err");
    }
  }

  return (
    <>
      {showConfirm && (
        <ConfirmModal
          title="Add to V1 Block List"
          description={`Block ${iocType} "${value}" across all Vision One endpoints?`}
          requireText
          onConfirm={block}
          onCancel={() => setShow(false)}
        />
      )}
      <button
        onClick={() => { setStatus("idle"); setShow(true); }}
        disabled={status === "busy"}
        title="Add to V1 block list"
        className="text-[11px] px-1.5 py-0.5 border border-line rounded hover:border-danger hover:text-danger disabled:opacity-40">
        {status === "busy" && <Loader2 size={10} className="inline animate-spin"/>}
        {status === "ok"   && <CheckCircle2 size={10} className="inline text-positive"/>}
        {status === "err"  && <XCircle size={10} className="inline text-danger"/>}
        {status === "idle" && <ShieldBan size={10} className="inline"/>}
        {" "}Block
      </button>
    </>
  );
}

// ── Exclude button — adds the IOC to OUR analyst exclusion list ───────────
// Opposite intent to Block: "known-good, stop triaging it" (not "contain it").
export function ExcludeButton({
  incidentId, iocType, value, customer,
}: {
  incidentId: string; iocType: string; value: string; customer?: string | null;
}) {
  const [showConfirm, setShow] = useState(false);
  const [status, setStatus] = useState<ActionStatus>("idle");
  const [scope, setScope] = useState<"customer" | "global">("customer");

  // Mirror the backend mapping so the modal can show what will actually be excluded.
  const t = iocType.toLowerCase();
  const exType =
    ["ipv4", "ipv6", "ip"].includes(t) ? "ip" :
    ["sha256", "sha1", "md5", "hash"].includes(t) ? "hash" :
    (t === "domain" || t === "url" || t === "email") ? "domain" : null;
  const broadens = t === "url" || t === "email";

  async function exclude() {
    setShow(false);
    setStatus("busy");
    try {
      await api.excludeIoc(incidentId, { ioc_type: iocType, value, scope });
      setStatus("ok");
    } catch {
      setStatus("err");
    }
  }

  if (!exType) return null;  // email→domain etc. covered; truly ineligible types hidden

  return (
    <>
      {showConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-surface border border-line rounded-lg p-5 max-w-md w-full mx-4 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-text">Exclude from triage</h3>
              <p className="text-xs text-muted mt-1 leading-relaxed">
                Adds <span className="font-mono text-text">{exType}</span>{" "}
                <span className="font-mono text-text break-all">
                  {exType === "domain" && broadens ? hostOrDomain(value) : value}
                </span>{" "}
                to the exclusion list — future alerts won't triage it (the LLM is
                still told it was excluded).
                {broadens && (
                  <span className="block mt-1 text-warning">
                    Note: this excludes the whole <b>domain</b>, not just this {t}.
                  </span>
                )}
              </p>
            </div>
            <div className="flex gap-2 text-xs">
              <button onClick={() => setScope("customer")}
                className={"flex-1 px-3 py-2 rounded-md border " + (scope === "customer"
                  ? "border-accent text-accent bg-accent/10" : "border-line text-muted")}>
                This customer{customer ? ` (${customer})` : ""}
              </button>
              <button onClick={() => setScope("global")}
                className={"flex-1 px-3 py-2 rounded-md border " + (scope === "global"
                  ? "border-warning text-warning bg-warning/10" : "border-line text-muted")}>
                Global (all customers)
              </button>
            </div>
            <div className="flex justify-end gap-2">
              <button onClick={() => setShow(false)}
                className="text-xs px-3 py-1.5 rounded-md border border-line text-muted hover:text-text">
                Cancel
              </button>
              <button onClick={exclude}
                className="text-xs px-3 py-1.5 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20">
                Exclude
              </button>
            </div>
          </div>
        </div>
      )}
      <button
        onClick={() => { setStatus("idle"); setScope("customer"); setShow(true); }}
        disabled={status === "busy"}
        title="Add to analyst exclusion list (suppress from triage)"
        className="text-[11px] px-1.5 py-0.5 border border-line rounded hover:border-accent hover:text-accent disabled:opacity-40">
        {status === "busy" && <Loader2 size={10} className="inline animate-spin"/>}
        {status === "ok"   && <CheckCircle2 size={10} className="inline text-positive"/>}
        {status === "err"  && <XCircle size={10} className="inline text-danger"/>}
        {status === "idle" && <EyeOff size={10} className="inline"/>}
        {" "}Exclude
      </button>
    </>
  );
}

function hostOrDomain(value: string): string {
  if (value.includes("@")) return value.split("@").pop()!.toLowerCase();
  try {
    const after = value.includes("://") ? value.split("://")[1] : value;
    return after.split("/")[0].split("?")[0].split(":")[0].toLowerCase();
  } catch { return value; }
}

// ── Custom IOC entry — analyst types a value, picks type, sends to V1 ─────

const V1_IOC_TYPES = [
  { v: "ip",                label: "IP" },
  { v: "domain",            label: "Domain" },
  { v: "url",               label: "URL" },
  { v: "fileSha256",        label: "SHA256" },
  { v: "fileSha1",          label: "SHA1" },
  { v: "senderMailAddress", label: "Email" },
];

function CustomIOCBlock({ incidentId }: { incidentId: string }) {
  const [type, setType]       = useState("ip");
  const [value, setValue]     = useState("");
  const [showConfirm, setShow]= useState(false);
  const [status, setStatus]   = useState<ActionStatus>("idle");
  const [msg, setMsg]         = useState<string | null>(null);

  async function block(justification: string) {
    setShow(false); setStatus("busy"); setMsg(null);
    try {
      await api.v1.addToBlocklist(incidentId, {
        ioc_type: type as any,
        value: value.trim(),
        description: justification,
        scan_action: "block",
        risk_level: "high",
      });
      setStatus("ok"); setMsg("Added");
      setValue("");
    } catch (e: any) {
      setStatus("err"); setMsg(e.message);
    }
  }

  const ready = value.trim().length > 0;

  return (
    <>
      {showConfirm && (
        <ConfirmModal
          title="Add custom IOC to V1 Block List"
          description={`Block ${type} "${value}" across all Vision One endpoints?`}
          requireText
          onConfirm={block}
          onCancel={() => setShow(false)}
        />
      )}
      <div className="mt-4 pt-3 border-t border-line/60">
        <div className="text-[10px] uppercase tracking-wider text-muted mb-2">Add custom IOC</div>
        <div className="flex gap-2 items-stretch">
          <select
            value={type}
            onChange={e => setType(e.target.value)}
            className="bg-base border border-line rounded-md px-2 py-1.5 text-sm text-text focus:outline-none focus:border-accent">
            {V1_IOC_TYPES.map(t => <option key={t.v} value={t.v}>{t.label}</option>)}
          </select>
          <input
            value={value}
            onChange={e => setValue(e.target.value)}
            placeholder="Enter value…"
            className="flex-1 bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text font-mono focus:outline-none focus:border-accent"
          />
          <button
            onClick={() => { setStatus("idle"); setMsg(null); setShow(true); }}
            disabled={!ready || status === "busy"}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-line rounded-md hover:border-danger hover:text-danger disabled:opacity-40">
            {status === "busy" && <Loader2 size={14} className="animate-spin"/>}
            {status === "ok"   && <CheckCircle2 size={14} className="text-positive"/>}
            {status === "err"  && <XCircle size={14} className="text-danger"/>}
            {status === "idle" && <ShieldBan size={14}/>}
            Block
          </button>
        </div>
        {msg && <p className={`text-xs mt-2 ${status === "err" ? "text-danger" : "text-muted"}`}>{msg}</p>}
      </div>
    </>
  );
}

// ── Main V1Actions panel ──────────────────────────────────────────────────

export function V1Actions({ incidentId, iocs, isV1Customer }: Props) {
  const [endpointName, setEndpointName] = useState("");

  return (
    <div className="space-y-5">
      {/* Block List — available for all incidents regardless of customer */}
      <Panel title="Block List (Vision One)">
        <p className="text-xs text-muted mb-3">
          Add any IOC from this incident to the Suspicious Object list.
          Blocks across all Vision One-connected endpoints.
        </p>
        <div className="space-y-2">
          {iocs.length === 0 && (
            <p className="text-xs text-muted italic">No IOCs extracted from this incident.</p>
          )}
          {iocs.map((ioc, i) => (
            <div key={i} className="flex items-center justify-between gap-3 text-sm">
              <div>
                <span className="text-[10px] uppercase tracking-wider text-muted mr-2">{ioc.ioc_type}</span>
                <span className="font-mono text-text break-all">{ioc.value}</span>
              </div>
              <BlocklistButton incidentId={incidentId} iocType={ioc.ioc_type} value={ioc.value}/>
            </div>
          ))}
        </div>
        <CustomIOCBlock incidentId={incidentId}/>
      </Panel>

      {/* Endpoint enrichment */}
      <Panel title="Endpoint Lookup">
        <EndpointSearch incidentId={incidentId}/>
      </Panel>

      {/* Response actions — only for V1 customers */}
      {isV1Customer && (
        <Panel title="Response Actions">
          <p className="text-xs text-muted mb-3">
            Destructive actions require a written justification and cannot be undone automatically.
          </p>
          <div className="mb-3">
            <label className="text-[10px] uppercase tracking-wider text-muted">Target endpoint hostname</label>
            <input
              className="mt-1 w-full bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
              placeholder="DESKTOP-ABC123"
              value={endpointName}
              onChange={e => setEndpointName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <ActionButton
              icon={WifiOff}
              label="Isolate endpoint"
              colorClass="border-line hover:border-danger text-text"
              confirmTitle="Isolate endpoint"
              confirmDesc={`This will cut "${endpointName}" from the network. Enter justification:`}
              onExecute={j => api.v1.isolate(incidentId, { endpoint_name: endpointName, justification: j })}
            />
            <ActionButton
              icon={Wifi}
              label="Restore connection"
              confirmTitle="Restore endpoint connection"
              confirmDesc={`Restore network access for "${endpointName}". Enter justification:`}
              onExecute={j => api.v1.restore(incidentId, { endpoint_name: endpointName, justification: j })}
            />
            <CollectFileAction incidentId={incidentId} endpointName={endpointName}/>
          </div>
        </Panel>
      )}
    </div>
  );
}

function CollectFileAction({ incidentId, endpointName }: { incidentId: string; endpointName: string }) {
  const [agentGuid, setGuid] = useState("");
  const [filePath, setPath] = useState("");
  const [showConfirm, setShow] = useState(false);
  const [status, setStatus]   = useState<ActionStatus>("idle");
  const [msg, setMsg]         = useState<string | null>(null);

  // Vision One identifies the endpoint by agent GUID (preferred / required on
  // FedRAMP tenants) OR hostname — send exactly one, GUID wins.
  const guid = agentGuid.trim();
  const host = endpointName.trim();
  const target = guid || host;

  async function run(justification: string) {
    setShow(false); setStatus("busy");
    try {
      await api.v1.collectFile(incidentId, {
        ...(guid ? { agent_guid: guid } : { endpoint_name: host }),
        file_path: filePath,
        justification,
      });
      setStatus("ok"); setMsg("Collection task queued");
    } catch (e: any) {
      setStatus("err"); setMsg(e.message);
    }
  }

  return (
    <>
      {showConfirm && (
        <ConfirmModal
          title="Collect file"
          description={`Collect "${filePath}" from "${target}". Enter justification:`}
          requireText
          onConfirm={run}
          onCancel={() => setShow(false)}
        />
      )}
      <div className="space-y-1.5">
        <input
          className="w-full bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text font-mono focus:outline-none focus:border-accent"
          placeholder="Agent GUID (preferred — from Endpoint Lookup)"
          value={agentGuid}
          onChange={e => setGuid(e.target.value)}
        />
        <input
          className="w-full bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
          placeholder="File path (e.g. C:\Users\victim\malware.exe)"
          value={filePath}
          onChange={e => setPath(e.target.value)}
        />
        <p className="text-[11px] text-muted">
          Identify the endpoint by <span className="text-text">Agent GUID</span> (preferred) or fall
          back to the <span className="text-text">Target endpoint hostname</span> above.
        </p>
        <button
          onClick={() => { setStatus("idle"); setMsg(null); setShow(true); }}
          disabled={status === "busy" || !filePath.trim() || !target}
          className="flex items-center gap-2 px-3 py-2 text-sm border border-line rounded-md hover:border-accent disabled:opacity-40 w-full">
          {status === "busy" && <Loader2 size={14} className="animate-spin"/>}
          {status === "ok"   && <CheckCircle2 size={14} className="text-positive"/>}
          {status === "err"  && <XCircle size={14} className="text-danger"/>}
          {status === "idle" && <FolderSearch size={14}/>}
          <span className="flex-1 text-left">Collect file</span>
          {msg && <span className="text-[11px] text-muted">{msg}</span>}
        </button>
      </div>
    </>
  );
}
