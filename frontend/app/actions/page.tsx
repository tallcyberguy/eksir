"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import {
  ShieldBan, ServerCrash, Wifi, WifiOff, FolderSearch, Search,
  Loader2, CheckCircle2, XCircle, ChevronDown, ChevronUp, History,
  AlertTriangle, FileSearch, Building2, UserX, UserCheck, ScanLine, Monitor,
} from "lucide-react";

type Status = "idle" | "busy" | "ok" | "err";
type Tenant = { identifier: string; label?: string; region?: string };

const V1_IOC_TYPES = [
  { v: "ip",                label: "IP" },
  { v: "domain",            label: "Domain" },
  { v: "url",               label: "URL" },
  { v: "fileSha256",        label: "SHA256" },
  { v: "fileSha1",          label: "SHA1" },
  { v: "senderMailAddress", label: "Email" },
];

const MDE_IOC_TYPES = [
  { v: "IpAddress",  label: "IP" },
  { v: "DomainName", label: "Domain" },
  { v: "Url",        label: "URL" },
  { v: "FileSha256", label: "SHA256" },
  { v: "FileSha1",   label: "SHA1" },
];

// ── Confirm dialog ─────────────────────────────────────────────────────────
function ConfirmModal({
  title, description, onConfirm, onCancel,
}: {
  title: string; description: string;
  onConfirm: (text: string) => void; onCancel: () => void;
}) {
  const [text, setText] = useState("");
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-surface border border-line rounded-xl shadow-cyber w-full max-w-md p-6 space-y-4">
        <h3 className="text-text font-semibold flex items-center gap-2">
          <AlertTriangle size={16} className="text-warning"/>{title}
        </h3>
        <p className="text-sm text-muted">{description}</p>
        <textarea
          className="w-full bg-base border border-line rounded-md p-2 text-sm text-text resize-none focus:outline-none focus:border-accent"
          rows={3}
          placeholder="Justification (required)…"
          value={text}
          onChange={e => setText(e.target.value)}
        />
        <div className="flex gap-3 justify-end">
          <button onClick={onCancel}
                  className="px-4 py-1.5 text-sm text-muted border border-line rounded-md hover:border-accent">
            Cancel
          </button>
          <button
            onClick={() => onConfirm(text)}
            disabled={!text.trim()}
            className="px-4 py-1.5 text-sm bg-danger/90 text-text rounded-md hover:bg-danger disabled:opacity-40">
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Status indicator helper ────────────────────────────────────────────────
function StatusIcon({ status }: { status: Status }) {
  if (status === "busy") return <Loader2 size={14} className="animate-spin"/>;
  if (status === "ok")   return <CheckCircle2 size={14} className="text-positive"/>;
  if (status === "err")  return <XCircle size={14} className="text-danger"/>;
  return null;
}

function EpRow({ k, v }: { k: string; v: any }) {
  return v ? (
    <div className="flex gap-2">
      <span className="w-24 shrink-0 uppercase tracking-wider text-[10px]">{k}</span>
      <span className="font-mono text-text break-all">{String(v)}</span>
    </div>
  ) : null;
}

// ── Tenant selector (shared per provider tab) ──────────────────────────────
function TenantSelect({
  tenants, value, onChange,
}: { tenants: Tenant[]; value: string; onChange: (v: string) => void }) {
  return (
    <div className="flex items-center gap-2">
      <Building2 size={14} className="text-accent"/>
      <label className="text-[10px] uppercase tracking-wider text-muted">Tenant</label>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        disabled={tenants.length === 0}
        className="bg-base border border-line rounded-md px-2 py-1.5 text-sm text-text focus:outline-none focus:border-accent disabled:opacity-40">
        {tenants.length === 0 && <option value="">No tenants configured</option>}
        {tenants.map(t => (
          <option key={t.identifier} value={t.identifier}>
            {(t.label || t.identifier)}{t.region ? ` · ${t.region}` : ""}
          </option>
        ))}
      </select>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Vision One panels
// ═══════════════════════════════════════════════════════════════════════════

function V1BlockListPanel({ customer }: { customer: string }) {
  const [type, setType]       = useState("ip");
  const [value, setValue]     = useState("");
  const [showConfirm, setShow]= useState(false);
  const [status, setStatus]   = useState<Status>("idle");
  const [msg, setMsg]         = useState<string | null>(null);

  async function submit(justification: string) {
    setShow(false); setStatus("busy"); setMsg(null);
    try {
      await api.v1ops.addToBlocklist({
        customer, ioc_type: type, value: value.trim(),
        description: justification, scan_action: "block", risk_level: "high",
      });
      setStatus("ok"); setMsg("Added to block list");
      setValue("");
    } catch (e: any) {
      setStatus("err"); setMsg(e.message);
    }
  }

  return (
    <>
      {showConfirm && (
        <ConfirmModal
          title="Add to V1 Block List"
          description={`Block ${type} "${value}" across the ${customer} Vision One tenant?`}
          onConfirm={submit}
          onCancel={() => setShow(false)}
        />
      )}
      <Panel title="Block List (Vision One)" icon={<ShieldBan size={14} className="text-accent"/>}>
        <p className="text-xs text-muted mb-3">
          Add any IOC to the Suspicious Object list — applies across the selected tenant's endpoints.
        </p>
        <div className="flex flex-wrap gap-2 items-stretch">
          <select
            value={type}
            onChange={e => setType(e.target.value)}
            className="bg-base border border-line rounded-md px-2 py-1.5 text-sm text-text focus:outline-none focus:border-accent">
            {V1_IOC_TYPES.map(t => <option key={t.v} value={t.v}>{t.label}</option>)}
          </select>
          <input
            value={value}
            onChange={e => setValue(e.target.value)}
            placeholder="IOC value (e.g. 8.8.8.8, evil.com, https://…)"
            className="flex-1 min-w-[200px] bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text font-mono focus:outline-none focus:border-accent"
          />
          <button
            onClick={() => { setStatus("idle"); setMsg(null); setShow(true); }}
            disabled={!value.trim() || !customer || status === "busy"}
            className="flex items-center gap-1.5 px-4 py-1.5 text-sm border border-line rounded-md hover:border-danger hover:text-danger disabled:opacity-40">
            <StatusIcon status={status}/>
            {status === "idle" && <ShieldBan size={14}/>}
            Block
          </button>
        </div>
        {msg && <p className={`text-xs mt-2 ${status === "err" ? "text-danger" : "text-positive"}`}>{msg}</p>}
      </Panel>
    </>
  );
}

function V1EndpointLookupPanel({ customer }: { customer: string }) {
  const [q, setQ]          = useState("");
  const [busy, setBusy]    = useState(false);
  const [results, setRes]  = useState<any[]>([]);
  const [err, setErr]      = useState<string | null>(null);
  const [expanded, setExp] = useState<string | null>(null);

  async function search() {
    if (!q.trim() || !customer) return;
    setBusy(true); setErr(null);
    try {
      const r = await api.v1ops.searchEndpoints(customer, q.trim());
      setRes(r.items || []);
      if ((r.items || []).length === 0) setErr("No endpoints found");
    } catch (e: any) {
      setErr(e.message);
    } finally { setBusy(false); }
  }

  return (
    <Panel title="Endpoint Lookup" icon={<FileSearch size={14} className="text-accent"/>}>
      <div className="flex gap-2">
        <input
          className="flex-1 bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
          placeholder="Hostname or IP…"
          value={q}
          onChange={e => setQ(e.target.value)}
          onKeyDown={e => e.key === "Enter" && search()}
        />
        <button
          onClick={search}
          disabled={busy || !q.trim() || !customer}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-line rounded-md hover:border-accent disabled:opacity-40">
          {busy ? <Loader2 size={14} className="animate-spin"/> : <Search size={14}/>}
          Search
        </button>
      </div>
      {err && <p className="text-xs text-danger mt-2">{err}</p>}
      <div className="space-y-2 mt-3">
        {results.map(ep => (
          <div key={ep.agentGuid || ep.endpointName} className="border border-line rounded-md overflow-hidden">
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
                <EpRow k="Agent GUID"   v={ep.agentGuid}/>
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
    </Panel>
  );
}

function V1EndpointResponsePanel({ customer }: { customer: string }) {
  const [endpointName, setName] = useState("");
  const [filePath, setPath]     = useState("");
  const [pending, setPending]   = useState<null | { kind: "isolate" | "restore" | "collect"; title: string; desc: string }>(null);
  const [status, setStatus]     = useState<Status>("idle");
  const [msg, setMsg]           = useState<string | null>(null);
  const [taskId, setTaskId]     = useState<string | null>(null);

  async function run(justification: string) {
    if (!pending) return;
    const kind = pending.kind;
    setPending(null); setStatus("busy"); setMsg(null); setTaskId(null);
    try {
      let result: any;
      if (kind === "isolate")      result = await api.v1ops.isolate({ customer, endpoint_name: endpointName, justification });
      else if (kind === "restore") result = await api.v1ops.restore({ customer, endpoint_name: endpointName, justification });
      else                         result = await api.v1ops.collectFile({ customer, endpoint_name: endpointName, file_path: filePath, justification });
      setStatus("ok"); setMsg(`${kind} task queued`);
      const tid = result?.task_id || result?.result?.[0]?.id || result?.result?.id;
      if (tid) setTaskId(tid);
    } catch (e: any) {
      setStatus("err"); setMsg(e.message);
    }
  }

  const epReady = endpointName.trim().length > 0 && !!customer;
  const fileReady = epReady && filePath.trim().length > 0;

  return (
    <>
      {pending && (
        <ConfirmModal
          title={pending.title}
          description={pending.desc}
          onConfirm={run}
          onCancel={() => setPending(null)}
        />
      )}
      <Panel title="Endpoint Response" icon={<ServerCrash size={14} className="text-warning"/>}>
        <p className="text-xs text-muted mb-3">
          Destructive actions require a written justification and cannot be undone automatically.
        </p>

        <label className="text-[10px] uppercase tracking-wider text-muted">Target endpoint hostname</label>
        <input
          className="mt-1 mb-3 w-full bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
          placeholder="DESKTOP-ABC123"
          value={endpointName}
          onChange={e => setName(e.target.value)}
        />

        <div className="space-y-2">
          <button
            onClick={() => setPending({
              kind: "isolate",
              title: "Isolate endpoint",
              desc: `Cut "${endpointName}" from the network (${customer}). Enter justification:`,
            })}
            disabled={!epReady || status === "busy"}
            className="flex items-center gap-2 px-3 py-2 text-sm w-full border border-line rounded-md hover:border-danger text-text disabled:opacity-40">
            <WifiOff size={14}/> Isolate endpoint
          </button>

          <button
            onClick={() => setPending({
              kind: "restore",
              title: "Restore endpoint connection",
              desc: `Restore network access for "${endpointName}" (${customer}). Enter justification:`,
            })}
            disabled={!epReady || status === "busy"}
            className="flex items-center gap-2 px-3 py-2 text-sm w-full border border-line rounded-md hover:border-accent text-text disabled:opacity-40">
            <Wifi size={14}/> Restore connection
          </button>
        </div>

        <div className="mt-4 pt-3 border-t border-line/60 space-y-2">
          <label className="text-[10px] uppercase tracking-wider text-muted">File collection</label>
          <input
            className="w-full bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
            placeholder="File path (e.g. C:\Users\victim\malware.exe)"
            value={filePath}
            onChange={e => setPath(e.target.value)}
          />
          <button
            onClick={() => setPending({
              kind: "collect",
              title: "Collect file",
              desc: `Collect "${filePath}" from "${endpointName}" (${customer}). Enter justification:`,
            })}
            disabled={!fileReady || status === "busy"}
            className="flex items-center gap-2 px-3 py-2 text-sm w-full border border-line rounded-md hover:border-accent disabled:opacity-40">
            <FolderSearch size={14}/> Collect file
          </button>
        </div>

        {(msg || status === "busy") && (
          <div className="mt-3 text-xs flex items-center gap-2">
            <StatusIcon status={status}/>
            <span className={status === "err" ? "text-danger" : "text-muted"}>{msg}</span>
            {taskId && <code className="ml-auto font-mono text-[10px] text-accent">task: {taskId}</code>}
          </div>
        )}
      </Panel>
    </>
  );
}

function V1TaskStatusPanel({ customer }: { customer: string }) {
  const [tid, setTid]     = useState("");
  const [busy, setBusy]   = useState(false);
  const [data, setData]   = useState<any>(null);
  const [err, setErr]     = useState<string | null>(null);

  async function check() {
    if (!tid.trim() || !customer) return;
    setBusy(true); setErr(null); setData(null);
    try { setData(await api.v1ops.getTask(customer, tid.trim())); }
    catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  }

  return (
    <Panel title="Task Status" icon={<History size={14} className="text-muted"/>}>
      <div className="flex gap-2">
        <input
          className="flex-1 bg-base border border-line rounded-md px-3 py-1.5 text-sm font-mono text-text focus:outline-none focus:border-accent"
          placeholder="Task ID…"
          value={tid}
          onChange={e => setTid(e.target.value)}
          onKeyDown={e => e.key === "Enter" && check()}
        />
        <button
          onClick={check}
          disabled={busy || !tid.trim() || !customer}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-line rounded-md hover:border-accent disabled:opacity-40">
          {busy ? <Loader2 size={14} className="animate-spin"/> : <Search size={14}/>}
          Check
        </button>
      </div>
      {err && <p className="text-xs text-danger mt-2">{err}</p>}
      {data && (
        <pre className="mt-3 text-xs bg-base border border-line rounded-md p-3 overflow-x-auto text-muted">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </Panel>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Microsoft Defender panels
// ═══════════════════════════════════════════════════════════════════════════

function MdeMachineLookupPanel({ customer, onPick }: { customer: string; onPick: (id: string) => void }) {
  const [q, setQ]          = useState("");
  const [busy, setBusy]    = useState(false);
  const [results, setRes]  = useState<any[]>([]);
  const [err, setErr]      = useState<string | null>(null);

  async function search() {
    if (!customer) return;
    setBusy(true); setErr(null);
    try {
      const r = await api.defenderops.searchMachines(customer, q.trim());
      setRes(r.items || []);
      if ((r.items || []).length === 0) setErr("No devices found");
    } catch (e: any) {
      setErr(e.message);
    } finally { setBusy(false); }
  }

  return (
    <Panel title="Device Lookup" icon={<Monitor size={14} className="text-accent"/>}>
      <p className="text-xs text-muted mb-2">
        Resolve a hostname to its Defender machine ID (advanced hunting). Click a result to load it below.
      </p>
      <div className="flex gap-2">
        <input
          className="flex-1 bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
          placeholder="Hostname (leave blank to list recent)…"
          value={q}
          onChange={e => setQ(e.target.value)}
          onKeyDown={e => e.key === "Enter" && search()}
        />
        <button
          onClick={search}
          disabled={busy || !customer}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-line rounded-md hover:border-accent disabled:opacity-40">
          {busy ? <Loader2 size={14} className="animate-spin"/> : <Search size={14}/>}
          Search
        </button>
      </div>
      {err && <p className="text-xs text-danger mt-2">{err}</p>}
      <div className="space-y-1.5 mt-3">
        {results.map((m, i) => (
          <button
            key={m.DeviceId || i}
            onClick={() => onPick(m.DeviceId)}
            className="w-full text-left border border-line rounded-md px-3 py-2 hover:border-accent">
            <div className="flex items-center justify-between text-sm">
              <span className="font-mono text-text">{m.DeviceName || "—"}</span>
              <span className="text-muted text-xs">{m.OSPlatform || ""}</span>
            </div>
            <div className="text-[10px] font-mono text-muted break-all mt-0.5">{m.DeviceId}</div>
          </button>
        ))}
      </div>
    </Panel>
  );
}

function MdeEndpointResponsePanel({
  customer, machineId, setMachineId,
}: { customer: string; machineId: string; setMachineId: (v: string) => void }) {
  const [pending, setPending] = useState<null | { kind: "isolate" | "unisolate" | "scan"; title: string; desc: string }>(null);
  const [status, setStatus]   = useState<Status>("idle");
  const [msg, setMsg]         = useState<string | null>(null);

  async function run(justification: string) {
    if (!pending) return;
    const kind = pending.kind;
    setPending(null); setStatus("busy"); setMsg(null);
    try {
      if (kind === "isolate")        await api.defenderops.isolate({ customer, machine_id: machineId, justification });
      else if (kind === "unisolate") await api.defenderops.unisolate({ customer, machine_id: machineId, justification });
      else                           await api.defenderops.scan({ customer, machine_id: machineId, justification });
      setStatus("ok"); setMsg(`${kind} submitted`);
    } catch (e: any) {
      setStatus("err"); setMsg(e.message);
    }
  }

  const ready = machineId.trim().length > 0 && !!customer;

  return (
    <>
      {pending && (
        <ConfirmModal
          title={pending.title}
          description={pending.desc}
          onConfirm={run}
          onCancel={() => setPending(null)}
        />
      )}
      <Panel title="Device Response" icon={<ServerCrash size={14} className="text-warning"/>}>
        <p className="text-xs text-muted mb-3">
          Machine ID targets a single Defender device. Use the lookup to fill it from a hostname.
        </p>

        <label className="text-[10px] uppercase tracking-wider text-muted">Machine ID</label>
        <input
          className="mt-1 mb-3 w-full bg-base border border-line rounded-md px-3 py-1.5 text-sm font-mono text-text focus:outline-none focus:border-accent"
          placeholder="e.g. 1e5bc9d7…  (Defender device id)"
          value={machineId}
          onChange={e => setMachineId(e.target.value)}
        />

        <div className="space-y-2">
          <button
            onClick={() => setPending({
              kind: "isolate",
              title: "Isolate device",
              desc: `Cut Defender device ${machineId} from the network (${customer}). Enter justification:`,
            })}
            disabled={!ready || status === "busy"}
            className="flex items-center gap-2 px-3 py-2 text-sm w-full border border-line rounded-md hover:border-danger text-text disabled:opacity-40">
            <WifiOff size={14}/> Isolate device
          </button>

          <button
            onClick={() => setPending({
              kind: "unisolate",
              title: "Release isolation",
              desc: `Restore network access for device ${machineId} (${customer}). Enter justification:`,
            })}
            disabled={!ready || status === "busy"}
            className="flex items-center gap-2 px-3 py-2 text-sm w-full border border-line rounded-md hover:border-accent text-text disabled:opacity-40">
            <Wifi size={14}/> Release isolation
          </button>

          <button
            onClick={() => setPending({
              kind: "scan",
              title: "Run antivirus scan",
              desc: `Run a Defender AV scan on device ${machineId} (${customer}). Enter justification:`,
            })}
            disabled={!ready || status === "busy"}
            className="flex items-center gap-2 px-3 py-2 text-sm w-full border border-line rounded-md hover:border-accent text-text disabled:opacity-40">
            <ScanLine size={14}/> Run AV scan
          </button>
        </div>

        {(msg || status === "busy") && (
          <div className="mt-3 text-xs flex items-center gap-2">
            <StatusIcon status={status}/>
            <span className={status === "err" ? "text-danger" : "text-muted"}>{msg}</span>
          </div>
        )}
      </Panel>
    </>
  );
}

function MdeBlockListPanel({ customer }: { customer: string }) {
  const [type, setType]       = useState("IpAddress");
  const [value, setValue]     = useState("");
  const [showConfirm, setShow]= useState(false);
  const [status, setStatus]   = useState<Status>("idle");
  const [msg, setMsg]         = useState<string | null>(null);

  async function submit(justification: string) {
    setShow(false); setStatus("busy"); setMsg(null);
    try {
      await api.defenderops.addToBlocklist({
        customer, indicator_type: type, indicator_value: value.trim(),
        justification, action: "Block", severity: "Medium",
      });
      setStatus("ok"); setMsg("Custom indicator created");
      setValue("");
    } catch (e: any) {
      setStatus("err"); setMsg(e.message);
    }
  }

  return (
    <>
      {showConfirm && (
        <ConfirmModal
          title="Add Defender custom indicator"
          description={`Block ${type} "${value}" across the ${customer} Defender tenant?`}
          onConfirm={submit}
          onCancel={() => setShow(false)}
        />
      )}
      <Panel title="Block List (Defender)" icon={<ShieldBan size={14} className="text-accent"/>}>
        <p className="text-xs text-muted mb-3">
          Create a custom indicator (blocklist entry) — applies across the selected Defender tenant.
        </p>
        <div className="flex flex-wrap gap-2 items-stretch">
          <select
            value={type}
            onChange={e => setType(e.target.value)}
            className="bg-base border border-line rounded-md px-2 py-1.5 text-sm text-text focus:outline-none focus:border-accent">
            {MDE_IOC_TYPES.map(t => <option key={t.v} value={t.v}>{t.label}</option>)}
          </select>
          <input
            value={value}
            onChange={e => setValue(e.target.value)}
            placeholder="Indicator value (e.g. 8.8.8.8, evil.com, https://…)"
            className="flex-1 min-w-[200px] bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text font-mono focus:outline-none focus:border-accent"
          />
          <button
            onClick={() => { setStatus("idle"); setMsg(null); setShow(true); }}
            disabled={!value.trim() || !customer || status === "busy"}
            className="flex items-center gap-1.5 px-4 py-1.5 text-sm border border-line rounded-md hover:border-danger hover:text-danger disabled:opacity-40">
            <StatusIcon status={status}/>
            {status === "idle" && <ShieldBan size={14}/>}
            Block
          </button>
        </div>
        {msg && <p className={`text-xs mt-2 ${status === "err" ? "text-danger" : "text-positive"}`}>{msg}</p>}
      </Panel>
    </>
  );
}

function MdeUserContainmentPanel({ customer }: { customer: string }) {
  const [userId, setUserId]   = useState("");
  const [pending, setPending] = useState<null | { kind: "disable" | "enable"; title: string; desc: string }>(null);
  const [status, setStatus]   = useState<Status>("idle");
  const [msg, setMsg]         = useState<string | null>(null);

  async function run(justification: string) {
    if (!pending) return;
    const kind = pending.kind;
    setPending(null); setStatus("busy"); setMsg(null);
    try {
      if (kind === "disable") await api.defenderops.disableUser({ customer, user_id: userId, justification });
      else                    await api.defenderops.enableUser({ customer, user_id: userId, justification });
      setStatus("ok"); setMsg(`user ${kind}d`);
    } catch (e: any) {
      setStatus("err"); setMsg(e.message);
    }
  }

  const ready = userId.trim().length > 0 && !!customer;

  return (
    <>
      {pending && (
        <ConfirmModal
          title={pending.title}
          description={pending.desc}
          onConfirm={run}
          onCancel={() => setPending(null)}
        />
      )}
      <Panel title="Identity Containment" icon={<UserX size={14} className="text-warning"/>}>
        <p className="text-xs text-muted mb-3">
          Disable or re-enable an Entra (Azure AD) account by object id or userPrincipalName.
        </p>

        <label className="text-[10px] uppercase tracking-wider text-muted">User (object id or UPN)</label>
        <input
          className="mt-1 mb-3 w-full bg-base border border-line rounded-md px-3 py-1.5 text-sm font-mono text-text focus:outline-none focus:border-accent"
          placeholder="user@contoso.com"
          value={userId}
          onChange={e => setUserId(e.target.value)}
        />

        <div className="space-y-2">
          <button
            onClick={() => setPending({
              kind: "disable",
              title: "Disable user account",
              desc: `Disable "${userId}" in the ${customer} tenant. Enter justification:`,
            })}
            disabled={!ready || status === "busy"}
            className="flex items-center gap-2 px-3 py-2 text-sm w-full border border-line rounded-md hover:border-danger text-text disabled:opacity-40">
            <UserX size={14}/> Disable user
          </button>
          <button
            onClick={() => setPending({
              kind: "enable",
              title: "Re-enable user account",
              desc: `Re-enable "${userId}" in the ${customer} tenant. Enter justification:`,
            })}
            disabled={!ready || status === "busy"}
            className="flex items-center gap-2 px-3 py-2 text-sm w-full border border-line rounded-md hover:border-accent text-text disabled:opacity-40">
            <UserCheck size={14}/> Re-enable user
          </button>
        </div>

        {(msg || status === "busy") && (
          <div className="mt-3 text-xs flex items-center gap-2">
            <StatusIcon status={status}/>
            <span className={status === "err" ? "text-danger" : "text-muted"}>{msg}</span>
          </div>
        )}
      </Panel>
    </>
  );
}

// ── Recent history (shared shell, per-provider source) ─────────────────────
function HistoryPanel({ title, load }: { title: string; load: (n: number) => Promise<any[]> }) {
  const [rows, setRows] = useState<any[]>([]);

  useEffect(() => {
    load(15).then(setRows).catch(() => {});
    const t = setInterval(() => load(15).then(setRows).catch(() => {}), 10000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <Panel title={title} icon={<History size={14} className="text-muted"/>}>
      {rows.length === 0 && <p className="text-xs text-muted italic">No actions yet.</p>}
      <div className="space-y-1.5">
        {rows.map(r => (
          <div key={r.id} className="flex items-center gap-3 text-xs border-b border-line/30 pb-1.5 last:border-b-0">
            <span className="w-24 shrink-0 font-mono text-accent uppercase">{r.action}</span>
            <span className="text-muted shrink-0">{r.target_type}</span>
            <span className="font-mono text-text break-all flex-1">{r.target || "—"}</span>
            <span className="text-muted shrink-0 text-[10px]">{r.ts ? new Date(r.ts).toLocaleString() : ""}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ── Provider tabs ──────────────────────────────────────────────────────────
function ProviderTabs({ value, onChange }: { value: "v1" | "defender"; onChange: (v: "v1" | "defender") => void }) {
  const tabs: { key: "v1" | "defender"; label: string }[] = [
    { key: "v1",       label: "Vision One" },
    { key: "defender", label: "Microsoft Defender" },
  ];
  return (
    <div className="inline-flex rounded-lg border border-line bg-surface p-1">
      {tabs.map(t => (
        <button
          key={t.key}
          onClick={() => onChange(t.key)}
          className={`px-4 py-1.5 text-sm rounded-md transition-colors ${
            value === t.key ? "bg-accent/20 text-accent" : "text-muted hover:text-text"
          }`}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ── Vision One tab ─────────────────────────────────────────────────────────
function VisionOneTab() {
  const [st, setSt]           = useState<any>(null);
  const [customer, setCustomer] = useState("");

  useEffect(() => {
    api.v1ops.status()
      .then(s => { setSt(s); setCustomer(s.tenants?.[0]?.identifier || ""); })
      .catch(() => setSt({ configured: false, tenants: [] }));
  }, []);

  if (st && !st.configured) {
    return (
      <Panel title="Vision One Actions" icon={<AlertTriangle size={14} className="text-danger"/>}>
        <p className="text-sm text-muted">
          No Vision One tenant is configured. Add a <code className="font-mono text-accent">vision_one</code>{" "}
          integration (or set <code className="font-mono text-accent">V1_API_KEY</code>) to enable response actions.
        </p>
      </Panel>
    );
  }

  return (
    <div className="space-y-5">
      <TenantSelect tenants={st?.tenants || []} value={customer} onChange={setCustomer}/>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <V1BlockListPanel customer={customer}/>
        <V1TaskStatusPanel customer={customer}/>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <V1EndpointLookupPanel customer={customer}/>
        <V1EndpointResponsePanel customer={customer}/>
      </div>
      <HistoryPanel title="Recent Vision One actions (audit log)" load={api.v1ops.history}/>
    </div>
  );
}

// ── Defender tab ───────────────────────────────────────────────────────────
function DefenderTab() {
  const [st, setSt]             = useState<any>(null);
  const [customer, setCustomer] = useState("");
  const [machineId, setMachineId] = useState("");

  useEffect(() => {
    api.defenderops.status()
      .then(s => { setSt(s); setCustomer(s.tenants?.[0]?.identifier || ""); })
      .catch(() => setSt({ configured: false, tenants: [] }));
  }, []);

  if (st && !st.configured) {
    return (
      <Panel title="Microsoft Defender Actions" icon={<AlertTriangle size={14} className="text-danger"/>}>
        <p className="text-sm text-muted">
          No Microsoft Defender tenant is configured. Add a{" "}
          <code className="font-mono text-accent">microsoft_defender</code> integration (client id / secret /
          tenant id) to enable response actions.
        </p>
      </Panel>
    );
  }

  return (
    <div className="space-y-5">
      <TenantSelect tenants={st?.tenants || []} value={customer} onChange={setCustomer}/>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <MdeMachineLookupPanel customer={customer} onPick={setMachineId}/>
        <MdeEndpointResponsePanel customer={customer} machineId={machineId} setMachineId={setMachineId}/>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <MdeBlockListPanel customer={customer}/>
        <MdeUserContainmentPanel customer={customer}/>
      </div>
      <HistoryPanel title="Recent Defender actions (audit log)" load={api.defenderops.history}/>
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────
export default function ActionsPage() {
  const [provider, setProvider] = useState<"v1" | "defender">("v1");

  return (
    <div className="space-y-5">
      <ProviderTabs value={provider} onChange={setProvider}/>
      {provider === "v1" ? <VisionOneTab/> : <DefenderTab/>}
    </div>
  );
}
