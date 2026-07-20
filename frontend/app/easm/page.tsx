"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import {
  Globe, AlertTriangle, Loader2, RefreshCw, Trash2, Plus, ShieldCheck, ShieldAlert,
  Mail, Lock, Server, ChevronDown, ChevronRight, ScanLine, Network,
} from "lucide-react";

type Posture = { spf: boolean; dmarc: boolean; dmarc_policy: string | null; mx: boolean; posture: string; findings: string[] };
type Tls = { expires_at: string; days_remaining: number; issuer: string | null; status: string };
type Port = { port: number; proto: string; service: string | null; product: string | null; version: string | null; tunnel: string | null };
type Result = {
  asset_type: string; dns: Record<string, string[]>; rdns: string | null;
  posture: Posture; tls: Tls | null; whois: any; risk: { score: number; level: string; reasons: string[] };
  scanned_at: string; errors: string[];
  ports?: Port[]; ports_scanned_at?: string | null; ports_error?: string | null;
};
type Asset = {
  id: string; value: string; asset_type: string; tags: string[]; notes: string | null;
  last_result: Result | null; last_scanned_at: string | null;
};
type Overview = {
  total_assets: number; scanned: number; cert_issues: number; weak_posture: number;
  open_ports: number; risky_ports: number; avg_risk: number; max_risk: number; by_type: Record<string, number>;
};

// Client-side highlight set for risky exposed services (display only; the
// backend does the authoritative risk scoring).
const RISKY_SVC = new Set([
  "telnet", "ftp", "microsoft-ds", "netbios-ssn", "ms-wbt-server", "vnc", "mysql",
  "ms-sql-s", "postgresql", "mongodb", "redis", "elasticsearch", "memcached", "snmp", "ldap",
]);
const RISKY_PORTS = new Set([21, 23, 135, 139, 445, 1433, 1521, 3306, 5432, 27017, 6379, 9200, 11211, 3389, 5900, 161, 389, 2049]);
const isRiskyPort = (p: Port) => RISKY_PORTS.has(p.port) || RISKY_SVC.has((p.service || "").toLowerCase());

const RISK: Record<string, string> = {
  critical: "text-danger bg-danger/10 border-danger/20",
  high: "text-danger bg-danger/10 border-danger/20",
  medium: "text-warning bg-warning/10 border-warning/20",
  low: "text-positive bg-positive/10 border-positive/20",
};
const POSTURE: Record<string, string> = {
  strong: "text-positive", moderate: "text-warning", weak: "text-danger", none: "text-danger",
};
const CERT: Record<string, string> = {
  valid: "text-positive", expiring: "text-warning", expired: "text-danger", unknown: "text-muted",
};

function Pill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${ok ? "text-positive border-positive/30 bg-positive/10" : "text-muted border-line"}`}>
      {label}{ok ? " ✓" : " ✕"}
    </span>
  );
}

function PortsCard({ r }: { r: Result }) {
  const ports = r.ports;
  if (ports === undefined && !r.ports_error) return null;
  return (
    <div className="rounded border border-line bg-base/40 p-3 mt-3">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5 text-xs text-muted"><Network size={13} /> Open ports &amp; services</div>
        {r.ports_scanned_at && <div className="text-[10px] text-muted">scanned {new Date(r.ports_scanned_at).toLocaleString()}</div>}
      </div>
      {r.ports_error ? (
        <div className="text-[11px] text-warning">{r.ports_error}</div>
      ) : !ports || ports.length === 0 ? (
        <div className="text-[11px] text-positive">No open ports found in the top-200 scan.</div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
          {ports.map((p) => {
            const risky = isRiskyPort(p);
            const tech = [p.product, p.version].filter(Boolean).join(" ");
            return (
              <div key={`${p.proto}-${p.port}`}
                className={`flex items-center gap-2 rounded px-2 py-1 text-[11px] border ${risky ? "border-danger/30 bg-danger/5" : "border-line/60"}`}>
                <span className={`font-mono ${risky ? "text-danger" : "text-text"}`}>{p.port}/{p.proto}</span>
                <span className="text-muted">{p.service || "?"}</span>
                {tech && <span className="text-text/70 truncate">{tech}</span>}
                {p.tunnel === "ssl" && <span className="text-[9px] text-positive border border-positive/30 rounded px-1">TLS</span>}
                {risky && <span className="text-[9px] text-danger border border-danger/30 rounded px-1 ml-auto">risky</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function Detail({ r }: { r: Result }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3">
      {/* Email auth posture */}
      <div className="rounded border border-line bg-base/40 p-3">
        <div className="flex items-center gap-1.5 text-xs text-muted mb-2"><Mail size={13} /> Email auth posture</div>
        {r.posture?.posture ? (
          <>
            <div className={`text-sm font-medium capitalize ${POSTURE[r.posture.posture] ?? "text-muted"}`}>{r.posture.posture}</div>
            <div className="flex gap-1.5 mt-2 flex-wrap">
              <Pill ok={r.posture.spf} label="SPF" />
              <Pill ok={r.posture.dmarc} label={`DMARC${r.posture.dmarc_policy ? ` p=${r.posture.dmarc_policy}` : ""}`} />
              <Pill ok={r.posture.mx} label="MX" />
            </div>
            {r.posture.findings?.length > 0 && (
              <ul className="mt-2 space-y-0.5">
                {r.posture.findings.map((f) => <li key={f} className="text-[11px] text-muted">• {f}</li>)}
              </ul>
            )}
          </>
        ) : <div className="text-xs text-muted">n/a</div>}
      </div>

      {/* TLS */}
      <div className="rounded border border-line bg-base/40 p-3">
        <div className="flex items-center gap-1.5 text-xs text-muted mb-2"><Lock size={13} /> TLS certificate</div>
        {r.tls ? (
          <>
            <div className={`text-sm font-medium capitalize ${CERT[r.tls.status] ?? "text-muted"}`}>
              {r.tls.status} · {r.tls.days_remaining}d
            </div>
            <div className="text-[11px] text-muted mt-1">Issuer: {r.tls.issuer ?? "—"}</div>
            <div className="text-[11px] text-muted">Expires: {r.tls.expires_at?.slice(0, 10)}</div>
          </>
        ) : <div className="text-xs text-muted">No HTTPS / not resolved</div>}
      </div>

      {/* DNS */}
      <div className="rounded border border-line bg-base/40 p-3">
        <div className="flex items-center gap-1.5 text-xs text-muted mb-2"><Server size={13} /> DNS</div>
        <div className="space-y-0.5 text-[11px] font-mono text-muted">
          {r.rdns && <div>rDNS: <span className="text-text">{r.rdns}</span></div>}
          {["a", "aaaa", "mx", "ns"].map((k) => (
            (r.dns?.[k]?.length ?? 0) > 0 && (
              <div key={k}>{k.toUpperCase()}: <span className="text-text">{r.dns[k].slice(0, 3).join(", ")}</span></div>
            )
          ))}
          {r.whois?.registrar && <div className="pt-1">Registrar: <span className="text-text">{r.whois.registrar}</span></div>}
        </div>
      </div>
    </div>
  );
}

export default function EASMPage() {
  const assets = useSWR<{ assets: Asset[] }>("easm:assets", api.easm.assets);
  const overview = useSWR<Overview>("easm:overview", api.easm.overview);
  const [val, setVal] = useState("");
  const [adding, setAdding] = useState(false);
  const [scanning, setScanning] = useState<string | null>(null);
  const [portscanning, setPortscanning] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  async function add() {
    const v = val.trim();
    if (!v || adding) return;
    setAdding(true);
    try { await api.easm.add({ value: v }); setVal(""); assets.mutate(); overview.mutate(); }
    finally { setAdding(false); }
  }
  async function scan(id: string) {
    setScanning(id);
    try { await api.easm.scan(id); assets.mutate(); overview.mutate(); setExpanded(id); }
    finally { setScanning(null); }
  }
  async function portscan(id: string) {
    setPortscanning(id);
    try { await api.easm.portscan(id); assets.mutate(); overview.mutate(); setExpanded(id); }
    finally { setPortscanning(null); }
  }
  async function del(id: string) {
    if (!confirm("Remove this asset?")) return;
    await api.easm.remove(id); assets.mutate(); overview.mutate();
  }

  const o = overview.data;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-accent text-sm font-mono tracking-wider">
          <Globe size={15} /> ATTACK SURFACE
        </div>
        <h1 className="text-2xl font-semibold text-text mt-1">Know what you expose.</h1>
        <p className="text-muted text-sm mt-1 max-w-2xl">
          Watch your external domains and IPs. <strong>Scan</strong> checks DNS, email-auth
          posture (SPF/DKIM/DMARC), and TLS health; <strong>Ports</strong> runs an nmap port +
          service/version scan to surface exposed services. Read-only — scanning only observes.
        </p>
      </div>

      {/* Overview KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: "Assets", value: o?.total_assets ?? "—", color: "text-accent" },
          { label: "Scanned", value: o?.scanned ?? "—", color: "text-text" },
          { label: "Cert issues", value: o?.cert_issues ?? "—", color: "text-warning" },
          { label: "Weak auth", value: o?.weak_posture ?? "—", color: "text-danger" },
          { label: "Risky ports", value: o?.risky_ports ?? "—", color: (o?.risky_ports ?? 0) > 0 ? "text-danger" : "text-positive" },
          { label: "Max risk", value: o?.max_risk ?? "—", color: (o?.max_risk ?? 0) >= 45 ? "text-danger" : "text-positive" },
        ].map((k) => (
          <div key={k.label} className="rounded-lg border border-line bg-surface/40 p-4">
            <div className="text-[11px] uppercase tracking-wider text-muted">{k.label}</div>
            <div className={`text-2xl font-semibold mt-1 ${k.color}`}>{k.value}</div>
          </div>
        ))}
      </div>

      {/* Add asset */}
      <div className="flex gap-2">
        <div className="flex-1 flex items-center gap-2 bg-surface border border-line rounded-lg px-3">
          <Globe size={15} className="text-muted shrink-0" />
          <input value={val} onChange={(e) => setVal(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && add()}
            placeholder="Add a domain, subdomain or IP — e.g. corp.example.com"
            className="flex-1 bg-transparent py-2.5 text-sm text-text outline-none" />
        </div>
        <button onClick={add} disabled={adding || !val.trim()}
          className="btn btn-primary px-4 flex items-center gap-1.5 disabled:opacity-50">
          {adding ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />} Add
        </button>
      </div>

      {/* Asset register */}
      {assets.error ? (
        <div className="rounded-lg border border-line bg-surface/40 p-8 flex flex-col items-center gap-3 text-center">
          <AlertTriangle size={22} className="text-danger" />
          <div className="text-sm text-text">Couldn&apos;t load the asset register.</div>
          <div className="text-[11px] text-muted font-mono">{assets.error.message}</div>
          <button onClick={() => assets.mutate()} className="text-xs border border-line rounded px-3 py-1.5 text-text hover:bg-surface2/40">Retry</button>
        </div>
      ) : assets.isLoading || !assets.data ? (
        <div className="flex items-center gap-2 text-muted text-sm py-16 justify-center">
          <Loader2 size={16} className="animate-spin" /> Loading assets…
        </div>
      ) : !assets.data.assets.length ? (
        <div className="rounded-lg border border-line bg-surface/40 p-10 text-center text-sm text-muted">
          No assets yet. Add a domain or IP above to start watching your attack surface.
        </div>
      ) : (
        <div className="space-y-2">
          {assets.data.assets.map((a) => {
            const r = a.last_result;
            const isOpen = expanded === a.id;
            return (
              <div key={a.id} className="rounded-lg border border-line bg-surface/40 overflow-hidden">
                <div className="flex items-center gap-3 px-4 py-3">
                  <button onClick={() => setExpanded(isOpen ? null : a.id)} className="text-muted hover:text-text shrink-0">
                    {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                  </button>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm text-text truncate">{a.value}</span>
                      <span className="text-[10px] uppercase text-muted border border-line rounded px-1.5 py-0.5">{a.asset_type}</span>
                    </div>
                    <div className="text-[11px] text-muted">
                      {a.last_scanned_at ? `Scanned ${new Date(a.last_scanned_at).toLocaleString()}` : "Never scanned"}
                    </div>
                  </div>
                  {r?.posture?.posture && (
                    <span className={`text-xs hidden md:flex items-center gap-1 ${POSTURE[r.posture.posture] ?? "text-muted"}`}>
                      {r.posture.posture === "strong" ? <ShieldCheck size={13} /> : <ShieldAlert size={13} />}
                      {r.posture.posture}
                    </span>
                  )}
                  {r?.risk && (
                    <span className={`text-xs font-medium px-2 py-0.5 rounded border ${RISK[r.risk.level] ?? RISK.low}`}>
                      risk {r.risk.score}
                    </span>
                  )}
                  <button onClick={() => scan(a.id)} disabled={scanning === a.id}
                    title="DNS · SPF/DMARC · TLS · WHOIS"
                    className="text-xs flex items-center gap-1 border border-line rounded px-2.5 py-1 text-text hover:bg-surface2/40 disabled:opacity-50">
                    {scanning === a.id ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />} Scan
                  </button>
                  <button onClick={() => portscan(a.id)} disabled={portscanning === a.id}
                    title="nmap port + service/version scan"
                    className="text-xs flex items-center gap-1 border border-line rounded px-2.5 py-1 text-text hover:bg-surface2/40 disabled:opacity-50">
                    {portscanning === a.id ? <Loader2 size={12} className="animate-spin" /> : <ScanLine size={12} />} Ports
                  </button>
                  <button onClick={() => del(a.id)} className="text-muted hover:text-danger shrink-0"><Trash2 size={14} /></button>
                </div>
                {isOpen && (
                  <div className="px-4 pb-4 border-t border-line/40">
                    {r ? (
                      <>
                        {r.risk?.reasons?.length > 0 && (
                          <div className="text-[11px] text-muted mt-3">{r.risk.reasons.join(" · ")}</div>
                        )}
                        <Detail r={r} />
                        <PortsCard r={r} />
                      </>
                    ) : (
                      <div className="text-xs text-muted py-4 text-center">Not scanned yet — press Scan to run recon.</div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
