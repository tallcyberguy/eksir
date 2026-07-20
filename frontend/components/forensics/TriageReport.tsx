"use client";

import { useState } from "react";
import { AlertTriangle, ShieldCheck, ShieldAlert, ShieldX, ChevronDown, ChevronRight } from "lucide-react";
import { Panel } from "@/components/ui/Panel";
import { cn } from "@/lib/utils";

/**
 * Renders triage.py JSON output into an analyst-grade report.
 *
 * Section order mirrors `format_triage_report()` in scripts/triage.py:
 *   [QUERY] → [VERDICT] → [SUMMARY] → [VT BEHAVIOUR] → [WHOIS]
 *   → [HOSTNAMES / PASSIVE DNS] → [SOURCE DETAILS]
 *
 * Every field is defensively coerced. The triage script sometimes returns
 * a string where another IOC returned an array for the same key (e.g.
 * `popular_threat_names`), so we always normalize before mapping.
 */
export function TriageReport({ data }: { data: any }) {
  const [showRaw, setShowRaw] = useState(false);

  if (!data || typeof data !== "object") {
    return <Panel title="Result"><div className="text-sm text-muted">No data.</div></Panel>;
  }
  if (data.error && !data.sources) {
    return (
      <Panel title="Result">
        <div className="text-sm text-danger">Error: {String(data.error)}</div>
        {data.query && <div className="text-xs text-muted mt-2">Query: <span className="font-mono">{String(data.query)}</span></div>}
      </Panel>
    );
  }

  const verdict     = (data.verdict || "unknown").toLowerCase();
  const confidence  = (data.confidence || "").toUpperCase();
  const summary     = data.summary || {};
  const sources     = arr(data.sources);
  const hostnames   = arr(data.hostnames);
  const queryText   = typeof data.query === "string" ? data.query : (data.query?.ioc ?? String(data.query ?? ""));
  const queryType   = data.type || data.query?.type || "?";
  const whois       = data.whois_info || {};

  const vtSource    = sources.find((s: any) => s?.source === "virustotal" && s?.found);
  const abuseSource = sources.find((s: any) => s?.source === "abuseipdb"  && s?.found);
  const behaviour   = vtSource?.behaviour_summary;

  const vtMaliciousCount = parseDetectionMalicious(summary.virustotal_detection);
  const sandboxEvasions: string[] = [];
  if (vtSource?.sandbox_verdicts && vtMaliciousCount > 5) {
    for (const [box, sv] of Object.entries(vtSource.sandbox_verdicts as Record<string, any>)) {
      if (String(sv?.category || "").toLowerCase() === "harmless") {
        sandboxEvasions.push(box);
      }
    }
  }
  const summaryTags = arr(summary.tags);
  const revokedCert = sources.some((s: any) => arr(s?.tags).includes("revoked-cert"))
                   || summaryTags.includes("revoked-cert");

  return (
    <div className="space-y-5">
      {/* ── [QUERY] + [VERDICT] ──────────────────────────────────────── */}
      <Panel>
        <div className="flex items-center gap-3 mb-3 flex-wrap">
          <VerdictPill verdict={verdict} />
          {confidence && <span className={cn("pill", confKlass(confidence))}>confidence {confidence}</span>}
          <span className="text-[10px] tracking-[0.18em] text-muted uppercase ml-auto">{queryType}</span>
          {data._cached && <span className="text-[10px] text-muted italic">cached</span>}
        </div>
        <div className="font-mono text-base break-all text-text">{queryText}</div>
        {data.timestamp && <div className="text-[10px] text-muted mt-1">{String(data.timestamp).slice(0, 19).replace("T", " ")} UTC</div>}
      </Panel>

      {/* ── [SUMMARY] ────────────────────────────────────────────────── */}
      <Panel title="Summary">
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-y-2 gap-x-6 text-sm">
          {arr(summary.found_in_sources).length > 0 && (
            <Signal label="Found in" value={arr(summary.found_in_sources).join(", ")}/>
          )}
          {arr(summary.malware_families).length > 0 && (
            <Signal label="Malware family"
                    value={arr(summary.malware_families).join(", ")}
                    accent="text-danger"/>
          )}
          {summary.virustotal_detection && (
            <Signal label="VT detection"
                    value={summary.virustotal_detection}
                    accent={vtBadgeClass(summary.virustotal_detection)}/>
          )}
          {summary.abuse_confidence_score !== undefined && summary.abuse_confidence_score !== null && (
            <Signal label="AbuseIPDB"
                    value={`${summary.abuse_confidence_score}%`}
                    accent={abuseBadge(toInt(summary.abuse_confidence_score))}/>
          )}
          {summary.otx_pulse_count !== undefined && (
            <Signal label="OTX pulses" value={String(summary.otx_pulse_count)}/>
          )}
          {hostnames.length > 0 && (
            <Signal label="Hostnames" value={`${hostnames.length} unique`}/>
          )}
          {summary.new_domain_flag && (
            <Signal label="Domain age"
                    value={`⚠ NEW — registered ${summary.domain_age_days ?? "?"} days ago`}
                    accent="text-danger font-semibold"/>
          )}
        </dl>

        {summaryTags.length > 0 && (
          <div className="mt-4">
            <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">Tags</div>
            <div className="flex flex-wrap gap-1.5">
              {summaryTags.slice(0, 16).map((t: string) => (
                <span key={t} className={cn("pill text-[10px]", tagClass(t))}>{t}</span>
              ))}
            </div>
          </div>
        )}
      </Panel>

      {/* ── Warnings (revoked cert + sandbox evasion) ────────────────── */}
      {(revokedCert || sandboxEvasions.length > 0) && (
        <Panel title="Warnings" className="border-danger/40">
          <ul className="space-y-2 text-sm">
            {revokedCert && (
              <li className="flex items-start gap-2 text-danger">
                <AlertTriangle size={16} className="mt-0.5 shrink-0"/>
                <span><b>Revoked certificate</b> — code-signing cert has been revoked by the issuer.</span>
              </li>
            )}
            {sandboxEvasions.map((box) => (
              <li key={box} className="flex items-start gap-2 text-warning">
                <AlertTriangle size={16} className="mt-0.5 shrink-0"/>
                <span><b>Possible sandbox evasion</b> — {box} reported <code>harmless</code> while {vtMaliciousCount} AV engines flagged the sample.</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {/* ── [VT BEHAVIOUR] ───────────────────────────────────────────── */}
      {behaviour && hasBehaviourContent(behaviour) && (
        <Panel title="VirusTotal behaviour (sandboxed)">
          <BehaviourBlock b={behaviour}/>
        </Panel>
      )}

      {/* ── [WHOIS] (domain only) ────────────────────────────────────── */}
      {whois?.found && (
        <Panel title="WHOIS">
          <dl className="grid grid-cols-1 md:grid-cols-2 gap-y-2 gap-x-6 text-sm">
            {whois.registrar && <Signal label="Registrar" value={String(whois.registrar)}/>}
            {whois.creation_date && (
              <Signal label="Registered"
                      value={`${whois.creation_date}${whois.age_days != null ? ` (${whois.age_days} days old)` : ""}`}
                      accent={whois.new_domain ? "text-danger font-semibold" : undefined}/>
            )}
            {whois.expiration_date && <Signal label="Expires" value={String(whois.expiration_date)}/>}
            {arr(whois.nameservers).length > 0 && (
              <Signal label="Nameservers" value={arr(whois.nameservers).join(", ")}/>
            )}
          </dl>
          {whois.new_domain && (
            <div className="mt-3 text-sm text-danger flex items-start gap-2">
              <AlertTriangle size={14} className="mt-0.5"/> Newly registered domain — heightened risk.
            </div>
          )}
        </Panel>
      )}

      {/* ── [HOSTNAMES / PASSIVE DNS] ────────────────────────────────── */}
      {hostnames.length > 0 && (
        <Panel title={`Hostnames / Passive DNS (${hostnames.length})`}>
          <table className="w-full text-sm">
            <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
              <tr className="text-left">
                <th className="py-2 pr-3">Hostname</th>
                <th className="py-2 pr-3">Sources</th>
                <th className="py-2 pr-3">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {hostnames.slice(0, 50).map((h: any, i: number) => {
                const name = typeof h === "string" ? h : (h?.hostname || h?.name || JSON.stringify(h));
                const srcs = arr(h?.sources).join(", ");
                return (
                  <tr key={`${name}-${i}`} className="border-t border-line/60">
                    <td className="py-2 pr-3 font-mono text-xs break-all">{flagIfInteresting(name)}</td>
                    <td className="py-2 pr-3 text-muted text-xs">{srcs || "—"}</td>
                    <td className="py-2 pr-3 text-muted text-xs">{h?.last_seen || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {hostnames.length > 50 && (
            <div className="text-xs text-muted mt-2">… {hostnames.length - 50} more in raw JSON below.</div>
          )}
        </Panel>
      )}

      {/* ── [SOURCE DETAILS] ─────────────────────────────────────────── */}
      <Panel title="Source details">
        <div className="space-y-5">
          {sources.map((s: any, i: number) => (
            <SourceBlock key={`${s?.source}-${i}`} s={s} vtMalCount={vtMaliciousCount}/>
          ))}
        </div>
      </Panel>

      {/* ── Raw JSON toggle ─────────────────────────────────────────── */}
      <div>
        <button onClick={() => setShowRaw((v) => !v)}
                className="inline-flex items-center gap-1.5 text-xs text-muted hover:text-accent">
          {showRaw ? <ChevronDown size={14}/> : <ChevronRight size={14}/>}
          {showRaw ? "Hide" : "Show"} raw JSON
        </button>
        {showRaw && (
          <pre className="mt-3 text-[11px] bg-base border border-line rounded-md p-3 overflow-x-auto max-h-[60vh] font-mono">
            {safeStringify(data)}
          </pre>
        )}
      </div>
    </div>
  );
}


// ── Sub-components ────────────────────────────────────────────────────

function VerdictPill({ verdict }: { verdict: string }) {
  const Icon =
    verdict === "malicious" ? ShieldX :
    verdict === "suspicious" ? ShieldAlert :
    verdict === "clean" ? ShieldCheck :
    ShieldAlert;
  const klass =
    verdict === "malicious" ? "pill pill-critical" :
    verdict === "suspicious" ? "pill pill-high" :
    verdict === "clean" ? "pill pill-resolved" :
    "pill pill-low";
  return (
    <span className={cn(klass, "inline-flex items-center gap-1.5")}>
      <Icon size={12}/> {verdict.toUpperCase()}
    </span>
  );
}

function Signal({ label, value, accent }: { label: string; value: React.ReactNode; accent?: string }) {
  return (
    <div className="flex justify-between gap-3 border-b border-line/40 pb-1">
      <dt className="text-[10px] uppercase tracking-wider text-muted">{label}</dt>
      <dd className={cn("text-sm text-right break-all", accent || "text-text")}>{value}</dd>
    </div>
  );
}

function SourceBlock({ s, vtMalCount }: { s: any; vtMalCount: number }) {
  if (!s || typeof s !== "object") return null;
  const name = String(s.source || "unknown").toUpperCase();
  const ok   = s.found === true;
  const error = s.error;
  const tags = arr(s.tags);
  const threatNames = arr(s.threat_names);
  const pulseNames  = arr(s.pulse_names);

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <span className={cn("inline-block w-5 h-5 rounded-full grid place-items-center text-xs",
          ok ? "bg-positive/15 text-positive border border-positive/40" :
               "bg-muted/10 text-muted border border-line"
        )}>{ok ? "✓" : "✗"}</span>
        <span className="font-mono text-sm font-semibold text-text">{name}</span>
        {!ok && (
          <span className="text-xs text-muted">
            {error ? `error: ${truncate(String(error), 80)}` : "not found"}
          </span>
        )}
      </div>

      {ok && (
        <dl className="ml-7 grid grid-cols-1 md:grid-cols-2 gap-y-1.5 gap-x-6 text-sm">
          {s.signature        && <Row k="Malware"     v={String(s.signature)}        accent="text-warning"/>}
          {s.popular_threat_names && (
            <Row k="Threat names"
                 v={asStringOrList(s.popular_threat_names)}
                 accent="text-warning"/>
          )}
          {s.detection_rate   && <Row k="Detection"   v={String(s.detection_rate)}   accent={vtBadgeClass(s.detection_rate)}/>}
          {s.detections && typeof s.detections === "object" && (() => {
            const m = toInt(s.detections.malicious);
            const sus = toInt(s.detections.suspicious);
            const h = toInt(s.detections.harmless);
            const u = toInt(s.detections.undetected);
            const total = m + sus + h + u;
            if (total === 0) return null;
            const rate = `${m}/${total}`;
            return <Row k="Detection" v={rate} accent={vtBadgeClass(rate)}/>;
          })()}
          {s.reputation !== undefined && s.reputation !== null && (
            <Row k="Reputation" v={signed(toInt(s.reputation))}
                 accent={toInt(s.reputation) < 0 ? "text-danger" : toInt(s.reputation) > 0 ? "text-positive" : undefined}/>
          )}
          {s.abuse_confidence_score !== undefined && s.abuse_confidence_score !== null && (
            <Row k="Abuse score"
                 v={`${s.abuse_confidence_score}%`}
                 accent={abuseBadge(toInt(s.abuse_confidence_score))}/>
          )}
          {s.total_reports !== undefined && <Row k="Reports" v={String(s.total_reports)}/>}
          {s.num_distinct_users !== undefined && <Row k="Distinct reporters" v={String(s.num_distinct_users)}/>}
          {s.country         && <Row k="Country"   v={String(s.country)}/>}
          {s.isp             && <Row k="ISP"       v={String(s.isp)}/>}
          {s.usage_type      && <Row k="Usage"     v={String(s.usage_type)}/>}
          {s.as_owner        && <Row k="ASN/Owner" v={`${s.asn ? `AS${s.asn} ` : ""}${s.as_owner}`}/>}
          {s.title           && <Row k="Page title" v={String(s.title)}/>}
          {s.final_url && s.final_url !== s.url && <Row k="Final URL" v={String(s.final_url)}/>}
          {s.first_seen      && <Row k="First seen" v={String(s.first_seen)}/>}
          {s.first_submission && <Row k="First submission"
                                       v={typeof s.first_submission === "number"
                                            ? new Date(s.first_submission * 1000).toISOString().slice(0, 10)
                                            : String(s.first_submission).slice(0, 10)}/>}
          {s.last_analysis   && <Row k="Last analysis"
                                       v={typeof s.last_analysis === "number"
                                            ? new Date(s.last_analysis * 1000).toISOString().slice(0, 10)
                                            : String(s.last_analysis).slice(0, 10)}/>}
          {s.file_name       && <Row k="File name" v={String(s.file_name)}/>}
          {s.file_type       && <Row k="File type" v={String(s.file_type)}/>}
          {s.file_size !== undefined && (
            <Row k="File size" v={`${Number(s.file_size).toLocaleString()} bytes`}/>
          )}
          {s.magic           && <Row k="Magic" v={String(s.magic)}/>}
          {s.md5             && <Row k="MD5"    v={<span className="font-mono text-[11px]">{String(s.md5)}</span>}/>}
          {s.sha1            && <Row k="SHA1"   v={<span className="font-mono text-[11px]">{String(s.sha1)}</span>}/>}
          {s.sha256          && <Row k="SHA256" v={<span className="font-mono text-[11px]">{String(s.sha256)}</span>}/>}
          {s.pulse_count !== undefined && <Row k="OTX pulses" v={String(s.pulse_count)}/>}
          {s.url_count !== undefined && <Row k="Malicious URLs" v={String(s.url_count)}/>}
          {s.malware_sample_count !== undefined && <Row k="Malware samples" v={String(s.malware_sample_count)}/>}
        </dl>
      )}

      {/* Tags */}
      {ok && tags.length > 0 && (
        <div className="ml-7 mt-2 flex flex-wrap gap-1.5">
          {tags.slice(0, 12).map((t: string) => (
            <span key={t} className={cn("pill text-[10px]", tagClass(t))}>{t}</span>
          ))}
        </div>
      )}

      {/* OTX pulse names */}
      {ok && pulseNames.length > 0 && (
        <div className="ml-7 mt-3">
          <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">OTX pulses</div>
          <ul className="text-xs text-text/90 space-y-0.5">
            {pulseNames.slice(0, 5).map((n: string, i: number) => <li key={i}>• {n}</li>)}
          </ul>
        </div>
      )}

      {/* threat_names (URL/domain sources) */}
      {ok && threatNames.length > 0 && (
        <div className="ml-7 mt-3">
          <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">Threats</div>
          <div className="text-xs text-warning">{threatNames.slice(0, 8).join(", ")}</div>
        </div>
      )}

      {/* signature_info */}
      {ok && s.signature_info && typeof s.signature_info === "object" && (
        <div className="ml-7 mt-3 text-xs">
          <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">Code signing</div>
          {[
            ["Product",   s.signature_info.product || s.signature_info.name],
            ["Publisher", s.signature_info.publisher || s.signature_info.signers],
            ["Verified",  s.signature_info.verified],
          ].filter(([, v]) => v).map(([k, v]) => (
            <div key={k as string} className="flex gap-2"><span className="text-muted w-20">{k}</span><span>{String(v)}</span></div>
          ))}
        </div>
      )}

      {/* Sandbox verdicts */}
      {ok && s.sandbox_verdicts && Object.keys(s.sandbox_verdicts).length > 0 && (
        <div className="ml-7 mt-3">
          <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">Sandboxes</div>
          <table className="w-full text-xs">
            <tbody>
              {Object.entries(s.sandbox_verdicts as Record<string, any>).map(([box, sv]: [string, any]) => {
                const cat = String(sv?.category || "?").toLowerCase();
                const conf = sv?.confidence;
                const names = arr(sv?.malware_names || sv?.malware_classification).join(", ");
                const evasion = cat === "harmless" && vtMalCount > 5;
                return (
                  <tr key={box} className="border-t border-line/40">
                    <td className="py-1.5 pr-3 font-mono text-muted">{box}</td>
                    <td className="py-1.5 pr-3">
                      <span className={cn("pill text-[10px]", catKlass(cat))}>{cat}</span>
                      {conf !== undefined && conf !== "" && <span className="ml-2 text-muted">conf:{conf}</span>}
                      {evasion && <span className="ml-2 text-warning">⚠ evasion</span>}
                    </td>
                    <td className="py-1.5 pr-3 text-muted">{names || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* last_analysis_results — top flagged AV vendors */}
      {ok && s.last_analysis_results && typeof s.last_analysis_results === "object" && (() => {
        const flagged = Object.entries(s.last_analysis_results as Record<string, any>)
          .filter(([, v]: [string, any]) => v?.category === "malicious" || v?.category === "suspicious")
          .map(([vendor, v]: [string, any]) => [vendor, v?.result || "?"] as [string, string]);
        if (flagged.length === 0) return null;
        return (
          <div className="ml-7 mt-3">
            <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
              Detections ({flagged.length} vendors)
            </div>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-y-0.5 text-[11px] font-mono">
              {flagged.slice(0, 14).map(([v, res]) => (
                <li key={v} className="flex gap-2">
                  <span className="text-muted w-32 shrink-0 truncate">{v}</span>
                  <span className="text-warning truncate">{res}</span>
                </li>
              ))}
            </ul>
            {flagged.length > 14 && (
              <div className="text-[10px] text-muted mt-1">… {flagged.length - 14} more vendors flagged.</div>
            )}
          </div>
        );
      })()}
    </div>
  );
}

function Row({ k, v, accent }: { k: string; v: React.ReactNode; accent?: string }) {
  return (
    <div className="flex justify-between gap-3 border-b border-line/40 pb-1">
      <dt className="text-[10px] uppercase tracking-wider text-muted">{k}</dt>
      <dd className={cn("text-sm text-right break-all", accent || "text-text")}>{v}</dd>
    </div>
  );
}

function BehaviourBlock({ b }: { b: any }) {
  const sections: Array<[string, any[], (x: any) => React.ReactNode]> = [
    ["DNS Lookups",         arr(b?.dns_lookups),         (x) => typeof x === "string" ? x :
                                                                  `${x?.hostname || x?.host || "?"}  →  ${arr(x?.resolved_ips).join(", ") || "(none)"}`],
    ["Network Connections", arr(b?.ip_traffic),          (x) => typeof x === "string" ? x :
                                                                  `${x?.destination_ip ?? "?"}:${x?.destination_port ?? "?"}  ${(x?.transport_layer_protocol || "").toUpperCase()}`],
    ["HTTP Requests",       arr(b?.http_conversations),  (x) => typeof x === "string" ? x :
                                                                  `${(x?.request_method || "GET")} ${truncate(x?.url || x?.request_url || "?", 80)}  →  ${x?.response_status_code ?? "?"}`],
    ["Files Written",       arr(b?.files_written),       (x) => typeof x === "string" ? x : (x?.path || safeStringify(x))],
    ["Files Opened",        arr(b?.files_opened),        (x) => typeof x === "string" ? x : (x?.path || safeStringify(x))],
    ["Processes Created",   arr(b?.processes_created),   (x) => typeof x === "string" ? truncate(x, 120) :
                                                                  truncate(x?.command_line || x?.process_name || safeStringify(x), 120)],
    ["Registry Keys Set",   arr(b?.registry_keys_set),   (x) => typeof x === "string" ? x : (x?.key || safeStringify(x))],
  ];

  return (
    <div className="space-y-4">
      {sections.filter(([, items]) => items.length > 0).map(([title, items, render]) => (
        <div key={title}>
          <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">{title} ({items.length})</div>
          <ul className="space-y-1">
            {items.slice(0, 10).map((it, i) => (
              <li key={i} className="font-mono text-xs text-text/90 break-all">{render(it)}</li>
            ))}
          </ul>
        </div>
      ))}
      {sections.every(([, items]) => items.length === 0) && (
        <div className="text-xs text-muted">No behavioural data captured by the sandbox.</div>
      )}
      {arr(b?.tags).length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">Behaviour tags</div>
          <div className="flex flex-wrap gap-1.5">
            {arr(b.tags).map((t: string) => (
              <span key={t} className={cn("pill text-[10px]", tagClass(String(t).toLowerCase()))}>{t}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}


// ── Helpers (all defensive) ───────────────────────────────────────────

/** Always return an array. Strings/null/undefined/objects all become safe arrays. */
function arr(v: any): any[] {
  if (Array.isArray(v)) return v;
  if (v == null) return [];
  // Common case: a single-string field that's sometimes returned scalar
  if (typeof v === "string") return v ? [v] : [];
  return [];
}

/** For fields like `popular_threat_names` that arrive as either string or array. */
function asStringOrList(v: any): string {
  if (Array.isArray(v)) return v.slice(0, 6).map(String).join(", ");
  return String(v ?? "");
}

function parseDetectionMalicious(d?: any): number {
  if (!d || typeof d !== "string") return 0;
  const m = d.match(/^(\d+)\/(\d+)/);
  return m ? parseInt(m[1], 10) : 0;
}

function vtBadgeClass(d?: any) {
  const m = parseDetectionMalicious(d);
  if (m >= 15) return "text-danger font-semibold";
  if (m >= 5)  return "text-warning font-semibold";
  if (m > 0)   return "text-accent";
  return "text-positive";
}

function abuseBadge(score: number) {
  if (score >= 75) return "text-danger font-semibold";
  if (score >= 25) return "text-warning";
  if (score >= 10) return "text-accent";
  return "text-positive";
}

function confKlass(c: string) {
  if (c === "HIGH")   return "pill-critical";
  if (c === "MEDIUM") return "pill-high";
  return "pill-low";
}

function catKlass(c: string) {
  if (c === "malicious")  return "pill-critical";
  if (c === "suspicious") return "pill-high";
  if (c === "harmless")   return "pill-resolved";
  return "pill-low";
}

function tagClass(t: string) {
  const danger = ["revoked-cert", "malware", "trojan", "ransomware", "phishing", "exploit", "spreader", "persistence"];
  const warn   = ["suspicious", "obfuscated", "packed", "self-signed", "long-sleeps", "detect-debug-environment", "checks-user-input"];
  const low    = ["nxdomain"];
  if (danger.some((d) => t.includes(d))) return "pill-critical";
  if (warn.some((d) => t.includes(d)))   return "pill-high";
  if (low.some((d) => t.includes(d)))    return "pill-low";
  return "pill-medium";
}

function flagIfInteresting(host: string) {
  const interesting = [".gov", ".gov.tr", ".mil", "btk.", "tubitak", "police"];
  if (host && interesting.some((s) => host.toLowerCase().includes(s))) {
    return <span><b className="text-warning">{host}</b> <span className="text-warning text-[10px]">★ gov/attrib</span></span>;
  }
  return host || "—";
}

function signed(v: number) { return v > 0 ? `+${v}` : String(v); }

function toInt(v: any): number {
  if (typeof v === "number") return v;
  const n = parseInt(String(v).replace("%", ""), 10);
  return Number.isFinite(n) ? n : 0;
}

function truncate(s: string, n: number) {
  s = String(s ?? "");
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function hasBehaviourContent(b: any): boolean {
  return [
    "dns_lookups","ip_traffic","http_conversations","files_written",
    "files_opened","processes_created","registry_keys_set",
  ].some((k) => arr(b?.[k]).length > 0);
}

function safeStringify(v: any): string {
  try { return JSON.stringify(v, null, 2); }
  catch { return String(v); }
}
