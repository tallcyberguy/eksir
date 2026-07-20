"use client";

import { useState } from "react";
import {
  ShieldX, ShieldAlert, ShieldCheck, AlertTriangle, ChevronDown, ChevronRight,
  Download, FileText, Cpu, Network, Shield, Hash,
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Panel } from "@/components/ui/Panel";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";

/**
 * Renders the JSONB `result` from a completed static-analysis forensics job
 * into an analyst-grade report. Mirrors the structure of the malware-analysis
 * skill's markdown output:
 *
 *   1. Verdict header        (synthesis.verdict + confidence + key_finding)
 *   2. File metadata         (file_info + diec + exiftool)
 *   3. Threat intel triage   (ti_triage card — VT detection, family, tags)
 *   4. LLM synthesis         (executive summary + behavioral assessment)
 *   5. YARA matches          (core + full hit counts; family chips)
 *   6. capa capabilities     (MITRE ATT&CK technique chips)
 *   7. Suspicious indicators (URLs, IPs, emails extracted by peframe / interesting strings)
 *   8. PE structure          (pescan anomalies + section summary)
 *   9. Raw tool outputs      (collapsible accordion — power users only)
 */
export function ForensicsReport({ jobId, data }: { jobId: string; data: any }) {
  const [showRaw, setShowRaw] = useState(false);

  if (!data || typeof data !== "object") {
    return <Panel title="Result"><div className="text-sm text-muted">No data.</div></Panel>;
  }

  const synthesis = data.synthesis || {};
  const fileInfo  = data.file_info || {};
  const diec      = (data.diec || {}).parsed || {};
  const exiftool  = (data.exiftool || {}).parsed || {};
  const peframe   = (data.peframe || {}).parsed || {};
  const pescan    = data.pescan || {};
  const capa      = data.capa || {};
  const yaraCore  = data.yara_core || {};
  const yaraFull  = data.yara_full || {};
  const signsrch  = data.signsrch || {};
  const pestr     = data.pestr || {};
  const floss     = data.floss || {};
  const ti        = data.ti_triage || {};
  // Type-specific
  const fileType  = String(data._file_type || "unknown");
  const toolsRun  = arr(data._tools_run);
  // Extended catalog + new analysis blocks
  const peStatic    = data.pe_static || {};
  const embeddedIocs = arr(data.embedded_ioc_triage);
  const ssdeepR     = data.ssdeep || {};
  const rtfobjR     = data.rtfobj || {};
  const xlmR        = data.xlmdeobfuscator || {};
  const jsR         = data.js_deobfuscate || {};
  const dotnetR     = data.dotnet_info || {};
  const csR         = data.cs_config || {};
  const unpackedR   = data.unpacked || {};
  const narrative   = String((data.synthesis || {}).analyst_narrative || "");
  const oledumpR  = data.oledump || {};
  const olevbaR   = data.olevba  || {};
  const oleidR    = data.oleid   || {};
  const mraptorR  = data.mraptor || {};
  const pdfidR    = data.pdfid   || {};
  const pdfParserR = data.pdf_parser || {};
  const peepdfR   = data.peepdf  || {};
  const readelfR  = data.readelf || {};
  const radare2R  = data.radare2 || {};
  const archiveR  = data.archive || {};

  const verdict       = String(synthesis.verdict || "").toUpperCase();
  const confidence    = String(synthesis.confidence || "").toUpperCase();
  const fpLikelihood  = String(synthesis.false_positive_likelihood || "").toUpperCase();

  return (
    <div className="space-y-5">
      {/* ── Verdict header ────────────────────────────────────────── */}
      <Panel className={verdictBorderClass(verdict)}>
        <div className="flex items-center gap-3 mb-3 flex-wrap">
          <VerdictPill verdict={verdict}/>
          {confidence && (
            <span className={cn("pill", confKlass(confidence))}>confidence {confidence}</span>
          )}
          {fileType && fileType !== "unknown" && (
            <span className="pill pill-medium text-[10px] font-mono" title={`Tools run: ${toolsRun.join(", ")}`}>
              type: {fileType}
            </span>
          )}
          {fpLikelihood && fpLikelihood !== "LOW" && (
            <span className="pill pill-low">FP likelihood: {fpLikelihood}</span>
          )}
          <span className="ml-auto flex items-center gap-2">
            <a
              href={api.reportMarkdownUrl(jobId)}
              target="_blank"
              rel="noopener"
              className="inline-flex items-center gap-1.5 text-xs text-muted hover:text-accent"
            >
              <Download size={13}/> Report .md
            </a>
          </span>
        </div>
        {synthesis.executive_summary && (
          <p className="text-sm text-text/90 leading-relaxed">{synthesis.executive_summary}</p>
        )}
        {synthesis.key_finding && (
          <p className="mt-3 text-sm text-text border-l-2 border-accent/60 pl-3">
            <span className="text-[10px] uppercase tracking-wider text-muted block mb-0.5">Key finding</span>
            {synthesis.key_finding}
          </p>
        )}
        {synthesis.error && (
          <p className="text-xs text-warning">⚠ LLM synthesis failed: {synthesis.error}</p>
        )}
      </Panel>

      {/* ── Analyst narrative (MBC / packing / detection eng / pyramid) ── */}
      {narrative && (
        <Panel title="Analyst Report">
          <div className="prose prose-invert prose-sm max-w-none text-sm leading-relaxed
                          prose-headings:text-text prose-headings:text-sm prose-headings:font-semibold
                          prose-code:text-accent prose-pre:bg-base prose-pre:border prose-pre:border-line">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{narrative}</ReactMarkdown>
          </div>
        </Panel>
      )}

      {/* ── File metadata ─────────────────────────────────────────── */}
      <Panel title="File">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-sm">
          {fileInfo.sha256 && <Field label="SHA256" mono small value={fileInfo.sha256}/>}
          {fileInfo.sha1   && <Field label="SHA1"   mono small value={fileInfo.sha1}/>}
          {fileInfo.md5    && <Field label="MD5"    mono small value={fileInfo.md5}/>}
          {fileInfo.size != null && <Field label="Size" value={`${fileInfo.size.toLocaleString()} bytes`}/>}
          {fileInfo.file_type && <Field label="Type" value={fileInfo.file_type}/>}
          {ssdeepR.fuzzy_hash && <Field label="ssdeep" mono small value={ssdeepR.fuzzy_hash}/>}
          {diec.compiler && <Field label="Compiler" value={diec.compiler}/>}
          {diec.linker   && <Field label="Linker"   value={diec.linker}/>}
          {diec.packer   && <Field label="Packer"   accent="text-warning" value={diec.packer}/>}
          {exiftool.TimeStamp && <Field label="PE timestamp" value={String(exiftool.TimeStamp)}/>}
          {exiftool.CompanyName && <Field label="Company" value={String(exiftool.CompanyName)}/>}
          {exiftool.OriginalFileName && <Field label="Original name" value={String(exiftool.OriginalFileName)}/>}
          {exiftool.LegalCopyright && <Field label="Copyright" value={String(exiftool.LegalCopyright)}/>}
        </div>
      </Panel>

      {/* ── PE structure (entropy / RWX / packing) ────────────────── */}
      {peStatic && Object.keys(peStatic).length > 0 && !peStatic.error && (
        <Panel title="PE Structure (entropy / packing)"
               className={peStatic.packed || arr(peStatic.rwx_sections).length > 0 ? "border-warning/40" : ""}>
          <div className="flex items-center gap-2 flex-wrap mb-3">
            {peStatic.packed && <span className="pill pill-high text-[10px]">packed</span>}
            {arr(peStatic.rwx_sections).length > 0 && (
              <span className="pill pill-critical text-[10px]">RWX: {peStatic.rwx_sections.join(", ")}</span>
            )}
            {peStatic.machine && <span className="pill pill-medium text-[10px] font-mono">{peStatic.type} · {peStatic.machine}</span>}
            {peStatic.compile_timestamp && (
              <span className="text-[11px] text-muted">compiled {peStatic.compile_timestamp}</span>
            )}
          </div>
          {arr(peStatic.sections).length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-[11px] font-mono">
                <thead>
                  <tr className="text-muted text-left">
                    <th className="py-1 pr-3">Section</th><th className="py-1 pr-3">Entropy</th>
                    <th className="py-1 pr-3">Raw size</th><th className="py-1 pr-3">Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {arr(peStatic.sections).map((s: any, i: number) => (
                    <tr key={i} className="border-t border-line/40">
                      <td className="py-1 pr-3 text-text/90">{s.name || "(unnamed)"}</td>
                      <td className={cn("py-1 pr-3", s.entropy > 7.0 && "text-danger font-bold")}>{s.entropy}</td>
                      <td className="py-1 pr-3 text-muted">{s.raw_size}</td>
                      <td className="py-1 pr-3">
                        {s.rwx ? <span className="text-danger">RWX</span>
                          : `${s.executable ? "X" : ""}${s.writable ? "W" : ""}` || "R"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {arr(peStatic.packing_indicators).length > 0 && (
            <ul className="mt-3 text-xs text-warning space-y-0.5">
              {arr(peStatic.packing_indicators).map((p: string, i: number) => <li key={i}>• {p}</li>)}
            </ul>
          )}
        </Panel>
      )}

      {/* ── TI triage (hash lookup) ───────────────────────────────── */}
      {ti && Object.keys(ti).length > 0 && (
        <Panel title="Threat intelligence (hash lookup)">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-sm">
            <Field label="Verdict" value={String(ti.verdict || "unknown")}
                   accent={ti.verdict === "malicious" ? "text-danger font-semibold" :
                           ti.verdict === "suspicious" ? "text-warning" :
                           ti.verdict === "clean_or_unknown" ? "text-positive" : undefined}/>
            <Field label="Confidence" value={String(ti.confidence || "—")}/>
            {ti.summary?.virustotal_detection && (
              <Field label="VirusTotal" value={ti.summary.virustotal_detection}
                     accent={vtBadgeClass(ti.summary.virustotal_detection)}/>
            )}
            {ti.summary?.found_in_sources && (
              <Field label="Sources matched" value={(ti.summary.found_in_sources || []).join(", ") || "—"}/>
            )}
          </div>
          {arr(ti.summary?.malware_families).length > 0 && (
            <div className="mt-3">
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">Malware families</div>
              <div className="flex flex-wrap gap-1.5">
                {arr(ti.summary.malware_families).map((f: string) => (
                  <span key={f} className="pill pill-critical text-[10px]">{f}</span>
                ))}
              </div>
            </div>
          )}
          {arr(ti.summary?.tags).length > 0 && (
            <div className="mt-3">
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">Tags</div>
              <div className="flex flex-wrap gap-1.5">
                {arr(ti.summary.tags).slice(0, 20).map((t: string) => (
                  <span key={t} className="pill pill-medium text-[10px]">{t}</span>
                ))}
              </div>
            </div>
          )}
        </Panel>
      )}

      {/* ── Behavioral assessment (LLM-synthesized) ───────────────── */}
      {arr(synthesis.behavioral_assessment).length > 0 && (
        <Panel title="Behavioral Assessment">
          <div className="space-y-3">
            {arr(synthesis.behavioral_assessment).map((b: any, i: number) => (
              <div key={i} className="border border-line/60 rounded-md p-3">
                <div className="flex items-center justify-between gap-3 mb-1">
                  <span className="text-sm font-semibold text-text">{b.capability}</span>
                  <span className={cn("pill text-[10px]", confKlass(String(b.confidence || "").toUpperCase()))}>
                    {String(b.confidence || "").toUpperCase()}
                  </span>
                </div>
                <p className="text-xs text-text/80 leading-relaxed">{b.evidence}</p>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* ── MITRE ATT&CK chips ────────────────────────────────────── */}
      {(arr(synthesis.mitre_techniques).length > 0 || arr(capa.attack_techniques).length > 0) && (
        <Panel title="MITRE ATT&CK">
          <div className="flex flex-wrap gap-1.5">
            {dedupeMitre([...arr(synthesis.mitre_techniques), ...arr(capa.attack_techniques)]).slice(0, 30).map((t: any, i: number) => (
              <span key={i} className="pill pill-medium text-[10px]" title={t.tactic ? `Tactic: ${t.tactic}` : ""}>
                <span className="font-mono text-[9px] opacity-70 mr-1">{t.id}</span>
                {t.name || t.technique}
              </span>
            ))}
          </div>
        </Panel>
      )}

      {/* ── Office macros (oledump + olevba + oleid + mraptor) ──── */}
      {(oledumpR.macros_present || olevbaR.macro_count > 0 || arr(olevbaR.suspicious_keywords).length > 0 || mraptorR.verdict) && (
        <Panel title="Office Macros" className={olevbaR.macro_count > 0 || mraptorR.verdict === "SUSPICIOUS" ? "border-warning/40" : ""}>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm mb-3">
            <Field label="VBA macros found" value={olevbaR.macro_count ?? "—"}
                   accent={olevbaR.macro_count > 0 ? "text-warning font-semibold" : "text-positive"}/>
            <Field label="OLE streams" value={arr(oledumpR.streams).length || "—"}/>
            <Field label="mraptor verdict" value={mraptorR.verdict || "—"}
                   accent={mraptorR.verdict === "SUSPICIOUS" ? "text-danger font-semibold" :
                           mraptorR.verdict === "NOT SUSPICIOUS" ? "text-positive" : undefined}/>
          </div>
          {arr(olevbaR.suspicious_keywords).length > 0 && (
            <div className="mb-3">
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
                olevba — Suspicious keywords ({arr(olevbaR.suspicious_keywords).length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {arr(olevbaR.suspicious_keywords).slice(0, 30).map((k: string, i: number) => (
                  <span key={i} className="pill pill-high text-[10px] font-mono">{k}</span>
                ))}
              </div>
            </div>
          )}
          {arr(olevbaR.iocs).length > 0 && (
            <div className="mb-3">
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">olevba — IOCs in macros</div>
              <ul className="text-xs font-mono text-warning space-y-0.5">
                {arr(olevbaR.iocs).slice(0, 20).map((v: string, i: number) => (
                  <li key={i} className="break-all">{defang(v)}</li>
                ))}
              </ul>
            </div>
          )}
          {arr(oledumpR.streams).length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">OLE streams ({oledumpR.streams.length})</div>
              <div className="overflow-x-auto">
                <table className="w-full text-[11px] font-mono">
                  <thead>
                    <tr className="text-muted text-left">
                      <th className="py-1 pr-3">#</th>
                      <th className="py-1 pr-3">Type</th>
                      <th className="py-1 pr-3">Size</th>
                      <th className="py-1 pr-3">Name</th>
                    </tr>
                  </thead>
                  <tbody>
                    {arr(oledumpR.streams).slice(0, 30).map((s: any, i: number) => (
                      <tr key={i} className="border-t border-line/40">
                        <td className="py-1 pr-3">{s.index}</td>
                        <td className={cn("py-1 pr-3", s.type === "M" && "text-danger font-bold")}>{s.type || "—"}</td>
                        <td className="py-1 pr-3">{s.size}</td>
                        <td className="py-1 pr-3 text-text/90 break-all">{s.name}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          {arr(oleidR.indicators).length > 0 && (
            <div className="mt-3">
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">oleid — indicators</div>
              <ul className="text-xs text-text/80 space-y-0.5 font-mono">
                {arr(oleidR.indicators).slice(0, 12).map((it: any, i: number) => (
                  <li key={i} className="break-all">• {it.line || JSON.stringify(it)}</li>
                ))}
              </ul>
            </div>
          )}
        </Panel>
      )}

      {/* ── PDF risk flags (pdfid + pdf-parser + peepdf) ────────── */}
      {(Object.keys(pdfidR.risk_flags || {}).length > 0 || Object.keys(pdfidR.counts || {}).length > 0) && (
        <Panel title="PDF Risk Analysis" className={Object.keys(pdfidR.risk_flags || {}).length > 0 ? "border-warning/40" : ""}>
          {Object.keys(pdfidR.risk_flags || {}).length > 0 && (
            <div className="mb-3">
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">⚠ Active-content keywords</div>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(pdfidR.risk_flags as Record<string, number>).map(([k, n]) => (
                  <span key={k} className="pill pill-high text-[10px] font-mono">
                    {k} <span className="opacity-70">×{n}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
          {Object.keys(pdfidR.counts || {}).length > 0 && (
            <details className="text-xs">
              <summary className="cursor-pointer text-muted hover:text-accent">
                All pdfid keyword counts ({Object.keys(pdfidR.counts).length})
              </summary>
              <table className="mt-2 text-[11px] font-mono">
                <tbody>
                  {Object.entries(pdfidR.counts as Record<string, number>).filter(([_, n]) => n > 0).map(([k, n]) => (
                    <tr key={k} className="border-t border-line/40">
                      <td className="py-1 pr-3 text-muted">{k}</td>
                      <td className="py-1 pr-3 text-right">{n}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          )}
          {peepdfR.raw && (
            <details className="text-xs mt-3">
              <summary className="cursor-pointer text-muted hover:text-accent">peepdf output</summary>
              <pre className="mt-2 text-[10px] bg-base border border-line rounded-md p-2 max-h-[30vh] overflow-auto font-mono">
                {String(peepdfR.raw).slice(0, 3000)}
              </pre>
            </details>
          )}
        </Panel>
      )}

      {/* ── ELF / radare2 ─────────────────────────────────────────── */}
      {(readelfR.raw || radare2R.raw) && (
        <Panel title="Binary Structure (ELF/Mach-O)">
          {readelfR.raw && (
            <details className="text-xs mb-2" open>
              <summary className="cursor-pointer text-muted hover:text-accent">readelf output</summary>
              <pre className="mt-2 text-[10px] bg-base border border-line rounded-md p-2 max-h-[30vh] overflow-auto font-mono">
                {String(readelfR.raw).slice(0, 4000)}
              </pre>
            </details>
          )}
          {radare2R.raw && (
            <details className="text-xs">
              <summary className="cursor-pointer text-muted hover:text-accent">radare2 analysis</summary>
              <pre className="mt-2 text-[10px] bg-base border border-line rounded-md p-2 max-h-[30vh] overflow-auto font-mono">
                {String(radare2R.raw).slice(0, 4000)}
              </pre>
            </details>
          )}
        </Panel>
      )}

      {/* ── Archive contents ──────────────────────────────────────── */}
      {arr(archiveR.entries).length > 0 && (
        <Panel title={`Archive Contents (${archiveR.entry_count ?? archiveR.entries.length} files)`}>
          <ul className="text-[11px] font-mono space-y-0.5 max-h-[40vh] overflow-y-auto">
            {arr(archiveR.entries).slice(0, 100).map((e: string, i: number) => (
              <li key={i} className="text-text/80 break-all">{e}</li>
            ))}
          </ul>
          {arr(archiveR.entries).length > 100 && (
            <div className="text-[10px] text-muted mt-2">… {arr(archiveR.entries).length - 100} more in raw JSON</div>
          )}
        </Panel>
      )}

      {/* ── YARA matches ──────────────────────────────────────────── */}
      <Panel title={`YARA matches (core: ${yaraCore.match_count ?? 0} / full: ${yaraFull.match_count ?? 0})`}>
        {(yaraCore.match_count ?? 0) === 0 && (yaraFull.match_count ?? 0) === 0 ? (
          <div className="text-xs text-muted">
            No matches across {yaraCore.rule_count ?? 0} core + {yaraFull.rule_count ?? 0} full YARA-Forge rules.
            Strong signal of absence — these rulesets aggregate 45+ malware family signature sources.
          </div>
        ) : (
          <div className="space-y-2">
            {[...arr(yaraCore.matches), ...arr(yaraFull.matches)].slice(0, 20).map((m: any, i: number) => (
              <div key={i} className="flex items-center gap-3 text-sm">
                <span className="pill pill-critical text-[10px] font-mono">{m.rule}</span>
                {m.namespace && <span className="text-xs text-muted font-mono">{m.namespace}</span>}
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* ── Suspicious indicators (URLs / IPs / Emails / API-strings) ── */}
      {(arr(peframe.urls).length + arr(peframe.ips).length + arr(peframe.emails).length + arr(pestr.interesting).length > 0) && (
        <Panel title="Suspicious Indicators">
          {arr(peframe.urls).length > 0 && (
            <IndicatorList label="URLs" items={arr(peframe.urls).map(defang)} accent="text-warning"/>
          )}
          {arr(peframe.ips).length > 0 && (
            <IndicatorList label="IPs" items={arr(peframe.ips).map(defang)} accent="text-accent2"/>
          )}
          {arr(peframe.emails).length > 0 && (
            <IndicatorList label="Emails" items={arr(peframe.emails).map(defang)} accent="text-accent"/>
          )}
          {arr(pestr.interesting).length > 0 && (
            <IndicatorList label="Suspicious-API strings" items={arr(pestr.interesting).slice(0, 20)} mono small/>
          )}
        </Panel>
      )}

      {/* ── Narrative strings (author-written text) ──────────────── */}
      {arr(pestr.narrative).length > 0 && (
        <Panel title={`Narrative Strings (${arr(pestr.narrative).length})`}>
          <div className="text-[10px] uppercase tracking-wider text-muted mb-2">
            Human-readable text — payload banners, target attribution, status/error messages.
            These are what the malware author actually wrote.
          </div>
          <ul className="space-y-0.5 text-[11px] font-mono text-text/90 max-h-[40vh] overflow-y-auto">
            {arr(pestr.narrative).slice(0, 50).map((s: string, i: number) => (
              <li key={i} className="break-all border-b border-line/30 py-0.5">{s}</li>
            ))}
          </ul>
        </Panel>
      )}

      {/* ── floss — obfuscated string extraction ────────────────── */}
      {(arr(floss.stack_strings).length + arr(floss.tight_strings).length + arr(floss.decoded_strings).length > 0 || floss.error) && (
        <Panel title="Obfuscated Strings (floss)" className={arr(floss.decoded_strings).length > 0 ? "border-warning/40" : ""}>
          {floss.error && (
            <div className="text-xs text-warning mb-2">floss: {floss.error}</div>
          )}
          {arr(floss.decoded_strings).length > 0 && (
            <FlossBlock label="Decoded (runtime XOR-decoded)" accent="text-danger" items={arr(floss.decoded_strings)}/>
          )}
          {arr(floss.stack_strings).length > 0 && (
            <FlossBlock label="Stack-allocated" accent="text-warning" items={arr(floss.stack_strings)}/>
          )}
          {arr(floss.tight_strings).length > 0 && (
            <FlossBlock label="Tight-loop decoded" accent="text-accent2" items={arr(floss.tight_strings)}/>
          )}
          {!floss.error && arr(floss.decoded_strings).length === 0
              && arr(floss.stack_strings).length === 0
              && arr(floss.tight_strings).length === 0 && (
            <div className="text-xs text-muted">No obfuscated strings recovered — sample uses plaintext strings.</div>
          )}
        </Panel>
      )}

      {/* ── PE structure / pescan anomalies ───────────────────────── */}
      {(arr(pescan.anomalies).length > 0 || arr(peframe.suspicious_sections).length > 0) && (
        <Panel title="PE Structure">
          {arr(peframe.behaviors).length > 0 && (
            <div className="mb-3">
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">peframe behaviors</div>
              <div className="flex flex-wrap gap-1.5">
                {arr(peframe.behaviors).map((b: string) => (
                  <span key={b} className="pill pill-medium text-[10px]">{b}</span>
                ))}
              </div>
            </div>
          )}
          {arr(peframe.suspicious_sections).length > 0 && (
            <div className="mb-3">
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">Suspicious sections</div>
              <ul className="text-xs font-mono text-warning space-y-0.5">
                {arr(peframe.suspicious_sections).map((s: string, i: number) => <li key={i}>• {s}</li>)}
              </ul>
            </div>
          )}
          {arr(pescan.anomalies).length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">pescan anomalies</div>
              <ul className="text-xs text-warning space-y-0.5">
                {arr(pescan.anomalies).slice(0, 20).map((a: string, i: number) => <li key={i}>• {a}</li>)}
              </ul>
            </div>
          )}
          {arr(signsrch.signatures).length > 0 && (
            <div className="mt-3">
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
                Embedded algorithms ({signsrch.count})
              </div>
              <ul className="text-xs text-muted space-y-0.5">
                {arr(signsrch.signatures).slice(0, 10).map((s: any, i: number) => (
                  <li key={i} className="font-mono">
                    <span className="text-accent">0x{s.offset}</span> {s.description}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>
      )}

      {/* ── Recommendations ───────────────────────────────────────── */}
      {arr(synthesis.recommendations).length > 0 && (
        <Panel title="Recommendations">
          <ul className="space-y-1.5 text-sm">
            {arr(synthesis.recommendations).map((r: string, i: number) => (
              <li key={i} className="flex items-start gap-2">
                <span className="text-accent mt-0.5">▸</span><span>{r}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {/* ── False positive reasoning ─────────────────────────────── */}
      {synthesis.false_positive_likelihood && synthesis.false_positive_reasoning && (
        <Panel title="False Positive Assessment" className="border-positive/40">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
            <Field label="Likelihood" value={fpLikelihood}
                   accent={fpLikelihood === "HIGH" ? "text-positive font-semibold" : undefined}/>
            <div className="md:col-span-2 text-text/90">{synthesis.false_positive_reasoning}</div>
          </div>
        </Panel>
      )}

      {/* ── Embedded network IOC triage ───────────────────────────── */}
      {embeddedIocs.length > 0 && (
        <Panel title="Embedded Network IOCs (threat intel)"
               className={embeddedIocs.some((e: any) => e.verdict === "malicious") ? "border-danger/40" : ""}>
          <div className="text-[10px] uppercase tracking-wider text-muted mb-2">
            IOCs found inside the sample, enriched via TI
          </div>
          <div className="space-y-1.5">
            {embeddedIocs.slice(0, 15).map((e: any, i: number) => {
              const v = e.ioc || e.value || e.indicator;
              const verdict = String(e.verdict || "unknown");
              return (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className={cn("pill text-[9px]",
                    verdict === "malicious" ? "pill-critical" :
                    verdict === "suspicious" ? "pill-high" : "pill-medium")}>{verdict}</span>
                  <span className="font-mono break-all text-text/90">{defang(String(v))}</span>
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      {/* ── UPX unpacked re-scan ──────────────────────────────────── */}
      {unpackedR.unpacked && (
        <Panel title="UPX-Unpacked Re-scan" className="border-warning/40">
          <p className="text-xs text-muted mb-2">
            Sample was UPX-packed; unpacked and re-analyzed. capa/strings below are from the unpacked binary.
          </p>
          {arr((unpackedR.capa || {}).attack_techniques).length > 0 && (
            <div className="flex flex-wrap gap-1.5 mb-2">
              {arr(unpackedR.capa.attack_techniques).slice(0, 20).map((t: any, i: number) => (
                <span key={i} className="pill pill-medium text-[10px]">
                  <span className="font-mono text-[9px] opacity-70 mr-1">{t.id}</span>{t.technique || t.name}
                </span>
              ))}
            </div>
          )}
          <RawDetails label="Unpacked tool output" obj={unpackedR}/>
        </Panel>
      )}

      {/* ── Extended-catalog tool cards ───────────────────────────── */}
      {csR.cobalt_strike_config_found && (
        <Panel title="Cobalt Strike Beacon Config" className="border-danger/40">
          <pre className="text-[10px] bg-base border border-line rounded-md p-2 overflow-auto max-h-[30vh] font-mono">
            {String(csR.raw || "")}
          </pre>
        </Panel>
      )}
      {rtfobjR && (rtfobjR.suspicious || arr(rtfobjR.objects).length > 0) && (
        <Panel title="RTF Embedded Objects" className={rtfobjR.suspicious ? "border-danger/40" : ""}>
          {rtfobjR.suspicious && <div className="text-xs text-danger mb-2">⚠ Exploit/dropper indicators present</div>}
          <ul className="text-[11px] font-mono space-y-0.5">
            {arr(rtfobjR.objects).map((o: string, i: number) => <li key={i} className="break-all">{o}</li>)}
          </ul>
        </Panel>
      )}
      {xlmR.xlm_macros_found && (
        <Panel title="Excel 4.0 (XLM) Macros — deobfuscated" className="border-warning/40">
          <pre className="text-[10px] bg-base border border-line rounded-md p-2 overflow-auto max-h-[30vh] font-mono">
            {String(xlmR.raw || "")}
          </pre>
        </Panel>
      )}
      {dotnetR.is_dotnet && (
        <Panel title=".NET Assembly Metadata">
          <RawDetails label="dotnetfile_dump output" obj={dotnetR}/>
        </Panel>
      )}
      {jsR.beautified && (
        <Panel title="JavaScript (beautified)">
          <pre className="text-[10px] bg-base border border-line rounded-md p-2 overflow-auto max-h-[40vh] font-mono">
            {String(jsR.beautified)}
          </pre>
        </Panel>
      )}

      {/* ── Raw JSON toggle ─────────────────────────────────────── */}
      <div>
        <button onClick={() => setShowRaw(v => !v)}
                className="inline-flex items-center gap-1.5 text-xs text-muted hover:text-accent">
          {showRaw ? <ChevronDown size={14}/> : <ChevronRight size={14}/>}
          {showRaw ? "Hide" : "Show"} raw tool outputs
        </button>
        {showRaw && (
          <pre className="mt-3 text-[11px] bg-base border border-line rounded-md p-3 overflow-x-auto max-h-[60vh] font-mono">
            {JSON.stringify(data, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}


// ── small helpers ────────────────────────────────────────────────────
function VerdictPill({ verdict }: { verdict: string }) {
  const Icon =
    verdict === "CRITICAL" ? ShieldX :
    verdict === "HIGH"     ? ShieldX :
    verdict === "MEDIUM"   ? ShieldAlert :
    verdict === "LOW"      ? ShieldCheck :
    AlertTriangle;
  const klass =
    verdict === "CRITICAL" ? "pill pill-critical" :
    verdict === "HIGH"     ? "pill pill-critical" :
    verdict === "MEDIUM"   ? "pill pill-high" :
    verdict === "LOW"      ? "pill pill-resolved" :
    "pill pill-low";
  return (
    <span className={cn(klass, "inline-flex items-center gap-1.5")}>
      <Icon size={12}/> {verdict || "UNKNOWN"}
    </span>
  );
}

function verdictBorderClass(verdict: string) {
  if (verdict === "CRITICAL" || verdict === "HIGH") return "border-danger/40";
  if (verdict === "MEDIUM") return "border-warning/40";
  if (verdict === "LOW")    return "border-positive/40";
  return "";
}

function confKlass(c: string) {
  if (c === "HIGH")   return "pill-critical";
  if (c === "MEDIUM") return "pill-high";
  return "pill-low";
}

function vtBadgeClass(d?: any) {
  if (!d) return undefined;
  const m = String(d).match(/^(\d+)\//);
  const n = m ? parseInt(m[1], 10) : 0;
  if (n >= 15) return "text-danger font-semibold";
  if (n >= 5)  return "text-warning font-semibold";
  if (n > 0)   return "text-accent";
  return "text-positive";
}

function Field({ label, value, mono, small, accent }: {
  label: string; value: React.ReactNode; mono?: boolean; small?: boolean; accent?: string;
}) {
  return (
    <div className="flex justify-between gap-3 border-b border-line/40 pb-1">
      <span className="text-[10px] uppercase tracking-wider text-muted">{label}</span>
      <span className={cn(
        "text-right break-all",
        mono && "font-mono",
        small ? "text-[11px]" : "text-sm",
        accent || "text-text",
      )}>{value}</span>
    </div>
  );
}

function FlossBlock({ label, items, accent }: { label: string; items: string[]; accent?: string }) {
  return (
    <div className="mb-3">
      <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
        {label} ({items.length})
      </div>
      <ul className={cn("space-y-0.5 font-mono text-[11px] max-h-[30vh] overflow-y-auto", accent || "text-text/90")}>
        {items.slice(0, 40).map((s, i) => (
          <li key={i} className="break-all border-b border-line/30 py-0.5">{s}</li>
        ))}
      </ul>
    </div>
  );
}

function IndicatorList({ label, items, accent, mono, small }: {
  label: string; items: string[]; accent?: string; mono?: boolean; small?: boolean;
}) {
  return (
    <div className="mb-3">
      <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">{label} ({items.length})</div>
      <ul className={cn("space-y-0.5", mono && "font-mono", small ? "text-[11px]" : "text-xs", accent || "text-text/90")}>
        {items.slice(0, 15).map((it, i) => <li key={i} className="break-all">{it}</li>)}
      </ul>
    </div>
  );
}

function arr(v: any): any[] {
  if (Array.isArray(v)) return v;
  if (v == null) return [];
  return [];
}

function RawDetails({ label, obj }: { label: string; obj: any }) {
  return (
    <details className="text-xs">
      <summary className="cursor-pointer text-muted hover:text-accent">{label}</summary>
      <pre className="mt-2 text-[10px] bg-base border border-line rounded-md p-2 max-h-[30vh] overflow-auto font-mono">
        {typeof obj === "string" ? obj : JSON.stringify(obj, null, 2)}
      </pre>
    </details>
  );
}

function defang(v: string): string {
  return String(v)
    .replace(/^http(s?):\/\//, "hxxp$1://")
    .replace(/\.(?=[A-Za-z])/g, "[.]");
}

function dedupeMitre(items: any[]) {
  const seen = new Set<string>();
  const out: any[] = [];
  for (const it of items) {
    const id = it.id || it.technique_id;
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(it);
  }
  return out;
}
