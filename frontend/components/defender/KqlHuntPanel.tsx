"use client";

import { useRef, useState } from "react";
import { Panel } from "@/components/ui/Panel";
import type { HuntResult } from "@/lib/api";
import { Search, Download, Loader2, TriangleAlert } from "lucide-react";

// One panel serves both the global Actions page (tenant picked explicitly) and the
// incident Actions tab (tenant resolved from the incident). The surfaces differ only
// in how a query is dispatched, so they inject `run` / `downloadCsv` and this
// component stays ignorant of incidents and tenants.
interface Props {
  run: (kql: string, maxRecords: number) => Promise<HuntResult>;
  downloadCsv: (kql: string, maxRecords: number) => Promise<void>;
  disabled?: boolean;
  disabledHint?: string;
}

const ROW_LIMITS = [100, 500, 1000, 5000];

// Mirrors HuntRequest.kql's max_length on both hunt routes. Checked client-side so
// an over-long paste fails with a sentence instead of a server validation error.
const MAX_KQL_CHARS = 8000;

// Starting points for the questions this panel gets opened for most often.
// They all use `=~` rather than `==` on identity fields: KQL's `==` is CASE
// SENSITIVE, and Entra stores the UPN with display casing ("Hasan@corp.com") while
// mail tables store it lowercased. `==` therefore returns zero rows against a real
// account, which reads as "no activity" instead of "wrong operator".
const EXAMPLES: { label: string; kql: string }[] = [
  {
    label: "Entra sign-ins for a user",
    kql: 'AADSignInEventsBeta\n| where Timestamp > ago(7d)\n| where AccountUpn =~ "user@example.com"\n| project Timestamp, Application, IPAddress, Country, ErrorCode, DeviceName\n| order by Timestamp desc',
  },
  {
    label: "Sign-in anomalies for a user",
    kql: 'AADSignInEventsBeta\n| where Timestamp > ago(30d)\n| where AccountUpn =~ "user@example.com"\n| summarize attempts = count(), failures = countif(ErrorCode != 0), countries = make_set(Country, 10), ips = dcount(IPAddress) by bin(Timestamp, 1d)\n| order by Timestamp desc',
  },
  {
    label: "Mail delivered to a recipient",
    kql: 'EmailEvents\n| where Timestamp > ago(30d)\n| where RecipientEmailAddress =~ "user@example.com"\n| project Timestamp, SenderFromAddress, Subject, DeliveryAction, ThreatTypes',
  },
  {
    label: "Device by hostname",
    kql: 'DeviceInfo\n| where DeviceName contains "wks"\n| summarize arg_max(Timestamp, OSPlatform, PublicIP) by DeviceId, DeviceName',
  },
];

function cellText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function KqlHuntPanel({ run, downloadCsv, disabled, disabledHint }: Props) {
  const [kql, setKql] = useState("");
  const [maxRecords, setMaxRecords] = useState(500);
  const [busy, setBusy] = useState(false);
  const [downloading, setDownloading] = useState(false);
  // The row cap the displayed result was actually fetched with. Kept alongside the
  // result because the Max-rows select can be changed without re-running, and the
  // truncation warning must describe the query that ran, not the current control.
  const [result, setResult] = useState<{ data: HuntResult; ranWith: number } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // Monotonic id of the newest dispatched query. A response whose id is stale is
  // dropped, so a slow earlier query can never overwrite a newer one's results.
  const runId = useRef(0);

  const ready = !disabled && !!kql.trim();
  const tooLong = kql.length > MAX_KQL_CHARS;

  async function execute() {
    // `busy` is checked here, not only on the button: Ctrl/Cmd+Enter calls this
    // directly and would otherwise start a second concurrent query.
    if (!ready || busy) return;
    if (tooLong) {
      setErr(`Query is ${kql.length} characters; the limit is ${MAX_KQL_CHARS}.`);
      return;
    }
    const id = ++runId.current;
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const data = await run(kql.trim(), maxRecords);
      if (id !== runId.current) return; // superseded by a newer query
      setResult({ data, ranWith: maxRecords });
    } catch (e: unknown) {
      if (id !== runId.current) return;
      setErr(e instanceof Error ? e.message : "Query failed");
    } finally {
      if (id === runId.current) setBusy(false);
    }
  }

  async function saveCsv() {
    if (!ready || downloading) return;
    if (tooLong) {
      setErr(`Query is ${kql.length} characters; the limit is ${MAX_KQL_CHARS}.`);
      return;
    }
    setDownloading(true);
    setErr(null);
    try {
      await downloadCsv(kql.trim(), maxRecords);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : "Download failed");
    } finally {
      setDownloading(false);
    }
  }

  function saveJson() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result.data.rows, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `defender-hunt-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  const btn =
    "flex items-center gap-1.5 px-3 py-1.5 text-sm border border-line rounded-md hover:border-accent disabled:opacity-40";

  return (
    <Panel title="Advanced Hunting (KQL)" icon={<Search size={14} className="text-accent" />}>
      <p className="text-xs text-muted mb-2">
        Run a read-only advanced-hunting query against this tenant and export the results.
        Queries are audit-logged. {disabled && disabledHint ? disabledHint : null}
      </p>

      <div className="flex flex-wrap gap-1.5 mb-2">
        {EXAMPLES.map((ex) => (
          <button
            key={ex.label}
            onClick={() => setKql(ex.kql)}
            disabled={disabled}
            className="px-2 py-0.5 text-[11px] border border-line rounded text-muted hover:border-accent hover:text-text disabled:opacity-40"
          >
            {ex.label}
          </button>
        ))}
      </div>

      <textarea
        value={kql}
        onChange={(e) => setKql(e.target.value)}
        // Ctrl/Cmd+Enter runs; plain Enter must stay newline (KQL is multi-line).
        onKeyDown={(e) => (e.metaKey || e.ctrlKey) && e.key === "Enter" && execute()}
        placeholder="DeviceInfo | take 10"
        rows={6}
        spellCheck={false}
        disabled={disabled}
        className="w-full px-3 py-2 bg-base border border-line rounded-md font-mono text-xs text-text focus:outline-none focus:border-accent disabled:opacity-40"
      />

      <div className="flex items-center gap-2 mt-2 flex-wrap">
        <button onClick={execute} disabled={!ready || busy} className={btn}>
          {busy ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
          Run
        </button>
        <button onClick={saveCsv} disabled={!ready || downloading} className={btn}>
          {downloading ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
          CSV
        </button>
        <button onClick={saveJson} disabled={!result?.data.rows.length} className={btn}>
          <Download size={14} />
          JSON
        </button>
        <label className="flex items-center gap-1.5 text-xs text-muted ml-auto">
          Max rows
          <select
            value={maxRecords}
            onChange={(e) => setMaxRecords(Number(e.target.value))}
            disabled={disabled}
            className="bg-base border border-line rounded-md px-2 py-1 text-xs text-text"
          >
            {ROW_LIMITS.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
      </div>

      <p className="text-[10px] text-muted mt-1.5">
        CSV re-runs the query server-side, so it reflects the tenant at download time.
        JSON saves the rows shown below.
      </p>

      {err && (
        <div className="flex items-start gap-2 mt-3 px-3 py-2 border border-danger/50 rounded-md">
          <TriangleAlert size={14} className="text-danger shrink-0 mt-0.5" />
          <p className="text-xs text-danger break-words">{err}</p>
        </div>
      )}

      {result && (
        <div className="mt-3">
          <p className="text-xs text-muted mb-1.5">
            {result.data.count} row{result.data.count === 1 ? "" : "s"}
            {result.data.count >= result.ranWith && (
              <span className="text-warning">
                {" "}
                (capped at {result.ranWith}, raise Max rows and re-run for more)
              </span>
            )}
          </p>
          {result.data.count === 0 ? (
            <p className="text-xs text-muted">
              No results. The table may be empty for this tenant, or the filter matched nothing.
            </p>
          ) : (
            // Hunting rows are wide (a bare DeviceInfo row is 56 columns), so the
            // table scrolls inside this box instead of wrapping the page.
            <div className="overflow-x-auto border border-line rounded-md max-h-[28rem] overflow-y-auto">
              <table className="text-[11px] font-mono whitespace-nowrap">
                <thead className="sticky top-0 bg-surface">
                  <tr>
                    {result.data.columns.map((c) => (
                      <th key={c} className="text-left px-2 py-1.5 border-b border-line text-muted font-medium">
                        {c}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.data.rows.map((row, i) => (
                    <tr key={i} className="border-b border-line/40 hover:bg-surface/60">
                      {result.data.columns.map((c) => {
                        const text = cellText(row[c]);
                        return (
                          <td key={c} className="px-2 py-1 max-w-[28rem] truncate" title={text}>
                            {text}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
