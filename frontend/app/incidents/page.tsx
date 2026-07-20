"use client";

import { Suspense, useEffect, useMemo, useState, useCallback, useTransition } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { ScoreChips } from "@/components/incidents/Scores";
import { severityPill, statusPill, verdictPill } from "@/lib/utils";
import useSWR from "@/lib/swr-shim";
import {
  Search, ArrowUpDown, ArrowDown, ArrowUp, X,
  Trash2, RotateCcw, Archive, Download, MoreHorizontal, Eye, EyeOff,
  ChevronLeft, ChevronRight, UserCheck,
} from "lucide-react";

export const dynamic = "force-dynamic";

// ── Filter state ──────────────────────────────────────────────────────────

interface Filters {
  q: string;
  status: string;
  severity: string;
  verdict: string;
  customer: string;
  sort: "asc" | "desc";
  include_deleted: "false" | "true";   // "true" = only archived (admin only)
}

const EMPTY: Filters = {
  q: "", status: "", severity: "", verdict: "", customer: "",
  sort: "desc", include_deleted: "false",
};

const STATUSES  = ["received","parsed","enriching","awaiting_review","awaiting_synthesis","synthesized","closed","failed","auto_closed_candidate"];
const SEVERITIES = ["critical","high","medium","low","info"];
const VERDICTS  = ["TP","FP","benign","pending"];
const PAGE_SIZES = [10, 25, 50, 100];

function hasActiveFilters(f: Filters) {
  return f.q || f.status || f.severity || f.verdict || f.customer || f.sort === "asc";
}

// ── Main page ─────────────────────────────────────────────────────────────

function IncidentsInner() {
  const searchParams = useSearchParams();
  const urlQ = searchParams.get("q") || "";
  const [filters, setFilters] = useState<Filters>({ ...EMPTY, q: urlQ });
  const [, startTransition] = useTransition();

  // Pagination state
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Selection state — set of incident ids (UUID strings).
  // Resets whenever the visible rows change (filter / page / page size).
  const [selected, setSelected] = useState<Set<string>>(() => new Set());

  // Current user — used to gate admin-only UI (delete, show-archived, etc.)
  const [me, setMe] = useState<any>(null);
  useEffect(() => { api.me().then(setMe).catch(() => {}); }, []);
  const isAdmin = me?.role === "admin";

  // Keep the local q filter in sync when the URL changes
  useEffect(() => {
    setFilters(f => f.q === urlQ ? f : { ...f, q: urlQ });
  }, [urlQ]);

  const set = useCallback((key: keyof Filters, val: string) => {
    startTransition(() => {
      setFilters(f => ({ ...f, [key]: val } as Filters));
      setPage(1);                           // any filter change → page 1
      setSelected(new Set());               // selection no longer applies
    });
  }, []);

  const reset = () => {
    setFilters(EMPTY);
    setPage(1);
    setSelected(new Set());
  };

  // Build API params
  const params: Record<string, string | number> = {
    page, page_size: pageSize, sort: filters.sort,
    include_deleted: filters.include_deleted,
  };
  if (filters.q)        params.q        = filters.q;
  if (filters.status)   params.status   = filters.status;
  if (filters.severity) params.severity = filters.severity;
  if (filters.verdict)  params.verdict  = filters.verdict;
  if (filters.customer) params.customer = filters.customer;

  const swrKey = "incidents:" + JSON.stringify(params);
  const { data, isLoading, mutate } = useSWR(swrKey, () => api.listIncidents(params));
  const rows: any[] = data?.items || [];
  const total: number = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  const activeCount = [filters.status, filters.severity, filters.verdict, filters.customer]
    .filter(Boolean).length;

  // Selection helpers
  const toggleRow = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };
  const selectedOnPage = rows.filter(r => selected.has(r.id)).length;
  const allOnPageSelected = rows.length > 0 && selectedOnPage === rows.length;
  const someOnPageSelected = selectedOnPage > 0 && !allOnPageSelected;
  const toggleAllOnPage = () => {
    setSelected(prev => {
      const next = new Set(prev);
      if (allOnPageSelected) {
        rows.forEach(r => next.delete(r.id));
      } else {
        rows.forEach(r => next.add(r.id));
      }
      return next;
    });
  };

  // ── Bulk action runner ─────────────────────────────────────────────────
  const [busy, setBusy] = useState(false);
  const runBulk = async (action: string, value?: any, confirmMsg?: string) => {
    if (selected.size === 0) return;
    if (confirmMsg && !window.confirm(confirmMsg)) return;
    setBusy(true);
    try {
      const res = await api.bulkIncidentAction(Array.from(selected), action, value);
      if (res.skipped?.length) {
        const reasons = [...new Set(res.skipped.map(s => s.reason))].join(", ");
        alert(`${res.affected.length} affected. ${res.skipped.length} skipped (${reasons}).`);
      }
      setSelected(new Set());
      await mutate();
    } catch (e: any) {
      alert(`Bulk action failed: ${e?.message ?? e}`);
    } finally {
      setBusy(false);
    }
  };

  // ── Per-row admin actions ──────────────────────────────────────────────
  const archiveRow = async (id: string, caseNum: string) => {
    if (!window.confirm(`Archive ${caseNum}? It will be hidden from default lists. Admins can restore or permanently delete it later.`)) return;
    setBusy(true);
    try { await api.archiveIncident(id); await mutate(); }
    catch (e: any) { alert(`Archive failed: ${e?.message ?? e}`); }
    finally { setBusy(false); }
  };
  const restoreRow = async (id: string, caseNum: string) => {
    setBusy(true);
    try { await api.restoreIncident(id); await mutate(); }
    catch (e: any) { alert(`Restore failed: ${e?.message ?? e}`); }
    finally { setBusy(false); }
  };
  const purgeRow = async (id: string, caseNum: string) => {
    if (!window.confirm(`Permanently DELETE ${caseNum}? This cannot be undone. Timeline, IOCs, and case links will be removed.`)) return;
    setBusy(true);
    try { await api.purgeIncident(id); await mutate(); }
    catch (e: any) { alert(`Purge failed: ${e?.message ?? e}`); }
    finally { setBusy(false); }
  };

  // CSV export — uses the *current filter*, not the selection. Most reporting
  // workflows want "everything matching these filters", which can be many more
  // rows than fit on one page.
  const exportCsv = async () => {
    const exportParams: Record<string, string | number> = { sort: filters.sort };
    if (filters.q)        exportParams.q        = filters.q;
    if (filters.status)   exportParams.status   = filters.status;
    if (filters.severity) exportParams.severity = filters.severity;
    if (filters.verdict)  exportParams.verdict  = filters.verdict;
    if (filters.customer) exportParams.customer = filters.customer;
    if (filters.include_deleted !== "false") exportParams.include_deleted = filters.include_deleted;
    try { await api.exportIncidentsCsv(exportParams); }
    catch (e: any) { alert(`Export failed: ${e?.message ?? e}`); }
  };

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="panel p-3">
        <div className="flex flex-wrap gap-2 items-center">

          {/* Free-text search */}
          <div className="relative flex-1 min-w-[200px]">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted pointer-events-none"/>
            <input
              className="w-full bg-base border border-line rounded-md pl-8 pr-3 py-1.5 text-sm text-text
                         placeholder:text-muted focus:outline-none focus:border-accent"
              placeholder="Search rule, title, case number…"
              value={filters.q}
              onChange={e => set("q", e.target.value)}
            />
          </div>

          {/* Customer */}
          <input
            className="bg-base border border-line rounded-md px-3 py-1.5 text-sm text-text
                       placeholder:text-muted focus:outline-none focus:border-accent w-36"
            placeholder="Customer…"
            value={filters.customer}
            onChange={e => set("customer", e.target.value)}
          />

          <Select value={filters.status} onChange={v => set("status", v)} placeholder="Status">
            {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g," ")}</option>)}
          </Select>
          <Select value={filters.severity} onChange={v => set("severity", v)} placeholder="Severity">
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Select value={filters.verdict} onChange={v => set("verdict", v)} placeholder="Verdict">
            {VERDICTS.map(v => <option key={v} value={v}>{v}</option>)}
          </Select>

          {/* Sort toggle */}
          <button
            onClick={() => set("sort", filters.sort === "desc" ? "asc" : "desc")}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-line rounded-md hover:border-accent text-muted hover:text-text"
            title={filters.sort === "desc" ? "Newest first — click for oldest" : "Oldest first — click for newest"}
          >
            {filters.sort === "desc"
              ? <><ArrowDown size={13}/> Newest</>
              : <><ArrowUp size={13}/> Oldest</>}
          </button>

          {/* Show archived (admin only) */}
          {isAdmin && (
            <button
              onClick={() => set("include_deleted",
                filters.include_deleted === "false" ? "true" : "false")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm border rounded-md
                ${filters.include_deleted === "true"
                  ? "border-warning text-warning"
                  : "border-line text-muted hover:text-text hover:border-accent"}`}
              title="Toggle archived-only view"
            >
              {filters.include_deleted === "true"
                ? <><EyeOff size={13}/> Archived</>
                : <><Eye size={13}/> Show archived</>}
            </button>
          )}

          {/* Export */}
          <button
            onClick={exportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-line rounded-md hover:border-accent text-muted hover:text-text"
            title="Download all matching incidents as CSV"
          >
            <Download size={13}/> CSV
          </button>

          {/* Clear */}
          {hasActiveFilters(filters) && (
            <button
              onClick={reset}
              className="flex items-center gap-1 px-2.5 py-1.5 text-sm text-muted hover:text-danger border border-line/60 rounded-md"
            >
              <X size={13}/> Clear {activeCount > 0 && `(${activeCount})`}
            </button>
          )}
        </div>
      </div>

      {/* Bulk-action toolbar — visible when at least 1 row is selected */}
      {selected.size > 0 && (
        <div className="panel p-3 flex flex-wrap items-center gap-2 bg-accent/5 border-accent/40">
          <span className="text-sm font-medium text-accent">
            {selected.size} selected
          </span>
          <button onClick={() => setSelected(new Set())}
                  className="text-xs text-muted hover:text-text underline">
            clear
          </button>
          <div className="flex-1"/>
          <BulkButton disabled={busy} onClick={() => runBulk("close", null, `Close ${selected.size} incident(s) without verdict?`)}>
            Close
          </BulkButton>
          <BulkVerdictMenu disabled={busy} onPick={(v) => runBulk("verdict", v, `Set verdict "${v}" on ${selected.size} incident(s)?`)}/>
          <BulkButton disabled={busy || !me?.id}
            onClick={() => me?.id && runBulk("reassign", me.id, `Assign ${selected.size} incident(s) to you? This starts the response SLA clock.`)}>
            <UserCheck size={13}/> Assign to me
          </BulkButton>
          <BulkReassignMenu disabled={busy} onPick={(userId) => runBulk("reassign", userId, `Reassign ${selected.size} incident(s)?`)}/>
          {isAdmin && (
            <BulkButton danger disabled={busy} onClick={() => runBulk("archive", null, `Archive ${selected.size} incident(s)? Hidden from default lists but recoverable.`)}>
              <Archive size={13}/> Archive
            </BulkButton>
          )}
          {isAdmin && filters.include_deleted === "true" && (
            <BulkButton danger disabled={busy} onClick={() => runBulk("purge", null, `PERMANENTLY DELETE ${selected.size} archived incident(s)? Cannot be undone.`)}>
              <Trash2 size={13}/> Purge
            </BulkButton>
          )}
        </div>
      )}

      {/* Results table */}
      <Panel title={
        isLoading
          ? "Incidents — loading…"
          : `Incidents — ${total} total${filters.include_deleted === "true" ? " (archived)" : ""}`
      }>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
              <tr className="text-left">
                <th className="py-2 pr-2 w-8">
                  <input
                    type="checkbox"
                    checked={allOnPageSelected}
                    ref={el => { if (el) el.indeterminate = someOnPageSelected; }}
                    onChange={toggleAllOnPage}
                    className="accent-accent cursor-pointer"
                    title={allOnPageSelected ? "Clear selection on this page" : "Select all on this page"}
                  />
                </th>
                <th className="py-2 pr-4">Case</th>
                <th className="py-2 pr-4">Title</th>
                <th className="py-2 pr-4">Customer</th>
                <th className="py-2 pr-4">Severity</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">Verdict</th>
                <th className="py-2 pr-4">Assignee</th>
                <th className="py-2 pr-4">Scores</th>
                <th className="py-2 pr-4 whitespace-nowrap">
                  <button
                    onClick={() => set("sort", filters.sort === "desc" ? "asc" : "desc")}
                    className="flex items-center gap-1 hover:text-accent">
                    Created <ArrowUpDown size={10}/>
                  </button>
                </th>
                {isAdmin && <th className="py-2 pr-2 w-20 text-right">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((r: any) => {
                const isArchived = !!r.deleted_at;
                return (
                  <tr key={r.id}
                      className={`border-t border-line/60 hover:bg-surface/60
                                 ${selected.has(r.id) ? "bg-accent/5" : ""}
                                 ${isArchived ? "opacity-60" : ""}`}>
                    <td className="py-2 pr-2">
                      <input
                        type="checkbox"
                        checked={selected.has(r.id)}
                        onChange={() => toggleRow(r.id)}
                        className="accent-accent cursor-pointer"
                      />
                    </td>
                    <td className="py-2 pr-4 font-mono text-accent whitespace-nowrap">
                      <Link href={`/incidents/${r.id}`}>{r.case_number}</Link>
                      {r.cluster_size > 1 && (
                        <span
                          className="ml-1.5 inline-flex items-center text-[9px] text-muted border border-line/60 rounded px-1 py-0.5 align-middle"
                          title={`Correlated into a cluster of ${r.cluster_size} related incidents`}
                          role="img"
                          aria-label={`cluster of ${r.cluster_size} related incidents`}
                        >
                          <span aria-hidden="true">◇{r.cluster_size}</span>
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-4 max-w-[34ch] truncate" title={r.title}>{r.title}</td>
                    <td className="py-2 pr-4 text-muted">{r.customer || "—"}</td>
                    <td className="py-2 pr-4"><span className={severityPill(r.severity)}>{r.severity}</span></td>
                    <td className="py-2 pr-4"><span className={statusPill(r.status)}>{r.status?.replace(/_/g," ")}</span></td>
                    <td className="py-2 pr-4"><span className={verdictPill(r.verdict)}>{r.verdict}</span></td>
                    <td className="py-2 pr-4 text-xs whitespace-nowrap">
                      {r.assignee_id ? (
                        <span className={`inline-flex items-center gap-1 ${r.assignee_id === me?.id ? "text-positive" : "text-text"}`}>
                          {r.assignee_id === me?.id && <UserCheck size={11}/>}
                          {r.assignee_name || "assigned"}
                        </span>
                      ) : (
                        <span className="text-muted italic">unassigned</span>
                      )}
                    </td>
                    <td className="py-2 pr-4"><ScoreChips confidence={r.confidence_score} threat={r.threat_score}/></td>
                    <td className="py-2 pr-4 text-muted text-xs whitespace-nowrap">
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    {isAdmin && (
                      <td className="py-2 pr-2 text-right">
                        <div className="inline-flex gap-1">
                          {isArchived ? (
                            <>
                              <IconBtn title="Restore (un-archive)" onClick={() => restoreRow(r.id, r.case_number)}>
                                <RotateCcw size={13}/>
                              </IconBtn>
                              <IconBtn danger title="Permanently delete (cannot be undone)"
                                       onClick={() => purgeRow(r.id, r.case_number)}>
                                <Trash2 size={13}/>
                              </IconBtn>
                            </>
                          ) : (
                            <IconBtn danger title="Archive (admin only)"
                                     onClick={() => archiveRow(r.id, r.case_number)}>
                              <Archive size={13}/>
                            </IconBtn>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                );
              })}
              {!isLoading && rows.length === 0 && (
                <tr>
                  <td colSpan={isAdmin ? 11 : 10} className="py-10 text-center text-muted">
                    {hasActiveFilters(filters) || filters.include_deleted === "true"
                      ? "No incidents match the current filters."
                      : "No incidents yet — paste an alert via the \"New investigation\" button."}
                  </td>
                </tr>
              )}
              {isLoading && (
                <tr>
                  <td colSpan={isAdmin ? 11 : 10} className="py-10 text-center text-muted">Loading…</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination footer */}
        {total > 0 && (
          <div className="flex items-center justify-between gap-3 pt-3 mt-3 border-t border-line/60 text-xs">
            <div className="text-muted">
              Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
            </div>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 text-muted">
                Page size
                <select
                  value={pageSize}
                  onChange={e => { setPageSize(Number(e.target.value)); setPage(1); }}
                  className="bg-base border border-line rounded-md px-2 py-1 text-text"
                >
                  {PAGE_SIZES.map(n => <option key={n} value={n}>{n}</option>)}
                </select>
              </label>
              <Pager page={page} pageCount={pageCount} onChange={setPage}/>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}

export default function IncidentsPage() {
  return (
    <Suspense fallback={<div className="text-muted text-sm">Loading…</div>}>
      <IncidentsInner/>
    </Suspense>
  );
}

// ── Reusable bits ───────────────────────────────────────────────────────────

function Select({ value, onChange, placeholder, children }: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  children: React.ReactNode;
}) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      className={`bg-base border border-line rounded-md px-2.5 py-1.5 text-sm focus:outline-none focus:border-accent
                  ${value ? "text-text border-accent/50" : "text-muted"}`}
    >
      <option value="">{placeholder}</option>
      {children}
    </select>
  );
}

function BulkButton({ children, onClick, disabled, danger }: {
  children: React.ReactNode; onClick: () => void; disabled?: boolean; danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`flex items-center gap-1.5 px-3 py-1.5 text-sm border rounded-md
        disabled:opacity-50 disabled:cursor-not-allowed
        ${danger
          ? "border-danger/50 text-danger hover:bg-danger/10"
          : "border-line text-text hover:border-accent"}`}
    >
      {children}
    </button>
  );
}

function BulkVerdictMenu({ onPick, disabled }: { onPick: (v: string) => void; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <BulkButton disabled={disabled} onClick={() => setOpen(o => !o)}>Set verdict ▾</BulkButton>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-20 min-w-[140px] panel border border-line shadow-lg p-1">
          {["TP","FP","benign","pending"].map(v => (
            <button key={v}
              onClick={() => { setOpen(false); onPick(v); }}
              className="block w-full text-left px-3 py-1.5 text-sm hover:bg-accent/10 rounded">
              {v}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// Reassign currently picks from "all admins/analysts in scope". We keep it
// simple: load users once when the menu opens.
function BulkReassignMenu({ onPick, disabled }: { onPick: (userId: string | null) => void; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const [users, setUsers] = useState<any[]>([]);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    if (open && !loaded) {
      // Lazy import to avoid pulling in admin client for non-admins. If the
      // endpoint 403s, the menu just shows "Unassign" + a hint.
      (async () => {
        try {
          const us = await (await fetch(`${process.env.NEXT_PUBLIC_API_BASE ?? "/api"}/v1/admin/users`, {
            headers: { Authorization: `Bearer ${localStorage.getItem("isoc.token")}` },
          })).json();
          if (Array.isArray(us)) setUsers(us);
        } catch {}
        setLoaded(true);
      })();
    }
  }, [open, loaded]);
  return (
    <div className="relative">
      <BulkButton disabled={disabled} onClick={() => setOpen(o => !o)}>Reassign ▾</BulkButton>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-20 min-w-[200px] max-h-[280px] overflow-y-auto panel border border-line shadow-lg p-1">
          <button onClick={() => { setOpen(false); onPick(null); }}
                  className="block w-full text-left px-3 py-1.5 text-sm hover:bg-accent/10 rounded text-muted italic">
            Unassign
          </button>
          {!loaded && <div className="px-3 py-2 text-xs text-muted">Loading…</div>}
          {loaded && users.length === 0 && (
            <div className="px-3 py-2 text-xs text-muted">No assignable users found.</div>
          )}
          {users.map((u: any) => (
            <button key={u.id}
              onClick={() => { setOpen(false); onPick(u.id); }}
              className="block w-full text-left px-3 py-1.5 text-sm hover:bg-accent/10 rounded">
              {u.full_name || u.email} <span className="text-muted text-xs">({u.role})</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function IconBtn({ children, onClick, title, danger }: {
  children: React.ReactNode; onClick: () => void; title: string; danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      className={`p-1.5 rounded border border-transparent
        ${danger ? "text-muted hover:text-danger hover:border-danger/40" : "text-muted hover:text-accent hover:border-accent/40"}`}
    >
      {children}
    </button>
  );
}

// Compact pager: « 1 … 4 [5] 6 … 12 »  — ellipsis collapses anything more than
// 1 step from page 1, current, or last. Keeps the footer single-line.
function Pager({ page, pageCount, onChange }: {
  page: number; pageCount: number; onChange: (p: number) => void;
}) {
  if (pageCount <= 1) return null;
  const nums: (number | "...")[] = [];
  const push = (n: number | "...") => {
    if (n === "..." && nums[nums.length - 1] === "...") return;
    nums.push(n);
  };
  for (let i = 1; i <= pageCount; i++) {
    if (i === 1 || i === pageCount || Math.abs(i - page) <= 1) push(i);
    else push("...");
  }
  return (
    <div className="flex items-center gap-1">
      <button onClick={() => onChange(Math.max(1, page - 1))}
              disabled={page <= 1}
              className="p-1 rounded border border-line disabled:opacity-40 hover:border-accent">
        <ChevronLeft size={13}/>
      </button>
      {nums.map((n, i) => n === "..." ? (
        <span key={`e${i}`} className="text-muted px-1">…</span>
      ) : (
        <button key={n} onClick={() => onChange(n)}
                className={`px-2 py-0.5 rounded border min-w-[28px]
                  ${n === page
                    ? "border-accent bg-accent/10 text-accent"
                    : "border-line text-muted hover:text-text hover:border-accent"}`}>
          {n}
        </button>
      ))}
      <button onClick={() => onChange(Math.min(pageCount, page + 1))}
              disabled={page >= pageCount}
              className="p-1 rounded border border-line disabled:opacity-40 hover:border-accent">
        <ChevronRight size={13}/>
      </button>
    </div>
  );
}
