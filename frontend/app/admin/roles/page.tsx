"use client";

import { useMemo, useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Loader2, Lock, Shield, Plus, Trash2, X, Check } from "lucide-react";

type Role = {
  id: string;
  name: string;
  description: string | null;
  is_system: boolean;
  permission_count: number;
};
type Perm = { id: string; name: string; description: string | null };
type Matrix = Record<string, Perm[]>;

type Editing = { id?: string; name: string; description: string; permNames: string[]; system?: boolean };

function RoleEditor({
  matrix,
  initial,
  onClose,
  onSaved,
}: {
  matrix: Matrix;
  initial: Editing | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const readOnly = !!initial?.system;
  const nameToId = useMemo(() => {
    const m: Record<string, string> = {};
    Object.values(matrix).flat().forEach((p) => (m[p.name] = p.id));
    return m;
  }, [matrix]);

  const [name, setName] = useState(initial?.name ?? "");
  const [desc, setDesc] = useState(initial?.description ?? "");
  const [picked, setPicked] = useState<Set<string>>(
    new Set((initial?.permNames ?? []).map((n) => nameToId[n]).filter(Boolean)),
  );
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const toggle = (id: string) =>
    setPicked((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  async function save() {
    if (!name.trim()) { setErr("Name is required"); return; }
    setBusy(true); setErr(null);
    const body = { name: name.trim(), description: desc || undefined, permission_ids: [...picked] };
    try {
      if (initial?.id) await api.rbac.updateRole(initial.id, body);
      else await api.rbac.createRole(body);
      onSaved();
    } catch (e: any) {
      setErr(e?.message ?? "save failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/50 grid place-items-center p-4" onClick={onClose}>
      <div onClick={(e) => e.stopPropagation()}
        className="w-full max-w-2xl max-h-[85vh] flex flex-col rounded-lg border border-line bg-base shadow-cyber">
        <div className="flex items-center justify-between px-4 py-3 border-b border-line">
          <div className="flex items-center gap-2 text-text"><Shield size={16} className="text-accent" />
            {initial?.id ? "Edit role" : "New role"}</div>
          <button onClick={onClose} className="text-muted hover:text-text"><X size={16} /></button>
        </div>
        <div className="px-4 py-3 space-y-3 overflow-y-auto">
          <div className="flex gap-3">
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Role name"
              className="flex-1 bg-surface border border-line rounded px-2 py-1 text-sm text-text" />
            <input value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Description (optional)"
              className="flex-1 bg-surface border border-line rounded px-2 py-1 text-sm text-text" />
          </div>
          {Object.entries(matrix).map(([cat, perms]) => (
            <div key={cat}>
              <div className="text-[10px] uppercase tracking-wider text-muted mb-1">{cat}</div>
              <div className="grid grid-cols-2 gap-1">
                {perms.map((p) => (
                  <label key={p.id} title={p.description ?? ""}
                    className="flex items-center gap-2 text-xs text-text cursor-pointer">
                    <input type="checkbox" checked={picked.has(p.id)} onChange={() => toggle(p.id)}
                      disabled={readOnly} className="accent-accent" />
                    <span className="font-mono">{p.name}</span>
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="flex items-center justify-between px-4 py-3 border-t border-line">
          {err ? <span className="text-xs text-danger">{err}</span> : <span className="text-xs text-muted">{picked.size} permissions{readOnly && " · system role (read-only)"}</span>}
          {!readOnly && (
            <button onClick={save} disabled={busy}
              className="btn btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50">
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />} Save
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default function RolesPage() {
  const { data, isLoading, mutate } = useSWR<{ roles: Role[] }>("rbac:roles", api.rbac.listRoles);
  const { data: pdata } = useSWR<{ permissions: Matrix }>("rbac:perms", api.rbac.listPermissions);
  const [editing, setEditing] = useState<Editing | null>(null);
  const [open, setOpen] = useState(false);

  async function openEdit(role: Role) {
    const full = await api.rbac.getRole(role.id);
    setEditing({ id: role.id, name: full.name, description: full.description ?? "", permNames: full.permissions, system: role.is_system });
    setOpen(true);
  }
  async function del(role: Role) {
    if (!confirm(`Delete role "${role.name}"?`)) return;
    await api.rbac.deleteRole(role.id);
    mutate();
  }

  return (
    <div className="max-w-3xl space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted">
          Custom roles add permissions on top of the coarse role gate. System roles are read-only.
        </p>
        <button onClick={() => { setEditing({ name: "", description: "", permNames: [] }); setOpen(true); }}
          className="btn btn-primary text-sm flex items-center gap-1.5"><Plus size={14} /> New role</button>
      </div>

      {isLoading || !data ? (
        <div className="flex items-center gap-2 text-muted text-sm py-6">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : (
        <div className="grid sm:grid-cols-2 gap-3">
          {data.roles.map((r) => (
            <Panel key={r.id} title={r.name}>
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-xs text-muted">{r.description || "—"}</div>
                  <div className="text-[11px] text-muted mt-2">{r.permission_count} permissions</div>
                </div>
                {r.is_system ? (
                  <span className="text-[10px] text-muted border border-line rounded px-1.5 py-0.5 flex items-center gap-1">
                    <Lock size={10} /> system
                  </span>
                ) : (
                  <div className="flex gap-1 shrink-0">
                    <button onClick={() => openEdit(r)} className="text-xs text-accent hover:underline">Edit</button>
                    <button onClick={() => del(r)} className="text-muted hover:text-danger" title="Delete"><Trash2 size={13} /></button>
                  </div>
                )}
              </div>
              {r.is_system && (
                <button onClick={() => openEdit(r)} className="text-[11px] text-muted hover:text-text mt-2">View permissions →</button>
              )}
            </Panel>
          ))}
        </div>
      )}

      {open && pdata && (
        <RoleEditor matrix={pdata.permissions} initial={editing}
          onClose={() => setOpen(false)}
          onSaved={() => { setOpen(false); mutate(); }} />
      )}
    </div>
  );
}
