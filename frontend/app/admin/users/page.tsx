"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Trash2, UserPlus } from "lucide-react";

export default function UsersPage() {
  const { data, mutate } = useSWR("admin.users", () => api.admin.listUsers());
  const users = data || [];
  const [form, setForm] = useState({ email: "", password: "", role: "analyst", full_name: "" });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function create() {
    setBusy(true); setErr(null);
    try {
      await api.admin.createUser(form);
      setForm({ email: "", password: "", role: "analyst", full_name: "" });
      await mutate();
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  async function remove(id: string, email: string) {
    if (!confirm(`Delete user ${email}?`)) return;
    await api.admin.deleteUser(id);
    await mutate();
  }

  return (
    <div className="grid lg:grid-cols-3 gap-5">
      <Panel title={`Users (${users.length})`} className="lg:col-span-2">
        <table className="w-full text-sm">
          <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
            <tr className="text-left">
              <th className="py-2 pr-3">Email</th>
              <th className="py-2 pr-3">Role</th>
              <th className="py-2 pr-3">Status</th>
              <th className="py-2 pr-3">Last login</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u: any) => (
              <tr key={u.id} className="border-t border-line/60">
                <td className="py-2 pr-3 font-mono">{u.email}</td>
                <td className="py-2 pr-3"><span className="pill pill-medium">{u.role}</span></td>
                <td className="py-2 pr-3 text-muted">{u.status}</td>
                <td className="py-2 pr-3 text-muted">{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "—"}</td>
                <td className="py-2 pr-3 text-right">
                  <button onClick={() => remove(u.id, u.email)}
                          className="text-muted hover:text-danger" title="Delete">
                    <Trash2 size={14}/>
                  </button>
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr><td colSpan={5} className="py-6 text-center text-muted">No users yet.</td></tr>
            )}
          </tbody>
        </table>
      </Panel>

      <Panel title="New user" icon={<UserPlus size={14} className="text-accent"/>}>
        <Field label="Email"     v={form.email}     on={v=>setForm({...form, email: v})} type="email"/>
        <Field label="Password"  v={form.password}  on={v=>setForm({...form, password: v})} type="password" hint="≥ 10 chars"/>
        <Field label="Full name" v={form.full_name} on={v=>setForm({...form, full_name: v})}/>
        <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mt-3 mb-1">Role</label>
        <select value={form.role} onChange={e=>setForm({...form, role: e.target.value})}
                className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm">
          <option value="admin">admin</option>
          <option value="analyst">analyst</option>
          <option value="viewer">viewer</option>
        </select>
        <button onClick={create} disabled={busy || !form.email || form.password.length < 10}
                className="mt-4 w-full px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
          {busy ? "Creating…" : "Create user"}
        </button>
        {err && <div className="mt-3 text-sm text-danger">{err}</div>}
      </Panel>
    </div>
  );
}

function Field({ label, v, on, type="text", hint }:{label:string;v:string;on:(s:string)=>void;type?:string;hint?:string}) {
  return (
    <div className="mt-3">
      <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mb-1">{label}</label>
      <input type={type} value={v} onChange={e=>on(e.target.value)}
             className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60"/>
      {hint && <div className="text-[10px] text-muted mt-1">{hint}</div>}
    </div>
  );
}
