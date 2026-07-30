"use client";

import { useState } from "react";
import useSWR from "@/lib/swr-shim";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import { Ban, CheckCircle2, Copy, KeyRound, Trash2, UserPlus } from "lucide-react";

const ROLES = ["admin", "analyst", "viewer"];

export default function UsersPage() {
  const { data, mutate } = useSWR("admin.users", () => api.admin.listUsers());
  const { data: me } = useSWR("me", () => api.me());
  const users = data || [];
  const [form, setForm] = useState({ email: "", password: "", role: "analyst", full_name: "" });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // One-time credentials reveal (create with generated pw, or a reset).
  const [reveal, setReveal] = useState<{ email: string; temp_password: string } | null>(null);

  async function create() {
    setBusy(true); setErr(null);
    try {
      // Send password only when the admin typed one; blank ⇒ server generates + emails it.
      const body: any = { email: form.email, role: form.role, full_name: form.full_name };
      if (form.password) body.password = form.password;
      const created = await api.admin.createUser(body);
      if (created?.temp_password) setReveal({ email: created.email, temp_password: created.temp_password });
      setForm({ email: "", password: "", role: "analyst", full_name: "" });
      await mutate();
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  async function patch(id: string, body: { role?: string; status?: string }) {
    setErr(null);
    try { await api.admin.updateUser(id, body); await mutate(); }
    catch (e: any) { setErr(e.message); }
  }

  async function resetPw(u: any) {
    if (!confirm(`Reset password for ${u.email}? This signs them out of every session.`)) return;
    setErr(null);
    try {
      const r = await api.admin.resetPassword(u.id);
      setReveal({ email: u.email, temp_password: r.temp_password });
    } catch (e: any) { setErr(e.message); }
  }

  async function remove(id: string, email: string) {
    if (!confirm(`Delete user ${email}?`)) return;
    setErr(null);
    try { await api.admin.deleteUser(id); await mutate(); }
    catch (e: any) { setErr(e.message); }
  }

  const pwTooShort = form.password.length > 0 && form.password.length < 10;

  return (
    <div className="grid lg:grid-cols-3 gap-5">
      <div className="lg:col-span-2 space-y-4">
        {reveal && (
          <div className="rounded-md border border-accent/40 bg-accent/10 px-4 py-3 text-sm">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-accent font-semibold">Temporary password for {reveal.email}</div>
                <div className="mt-1 flex items-center gap-2">
                  <code className="bg-base border border-line rounded px-2 py-0.5 font-mono">{reveal.temp_password}</code>
                  <button title="Copy" className="text-muted hover:text-accent"
                          onClick={() => navigator.clipboard?.writeText(reveal.temp_password)}>
                    <Copy size={14}/>
                  </button>
                </div>
                <div className="mt-1 text-[11px] text-muted">
                  Copy it now; it won&apos;t be shown again. It was emailed to the user if mail is configured.
                </div>
              </div>
              <button className="text-muted hover:text-text text-xs" onClick={() => setReveal(null)}>Dismiss</button>
            </div>
          </div>
        )}

        <Panel title={`Users (${users.length})`}>
          <table className="w-full text-sm">
            <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
              <tr className="text-left">
                <th className="py-2 pr-3">Email</th>
                <th className="py-2 pr-3">Role</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Last login</th>
                <th className="py-2 pr-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u: any) => {
                const isSelf = me?.id === u.id;
                const disabled = u.status === "disabled";
                return (
                  <tr key={u.id} className="border-t border-line/60">
                    <td className="py-2 pr-3 font-mono">
                      {u.email}
                      {isSelf && <span className="ml-2 text-[10px] text-muted">(you)</span>}
                    </td>
                    <td className="py-2 pr-3">
                      <select value={u.role} disabled={isSelf}
                              onChange={e => patch(u.id, { role: e.target.value })}
                              title={isSelf ? "You can't change your own role" : "Change role"}
                              className="bg-base border border-line rounded-md px-2 py-1 text-xs disabled:opacity-50">
                        {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </td>
                    <td className="py-2 pr-3">
                      <span className={disabled ? "text-danger" : "text-positive"}>{u.status}</span>
                    </td>
                    <td className="py-2 pr-3 text-muted">
                      {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "—"}
                    </td>
                    <td className="py-2 pr-3">
                      <div className="flex items-center justify-end gap-3">
                        <button onClick={() => patch(u.id, { status: disabled ? "active" : "disabled" })}
                                disabled={isSelf}
                                title={isSelf ? "You can't disable your own account" : (disabled ? "Enable" : "Disable")}
                                className="text-muted hover:text-text disabled:opacity-30">
                          {disabled ? <CheckCircle2 size={14}/> : <Ban size={14}/>}
                        </button>
                        <button onClick={() => resetPw(u)} title="Reset password"
                                className="text-muted hover:text-accent">
                          <KeyRound size={14}/>
                        </button>
                        <button onClick={() => remove(u.id, u.email)} disabled={isSelf}
                                title={isSelf ? "You can't delete your own account" : "Delete"}
                                className="text-muted hover:text-danger disabled:opacity-30">
                          <Trash2 size={14}/>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {users.length === 0 && (
                <tr><td colSpan={5} className="py-6 text-center text-muted">No users yet.</td></tr>
              )}
            </tbody>
          </table>
        </Panel>
      </div>

      <Panel title="New user" icon={<UserPlus size={14} className="text-accent"/>}>
        <Field label="Email"     v={form.email}     on={v=>setForm({...form, email: v})} type="email"/>
        <Field label="Password"  v={form.password}  on={v=>setForm({...form, password: v})} type="password"
               hint="Leave blank to auto-generate and email the user"/>
        <Field label="Full name" v={form.full_name} on={v=>setForm({...form, full_name: v})}/>
        <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mt-3 mb-1">Role</label>
        <select value={form.role} onChange={e=>setForm({...form, role: e.target.value})}
                className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm">
          {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
        </select>
        <button onClick={create} disabled={busy || !form.email || pwTooShort}
                className="mt-4 w-full px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
          {busy ? "Creating…" : "Create user"}
        </button>
        {pwTooShort && <div className="mt-2 text-[11px] text-danger">Password must be ≥ 10 characters (or blank).</div>}
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
