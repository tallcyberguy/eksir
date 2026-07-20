"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import {
  ArrowLeft, Save, Trash2, Plus, UserPlus, Copy, Check, AlertTriangle,
} from "lucide-react";

const TIERS = ["host", "mssp", "client"];
const ROLES = ["admin", "analyst", "viewer"];

export default function TenantDetail() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();

  const [tenant, setTenant]     = useState<any>(null);
  const [allTenants, setAll]    = useState<any[]>([]);
  const [members, setMembers]   = useState<any[]>([]);
  const [busy, setBusy]         = useState(false);
  const [err, setErr]           = useState<string | null>(null);

  const [form, setForm] = useState({
    name: "", tier: "client", parent_id: "", tier_label: "",
    notification_email: "", notification_email_cc: "", locale: "",
  });
  const [invite, setInvite] = useState({ email: "", role: "analyst", full_name: "", password: "" });
  const [tempPw, setTempPw] = useState<{ email: string; pw: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [tenants, mems] = await Promise.all([
        api.admin.listTenants(),
        api.admin.listMembers(id),
      ]);
      const t = tenants.find((x: any) => x.id === id);
      if (!t) { router.replace("/admin/tenants"); return; }
      setTenant(t);
      setAll(tenants);
      setMembers(mems);
      setForm({
        name: t.name,
        tier: t.tier,
        parent_id: t.parent_id || "",
        tier_label: t.tier_label || "",
        notification_email:    t.notification_email    || "",
        notification_email_cc: t.notification_email_cc || "",
        locale:                t.locale                || "",
      });
    } catch (e: any) {
      setErr(e.message);
    }
  }, [id, router]);

  useEffect(() => { refresh(); }, [refresh]);

  async function save() {
    setBusy(true); setErr(null);
    try {
      await api.admin.patchTenant(id, {
        name: form.name,
        tier: form.tier,
        parent_id: form.parent_id || null,
        tier_label: form.tier_label || null,
        notification_email:    form.notification_email    || null,
        notification_email_cc: form.notification_email_cc || null,
        locale:                form.locale                || null,
      });
      await refresh();
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  async function remove() {
    if (!tenant) return;
    if (!confirm(`Delete tenant "${tenant.name}"? ${tenant.incident_count} incident(s) will become unassigned.`)) return;
    try {
      await api.admin.deleteTenant(id);
      router.replace("/admin/tenants");
    } catch (e: any) { alert(e.message); }
  }

  async function addMember() {
    setBusy(true); setErr(null);
    try {
      const r = await api.admin.addMember(id, {
        email: invite.email.trim(),
        role: invite.role,
        full_name: invite.full_name || undefined,
        password: invite.password || undefined,
      });
      if (r.temp_password_shown_once) {
        setTempPw({ email: r.email, pw: r.temp_password_shown_once });
      }
      setInvite({ email: "", role: "analyst", full_name: "", password: "" });
      await refresh();
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  async function changeRole(membershipId: string, role: string) {
    try {
      await api.admin.patchMember(id, membershipId, { role });
      await refresh();
    } catch (e: any) { alert(e.message); }
  }

  async function removeMember(membershipId: string, email: string) {
    if (!confirm(`Revoke ${email}'s membership in this tenant?`)) return;
    try {
      await api.admin.removeMember(id, membershipId);
      await refresh();
    } catch (e: any) { alert(e.message); }
  }

  function copyPw() {
    if (!tempPw) return;
    navigator.clipboard.writeText(tempPw.pw).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  if (!tenant) return <div className="text-muted">Loading…</div>;

  const possibleParents = allTenants.filter((t: any) => t.id !== id && t.tier !== "client");

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3 text-sm">
        <Link href="/admin/tenants" className="flex items-center gap-1 text-muted hover:text-accent">
          <ArrowLeft size={14}/> Tenants
        </Link>
        <span className="text-muted">/</span>
        <span className="font-mono text-accent">{tenant.name}</span>
      </div>

      {/* Edit panel */}
      <div className="grid lg:grid-cols-3 gap-5">
        <Panel title="Tenant details" className="lg:col-span-2">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="block text-xs uppercase tracking-wider text-muted">
              Name
              <input value={form.name} onChange={e => setForm({...form, name: e.target.value})}
                     className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent"/>
            </label>

            <label className="block text-xs uppercase tracking-wider text-muted">
              Tier
              <select value={form.tier} onChange={e => setForm({...form, tier: e.target.value})}
                      className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent">
                {TIERS.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </label>

            <label className="block text-xs uppercase tracking-wider text-muted">
              Parent
              <select value={form.parent_id} onChange={e => setForm({...form, parent_id: e.target.value})}
                      className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent">
                <option value="">none</option>
                {possibleParents.map((p: any) => (
                  <option key={p.id} value={p.id}>{p.name} ({p.tier})</option>
                ))}
              </select>
            </label>

            <label className="block text-xs uppercase tracking-wider text-muted">
              Tier label (e.g. Gold)
              <input value={form.tier_label} onChange={e => setForm({...form, tier_label: e.target.value})}
                     className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent"/>
            </label>
          </div>

          {/* Customer notification routing — used when an analyst sends a case to this tenant. */}
          <div className="mt-5 pt-4 border-t border-line/60">
            <div className="text-[10px] uppercase tracking-wider text-muted mb-3">
              Customer notification routing
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <label className="block text-xs uppercase tracking-wider text-muted">
                Notification email (TO)
                <input type="email"
                       value={form.notification_email}
                       onChange={e => setForm({...form, notification_email: e.target.value})}
                       placeholder="soc@customer.com"
                       className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm font-mono focus:outline-none focus:border-accent"/>
              </label>
              <label className="block text-xs uppercase tracking-wider text-muted">
                CC (comma-separated)
                <input value={form.notification_email_cc}
                       onChange={e => setForm({...form, notification_email_cc: e.target.value})}
                       placeholder="ciso@customer.com, security@customer.com"
                       className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm font-mono focus:outline-none focus:border-accent"/>
              </label>
              <label className="block text-xs uppercase tracking-wider text-muted">
                Default locale
                <select value={form.locale}
                        onChange={e => setForm({...form, locale: e.target.value})}
                        className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent">
                  <option value="">(system default: en)</option>
                  <option value="en">en — English</option>
                  <option value="tr">tr — Türkçe</option>
                  <option value="de">de — Deutsch</option>
                  <option value="fr">fr — Français</option>
                  <option value="es">es — Español</option>
                </select>
              </label>
            </div>
            <p className="text-[11px] text-muted mt-2 leading-relaxed">
              These auto-populate the TO/CC fields when an analyst sends a customer case
              to this tenant. The Subject is set from the incident title — analysts cannot
              edit any of these at send time.
            </p>
          </div>

          <div className="flex items-center gap-3 mt-4">
            <button onClick={save} disabled={busy || !form.name.trim()}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40 text-sm">
              <Save size={14}/> Save changes
            </button>
            <button onClick={remove}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-line text-muted hover:border-danger hover:text-danger text-sm ml-auto">
              <Trash2 size={14}/> Delete tenant
            </button>
          </div>
          {err && <p className="mt-3 text-sm text-danger">{err}</p>}
        </Panel>

        <Panel title="Summary">
          <div className="space-y-3 text-sm">
            <div className="flex justify-between"><span className="text-muted">Slug</span><span className="font-mono text-text">{tenant.slug}</span></div>
            <div className="flex justify-between"><span className="text-muted">Incidents</span><span className="font-mono text-text">{tenant.incident_count}</span></div>
            <div className="flex justify-between"><span className="text-muted">Members</span><span className="font-mono text-text">{tenant.member_count}</span></div>
            <div className="flex justify-between"><span className="text-muted">Children</span><span className="font-mono text-text">{tenant.child_count}</span></div>
            <div className="flex justify-between"><span className="text-muted">Created</span><span className="font-mono text-muted text-xs">{tenant.created_at ? new Date(tenant.created_at).toLocaleDateString() : "—"}</span></div>
          </div>
        </Panel>
      </div>

      {/* Temp password warning */}
      {tempPw && (
        <div className="panel p-4 border-warning/40 bg-warning/5">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-warning"/>
            <h3 className="text-sm text-warning font-semibold">Temporary password — copy now, never shown again</h3>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <span className="text-muted">{tempPw.email}:</span>
            <code className="flex-1 font-mono text-text bg-base border border-line rounded px-2 py-1 break-all">{tempPw.pw}</code>
            <button onClick={copyPw}
                    className="flex items-center gap-1 px-2 py-1 border border-line rounded hover:border-accent text-xs">
              {copied ? <Check size={12} className="text-positive"/> : <Copy size={12}/>}
              {copied ? "Copied" : "Copy"}
            </button>
            <button onClick={() => setTempPw(null)} className="text-muted hover:text-text text-xs ml-2">Dismiss</button>
          </div>
        </div>
      )}

      {/* Members */}
      <div className="grid lg:grid-cols-3 gap-5">
        <Panel title={`Members (${members.length})`} className="lg:col-span-2">
          {members.length === 0 && (
            <p className="text-xs text-muted italic">No members yet. Invite one on the right.</p>
          )}
          {members.length > 0 && (
            <table className="w-full text-sm">
              <thead className="text-[10px] tracking-[0.18em] text-muted uppercase">
                <tr className="text-left">
                  <th className="py-2 pr-3">Email</th>
                  <th className="py-2 pr-3">Name</th>
                  <th className="py-2 pr-3">Role in this tenant</th>
                  <th className="py-2 pr-3">Last login</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {members.map(m => (
                  <tr key={m.membership_id} className="border-t border-line/60">
                    <td className="py-2 pr-3 font-mono text-text">{m.email}</td>
                    <td className="py-2 pr-3 text-muted">{m.full_name || "—"}</td>
                    <td className="py-2 pr-3">
                      <select value={m.tenant_role}
                              onChange={e => changeRole(m.membership_id, e.target.value)}
                              className="bg-base border border-line rounded px-2 py-0.5 text-xs focus:outline-none focus:border-accent">
                        {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </td>
                    <td className="py-2 pr-3 text-xs text-muted">
                      {m.last_login_at ? new Date(m.last_login_at).toLocaleString() : "—"}
                    </td>
                    <td className="py-2 pr-3 text-right">
                      <button onClick={() => removeMember(m.membership_id, m.email)}
                              className="text-muted hover:text-danger" title="Revoke membership">
                        <Trash2 size={14}/>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Invite a user" icon={<UserPlus size={14} className="text-accent"/>}>
          <label className="block mb-3 text-xs uppercase tracking-wider text-muted">
            Email
            <input type="email" value={invite.email}
                   onChange={e => setInvite({...invite, email: e.target.value})}
                   placeholder="analyst@acme.example.com"
                   className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent"/>
          </label>
          <label className="block mb-3 text-xs uppercase tracking-wider text-muted">
            Full name (optional)
            <input value={invite.full_name}
                   onChange={e => setInvite({...invite, full_name: e.target.value})}
                   className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent"/>
          </label>
          <label className="block mb-3 text-xs uppercase tracking-wider text-muted">
            Role in this tenant
            <select value={invite.role}
                    onChange={e => setInvite({...invite, role: e.target.value})}
                    className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent">
              {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </label>
          <label className="block mb-4 text-xs uppercase tracking-wider text-muted">
            Password (leave blank to auto-generate)
            <input type="text" value={invite.password}
                   onChange={e => setInvite({...invite, password: e.target.value})}
                   placeholder="(generated, shown once)"
                   className="mt-1 w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm font-mono focus:outline-none focus:border-accent"/>
          </label>
          <button onClick={addMember} disabled={busy || !invite.email.includes("@")}
                  className="w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40 text-sm">
            <Plus size={14}/> Invite
          </button>
          <div className="mt-3 text-[11px] text-muted leading-relaxed border-t border-line/60 pt-3">
            Existing users (by email) are added to this tenant without creating a new account.
            New users get a generated password shown once.
          </div>
        </Panel>
      </div>
    </div>
  );
}
