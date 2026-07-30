"use client";

import { useEffect, useState } from "react";
import { ShieldCheck, ShieldAlert, KeyRound, Copy, Check, Lock } from "lucide-react";
import { api, setToken } from "@/lib/api";

export const dynamic = "force-dynamic";

type Me = { email?: string; mfa_enabled?: boolean } | null;

export default function SecurityPage() {
  const [me, setMe] = useState<Me>(undefined as any);   // undefined = loading
  const [enroll, setEnroll] = useState<{ secret: string; otpauth_uri: string; qr_data_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  async function refresh() {
    try { setMe(await api.me()); } catch { setMe(null); }
  }
  useEffect(() => { refresh(); }, []);

  function reset() { setEnroll(null); setCode(""); setErr(null); setMsg(null); }

  async function startEnroll() {
    setBusy(true); setErr(null); setMsg(null);
    try { setEnroll(await api.mfa.enroll()); }
    catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  }

  async function confirm() {
    setBusy(true); setErr(null);
    try {
      await api.mfa.activate(code.trim());
      reset(); setMsg("Two-factor authentication is now enabled.");
      await refresh();
    } catch { setErr("Invalid code — check your authenticator app and try again."); }
    finally { setBusy(false); }
  }

  async function disable() {
    setBusy(true); setErr(null);
    try {
      await api.mfa.disable(code.trim());
      reset(); setMsg("Two-factor authentication has been disabled.");
      await refresh();
    } catch { setErr("Invalid code — enter a current code to disable 2FA."); }
    finally { setBusy(false); }
  }

  async function copy(text: string, key: string) {
    try { await navigator.clipboard.writeText(text); setCopied(key); setTimeout(() => setCopied(null), 1500); }
    catch { /* clipboard blocked — the value is visible to copy manually */ }
  }

  const codeInput = (
    <input
      inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="123456"
      value={code} onChange={e => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
      className="w-40 bg-base border border-line rounded-md px-2 py-1.5 text-sm tracking-[0.3em] text-center font-mono focus:outline-none focus:border-accent/60"/>
  );

  return (
    <div className="max-w-2xl">
      <h1 className="text-lg font-semibold text-text mb-1">Security</h1>
      <p className="text-sm text-muted mb-6">Manage your password and two-factor authentication.</p>

      <ChangePassword />


      <div className="panel p-6">
        <div className="flex items-center gap-2 mb-4">
          {me?.mfa_enabled
            ? <ShieldCheck size={18} className="text-positive"/>
            : <ShieldAlert size={18} className="text-muted"/>}
          <div className="text-sm font-medium text-text">Two-factor authentication (TOTP)</div>
          <span className={`ml-auto text-[11px] uppercase tracking-wider px-2 py-0.5 rounded-full border ${
            me?.mfa_enabled ? "text-positive border-positive/40 bg-positive/10" : "text-muted border-line"}`}>
            {me === undefined ? "…" : me?.mfa_enabled ? "Enabled" : "Disabled"}
          </span>
        </div>

        {me === undefined && <div className="text-sm text-muted">Loading…</div>}

        {/* Enabled → offer disable (requires a current code) */}
        {me?.mfa_enabled && (
          <div>
            <p className="text-sm text-muted mb-3">
              Your account is protected. To turn it off, enter a current code from your authenticator app.
            </p>
            <div className="flex items-center gap-2">
              {codeInput}
              <button
                onClick={disable} disabled={busy || code.length < 6}
                className="px-3 py-1.5 rounded-md text-sm bg-danger/10 border border-danger/40 text-danger hover:bg-danger/20 disabled:opacity-40">
                {busy ? "Disabling…" : "Disable 2FA"}
              </button>
            </div>
          </div>
        )}

        {/* Disabled + not yet enrolling → offer enable */}
        {me?.mfa_enabled === false && !enroll && (
          <div>
            <p className="text-sm text-muted mb-4">
              Add a second factor. You'll need an authenticator app (Google Authenticator, Authy, 1Password…).
            </p>
            <button
              onClick={startEnroll} disabled={busy}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-sm bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
              <KeyRound size={14}/> {busy ? "Generating…" : "Enable 2FA"}
            </button>
          </div>
        )}

        {/* Enrolling → show secret + otpauth URI, confirm with a code */}
        {enroll && (
          <div>
            <ol className="text-sm text-muted list-decimal ml-4 space-y-3">
              <li>
                Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password…):
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={enroll.qr_data_uri} alt="TOTP QR code" width={176} height={176}
                  className="mt-2 w-44 h-44 rounded-md bg-white p-2 border border-line"/>
                <div className="mt-3 text-xs text-muted">Can't scan? Enter this key manually:</div>
                <div className="mt-1 flex items-center gap-2">
                  <code className="flex-1 bg-base border border-line rounded-md px-2 py-1.5 text-xs font-mono text-text break-all">{enroll.secret}</code>
                  <button onClick={() => copy(enroll.secret, "secret")} title="Copy secret"
                    className="p-1.5 rounded-md border border-line text-muted hover:text-text">
                    {copied === "secret" ? <Check size={14} className="text-positive"/> : <Copy size={14}/>}
                  </button>
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <code className="flex-1 bg-base border border-line rounded-md px-2 py-1.5 text-[11px] font-mono text-muted break-all">{enroll.otpauth_uri}</code>
                  <button onClick={() => copy(enroll.otpauth_uri, "uri")} title="Copy otpauth URI"
                    className="p-1.5 rounded-md border border-line text-muted hover:text-text">
                    {copied === "uri" ? <Check size={14} className="text-positive"/> : <Copy size={14}/>}
                  </button>
                </div>
              </li>
              <li>
                Enter the 6-digit code it shows to confirm:
                <div className="mt-2 flex items-center gap-2">
                  {codeInput}
                  <button
                    onClick={confirm} disabled={busy || code.length < 6}
                    className="px-3 py-1.5 rounded-md text-sm bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
                    {busy ? "Confirming…" : "Confirm & enable"}
                  </button>
                  <button onClick={reset} className="px-3 py-1.5 rounded-md text-sm text-muted hover:text-text">Cancel</button>
                </div>
              </li>
            </ol>
          </div>
        )}

        {err && <div className="mt-4 text-sm text-danger">{err}</div>}
        {msg && <div className="mt-4 text-sm text-positive">{msg}</div>}
      </div>
    </div>
  );
}

function ChangePassword() {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const tooShort = next.length > 0 && next.length < 10;
  const mismatch = confirmPw.length > 0 && next !== confirmPw;
  const canSubmit = cur.length > 0 && next.length >= 10 && next === confirmPw && !busy;

  async function submit() {
    setBusy(true); setErr(null); setMsg(null);
    try {
      // The server revokes every other session and returns a fresh token for
      // this one, so persist it to stay signed in.
      const res = await api.changePassword(cur, next);
      setToken(res.token);
      setCur(""); setNext(""); setConfirmPw("");
      setMsg("Password changed. Other sessions have been signed out.");
    } catch (e: any) {
      setErr(e?.message || "Could not change password.");
    } finally { setBusy(false); }
  }

  return (
    <div className="panel p-6 mb-5">
      <div className="flex items-center gap-2 mb-4">
        <Lock size={18} className="text-muted"/>
        <div className="text-sm font-medium text-text">Password</div>
      </div>
      <p className="text-sm text-muted mb-4">Change your sign-in password. You'll stay signed in here.</p>
      <div className="space-y-3 max-w-sm">
        <PwField label="Current password" v={cur} on={setCur}/>
        <PwField label="New password" v={next} on={setNext} hint="≥ 10 characters"/>
        <PwField label="Confirm new password" v={confirmPw} on={setConfirmPw}/>
      </div>
      {tooShort && <div className="mt-2 text-[11px] text-danger">New password must be at least 10 characters.</div>}
      {mismatch && <div className="mt-2 text-[11px] text-danger">Passwords don&apos;t match.</div>}
      <button onClick={submit} disabled={!canSubmit}
        className="mt-4 inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-sm bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
        <KeyRound size={14}/> {busy ? "Changing…" : "Change password"}
      </button>
      {err && <div className="mt-3 text-sm text-danger">{err}</div>}
      {msg && <div className="mt-3 text-sm text-positive">{msg}</div>}
    </div>
  );
}

function PwField({ label, v, on, hint }: { label: string; v: string; on: (s: string) => void; hint?: string }) {
  return (
    <div>
      <label className="block text-[10px] tracking-[0.18em] text-muted uppercase mb-1">{label}</label>
      <input type="password" value={v} autoComplete="off" onChange={e => on(e.target.value)}
        className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60"/>
      {hint && <div className="text-[10px] text-muted mt-1">{hint}</div>}
    </div>
  );
}
