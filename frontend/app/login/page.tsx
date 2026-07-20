"use client";

import { useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { api, setToken } from "@/lib/api";

export const dynamic = "force-dynamic";

function LoginInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const next = searchParams.get("next") || "/";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string|null>(null);
  const [busy, setBusy] = useState(false);

  // MFA second step: set once /auth/login returns an mfa_required challenge.
  const [mfaToken, setMfaToken] = useState<string|null>(null);
  const [code, setCode] = useState("");

  function finish(tok: string) {
    setToken(tok);
    // Only redirect to in-app paths — never to an external URL passed via ?next=
    const dest = next.startsWith("/") && !next.startsWith("//") ? next : "/";
    router.replace(dest);
  }

  async function submit(e?: React.FormEvent) {
    e?.preventDefault();
    setBusy(true); setErr(null);
    try {
      const r = await api.login(email, password);
      if (r.mfa_required && r.mfa_token) { setMfaToken(r.mfa_token); }
      else if (r.token)                  { finish(r.token); }
      else                               { setErr("Unexpected login response"); }
    } catch (e: any) { setErr(e.message); }
    finally          { setBusy(false); }
  }

  async function submitMfa(e?: React.FormEvent) {
    e?.preventDefault();
    if (!mfaToken) return;
    setBusy(true); setErr(null);
    try {
      const r = await api.loginMfa(mfaToken, code.trim());
      finish(r.token);
    } catch (e: any) { setErr("Invalid or expired code — try again."); }
    finally          { setBusy(false); }
  }

  function backToPassword() {
    setMfaToken(null); setCode(""); setErr(null); setPassword("");
  }

  const brand = (
    <div className="flex items-center gap-2 mb-6">
      <div className="w-8 h-8 rounded-md overflow-hidden shrink-0">
        <img src="/icon.svg" alt="EKSIR" width={32} height={32} className="w-full h-full"/>
      </div>
      <div>
        <div className="font-mono font-semibold tracking-wider text-text">EKSIR</div>
        <div className="text-[10px] text-muted">Security Operations</div>
      </div>
    </div>
  );

  // ── Second factor step ──────────────────────────────────────────────────
  if (mfaToken) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <form onSubmit={submitMfa} className="panel p-8 w-full max-w-sm">
          {brand}
          <div className="text-sm text-text mb-1">Two-factor authentication</div>
          <div className="text-xs text-muted mb-4">Enter the 6-digit code from your authenticator app.</div>
          <input
            inputMode="numeric" autoComplete="one-time-code" autoFocus maxLength={6}
            placeholder="123456"
            value={code} onChange={e=>setCode(e.target.value.replace(/\D/g,"").slice(0,6))}
            className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm tracking-[0.3em] text-center font-mono focus:outline-none focus:border-accent/60"/>
          <button
            type="submit"
            disabled={busy || code.length < 6}
            className="mt-5 w-full px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
            {busy ? "Verifying…" : "Verify"}
          </button>
          <button
            type="button" onClick={backToPassword}
            className="mt-2 w-full px-3 py-2 rounded-md text-sm text-muted hover:text-text">
            Back
          </button>
          {err && <div className="mt-3 text-sm text-danger">{err}</div>}
        </form>
      </div>
    );
  }

  // ── Password step ─────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <form onSubmit={submit} className="panel p-8 w-full max-w-sm">
        {brand}
        <label className="block text-xs uppercase tracking-wider text-muted mb-1">Email</label>
        <input
          type="email" autoComplete="email" autoFocus
          value={email} onChange={e=>setEmail(e.target.value)}
          className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60"/>
        <label className="block text-xs uppercase tracking-wider text-muted mt-3 mb-1">Password</label>
        <input
          type="password" autoComplete="current-password"
          value={password} onChange={e=>setPassword(e.target.value)}
          className="w-full bg-base border border-line rounded-md px-2 py-1.5 text-sm focus:outline-none focus:border-accent/60"/>
        <button
          type="submit"
          disabled={busy || !email || !password}
          className="mt-5 w-full px-3 py-2 rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40">
          {busy ? "Signing in…" : "Sign in"}
        </button>
        {err && <div className="mt-3 text-sm text-danger">{err}</div>}
      </form>
    </div>
  );
}

export default function Login() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-muted text-sm">Loading…</div>}>
      <LoginInner/>
    </Suspense>
  );
}
