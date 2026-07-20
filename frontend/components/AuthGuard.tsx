"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { api, setToken } from "@/lib/api";
import { Sidebar } from "@/components/layout/Sidebar";
import { Topbar } from "@/components/layout/Topbar";
import { CopilotDock } from "@/components/copilot/CopilotDock";

const PUBLIC_PATHS = new Set(["/login"]);

type Status = "checking" | "authed" | "anon";

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router   = useRouter();
  const [status, setStatus] = useState<Status>("checking");
  const [user,   setUser]   = useState<any>(null);

  const isPublic = PUBLIC_PATHS.has(pathname);

  useEffect(() => {
    let cancelled = false;

    const token = typeof window !== "undefined" ? window.localStorage.getItem("isoc.token") : null;

    if (!token) {
      if (!isPublic) router.replace(`/login?next=${encodeURIComponent(pathname)}`);
      setStatus(isPublic ? "anon" : "anon");
      return;
    }

    // Validate token with /auth/me — covers expired / revoked tokens too.
    api.me()
      .then(u => {
        if (cancelled) return;
        setUser(u);
        setStatus("authed");
      })
      .catch(() => {
        if (cancelled) return;
        setToken(null);
        setStatus("anon");
        if (!isPublic) router.replace(`/login?next=${encodeURIComponent(pathname)}`);
      });

    return () => { cancelled = true; };
  }, [pathname, isPublic, router]);

  // ── Public pages (login) — no shell ─────────────────────────────────────
  if (isPublic) {
    return <>{children}</>;
  }

  // ── Still checking the token — show a placeholder, no shell ─────────────
  if (status === "checking") {
    return (
      <div className="min-h-screen flex items-center justify-center text-muted text-sm">
        Authorising…
      </div>
    );
  }

  // ── Not authed and not on a public page — the redirect is in-flight ─────
  if (status === "anon") {
    return (
      <div className="min-h-screen flex items-center justify-center text-muted text-sm">
        Redirecting to login…
      </div>
    );
  }

  // ── Authed — render the app shell ───────────────────────────────────────
  return (
    <div className="min-h-screen flex">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <Topbar user={user}/>
        <main className="flex-1 px-6 py-5 overflow-x-hidden">{children}</main>
      </div>
      <CopilotDock />
    </div>
  );
}
