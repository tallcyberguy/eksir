"use client";

import Link from "next/link";
import { useState } from "react";
import { Menu, X } from "lucide-react";

const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "https://platform.eksir.com";

const links = [
  { href: "#features",   label: "Features"  },
  { href: "#how",        label: "How it works" },
  { href: "#use-cases",  label: "Use cases" },
  { href: "#pricing",    label: "Pricing"   },
];

export function Nav() {
  const [open, setOpen] = useState(false);
  return (
    <header className="sticky top-0 z-40 backdrop-blur-md bg-base/70 border-b border-line/60">
      <div className="container-rail flex items-center h-16">
        <Link href="/" className="flex items-center gap-2.5">
          <img src="/icon.svg" alt="" width={28} height={28}/>
          <span className="font-mono font-semibold tracking-wider text-text text-lg">EKSIR</span>
        </Link>

        <nav className="hidden md:flex items-center gap-7 ml-10">
          {links.map(l => (
            <a key={l.href} href={l.href}
               className="text-sm text-muted hover:text-text transition-colors">
              {l.label}
            </a>
          ))}
        </nav>

        <div className="ml-auto hidden md:flex items-center gap-3">
          <a href={APP_URL} className="text-sm text-muted hover:text-text transition-colors">
            Sign in
          </a>
          <Link href="/request-demo" className="btn btn-primary !py-2 !px-4">
            Request demo
          </Link>
        </div>

        <button className="md:hidden ml-auto text-text" onClick={() => setOpen(v => !v)}
                aria-label="Toggle menu">
          {open ? <X size={20}/> : <Menu size={20}/>}
        </button>
      </div>

      {open && (
        <div className="md:hidden border-t border-line/60 bg-base/95">
          <div className="container-rail py-4 flex flex-col gap-3">
            {links.map(l => (
              <a key={l.href} href={l.href} onClick={() => setOpen(false)}
                 className="text-sm text-muted hover:text-text py-1">
                {l.label}
              </a>
            ))}
            <a href={APP_URL} className="text-sm text-muted hover:text-text py-1">Sign in</a>
            <Link href="/request-demo" onClick={() => setOpen(false)}
                  className="btn btn-primary !py-2 !px-4 self-start">
              Request demo
            </Link>
          </div>
        </div>
      )}
    </header>
  );
}
