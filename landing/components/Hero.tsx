import Link from "next/link";
import { ArrowRight, ShieldCheck } from "lucide-react";

const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "https://platform.eksir.com";

export function Hero() {
  return (
    <section className="relative overflow-hidden">
      {/* Cyan glow behind the hero. */}
      <div className="absolute inset-0 bg-hero-glow pointer-events-none" aria-hidden/>

      <div className="container-rail pt-16 pb-20 md:pt-24 md:pb-28 relative">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 text-xs uppercase tracking-[0.2em] font-semibold
                          text-accent border border-accent/40 bg-accent/10 rounded-full px-3 py-1 mb-6">
            <ShieldCheck size={12}/> Built for MSSPs and their clients
          </div>

          <h1 className="text-4xl md:text-6xl font-semibold tracking-tight leading-[1.05] text-text">
            The SOC workbench that{" "}
            <span className="text-accent">thinks alongside your analysts.</span>
          </h1>

          <p className="mt-6 text-lg text-muted leading-relaxed max-w-2xl">
            EKSIR turns raw alerts into triaged incidents, enriched indicators, and customer-ready
            briefs — across every tenant from a single pane. Less alert fatigue, faster response,
            and clients who actually understand what just happened.
          </p>

          <div className="mt-9 flex flex-wrap gap-3">
            <Link href="/request-demo" className="btn btn-primary">
              Request a demo <ArrowRight size={16}/>
            </Link>
            <a href={APP_URL} className="btn btn-ghost">
              Sign in to platform
            </a>
          </div>

          <p className="mt-5 text-xs text-muted/70">
            No credit card. Live walkthrough with a real incident from your environment.
          </p>
        </div>

        {/* Product mock card — abstract UI scaffolding, not a screenshot. */}
        <ProductMock/>
      </div>
    </section>
  );
}

function ProductMock() {
  return (
    <div className="panel mt-16 p-5 md:p-7 shadow-glowLg overflow-hidden">
      <div className="flex items-center gap-2 mb-5">
        <span className="w-2 h-2 rounded-full bg-danger/70"/>
        <span className="w-2 h-2 rounded-full bg-warning/70"/>
        <span className="w-2 h-2 rounded-full bg-positive/70"/>
        <span className="ml-3 font-mono text-[11px] text-muted truncate">
          platform.eksir.com/incidents/INC-001022
        </span>
      </div>

      <div className="grid md:grid-cols-[1fr_280px] gap-5">
        {/* Left: fake incident summary */}
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded
                             bg-danger/15 text-danger border border-danger/40">Critical</span>
            <span className="px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded
                             bg-accent/10 text-accent border border-accent/40">Phishing</span>
            <span className="text-xs font-mono text-muted ml-auto">INC-001022</span>
          </div>
          <h3 className="text-text font-semibold text-lg leading-tight">
            Suspicious credential-harvest URL delivered to finance@acme.com
          </h3>

          <div className="text-sm text-muted space-y-2 leading-relaxed">
            <p>
              <span className="text-accent font-mono">AI summary:</span> The user received an email
              impersonating Microsoft 365, containing a link to
              <code className="text-accent mx-1">2acnmzzlink.webcindario.com</code>
              flagged by 8/90 VT engines as malicious. No click confirmed.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-2 pt-2">
            <Stat label="VT Score" value="8/90" tone="danger"/>
            <Stat label="Verdict" value="Malicious" tone="danger"/>
            <Stat label="Confidence" value="Medium" tone="warning"/>
          </div>
        </div>

        {/* Right: action strip */}
        <div className="border-l border-line/60 pl-5 space-y-2 text-sm">
          <p className="text-xs uppercase tracking-wider text-muted mb-1">Actions</p>
          <ActionRow icon="◇" label="Promote to customer case" tone="accent"/>
          <ActionRow icon="✓" label="Block URL on perimeter" tone="positive"/>
          <ActionRow icon="◇" label="Notify finance@acme.com" tone="muted"/>
          <ActionRow icon="◇" label="Open response runbook" tone="muted"/>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone: "danger"|"warning"|"positive" }) {
  const toneClass = {
    danger:  "text-danger border-danger/40 bg-danger/10",
    warning: "text-warning border-warning/40 bg-warning/10",
    positive:"text-positive border-positive/40 bg-positive/10",
  }[tone];
  return (
    <div className={`border ${toneClass} rounded-md px-2.5 py-2`}>
      <div className="text-[10px] uppercase tracking-wider text-muted">{label}</div>
      <div className="font-mono text-base">{value}</div>
    </div>
  );
}

function ActionRow({ icon, label, tone }: { icon: string; label: string; tone: "accent"|"positive"|"muted" }) {
  const color = { accent: "text-accent", positive: "text-positive", muted: "text-muted" }[tone];
  return (
    <div className="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-surface2/40 transition-colors">
      <span className={`font-mono ${color}`}>{icon}</span>
      <span className="text-text/90">{label}</span>
    </div>
  );
}
