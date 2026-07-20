import Link from "next/link";
import { Check } from "lucide-react";

const tiers = [
  {
    name: "Starter",
    price: "Free",
    sub: "for early-access pilots",
    cta: "Request access",
    href: "/request-demo",
    features: [
      "Up to 2 client tenants",
      "AI triage + IOC enrichment",
      "Customer notifications (HTML preview)",
      "Community support",
    ],
    highlighted: false,
  },
  {
    name: "MSSP",
    price: "Contact us",
    sub: "for production MSSP deployments",
    cta: "Request demo",
    href: "/request-demo",
    features: [
      "Unlimited client tenants",
      "Role-per-tenant access control",
      "SMTP send + branded preview",
      "Immutable per-action audit log",
      "Priority email support",
    ],
    highlighted: true,
  },
  {
    name: "Self-hosted",
    price: "Custom",
    sub: "for regulated environments",
    cta: "Talk to us",
    href: "/request-demo",
    features: [
      "Docker / on-prem deployment",
      "Bring-your-own LLM keys",
      "Single tenant or full MSSP topology",
      "MFA + full audit trail",
      "Dedicated engineering support",
    ],
    highlighted: false,
  },
];

export function Pricing() {
  return (
    <section id="pricing" className="container-rail py-20 md:py-28 border-t border-line/60">
      <div className="max-w-2xl">
        <span className="eyebrow">Pricing</span>
        <h2 className="mt-4 text-3xl md:text-4xl font-semibold tracking-tight text-text leading-tight">
          Honest plans, no per-seat tax.
        </h2>
        <p className="mt-4 text-muted leading-relaxed">
          EKSIR is in early access. Pricing is shaped together with each design partner — talk
          to us and we'll find the structure that fits.
        </p>
      </div>

      <div className="grid md:grid-cols-3 gap-5 mt-12">
        {tiers.map(t => (
          <div key={t.name}
               className={`panel p-7 flex flex-col ${t.highlighted ? "shadow-cyber border-accent/60" : ""}`}>
            {t.highlighted && (
              <span className="self-start text-[10px] uppercase tracking-[0.2em] font-semibold
                               text-accent bg-accent/10 border border-accent/40 rounded-full px-2 py-0.5 mb-3">
                Most common
              </span>
            )}
            <h3 className="text-text font-semibold text-lg">{t.name}</h3>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-mono font-semibold text-text">{t.price}</span>
            </div>
            <p className="text-xs text-muted mt-1">{t.sub}</p>

            <ul className="mt-6 space-y-2.5 flex-1">
              {t.features.map(f => (
                <li key={f} className="flex items-start gap-2 text-sm text-text/90">
                  <Check size={14} className="text-accent mt-0.5 shrink-0"/>
                  <span>{f}</span>
                </li>
              ))}
            </ul>

            <Link href={t.href}
                  className={`mt-6 ${t.highlighted ? "btn btn-primary" : "btn btn-ghost"}`}>
              {t.cta}
            </Link>
          </div>
        ))}
      </div>
    </section>
  );
}
