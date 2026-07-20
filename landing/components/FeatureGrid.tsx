import {
  Brain, Building2, Mail, ShieldCheck, History, Plug,
} from "lucide-react";

const features = [
  {
    icon: Brain,
    title: "AI-assisted triage",
    body: "Every incident gets an instant LLM summary, severity hint, and indicator list. Analysts confirm or override — they don't write from scratch.",
  },
  {
    icon: Building2,
    title: "MSSP multi-tenancy",
    body: "Host → MSSP → Client hierarchy with role-per-tenant. Cross-tenant data simply doesn't exist in another tenant's view.",
  },
  {
    icon: Mail,
    title: "Customer notifications",
    body: "Promote any incident to a customer case. EKSIR drafts the brief in the client's language. You review the HTML preview, then send.",
  },
  {
    icon: ShieldCheck,
    title: "IOC enrichment built in",
    body: "VirusTotal, AbuseIPDB, ThreatFox, URLhaus, MalwareBazaar, WHOIS — one click. No tab-juggling, no API key tour.",
  },
  {
    icon: History,
    title: "Full audit trail",
    body: "Every user action, admin change, and pipeline event is logged, scoped to tenant, and searchable. Built for the audit you'll have.",
  },
  {
    icon: Plug,
    title: "Open architecture",
    body: "Postgres, Qdrant, and a LiteLLM proxy under the hood. Bring your own LLM keys. No vendor lock-in on the brain of your SOC.",
  },
];

export function FeatureGrid() {
  return (
    <section id="features" className="container-rail py-20 md:py-28 border-t border-line/60">
      <div className="max-w-2xl">
        <span className="eyebrow">Features</span>
        <h2 className="mt-4 text-3xl md:text-4xl font-semibold tracking-tight text-text leading-tight">
          Built around the actual SOC workflow.
        </h2>
        <p className="mt-4 text-muted leading-relaxed">
          Not a SIEM. Not a ticketing tool. EKSIR sits between your detection stack and your
          customers — the layer where alerts become decisions.
        </p>
      </div>

      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5 mt-12">
        {features.map(f => (
          <div key={f.title} className="panel p-6 hover:shadow-cyber transition-shadow">
            <div className="w-10 h-10 rounded-lg bg-accent/10 border border-accent/40
                            flex items-center justify-center text-accent mb-4">
              <f.icon size={18}/>
            </div>
            <h3 className="text-text font-semibold text-base">{f.title}</h3>
            <p className="text-sm text-muted mt-2 leading-relaxed">{f.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
