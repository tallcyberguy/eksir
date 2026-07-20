import { Inbox, Sparkles, Send } from "lucide-react";

const steps = [
  {
    n: "01",
    icon: Inbox,
    title: "Ingest",
    body: "Alerts land via API, webhook, or paste-in. EKSIR parses the raw payload — Wazuh, FortiGate, M365, whatever your stack speaks.",
  },
  {
    n: "02",
    icon: Sparkles,
    title: "Triage",
    body: "AI summarises the incident, enriches every IP, hash, and domain, and suggests a verdict. Analyst confirms — usually in under 60 seconds.",
  },
  {
    n: "03",
    icon: Send,
    title: "Act & brief",
    body: "Promote to customer case → EKSIR drafts in the client's language → review preview → send. Trigger response actions in the same flow.",
  },
];

export function HowItWorks() {
  return (
    <section id="how" className="container-rail py-20 md:py-28 border-t border-line/60">
      <div className="max-w-2xl">
        <span className="eyebrow">How it works</span>
        <h2 className="mt-4 text-3xl md:text-4xl font-semibold tracking-tight text-text leading-tight">
          From raw alert to customer brief in three steps.
        </h2>
      </div>

      <div className="grid md:grid-cols-3 gap-5 mt-12 relative">
        {/* Connector line behind cards (decorative) */}
        <div className="hidden md:block absolute left-0 right-0 top-12 h-px
                        bg-gradient-to-r from-transparent via-accent/40 to-transparent" aria-hidden/>

        {steps.map(s => (
          <div key={s.n} className="panel p-6 relative">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 rounded-lg bg-base border border-accent
                              flex items-center justify-center text-accent shadow-glow">
                <s.icon size={18}/>
              </div>
              <span className="font-mono text-2xl text-accent/40 font-semibold">{s.n}</span>
            </div>
            <h3 className="text-text font-semibold text-lg">{s.title}</h3>
            <p className="text-sm text-muted mt-2 leading-relaxed">{s.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
