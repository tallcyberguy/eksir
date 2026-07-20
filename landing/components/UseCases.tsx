import { Briefcase, Users, Cpu } from "lucide-react";

const cases = [
  {
    icon: Briefcase,
    audience: "MSSPs",
    title: "One pane for every client.",
    body: "Triage incidents across dozens of clients without ever leaking data between them. Brief each one in their own language and channel.",
  },
  {
    icon: Users,
    audience: "In-house SOC teams",
    title: "Cut alert fatigue at the source.",
    body: "Let AI handle the first pass — summary, enrichment, severity hint. Your analysts spend their hours on the decisions, not the legwork.",
  },
  {
    icon: Cpu,
    audience: "Security-conscious orgs",
    title: "Audit every step, AI included.",
    body: "Every action, override, and pipeline event is logged. Show your auditor exactly what the AI saw and what the analyst decided.",
  },
];

export function UseCases() {
  return (
    <section id="use-cases" className="container-rail py-20 md:py-28 border-t border-line/60">
      <div className="max-w-2xl">
        <span className="eyebrow">Who it's for</span>
        <h2 className="mt-4 text-3xl md:text-4xl font-semibold tracking-tight text-text leading-tight">
          Built for the teams who answer the on-call phone.
        </h2>
      </div>

      <div className="grid md:grid-cols-3 gap-5 mt-12">
        {cases.map(c => (
          <div key={c.audience} className="panel p-6">
            <div className="flex items-center gap-2 mb-3">
              <c.icon size={14} className="text-accent"/>
              <span className="text-xs uppercase tracking-[0.15em] text-accent font-semibold">
                {c.audience}
              </span>
            </div>
            <h3 className="text-text font-semibold text-lg leading-tight">{c.title}</h3>
            <p className="text-sm text-muted mt-3 leading-relaxed">{c.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
