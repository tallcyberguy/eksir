import { AlertOctagon, Clock, Languages, FileSearch } from "lucide-react";

const pains = [
  { icon: AlertOctagon, t: "Alert fatigue", d: "Analysts spend their day on the same low-value triage steps for every alert." },
  { icon: Clock,        t: "Slow customer comms", d: "Briefing a client takes longer than triaging the incident itself." },
  { icon: FileSearch,   t: "Indicator hunting", d: "Pivoting through VT, AbuseIPDB, WHOIS, MalwareBazaar by hand wastes minutes per IOC." },
  { icon: Languages,    t: "Multi-tenant chaos", d: "MSSPs juggle clients across tools, inboxes, and languages with no isolation." },
];

export function Problem() {
  return (
    <section className="container-rail py-20 md:py-28">
      <div className="max-w-2xl">
        <span className="eyebrow">The problem</span>
        <h2 className="mt-4 text-3xl md:text-4xl font-semibold tracking-tight text-text leading-tight">
          A SOC analyst's day shouldn't be 70% copy-paste.
        </h2>
        <p className="mt-4 text-muted leading-relaxed">
          Most SOC tooling stops at the alert. The hard part — making sense of it, enriching it,
          and explaining it to the customer in plain language — falls on whoever's on shift.
        </p>
      </div>

      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-12">
        {pains.map(p => (
          <div key={p.t} className="panel p-5">
            <p.icon size={18} className="text-accent mb-3"/>
            <h3 className="text-text font-semibold">{p.t}</h3>
            <p className="text-sm text-muted mt-2 leading-relaxed">{p.d}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
