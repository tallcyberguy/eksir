import Link from "next/link";
import { ArrowLeft, ShieldCheck, Languages, Activity } from "lucide-react";
import { DemoForm } from "@/components/DemoForm";
import { Nav } from "@/components/Nav";
import { Footer } from "@/components/Footer";

export const metadata = { title: "Request a demo — EKSIR" };

const highlights = [
  { icon: Activity,    t: "Live walkthrough", d: "We triage a real incident from your environment, not a canned demo." },
  { icon: Languages,   t: "Multi-locale brief", d: "See the same incident drafted in three different customer languages." },
  { icon: ShieldCheck, t: "Tenant isolation", d: "Watch how MSSP, client, and host roles see (and don't see) each other's data." },
];

export default function RequestDemoPage() {
  return (
    <>
      <Nav/>
      <main className="container-rail py-16 md:py-20">
        <Link href="/" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-text mb-8">
          <ArrowLeft size={14}/> Back
        </Link>

        <div className="grid lg:grid-cols-[1fr_1.1fr] gap-10 lg:gap-16 items-start">
          <div>
            <span className="eyebrow">Request a demo</span>
            <h1 className="mt-4 text-3xl md:text-5xl font-semibold tracking-tight text-text leading-tight">
              Let's triage one of your alerts together.
            </h1>
            <p className="mt-5 text-muted leading-relaxed max-w-lg">
              30 minutes, screen-share, your own data. We'll show you how EKSIR turns a raw alert
              into a customer-ready brief — and answer whatever you throw at us about MSSP
              deployments, LLM cost, or self-hosting.
            </p>

            <ul className="mt-8 space-y-4">
              {highlights.map(h => (
                <li key={h.t} className="flex gap-3">
                  <div className="w-9 h-9 rounded-lg bg-accent/10 border border-accent/40
                                  flex items-center justify-center text-accent shrink-0">
                    <h.icon size={16}/>
                  </div>
                  <div>
                    <p className="text-text font-semibold text-sm">{h.t}</p>
                    <p className="text-sm text-muted leading-relaxed">{h.d}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>

          <DemoForm/>
        </div>
      </main>
      <Footer/>
    </>
  );
}
