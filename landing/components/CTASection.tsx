import Link from "next/link";
import { ArrowRight } from "lucide-react";

export function CTASection() {
  return (
    <section className="container-rail py-20 md:py-28">
      <div className="panel p-10 md:p-14 text-center relative overflow-hidden">
        <div className="absolute inset-0 bg-hero-glow pointer-events-none" aria-hidden/>
        <div className="relative">
          <h2 className="text-3xl md:text-4xl font-semibold tracking-tight text-text leading-tight max-w-2xl mx-auto">
            See EKSIR triage one of your real alerts.
          </h2>
          <p className="mt-4 text-muted max-w-xl mx-auto">
            We'll walk you through the workflow on a sample from your own environment.
            No prep needed — bring an alert, leave with a customer brief.
          </p>
          <Link href="/request-demo" className="btn btn-primary mt-8">
            Request a demo <ArrowRight size={16}/>
          </Link>
        </div>
      </div>
    </section>
  );
}
