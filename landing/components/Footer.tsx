import Link from "next/link";

const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "https://platform.eksir.com";

export function Footer() {
  return (
    <footer className="border-t border-line/60 mt-10">
      <div className="container-rail py-12 grid md:grid-cols-[1.5fr_1fr_1fr_1fr] gap-10">
        <div>
          <div className="flex items-center gap-2.5">
            <img src="/icon.svg" alt="" width={28} height={28}/>
            <span className="font-mono font-semibold tracking-wider text-text text-lg">EKSIR</span>
          </div>
          <p className="text-sm text-muted mt-3 leading-relaxed max-w-xs">
            AI-assisted SOC operations for MSSPs and their clients.
          </p>
        </div>

        <FooterCol title="Product" links={[
          { l: "Features",     h: "#features" },
          { l: "How it works", h: "#how" },
          { l: "Pricing",      h: "#pricing" },
          { l: "Sign in",      h: APP_URL },
        ]}/>

        <FooterCol title="Company" links={[
          { l: "Request demo", h: "/request-demo" },
          { l: "Contact",      h: "mailto:hello@eksir.com" },
        ]}/>

        <FooterCol title="Legal" links={[
          { l: "Privacy",  h: "/privacy" },
          { l: "Terms",    h: "/terms" },
        ]}/>
      </div>

      <div className="border-t border-line/60">
        <div className="container-rail py-5 flex flex-wrap items-center justify-between text-xs text-muted gap-3">
          <span>© {new Date().getFullYear()} EKSIR. All rights reserved.</span>
          <span className="font-mono">platform.eksir.com</span>
        </div>
      </div>
    </footer>
  );
}

function FooterCol({ title, links }: { title: string; links: { l: string; h: string }[] }) {
  return (
    <div>
      <h4 className="text-xs uppercase tracking-[0.2em] text-muted font-semibold mb-3">{title}</h4>
      <ul className="space-y-2">
        {links.map(l => (
          <li key={l.l}>
            <Link href={l.h} className="text-sm text-text/80 hover:text-accent transition-colors">
              {l.l}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
