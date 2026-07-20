import "../styles/globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  metadataBase: new URL("https://eksir.com"),
  title: "EKSIR — AI-assisted SOC operations for MSSPs",
  description:
    "Triage incidents in seconds, brief clients in their language, and run response actions — across every tenant from one pane.",
  keywords: [
    "SOC", "MSSP", "security operations", "incident response", "threat intelligence",
    "AI triage", "multi-tenant SOC", "SOC workbench",
  ],
  icons: { icon: "/icon.svg" },
  openGraph: {
    title: "EKSIR — AI-assisted SOC operations for MSSPs",
    description:
      "Triage incidents in seconds, brief clients in their language, and run response actions — across every tenant from one pane.",
    type: "website",
    url: "https://eksir.com",
    siteName: "EKSIR",
  },
  twitter: {
    card: "summary_large_image",
    title: "EKSIR — AI-assisted SOC operations for MSSPs",
    description:
      "Triage, enrich, and brief clients on incidents from a single pane.",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com"/>
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin=""/>
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-screen">{children}</body>
    </html>
  );
}
