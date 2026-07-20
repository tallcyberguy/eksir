import type { Metadata } from "next";
import "../styles/globals.css";
import { AuthGuard } from "@/components/AuthGuard";
import { ThemeProvider } from "@/components/ThemeProvider";

export const metadata: Metadata = {
  title: "EKSIR — Security Operations Platform",
  description: "Security alert investigation workbench",
};

// Prevent flash of wrong theme before React hydrates by reading localStorage
// and setting data-theme synchronously in a blocking script.
const themeInitScript = `
(function(){
  try {
    var t = localStorage.getItem('eksir-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', t);
    if (t !== 'light') document.documentElement.classList.add('dark');
    else document.documentElement.classList.remove('dark');
  } catch(e) {}
})();
`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      {/* eslint-disable-next-line @next/next/no-sync-scripts */}
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }}/>
      </head>
      <body className="min-h-screen">
        <ThemeProvider>
          <AuthGuard>{children}</AuthGuard>
        </ThemeProvider>
      </body>
    </html>
  );
}
