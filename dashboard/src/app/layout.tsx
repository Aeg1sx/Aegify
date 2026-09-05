import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";
import { Sidebar } from "@/components/sidebar";
import { SessionProvider } from "next-auth/react";

export const metadata: Metadata = {
  title: "Aegify",
  description: "Security findings dashboard for Aegify scanner",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem('theme');if(t==='dark')document.documentElement.classList.add('dark')}catch(e){}})()`,
          }}
        />
      </head>
      <body
        className={`${GeistSans.variable} ${GeistMono.variable} antialiased`}
      >
        <SessionProvider>
          <a href="#workspace" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-background focus:p-3">Skip to workspace</a>
          <div className="flex h-dvh">
            <Sidebar />
            <main id="workspace" className="min-w-0 flex-1 overflow-auto">
              <div className="mx-auto max-w-[1920px] p-4 md:p-7">{children}</div>
            </main>
          </div>
        </SessionProvider>
      </body>
    </html>
  );
}
