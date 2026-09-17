import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "@/lib/providers";
import { TopNav } from "@/components/layout/TopNav";
import { SidebarNav } from "@/components/layout/SidebarNav";
import { HaltAgentsModal } from "@/components/layout/HaltAgentsModal";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "ARKA — Unified Security Operations Console",
  description: "Autonomous Risk Knowledge & Assessment Platform - Deterministic Security Control Plane",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased dark`}
    >
      <body className="h-full bg-[#060e20] text-slate-100 flex flex-col font-sans">
        <Providers>
          <TopNav />
          <div className="flex-1 flex overflow-hidden">
            <SidebarNav />
            <main className="flex-1 overflow-y-auto bg-[#060e20] p-6">
              {children}
            </main>
          </div>
          <HaltAgentsModal />
        </Providers>
      </body>
    </html>
  );
}
