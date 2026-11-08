"use client";

import { useState, type ReactNode } from "react";
import { usePathname } from "next/navigation";
import { Bell, Menu, X } from "lucide-react";
import { isDemoMode } from "@/lib/api/config";

const navItems = [
  { label: "Overview", href: "/" },
  { label: "Threat Intelligence", href: "/hidden-threats" },
  { label: "Remediation Center", href: "/alerts" },
];

interface AppShellProps {
  children: ReactNode;
  title: string;
  subtitle: string;
  breadcrumb: string;
}

function NavLink({ label, href, active, mobile = false, onNavigate }: { label: string; href: string; active: boolean; mobile?: boolean; onNavigate?: () => void }) {
  return (
    <a href={href} draggable={false} aria-current={active ? "page" : undefined} onClick={onNavigate} className={mobile
      ? `flex h-12 select-none items-center border-b border-[#e0e0e0] px-5 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#0f62fe] ${active ? "border-l-4 border-l-[#0f62fe] bg-[#f4f4f4] font-medium" : "text-[#525252]"}`
      : `relative flex select-none items-center px-5 text-sm transition-colors hover:bg-[#f4f4f4] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[#0f62fe] ${active ? "font-medium text-[#161616]" : "text-[#525252]"}`}>
      {!mobile && <span className={`pointer-events-none absolute inset-x-0 bottom-0 h-[3px] ${active ? "bg-[#0f62fe]" : "bg-transparent"}`} />}
      {label}
    </a>
  );
}

export function AppShell({ children }: AppShellProps) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const pathname = usePathname();
  const demo = isDemoMode();

  return (
    <div className="min-h-screen bg-white text-[#161616] selection:bg-[#0f62fe] selection:text-white">
      <div className="border-b border-[#e0e0e0] bg-[#f4f4f4] px-5 py-2 text-[11px] text-[#525252] sm:px-8 lg:px-12">
        Independent IBM Before the Breach hackathon project · {demo ? "Simulated demo data" : "Live API mode"}
      </div>
      <header className="sticky top-0 z-40 border-b border-[#e0e0e0] bg-white">
        <div className="flex h-16 items-stretch px-5 sm:px-8 lg:px-12">
          {/* Full-document anchors are intentional: Vinext RSC client navigation has failed in prior production builds. */}
          {/* eslint-disable-next-line @next/next/no-html-link-for-pages */}
          <a href="/" draggable={false} className="flex min-w-fit select-none items-center pr-6 text-xl font-medium tracking-tight" onClick={() => setMobileOpen(false)}>
            <span className="gradient-text font-light tracking-[-0.03em]">Vigil</span>
          </a>
          <nav className="hidden items-stretch lg:flex" aria-label="Primary navigation">
            {navItems.map(({ label, href }) => <NavLink key={label} label={label} href={href} active={href === "/" ? pathname === "/" : pathname.startsWith(href)} />)}
          </nav>
          <div className="ml-auto flex items-stretch">
            <button
              className={`relative grid w-12 place-items-center border-l border-[#e0e0e0] text-[#525252] hover:bg-[#f4f4f4] ${notificationsOpen ? "bg-[#f4f4f4] text-[#0f62fe]" : ""}`}
              aria-label="Notifications"
              aria-expanded={notificationsOpen}
              aria-controls="notification-panel"
              onClick={() => { setNotificationsOpen((value) => !value); setMobileOpen(false); }}
            ><Bell size={18} /></button>
            <button className="grid w-12 place-items-center border-l border-[#e0e0e0] lg:hidden" onClick={() => { setMobileOpen((value) => !value); setNotificationsOpen(false); }} aria-expanded={mobileOpen} aria-label="Toggle navigation">{mobileOpen ? <X size={21} /> : <Menu size={21} />}</button>
          </div>
        </div>
        {notificationsOpen && <section id="notification-panel" aria-label="Notification center" className="absolute right-5 top-full z-50 w-[min(24rem,calc(100vw-2.5rem))] border border-[#c6c6c6] bg-white p-5 text-sm text-[#525252] sm:right-8 lg:right-12">
          Real-time notification not connected yet.
        </section>}
        {mobileOpen && <nav className="border-t border-[#e0e0e0] bg-white lg:hidden" aria-label="Mobile navigation">{navItems.map(({ label, href }) => <NavLink key={label} label={label} href={href} active={href === "/" ? pathname === "/" : pathname.startsWith(href)} mobile onNavigate={() => setMobileOpen(false)} />)}</nav>}
      </header>
      <main>
        <div className="mx-auto max-w-[1500px] px-5 py-10 sm:px-8 lg:px-12 lg:py-14">{children}</div>
      </main>
    </div>
  );
}
