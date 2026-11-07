"use client";

import { useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Bell, ChevronDown, Menu, X } from "lucide-react";

const navItems = [
  { label: "Overview", href: "/" },
  { label: "Time Machine", href: "/time-machine" },
  { label: "Hidden Threats", href: "/hidden-threats" },
  { label: "Company Assets", href: "/assets" },
  { label: "Alert Activity", href: "/alerts", badge: "8" },
];

interface AppShellProps {
  children: ReactNode;
  title: string;
  subtitle: string;
  breadcrumb: string;
}

export function AppShell({ children, title, subtitle, breadcrumb }: AppShellProps) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const pathname = usePathname();

  return (
    <div className="min-h-screen bg-white text-[#161616] selection:bg-[#0f62fe] selection:text-white">
      <div className="border-b border-[#e0e0e0] bg-[#f4f4f4] px-5 py-2 text-[11px] text-[#525252] sm:px-8 lg:px-12">
        Independent project for the IBM Before the Breach hackathon · Simulated data environment
      </div>
      <header className="sticky top-0 z-40 border-b border-[#e0e0e0] bg-white">
        <div className="flex h-16 items-stretch px-5 sm:px-8 lg:px-12">
          <Link href="/" draggable={false} className="flex min-w-fit select-none items-center border-r border-[#e0e0e0] pr-6 text-xl font-medium tracking-tight" onClick={() => setMobileOpen(false)}>
            Signal<span className="text-[#0f62fe]">Zero</span>
          </Link>
          <nav className="hidden items-stretch lg:flex">
            {navItems.map(({ label, href, badge }) => {
              const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
              return <Link key={label} href={href} draggable={false} aria-current={active ? "page" : undefined} className={`relative flex select-none items-center gap-2 px-5 text-sm transition-colors hover:bg-[#f4f4f4] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[#0f62fe] ${active ? "font-medium text-[#161616]" : "text-[#525252]"}`}><span className={`pointer-events-none absolute inset-x-0 bottom-0 h-[3px] ${active ? "bg-[#0f62fe]" : "bg-transparent"}`}/>{label}{badge && <span className="pointer-events-none bg-[#da1e28] px-1.5 py-0.5 text-[10px] text-white">{badge}</span>}</Link>;
            })}
          </nav>
          <div className="ml-auto flex items-stretch">
            <button className="relative grid w-12 place-items-center border-l border-[#e0e0e0] text-[#525252] hover:bg-[#f4f4f4]" aria-label="Notifications"><Bell size={18}/><span className="absolute right-3 top-4 h-1.5 w-1.5 rounded-full bg-[#da1e28]"/></button>
            <button className="hidden items-center gap-3 border-l border-[#e0e0e0] px-4 text-left sm:flex"><span className="grid h-8 w-8 place-items-center bg-[#0f62fe] text-xs font-semibold text-white">SZ</span><span><span className="block text-xs font-medium">Demo workspace</span><span className="block text-[10px] text-[#6f6f6f]">Hackathon project</span></span><ChevronDown size={14} className="text-[#6f6f6f]"/></button>
            <button className="grid w-12 place-items-center border-l border-[#e0e0e0] lg:hidden" onClick={() => setMobileOpen((value) => !value)} aria-label="Toggle navigation">{mobileOpen ? <X size={21}/> : <Menu size={21}/>}</button>
          </div>
        </div>
        {mobileOpen && <nav className="border-t border-[#e0e0e0] bg-white lg:hidden">{navItems.map(({ label, href, badge }) => { const active = href === "/" ? pathname === "/" : pathname.startsWith(href); return <Link key={label} href={href} draggable={false} aria-current={active ? "page" : undefined} onClick={() => setMobileOpen(false)} className={`flex h-12 select-none items-center justify-between border-b border-[#e0e0e0] px-5 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#0f62fe] ${active ? "border-l-4 border-l-[#0f62fe] bg-[#f4f4f4] font-medium" : "text-[#525252]"}`}><span>{label}</span>{badge && <span className="pointer-events-none bg-[#da1e28] px-2 py-0.5 text-[10px] text-white">{badge}</span>}</Link>; })}</nav>}
      </header>

      <main>
        <div className="border-b border-[#e0e0e0] bg-[#f4f4f4] px-5 py-4 sm:px-8 lg:px-12"><div className="mx-auto flex max-w-[1500px] flex-col justify-between gap-2 sm:flex-row sm:items-center"><div><p className="text-sm font-medium">{title}</p><p className="mt-1 text-xs text-[#525252]">{subtitle}</p></div><div className="text-xs text-[#6f6f6f]"><span>SignalZero</span><span className="mx-2">/</span><span className="text-[#161616]">{breadcrumb}</span></div></div></div>
        <div className="mx-auto max-w-[1500px] px-5 py-10 sm:px-8 lg:px-12 lg:py-14">{children}</div>
      </main>
    </div>
  );
}
