"use client";

import { useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, Bell, Box, ChevronDown, Clock3, Command, Eye, Hexagon, LayoutDashboard, Menu, Server, Sparkles, X } from "lucide-react";

const navItems = [
  { label: "Overview", icon: LayoutDashboard, href: "/" },
  { label: "Time Machine", icon: Clock3, href: "/time-machine" },
  { label: "Hidden Threats", icon: Eye, href: "#" },
  { label: "Company Assets", icon: Server, href: "#" },
  { label: "Alert Activity", icon: Activity, href: "#", badge: "8" },
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
    <div className="min-h-screen bg-[#161616] text-[#f4f4f4] selection:bg-[#0f62fe] selection:text-white">
      <div className="pointer-events-none fixed inset-0 bg-[linear-gradient(135deg,rgba(15,98,254,.05),transparent_38%)]" />
      <aside className={`fixed inset-y-0 left-0 z-40 flex w-[256px] flex-col border-r border-[#393939] bg-[#161616]/98 pb-5 pt-6 backdrop-blur-xl transition-transform lg:translate-x-0 ${mobileOpen ? "translate-x-0" : "-translate-x-full"}`}>
        <div className="flex items-center justify-between px-5">
          <Link href="/" className="flex items-center gap-3" onClick={() => setMobileOpen(false)}>
            <div className="relative grid h-9 w-9 place-items-center bg-[#0f62fe] text-white"><Hexagon size={23} strokeWidth={1.4}/><Command size={11} className="absolute"/></div>
            <div><p className="text-sm font-semibold tracking-wide">SIGNAL<span className="text-[#78a9ff]">ZERO</span></p><p className="text-[10px] tracking-[.16em] text-[#8d8d8d]">IBM · THREAT INTELLIGENCE</p></div>
          </Link>
          <button className="text-[#8d8d8d] lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Close menu"><X size={20}/></button>
        </div>

        <div className="mx-4 mt-8 border-l-2 border-[#24a148] bg-[#262626] px-3 py-3"><div className="flex items-center gap-2 text-[11px] font-semibold text-[#f4f4f4]"><span className="h-2 w-2 rounded-full bg-[#24a148]"/>System operational</div><p className="mt-1 text-xs text-[#8d8d8d]">Last sync · 2 min ago</p></div>

        <nav className="mt-7"><p className="mb-2 px-5 text-[11px] font-semibold uppercase tracking-[.08em] text-[#6f6f6f]">Command center</p>{navItems.map(({ label, icon: Icon, href, badge }) => {
          const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
          return <Link key={label} href={href} onClick={() => setMobileOpen(false)} className={`relative flex h-11 items-center gap-3 px-5 text-sm transition-colors ${active ? "bg-[#262626] text-white" : "text-[#c6c6c6] hover:bg-[#262626] hover:text-white"}`}><span className={`absolute inset-y-0 left-0 w-1 ${active ? "bg-[#0f62fe]" : "bg-transparent"}`}/><Icon size={18} strokeWidth={1.6}/><span className="flex-1">{label}</span>{badge && <span className="bg-[#da1e28] px-2 py-0.5 text-[10px] font-semibold text-white">{badge}</span>}</Link>;
        })}</nav>

        <div className="mx-4 mt-auto border border-[#393939] bg-[#262626] p-3"><div className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center bg-[#001d6c] text-[#a6c8ff]"><Box size={17}/></div><div className="min-w-0"><p className="text-xs font-semibold text-[#f4f4f4]">Enterprise workspace</p><p className="truncate text-[11px] text-[#8d8d8d]">signalzero-demo</p></div><ChevronDown size={14} className="ml-auto text-[#8d8d8d]"/></div></div>
      </aside>

      <main className="relative lg:pl-[256px]">
        <header className="sticky top-0 z-30 flex h-[72px] items-center justify-between border-b border-[#393939] bg-[#161616]/92 px-5 backdrop-blur-xl sm:px-8 lg:px-10">
          <div className="flex items-center gap-3"><button className="text-[#c6c6c6] lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open menu"><Menu size={21}/></button><div><p className="text-sm font-semibold">{title}</p><p className="hidden text-xs text-[#8d8d8d] sm:block">{subtitle}</p></div></div>
          <div className="flex items-center gap-2"><span className="hidden items-center gap-2 border border-[#525252] bg-[#262626] px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-[#a6c8ff] sm:flex"><Sparkles size={13}/>Simulated data</span><button className="relative grid h-10 w-10 place-items-center border border-[#393939] text-[#a8a8a8] transition hover:bg-[#262626] hover:text-white" aria-label="Notifications"><Bell size={17}/><span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-[#da1e28]"/></button><div className="grid h-10 w-10 place-items-center bg-[#0f62fe] text-xs font-semibold text-white">SZ</div></div>
        </header>
        <div className="mx-auto max-w-[1500px] px-5 py-7 sm:px-8 lg:px-10 lg:py-9">
          <div className="mb-2 flex items-center gap-2 text-xs text-[#8d8d8d]"><span>Command center</span><span>/</span><span className="text-[#c6c6c6]">{breadcrumb}</span></div>
          {children}
        </div>
      </main>
      {mobileOpen && <button className="fixed inset-0 z-30 bg-black/70 lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Close navigation overlay"/>}
    </div>
  );
}
