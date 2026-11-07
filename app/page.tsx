"use client";

import { useMemo, useState } from "react";
import { Activity, Bell, Box, ChevronDown, ChevronsUp, Clock3, Command, Download, Eye, Hexagon, LayoutDashboard, Menu, Search, Server, ShieldCheck, Sparkles, TriangleAlert, X } from "lucide-react";
import { fetchVulnerabilityOverview } from "@/lib/api/vulnerabilities";
import type { Priority, Vulnerability } from "@/lib/types/vulnerability";

const navItems = [
  { label: "Overview", icon: LayoutDashboard, active: true },
  { label: "Time Machine", icon: Clock3 },
  { label: "Hidden Threats", icon: Eye },
  { label: "Company Assets", icon: Server },
  { label: "Alert Activity", icon: Activity, badge: "8" },
];

const metrics = [
  { label: "Known vulnerabilities", value: "1,284", change: "+24 this week", icon: ShieldCheck, tone: "cyan" },
  { label: "Critical priority", value: "18", change: "4 need attention", icon: TriangleAlert, tone: "red" },
  { label: "Assets exposed", value: "36", change: "Across 12 services", icon: Server, tone: "amber" },
  { label: "Prediction horizon", value: "30d", change: "Threat window", icon: Clock3, tone: "violet" },
];

const priorityStyles: Record<Priority, string> = {
  Critical: "border-rose-400/25 bg-rose-400/10 text-rose-300",
  High: "border-orange-400/25 bg-orange-400/10 text-orange-300",
  Medium: "border-amber-400/25 bg-amber-400/10 text-amber-300",
  Low: "border-slate-400/20 bg-slate-400/10 text-slate-300",
};

function Score({ value, kind }: { value: number; kind: "cvss" | "epss" }) {
  const level = kind === "cvss" ? (value >= 9 ? "bg-rose-400" : value >= 7 ? "bg-orange-400" : "bg-amber-400") : "bg-cyan-400";
  const width = kind === "cvss" ? `${value * 10}%` : `${Math.max(4, value * 100)}%`;
  return (
    <div className="min-w-[88px]">
      <div className="mb-1.5 flex items-center justify-between text-xs">
        <span className="font-semibold text-slate-200">{kind === "epss" ? `${Math.round(value * 100)}%` : value.toFixed(1)}</span>
        <span className="text-[10px] uppercase tracking-wider text-slate-600">{kind}</span>
      </div>
      <div className="h-1 overflow-hidden rounded-full bg-white/6"><div className={`h-full rounded-full ${level}`} style={{ width }} /></div>
    </div>
  );
}

function VulnerabilityRow({ item }: { item: Vulnerability }) {
  return (
    <tr className="border-t border-white/[0.06] transition hover:bg-white/[0.025]">
      <td className="px-5 py-4"><div className="flex items-start gap-3"><span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${item.priority === "Critical" ? "bg-rose-400 shadow-[0_0_12px_#fb7185]" : item.priority === "High" ? "bg-orange-400" : "bg-amber-400"}`} /><div><p className="font-mono text-xs font-semibold text-cyan-300">{item.id}</p><p className="mt-1 max-w-[360px] text-sm font-medium text-slate-200">{item.title}</p></div></div></td>
      <td className="hidden px-4 py-4 lg:table-cell"><p className="text-sm text-slate-300">{item.asset}</p><p className="mt-1 text-xs text-slate-600">{item.service}</p></td>
      <td className="px-4 py-4"><Score value={item.cvss} kind="cvss" /></td>
      <td className="hidden px-4 py-4 sm:table-cell"><Score value={item.epss} kind="epss" /></td>
      <td className="px-4 py-4"><span className={`inline-flex rounded-md border px-2.5 py-1 text-[11px] font-semibold ${priorityStyles[item.priority]}`}>{item.priority}</span></td>
      <td className="hidden px-5 py-4 text-right text-xs text-slate-500 xl:table-cell">{item.detected}</td>
    </tr>
  );
}

export default function Home() {
  const [query, setQuery] = useState("");
  const [priority, setPriority] = useState<"All" | Priority>("All");
  const [mobileOpen, setMobileOpen] = useState(false);
  const vulnerabilities = useMemo(() => fetchVulnerabilityOverview(), []);
  const filtered = useMemo(() => vulnerabilities.filter((item) => {
    const matches = `${item.id} ${item.title} ${item.asset} ${item.service}`.toLowerCase().includes(query.toLowerCase());
    return matches && (priority === "All" || item.priority === priority);
  }), [query, priority, vulnerabilities]);

  return (
    <div className="min-h-screen bg-[#070a10] text-slate-100 selection:bg-cyan-300 selection:text-slate-950">
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(circle_at_70%_-10%,rgba(34,211,238,.09),transparent_32%),radial-gradient(circle_at_15%_80%,rgba(99,102,241,.06),transparent_28%)]" />
      <aside className={`fixed inset-y-0 left-0 z-40 flex w-[246px] flex-col border-r border-white/[0.07] bg-[#090d15]/95 px-4 pb-5 pt-6 backdrop-blur-xl transition-transform lg:translate-x-0 ${mobileOpen ? "translate-x-0" : "-translate-x-full"}`}>
        <div className="flex items-center justify-between px-2">
          <div className="flex items-center gap-3"><div className="relative grid h-9 w-9 place-items-center rounded-xl border border-cyan-300/30 bg-cyan-300/10 text-cyan-300"><Hexagon size={22} strokeWidth={1.5}/><Command size={11} className="absolute"/></div><div><p className="text-sm font-bold tracking-wide">SIGNAL<span className="text-cyan-300">ZERO</span></p><p className="text-[9px] uppercase tracking-[.22em] text-slate-600">Threat intelligence</p></div></div>
          <button className="text-slate-500 lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Close menu"><X size={20}/></button>
        </div>
        <div className="mt-8 rounded-xl border border-cyan-300/15 bg-cyan-300/[0.04] p-3"><div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-widest text-cyan-300"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-300"/>System operational</div><p className="mt-2 text-xs text-slate-500">Last sync · 2 min ago</p></div>
        <nav className="mt-7 space-y-1"><p className="mb-3 px-3 text-[9px] font-bold uppercase tracking-[.2em] text-slate-700">Command center</p>{navItems.map(({ label, icon: Icon, active, badge }) => <button key={label} className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition ${active ? "border border-cyan-300/15 bg-cyan-300/[0.07] text-cyan-200" : "border border-transparent text-slate-500 hover:bg-white/[0.03] hover:text-slate-300"}`} onClick={() => setMobileOpen(false)}><Icon size={17} strokeWidth={1.7}/><span className="flex-1">{label}</span>{badge && <span className="rounded-full bg-rose-400/15 px-2 py-0.5 text-[10px] font-bold text-rose-300">{badge}</span>}</button>)}</nav>
        <div className="mt-auto rounded-xl border border-white/[0.07] bg-white/[0.025] p-3"><div className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center rounded-lg bg-indigo-400/10 text-indigo-300"><Box size={17}/></div><div className="min-w-0"><p className="text-xs font-semibold text-slate-300">Enterprise workspace</p><p className="truncate text-[10px] text-slate-600">signalzero-demo</p></div><ChevronDown size={14} className="ml-auto text-slate-600"/></div></div>
      </aside>

      <main className="relative lg:pl-[246px]">
        <header className="sticky top-0 z-30 flex h-[70px] items-center justify-between border-b border-white/[0.07] bg-[#070a10]/80 px-5 backdrop-blur-xl sm:px-7 lg:px-10">
          <div className="flex items-center gap-3"><button className="text-slate-400 lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open menu"><Menu size={21}/></button><div><p className="text-sm font-semibold">Vulnerability overview</p><p className="hidden text-xs text-slate-600 sm:block">Saturday, November 7 · Global environment</p></div></div>
          <div className="flex items-center gap-2"><span className="hidden items-center gap-2 rounded-lg border border-amber-300/15 bg-amber-300/[0.05] px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-amber-200 sm:flex"><Sparkles size={13}/>Simulated data</span><button className="relative grid h-9 w-9 place-items-center rounded-lg border border-white/[0.08] text-slate-500 hover:text-slate-200" aria-label="Notifications"><Bell size={17}/><span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-rose-400"/></button><div className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-to-br from-cyan-300 to-indigo-400 text-xs font-black text-slate-950">SZ</div></div>
        </header>
        <div className="mx-auto max-w-[1500px] px-5 py-7 sm:px-7 lg:px-10 lg:py-9">
          <section className="flex flex-col justify-between gap-5 md:flex-row md:items-end"><div><div className="mb-2 flex items-center gap-2 text-xs text-slate-600"><span>Command center</span><span>/</span><span className="text-slate-400">Overview</span></div><h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">Good afternoon, <span className="text-slate-500">Analyst.</span></h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">Your attack surface at a glance. Priorities combine vulnerability severity and simulated exploitation likelihood.</p></div><button className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-white/[0.09] bg-white/[0.03] px-4 text-xs font-semibold text-slate-300 transition hover:bg-white/[0.06]"><Download size={15}/>Export report</button></section>

          <section className="mt-7 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{metrics.map(({ label, value, change, icon: Icon, tone }) => <article key={label} className="relative overflow-hidden rounded-xl border border-white/[0.07] bg-[#0c111b] p-5"><div className={`absolute -right-8 -top-10 h-28 w-28 rounded-full blur-3xl ${tone === "red" ? "bg-rose-500/10" : tone === "amber" ? "bg-amber-500/10" : tone === "violet" ? "bg-indigo-500/10" : "bg-cyan-500/10"}`}/><div className="flex items-start justify-between"><p className="text-xs font-medium text-slate-500">{label}</p><Icon size={17} className={tone === "red" ? "text-rose-400" : tone === "amber" ? "text-amber-400" : tone === "violet" ? "text-indigo-400" : "text-cyan-400"}/></div><p className="mt-5 text-3xl font-semibold tracking-tight">{value}</p><p className="mt-2 text-[11px] text-slate-600">{change}</p></article>)}</section>

          <section className="mt-5 overflow-hidden rounded-xl border border-white/[0.07] bg-[#0c111b]">
            <div className="flex flex-col gap-4 border-b border-white/[0.07] p-5 xl:flex-row xl:items-center xl:justify-between"><div><div className="flex items-center gap-2"><h2 className="font-semibold">Priority vulnerabilities</h2><span className="rounded border border-white/[0.08] bg-white/[0.04] px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-slate-500">Simulated</span></div><p className="mt-1 text-xs text-slate-600">Ranked by risk and projected exploit activity</p></div><div className="flex flex-col gap-2 sm:flex-row"><label className="relative min-w-[280px]"><Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600"/><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CVE, asset, or service…" className="h-10 w-full rounded-lg border border-white/[0.08] bg-[#080c13] pl-9 pr-3 text-xs text-slate-200 outline-none placeholder:text-slate-700 focus:border-cyan-300/30"/></label><select value={priority} onChange={(event) => setPriority(event.target.value as "All" | Priority)} className="h-10 rounded-lg border border-white/[0.08] bg-[#080c13] px-3 text-xs text-slate-400 outline-none"><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></div></div>
            <div className="overflow-x-auto"><table className="w-full min-w-[760px] text-left"><thead><tr className="text-[9px] font-bold uppercase tracking-[.16em] text-slate-700"><th className="px-5 py-3">Vulnerability</th><th className="hidden px-4 py-3 lg:table-cell">Affected asset</th><th className="px-4 py-3">CVSS score</th><th className="hidden px-4 py-3 sm:table-cell">EPSS probability</th><th className="px-4 py-3">Priority</th><th className="hidden px-5 py-3 text-right xl:table-cell">Detected</th></tr></thead><tbody>{filtered.map((item) => <VulnerabilityRow key={item.id} item={item}/>)}</tbody></table></div>
            {filtered.length === 0 && <div className="px-5 py-14 text-center"><Search className="mx-auto text-slate-700"/><p className="mt-3 text-sm text-slate-400">No vulnerabilities match your search.</p><button onClick={() => { setQuery(""); setPriority("All"); }} className="mt-2 text-xs text-cyan-300">Clear filters</button></div>}
            <div className="flex items-center justify-between border-t border-white/[0.07] px-5 py-3 text-[11px] text-slate-600"><span>Showing {filtered.length} of {vulnerabilities.length} prioritized findings</span><span className="hidden items-center gap-1 text-cyan-300 sm:flex"><ChevronsUp size={13}/>Highest risk first</span></div>
          </section>
          <p className="mt-4 text-center text-[10px] leading-5 text-slate-700">Demo environment · All vulnerability, asset, CVSS, EPSS, and priority data shown here is simulated for interface development.</p>
        </div>
      </main>
      {mobileOpen && <button className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Close navigation overlay"/>}
    </div>
  );
}
