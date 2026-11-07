"use client";

import { useMemo, useState } from "react";
import { ChevronsUp, Clock3, Download, Search, Server, ShieldCheck, TriangleAlert } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { fetchVulnerabilityOverview } from "@/lib/api/vulnerabilities";
import type { Priority, Vulnerability } from "@/lib/types/vulnerability";

const metrics = [
  { label: "Known vulnerabilities", value: "1,284", change: "+24 this week", icon: ShieldCheck, tone: "blue" },
  { label: "Critical priority", value: "18", change: "4 need attention", icon: TriangleAlert, tone: "red" },
  { label: "Assets exposed", value: "36", change: "Across 12 services", icon: Server, tone: "orange" },
  { label: "Prediction horizon", value: "30d", change: "Threat window", icon: Clock3, tone: "purple" },
];

const priorityStyles: Record<Priority, string> = {
  Critical: "bg-[#da1e28] text-white",
  High: "bg-[#ff832b] text-[#161616]",
  Medium: "bg-[#f1c21b] text-[#161616]",
  Low: "bg-[#525252] text-white",
};

function Score({ value, kind }: { value: number; kind: "cvss" | "epss" }) {
  const level = kind === "cvss" ? (value >= 9 ? "bg-[#da1e28]" : value >= 7 ? "bg-[#ff832b]" : "bg-[#f1c21b]") : "bg-[#0f62fe]";
  const width = kind === "cvss" ? `${value * 10}%` : `${Math.max(4, value * 100)}%`;
  return <div className="min-w-[88px]"><div className="mb-1.5 flex items-center justify-between text-xs"><span className="font-semibold text-[#161616]">{kind === "epss" ? `${Math.round(value * 100)}%` : value.toFixed(1)}</span><span className="text-[10px] uppercase tracking-wider text-[#6f6f6f]">{kind}</span></div><div className="h-1 overflow-hidden bg-[#f4f4f4]"><div className={`h-full ${level}`} style={{ width }} /></div></div>;
}

function VulnerabilityRow({ item }: { item: Vulnerability }) {
  return <tr className="border-t border-[#e0e0e0] transition-colors hover:bg-[#f4f4f4]"><td className="px-5 py-4"><div className="flex items-start gap-3"><span className={`mt-1.5 h-2 w-2 shrink-0 ${item.priority === "Critical" ? "bg-[#da1e28]" : item.priority === "High" ? "bg-[#ff832b]" : "bg-[#f1c21b]"}`} /><div><p className="font-mono text-xs font-semibold text-[#0f62fe]">{item.id}</p><p className="mt-1 max-w-[360px] text-sm font-medium text-[#161616]">{item.title}</p></div></div></td><td className="hidden px-4 py-4 lg:table-cell"><p className="text-sm text-[#161616]">{item.asset}</p><p className="mt-1 text-xs text-[#6f6f6f]">{item.service}</p></td><td className="px-4 py-4"><Score value={item.cvss} kind="cvss" /></td><td className="hidden px-4 py-4 sm:table-cell"><Score value={item.epss} kind="epss" /></td><td className="px-4 py-4"><span className={`inline-flex px-2.5 py-1 text-[11px] font-semibold ${priorityStyles[item.priority]}`}>{item.priority}</span></td><td className="hidden px-5 py-4 text-right text-xs text-[#6f6f6f] xl:table-cell">{item.detected}</td></tr>;
}

export default function Home() {
  const [query, setQuery] = useState("");
  const [priority, setPriority] = useState<"All" | Priority>("All");
  const vulnerabilities = useMemo(() => fetchVulnerabilityOverview(), []);
  const filtered = useMemo(() => vulnerabilities.filter((item) => `${item.id} ${item.title} ${item.asset} ${item.service}`.toLowerCase().includes(query.toLowerCase()) && (priority === "All" || item.priority === priority)), [query, priority, vulnerabilities]);

  return <AppShell title="Vulnerability overview" subtitle="Global environment Ã‚· Continuous monitoring" breadcrumb="Overview">
    <section className="flex flex-col justify-between gap-5 md:flex-row md:items-end"><div><h1 className="text-3xl font-light tracking-tight sm:text-4xl">Good afternoon, <span className="text-[#525252]">Analyst.</span></h1><p className="mt-3 max-w-2xl text-sm leading-6 text-[#525252]">Your attack surface at a glance. Priorities combine vulnerability severity and simulated exploitation likelihood.</p></div><button className="inline-flex h-10 items-center justify-center gap-2 bg-[#0f62fe] px-4 text-sm font-medium text-white transition hover:bg-[#0353e9]"><Download size={16}/>Export report</button></section>
    <section className="mt-8 grid gap-px bg-[#e0e0e0] sm:grid-cols-2 xl:grid-cols-4">{metrics.map(({ label, value, change, icon: Icon, tone }) => <article key={label} className="bg-white p-5"><div className="flex items-start justify-between"><p className="text-sm text-[#525252]">{label}</p><Icon size={19} className={tone === "red" ? "text-[#fa4d56]" : tone === "orange" ? "text-[#ff832b]" : tone === "purple" ? "text-[#be95ff]" : "text-[#0f62fe]"}/></div><p className="mt-6 text-3xl font-light tracking-tight">{value}</p><p className="mt-2 text-xs text-[#6f6f6f]">{change}</p></article>)}</section>
    <section className="mt-5 overflow-hidden border border-[#e0e0e0] bg-white"><div className="flex flex-col gap-4 border-b border-[#e0e0e0] p-5 xl:flex-row xl:items-center xl:justify-between"><div><div className="flex items-center gap-2"><h2 className="text-lg font-medium">Priority vulnerabilities</h2><span className="border border-[#525252] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-[#0043ce]">Simulated</span></div><p className="mt-1 text-xs text-[#6f6f6f]">Ranked by risk and projected exploit activity</p></div><div className="flex flex-col gap-2 sm:flex-row"><label className="relative min-w-[280px]"><Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6f6f6f]"/><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CVE, asset, or serviceÃ¢â‚¬Â¦" className="h-10 w-full border-b border-[#8d8d8d] bg-[#f4f4f4] pl-10 pr-3 text-sm text-[#161616] outline-none placeholder:text-[#6f6f6f] focus:border-[#0f62fe]"/></label><select value={priority} onChange={(event) => setPriority(event.target.value as "All" | Priority)} className="h-10 border-b border-[#8d8d8d] bg-[#f4f4f4] px-3 text-sm text-[#161616] outline-none"><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></div></div>
      <div className="overflow-x-auto"><table className="w-full min-w-[760px] text-left"><thead><tr className="bg-[#f4f4f4] text-[11px] font-semibold uppercase tracking-[.08em] text-[#525252]"><th className="px-5 py-3">Vulnerability</th><th className="hidden px-4 py-3 lg:table-cell">Affected asset</th><th className="px-4 py-3">CVSS score</th><th className="hidden px-4 py-3 sm:table-cell">EPSS probability</th><th className="px-4 py-3">Priority</th><th className="hidden px-5 py-3 text-right xl:table-cell">Detected</th></tr></thead><tbody>{filtered.map((item) => <VulnerabilityRow key={item.id} item={item}/>)}</tbody></table></div>
      {filtered.length === 0 && <div className="px-5 py-14 text-center"><Search className="mx-auto text-[#6f6f6f]"/><p className="mt-3 text-sm text-[#525252]">No vulnerabilities match your search.</p><button onClick={() => { setQuery(""); setPriority("All"); }} className="mt-2 text-sm text-[#0f62fe]">Clear filters</button></div>}
      <div className="flex items-center justify-between border-t border-[#e0e0e0] px-5 py-3 text-xs text-[#6f6f6f]"><span>Showing {filtered.length} of {vulnerabilities.length} prioritized findings</span><span className="hidden items-center gap-1 text-[#0f62fe] sm:flex"><ChevronsUp size={14}/>Highest risk first</span></div>
    </section>
    <p className="mt-4 text-center text-[11px] leading-5 text-[#6f6f6f]">Demo environment Ã‚· All vulnerability, asset, CVSS, EPSS, and priority data is simulated for interface development.</p>
  </AppShell>;
}
