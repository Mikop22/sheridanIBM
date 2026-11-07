"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertCircle, ChevronsUp, Clock3, Download, LoaderCircle, RotateCcw, Search, Server, ShieldCheck, TriangleAlert } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { isDemoMode } from "@/lib/api/config";
import { fetchVulnerabilityOverview } from "@/lib/api/vulnerabilities";
import type { OverviewSummary, Priority, Vulnerability } from "@/lib/types/vulnerability";
const priorityStyles: Record<Priority, string> = { Critical: "bg-[#da1e28] text-white", High: "bg-[#ff832b] text-[#161616]", Medium: "bg-[#f1c21b] text-[#161616]", Low: "bg-[#525252] text-white", Unknown: "bg-[#f4f4f4] text-[#525252]" };

function Score({ value, kind }: { value: number | null; kind: "cvss" | "epss" }) {
  if (value === null) return <span className="text-sm text-[#6f6f6f]">Not provided</span>;
  const level = kind === "cvss" ? (value >= 9 ? "bg-[#da1e28]" : value >= 7 ? "bg-[#ff832b]" : "bg-[#f1c21b]") : "bg-[#0f62fe]";
  return <div className="min-w-[88px]"><div className="mb-1.5 flex items-center justify-between text-xs"><span className="font-semibold">{kind === "epss" ? `${Math.round(value * 100)}%` : value.toFixed(1)}</span><span className="text-[10px] uppercase tracking-wider text-[#6f6f6f]">{kind}</span></div><div className="h-1 bg-[#f4f4f4]"><div className={`h-full ${level}`} style={{ width: kind === "cvss" ? `${value * 10}%` : `${Math.max(4, value * 100)}%` }}/></div></div>;
}

export default function Home() {
  const demo = isDemoMode();
  const [query, setQuery] = useState("");
  const [priority, setPriority] = useState<"All" | Priority>("All");
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [summary, setSummary] = useState<OverviewSummary | null>(null);
  const [source, setSource] = useState<"simulated" | "api" | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requestKey, setRequestKey] = useState(0);
  useEffect(() => { let cancelled = false; fetchVulnerabilityOverview().then((data) => { if (!cancelled) { setVulnerabilities(data.vulnerabilities); setSummary(data.summary); setSource(data.source); } }).catch((cause) => { if (!cancelled) setError(cause instanceof Error ? cause.message : "Overview data could not be loaded."); }).finally(() => { if (!cancelled) setLoading(false); }); return () => { cancelled = true; }; }, [requestKey]);
  const filtered = useMemo(() => vulnerabilities.filter((item) => `${item.id} ${item.title} ${item.asset} ${item.service}`.toLowerCase().includes(query.toLowerCase()) && (priority === "All" || item.priority === priority)), [query, priority, vulnerabilities]);
  const metrics = [
    { label: "Known vulnerabilities", value: summary?.totalVulnerabilities, suffix: "", change: "Current API snapshot", icon: ShieldCheck, tone: "blue" },
    { label: "Critical priority", value: summary?.criticalPriority, suffix: "", change: "Current API snapshot", icon: TriangleAlert, tone: "red" },
    { label: "Assets exposed", value: summary?.exposedAssets, suffix: "", change: "Current API snapshot", icon: Server, tone: "orange" },
    { label: "Prediction horizon", value: summary?.predictionHorizonDays, suffix: " days", change: "Threat window", icon: Clock3, tone: "purple" },
  ];

  return <AppShell title="Vulnerability overview" subtitle="Global environment · Continuous monitoring" breadcrumb="Overview">
    <section className="flex flex-col justify-between gap-5 md:flex-row md:items-end"><div><h1 className="text-3xl font-light tracking-tight sm:text-4xl">Good afternoon, <span className="text-[#525252]">Analyst.</span></h1><p className="mt-3 max-w-2xl text-sm leading-6 text-[#525252]">Your attack surface at a glance. Priorities combine vulnerability severity and exploitation likelihood signals.</p></div><button className="inline-flex h-10 items-center justify-center gap-2 bg-[#0f62fe] px-4 text-sm font-medium text-white hover:bg-[#0353e9]"><Download size={16}/>Export report</button></section>
    <section className="mt-8 grid gap-px bg-[#e0e0e0] sm:grid-cols-2 xl:grid-cols-4">{metrics.map(({ label, value, suffix, change, icon: Icon, tone }) => <article key={label} className="bg-white p-5"><div className="flex justify-between"><p className="text-sm text-[#525252]">{label}</p><Icon size={19} className={tone === "red" ? "text-[#fa4d56]" : tone === "orange" ? "text-[#ff832b]" : tone === "purple" ? "text-[#8a3ffc]" : "text-[#0f62fe]"}/></div><p className="mt-6 text-3xl font-light">{value === null || value === undefined ? <span className="text-lg text-[#6f6f6f]">Not available</span> : `${value.toLocaleString()}${suffix}`}</p><p className="mt-2 text-xs text-[#6f6f6f]">{change}</p></article>)}</section>
    <section className="mt-5 overflow-hidden border border-[#e0e0e0]"><div className="flex flex-col gap-4 border-b border-[#e0e0e0] p-5 xl:flex-row xl:items-center xl:justify-between"><div><div className="flex items-center gap-2"><h2 className="text-lg font-medium">Priority vulnerabilities</h2><span className="border border-[#525252] px-2 py-0.5 text-[10px] font-semibold uppercase text-[#0043ce]">{demo ? "Demo data" : "Live API"}</span></div><p className="mt-1 text-xs text-[#6f6f6f]">Ranked by risk and projected exploit activity</p></div><div className="flex flex-col gap-2 sm:flex-row"><label className="relative min-w-[280px]"><Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6f6f6f]"/><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CVE, asset, or service…" className="h-10 w-full border-b border-[#8d8d8d] bg-[#f4f4f4] pl-10 pr-3 text-sm outline-none focus:border-[#0f62fe]"/></label><select value={priority} onChange={(event) => setPriority(event.target.value as "All" | Priority)} className="h-10 border-b border-[#8d8d8d] bg-[#f4f4f4] px-3 text-sm"><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></div></div>
      {loading && <div className="grid min-h-[280px] place-items-center"><div className="text-center"><LoaderCircle className="mx-auto animate-spin text-[#0f62fe]"/><p className="mt-3 text-sm text-[#525252]">Loading vulnerability overview…</p></div></div>}
      {!loading && error && <div className="grid min-h-[280px] place-items-center p-6 text-center"><div><AlertCircle className="mx-auto text-[#da1e28]"/><p className="mt-3 font-medium">Overview unavailable</p><p className="mt-2 max-w-lg text-sm text-[#525252]">{error}</p><button onClick={() => { setLoading(true); setError(null); setRequestKey((value) => value + 1); }} className="mt-5 inline-flex h-10 items-center gap-2 bg-[#0f62fe] px-4 text-sm text-white"><RotateCcw size={15}/>Retry</button></div></div>}
      {!loading && !error && <><div className="overflow-x-auto"><table className="w-full min-w-[760px] text-left"><thead><tr className="bg-[#f4f4f4] text-[11px] font-semibold uppercase text-[#525252]"><th className="px-5 py-3">Vulnerability</th><th className="hidden px-4 py-3 lg:table-cell">Affected asset</th><th className="px-4 py-3">CVSS</th><th className="hidden px-4 py-3 sm:table-cell">EPSS</th><th className="px-4 py-3">Priority</th><th className="hidden px-5 py-3 text-right xl:table-cell">Detected</th></tr></thead><tbody>{filtered.map((item) => <tr key={item.id} className="border-t border-[#e0e0e0] hover:bg-[#f4f4f4]"><td className="px-5 py-4"><p className="font-mono text-xs font-semibold text-[#0f62fe]">{item.id}</p><p className="mt-1 max-w-[360px] text-sm font-medium">{item.title}</p></td><td className="hidden px-4 py-4 lg:table-cell"><p className="text-sm">{item.asset ?? "Not provided"}</p><p className="mt-1 text-xs text-[#6f6f6f]">{item.service ?? "Not provided"}</p></td><td className="px-4 py-4"><Score value={item.cvss} kind="cvss"/></td><td className="hidden px-4 py-4 sm:table-cell"><Score value={item.epss} kind="epss"/></td><td className="px-4 py-4"><span className={`px-2.5 py-1 text-xs font-semibold ${priorityStyles[item.priority]}`}>{item.priority}</span></td><td className="hidden px-5 py-4 text-right text-xs text-[#6f6f6f] xl:table-cell">{item.detected ?? "Not provided"}</td></tr>)}</tbody></table></div>{filtered.length === 0 && <div className="px-5 py-14 text-center"><Search className="mx-auto text-[#6f6f6f]"/><p className="mt-3 text-sm text-[#525252]">No vulnerabilities match your search.</p></div>}<div className="flex justify-between border-t border-[#e0e0e0] px-5 py-3 text-xs text-[#6f6f6f]"><span>Showing {filtered.length} of {vulnerabilities.length} findings</span><span className="hidden items-center gap-1 text-[#0f62fe] sm:flex"><ChevronsUp size={14}/>Highest risk first</span></div></>}
    </section>
    {(source === "simulated" || (source === null && demo)) && <p className="mt-4 text-center text-[11px] text-[#6f6f6f]">Demo environment · All vulnerability and priority data is simulated for interface development.</p>}
  </AppShell>;
}
