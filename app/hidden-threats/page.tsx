"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertCircle, ArrowDown, ArrowUp, ChevronRight, Filter, LoaderCircle, RotateCcw, Search, X } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { fetchHiddenThreats } from "@/lib/api/hidden-threats";
import type { HiddenThreat, HiddenThreatRisk } from "@/lib/types/hidden-threat";

type SortKey = "modelRank" | "cvss" | "epss" | "traditionalRank";
type SortDirection = "asc" | "desc";

const riskStyles: Record<HiddenThreatRisk, string> = {
  Critical: "bg-[#da1e28] text-white",
  High: "bg-[#ff832b] text-[#161616]",
  Elevated: "bg-[#f1c21b] text-[#161616]",
};

function SortButton({ label, value, active, direction, onSort }: { label: string; value: SortKey; active: boolean; direction: SortDirection; onSort: (value: SortKey) => void }) {
  return <button onClick={() => onSort(value)} className="inline-flex items-center gap-1 font-semibold uppercase tracking-[.06em] hover:text-[#0f62fe]">{label}{active && (direction === "asc" ? <ArrowUp size={12}/> : <ArrowDown size={12}/>)}</button>;
}

function ThreatDetails({ threat, onClose }: { threat: HiddenThreat; onClose: () => void }) {
  return <div className="fixed inset-0 z-50 flex justify-end bg-black/35" onClick={onClose} role="presentation"><aside className="h-full w-full max-w-[520px] overflow-y-auto border-l border-[#e0e0e0] bg-white" onClick={(event) => event.stopPropagation()} aria-label={`${threat.id} details`}><div className="sticky top-0 flex items-center justify-between border-b border-[#e0e0e0] bg-white px-6 py-5"><div><p className="font-mono text-sm font-semibold text-[#0f62fe]">{threat.id}</p><p className="mt-1 text-xs text-[#525252]">Model rank #{threat.modelRank}</p></div><button onClick={onClose} className="grid h-10 w-10 place-items-center hover:bg-[#f4f4f4]" aria-label="Close details"><X size={20}/></button></div><div className="p-6"><span className={`inline-flex px-3 py-1 text-xs font-semibold ${riskStyles[threat.predictedRisk]}`}>{threat.predictedRisk} predicted risk</span><h2 className="mt-5 text-2xl font-light leading-8">{threat.description}</h2><p className="mt-3 text-sm text-[#525252]">Affected product · {threat.affectedProduct}</p><div className="mt-7 grid grid-cols-2 border-y border-[#e0e0e0]"><div className="border-r border-[#e0e0e0] py-5 pr-5"><p className="text-xs text-[#525252]">Model rank</p><p className="mt-2 text-3xl font-light text-[#0f62fe]">#{threat.modelRank}</p></div><div className="py-5 pl-5"><p className="text-xs text-[#525252]">Traditional rank</p><p className="mt-2 text-3xl font-light">{threat.traditionalRank ? `#${threat.traditionalRank}` : "Missing"}</p></div></div><h3 className="mt-8 text-xs font-semibold uppercase tracking-[.08em] text-[#525252]">Why this threat surfaced</h3><div className="mt-3 divide-y divide-[#e0e0e0] border-y border-[#e0e0e0]">{threat.signals.map((signal) => <div key={signal.label} className="py-5"><div className="flex justify-between gap-5"><p className="font-medium">{signal.label}</p><p className="text-sm font-medium text-[#0f62fe]">{signal.value}</p></div><p className="mt-2 text-sm leading-6 text-[#525252]">{signal.explanation}</p></div>)}</div><div className="mt-8 border-l-4 border-[#0f62fe] bg-[#edf5ff] p-4 text-sm leading-6 text-[#0043ce]">Simulated explanation for interface development. These signals are not production model outputs.</div></div></aside></div>;
}

export default function HiddenThreatsPage() {
  const [threats, setThreats] = useState<HiddenThreat[]>([]);
  const [query, setQuery] = useState("");
  const [outsideOnly, setOutsideOnly] = useState(true);
  const [risk, setRisk] = useState<"All" | HiddenThreatRisk>("All");
  const [sortKey, setSortKey] = useState<SortKey>("modelRank");
  const [direction, setDirection] = useState<SortDirection>("asc");
  const [selected, setSelected] = useState<HiddenThreat | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requestKey, setRequestKey] = useState(0);

  useEffect(() => { let cancelled = false; fetchHiddenThreats().then((response) => { if (!cancelled) setThreats(response.threats); }).catch(() => { if (!cancelled) setError("Hidden-threat data could not be loaded."); }).finally(() => { if (!cancelled) setLoading(false); }); return () => { cancelled = true; }; }, [requestKey]);

  const filtered = useMemo(() => threats.filter((item) => `${item.id} ${item.description} ${item.affectedProduct}`.toLowerCase().includes(query.toLowerCase())).filter((item) => !outsideOnly || item.traditionalRank === null || item.traditionalRank > 500).filter((item) => risk === "All" || item.predictedRisk === risk).sort((a, b) => { const aValue = a[sortKey] ?? Number.MAX_SAFE_INTEGER; const bValue = b[sortKey] ?? Number.MAX_SAFE_INTEGER; return direction === "asc" ? aValue - bValue : bValue - aValue; }), [threats, query, outsideOnly, risk, sortKey, direction]);

  function handleSort(value: SortKey) { if (value === sortKey) setDirection((current) => current === "asc" ? "desc" : "asc"); else { setSortKey(value); setDirection(value === "modelRank" || value === "traditionalRank" ? "asc" : "desc"); } }
  function retry() { setLoading(true); setError(null); setRequestKey((value) => value + 1); }

  return <AppShell title="Hidden Threats" subtitle="Vulnerabilities missed by conventional ranking" breadcrumb="Hidden Threats"><section className="grid gap-8 border-b border-[#e0e0e0] pb-10 lg:grid-cols-[1.2fr_.8fr]"><div><p className="mb-4 text-sm font-medium text-[#0f62fe]">Feature B · Discovery</p><h1 className="max-w-4xl text-4xl font-light leading-[1.08] tracking-tight sm:text-6xl">Find the risks traditional rankings leave behind.</h1></div><div className="self-end"><p className="max-w-xl text-base leading-7 text-[#525252]">Compare contextual model ranking with CVSS- and EPSS-led ordering to surface vulnerabilities outside conventional top-500 lists.</p><p className="mt-4 text-xs font-medium uppercase tracking-[.08em] text-[#6f6f6f]">Simulated predictions · Not production results</p></div></section>

    <section className="mt-8 grid gap-px bg-[#e0e0e0] sm:grid-cols-3"><div className="bg-[#f4f4f4] p-5"><p className="text-sm text-[#525252]">Threats reviewed</p><p className="mt-5 text-4xl font-light">{threats.length}</p></div><div className="bg-[#f4f4f4] p-5"><p className="text-sm text-[#525252]">Outside traditional top 500</p><p className="mt-5 text-4xl font-light">{threats.filter((item) => item.traditionalRank === null || item.traditionalRank > 500).length}</p></div><div className="bg-[#f4f4f4] p-5"><p className="text-sm text-[#525252]">Current view</p><p className="mt-5 text-4xl font-light">{filtered.length}</p></div></section>

    <section className="mt-8 border border-[#e0e0e0]"><div className="grid gap-4 border-b border-[#e0e0e0] p-5 xl:grid-cols-[1fr_auto_auto]"><label className="relative"><Search size={17} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#525252]"/><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CVE, description, or product" className="h-12 w-full border-b-2 border-[#8d8d8d] bg-[#f4f4f4] pl-10 pr-3 text-sm outline-none focus:border-[#0f62fe]"/></label><label className="flex h-12 cursor-pointer items-center gap-3 border border-[#e0e0e0] px-4 text-sm"><input type="checkbox" checked={outsideOnly} onChange={(event) => setOutsideOnly(event.target.checked)} className="h-4 w-4 accent-[#0f62fe]"/><Filter size={16}/>Outside top 500 only</label><select value={risk} onChange={(event) => setRisk(event.target.value as "All" | HiddenThreatRisk)} className="h-12 border-b-2 border-[#8d8d8d] bg-[#f4f4f4] px-4 text-sm outline-none focus:border-[#0f62fe]"><option>All</option><option>Critical</option><option>High</option><option>Elevated</option></select></div>

      {loading && <div className="grid min-h-[320px] place-items-center"><div className="text-center"><LoaderCircle className="mx-auto animate-spin text-[#0f62fe]"/><p className="mt-3 text-sm text-[#525252]">Loading simulated threat rankings…</p></div></div>}
      {!loading && error && <div className="grid min-h-[320px] place-items-center p-6 text-center"><div><AlertCircle className="mx-auto text-[#da1e28]"/><p className="mt-3 font-medium">Unable to load hidden threats</p><p className="mt-2 text-sm text-[#525252]">{error}</p><button onClick={retry} className="mt-5 inline-flex h-10 items-center gap-2 bg-[#0f62fe] px-4 text-sm text-white"><RotateCcw size={15}/>Retry</button></div></div>}
      {!loading && !error && <div className="overflow-x-auto"><table className="w-full min-w-[980px] text-left"><thead><tr className="bg-[#f4f4f4] text-[11px] text-[#525252]"><th className="px-5 py-4">Vulnerability</th><th className="px-4 py-4"><SortButton label="CVSS" value="cvss" active={sortKey === "cvss"} direction={direction} onSort={handleSort}/></th><th className="px-4 py-4"><SortButton label="EPSS" value="epss" active={sortKey === "epss"} direction={direction} onSort={handleSort}/></th><th className="px-4 py-4"><SortButton label="Model rank" value="modelRank" active={sortKey === "modelRank"} direction={direction} onSort={handleSort}/></th><th className="px-4 py-4"><SortButton label="Traditional rank" value="traditionalRank" active={sortKey === "traditionalRank"} direction={direction} onSort={handleSort}/></th><th className="px-4 py-4">Predicted risk</th><th className="w-12 px-4 py-4"/></tr></thead><tbody>{filtered.map((item) => <tr key={item.id} onClick={() => setSelected(item)} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") setSelected(item); }} className="cursor-pointer border-t border-[#e0e0e0] hover:bg-[#f4f4f4]"><td className="px-5 py-4"><p className="font-mono text-xs font-semibold text-[#0f62fe]">{item.id}</p><p className="mt-1 max-w-[430px] text-sm">{item.description}</p><p className="mt-1 text-xs text-[#6f6f6f]">{item.affectedProduct}</p></td><td className="px-4 py-4 text-sm">{item.cvss.toFixed(1)}</td><td className="px-4 py-4 text-sm">{Math.round(item.epss * 100)}%</td><td className="px-4 py-4 text-xl font-light text-[#0f62fe]">#{item.modelRank}</td><td className="px-4 py-4 text-sm">{item.traditionalRank ? `#${item.traditionalRank}` : <span className="text-[#6f6f6f]">Missing</span>}</td><td className="px-4 py-4"><span className={`inline-flex px-2.5 py-1 text-xs font-semibold ${riskStyles[item.predictedRisk]}`}>{item.predictedRisk}</span></td><td className="px-4 py-4"><ChevronRight size={18} className="text-[#6f6f6f]"/></td></tr>)}</tbody></table>{filtered.length === 0 && <div className="border-t border-[#e0e0e0] px-5 py-16 text-center"><p className="font-medium">No hidden threats match these filters.</p><button onClick={() => { setQuery(""); setOutsideOnly(false); setRisk("All"); }} className="mt-3 text-sm text-[#0f62fe]">Clear filters</button></div>}</div>}
    </section>
    {selected && <ThreatDetails threat={selected} onClose={() => setSelected(null)}/>} 
  </AppShell>;
}
