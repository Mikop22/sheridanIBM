"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertCircle, ArrowDown, ArrowUp, CheckCircle2, ChevronRight, ExternalLink, Filter, LoaderCircle, RotateCcw, Search, X } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { isDemoMode } from "@/lib/api/config";
import { fetchAlertActivity } from "@/lib/api/alerts";
import { fetchHiddenThreats } from "@/lib/api/hidden-threats";
import type { VulnerabilityAlert } from "@/lib/types/alert";
import type { HiddenThreat, HiddenThreatRisk } from "@/lib/types/hidden-threat";

type SortKey = "modelRank" | "cvss" | "epss" | "traditionalRank";
type SortDirection = "asc" | "desc";

const riskStyles: Record<HiddenThreatRisk, string> = { Critical: "bg-[#da1e28] text-white", High: "bg-[#ff832b] text-[#161616]", Elevated: "bg-[#f1c21b] text-[#161616]", Unknown: "bg-[#f4f4f4] text-[#525252]" };
const isValidExternalUrl = (value: string | null) => value !== null && /^https?:\/\//i.test(value);

function SortButton({ label, value, active, direction, onSort }: { label: string; value: SortKey; active: boolean; direction: SortDirection; onSort: (value: SortKey) => void }) {
  return <button onClick={() => onSort(value)} className="inline-flex items-center gap-1 font-semibold uppercase tracking-[.06em] hover:text-[#0f62fe]">{label}{active && (direction === "asc" ? <ArrowUp size={12} /> : <ArrowDown size={12} />)}</button>;
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div className="border-b border-[#e0e0e0] py-3"><dt className="text-xs text-[#6f6f6f]">{label}</dt><dd className="mt-1 text-sm">{value}</dd></div>;
}

function ThreatDetails({ threat, alert, demo, onClose }: { threat: HiddenThreat; alert: VulnerabilityAlert | null; demo: boolean; onClose: () => void }) {
  const rankedHigher = threat.modelRank !== null && threat.traditionalRank !== null && threat.modelRank < threat.traditionalRank;
  return <div className="fixed inset-0 z-50 flex justify-end bg-black/35" onClick={onClose} role="presentation"><aside className="h-full w-full max-w-[620px] overflow-y-auto border-l border-[#e0e0e0] bg-white" onClick={(event) => event.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="finding-title">
    <div className="sticky top-0 z-10 flex items-center justify-between border-b border-[#e0e0e0] bg-white px-6 py-5"><div><p className="text-[11px] font-semibold uppercase tracking-[.1em] text-[#0f62fe]">Finding details</p><h2 id="finding-title" className="mt-1 font-mono text-lg font-semibold">{threat.id}</h2></div><button onClick={onClose} className="grid h-10 w-10 place-items-center hover:bg-[#f4f4f4]" aria-label="Close finding details"><X size={20} /></button></div>
    <div className="p-6">
      <div className={`mb-6 border-l-4 p-4 text-sm ${demo ? "border-[#0f62fe] bg-[#edf5ff] text-[#0043ce]" : "border-[#8d8d8d] bg-[#f4f4f4] text-[#525252]"}`}>{demo ? "Simulated finding for interface development. Scores, assets, evidence, and workflow records below are demo fixtures." : "Live backend record. Unknown fields remain explicitly unavailable."}</div>
      <span className={`inline-flex px-3 py-1 text-xs font-semibold ${riskStyles[threat.predictedRisk]}`}>{threat.predictedRisk} model prediction</span>
      <p className="mt-5 text-xl font-light leading-8">{threat.description}</p>
      {rankedHigher && <div className="mt-5 flex gap-3 border border-[#a6c8ff] bg-[#edf5ff] p-4"><CheckCircle2 className="mt-0.5 shrink-0 text-[#0f62fe]" size={18} /><p className="text-sm leading-6 text-[#0043ce]">Vigil ranks this finding #{threat.modelRank}, above its traditional baseline rank of #{threat.traditionalRank}.</p></div>}
      <dl className="mt-6 grid gap-x-6 sm:grid-cols-2"><Fact label="CVSS severity" value={threat.cvss === null ? "Unknown" : threat.cvss.toFixed(1)} /><Fact label="EPSS probability" value={threat.epss === null ? "Unknown" : `${(threat.epss * 100).toFixed(1)}%`} /><Fact label="Vigil model rank" value={threat.modelRank === null ? "Unknown" : `#${threat.modelRank}`} /><Fact label="Relative model score" value={threat.rankingScore === null ? "Unavailable" : `${threat.rankingScore} (not a probability)`} /><Fact label="Affected application" value={threat.affectedProduct ?? "Unknown"} /><Fact label="Asset match confidence" value="Unavailable — backend field not provided" /><Fact label="Repository" value="Unknown — backend field not provided" /><Fact label="Remediation status" value={alert ? alert.lifecycle : "Unavailable"} /></dl>
      <h3 className="mt-8 text-xs font-semibold uppercase tracking-[.08em] text-[#525252]">Why the model prioritized it</h3>
      {threat.signals.length > 0 ? <div className="mt-3 divide-y divide-[#e0e0e0] border-y border-[#e0e0e0]">{threat.signals.map((signal, index) => <div key={`${signal.label}-${index}`} className="py-5"><div className="flex justify-between gap-5"><p className="font-medium">{signal.label}</p><p className="text-sm font-medium text-[#0f62fe]">{signal.value}</p></div><p className="mt-2 text-sm leading-6 text-[#525252]">{signal.explanation}</p><p className="mt-2 text-xs text-[#6f6f6f]">Source: {signal.source ?? "Unknown"}{signal.observedAt ? ` · Observed ${signal.observedAt}` : ""}</p></div>)}</div> : <p className="mt-3 bg-[#f4f4f4] p-4 text-sm text-[#525252]">No grounded explanation or public exploit evidence was supplied for this finding.</p>}
      <h3 className="mt-8 text-xs font-semibold uppercase tracking-[.08em] text-[#525252]">Grounded explanation</h3><p className="mt-3 bg-[#f4f4f4] p-4 text-sm leading-6 text-[#525252]">IBM Granite explanation unavailable in this collection response. The browser does not generate a substitute.</p>
      <h3 className="mt-8 text-xs font-semibold uppercase tracking-[.08em] text-[#525252]">Remediation and integrations</h3><dl className="mt-2"><Fact label="Recommendation" value="Unavailable — no recommendation included in this response" /><Fact label="GitHub draft PR" value="Unavailable — backend field not provided" /><Fact label="Entire session / checkpoint" value="Unavailable — backend field not provided" /></dl>
      {alert && isValidExternalUrl(alert.jiraUrl) && <a href={alert.jiraUrl ?? undefined} target="_blank" rel="noreferrer" className="mt-5 inline-flex items-center gap-2 text-sm text-[#0f62fe] hover:underline">Open Jira ticket {alert.jiraKey}<ExternalLink size={14} /></a>}
    </div>
  </aside></div>;
}

export default function HiddenThreatsPage() {
  const demo = isDemoMode();
  const [threats, setThreats] = useState<HiddenThreat[]>([]);
  const [alerts, setAlerts] = useState<VulnerabilityAlert[]>([]);
  const [query, setQuery] = useState("");
  const [outsideOnly, setOutsideOnly] = useState(false);
  const [risk, setRisk] = useState<"All" | HiddenThreatRisk>("All");
  const [sortKey, setSortKey] = useState<SortKey>("modelRank");
  const [direction, setDirection] = useState<SortDirection>("asc");
  const [selected, setSelected] = useState<HiddenThreat | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requestKey, setRequestKey] = useState(0);

  useEffect(() => { let cancelled = false; Promise.all([fetchHiddenThreats(), fetchAlertActivity()]).then(([threatResponse, alertResponse]) => { if (!cancelled) { setThreats(threatResponse.threats); setAlerts(alertResponse.alerts); const findingId = new URLSearchParams(window.location.search).get("finding"); const match = threatResponse.threats.find((threat) => threat.id === findingId); if (match) setSelected(match); } }).catch((cause) => { if (!cancelled) setError(cause instanceof Error ? cause.message : "Threat intelligence could not be loaded."); }).finally(() => { if (!cancelled) setLoading(false); }); return () => { cancelled = true; }; }, [requestKey]);

  const filtered = useMemo(() => threats.filter((item) => `${item.id} ${item.description} ${item.affectedProduct ?? ""}`.toLowerCase().includes(query.toLowerCase())).filter((item) => !outsideOnly || (item.traditionalRank !== null && item.traditionalRank > 500)).filter((item) => risk === "All" || item.predictedRisk === risk).sort((a, b) => { const aValue = a[sortKey] ?? Number.MAX_SAFE_INTEGER; const bValue = b[sortKey] ?? Number.MAX_SAFE_INTEGER; return direction === "asc" ? aValue - bValue : bValue - aValue; }), [threats, query, outsideOnly, risk, sortKey, direction]);
  const alertByCve = useMemo(() => new Map(alerts.map((alert) => [alert.cveId, alert])), [alerts]);
  const divergences = threats.filter((item) => item.modelRank !== null && item.traditionalRank !== null && item.modelRank < item.traditionalRank).length;

  function handleSort(value: SortKey) { if (value === sortKey) setDirection((current) => current === "asc" ? "desc" : "asc"); else { setSortKey(value); setDirection(value === "modelRank" || value === "traditionalRank" ? "asc" : "desc"); } }
  function retry() { setLoading(true); setError(null); setRequestKey((value) => value + 1); }

  return <AppShell title="Threat intelligence" subtitle="Ranked vulnerability evidence and affected assets" breadcrumb="Threat Intelligence">
    <section className="glass-stats grid gap-3 sm:grid-cols-3"><div className="glass-stat p-5"><p className="text-sm text-[#525252]">Ranked vulnerabilities</p><p className="mt-5 text-4xl font-light">{threats.length}</p></div><div className="glass-stat p-5"><p className="text-sm text-[#525252]">Model ranked higher</p><p className="mt-5 text-4xl font-light">{divergences}</p></div><div className="glass-stat p-5"><p className="text-sm text-[#525252]">Current view</p><p className="mt-5 text-4xl font-light">{filtered.length}</p></div></section>
    <section className="mt-8 border border-[#e0e0e0]"><div className="grid gap-4 border-b border-[#e0e0e0] p-5 xl:grid-cols-[1fr_auto_auto]"><label className="relative"><span className="sr-only">Search vulnerabilities</span><Search size={17} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#525252]" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CVE, description, or asset" className="h-12 w-full border-b-2 border-[#8d8d8d] bg-[#f4f4f4] pl-10 pr-3 text-sm outline-none focus:border-[#0f62fe]" /></label><label className="flex h-12 cursor-pointer items-center gap-3 border border-[#e0e0e0] px-4 text-sm"><input type="checkbox" checked={outsideOnly} onChange={(event) => setOutsideOnly(event.target.checked)} className="h-4 w-4 accent-[#0f62fe]" /><Filter size={16} />Outside top 500 only</label><select aria-label="Filter by model risk" value={risk} onChange={(event) => setRisk(event.target.value as "All" | HiddenThreatRisk)} className="h-12 border-b-2 border-[#8d8d8d] bg-[#f4f4f4] px-4 text-sm outline-none focus:border-[#0f62fe]"><option>All</option><option>Critical</option><option>High</option><option>Elevated</option></select></div>
      {loading && <div className="grid min-h-[320px] place-items-center"><div className="text-center"><LoaderCircle className="mx-auto animate-spin text-[#0f62fe]" /><p className="mt-3 text-sm text-[#525252]">Loading threat intelligence…</p></div></div>}
      {!loading && error && <div className="grid min-h-[320px] place-items-center p-6 text-center"><div><AlertCircle className="mx-auto text-[#da1e28]" /><p className="mt-3 font-medium">Unable to load threat intelligence</p><p className="mt-2 text-sm text-[#525252]">{error}</p><button onClick={retry} className="mt-5 inline-flex h-10 items-center gap-2 bg-[#0f62fe] px-4 text-sm text-white"><RotateCcw size={15} />Retry</button></div></div>}
      {!loading && !error && <div className="overflow-x-auto"><table className="w-full min-w-[1080px] text-left"><thead><tr className="bg-[#f4f4f4] text-[11px] text-[#525252]"><th className="px-5 py-4">Vulnerability</th><th className="px-4 py-4"><SortButton label="CVSS" value="cvss" active={sortKey === "cvss"} direction={direction} onSort={handleSort} /></th><th className="px-4 py-4"><SortButton label="EPSS" value="epss" active={sortKey === "epss"} direction={direction} onSort={handleSort} /></th><th className="px-4 py-4"><SortButton label="Model rank" value="modelRank" active={sortKey === "modelRank"} direction={direction} onSort={handleSort} /></th><th className="px-4 py-4"><SortButton label="Baseline rank" value="traditionalRank" active={sortKey === "traditionalRank"} direction={direction} onSort={handleSort} /></th><th className="px-4 py-4">Affected asset</th><th className="px-4 py-4">Remediation</th><th className="w-12 px-4 py-4" /></tr></thead><tbody>{filtered.map((item) => { const rankedHigher = item.modelRank !== null && item.traditionalRank !== null && item.modelRank < item.traditionalRank; const alert = alertByCve.get(item.id); return <tr key={item.id} onClick={() => setSelected(item)} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") setSelected(item); }} className="cursor-pointer border-t border-[#e0e0e0] hover:bg-[#f4f4f4] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#0f62fe]"><td className="px-5 py-4"><p className="font-mono text-xs font-semibold text-[#0f62fe]">{item.id}</p><p className="mt-1 max-w-[360px] text-sm">{item.description}</p>{rankedHigher && <span className="mt-2 inline-flex bg-[#edf5ff] px-2 py-1 text-[10px] font-semibold uppercase text-[#0043ce]">Model ranked higher</span>}</td><td className="px-4 py-4 text-sm">{item.cvss === null ? "Unknown" : item.cvss.toFixed(1)}</td><td className="px-4 py-4 text-sm">{item.epss === null ? "Unknown" : `${Math.round(item.epss * 100)}%`}</td><td className="px-4 py-4 text-xl font-light text-[#0f62fe]">{item.modelRank === null ? <span className="text-sm text-[#6f6f6f]">Unknown</span> : `#${item.modelRank}`}</td><td className="px-4 py-4 text-sm">{item.traditionalRank === null ? <span className="text-[#6f6f6f]">Unknown</span> : `#${item.traditionalRank}`}</td><td className="px-4 py-4 text-sm">{item.affectedProduct ?? "Unknown"}</td><td className="px-4 py-4 text-sm">{alert?.lifecycle ?? "Unavailable"}</td><td className="px-4 py-4"><ChevronRight size={18} className="text-[#6f6f6f]" /></td></tr>; })}</tbody></table>{filtered.length === 0 && <div className="border-t border-[#e0e0e0] px-5 py-16 text-center"><p className="font-medium">No vulnerabilities match these filters.</p><button onClick={() => { setQuery(""); setOutsideOnly(false); setRisk("All"); }} className="mt-3 text-sm text-[#0f62fe]">Clear filters</button></div>}</div>}
    </section>
    {selected && <ThreatDetails threat={selected} alert={alertByCve.get(selected.id) ?? null} demo={demo} onClose={() => setSelected(null)} />}
  </AppShell>;
}
