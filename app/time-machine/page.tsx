"use client";

import { useEffect, useState } from "react";
import { AlertCircle, ArrowRight, Check, ChevronRight, CircleHelp, Clock3, Eye, EyeOff, LoaderCircle, RotateCcw, ShieldAlert, X } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { fetchHistoricalSnapshot } from "@/lib/api/time-machine";
import { historicalMonths } from "@/lib/data/mock-time-machine";
import type { HistoricalSnapshot, HistoricalVulnerability, RiskLevel } from "@/lib/types/time-machine";

const riskStyles: Record<RiskLevel, string> = {
  Critical: "bg-[#da1e28] text-white",
  High: "bg-[#ff832b] text-[#161616]",
  Elevated: "bg-[#f1c21b] text-[#161616]",
  Moderate: "bg-[#525252] text-white",
};

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" }).format(new Date(`${value}T00:00:00Z`));
}

function OutcomeBadge({ item, revealed }: { item: HistoricalVulnerability; revealed: boolean }) {
  if (!revealed) return <span className="inline-flex items-center gap-1.5 text-xs text-[#6f6f6f]"><EyeOff size={14}/>Hidden</span>;
  if (item.outcome === "confirmed-kev") return <span className="inline-flex items-center gap-1.5 bg-[#044317] px-2.5 py-1 text-xs font-medium text-[#198038]"><Check size={14}/>KEV · {item.kevAddedDate ? formatDate(item.kevAddedDate) : "Confirmed"}</span>;
  if (item.outcome === "missing") return <span className="inline-flex items-center gap-1.5 border border-[#6f6f6f] px-2.5 py-1 text-xs text-[#525252]"><CircleHelp size={14}/>Outcome unavailable</span>;
  return <span className="inline-flex items-center gap-1.5 bg-[#f4f4f4] px-2.5 py-1 text-xs text-[#525252]"><X size={13}/>Not in KEV by cutoff</span>;
}

function DetailPanel({ item, snapshot, onClose }: { item: HistoricalVulnerability; snapshot: HistoricalSnapshot; onClose: () => void }) {
  return <div className="fixed inset-0 z-50 flex justify-end bg-black/50" onClick={onClose} role="presentation"><aside className="h-full w-full max-w-[520px] overflow-y-auto border-l border-[#525252] bg-white shadow-2xl" onClick={(event) => event.stopPropagation()} aria-label={`${item.id} risk details`}>
    <div className="sticky top-0 flex items-center justify-between border-b border-[#e0e0e0] bg-white/95 px-6 py-5 backdrop-blur"><div><p className="font-mono text-sm font-semibold text-[#0f62fe]">{item.id}</p><p className="mt-1 text-xs text-[#6f6f6f]">Historical rank #{item.modelRank}</p></div><button onClick={onClose} className="grid h-10 w-10 place-items-center text-[#525252] transition hover:bg-white" aria-label="Close details"><X size={20}/></button></div>
    <div className="p-6"><span className={`inline-flex px-3 py-1 text-xs font-semibold ${riskStyles[item.predictedRisk]}`}>{item.predictedRisk} predicted risk</span><h2 className="mt-5 text-2xl font-light leading-8">{item.description}</h2><div className="mt-6 grid grid-cols-2 gap-px bg-[#f4f4f4]"><div className="bg-white p-4"><p className="text-xs text-[#6f6f6f]">CVSS at snapshot</p><p className="mt-2 text-2xl font-light">{item.cvss?.toFixed(1) ?? "—"}</p></div><div className="bg-white p-4"><p className="text-xs text-[#6f6f6f]">EPSS at snapshot</p><p className="mt-2 text-2xl font-light">{item.epss === null ? "Missing" : `${Math.round(item.epss * 100)}%`}</p></div></div>
      <div className="mt-8"><p className="text-xs font-semibold uppercase tracking-[.08em] text-[#525252]">Risk signals available by {formatDate(snapshot.predictionCutoff)}</p><div className="mt-3 divide-y divide-[#e0e0e0] border-y border-[#e0e0e0]">{item.signals.map((signal) => <div key={signal.label} className="py-4"><div className="flex items-center justify-between gap-4"><p className="text-sm font-medium">{signal.label}</p><span className="text-sm text-[#0f62fe]">{signal.value}</span></div><p className="mt-2 text-sm leading-6 text-[#525252]">{signal.detail}</p></div>)}</div></div>
      <div className="mt-8 border-l-2 border-[#0f62fe] bg-white p-4"><p className="text-sm font-medium">Temporal integrity</p><p className="mt-2 text-sm leading-6 text-[#525252]">Only signals available on or before the prediction cutoff are represented. Confirmed outcomes are evaluated separately through {formatDate(snapshot.evaluationCutoff)}.</p></div>
    </div>
  </aside></div>;
}

function LoadingState() {
  return <div className="mt-6 grid min-h-[360px] place-items-center border border-[#e0e0e0] bg-white"><div className="text-center"><LoaderCircle className="mx-auto animate-spin text-[#0f62fe]"/><p className="mt-3 text-sm text-[#525252]">Loading historical snapshot…</p><p className="mt-1 text-xs text-[#6f6f6f]">Reconstructing signals available at the selected cutoff</p></div></div>;
}

export default function TimeMachinePage() {
  const [month, setMonth] = useState("2025-12");
  const [snapshot, setSnapshot] = useState<HistoricalSnapshot | null>(null);
  const [selected, setSelected] = useState<HistoricalVulnerability | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requestKey, setRequestKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    fetchHistoricalSnapshot(month).then((data) => { if (!cancelled) setSnapshot(data); }).catch((cause) => { if (!cancelled) setError(cause instanceof Error ? cause.message : "The historical snapshot could not be loaded."); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [month, requestKey]);

  function changeMonth(nextMonth: string) {
    setMonth(nextMonth);
    setLoading(true);
    setError(null);
    setRevealed(false);
    setSelected(null);
  }

  function retry() {
    setLoading(true);
    setError(null);
    setRequestKey((value) => value + 1);
  }

  return <AppShell title="Vulnerability Time Machine" subtitle="Historical prediction replay · Temporal evaluation" breadcrumb="Time Machine">
    <section className="flex flex-col justify-between gap-6 md:flex-row md:items-end"><div><div className="mb-4 inline-flex items-center gap-2 bg-[#edf5ff] px-3 py-1.5 text-xs text-[#0043ce]"><Clock3 size={14}/>Historical replay</div><h1 className="max-w-3xl text-3xl font-light tracking-tight sm:text-5xl">Travel back. Rank threats <span className="text-[#0f62fe]">before they break.</span></h1><p className="mt-4 max-w-2xl text-sm leading-6 text-[#525252]">Freeze the data at a historical cutoff, inspect what the model would have prioritized, then reveal only the outcomes known by the evaluation window.</p></div><div className="min-w-[220px]"><label htmlFor="month-select" className="mb-2 block text-xs font-semibold uppercase tracking-[.08em] text-[#525252]">Historical snapshot</label><select id="month-select" value={month} onChange={(event) => changeMonth(event.target.value)} className="h-12 w-full border-b-2 border-[#0f62fe] bg-[#f4f4f4] px-4 text-sm text-[#161616] outline-none">{historicalMonths.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select></div></section>

    <section className="mt-8 border-y border-[#e0e0e0] bg-white px-4 py-5 sm:px-6"><div className="mb-4 flex items-center justify-between"><div><p className="text-sm font-medium">Snapshot timeline</p><p className="mt-1 text-xs text-[#6f6f6f]">January 2024 — December 2025</p></div><span className="hidden text-xs text-[#0043ce] sm:block">24 monthly checkpoints</span></div><div className="scrollbar-thin overflow-x-auto pb-2"><div className="relative flex min-w-[1040px] items-center justify-between pt-3 before:absolute before:left-3 before:right-3 before:top-[23px] before:h-px before:bg-[#525252]">{historicalMonths.map((item, index) => <button key={item.value} onClick={() => changeMonth(item.value)} className="group relative z-10 flex w-10 flex-col items-center" aria-label={`Select ${item.label}`}><span className={`h-5 w-5 border-4 transition-colors ${month === item.value ? "border-[#0f62fe] bg-[#0f62fe]" : "border-white bg-[#8d8d8d] group-hover:bg-[#525252]"}`}/><span className={`mt-3 text-[10px] ${month === item.value ? "font-semibold text-white" : "text-[#6f6f6f]"}`}>{item.shortLabel}</span>{index % 12 === 0 && <span className="mt-1 text-[10px] text-[#0f62fe]">{item.value.slice(0, 4)}</span>}</button>)}</div></div></section>

    {loading && <LoadingState/>}
    {!loading && error && <div className="mt-6 grid min-h-[300px] place-items-center border border-[#da1e28] bg-white p-6 text-center"><div><AlertCircle className="mx-auto text-[#fa4d56]"/><p className="mt-3 font-medium">Historical data unavailable</p><p className="mt-2 text-sm text-[#525252]">{error}</p><button onClick={retry} className="mt-5 inline-flex h-10 items-center gap-2 bg-[#0f62fe] px-4 text-sm font-medium text-white hover:bg-[#0353e9]"><RotateCcw size={15}/>Retry</button></div></div>}
    {!loading && !error && snapshot && snapshot.vulnerabilities.length === 0 && <div className="mt-6 grid min-h-[300px] place-items-center border border-[#e0e0e0] bg-white p-6 text-center"><div><ShieldAlert className="mx-auto text-[#6f6f6f]"/><p className="mt-3 font-medium">No predictions for this snapshot</p><p className="mt-2 text-sm text-[#525252]">The backend returned a valid snapshot without ranked vulnerabilities.</p></div></div>}

    {!loading && !error && snapshot && snapshot.vulnerabilities.length > 0 && <>
      <section className="mt-6 grid gap-px bg-[#f4f4f4] md:grid-cols-3"><div className="bg-white p-5"><p className="text-xs text-[#6f6f6f]">Prediction snapshot</p><p className="mt-2 text-lg font-light">{formatDate(snapshot.predictionCutoff)}</p><p className="mt-2 text-xs text-[#0043ce]">Features frozen at this date</p></div><div className="bg-white p-5"><p className="text-xs text-[#6f6f6f]">Evaluation cutoff</p><p className="mt-2 text-lg font-light">{formatDate(snapshot.evaluationCutoff)}</p><p className="mt-2 text-xs text-[#198038]">Outcomes observed only through here</p></div><div className="bg-white p-5"><p className="text-xs text-[#6f6f6f]">Data status</p><p className="mt-2 text-lg font-light">{snapshot.source === "simulated" ? "Simulated replay" : "Live API replay"}</p><p className="mt-2 text-xs text-[#8e6a00]">{snapshot.source === "simulated" ? "Not a production model result" : "Validated backend response"}</p></div></section>

      <section className="mt-5 overflow-hidden border border-[#e0e0e0] bg-white"><div className="flex flex-col gap-4 border-b border-[#e0e0e0] p-5 md:flex-row md:items-center md:justify-between"><div><div className="flex items-center gap-2"><h2 className="text-lg font-medium">Ranked vulnerabilities</h2><span className="border border-[#525252] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-[#0043ce]">{snapshot.source === "simulated" ? "Simulated predictions" : "Live predictions"}</span></div><p className="mt-1 text-xs text-[#6f6f6f]">Click any row to inspect the signals available at prediction time.</p></div><button onClick={() => setRevealed((value) => !value)} className={`inline-flex h-10 items-center justify-center gap-2 px-4 text-sm font-medium transition ${revealed ? "border border-[#6f6f6f] text-[#161616] hover:bg-[#f4f4f4]" : "bg-[#0f62fe] text-white hover:bg-[#0353e9]"}`}>{revealed ? <EyeOff size={16}/> : <Eye size={16}/>} {revealed ? "Hide outcomes" : "Reveal outcomes"}</button></div>
        {revealed && <div className="border-b border-[#e0e0e0] bg-[#edf5ff] px-5 py-3 text-xs leading-5 text-[#0043ce]">Confirmed outcomes are simulated and limited to information available by <strong>{formatDate(snapshot.evaluationCutoff)}</strong>. They were not used as predictive features.</div>}
        <div className="overflow-x-auto"><table className="w-full min-w-[900px] text-left"><thead><tr className="bg-[#f4f4f4] text-[11px] font-semibold uppercase tracking-[.08em] text-[#525252]"><th className="w-16 px-5 py-3">Rank</th><th className="px-4 py-3">Vulnerability</th><th className="px-4 py-3">CVSS</th><th className="px-4 py-3">EPSS</th><th className="px-4 py-3">Predicted risk</th><th className="px-4 py-3">Outcome</th><th className="w-12 px-4 py-3"/></tr></thead><tbody>{snapshot.vulnerabilities.map((item) => <tr key={item.id} onClick={() => setSelected(item)} className="cursor-pointer border-t border-[#e0e0e0] transition-colors hover:bg-[#f4f4f4]" tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") setSelected(item); }}><td className="px-5 py-4 text-xl font-light text-[#0f62fe]">{String(item.modelRank).padStart(2, "0")}</td><td className="px-4 py-4"><p className="font-mono text-xs font-semibold text-[#0f62fe]">{item.id}</p><p className="mt-1 max-w-[430px] text-sm text-[#161616]">{item.description}</p></td><td className="px-4 py-4 text-sm">{item.cvss?.toFixed(1) ?? <span className="text-[#6f6f6f]">Missing</span>}</td><td className="px-4 py-4 text-sm">{item.epss === null ? <span className="text-[#8e6a00]">Missing</span> : `${Math.round(item.epss * 100)}%`}</td><td className="px-4 py-4"><span className={`inline-flex px-2.5 py-1 text-xs font-semibold ${riskStyles[item.predictedRisk]}`}>{item.predictedRisk}</span></td><td className="px-4 py-4"><OutcomeBadge item={item} revealed={revealed}/></td><td className="px-4 py-4"><ChevronRight size={18} className="text-[#6f6f6f]"/></td></tr>)}</tbody></table></div>
      </section>

      <section className="mt-5 grid gap-5 xl:grid-cols-[1.35fr_.65fr]"><div className="border border-[#e0e0e0] bg-white p-5 sm:p-6"><div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><h2 className="text-lg font-medium">Historical Hits@500 comparison</h2><p className="mt-1 text-xs text-[#6f6f6f]">How many subsequently confirmed items appeared in each method’s top 500.</p></div><span className="bg-[#f1c21b] px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-[#161616]">{snapshot.source === "simulated" ? "Demo values only" : "Backend evaluation"}</span></div><div className="mt-7 space-y-6">{snapshot.metrics.map((metric) => { const max = Math.max(...snapshot.metrics.map((item) => item.hitsAt500 ?? 0)); const width = metric.hitsAt500 === null || max === 0 ? 0 : (metric.hitsAt500 / max) * 100; return <div key={metric.method}><div className="mb-2 flex items-center justify-between gap-4"><div><p className="text-sm font-medium">{metric.method}</p><p className="mt-1 text-xs text-[#6f6f6f]">{metric.note}</p></div><span className="text-2xl font-light">{metric.hitsAt500 ?? "—"}</span></div><div className="h-2 bg-[#f4f4f4]"><div className={`h-full ${metric.method === "SignalZero" ? "bg-[#0f62fe]" : "bg-[#8d8d8d]"}`} style={{ width: `${width}%` }}/></div></div>; })}</div><p className="mt-6 border-l-2 border-[#f1c21b] pl-3 text-xs leading-5 text-[#525252]">These simulated figures demonstrate the comparison layout only. They are not claims about model performance and must be replaced with evaluation data from the ML pipeline.</p></div>
        <div className="border border-[#e0e0e0] bg-white p-6"><p className="text-xs font-semibold uppercase tracking-[.08em] text-[#525252]">Reading the replay</p><div className="mt-5 space-y-5"><div className="flex gap-3"><span className="mt-1 h-3 w-3 shrink-0 bg-[#0f62fe]"/><div><p className="text-sm font-medium">Prediction</p><p className="mt-1 text-xs leading-5 text-[#525252]">Rank and risk computed from features frozen at the snapshot cutoff.</p></div></div><div className="flex gap-3"><span className="mt-1 h-3 w-3 shrink-0 bg-[#24a148]"/><div><p className="text-sm font-medium">Confirmed outcome</p><p className="mt-1 text-xs leading-5 text-[#525252]">KEV status observed only by the evaluation cutoff.</p></div></div><div className="flex gap-3"><span className="mt-1 h-3 w-3 shrink-0 border border-[#f1c21b]"/><div><p className="text-sm font-medium">Missing information</p><p className="mt-1 text-xs leading-5 text-[#525252]">Unavailable fields remain explicit and are never silently imputed in the UI.</p></div></div></div><button onClick={() => setSelected(snapshot.vulnerabilities[0])} className="mt-7 inline-flex items-center gap-2 text-sm font-medium text-[#0f62fe] hover:text-[#0043ce]">Explore the top-ranked signals <ArrowRight size={16}/></button></div></section>
    </>}
    {selected && snapshot && <DetailPanel item={selected} snapshot={snapshot} onClose={() => setSelected(null)}/>} 
  </AppShell>;
}
