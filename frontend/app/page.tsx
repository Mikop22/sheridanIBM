"use client";

import { useEffect, useState } from "react";
import { AlertCircle, GitPullRequest, LoaderCircle, RotateCcw, ShieldAlert, Siren, Wrench } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { isDemoMode } from "@/lib/api/config";
import { fetchAlertActivity } from "@/lib/api/alerts";
import { fetchVulnerabilityOverview } from "@/lib/api/vulnerabilities";
import type { VulnerabilityAlert } from "@/lib/types/alert";
import type { OverviewSummary, Priority, Vulnerability } from "@/lib/types/vulnerability";

const priorityStyles: Record<Priority, string> = { Critical: "bg-[#da1e28] text-white", High: "bg-[#ff832b] text-[#161616]", Medium: "bg-[#f1c21b] text-[#161616]", Low: "bg-[#525252] text-white", Unknown: "bg-[#f4f4f4] text-[#525252]" };
const formatTime = (value: string) => new Intl.DateTimeFormat("en-CA", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value));

function MetricCard({ label, value, detail, icon: Icon, tone = "text-[#0f62fe]" }: { label: string; value: number | null; detail: string; icon: typeof ShieldAlert; tone?: string }) {
  return <article className="glass-stat p-5"><div className="flex justify-between gap-4"><p className="text-sm text-[#525252]">{label}</p><Icon size={19} className={tone} /></div><p className="mt-7 text-3xl font-light">{value === null ? <span className="text-lg text-[#6f6f6f]">Unavailable</span> : value.toLocaleString()}</p><p className="mt-2 text-xs text-[#6f6f6f]">{detail}</p></article>;
}

export default function Home() {
  const demo = isDemoMode();
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [alerts, setAlerts] = useState<VulnerabilityAlert[]>([]);
  const [summary, setSummary] = useState<OverviewSummary | null>(null);
  const [source, setSource] = useState<"simulated" | "api" | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requestKey, setRequestKey] = useState(0);

  useEffect(() => { let cancelled = false; Promise.all([fetchVulnerabilityOverview(), fetchAlertActivity()]).then(([overview, activity]) => { if (!cancelled) { setVulnerabilities(overview.vulnerabilities); setSummary(overview.summary); setSource(overview.source); setAlerts(activity.alerts); } }).catch((cause) => { if (!cancelled) setError(cause instanceof Error ? cause.message : "Overview data could not be loaded."); }).finally(() => { if (!cancelled) setLoading(false); }); return () => { cancelled = true; }; }, [requestKey]);

  const noLiveAdapterData = source === "api" && vulnerabilities.length === 0 && alerts.length === 0;
  const actionable = noLiveAdapterData ? null : vulnerabilities.length;
  const urgent = noLiveAdapterData ? summary?.criticalPriority ?? null : vulnerabilities.filter((item) => item.priority === "Critical" || item.priority === "High").length;
  const inProgress = noLiveAdapterData ? null : alerts.filter((alert) => alert.lifecycle === "Investigating").length;
  const metrics = [
    { label: "Actionable vulnerabilities \& Prioritized findings", value: actionable, detail: demo ? "" : "Current backend collection", icon: ShieldAlert, tone: "text-[#0f62fe]" },
    { label: "Urgent findings", value: urgent, detail: "", icon: Siren, tone: "text-[#da1e28]" },
    { label: "Remediations in progress", value: inProgress, detail: "", icon: Wrench, tone: "text-[#8a3ffc]" },
    { label: "Draft pull requests awaiting review", value: null, detail: "", icon: GitPullRequest, tone: "text-[#525252]" },
  ];

  return <AppShell title="Overview" subtitle="Predict, prioritize, and move evidence toward human-reviewed remediation" breadcrumb="Overview">
    {loading && <div className="grid min-h-[360px] place-items-center"><div className="text-center"><LoaderCircle className="mx-auto animate-spin text-[#0f62fe]" /><p className="mt-3 text-sm text-[#525252]">Loading environment overview…</p></div></div>}
    {!loading && error && <div className="mt-8 grid min-h-[280px] place-items-center border border-[#e0e0e0] p-6 text-center"><div><AlertCircle className="mx-auto text-[#da1e28]" /><p className="mt-3 font-medium">Overview unavailable</p><p className="mt-2 max-w-lg text-sm text-[#525252]">{error}</p><button onClick={() => { setLoading(true); setError(null); setRequestKey((value) => value + 1); }} className="mt-5 inline-flex h-10 items-center gap-2 bg-[#0f62fe] px-4 text-sm text-white"><RotateCcw size={15} />Retry</button></div></div>}
    {!loading && !error && <>
      <section aria-labelledby="posture-heading"><div className="mb-5"><p className="text-xs font-semibold uppercase tracking-[.1em] text-[#0f62fe]">Current posture</p><h1 id="posture-heading" className="mt-2 text-2xl font-light">What needs attention now</h1></div><div className="glass-stats grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{metrics.map((metric) => <MetricCard key={metric.label} {...metric} />)}</div>{noLiveAdapterData && <p className="mt-3 border-l-4 border-[#8d8d8d] bg-[#f4f4f4] p-4 text-sm text-[#525252]">The live backend is connected, but real prediction, asset, and alert adapters are not configured. No demo totals have been substituted.</p>}</section>
      <section className="mt-10 grid gap-8 xl:grid-cols-[1.5fr_.8fr]">
        <div className="border border-[#e0e0e0]"><div className="flex items-end justify-between border-b border-[#e0e0e0] p-5"><div><h2 className="text-lg font-medium">Prioritized findings</h2><p className="mt-1 text-xs text-[#6f6f6f]">Compact view of the current ranking snapshot</p></div><a href="/hidden-threats" className="text-sm text-[#0f62fe] hover:underline">View all</a></div><div className="overflow-x-auto"><table className="w-full min-w-[680px] text-left"><thead><tr className="bg-[#f4f4f4] text-[11px] font-semibold uppercase text-[#525252]"><th className="px-5 py-3">Finding</th><th className="px-4 py-3">Asset</th><th className="px-4 py-3">CVSS</th><th className="px-4 py-3">EPSS</th><th className="px-4 py-3">Priority</th></tr></thead><tbody>{vulnerabilities.slice(0, 5).map((item) => <tr key={item.id} className="border-t border-[#e0e0e0]"><td className="px-5 py-4"><a href={`/hidden-threats?finding=${encodeURIComponent(item.id)}`} className="font-mono text-xs font-semibold text-[#0f62fe] hover:underline">{item.id}</a><p className="mt-1 max-w-[330px] text-sm">{item.title}</p></td><td className="px-4 py-4 text-sm">{item.asset ?? "Unknown"}</td><td className="px-4 py-4 text-sm">{item.cvss === null ? "Unknown" : item.cvss.toFixed(1)}</td><td className="px-4 py-4 text-sm">{item.epss === null ? "Unknown" : `${Math.round(item.epss * 100)}%`}</td><td className="px-4 py-4"><span className={`px-2.5 py-1 text-xs font-semibold ${priorityStyles[item.priority]}`}>{item.priority}</span></td></tr>)}</tbody></table>{vulnerabilities.length === 0 && <p className="px-5 py-14 text-center text-sm text-[#525252]">No findings are available from the current data source.</p>}</div></div>
        <div className="border border-[#e0e0e0]"><div className="flex items-end justify-between border-b border-[#e0e0e0] p-5"><div><h2 className="text-lg font-medium">Recent remediation activity</h2><p className="mt-1 text-xs text-[#6f6f6f]">Provider and analyst workflow updates</p></div><a href="/alerts" className="text-sm text-[#0f62fe] hover:underline">Open center</a></div><div className="divide-y divide-[#e0e0e0]">{alerts.slice(0, 5).map((alert) => <a key={alert.id} href="/alerts" className="block p-5 hover:bg-[#f4f4f4]"><div className="flex justify-between gap-3"><p className="font-mono text-xs font-semibold text-[#0f62fe]">{alert.cveId}</p><p className="text-xs text-[#6f6f6f]">{formatTime(alert.timestamp)}</p></div><p className="mt-2 text-sm font-medium">{alert.assetName}</p><p className="mt-1 text-xs text-[#525252]">{alert.lifecycle} · Slack {alert.slackStatus} · Jira {alert.jiraStatus}</p>{alert.simulated && <p className="mt-2 text-[10px] font-semibold uppercase tracking-[.08em] text-[#6f6f6f]">Simulated record</p>}</a>)}{alerts.length === 0 && <p className="p-8 text-center text-sm text-[#525252]">No remediation activity is available.</p>}</div></div>
      </section>
    </>}
  </AppShell>;
}
