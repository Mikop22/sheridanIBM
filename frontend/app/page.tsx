"use client";

import { useEffect, useState } from "react";
import {
  AlertCircle,
  GitPullRequest,
  LoaderCircle,
  RotateCcw,
  Server,
  ShieldAlert,
  Wrench,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { isDemoMode } from "@/lib/api/config";
import { fetchAlertActivity } from "@/lib/api/alerts";
import { fetchVulnerabilityOverview } from "@/lib/api/vulnerabilities";
import type { VulnerabilityAlert } from "@/lib/types/alert";
import type { OverviewSummary, Vulnerability } from "@/lib/types/vulnerability";

const formatTime = (value: string) =>
  new Intl.DateTimeFormat("en-CA", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));

function MetricCard({
  label,
  value,
  detail,
  icon: Icon,
  tone = "text-[#0f62fe]",
}: {
  label: string;
  value: number | null;
  detail: string;
  icon: typeof ShieldAlert;
  tone?: string;
}) {
  return (
    <article className="glass-stat p-5">
      <div className="flex justify-between gap-4">
        <p className="text-sm text-[#525252]">{label}</p>
        <Icon size={19} className={tone} />
      </div>
      <p className="mt-7 text-3xl font-light">
        {value === null ? (
          <span className="text-lg text-[#6f6f6f]">Unavailable</span>
        ) : (
          value.toLocaleString()
        )}
      </p>
      <p className="mt-2 text-xs text-[#6f6f6f]">{detail}</p>
    </article>
  );
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

  useEffect(() => {
    let cancelled = false;
    Promise.all([fetchVulnerabilityOverview(), fetchAlertActivity()])
      .then(([overview, activity]) => {
        if (!cancelled) {
          setVulnerabilities(overview.vulnerabilities);
          setSummary(overview.summary);
          setSource(overview.source);
          setAlerts(activity.alerts);
        }
      })
      .catch((cause) => {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : "Overview data could not be loaded.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [requestKey]);

  const noLiveAdapterData = source === "api" && vulnerabilities.length === 0 && alerts.length === 0;
  const actionable = noLiveAdapterData ? null : (summary?.totalVulnerabilities ?? vulnerabilities.length);
  const matchedAssets = noLiveAdapterData
    ? null
    : (summary?.inventoryMatches ?? vulnerabilities.filter((item) => item.asset !== null).length);
  const inProgress = noLiveAdapterData
    ? null
    : alerts.filter((alert) => alert.lifecycle === "Investigating" || alert.lifecycle === "Open").length;
  const draftPrs = noLiveAdapterData
    ? null
    : (summary?.draftPullRequests ?? alerts.filter((alert) => Boolean(alert.prUrl)).length);

  const metrics = [
    {
      label: "Model-ranked vulnerabilities",
      value: actionable,
      detail: demo ? "Simulated snapshot" : "Top predictions from the ranking model",
      icon: ShieldAlert,
      tone: "text-[#0f62fe]",
    },
    {
      label: "Inventory-matched findings",
      value: matchedAssets,
      detail: "Present in the demo asset inventory",
      icon: Server,
      tone: "text-[#da1e28]",
    },
    {
      label: "Active remediation workflows",
      value: inProgress,
      detail: "Open or investigating",
      icon: Wrench,
      tone: "text-[#8a3ffc]",
    },
    {
      label: "Draft pull requests awaiting review",
      value: draftPrs,
      detail: draftPrs !== null ? "Mikop22/securitydemo" : "",
      icon: GitPullRequest,
      tone: "text-[#0f62fe]",
    },
  ];

  return (
    <AppShell
      title="Overview"
      subtitle="Predict, prioritize, and move evidence toward human-reviewed remediation"
      breadcrumb="Overview"
    >
      {loading && (
        <div className="grid min-h-[360px] place-items-center">
          <div className="text-center">
            <LoaderCircle className="mx-auto animate-spin text-[#0f62fe]" />
            <p className="mt-3 text-sm text-[#525252]">Loading environment overview…</p>
          </div>
        </div>
      )}
      {!loading && error && (
        <div className="mt-8 grid min-h-[280px] place-items-center border border-[#e0e0e0] p-6 text-center">
          <div>
            <AlertCircle className="mx-auto text-[#da1e28]" />
            <p className="mt-3 font-medium">Overview unavailable</p>
            <p className="mt-2 max-w-lg text-sm text-[#525252]">{error}</p>
            <button
              onClick={() => {
                setLoading(true);
                setError(null);
                setRequestKey((value) => value + 1);
              }}
              className="mt-5 inline-flex h-10 items-center gap-2 bg-[#0f62fe] px-4 text-sm text-white"
            >
              <RotateCcw size={15} />
              Retry
            </button>
          </div>
        </div>
      )}
      {!loading && !error && (
        <>
          <section aria-labelledby="posture-heading">
            <div className="mb-5">
              <h1 id="posture-heading" className="text-2xl font-light">
                What needs attention now
              </h1>
            </div>
            <div className="glass-stats grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              {metrics.map((metric) => (
                <MetricCard key={metric.label} {...metric} />
              ))}
            </div>
            {noLiveAdapterData && (
              <p className="mt-3 border-l-4 border-[#8d8d8d] bg-[#f4f4f4] p-4 text-sm text-[#525252]">
                The live backend is connected, but real prediction, asset, and alert adapters are not
                configured. No demo totals have been substituted.
              </p>
            )}
          </section>

          <section className="mt-10 grid gap-8 xl:grid-cols-[1.55fr_.75fr]">
            <div className="border border-[#e0e0e0]">
              <div className="flex items-end justify-between border-b border-[#e0e0e0] p-5">
                <div>
                  <h2 className="text-xl font-light">Prioritized findings</h2>
                  <p className="mt-1 text-xs text-[#6f6f6f]">
                    Top model-ranked CVEs with vulnerability descriptions and matched assets
                  </p>
                </div>
                <a href="/hidden-threats" className="text-sm text-[#0f62fe] hover:underline">
                  View all {vulnerabilities.length}
                </a>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left">
                  <thead>
                    <tr className="bg-[#f4f4f4] text-[11px] font-semibold uppercase text-[#525252]">
                      <th className="w-20 px-4 py-3">Rank</th>
                      <th className="px-4 py-3">Finding & description</th>
                      <th className="px-4 py-3">Affected asset</th>
                      <th className="w-28 px-4 py-3">Snapshot</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vulnerabilities.slice(0, 8).map((item) => (
                      <tr key={item.id} className="border-t border-[#e0e0e0] hover:bg-[#f4f4f4]">
                        <td className="px-4 py-4 align-top">
                          <span className="text-base font-light tabular-nums text-[#0f62fe]">
                            {item.modelRank === null ? "—" : `#${item.modelRank}`}
                          </span>
                        </td>
                        <td className="px-4 py-4 align-top">
                          <a
                            href={`/hidden-threats?finding=${encodeURIComponent(item.id)}`}
                            className="font-mono text-xs font-semibold text-[#0f62fe] hover:underline"
                          >
                            {item.id}
                          </a>
                          <p className="mt-1 max-w-[580px] text-sm leading-5 text-[#161616] line-clamp-2">
                            {item.title}
                          </p>
                        </td>
                        <td className="px-4 py-4 align-top">
                          <p className="text-sm">{item.asset ?? "Not in inventory"}</p>
                          {item.service && (
                            <p className="mt-0.5 text-xs text-[#6f6f6f]">{item.service}</p>
                          )}
                        </td>
                        <td className="px-4 py-4 align-top text-sm tabular-nums text-[#525252]">
                          {item.snapshotMonth ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {vulnerabilities.length === 0 && (
                  <p className="px-5 py-14 text-center text-sm text-[#525252]">
                    No findings are available from the current data source.
                  </p>
                )}
              </div>
            </div>

            <div className="border border-[#e0e0e0]">
              <div className="flex items-end justify-between border-b border-[#e0e0e0] p-5">
                <div>
                  <h2 className="text-xl font-light">Recent remediation activity</h2>
                  <p className="mt-1 text-xs text-[#6f6f6f]">
                    Provider and analyst workflow updates
                  </p>
                </div>
                <a href="/alerts" className="text-sm text-[#0f62fe] hover:underline">
                  Open center
                </a>
              </div>
              <div className="divide-y divide-[#e0e0e0]">
                {alerts.slice(0, 5).map((alert) => (
                  <a key={alert.id} href="/alerts" className="block p-5 hover:bg-[#f4f4f4]">
                    <div className="flex justify-between gap-3">
                      <p className="font-mono text-xs font-semibold text-[#0f62fe]">{alert.cveId}</p>
                      <p className="text-xs text-[#6f6f6f]">{formatTime(alert.timestamp)}</p>
                    </div>
                    <p className="mt-2 text-sm font-normal text-[#161616]">{alert.assetName}</p>
                    <p className="mt-1 text-xs text-[#525252]">
                      {alert.lifecycle} · Slack {alert.slackStatus} · Jira {alert.jiraStatus}
                      {alert.prUrl
                        ? ` · Draft PR ${alert.prNumber ? `#${alert.prNumber}` : "open"}`
                        : ""}
                    </p>
                    {alert.prUrl && (
                      <p className="mt-1.5 font-mono text-[11px] text-[#0f62fe]">
                        {alert.repository ?? "Mikop22/securitydemo"}
                        {alert.prNumber ? `#${alert.prNumber}` : ""} awaiting review
                      </p>
                    )}
                    {alert.simulated && (
                      <p className="mt-2 text-[10px] font-semibold uppercase tracking-[.08em] text-[#6f6f6f]">
                        Simulated record
                      </p>
                    )}
                  </a>
                ))}
                {alerts.length === 0 && (
                  <p className="p-8 text-center text-sm text-[#525252]">
                    No remediation activity is available.
                  </p>
                )}
              </div>
            </div>
          </section>
        </>
      )}
    </AppShell>
  );
}
