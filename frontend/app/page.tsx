"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  ChevronsUp,
  Download,
  Layers3,
  LoaderCircle,
  RotateCcw,
  Search,
  Server,
  ShieldCheck,
  Trophy,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { isDemoMode } from "@/lib/api/config";
import { fetchVulnerabilityOverview } from "@/lib/api/vulnerabilities";
import type { OverviewSummary, Vulnerability } from "@/lib/types/vulnerability";

function RankingScore({ value, kind }: { value: number | null; kind: "relative" | "unknown" }) {
  if (value === null) return <span className="text-sm text-[#6f6f6f]">Not provided</span>;
  const pct = Math.max(4, Math.min(100, value * 100));
  return (
    <div className="min-w-[104px]">
      <div className="mb-1.5 flex items-center justify-between gap-2 text-xs">
        <span className="font-semibold tabular-nums">{value.toFixed(4)}</span>
        <span className="text-[10px] uppercase tracking-wider text-[#6f6f6f]">
          {kind === "relative" ? "relative" : "score"}
        </span>
      </div>
      <div className="h-1 bg-[#f4f4f4]">
        <div className="h-full bg-[#0f62fe]" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export default function Home() {
  const demo = isDemoMode();
  const [query, setQuery] = useState("");
  const [matchFilter, setMatchFilter] = useState<"All" | "Matched" | "Unmatched">("All");
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [summary, setSummary] = useState<OverviewSummary | null>(null);
  const [source, setSource] = useState<"simulated" | "api" | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requestKey, setRequestKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    fetchVulnerabilityOverview()
      .then((data) => {
        if (!cancelled) {
          setVulnerabilities(data.vulnerabilities);
          setSummary(data.summary);
          setSource(data.source);
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

  const filtered = useMemo(
    () =>
      vulnerabilities
        .filter((item) =>
          `${item.id} ${item.title} ${item.asset ?? ""} ${item.service ?? ""} ${item.snapshotMonth ?? ""}`
            .toLowerCase()
            .includes(query.toLowerCase()),
        )
        .filter((item) => {
          if (matchFilter === "Matched") return item.asset !== null;
          if (matchFilter === "Unmatched") return item.asset === null;
          return true;
        })
        .sort((a, b) => {
          if (a.modelRank === null && b.modelRank === null) return a.id.localeCompare(b.id);
          if (a.modelRank === null) return 1;
          if (b.modelRank === null) return -1;
          return a.modelRank - b.modelRank;
        }),
    [query, matchFilter, vulnerabilities],
  );

  const metrics = [
    {
      label: "Ranked vulnerabilities",
      value: summary?.totalVulnerabilities,
      change: "Member 1 artifact rows",
      icon: ShieldCheck,
      tone: "blue",
    },
    {
      label: "Inventory matches",
      value: summary?.inventoryMatches,
      change: "Synthetic demo inventory",
      icon: Server,
      tone: "orange",
    },
    {
      label: "Top model rank",
      value: summary?.topModelRank,
      change: "Highest SignalZero priority",
      icon: Trophy,
      tone: "red",
    },
    {
      label: "Score semantics",
      value: null,
      display: "Relative",
      change: "Not an exploitation probability",
      icon: Layers3,
      tone: "purple",
    },
  ] as const;

  return (
    <AppShell
      title="Vulnerability overview"
      subtitle="Global environment · Continuous monitoring"
      breadcrumb="Overview"
    >
      <section className="flex flex-col justify-between gap-5 md:flex-row md:items-end">
        <div>
          <h1 className="text-3xl font-light tracking-tight sm:text-4xl">
            Good afternoon, <span className="text-[#525252]">Analyst.</span>
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-[#525252]">
            SignalZero ranks CVEs with a relative ensemble score. CVSS, EPSS, and Critical/High labels
            are not invented here when the artifact does not supply them.
          </p>
        </div>
        <button className="inline-flex h-10 items-center justify-center gap-2 bg-[#0f62fe] px-4 text-sm font-medium text-white hover:bg-[#0353e9]">
          <Download size={16} />
          Export report
        </button>
      </section>

      <section className="mt-8 grid gap-px bg-[#e0e0e0] sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map(({ label, value, change, icon: Icon, tone, ...rest }) => {
          const display = "display" in rest ? rest.display : null;
          return (
            <article key={label} className="bg-white p-5">
              <div className="flex justify-between">
                <p className="text-sm text-[#525252]">{label}</p>
                <Icon
                  size={19}
                  className={
                    tone === "red"
                      ? "text-[#fa4d56]"
                      : tone === "orange"
                        ? "text-[#ff832b]"
                        : tone === "purple"
                          ? "text-[#8a3ffc]"
                          : "text-[#0f62fe]"
                  }
                />
              </div>
              <p className="mt-6 text-3xl font-light">
                {display !== null ? (
                  display
                ) : value === null || value === undefined ? (
                  <span className="text-lg text-[#6f6f6f]">Not available</span>
                ) : (
                  value.toLocaleString()
                )}
              </p>
              <p className="mt-2 text-xs text-[#6f6f6f]">{change}</p>
            </article>
          );
        })}
      </section>

      <section className="mt-5 overflow-hidden border border-[#e0e0e0]">
        <div className="flex flex-col gap-4 border-b border-[#e0e0e0] p-5 xl:flex-row xl:items-center xl:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-medium">Model-ranked vulnerabilities</h2>
              <span className="border border-[#525252] px-2 py-0.5 text-[10px] font-semibold uppercase text-[#0043ce]">
                {demo ? "Demo data" : "Live API"}
              </span>
            </div>
            <p className="mt-1 text-xs text-[#6f6f6f]">
              Ordered by SignalZero model rank · Ranking score is relative, not calibrated risk
            </p>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <label className="relative min-w-[280px]">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6f6f6f]" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search CVE, asset, or product…"
                className="h-10 w-full border-b border-[#8d8d8d] bg-[#f4f4f4] pl-10 pr-3 text-sm outline-none focus:border-[#0f62fe]"
              />
            </label>
            <select
              value={matchFilter}
              onChange={(event) => setMatchFilter(event.target.value as "All" | "Matched" | "Unmatched")}
              className="h-10 border-b border-[#8d8d8d] bg-[#f4f4f4] px-3 text-sm"
            >
              <option value="All">All inventory states</option>
              <option value="Matched">Inventory matched</option>
              <option value="Unmatched">No inventory match</option>
            </select>
          </div>
        </div>

        {loading && (
          <div className="grid min-h-[280px] place-items-center">
            <div className="text-center">
              <LoaderCircle className="mx-auto animate-spin text-[#0f62fe]" />
              <p className="mt-3 text-sm text-[#525252]">Loading vulnerability overview…</p>
            </div>
          </div>
        )}

        {!loading && error && (
          <div className="grid min-h-[280px] place-items-center p-6 text-center">
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
            <div className="overflow-x-auto">
              <table className="w-full min-w-[860px] text-left">
                <thead>
                  <tr className="bg-[#f4f4f4] text-[11px] font-semibold uppercase text-[#525252]">
                    <th className="px-5 py-3">Model rank</th>
                    <th className="px-4 py-3">Vulnerability</th>
                    <th className="hidden px-4 py-3 lg:table-cell">Affected asset</th>
                    <th className="px-4 py-3">Ranking score</th>
                    <th className="hidden px-4 py-3 sm:table-cell">Snapshot</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((item) => (
                    <tr key={item.id} className="border-t border-[#e0e0e0] hover:bg-[#f4f4f4]">
                      <td className="px-5 py-4">
                        <span className="text-lg font-light tabular-nums text-[#0f62fe]">
                          {item.modelRank ?? "—"}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        <p className="font-mono text-xs font-semibold text-[#0f62fe]">{item.id}</p>
                        <p className="mt-1 max-w-[420px] text-sm leading-5 text-[#525252] line-clamp-2">
                          {item.title}
                        </p>
                      </td>
                      <td className="hidden px-4 py-4 lg:table-cell">
                        <p className="text-sm">{item.asset ?? "No inventory match"}</p>
                        <p className="mt-1 text-xs text-[#6f6f6f]">{item.service ?? "—"}</p>
                      </td>
                      <td className="px-4 py-4">
                        <RankingScore value={item.rankingScore} kind={item.rankingScoreKind} />
                      </td>
                      <td className="hidden px-4 py-4 text-sm tabular-nums text-[#525252] sm:table-cell">
                        {item.snapshotMonth ?? "Not provided"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {filtered.length === 0 && (
              <div className="px-5 py-14 text-center">
                <Search className="mx-auto text-[#6f6f6f]" />
                <p className="mt-3 text-sm text-[#525252]">No vulnerabilities match your search.</p>
              </div>
            )}
            <div className="flex justify-between border-t border-[#e0e0e0] px-5 py-3 text-xs text-[#6f6f6f]">
              <span>
                Showing {filtered.length} of {vulnerabilities.length} ranked findings
              </span>
              <span className="hidden items-center gap-1 text-[#0f62fe] sm:flex">
                <ChevronsUp size={14} />
                Lowest model rank first
              </span>
            </div>
          </>
        )}
      </section>

      {(source === "simulated" || (source === null && demo)) && (
        <p className="mt-4 text-center text-[11px] text-[#6f6f6f]">
          Demo environment · Vulnerability fixtures are simulated for interface development.
        </p>
      )}
    </AppShell>
  );
}
