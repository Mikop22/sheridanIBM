"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  ArrowDown,
  ArrowUp,
  CheckCircle2,
  ChevronRight,
  ExternalLink,
  LoaderCircle,
  RotateCcw,
  Search,
  X,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { isDemoMode } from "@/lib/api/config";
import { fetchAlertActivity } from "@/lib/api/alerts";
import { fetchHiddenThreats } from "@/lib/api/hidden-threats";
import type { VulnerabilityAlert } from "@/lib/types/alert";
import type { HiddenThreat } from "@/lib/types/hidden-threat";

type SortKey = "modelRank" | "rankingScore";
type SortDirection = "asc" | "desc";

const isValidExternalUrl = (value: string | null) => value !== null && /^https?:\/\//i.test(value);

function SortButton({
  label,
  value,
  active,
  direction,
  onSort,
}: {
  label: string;
  value: SortKey;
  active: boolean;
  direction: SortDirection;
  onSort: (value: SortKey) => void;
}) {
  return (
    <button
      onClick={() => onSort(value)}
      className="inline-flex items-center gap-1 font-semibold uppercase tracking-[.06em] hover:text-[#0f62fe]"
    >
      {label}
      {active && (direction === "asc" ? <ArrowUp size={12} /> : <ArrowDown size={12} />)}
    </button>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-b border-[#e0e0e0] py-3">
      <dt className="text-xs text-[#6f6f6f]">{label}</dt>
      <dd className="mt-1 text-sm">{value}</dd>
    </div>
  );
}

function usefulSignals(threat: HiddenThreat) {
  return threat.signals.filter((signal) => {
    if (signal.status === "unknown") return false;
    if (signal.value === "Unknown" || signal.value === "null") return false;
    if (/no causal contribution/i.test(signal.explanation)) return false;
    if (/not included in the prediction artifact/i.test(signal.explanation)) return false;
    return true;
  });
}

function ThreatDetails({
  threat,
  alert,
  demo,
  onClose,
}: {
  threat: HiddenThreat;
  alert: VulnerabilityAlert | null;
  demo: boolean;
  onClose: () => void;
}) {
  const rankedHigher =
    threat.modelRank !== null &&
    threat.traditionalRank !== null &&
    threat.modelRank < threat.traditionalRank;
  const signals = usefulSignals(threat);
  const facts: { label: string; value: string }[] = [];
  if (threat.modelRank !== null) facts.push({ label: "Vigil model rank", value: `#${threat.modelRank}` });
  if (threat.rankingScore !== null) {
    facts.push({
      label: "Relative model score",
      value: `${threat.rankingScore} (ranking score, not a probability)`,
    });
  }
  if (threat.cvss !== null) facts.push({ label: "CVSS severity", value: threat.cvss.toFixed(1) });
  if (threat.epss !== null) {
    facts.push({ label: "EPSS probability", value: `${(threat.epss * 100).toFixed(1)}%` });
  }
  if (threat.affectedProduct) facts.push({ label: "Affected asset", value: threat.affectedProduct });
  if (threat.affectedService) facts.push({ label: "Service", value: threat.affectedService });
  if (alert?.repository) facts.push({ label: "Repository", value: alert.repository });
  if (alert) facts.push({ label: "Remediation status", value: alert.lifecycle });

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/35"
      onClick={onClose}
      role="presentation"
    >
      <aside
        className="h-full w-full max-w-[620px] overflow-y-auto border-l border-[#e0e0e0] bg-white"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-title"
      >
        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-[#e0e0e0] bg-white px-6 py-5">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[.1em] text-[#0f62fe]">
              Finding details
            </p>
            <h2 id="finding-title" className="mt-1 font-mono text-lg font-semibold">
              {threat.id}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="grid h-10 w-10 place-items-center hover:bg-[#f4f4f4]"
            aria-label="Close finding details"
          >
            <X size={20} />
          </button>
        </div>
        <div className="p-6">
          {demo && (
            <div className="mb-6 border-l-4 border-[#0f62fe] bg-[#edf5ff] p-4 text-sm text-[#0043ce]">
              Simulated finding for interface development. Scores, assets, evidence, and workflow
              records below are demo fixtures.
            </div>
          )}
          {threat.modelRank !== null ? (
            <span className="inline-flex bg-[#edf5ff] px-3 py-1 text-xs font-semibold text-[#0043ce]">
              Model rank #{threat.modelRank}
            </span>
          ) : null}
          <p className="mt-5 text-xl font-light leading-8">{threat.description}</p>
          {rankedHigher && (
            <div className="mt-5 flex gap-3 border border-[#a6c8ff] bg-[#edf5ff] p-4">
              <CheckCircle2 className="mt-0.5 shrink-0 text-[#0f62fe]" size={18} />
              <p className="text-sm leading-6 text-[#0043ce]">
                Vigil ranks this finding #{threat.modelRank}, above its traditional baseline rank of
                #{threat.traditionalRank}.
              </p>
            </div>
          )}
          {facts.length > 0 && (
            <dl className="mt-6 grid gap-x-6 sm:grid-cols-2">
              {facts.map((fact) => (
                <Fact key={fact.label} label={fact.label} value={fact.value} />
              ))}
            </dl>
          )}
          {signals.length > 0 && (
            <>
              <h3 className="mt-8 text-xs font-semibold uppercase tracking-[.08em] text-[#525252]">
                Ranking signals
              </h3>
              <div className="mt-3 divide-y divide-[#e0e0e0] border-y border-[#e0e0e0]">
                {signals.slice(0, 4).map((signal, index) => (
                  <div key={`${signal.label}-${index}`} className="py-5">
                    <div className="flex justify-between gap-5">
                      <p className="font-medium">{signal.label}</p>
                      <p className="text-sm font-medium text-[#0f62fe]">{signal.value}</p>
                    </div>
                    {signal.source && (
                      <p className="mt-2 text-xs text-[#6f6f6f]">Source: {signal.source}</p>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
          {(alert?.prUrl || isValidExternalUrl(alert?.jiraUrl ?? null)) && (
            <>
              <h3 className="mt-8 text-xs font-semibold uppercase tracking-[.08em] text-[#525252]">
                Remediation links
              </h3>
              <div className="mt-3 space-y-3">
                {alert?.prUrl && (
                  <a
                    href={alert.prUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-between border border-[#a6c8ff] bg-[#edf5ff] px-4 py-3 text-sm text-[#0043ce] hover:underline"
                  >
                    <span>
                      Draft GitHub PR
                      {alert.prNumber ? ` #${alert.prNumber}` : ""}
                      {alert.prTitle ? ` · ${alert.prTitle}` : ""}
                    </span>
                    <ExternalLink size={14} />
                  </a>
                )}
                {alert && isValidExternalUrl(alert.jiraUrl) && (
                  <a
                    href={alert.jiraUrl ?? undefined}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-2 text-sm text-[#0f62fe] hover:underline"
                  >
                    Open Jira ticket {alert.jiraKey}
                    <ExternalLink size={14} />
                  </a>
                )}
              </div>
            </>
          )}
          {!alert && (
            <p className="mt-8 text-sm leading-6 text-[#525252]">
              Not matched to an inventory asset yet — no remediation workflow has been opened for
              this CVE.
            </p>
          )}
        </div>
      </aside>
    </div>
  );
}

export default function HiddenThreatsPage() {
  const demo = isDemoMode();
  const [threats, setThreats] = useState<HiddenThreat[]>([]);
  const [alerts, setAlerts] = useState<VulnerabilityAlert[]>([]);
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("modelRank");
  const [direction, setDirection] = useState<SortDirection>("asc");
  const [selected, setSelected] = useState<HiddenThreat | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requestKey, setRequestKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    Promise.all([fetchHiddenThreats(), fetchAlertActivity()])
      .then(([threatResponse, alertResponse]) => {
        if (!cancelled) {
          setThreats(threatResponse.threats);
          setAlerts(alertResponse.alerts);
          const findingId = new URLSearchParams(window.location.search).get("finding");
          const match = threatResponse.threats.find((threat) => threat.id === findingId);
          if (match) setSelected(match);
        }
      })
      .catch((cause) => {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : "Threat intelligence could not be loaded.");
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
      threats
        .filter((item) =>
          `${item.id} ${item.description} ${item.affectedProduct ?? ""}`
            .toLowerCase()
            .includes(query.toLowerCase()),
        )
        .sort((a, b) => {
          const aValue = a[sortKey] ?? Number.MAX_SAFE_INTEGER;
          const bValue = b[sortKey] ?? Number.MAX_SAFE_INTEGER;
          return direction === "asc" ? aValue - bValue : bValue - aValue;
        }),
    [threats, query, sortKey, direction],
  );
  const alertByCve = useMemo(() => new Map(alerts.map((alert) => [alert.cveId, alert])), [alerts]);
  const inventoryMatches = threats.filter((item) => item.affectedProduct !== null).length;

  function handleSort(value: SortKey) {
    if (value === sortKey) setDirection((current) => (current === "asc" ? "desc" : "asc"));
    else {
      setSortKey(value);
      setDirection(value === "modelRank" ? "asc" : "desc");
    }
  }

  function retry() {
    setLoading(true);
    setError(null);
    setRequestKey((value) => value + 1);
  }

  return (
    <AppShell
      title="Threat intelligence"
      subtitle="Ranked vulnerability evidence and affected assets"
      breadcrumb="Threat Intelligence"
    >
      <section className="glass-stats grid gap-3 sm:grid-cols-3">
        <div className="glass-stat p-5">
          <p className="text-sm text-[#525252]">Ranked vulnerabilities</p>
          <p className="mt-5 text-4xl font-light">{threats.length}</p>
        </div>
        <div className="glass-stat p-5">
          <p className="text-sm text-[#525252]">Inventory matches</p>
          <p className="mt-5 text-4xl font-light">{inventoryMatches}</p>
        </div>
        <div className="glass-stat p-5">
          <p className="text-sm text-[#525252]">Current view</p>
          <p className="mt-5 text-4xl font-light">{filtered.length}</p>
        </div>
      </section>
      <section className="mt-8 border border-[#e0e0e0]">
        <div className="border-b border-[#e0e0e0] p-5">
          <label className="relative block max-w-xl">
            <span className="sr-only">Search vulnerabilities</span>
            <Search size={17} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#525252]" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search CVE, description, or asset"
              className="h-12 w-full border-b-2 border-[#8d8d8d] bg-[#f4f4f4] pl-10 pr-3 text-sm outline-none focus:border-[#0f62fe]"
            />
          </label>
        </div>
        {loading && (
          <div className="grid min-h-[320px] place-items-center">
            <div className="text-center">
              <LoaderCircle className="mx-auto animate-spin text-[#0f62fe]" />
              <p className="mt-3 text-sm text-[#525252]">Loading threat intelligence…</p>
            </div>
          </div>
        )}
        {!loading && error && (
          <div className="grid min-h-[320px] place-items-center p-6 text-center">
            <div>
              <AlertCircle className="mx-auto text-[#da1e28]" />
              <p className="mt-3 font-medium">Unable to load threat intelligence</p>
              <p className="mt-2 text-sm text-[#525252]">{error}</p>
              <button
                onClick={retry}
                className="mt-5 inline-flex h-10 items-center gap-2 bg-[#0f62fe] px-4 text-sm text-white"
              >
                <RotateCcw size={15} />
                Retry
              </button>
            </div>
          </div>
        )}
        {!loading && !error && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left">
              <thead>
                <tr className="bg-[#f4f4f4] text-[11px] text-[#525252]">
                  <th className="w-28 px-5 py-4">
                    <SortButton
                      label="Model rank"
                      value="modelRank"
                      active={sortKey === "modelRank"}
                      direction={direction}
                      onSort={handleSort}
                    />
                  </th>
                  <th className="px-4 py-4">Vulnerability & description</th>
                  <th className="px-4 py-4">Affected asset</th>
                  <th className="px-4 py-4">Remediation</th>
                  <th className="w-12 px-4 py-4" />
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => {
                  const rankedHigher =
                    item.modelRank !== null &&
                    item.traditionalRank !== null &&
                    item.modelRank < item.traditionalRank;
                  const alert = alertByCve.get(item.id);
                  return (
                    <tr
                      key={item.id}
                      onClick={() => setSelected(item)}
                      tabIndex={0}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") setSelected(item);
                      }}
                      className="cursor-pointer border-t border-[#e0e0e0] hover:bg-[#f4f4f4] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#0f62fe]"
                    >
                      <td className="px-5 py-4 text-xl font-light text-[#0f62fe]">
                        {item.modelRank === null ? (
                          <span className="text-sm text-[#6f6f6f]">—</span>
                        ) : (
                          `#${item.modelRank}`
                        )}
                      </td>
                      <td className="px-4 py-4">
                        <p className="font-mono text-xs font-semibold text-[#0f62fe]">{item.id}</p>
                        <p className="mt-1 max-w-[680px] text-sm leading-5 text-[#161616] line-clamp-2">
                          {item.description}
                        </p>
                        {rankedHigher && (
                          <span className="mt-2 inline-flex bg-[#edf5ff] px-2 py-1 text-[10px] font-semibold uppercase text-[#0043ce]">
                            Model ranked higher
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-4 text-sm">
                        <p>{item.affectedProduct ?? "Not in inventory"}</p>
                        {item.affectedService && (
                          <p className="mt-0.5 text-xs text-[#6f6f6f]">{item.affectedService}</p>
                        )}
                      </td>
                      <td className="px-4 py-4 text-sm">{alert?.lifecycle ?? "Watchlist"}</td>
                      <td className="px-4 py-4">
                        <ChevronRight size={18} className="text-[#6f6f6f]" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <div className="border-t border-[#e0e0e0] px-5 py-16 text-center">
                <p className="font-medium">No vulnerabilities match this search.</p>
                <button onClick={() => setQuery("")} className="mt-3 text-sm text-[#0f62fe]">
                  Clear search
                </button>
              </div>
            )}
          </div>
        )}
      </section>
      {selected && (
        <ThreatDetails
          threat={selected}
          alert={alertByCve.get(selected.id) ?? null}
          demo={demo}
          onClose={() => setSelected(null)}
        />
      )}
    </AppShell>
  );
}
