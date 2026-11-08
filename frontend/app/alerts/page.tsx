"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  BellRing,
  Check,
  ChevronRight,
  CircleHelp,
  Clock3,
  ExternalLink,
  LoaderCircle,
  RefreshCw,
  RotateCcw,
  X,
  XCircle,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { fetchAlertActivity } from "@/lib/api/alerts";
import type {
  AlertLifecycle,
  AlertPriority,
  DeliveryStatus,
  JiraStatus,
  VulnerabilityAlert,
} from "@/lib/types/alert";

type WorkflowStatus = "Pending" | "Running" | "Succeeded" | "Failed" | "Skipped" | "Unavailable";
const priorityStyles: Record<AlertPriority, string> = {
  Critical: "bg-[#da1e28] text-white",
  High: "bg-[#ff832b] text-[#161616]",
  Medium: "bg-[#f1c21b] text-[#161616]",
};
const lifecycleStyles: Record<AlertLifecycle, string> = {
  Open: "bg-[#edf5ff] text-[#0043ce]",
  Investigating: "bg-[#e8daff] text-[#491d8b]",
  Resolved: "bg-[#defbe6] text-[#0e6027]",
  Suppressed: "bg-[#e0e0e0] text-[#525252]",
};
const workflowStyles: Record<WorkflowStatus, string> = {
  Pending: "bg-[#fff1f1] text-[#8e6a00]",
  Running: "bg-[#edf5ff] text-[#0043ce]",
  Succeeded: "bg-[#defbe6] text-[#0e6027]",
  Failed: "bg-[#fff1f1] text-[#a2191f]",
  Skipped: "bg-[#f4f4f4] text-[#525252]",
  Unavailable: "bg-[#f4f4f4] text-[#6f6f6f]",
};
const formatTimestamp = (value: string) =>
  new Intl.DateTimeFormat("en-CA", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));

function isIntentionalTestCase(alert: VulnerabilityAlert) {
  return (
    alert.assetName === "Unknown asset" ||
    alert.assetId.includes("does-not-exist") ||
    alert.cveId.startsWith("CVE-X")
  );
}

function findingLabel(alert: VulnerabilityAlert) {
  return `${alert.cveId} → ${alert.assetName}`;
}

function isValidExternalUrl(value: string | null | undefined) {
  return Boolean(value && /^https?:\/\//i.test(value) && !value.includes("example.invalid"));
}

function DeliveryBadge({ status }: { status: DeliveryStatus }) {
  const config =
    status === "Delivered"
      ? { icon: Check, className: "text-[#198038]" }
      : status === "Failed"
        ? { icon: XCircle, className: "text-[#da1e28]" }
        : status === "Pending"
          ? { icon: Clock3, className: "text-[#8e6a00]" }
          : { icon: CircleHelp, className: "text-[#6f6f6f]" };
  const Icon = config.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs ${config.className}`}>
      <Icon size={14} />
      {status}
    </span>
  );
}

function providerStatus(status: DeliveryStatus | JiraStatus): WorkflowStatus {
  if (["Delivered", "Created", "Updated", "Commented"].includes(status)) return "Succeeded";
  if (status === "Failed") return "Failed";
  if (status === "Pending") return "Pending";
  if (status === "Not attempted" || status === "Simulated — not sent") return "Skipped";
  return "Unavailable";
}

function workflowFor(alert: VulnerabilityAlert) {
  const hasPr = Boolean(alert.prUrl);
  const unknownAsset = isIntentionalTestCase(alert);
  const testStatus: WorkflowStatus =
    alert.checksPassed === true
      ? "Succeeded"
      : alert.checksPassed === false
        ? "Failed"
        : hasPr
          ? "Succeeded"
          : "Unavailable";
  return [
    { label: "Threat detected", status: "Succeeded" as WorkflowStatus, timestamp: alert.timestamp },
    {
      label: "Asset identified",
      status: (unknownAsset ? "Unavailable" : "Succeeded") as WorkflowStatus,
      timestamp: unknownAsset ? null : alert.timestamp,
    },
    {
      label: "Slack notification",
      status: providerStatus(alert.slackStatus),
      timestamp: alert.slackDelivery?.deliveredAt ?? alert.slackDelivery?.attemptedAt ?? null,
    },
    {
      label: "Jira issue created or updated",
      status: providerStatus(alert.jiraStatus),
      timestamp: alert.jiraDelivery?.deliveredAt ?? alert.jiraDelivery?.attemptedAt ?? null,
    },
    {
      label: "Coding agent investigation",
      status: (hasPr ? "Succeeded" : "Unavailable") as WorkflowStatus,
      timestamp: hasPr ? alert.timestamp : null,
    },
    {
      label: "Draft GitHub PR",
      status: (hasPr ? "Succeeded" : "Unavailable") as WorkflowStatus,
      timestamp: hasPr ? alert.timestamp : null,
    },
    {
      label: "Automated tests",
      status: testStatus,
      timestamp: hasPr ? alert.timestamp : null,
    },
    {
      label: "Awaiting human approval",
      status: (hasPr ? "Pending" : "Unavailable") as WorkflowStatus,
      timestamp: null,
    },
  ];
}

function WorkflowStrip({ alert }: { alert: VulnerabilityAlert }) {
  return (
    <div className="flex items-center gap-1" aria-label="Eight-stage remediation workflow">
      {workflowFor(alert).map((stage, index) => (
        <span
          key={stage.label}
          title={`${index + 1}. ${stage.label}: ${stage.status}`}
          className={`h-2.5 w-5 ${
            stage.status === "Succeeded"
              ? "bg-[#24a148]"
              : stage.status === "Failed"
                ? "bg-[#da1e28]"
                : stage.status === "Pending" || stage.status === "Running"
                  ? "bg-[#0f62fe]"
                  : "bg-[#c6c6c6]"
          }`}
        />
      ))}
    </div>
  );
}

function AlertDrawer({ alert, onClose }: { alert: VulnerabilityAlert; onClose: () => void }) {
  const stages = workflowFor(alert);
  const jiraLink = isValidExternalUrl(alert.jiraUrl) ? alert.jiraUrl : null;
  const slackLink = isValidExternalUrl(alert.slackDelivery?.externalUrl)
    ? alert.slackDelivery?.externalUrl
    : null;
  const testCase = isIntentionalTestCase(alert);

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/35"
      onClick={onClose}
      role="presentation"
    >
      <aside
        className="h-full w-full max-w-[640px] overflow-y-auto border-l border-[#e0e0e0] bg-white"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={`${findingLabel(alert)} remediation details`}
      >
        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-[#e0e0e0] bg-white px-6 py-5">
          <div>
            <p className="text-xs font-medium text-[#0f62fe]">Remediation details</p>
            <h2 className="mt-1 font-mono text-lg font-semibold">{alert.cveId}</h2>
            <p className="mt-1 text-sm text-[#525252]">→ {alert.assetName}</p>
          </div>
          <button
            onClick={onClose}
            className="grid h-10 w-10 place-items-center hover:bg-[#f4f4f4]"
            aria-label="Close remediation details"
          >
            <X size={20} />
          </button>
        </div>
        <div className="p-6">
          {testCase && (
            <div className="mb-6 border-l-4 border-[#8a3ffc] bg-[#f6f2ff] p-4">
              <p className="text-sm font-medium text-[#491d8b]">Intentional test case</p>
              <p className="mt-1 text-sm leading-6 text-[#491d8b]">
                This workflow demonstrates failure handling when a CVE has no matching inventory
                asset. The Unavailable stages and failed ticket below are expected.
              </p>
            </div>
          )}
          {alert.simulated && (
            <div className="mb-6 border-l-4 border-[#0f62fe] bg-[#edf5ff] p-4">
              <p className="text-sm font-medium text-[#0043ce]">Simulated workflow record</p>
              <p className="mt-1 text-sm leading-6 text-[#0043ce]">
                Provider results and ticket references are demo fixtures. No external action is
                being executed.
              </p>
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            <span className={`px-3 py-1 text-xs font-medium ${priorityStyles[alert.priority]}`}>
              {alert.priority}
            </span>
            <span className={`px-3 py-1 text-xs font-medium ${lifecycleStyles[alert.lifecycle]}`}>
              {alert.lifecycle}
            </span>
            {testCase && (
              <span className="bg-[#e8daff] px-3 py-1 text-xs font-medium text-[#491d8b]">
                Test case
              </span>
            )}
            <span className="bg-[#f4f4f4] px-3 py-1 text-xs text-[#525252]">
              {alert.occurrenceCount} detection{alert.occurrenceCount === 1 ? "" : "s"}
            </span>
          </div>
          <h3 className="mt-7 text-xl font-light">{alert.assetName}</h3>
          <p className="mt-1 text-xs text-[#6f6f6f]">
            {alert.ownerTeam ? `${alert.ownerTeam} team` : alert.assetId}
          </p>
          <p className="mt-5 text-sm leading-6 text-[#525252]">{alert.triggerReason}</p>
          <h3 className="mt-8 text-sm font-medium">Remediation workflow</h3>
          <ol className="mt-3 border-y border-[#e0e0e0]">
            {stages.map((stage, index) => (
              <li
                key={stage.label}
                className="grid grid-cols-[28px_1fr_auto] items-center gap-3 border-b border-[#e0e0e0] py-3 last:border-b-0"
              >
                <span className="text-xs text-[#6f6f6f]">{index + 1}</span>
                <div>
                  <p className="text-sm font-medium">{stage.label}</p>
                  {stage.timestamp && (
                    <p className="mt-1 text-xs text-[#6f6f6f]">{formatTimestamp(stage.timestamp)}</p>
                  )}
                </div>
                <span
                  className={`px-2 py-1 text-[10px] font-semibold uppercase ${workflowStyles[stage.status]}`}
                >
                  {stage.status}
                </span>
              </li>
            ))}
          </ol>
          <div className="mt-6 grid grid-cols-2 gap-px bg-[#e0e0e0]">
            <div className="bg-[#f4f4f4] p-4">
              <p className="text-xs text-[#525252]">Slack provider result</p>
              <div className="mt-2">
                <DeliveryBadge status={alert.slackStatus} />
              </div>
              {slackLink && (
                <a
                  href={slackLink}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-2 inline-flex items-center gap-1 text-xs text-[#0f62fe] hover:underline"
                >
                  Open Slack message
                  <ExternalLink size={12} />
                </a>
              )}
              {!slackLink && alert.slackDelivery?.externalId && alert.slackStatus === "Delivered" && (
                <p className="mt-2 text-xs text-[#6f6f6f]">
                  Message ts {alert.slackDelivery.externalId}
                </p>
              )}
            </div>
            <div className="bg-[#f4f4f4] p-4">
              <p className="text-xs text-[#525252]">Jira provider result</p>
              <p className="mt-2 text-sm">{alert.jiraStatus}</p>
              {jiraLink && (
                <a
                  href={jiraLink}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-2 inline-flex items-center gap-1 text-xs text-[#0f62fe]"
                >
                  {alert.jiraKey ?? "Open Jira"}
                  <ExternalLink size={12} />
                </a>
              )}
              {alert.jiraKey && !jiraLink && (
                <p className="mt-2 text-xs text-[#6f6f6f]">
                  {alert.jiraKey}
                  {alert.simulated ? " · simulated reference" : ""}
                </p>
              )}
            </div>
          </div>
          {(alert.slackDelivery?.errorMessage || alert.jiraDelivery?.errorMessage) && (
            <div className="mt-3 border-l-4 border-[#da1e28] bg-[#fff1f1] p-3 text-xs text-[#a2191f]">
              {alert.slackDelivery?.errorMessage && <p>Slack: {alert.slackDelivery.errorMessage}</p>}
              {alert.jiraDelivery?.errorMessage && <p>Jira: {alert.jiraDelivery.errorMessage}</p>}
            </div>
          )}
          {(alert.repository || alert.ownerTeam) && (
            <div className="mt-6 grid gap-px bg-[#e0e0e0] sm:grid-cols-2">
              {alert.repository && (
                <div className="bg-[#f4f4f4] p-4">
                  <p className="text-xs text-[#525252]">Affected repository</p>
                  <p className="mt-2 font-mono text-sm">{alert.repository}</p>
                </div>
              )}
              {alert.ownerTeam && (
                <div className="bg-[#f4f4f4] p-4">
                  <p className="text-xs text-[#525252]">Responsible team</p>
                  <p className="mt-2 text-sm">{alert.ownerTeam}</p>
                </div>
              )}
            </div>
          )}
          {alert.prUrl && (
            <div className="mt-4 border border-[#a6c8ff] bg-[#edf5ff] p-4">
              <p className="text-xs font-semibold uppercase tracking-[.08em] text-[#0043ce]">
                Draft GitHub pull request
              </p>
              <p className="mt-1.5 text-sm text-[#161616]">
                {alert.prTitle ?? `${alert.repository ?? "Mikop22/securitydemo"} pull request`}
              </p>
              <a
                href={alert.prUrl}
                target="_blank"
                rel="noreferrer"
                className="mt-2 inline-flex items-center gap-1.5 font-mono text-xs font-semibold text-[#0f62fe] hover:underline"
              >
                {alert.repository ?? "Mikop22/securitydemo"}
                {alert.prNumber ? `#${alert.prNumber}` : ""} · Open draft PR on GitHub
                <ExternalLink size={12} />
              </a>
            </div>
          )}
          <h3 className="mt-8 text-sm font-medium">Evidence</h3>
          {alert.evidence.length > 0 ? (
            <ul className="mt-3 divide-y divide-[#e0e0e0] border-y border-[#e0e0e0]">
              {alert.evidence.map((item) => (
                <li key={item} className="py-3 text-sm leading-6 text-[#525252]">
                  {item}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-3 bg-[#f4f4f4] p-4 text-sm text-[#525252]">No evidence supplied.</p>
          )}
          <h3 className="mt-8 text-sm font-medium">Activity history</h3>
          <div className="relative mt-4 border-l border-[#c6c6c6] pl-5">
            {alert.history.map((event) => (
              <div key={`${event.timestamp}-${event.label}`} className="relative pb-6 last:pb-0">
                <span className="absolute -left-[25px] top-1.5 h-2 w-2 bg-[#0f62fe]" />
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-medium">{event.label}</p>
                  <p className="text-xs text-[#6f6f6f]">{formatTimestamp(event.timestamp)}</p>
                </div>
                <p className="mt-1 text-sm leading-6 text-[#525252]">{event.detail}</p>
              </div>
            ))}
          </div>
        </div>
      </aside>
    </div>
  );
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<VulnerabilityAlert[]>([]);
  const [priority, setPriority] = useState("All");
  const [lifecycle, setLifecycle] = useState("All");
  const [delivery, setDelivery] = useState("All");
  const [selected, setSelected] = useState<VulnerabilityAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requestKey, setRequestKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    fetchAlertActivity()
      .then((response) => {
        if (!cancelled) setAlerts(response.alerts);
      })
      .catch((cause) => {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : "The remediation feed could not be loaded.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [requestKey]);

  const orderedAlerts = useMemo(
    () =>
      [...alerts].sort((a, b) => {
        const aTest = isIntentionalTestCase(a) ? 1 : 0;
        const bTest = isIntentionalTestCase(b) ? 1 : 0;
        return aTest - bTest;
      }),
    [alerts],
  );

  const filtered = useMemo(
    () =>
      orderedAlerts
        .filter((alert) => priority === "All" || alert.priority === priority)
        .filter((alert) => lifecycle === "All" || alert.lifecycle === lifecycle)
        .filter((alert) => delivery === "All" || alert.slackStatus === delivery),
    [orderedAlerts, priority, lifecycle, delivery],
  );

  const primaryAlerts = orderedAlerts.filter((alert) => !isIntentionalTestCase(alert));
  const stats = {
    total: primaryAlerts.length,
    open: primaryAlerts.filter(
      (alert) => alert.lifecycle === "Open" || alert.lifecycle === "Investigating",
    ).length,
    delivered: primaryAlerts.filter((alert) => alert.slackStatus === "Delivered").length,
    failed: primaryAlerts.filter(
      (alert) => alert.slackStatus === "Failed" || alert.jiraStatus === "Failed",
    ).length,
  };

  function retry() {
    setLoading(true);
    setError(null);
    setRequestKey((value) => value + 1);
  }

  return (
    <AppShell
      title="Remediation center"
      subtitle="Human-reviewed security workflows"
      breadcrumb="Remediation Center"
    >
      <section className="glass-stats grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {(
          [
            ["Active workflows", stats.total],
            ["Needs attention", stats.open],
            ["Slack delivered", stats.delivered],
            ["Delivery issues", stats.failed],
          ] as const
        ).map(([label, value]) => (
          <div key={label} className="glass-stat p-5">
            <p className="text-sm text-[#525252]">{label}</p>
            <p className="mt-5 text-4xl font-light">{value}</p>
          </div>
        ))}
      </section>
      <section className="mt-8 border border-[#e0e0e0]">
        <div className="flex flex-col gap-3 border-b border-[#e0e0e0] p-5 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-xl font-light">Remediation workflows</h2>
            <p className="mt-1 text-xs text-[#6f6f6f]">
              Human-reviewed path from ranked finding to Slack, Jira, and draft PR.
            </p>
          </div>
          <div className="grid gap-2 sm:grid-cols-3">
            <select
              aria-label="Filter by priority"
              value={priority}
              onChange={(event) => setPriority(event.target.value)}
              className="h-10 border-b-2 border-[#8d8d8d] bg-[#f4f4f4] px-3 text-sm"
            >
              <option>All</option>
              <option>Critical</option>
              <option>High</option>
              <option>Medium</option>
            </select>
            <select
              aria-label="Filter by lifecycle"
              value={lifecycle}
              onChange={(event) => setLifecycle(event.target.value)}
              className="h-10 border-b-2 border-[#8d8d8d] bg-[#f4f4f4] px-3 text-sm"
            >
              <option>All</option>
              <option>Open</option>
              <option>Investigating</option>
              <option>Resolved</option>
              <option>Suppressed</option>
            </select>
            <select
              aria-label="Filter by Slack delivery"
              value={delivery}
              onChange={(event) => setDelivery(event.target.value)}
              className="h-10 border-b-2 border-[#8d8d8d] bg-[#f4f4f4] px-3 text-sm"
            >
              <option>All</option>
              <option>Delivered</option>
              <option>Failed</option>
              <option>Pending</option>
              <option>Not attempted</option>
            </select>
          </div>
        </div>
        {loading && (
          <div className="grid min-h-[320px] place-items-center">
            <div className="text-center">
              <LoaderCircle className="mx-auto animate-spin text-[#0f62fe]" />
              <p className="mt-3 text-sm text-[#525252]">Loading remediation workflows…</p>
            </div>
          </div>
        )}
        {!loading && error && (
          <div className="grid min-h-[320px] place-items-center p-6 text-center">
            <div>
              <AlertCircle className="mx-auto text-[#da1e28]" />
              <p className="mt-3 font-medium">Remediation activity unavailable</p>
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
            <table className="w-full min-w-[1120px] text-left">
              <thead>
                <tr className="bg-[#f4f4f4] text-[11px] font-semibold uppercase tracking-[.06em] text-[#525252]">
                  <th className="px-5 py-4">Finding</th>
                  <th className="px-4 py-4">Affected asset</th>
                  <th className="px-4 py-4">Priority</th>
                  <th className="px-4 py-4">8-stage workflow</th>
                  <th className="px-4 py-4">Slack</th>
                  <th className="px-4 py-4">Jira</th>
                  <th className="px-4 py-4">Lifecycle</th>
                  <th className="px-4 py-4">Updated</th>
                  <th className="w-12 px-4 py-4" />
                </tr>
              </thead>
              <tbody>
                {filtered.map((alert) => {
                  const testCase = isIntentionalTestCase(alert);
                  const slackLink = isValidExternalUrl(alert.slackDelivery?.externalUrl)
                    ? alert.slackDelivery?.externalUrl
                    : null;
                  return (
                    <tr
                      key={alert.id}
                      onClick={() => setSelected(alert)}
                      tabIndex={0}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") setSelected(alert);
                      }}
                      className="cursor-pointer border-t border-[#e0e0e0] hover:bg-[#f4f4f4] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#0f62fe]"
                    >
                      <td className="px-5 py-4">
                        <p className="font-mono text-sm font-semibold text-[#0f62fe]">{alert.cveId}</p>
                        <p className="mt-1 text-sm text-[#161616]">→ {alert.assetName}</p>
                        {testCase && (
                          <span className="mt-2 inline-flex bg-[#e8daff] px-2 py-1 text-[10px] font-semibold uppercase tracking-[.06em] text-[#491d8b]">
                            Intentional test case
                          </span>
                        )}
                        {alert.occurrenceCount > 1 && (
                          <span className="mt-2 inline-flex items-center gap-1 text-[11px] text-[#6f6f6f]">
                            <RefreshCw size={12} />
                            {alert.occurrenceCount} detections merged
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-4">
                        <p className="text-sm">{alert.assetName}</p>
                        <p className="mt-1 text-xs text-[#6f6f6f]">
                          {alert.ownerTeam ?? alert.assetId}
                        </p>
                      </td>
                      <td className="px-4 py-4">
                        <span
                          className={`px-2.5 py-1 text-xs font-medium ${priorityStyles[alert.priority]}`}
                        >
                          {alert.priority}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        <WorkflowStrip alert={alert} />
                        <p className="mt-2 max-w-[240px] text-xs text-[#6f6f6f]">
                          {alert.triggerReason}
                        </p>
                      </td>
                      <td className="px-4 py-4">
                        <DeliveryBadge status={alert.slackStatus} />
                        {slackLink && (
                          <a
                            href={slackLink}
                            target="_blank"
                            rel="noreferrer"
                            onClick={(event) => event.stopPropagation()}
                            className="mt-1 inline-flex items-center gap-1 text-[11px] text-[#0f62fe] hover:underline"
                          >
                            Open message
                            <ExternalLink size={11} />
                          </a>
                        )}
                      </td>
                      <td className="px-4 py-4">
                        <p className="text-xs">{alert.jiraStatus}</p>
                        {alert.jiraKey && (
                          <p className="mt-1 text-xs text-[#0f62fe]">{alert.jiraKey}</p>
                        )}
                      </td>
                      <td className="px-4 py-4">
                        <span
                          className={`px-2.5 py-1 text-xs font-medium ${lifecycleStyles[alert.lifecycle]}`}
                        >
                          {alert.lifecycle}
                        </span>
                      </td>
                      <td className="px-4 py-4 text-xs text-[#6f6f6f]">
                        {formatTimestamp(alert.timestamp)}
                      </td>
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
                <BellRing className="mx-auto text-[#6f6f6f]" />
                <p className="mt-3 font-medium">No workflows match these filters.</p>
                <button
                  onClick={() => {
                    setPriority("All");
                    setLifecycle("All");
                    setDelivery("All");
                  }}
                  className="mt-3 text-sm text-[#0f62fe]"
                >
                  Clear filters
                </button>
              </div>
            )}
          </div>
        )}
      </section>
      {selected && <AlertDrawer alert={selected} onClose={() => setSelected(null)} />}
    </AppShell>
  );
}
