"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  BellRing,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  ExternalLink,
  LoaderCircle,
  Play,
  RefreshCw,
  RotateCcw,
  Terminal,
  X,
  XCircle,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { fetchAlertActivity } from "@/lib/api/alerts";
import {
  DEFAULT_SCENARIOS,
  executeSimulationStage,
  fetchSimulationScenarios,
  scenarioIdForCve,
  updateAlertLifecycle,
  type ScenarioCatalogItem,
  type SimulationStepResponse,
} from "@/lib/api/simulations";
import type {
  AlertLifecycle,
  AlertPriority,
  DeliveryStatus,
  JiraStatus,
  VulnerabilityAlert,
} from "@/lib/types/alert";

type WorkflowStatus =
  | "Pending"
  | "Running"
  | "Succeeded"
  | "Failed"
  | "Skipped"
  | "Manual path"
  | "Unavailable";
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
  "Manual path": "bg-[#edf5ff] text-[#0043ce]",
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
  const manualAppliance = !unknownAsset && !hasPr && !alert.repository;
  const codeStageStatus: WorkflowStatus = hasPr
    ? "Succeeded"
    : manualAppliance
      ? "Manual path"
      : "Unavailable";
  const testStatus: WorkflowStatus =
    alert.checksPassed === true
      ? "Succeeded"
      : alert.checksPassed === false
        ? "Failed"
        : hasPr
          ? "Succeeded"
          : manualAppliance
            ? "Manual path"
            : "Unavailable";
  const approvalStatus: WorkflowStatus =
    alert.lifecycle === "Resolved"
      ? "Succeeded"
      : hasPr
        ? "Pending"
        : manualAppliance
          ? "Pending"
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
      label: manualAppliance ? "Coding agent investigation (appliance)" : "Coding agent investigation",
      status: codeStageStatus,
      timestamp: hasPr ? alert.timestamp : null,
    },
    {
      label: manualAppliance ? "Vendor firmware route (no code PR)" : "Draft GitHub PR",
      status: codeStageStatus,
      timestamp: hasPr ? alert.timestamp : null,
    },
    {
      label: manualAppliance ? "Automated repo tests (not applicable)" : "Automated tests",
      status: testStatus,
      timestamp: hasPr ? alert.timestamp : null,
    },
    {
      label: manualAppliance ? "Awaiting network ops firmware upgrade" : "Awaiting human approval",
      status: approvalStatus,
      timestamp: null,
    },
  ];
}

const PIPELINE_STAGE_LABELS = [
  "Threat detected",
  "Asset identified",
  "Slack notification",
  "Jira issue created or updated",
  "Coding agent investigation",
  "Draft GitHub PR",
  "Automated tests",
  "Awaiting human approval",
] as const;

function WorkflowStrip({
  alert,
  activeStage = null,
  activeFindingKey = null,
}: {
  alert: VulnerabilityAlert;
  activeStage?: number | null;
  activeFindingKey?: string | null;
}) {
  const isTargetRow =
    activeStage !== null &&
    (activeFindingKey === null || alert.id === activeFindingKey || alert.dedupeKey === activeFindingKey);
  return (
    <div className="flex items-center gap-1" aria-label="Eight-stage remediation workflow">
      {workflowFor(alert).map((stage, index) => {
        const stageNum = index + 1;
        let colorClass =
          stage.status === "Succeeded"
            ? "bg-[#24a148]"
            : stage.status === "Failed"
              ? "bg-[#da1e28]"
              : stage.status === "Pending" || stage.status === "Running"
                ? "bg-[#0f62fe]"
                : stage.status === "Manual path"
                  ? "bg-[#a6c8ff]"
                  : "bg-[#c6c6c6]";

        if (isTargetRow && activeStage !== null) {
          if (stageNum < activeStage) {
            colorClass =
              stage.status === "Manual path"
                ? "bg-[#a6c8ff]"
                : stage.status === "Unavailable"
                  ? "bg-[#c6c6c6]"
                  : stage.status === "Failed"
                    ? "bg-[#da1e28]"
                    : "bg-[#24a148]";
          } else if (stageNum === activeStage) {
            colorClass = "bg-[#0f62fe] animate-pulse ring-2 ring-[#0f62fe]/40";
          } else {
            colorClass = "bg-[#e0e0e0]";
          }
        }

        return (
          <span
            key={stage.label}
            title={`${stageNum}. ${stage.label}: ${
              isTargetRow && stageNum === activeStage ? "Running" : stage.status
            }`}
            className={`h-2.5 w-5 transition-colors duration-200 ${colorClass}`}
          />
        );
      })}
    </div>
  );
}

function AlertDrawer({
  alert,
  onClose,
  onToggleLifecycle,
}: {
  alert: VulnerabilityAlert;
  onClose: () => void;
  onToggleLifecycle: (alert: VulnerabilityAlert) => void;
}) {
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
          <div className="flex flex-wrap items-center gap-2">
            <span className={`px-3 py-1 text-xs font-medium ${priorityStyles[alert.priority]}`}>
              {alert.priority}
            </span>
            <span className={`px-3 py-1 text-xs font-medium ${lifecycleStyles[alert.lifecycle]}`}>
              {alert.lifecycle}
            </span>
            <button
              type="button"
              onClick={() => onToggleLifecycle(alert)}
              className="border border-[#c6c6c6] bg-white px-3 py-1 text-xs font-medium text-[#161616] transition-colors hover:border-[#0f62fe] hover:text-[#0f62fe]"
            >
              {alert.lifecycle === "Resolved"
                ? "Reopen workflow"
                : "Mark resolved"}
            </button>
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
            <>
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
              <div className="mt-3 border border-[#e0e0e0] bg-[#f4f4f4] p-4">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs font-semibold uppercase tracking-[.08em] text-[#525252]">
                    Entire agent provenance
                  </p>
                  <span className="bg-[#defbe6] px-2 py-0.5 font-mono text-[10px] font-semibold text-[#0e6027]">
                    checkpoint-backend: branch
                  </span>
                </div>
                <p className="mt-1.5 text-xs text-[#525252]">
                  Entire CLI v0.13.1 · Checkpoint commit
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
                  {alert.commitSha && alert.commitUrl ? (
                    <a
                      href={alert.commitUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 font-mono font-semibold text-[#0f62fe] hover:underline"
                    >
                      {alert.commitSha}
                      <ExternalLink size={11} />
                    </a>
                  ) : (
                    <span className="font-mono text-[#525252]">
                      {alert.prBranch ?? "branch checkpoint"}
                    </span>
                  )}
                  {alert.verificationCommand && (
                    <span className="font-mono text-[#161616]">
                      Verify: {alert.verificationCommand}
                    </span>
                  )}
                </div>
              </div>
            </>
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
  const [scenarios, setScenarios] = useState<ScenarioCatalogItem[]>(DEFAULT_SCENARIOS);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(DEFAULT_SCENARIOS[0].id);
  const [labOpen, setLabOpen] = useState(false);
  const [simStage, setSimStage] = useState<number | null>(null);
  const [activeFindingKey, setActiveFindingKey] = useState<string | null>(null);
  const [simLogs, setSimLogs] = useState<SimulationStepResponse[]>([]);
  const [simError, setSimError] = useState<string | null>(null);
  const [simCompleted, setSimCompleted] = useState(false);

  function handleToggleLifecycle(target: VulnerabilityAlert) {
    const nextLifecycle: AlertLifecycle =
      target.lifecycle === "Resolved"
        ? target.prUrl
          ? "Investigating"
          : "Open"
        : "Resolved";
    setAlerts((current) =>
      current.map((item) =>
        item.id === target.id ? { ...item, lifecycle: nextLifecycle } : item,
      ),
    );
    setSelected((current) =>
      current && current.id === target.id
        ? { ...current, lifecycle: nextLifecycle }
        : current,
    );
    void updateAlertLifecycle(target.id, nextLifecycle);
  }

  useEffect(() => {
    let cancelled = false;
    fetchSimulationScenarios().then((items) => {
      if (!cancelled && items.length > 0) {
        setScenarios(items);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const triageCve = params.get("triage");
    if (triageCve) {
      const targetScenarioId = scenarioIdForCve(triageCve);
      setSelectedScenarioId(targetScenarioId);
      setLabOpen(true);
      window.history.replaceState({}, "", window.location.pathname);
      void runLiveScenario(targetScenarioId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runLiveScenario(scenarioId = selectedScenarioId) {
    if (simStage !== null) return;
    setSimError(null);
    setSimCompleted(false);
    setSimLogs([]);
    setSimStage(1);
    setActiveFindingKey(null);

    try {
      for (let stage = 1; stage <= 8; stage += 1) {
        setSimStage(stage);
        const stepResult = await executeSimulationStage(scenarioId, stage);
        setActiveFindingKey(stepResult.findingKey);
        setSimLogs((prev) => [...prev, stepResult]);
        if (stage === 3 || stage === 4 || stage === 6 || stage === 7 || stage === 8) {
          const refreshed = await fetchAlertActivity();
          setAlerts(refreshed.alerts);
        }
      }
      setSimStage(null);
      setSimCompleted(true);
    } catch (cause) {
      setSimStage(null);
      setSimError(
        cause instanceof Error ? cause.message : "Live pipeline execution encountered an error.",
      );
    }
  }

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

  const selectedScenario =
    scenarios.find((item) => item.id === selectedScenarioId) ?? scenarios[0];

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
            ["Active workflows", stats.total, "Tracked CVE + asset remediations"],
            ["Needs attention", stats.open, "Open or awaiting human review"],
            ["Slack delivered", stats.delivered, "Channel alerts posted"],
            ["Delivery issues", stats.failed, "Failed Slack or Jira deliveries"],
          ] as const
        ).map(([label, value, detail]) => (
          <div key={label} className="glass-stat p-5">
            <p className="text-sm text-[#525252]">{label}</p>
            <p className="mt-5 text-4xl font-light">{value}</p>
            <p className="mt-2 text-xs text-[#6f6f6f]">{detail}</p>
          </div>
        ))}
      </section>
      <section className="mt-8 border border-[#e0e0e0]">
        <div className="flex flex-col gap-3 border-b border-[#e0e0e0] p-5 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-xl font-light">Remediation workflows</h2>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Filter by priority"
              value={priority}
              onChange={(event) => setPriority(event.target.value)}
              className="h-10 border-b-2 border-[#8d8d8d] bg-[#f4f4f4] px-3 text-sm"
            >
              <option value="All">Priority: All</option>
              <option value="Critical">Priority: Critical</option>
              <option value="High">Priority: High</option>
              <option value="Medium">Priority: Medium</option>
            </select>
            <select
              aria-label="Filter by lifecycle"
              value={lifecycle}
              onChange={(event) => setLifecycle(event.target.value)}
              className="h-10 border-b-2 border-[#8d8d8d] bg-[#f4f4f4] px-3 text-sm"
            >
              <option value="All">Lifecycle: All</option>
              <option value="Open">Lifecycle: Open</option>
              <option value="Investigating">Lifecycle: Investigating</option>
              <option value="Resolved">Lifecycle: Resolved</option>
              <option value="Suppressed">Lifecycle: Suppressed</option>
            </select>
            <select
              aria-label="Filter by Slack delivery"
              value={delivery}
              onChange={(event) => setDelivery(event.target.value)}
              className="h-10 border-b-2 border-[#8d8d8d] bg-[#f4f4f4] px-3 text-sm"
            >
              <option value="All">Slack: All</option>
              <option value="Delivered">Slack: Delivered</option>
              <option value="Failed">Slack: Failed</option>
              <option value="Pending">Slack: Pending</option>
              <option value="Not attempted">Slack: Not attempted</option>
            </select>
            <button
              type="button"
              onClick={() => setLabOpen((current) => !current)}
              aria-expanded={labOpen}
              className={`inline-flex h-10 items-center gap-1.5 border px-3 text-xs transition-colors ${
                labOpen
                  ? "border-[#0f62fe] bg-[#edf5ff] font-medium text-[#0043ce]"
                  : "border-[#e0e0e0] bg-white text-[#525252] hover:bg-[#f4f4f4]"
              }`}
            >
              <Terminal size={13} />
              Scenario lab
              <ChevronDown
                size={13}
                className={`transition-transform ${labOpen ? "rotate-180" : ""}`}
              />
            </button>
          </div>
        </div>
        {labOpen && (
          <div className="border-b border-[#e0e0e0] bg-[#f4f4f4]/70 p-5">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div className="max-w-2xl">
                <p className="text-[11px] font-semibold uppercase tracking-[.08em] text-[#525252]">
                  Live vulnerability scenario runner
                </p>
                <p className="mt-1 text-xs text-[#525252]">
                  Select a vulnerability category to execute the real 8-stage backend pipeline
                  (Slack CLI, Jira REST API v3, Entire CLI v0.13.1 checkpoint, GitHub PR update, and
                  verification script).
                </p>
              </div>
              <button
                type="button"
                onClick={() => void runLiveScenario(selectedScenario.id)}
                disabled={simStage !== null}
                className="inline-flex h-10 shrink-0 items-center gap-2 bg-[#0f62fe] px-4 text-xs font-medium text-white transition-colors hover:bg-[#0043ce] disabled:cursor-wait disabled:bg-[#8d8d8d]"
              >
                {simStage !== null ? (
                  <LoaderCircle size={14} className="animate-spin" />
                ) : (
                  <Play size={14} />
                )}
                {simStage !== null
                  ? `Executing stage ${simStage}/8…`
                  : `Execute: ${selectedScenario.category}`}
              </button>
            </div>
            <div className="mt-4 grid gap-2.5 md:grid-cols-2 xl:grid-cols-4">
              {scenarios.map((scenario) => {
                const active = scenario.id === selectedScenario.id;
                return (
                  <button
                    key={scenario.id}
                    type="button"
                    disabled={simStage !== null}
                    onClick={() => setSelectedScenarioId(scenario.id)}
                    className={`flex flex-col justify-between border p-3.5 text-left transition-colors ${
                      active
                        ? "border-[#0f62fe] bg-white ring-1 ring-[#0f62fe]"
                        : "border-[#e0e0e0] bg-white hover:bg-[#f4f4f4]"
                    }`}
                  >
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-[.08em] text-[#0f62fe]">
                        {scenario.category}
                      </p>
                      <p className="mt-1 font-mono text-xs font-semibold text-[#161616]">
                        {scenario.cveId} → {scenario.assetName}
                      </p>
                      <p className="mt-1.5 text-xs leading-5 text-[#525252]">{scenario.summary}</p>
                    </div>
                    <p className="mt-3 border-t border-[#e0e0e0] pt-2 font-mono text-[10px] text-[#6f6f6f]">
                      {scenario.routeLabel}
                    </p>
                  </button>
                );
              })}
            </div>
            {(simStage !== null || simLogs.length > 0 || simError) && (
              <div className="mt-4 border border-[#e0e0e0] bg-white p-4">
                <div className="flex items-center justify-between border-b border-[#e0e0e0] pb-2.5">
                  <p className="text-xs font-semibold uppercase tracking-[.06em] text-[#525252]">
                    Live backend execution log · {selectedScenario.category}
                  </p>
                  {simStage !== null ? (
                    <span className="inline-flex items-center gap-1.5 font-mono text-xs text-[#0f62fe]">
                      <LoaderCircle size={12} className="animate-spin" />
                      Stage {simStage}/8: {PIPELINE_STAGE_LABELS[simStage - 1]}
                    </span>
                  ) : simCompleted ? (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-[#198038]">
                      <Check size={13} />
                      Completed all 8 stages
                    </span>
                  ) : null}
                </div>
                {simError && (
                  <p className="mt-3 border-l-4 border-[#da1e28] bg-[#fff1f1] p-2.5 text-xs text-[#a2191f]">
                    {simError}
                  </p>
                )}
                <ol className="mt-2 divide-y divide-[#e0e0e0] text-xs">
                  {simLogs.map((entry) => (
                    <li
                      key={`${entry.stage}-${entry.stageLabel}`}
                      className="flex flex-wrap items-center justify-between gap-2 py-2"
                    >
                      <div className="flex items-center gap-2.5">
                        <span className="font-mono text-[11px] text-[#6f6f6f]">
                          {entry.stage}/8
                        </span>
                        <span className="font-medium text-[#161616]">{entry.stageLabel}:</span>
                        <span className="text-[#525252]">{entry.detail}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        {entry.entireCheckpointId && (
                          <span className="bg-[#f6f2ff] px-2 py-0.5 font-mono text-[11px] font-medium text-[#491d8b]">
                            Entire-Checkpoint: {entry.entireCheckpointId}
                          </span>
                        )}
                        {entry.commitUrl && entry.commitSha && (
                          <a
                            href={entry.commitUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 font-mono text-[11px] text-[#0f62fe] hover:underline"
                          >
                            {entry.commitSha}
                            <ExternalLink size={10} />
                          </a>
                        )}
                        {entry.prUrl && (
                          <a
                            href={entry.prUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 font-mono text-[11px] text-[#0f62fe] hover:underline"
                          >
                            PR #{entry.prNumber}
                            <ExternalLink size={10} />
                          </a>
                        )}
                        {entry.jiraUrl && entry.jiraKey && (
                          <a
                            href={entry.jiraUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 font-mono text-[11px] text-[#0f62fe] hover:underline"
                          >
                            {entry.jiraKey}
                            <ExternalLink size={10} />
                          </a>
                        )}
                        {entry.slackUrl && (
                          <a
                            href={entry.slackUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-[11px] text-[#0f62fe] hover:underline"
                          >
                            Slack
                            <ExternalLink size={10} />
                          </a>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        )}
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
                        <WorkflowStrip
                          alert={alert}
                          activeStage={simStage}
                          activeFindingKey={activeFindingKey}
                        />
                        <p className="mt-2 max-w-[240px] text-xs text-[#6f6f6f]">
                          {alert.triggerReason}
                        </p>
                      </td>
                      <td className="px-4 py-4">
                        <div className="flex flex-col items-start gap-1">
                          <DeliveryBadge status={alert.slackStatus} />
                          {slackLink && (
                            <a
                              href={slackLink}
                              target="_blank"
                              rel="noreferrer"
                              onClick={(event) => event.stopPropagation()}
                              className="inline-flex items-center gap-1 text-[11px] text-[#0f62fe] hover:underline"
                            >
                              Open message
                              <ExternalLink size={11} />
                            </a>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-4">
                        <p className="text-xs">{alert.jiraStatus}</p>
                        {alert.jiraKey && (
                          <p className="mt-1 text-xs text-[#0f62fe]">{alert.jiraKey}</p>
                        )}
                      </td>
                      <td className="px-4 py-4">
                        <div className="flex flex-col items-start gap-1.5">
                          <span
                            className={`px-2.5 py-1 text-xs font-medium ${lifecycleStyles[alert.lifecycle]}`}
                          >
                            {alert.lifecycle}
                          </span>
                          <button
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              handleToggleLifecycle(alert);
                            }}
                            className="text-[11px] text-[#525252] underline-offset-2 hover:text-[#0f62fe] hover:underline"
                          >
                            {alert.lifecycle === "Resolved" ? "Reopen" : "Mark resolved"}
                          </button>
                        </div>
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
      {selected && (
        <AlertDrawer
          alert={selected}
          onClose={() => setSelected(null)}
          onToggleLifecycle={handleToggleLifecycle}
        />
      )}
    </AppShell>
  );
}
