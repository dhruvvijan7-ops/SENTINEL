import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Eye,
  FileJson2,
  RefreshCw,
  Search,
  ShieldAlert,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import { monitoringService } from "@/services/monitoringService";

import type {
  Alert,
  MonitorRecord,
  MonitorRecordType,
  MonitoringRunDetail,
} from "@/types/api";


/* =========================================================
   Severity Styles
   ========================================================= */

const severityStyles: Record<string, string> = {
  critical: "border-[#FF3B30]/30 bg-[#FF3B30]/10 text-[#FF3B30]",
  high: "border-[#FF7A00]/30 bg-[#FF7A00]/10 text-[#FF7A00]",
  medium: "border-[#F5C542]/30 bg-[#F5C542]/10 text-[#F5C542]",
  low: "border-[#3B9EFF]/30 bg-[#3B9EFF]/10 text-[#3B9EFF]",
  info: "border-[#22C55E]/30 bg-[#22C55E]/10 text-[#22C55E]",
  normal: "border-muted bg-muted/40 text-muted-foreground",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={[
        "inline-flex rounded-full border px-2.5 py-1",
        "text-xs font-semibold uppercase tracking-wide",
        severityStyles[severity] ?? severityStyles.normal,
      ].join(" ")}
    >
      {severity}
    </span>
  );
}

const statusStyles: Record<string, string> = {
  completed: "text-[#22C55E]",
  failed: "text-[#FF3B30]",
  processing: "text-[#F5C542]",
};

function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`text-xs font-semibold uppercase tracking-wide ${
        statusStyles[status] ?? "text-muted-foreground"
      }`}
    >
      {status}
    </span>
  );
}


/* =========================================================
   Helpers
   ========================================================= */

function formatTimestamp(timestamp: string | null) {
  if (!timestamp) return "—";
  return new Date(timestamp).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

const RECORD_TYPE_LABELS: Record<string, string> = {
  detection: "Detection",
  network_event: "Network Event",
};

function RecordTypeBadge({ recordType }: { recordType: string }) {
  const isDetection = recordType === "detection";
  return (
    <span
      className={[
        "inline-flex rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide",
        isDetection
          ? "border-[#FF7A00]/30 bg-[#FF7A00]/10 text-[#FF7A00]"
          : "border-muted bg-muted/40 text-muted-foreground",
      ].join(" ")}
    >
      {RECORD_TYPE_LABELS[recordType] ?? recordType}
    </span>
  );
}


/* =========================================================
   Run Detail - View All Tabs
   ========================================================= */

function RunDetailView({
  run,
  onBack,
}: {
  run: MonitoringRunDetail;
  onBack: () => void;
}) {
  const [tab, setTab] = useState<"records" | "alerts">("records");
  const [recordType, setRecordType] = useState<MonitorRecordType | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [records, setRecords] = useState<MonitorRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  const loadRecords = useCallback(async () => {
    setLoading(true);
    try {
      const result = await monitoringService.getRunRecords(run.id, {
        recordType,
        severity: severityFilter,
        search,
        page,
        page_size: 20,
      });
      setRecords(result.items);
      setTotal(result.total);
      setTotalPages(result.total_pages);
    } catch (error) {
      console.error("Failed to load run records:", error);
      setRecords([]);
      setTotal(0);
      setTotalPages(1);
    } finally {
      setLoading(false);
    }
  }, [run.id, recordType, severityFilter, search, page]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadRecords();
  }, [loadRecords]);

  const loadAlerts = useCallback(async () => {
    try {
      const result = await monitoringService.getRunAlerts(run.id);
      setAlerts(result);
    } catch (error) {
      console.error("Failed to load run alerts:", error);
      setAlerts([]);
    }
  }, [run.id]);

  useEffect(() => {
    if (tab === "alerts") {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      void loadAlerts();
    }
  }, [tab, loadAlerts]);

  const severityCount = useMemo(() => {
    return run.severity_counts;
  }, [run]);

  return (
    <div className="space-y-6">
      {/* Detail header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="flex items-start gap-3">
          <Button variant="outline" size="sm" onClick={onBack}>
            <ArrowLeft className="mr-2 size-4" />
            Back
          </Button>
          <div>
            <h2 className="text-xl font-bold tracking-tight">{run.file_name}</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Submitted {formatTimestamp(run.submitted_at)}
              {" · "}
              {run.event_count.toLocaleString()} events
              {" · "}
              {run.sequence_count.toLocaleString()} sequences
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={run.status} />
          <Button variant="outline" size="sm" onClick={() => void loadRecords()}>
            <RefreshCw className="mr-2 size-4" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Run stats */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border bg-card p-5">
          <span className="text-sm text-muted-foreground">Total Events</span>
          <p className="mt-3 text-3xl font-bold">{run.event_count.toLocaleString()}</p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <span className="text-sm text-muted-foreground">Detections</span>
          <p className="mt-3 text-3xl font-bold">{run.detection_count}</p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <span className="text-sm text-muted-foreground">Alerts</span>
          <p className="mt-3 text-3xl font-bold">{run.alert_count}</p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <span className="text-sm text-muted-foreground">High+ Critical</span>
          <p className="mt-3 text-3xl font-bold text-[#FF7A00]">
            {severityCount.high + severityCount.critical}
          </p>
        </div>
      </div>

      {/* Severity distribution */}
      <div className="rounded-xl border bg-card p-5">
        <p className="mb-3 text-sm font-semibold">Severity Distribution</p>
        <div className="flex flex-wrap gap-2">
          {(["critical", "high", "medium", "low", "info", "normal"] as const).map(
            (key) => (
              <div key={key} className="flex items-center gap-2">
                <SeverityBadge severity={key} />
                <span className="text-sm font-semibold">{severityCount[key]}</span>
              </div>
            ),
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex rounded-lg border border-border bg-input p-0.5">
        <button
          onClick={() => {
            setTab("records");
            setPage(1);
          }}
          className={[
            "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
            tab === "records"
              ? "bg-primary text-primary-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground",
          ].join(" ")}
        >
          View All
        </button>
        <button
          onClick={() => {
            setTab("alerts");
            setPage(1);
          }}
          className={[
            "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
            tab === "alerts"
              ? "bg-primary text-primary-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground",
          ].join(" ")}
        >
          Alerts ({run.alert_count})
        </button>
      </div>

      {tab === "alerts" ? (
        <div className="overflow-hidden rounded-xl border bg-card">
          <div className="border-b px-5 py-4">
            <h2 className="font-semibold">Run Alerts</h2>
            <p className="text-sm text-muted-foreground">
              {alerts.length} alert{alerts.length !== 1 ? "s" : ""} associated with this run
            </p>
          </div>
          {alerts.length === 0 ? (
            <div className="flex h-48 flex-col items-center justify-center">
              <CheckCircle2 className="mb-3 size-10 text-[#22C55E]" />
              <p className="font-medium">No alerts for this run</p>
            </div>
          ) : (
            <div className="divide-y">
              {alerts.map((alert) => (
                <div key={alert.id} className="flex flex-col gap-2 p-5 lg:flex-row lg:items-center">
                  <div className="min-w-0 flex-1">
                    <div className="mb-2 flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={String(alert.severity)} />
                      <span className="text-xs text-muted-foreground">{alert.id.slice(0, 8)}</span>
                    </div>
                    <h3 className="font-semibold">{String(alert.title)}</h3>
                    {alert.description && (
                      <p className="mt-1 text-sm text-muted-foreground">{String(alert.description)}</p>
                    )}
                  </div>
                  <div className="text-right text-xs text-muted-foreground">
                    <p>{formatTimestamp(String(alert.created_at))}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border bg-card">
          {/* Filters */}
          <div className="border-b px-5 py-4">
            <h2 className="font-semibold">All Records</h2>
            <p className="text-sm text-muted-foreground">
              {total} record{total !== 1 ? "s" : ""} found in this run
            </p>

            <div className="mt-4 flex flex-col gap-3 lg:flex-row lg:items-center">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={search}
                  onChange={(event) => {
                    setSearch(event.target.value);
                    setPage(1);
                  }}
                  placeholder="Search by IP, type, title..."
                  className="pl-9"
                />
              </div>
              <select
                value={recordType}
                onChange={(event) => {
                  setRecordType(event.target.value as MonitorRecordType | "all");
                  setPage(1);
                }}
                className="h-10 rounded-md border border-border bg-input px-3 text-sm text-foreground outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="all">All types</option>
                <option value="detection">Detections</option>
                <option value="network_event">Network Events</option>
              </select>
              <select
                value={severityFilter}
                onChange={(event) => {
                  setSeverityFilter(event.target.value);
                  setPage(1);
                }}
                className="h-10 rounded-md border border-border bg-input px-3 text-sm text-foreground outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
                <option value="normal">Normal</option>
              </select>
            </div>
          </div>

          {/* Loading */}
          {loading ? (
            <div className="flex h-64 items-center justify-center">
              <RefreshCw className="size-6 animate-spin text-primary" />
            </div>
          ) : records.length === 0 ? (
            <div className="flex h-64 flex-col items-center justify-center">
              <FileJson2 className="mb-3 size-10 text-muted-foreground" />
              <p className="font-medium">No records found</p>
              <p className="text-sm text-muted-foreground">
                Try changing your filters.
              </p>
            </div>
          ) : (
            <div className="divide-y">
              {records.map((record) => (
                <div
                  key={`${record.record_type}-${record.id}`}
                  className="flex flex-col gap-3 p-5 transition-colors hover:bg-muted/40 lg:flex-row lg:items-center"
                >
                  <div className="flex flex-wrap items-center gap-2 lg:w-56">
                    <RecordTypeBadge recordType={record.record_type} />
                    <SeverityBadge severity={record.severity} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="font-semibold">
                        {record.title ?? record.kind ?? "Record"}
                      </h3>
                      {record.kind && record.kind !== record.title && (
                        <span className="text-xs text-muted-foreground">{record.kind}</span>
                      )}
                    </div>
                    {record.description && record.description !== record.title && (
                      <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">
                        {record.description}
                      </p>
                    )}
                    <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted-foreground">
                      {record.source_ip && (
                        <span>
                          Source: <span className="font-mono text-foreground">{record.source_ip}</span>
                        </span>
                      )}
                      {record.destination_ip && (
                        <span>
                          Destination: <span className="font-mono text-foreground">{record.destination_ip}</span>
                        </span>
                      )}
                      {record.protocol && (
                        <span>
                          Protocol: <span className="text-foreground">{record.protocol}</span>
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {formatTimestamp(record.timestamp)}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between border-t px-5 py-3">
              <p className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  <ChevronLeft className="size-4" />
                  Prev
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                >
                  Next
                  <ChevronRight className="size-4" />
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}


/* =========================================================
   Monitoring Page
   ========================================================= */

export default function MonitoringPage() {
  const [runs, setRuns] = useState<MonitoringRunDetail[]>([]);
  const [selectedRun, setSelectedRun] = useState<MonitoringRunDetail | null>(null);
  const [loading, setLoading] = useState(true);

  const loadRuns = useCallback(async () => {
    setLoading(true);
    try {
      const result = await monitoringService.getMonitoringRuns();
      setRuns(result);
    } catch (error) {
      console.error("Failed to load monitoring runs:", error);
      setRuns([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadRuns();
  }, [loadRuns]);

  const aggregates = useMemo(() => {
    const totalDetections = runs.reduce((sum, run) => sum + run.detection_count, 0);
    const totalAlerts = runs.reduce((sum, run) => sum + run.alert_count, 0);
    const critical = runs.reduce((sum, run) => sum + run.severity_counts.critical, 0);
    const high = runs.reduce((sum, run) => sum + run.severity_counts.high, 0);
    const medium = runs.reduce((sum, run) => sum + run.severity_counts.medium, 0);
    const totalEvents = runs.reduce((sum, run) => sum + run.event_count, 0);
    return { totalDetections, totalAlerts, critical, high, medium, totalEvents };
  }, [runs]);

  if (selectedRun) {
    return (
      <div className="min-h-screen bg-background p-4 md:p-6 lg:p-8">
        <RunDetailView
          run={selectedRun}
          onBack={() => setSelectedRun(null)}
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background p-4 md:p-6 lg:p-8">

      {/* =================================================
          Page Header
          ================================================= */}

      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2">
            <Activity className="size-5 text-primary" />
            <span className="text-sm font-medium text-primary">
              Network Monitoring
            </span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight">
            Detection Monitoring
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Monitor analysis runs, review LIGHT-HIDS detections, and trace events to alerts.
          </p>
        </div>

        <Button
          variant="outline"
          onClick={() => void loadRuns()}
          disabled={loading}
        >
          <RefreshCw
            className={[
              "mr-2 size-4",
              loading ? "animate-spin" : "",
            ].join(" ")}
          />
          Refresh
        </Button>
      </div>

      {/* =================================================
          Statistics
          ================================================= */}

      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border bg-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Total Events</span>
            <Activity className="size-5 text-primary" />
          </div>
          <p className="mt-3 text-3xl font-bold">{aggregates.totalEvents.toLocaleString()}</p>
        </div>

        <div className="rounded-xl border bg-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Total Detections</span>
            <ShieldAlert className="size-5 text-primary" />
          </div>
          <p className="mt-3 text-3xl font-bold">{aggregates.totalDetections}</p>
        </div>

        <div className="rounded-xl border bg-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Critical</span>
            <AlertTriangle className="size-5 text-[#FF3B30]" />
          </div>
          <p className="mt-3 text-3xl font-bold text-[#FF3B30]">{aggregates.critical}</p>
        </div>

        <div className="rounded-xl border bg-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">High</span>
            <AlertTriangle className="size-5 text-[#FF7A00]" />
          </div>
          <p className="mt-3 text-3xl font-bold text-[#FF7A00]">{aggregates.high}</p>
        </div>
      </div>

      {/* =================================================
          Monitoring History
          ================================================= */}

      <div className="overflow-hidden rounded-xl border bg-card">
        <div className="border-b px-5 py-4">
          <h2 className="font-semibold">Monitoring History</h2>
          <p className="text-sm text-muted-foreground">
            Analysis runs persisted in the backend, newest first. Select a run for full traceability.
          </p>
        </div>

        {loading ? (
          <div className="flex h-64 items-center justify-center">
            <RefreshCw className="size-6 animate-spin text-primary" />
          </div>
        ) : runs.length === 0 ? (
          <div className="flex h-64 flex-col items-center justify-center">
            <CheckCircle2 className="mb-3 size-10 text-[#22C55E]" />
            <p className="font-medium">No analysis runs yet</p>
            <p className="text-sm text-muted-foreground">
              Run a host trace analysis to see monitoring history here.
            </p>
          </div>
        ) : (
          <div className="divide-y">
            {runs.map((run) => (
              <div
                key={run.id}
                className="flex flex-col gap-4 p-5 transition-colors hover:bg-muted/40 lg:flex-row lg:items-center"
              >
                <div className="min-w-0 flex-1">
                  <div className="mb-2 flex flex-wrap items-center gap-2">
                    <StatusBadge status={run.status} />
                    <span className="text-xs text-muted-foreground">{run.id.slice(0, 8)}</span>
                  </div>

                  <h3 className="font-semibold">{run.file_name}</h3>

                  <p className="mt-1 text-sm text-muted-foreground">
                    {formatTimestamp(run.submitted_at)}
                  </p>

                  <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted-foreground">
                    <span>Events: <span className="font-medium text-foreground">{run.event_count.toLocaleString()}</span></span>
                    <span>Detections: <span className="font-medium text-foreground">{run.detection_count}</span></span>
                    <span>Alerts: <span className="font-medium text-foreground">{run.alert_count}</span></span>
                  </div>

                  {(run.detection_count > 0 || run.alert_count > 0) && (
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      {(["critical", "high", "medium", "low"] as const)
                        .filter((key) => run.severity_counts[key] > 0)
                        .map((key) => (
                          <span key={key} className="inline-flex items-center gap-1.5">
                            <SeverityBadge severity={key} />
                            <span className="text-xs font-semibold">{run.severity_counts[key]}</span>
                          </span>
                        ))}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-3 lg:w-40 lg:justify-end">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setSelectedRun(run)}
                  >
                    <Eye className="mr-2 size-4" />
                    View Details
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  );
}
