import { useCallback, useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  CheckCircle2,
  ExternalLink,
  FileText,
  Info,
  Loader2,
  Network,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Tag,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { detectionService } from "@/services/detectionService";
import type {
  DetectionDetailResponse,
  DetectionStatus,
} from "@/types/detection";

const severityStyles: Record<string, string> = {
  critical: "border-[#FF3B30]/30 bg-[#FF3B30]/10 text-[#FF3B30]",
  high: "border-[#FF7A00]/30 bg-[#FF7A00]/10 text-[#FF7A00]",
  medium: "border-[#F5C542]/30 bg-[#F5C542]/10 text-[#F5C542]",
  low: "border-[#3B9EFF]/30 bg-[#3B9EFF]/10 text-[#3B9EFF]",
};

const severityIcons: Record<string, typeof ShieldAlert> = {
  critical: ShieldAlert,
  high: ShieldAlert,
  medium: Shield,
  low: Shield,
};

const statusActions: { label: string; status: DetectionStatus; color: string }[] = [
  { label: "Mark Investigating", status: "investigating", color: "bg-[#FF7A00] hover:bg-[#FF7A00]/90 text-white" },
  { label: "Resolve", status: "resolved", color: "bg-[#22C55E] hover:bg-[#22C55E]/90 text-white" },
  { label: "Reopen", status: "new", color: "bg-border hover:bg-muted text-foreground" },
];

function formatTimestamp(timestamp: string) {
  return new Date(timestamp).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export default function InvestigationPage() {
  const { detectionId } = useParams<{ detectionId: string }>();
  const navigate = useNavigate();

  const [detail, setDetail] = useState<DetectionDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);

  const loadDetail = useCallback(async () => {
    if (!detectionId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await detectionService.getDetection(detectionId);
      setDetail(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load detection.");
    } finally {
      setLoading(false);
    }
  }, [detectionId]);

  useEffect(() => {
    void loadDetail();
  }, [loadDetail]);

  const handleStatusChange = async (newStatus: DetectionStatus) => {
    if (!detectionId || updating) return;
    setUpdating(true);
    try {
      await detectionService.updateDetectionStatus(detectionId, newStatus);
      setDetail((prev) =>
        prev ? { ...prev, detection: { ...prev.detection, status: newStatus } } : prev,
      );
    } catch (err) {
      console.error("Failed to update status:", err);
    } finally {
      setUpdating(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="size-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div className="min-h-screen bg-background p-8">
        <div className="mx-auto max-w-2xl rounded-xl border bg-card p-8 text-center">
          <AlertTriangle className="mx-auto mb-4 size-10 text-[#FF3B30]" />
          <p className="font-medium">{error ?? "Detection not found."}</p>
          <Button variant="outline" className="mt-4" onClick={() => navigate("/monitoring")}>
            <ArrowLeft className="mr-2 size-4" />
            Back to Monitoring
          </Button>
        </div>
      </div>
    );
  }

  const { detection, analysis_run, alerts, other_detections_in_run } = detail;
  const SevIcon = severityIcons[detection.severity] ?? Shield;

  const availableActions = statusActions.filter((a) => a.status !== detection.status);

  return (
    <div className="min-h-screen bg-background p-4 md:p-6 lg:p-8">

      <div className="mx-auto max-w-5xl">

        {/* Header */}
        <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <button
              onClick={() => navigate("/monitoring")}
              className="mb-2 flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="size-4" />
              Back to Monitoring
            </button>

            <div className="flex items-center gap-3">
              <div className={`flex size-10 items-center justify-center rounded-lg border ${severityStyles[detection.severity]}`}>
                <SevIcon className="size-5" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground font-mono">{detection.id.slice(0, 12)}</p>
                <h1 className="text-2xl font-bold tracking-tight">{detection.title}</h1>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {availableActions.map((action) => (
              <Button
                key={action.status}
                onClick={() => void handleStatusChange(action.status)}
                disabled={updating}
                className={action.color}
                size="sm"
              >
                {updating ? (
                  <RefreshCw className="mr-2 size-4 animate-spin" />
                ) : null}
                {action.label}
              </Button>
            ))}
          </div>
        </div>

        {/* Meta grid */}
        <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">

          <div className="rounded-xl border bg-card p-4">
            <p className="text-xs text-muted-foreground mb-1">Severity</p>
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold uppercase ${severityStyles[detection.severity]}`}>
              {detection.severity}
            </span>
          </div>

          <div className="rounded-xl border bg-card p-4">
            <p className="text-xs text-muted-foreground mb-1">Status</p>
            <p className="font-medium capitalize">{detection.status}</p>
          </div>

          <div className="rounded-xl border bg-card p-4">
            <p className="text-xs text-muted-foreground mb-1">Confidence</p>
            <p className="text-2xl font-bold">{detection.confidence}%</p>
          </div>

          <div className="rounded-xl border bg-card p-4">
            <p className="text-xs text-muted-foreground mb-1">Detected</p>
            <p className="flex items-center gap-1.5 text-sm">
              <Calendar className="size-4 text-muted-foreground" />
              {formatTimestamp(detection.created_at)}
            </p>
          </div>

        </div>

        <div className="grid gap-6 lg:grid-cols-3">

          {/* Main column */}
          <div className="space-y-6 lg:col-span-2">

            {/* Description */}
            <div className="rounded-xl border bg-card p-5">
              <div className="mb-3 flex items-center gap-2">
                <Info className="size-4 text-muted-foreground" />
                <h2 className="font-semibold">Description</h2>
              </div>
              <p className="text-sm leading-relaxed text-muted-foreground">
                {detection.description}
              </p>
            </div>

            {/* Network Info */}
            <div className="rounded-xl border bg-card p-5">
              <div className="mb-3 flex items-center gap-2">
                <Network className="size-4 text-muted-foreground" />
                <h2 className="font-semibold">Network Details</h2>
              </div>
              <div className="grid gap-4 sm:grid-cols-3">
                <div>
                  <p className="text-xs text-muted-foreground">Source IP</p>
                  <p className="mt-1 font-mono text-sm">{detection.source_ip || "N/A"}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Destination IP</p>
                  <p className="mt-1 font-mono text-sm">{detection.destination_ip || "N/A"}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Protocol</p>
                  <p className="mt-1 text-sm">{detection.protocol || "N/A"}</p>
                </div>
              </div>
            </div>

            {/* Evidence */}
            {Object.keys(detection.evidence).length > 0 && (
              <div className="rounded-xl border bg-card p-5">
                <div className="mb-3 flex items-center gap-2">
                  <FileText className="size-4 text-muted-foreground" />
                  <h2 className="font-semibold">Evidence</h2>
                </div>
                <pre className="overflow-x-auto rounded-lg bg-muted/40 p-4 text-xs text-foreground">
                  {JSON.stringify(detection.evidence, null, 2)}
                </pre>
              </div>
            )}

            {/* Related Alerts */}
            {alerts.length > 0 && (
              <div className="rounded-xl border bg-card p-5">
                <div className="mb-3 flex items-center gap-2">
                  <AlertTriangle className="size-4 text-muted-foreground" />
                  <h2 className="font-semibold">Related Alerts ({alerts.length})</h2>
                </div>
                <div className="space-y-3">
                  {alerts.map((alert) => (
                    <div key={alert.id} className="rounded-lg border bg-muted/20 p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs font-semibold uppercase ${
                          alert.severity === "critical" ? "text-[#FF3B30]"
                            : alert.severity === "high" ? "text-[#FF7A00]"
                            : alert.severity === "medium" ? "text-[#F5C542]"
                            : "text-[#3B9EFF]"
                        }`}>
                          {alert.severity}
                        </span>
                        <span className="text-xs text-muted-foreground capitalize">{alert.status}</span>
                        <span className="text-xs text-muted-foreground ml-auto">{formatTimestamp(alert.created_at)}</span>
                      </div>
                      <p className="text-sm font-medium">{alert.title}</p>
                      <p className="text-xs text-muted-foreground mt-1">{alert.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">

            {/* Analysis Run */}
            {analysis_run && (
              <div className="rounded-xl border bg-card p-5">
                <div className="mb-3 flex items-center gap-2">
                  <Server className="size-4 text-muted-foreground" />
                  <h2 className="font-semibold">Analysis Run</h2>
                </div>
                <div className="space-y-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">File</span>
                    <span className="font-mono text-xs truncate max-w-[160px]">{analysis_run.file_name}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Events</span>
                    <span className="font-semibold">{analysis_run.event_count.toLocaleString()}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Sequences</span>
                    <span className="font-semibold">{analysis_run.sequence_count.toLocaleString()}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Status</span>
                    <span className="flex items-center gap-1.5">
                      {analysis_run.status === "completed" ? (
                        <CheckCircle2 className="size-3.5 text-[#22C55E]" />
                      ) : null}
                      <span className="capitalize">{analysis_run.status}</span>
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Submitted</span>
                    <span className="text-xs">{formatTimestamp(analysis_run.submitted_at)}</span>
                  </div>
                  {analysis_run.completed_at && (
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Completed</span>
                      <span className="text-xs">{formatTimestamp(analysis_run.completed_at)}</span>
                    </div>
                  )}
                </div>

                {other_detections_in_run > 0 && (
                  <div className="mt-4 rounded-lg bg-muted/30 p-3 text-center">
                    <p className="text-xs text-muted-foreground">
                      This run produced{" "}
                      <span className="font-semibold text-foreground">
                        {other_detections_in_run} other detection{other_detections_in_run !== 1 ? "s" : ""}
                      </span>
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Detection Type */}
            <div className="rounded-xl border bg-card p-5">
              <div className="mb-3 flex items-center gap-2">
                <Tag className="size-4 text-muted-foreground" />
                <h2 className="font-semibold">Detection Type</h2>
              </div>
              <span className="inline-flex rounded-full border border-border bg-muted/30 px-3 py-1 text-sm font-mono">
                {detection.detection_type}
              </span>
            </div>

            {/* Quick Actions */}
            <div className="rounded-xl border bg-card p-5">
              <div className="mb-3 flex items-center gap-2">
                <ExternalLink className="size-4 text-muted-foreground" />
                <h2 className="font-semibold">Quick Actions</h2>
              </div>
              <div className="space-y-2">
                <Button
                  variant="outline"
                  className="w-full justify-start"
                  size="sm"
                  onClick={() => navigate("/alerts")}
                >
                  View All Alerts
                </Button>
                <Button
                  variant="outline"
                  className="w-full justify-start"
                  size="sm"
                  onClick={() => navigate("/analysis")}
                >
                  Upload New Trace
                </Button>
              </div>
            </div>

          </div>

        </div>
      </div>
    </div>
  );
}
