export interface SystemStatus {
  api_status: "online";
  database_status: "online";
  light_hids_status: "not_configured" | "ready" | "offline";
  light_hids_message: string;
}

export interface DashboardSummary {
  analysis_runs: number;
  analyzed_events: number;
  detections: number;
  open_alerts: number;
}

export interface AnalysisRun {
  id: string;
  source_type: "host_trace";
  file_name: string;
  status: "completed" | "failed" | "processing";
  event_count: number;
  sequence_count: number;
  details: { unique_system_calls?: number };
  submitted_at: string;
  completed_at: string | null;
}

export interface AnalysisRunListResponse {
  items: AnalysisRun[];
}

export type AlertSeverity = "critical" | "high" | "medium" | "low";
export type AlertStatus = "new" | "investigating" | "resolved";

export interface Alert {
  id: string;
  detection_id: string | null;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  description: string;
  source: string;
  created_at: string;
  updated_at: string | null;
}

export interface AlertListResponse {
  items: Alert[];
}

export interface SystemSettings {
  max_upload_mb: number;
  analysis_history_limit: number;
  updated_at: string | null;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  normal: number;
}

export interface MonitoringRunDetail {
  id: string;
  source_type: string;
  file_name: string;
  status: "completed" | "failed" | "processing";
  event_count: number;
  sequence_count: number;
  details: Record<string, unknown>;
  submitted_at: string;
  completed_at: string | null;
  detection_count: number;
  alert_count: number;
  severity_counts: SeverityCounts;
}

export interface MonitoringRunListResponse {
  items: MonitoringRunDetail[];
}

export type MonitorRecordType = "detection" | "network_event";

export interface MonitorRecord {
  id: string;
  record_type: MonitorRecordType;
  severity: string;
  kind: string | null;
  title: string | null;
  description: string | null;
  timestamp: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  protocol: string | null;
  detection_id: string | null;
}

export interface MonitorRecordListResponse {
  items: MonitorRecord[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface MonitorRecordFilters {
  recordType?: MonitorRecordType | "all";
  severity?: string | "all";
  search?: string;
  page?: number;
  page_size?: number;
}
