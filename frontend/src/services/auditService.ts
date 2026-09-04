import { apiClient } from "@/services/apiClient";

export interface AuditLogRecord {
  id: string;
  timestamp: string;
  created_at: string;
  actor_user_id: string | null;
  actor_email: string | null;
  actor_type: string;
  category: string;
  action: string;
  result: string;
  severity: string;
  resource_type: string | null;
  resource_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  request_id: string | null;
  metadata_json: Record<string, unknown> | null;
  description: string | null;
}

export interface AuditLogListResponse {
  items: AuditLogRecord[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface AuditLogFilters {
  page?: number;
  page_size?: number;
  category?: string;
  action?: string;
  actor_user_id?: string;
  actor_email?: string;
  resource_type?: string;
  resource_id?: string;
  result?: string;
  severity?: string;
  user_agent?: string;
  ip_address?: string;
  from_timestamp?: string;
  to_timestamp?: string;
  search?: string;
  sort_by?: string;
  sort_order?: string;
}

export const AUDIT_SEVERITIES = [
  { value: "", label: "All Severities" },
  { value: "info", label: "Info" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
] as const;

export const AUDIT_CATEGORIES = [
  { value: "", label: "All Categories" },
  { value: "AUTHENTICATION", label: "Authentication" },
  { value: "USER_MANAGEMENT", label: "User Management" },
  { value: "INGESTION", label: "Ingestion" },
  { value: "ANALYSIS", label: "Analysis" },
  { value: "DETECTION", label: "Detection" },
  { value: "ALERT", label: "Alert" },
  { value: "SETTINGS", label: "Settings" },
  { value: "ADMINISTRATION", label: "Administration" },
  { value: "SYSTEM", label: "System" },
  { value: "NETWORK", label: "Network" },
] as const;

export const AUDIT_ACTIONS_BY_CATEGORY: Record<string, { value: string; label: string }[]> = {
  AUTHENTICATION: [
    { value: "", label: "All Actions" },
    { value: "LOGIN_SUCCESS", label: "Login Success" },
    { value: "LOGIN_FAILED", label: "Login Failed" },
    { value: "LOGOUT", label: "Logout" },
    { value: "REGISTRATION", label: "Registration" },
    { value: "PASSWORD_RESET_REQUESTED", label: "Password Reset Requested" },
    { value: "PASSWORD_RESET_COMPLETED", label: "Password Reset Completed" },
    { value: "PASSWORD_CHANGED", label: "Password Changed" },
  ],
  USER_MANAGEMENT: [
    { value: "", label: "All Actions" },
    { value: "USER_CREATED", label: "User Created" },
    { value: "USER_UPDATED", label: "User Updated" },
    { value: "USER_ACTIVATED", label: "User Activated" },
    { value: "USER_DEACTIVATED", label: "User Deactivated" },
    { value: "USER_ROLE_CHANGED", label: "User Role Changed" },
  ],
  INGESTION: [
    { value: "", label: "All Actions" },
    { value: "JSON_UPLOAD", label: "JSON Upload" },
    { value: "CSV_UPLOAD", label: "CSV Upload" },
    { value: "UPLOAD_REJECTED", label: "Upload Rejected" },
    { value: "VALIDATION_STARTED", label: "Validation Started" },
    { value: "VALIDATION_COMPLETED", label: "Validation Completed" },
    { value: "VALIDATION_FAILED", label: "Validation Failed" },
  ],
  ANALYSIS: [
    { value: "", label: "All Actions" },
    { value: "ANALYSIS_STARTED", label: "Analysis Started" },
    { value: "ANALYSIS_COMPLETED", label: "Analysis Completed" },
    { value: "ANALYSIS_FAILED", label: "Analysis Failed" },
  ],
  DETECTION: [
    { value: "", label: "All Actions" },
    { value: "DETECTION_CREATED", label: "Detection Created" },
    { value: "DETECTION_VIEWED", label: "Detection Viewed" },
    { value: "DETECTION_INVESTIGATED", label: "Detection Investigated" },
    { value: "DETECTION_STATUS_CHANGED", label: "Detection Status Changed" },
  ],
  ALERT: [
    { value: "", label: "All Actions" },
    { value: "ALERT_CREATED", label: "Alert Created" },
    { value: "ALERT_VIEWED", label: "Alert Viewed" },
    { value: "ALERT_ACKNOWLEDGED", label: "Alert Acknowledged" },
    { value: "ALERT_ASSIGNED", label: "Alert Assigned" },
    { value: "ALERT_ESCALATED", label: "Alert Escalated" },
    { value: "ALERT_STATUS_CHANGED", label: "Alert Status Changed" },
    { value: "ALERT_RESOLVED", label: "Alert Resolved" },
    { value: "ALERT_REOPENED", label: "Alert Reopened" },
    { value: "ALERT_ARCHIVED", label: "Alert Archived" },
  ],
  SETTINGS: [
    { value: "", label: "All Actions" },
    { value: "SYSTEM_SETTING_CHANGED", label: "System Setting Changed" },
    { value: "DETECTION_THRESHOLD_CHANGED", label: "Detection Threshold Changed" },
    { value: "SECURITY_SETTING_CHANGED", label: "Security Setting Changed" },
  ],
  ADMINISTRATION: [
    { value: "", label: "All Actions" },
    { value: "SYSTEM_CONFIGURATION_CHANGED", label: "Configuration Changed" },
  ],
  SYSTEM: [
    { value: "", label: "All Actions" },
  ],
  NETWORK: [
    { value: "", label: "All Actions" },
    { value: "NETWORK_DATA_VIEWED", label: "Network Data Viewed" },
    { value: "IP_INVESTIGATION_VIEWED", label: "IP Investigation Viewed" },
    { value: "PORT_INVESTIGATION_VIEWED", label: "Port Investigation Viewed" },
    { value: "NETWORK_EVENT_VIEWED", label: "Network Event Viewed" },
  ],
};

export const TIME_PRESETS = [
  { label: "Today", getRange: () => ({ from: startOfDay(), to: endOfDay() }) },
  { label: "Yesterday", getRange: () => ({ from: startOfDay(-1), to: endOfDay(-1) }) },
  { label: "Last 24h", getRange: () => ({ from: hoursAgo(24), to: now() }) },
  { label: "Last 7 days", getRange: () => ({ from: daysAgo(7), to: now() }) },
  { label: "Last 30 days", getRange: () => ({ from: daysAgo(30), to: now() }) },
  { label: "This month", getRange: () => ({ from: startOfMonth(), to: now() }) },
  { label: "Previous month", getRange: () => ({ from: startOfPrevMonth(), to: endOfPrevMonth() }) },
] as const;

function now(): string {
  return new Date().toISOString();
}

function hoursAgo(h: number): string {
  return new Date(Date.now() - h * 3600_000).toISOString();
}

function daysAgo(d: number): string {
  return new Date(Date.now() - d * 86400_000).toISOString();
}

function startOfDay(offset = 0): string {
  const d = new Date();
  d.setDate(d.getDate() + offset);
  d.setHours(0, 0, 0, 0);
  return d.toISOString();
}

function endOfDay(offset = 0): string {
  const d = new Date();
  d.setDate(d.getDate() + offset);
  d.setHours(23, 59, 59, 999);
  return d.toISOString();
}

function startOfMonth(): string {
  const d = new Date();
  d.setDate(1);
  d.setHours(0, 0, 0, 0);
  return d.toISOString();
}

function startOfPrevMonth(): string {
  const d = new Date();
  d.setDate(0);
  d.setDate(1);
  d.setHours(0, 0, 0, 0);
  return d.toISOString();
}

function endOfPrevMonth(): string {
  const d = new Date();
  d.setDate(0);
  d.setHours(23, 59, 59, 999);
  return d.toISOString();
}

export const auditService = {
  getAuditLogs: async (filters: AuditLogFilters = {}): Promise<AuditLogListResponse> => {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== null && value !== "") {
        params.set(key, String(value));
      }
    }
    const qs = params.toString();
    return apiClient.get<AuditLogListResponse>(`/audit-logs${qs ? `?${qs}` : ""}`);
  },

  getAuditLog: async (logId: string): Promise<AuditLogRecord> => {
    return apiClient.get<AuditLogRecord>(`/audit-logs/${logId}`);
  },

  exportCsv: async (filters: AuditLogFilters = {}): Promise<void> => {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== null && value !== "") {
        params.set(key, String(value));
      }
    }
    const qs = params.toString();
    const token = localStorage.getItem("sentinel-token");
    const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
    const res = await fetch(
      `${API_BASE_URL}/api/audit-logs/export${qs ? `?${qs}` : ""}`,
      {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      },
    );
    if (!res.ok) {
      throw new Error("Failed to export audit logs.");
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "audit-logs.csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};
