import { apiClient } from "@/services/apiClient";
import type { DashboardSummary, SystemSettings, SystemStatus } from "@/types/api";

export const systemService = {
  getStatus: () => apiClient.get<SystemStatus>("/system/status"),
  getDashboardSummary: () => apiClient.get<DashboardSummary>("/dashboard/summary"),
  getSettings: () => apiClient.get<SystemSettings>("/system/settings"),
  updateSettings: (settings: Pick<SystemSettings, "max_upload_mb" | "analysis_history_limit">) =>
    apiClient.patch<SystemSettings>("/system/settings", settings),
};
