import { apiClient } from "@/services/apiClient";
import type {
  Alert,
  MonitorRecordListResponse,
  MonitorRecordFilters,
  MonitoringRunDetail,
  MonitoringRunListResponse,
} from "@/types/api";

export const monitoringService = {
  getMonitoringRuns: async (): Promise<MonitoringRunDetail[]> => {
    const response =
      await apiClient.get<MonitoringRunListResponse>("/analysis-runs/monitoring");
    return response.items;
  },

  getRunDetail: async (runId: string): Promise<MonitoringRunDetail> => {
    return apiClient.get<MonitoringRunDetail>(`/analysis-runs/${runId}/detail`);
  },

  getRunAlerts: async (runId: string): Promise<Alert[]> => {
    return apiClient.get<Alert[]>(`/analysis-runs/${runId}/alerts`);
  },

  getRunRecords: async (
    runId: string,
    filters: MonitorRecordFilters = {},
  ): Promise<MonitorRecordListResponse> => {
    const params = new URLSearchParams();

    if (filters.page) params.set("page", String(filters.page));
    if (filters.page_size) params.set("page_size", String(filters.page_size));
    if (filters.recordType && filters.recordType !== "all")
      params.set("type", filters.recordType);
    if (filters.severity && filters.severity !== "all")
      params.set("severity", filters.severity);
    if (filters.search) params.set("search", filters.search);

    const qs = params.toString();
    const url = `/analysis-runs/${runId}/records${qs ? `?${qs}` : ""}`;

    return apiClient.get<MonitorRecordListResponse>(url);
  },
};
