import { apiClient } from "@/services/apiClient";
import type { Alert, AlertListResponse, AlertStatus } from "@/types/api";

export const alertService = {
  getAlerts: async (status?: AlertStatus): Promise<Alert[]> => {
    const query = status ? `?status=${status}` : "";
    const response = await apiClient.get<AlertListResponse>(`/alerts${query}`);
    return response.items;
  },
  updateStatus: (id: string, status: AlertStatus) =>
    apiClient.patch<Alert>(`/alerts/${id}`, { status }),
};
