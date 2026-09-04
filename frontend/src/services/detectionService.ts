import { apiClient } from "@/services/apiClient";
import type {
  DetectionDetailResponse,
  Detection,
  DetectionListResponse,
  DetectionFilters,
  DetectionStatus,
} from "@/types/detection";

export const detectionService = {
  getDetections: async (
    filters: DetectionFilters = {},
  ): Promise<DetectionListResponse> => {
    const params = new URLSearchParams();

    if (filters.page) params.set("page", String(filters.page));
    if (filters.page_size) params.set("page_size", String(filters.page_size));
    if (filters.severity && filters.severity !== "all")
      params.set("severity", filters.severity);
    if (filters.search) params.set("search", filters.search);

    const qs = params.toString();
    const url = `/detections${qs ? `?${qs}` : ""}`;

    return apiClient.get<DetectionListResponse>(url);
  },

  getDetection: async (
    detectionId: string,
  ): Promise<DetectionDetailResponse> => {
    return apiClient.get<DetectionDetailResponse>(
      `/detections/${detectionId}`,
    );
  },

  updateDetectionStatus: async (
    detectionId: string,
    status: DetectionStatus,
  ): Promise<Detection> => {
    return apiClient.patch<Detection>(`/detections/${detectionId}`, {
      status,
    });
  },
};
