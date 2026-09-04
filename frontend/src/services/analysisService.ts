import { apiClient } from "@/services/apiClient";
import type { AnalysisRun, AnalysisRunListResponse } from "@/types/api";

export const analysisService = {
  getRuns: async (): Promise<AnalysisRun[]> => {
    const response = await apiClient.get<AnalysisRunListResponse>("/analysis-runs");
    return response.items;
  },
  uploadHostTrace: (file: File): Promise<AnalysisRun> => {
    const formData = new FormData();
    formData.append("file", file);
    return apiClient.postForm<AnalysisRun>("/analysis-runs/host-traces", formData);
  },
};
