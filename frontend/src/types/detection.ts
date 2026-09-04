export type DetectionSeverity = "critical" | "high" | "medium" | "low";
export type DetectionStatus = "new" | "investigating" | "resolved";

export interface Detection {
  id: string;
  analysis_run_id: string | null;
  detector_id?: string | null;
  detector_version?: string | null;
  detection_type: string;
  title: string;
  description: string;
  severity: DetectionSeverity;
  status: DetectionStatus;
  confidence: number;
  source_ip: string | null;
  destination_ip: string | null;
  protocol: string | null;
  evidence: Record<string, unknown>;
  source_events?: string[] | null;
  created_at: string;
}

export interface DetectionListResponse {
  items: Detection[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface DetectionFilters {
  search?: string;
  severity?: DetectionSeverity | "all";
  page?: number;
  page_size?: number;
}

export interface AnalysisRunSummary {
  id: string;
  source_type: string;
  file_name: string;
  status: string;
  event_count: number;
  sequence_count: number;
  details: Record<string, unknown>;
  submitted_at: string;
  completed_at: string | null;
}

export interface AlertSummary {
  id: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  source: string;
  created_at: string;
  updated_at: string | null;
}

export interface DetectionDetailResponse {
  detection: Detection;
  analysis_run: AnalysisRunSummary | null;
  alerts: AlertSummary[];
  other_detections_in_run: number;
}
