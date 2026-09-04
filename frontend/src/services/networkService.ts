import { apiClient } from "./apiClient";

export interface NetworkEventRecord {
  id: string;
  analysis_run_id: string | null;
  detection_id: string | null;
  alert_id: string | null;
  timestamp: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  connection_id: string | null;
  syscall_name: string | null;
  sequence_index: number;
  event_index: number;
  description: string | null;
  created_at: string;
}

export interface NetworkEventListResponse {
  items: NetworkEventRecord[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface NetworkSummary {
  total_events: number;
  unique_source_ips: number;
  unique_destination_ips: number;
  unique_ports: number;
  protocols_observed: string[];
}

export interface NetworkIPDetail {
  ip_address: string;
  first_seen: string | null;
  last_seen: string | null;
  total_events: number;
  unique_destinations: number;
  unique_sources: number;
  unique_ports: number;
  protocols: string[];
  related_detections: number;
  related_alerts: number;
}

export interface NetworkPortRecord {
  port: number;
  protocol: string | null;
  event_count: number;
  unique_sources: number;
  unique_destinations: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface NetworkPortListResponse {
  items: NetworkPortRecord[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface NetworkProtocolRecord {
  protocol: string;
  event_count: number;
  percentage: number;
}

export interface NetworkProtocolListResponse {
  items: NetworkProtocolRecord[];
}

export interface NetworkTopTalker {
  ip_address: string;
  connection_count: number;
  unique_destinations: number;
  unique_sources: number;
  unique_ports: number;
  direction: string;
}

export interface NetworkTopTalkerListResponse {
  items: NetworkTopTalker[];
}

export interface NetworkTimelinePoint {
  timestamp: string;
  event_count: number;
}

export interface NetworkTimelineResponse {
  items: NetworkTimelinePoint[];
  interval: string;
}

export interface NetworkEventDetail {
  event: NetworkEventRecord;
  related_detections: Record<string, object>[];
  related_alerts: Record<string, object>[];
}

export interface EventFilters {
  page?: number;
  page_size?: number;
  search?: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  from_timestamp?: string;
  to_timestamp?: string;
  analysis_run_id?: string;
  detection_id?: string;
  alert_id?: string;
}

function toParams(filters: Record<string, unknown>): URLSearchParams {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) {
    if (v !== undefined && v !== null && v !== "") {
      params.set(k, String(v));
    }
  }
  return params;
}

export const networkService = {
  async getEvents(filters: EventFilters = {}): Promise<NetworkEventListResponse> {
    const params = toParams(filters as Record<string, unknown>);
    return apiClient.get<NetworkEventListResponse>(
      `/network/events?${params.toString()}`
    );
  },

  async getSummary(filters: { from_timestamp?: string; to_timestamp?: string; analysis_run_id?: string } = {}): Promise<NetworkSummary> {
    const params = toParams(filters as Record<string, unknown>);
    return apiClient.get<NetworkSummary>(
      `/network/summary?${params.toString()}`
    );
  },

  async getIPDetail(ip: string): Promise<NetworkIPDetail> {
    return apiClient.get<NetworkIPDetail>(`/network/ips/${encodeURIComponent(ip)}`);
  },

  async getPorts(filters: { page?: number; page_size?: number; from_timestamp?: string; to_timestamp?: string; analysis_run_id?: string } = {}): Promise<NetworkPortListResponse> {
    const params = toParams(filters as Record<string, unknown>);
    return apiClient.get<NetworkPortListResponse>(
      `/network/ports?${params.toString()}`
    );
  },

  async getProtocols(filters: { from_timestamp?: string; to_timestamp?: string; analysis_run_id?: string } = {}): Promise<NetworkProtocolListResponse> {
    const params = toParams(filters as Record<string, unknown>);
    return apiClient.get<NetworkProtocolListResponse>(
      `/network/protocols?${params.toString()}`
    );
  },

  async getTopTalkers(filters: { limit?: number; from_timestamp?: string; to_timestamp?: string; analysis_run_id?: string } = {}): Promise<NetworkTopTalkerListResponse> {
    const params = toParams(filters as Record<string, unknown>);
    return apiClient.get<NetworkTopTalkerListResponse>(
      `/network/top-talkers?${params.toString()}`
    );
  },

  async getTimeline(filters: { from_timestamp?: string; to_timestamp?: string; analysis_run_id?: string } = {}): Promise<NetworkTimelineResponse> {
    const params = toParams(filters as Record<string, unknown>);
    return apiClient.get<NetworkTimelineResponse>(
      `/network/timeline?${params.toString()}`
    );
  },

  async getEventDetail(eventId: string): Promise<NetworkEventDetail> {
    return apiClient.get<NetworkEventDetail>(`/network/events/${eventId}`);
  },
};
