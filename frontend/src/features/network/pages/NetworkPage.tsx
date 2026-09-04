import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Activity, Globe, Layers, Network as NetworkIcon, Server, Radio, ArrowUpDown, ChevronLeft, ChevronRight, X } from "lucide-react";

import { networkService } from "@/services/networkService";
import type {
  NetworkEventListResponse,
  NetworkSummary,
  NetworkIPDetail,
  NetworkPortRecord,
  NetworkProtocolRecord,
  NetworkTopTalker,
  NetworkTimelinePoint,
  NetworkEventDetail,
} from "@/services/networkService";

type Tab = "overview" | "events" | "ips" | "ports" | "protocols" | "talkers" | "timeline";

const TABS: { key: Tab; label: string; icon: React.ReactNode }[] = [
  { key: "overview", label: "Overview", icon: <Activity className="size-4" /> },
  { key: "events", label: "Events", icon: <Globe className="size-4" /> },
  { key: "ips", label: "IP Investigation", icon: <Server className="size-4" /> },
  { key: "ports", label: "Ports", icon: <Radio className="size-4" /> },
  { key: "protocols", label: "Protocols", icon: <Layers className="size-4" /> },
  { key: "talkers", label: "Top Talkers", icon: <ArrowUpDown className="size-4" /> },
  { key: "timeline", label: "Timeline", icon: <NetworkIcon className="size-4" /> },
];

function formatTs(ts: string | null | undefined) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
      <div className="text-xs text-neutral-500">{label}</div>
      <div className="mt-1 text-2xl font-bold text-white">{value}</div>
    </div>
  );
}

function Pagination({
  page,
  totalPages,
  onChange,
}: {
  page: number;
  totalPages: number;
  onChange: (p: number) => void;
}) {
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center gap-2 text-sm text-neutral-400">
      <button
        disabled={page <= 1}
        onClick={() => onChange(page - 1)}
        className="rounded bg-white/[0.06] px-2 py-1 disabled:opacity-30"
      >
        <ChevronLeft className="size-4" />
      </button>
      <span>
        Page {page} of {totalPages}
      </span>
      <button
        disabled={page >= totalPages}
        onClick={() => onChange(page + 1)}
        className="rounded bg-white/[0.06] px-2 py-1 disabled:opacity-30"
      >
        <ChevronRight className="size-4" />
      </button>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-neutral-500">
      <Globe className="mb-3 size-10 opacity-40" />
      <p>{text}</p>
    </div>
  );
}

function LoadingBar() {
  return (
    <div className="h-0.5 w-full animate-pulse bg-gradient-to-r from-transparent via-primary/40 to-transparent" />
  );
}

function JsonModal({
  data,
  onClose,
}: {
  data: unknown;
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="relative max-h-[80vh] w-full max-w-2xl overflow-auto rounded-xl border border-white/[0.08] bg-neutral-900 p-6">
        <button onClick={onClose} className="absolute right-3 top-3 text-neutral-400 hover:text-white">
          <X className="size-5" />
        </button>
        <pre className="whitespace-pre-wrap text-xs text-neutral-300">
          {JSON.stringify(data, null, 2)}
        </pre>
      </div>
    </div>
  );
}

function EventDetailModal({
  detail,
  onClose,
}: {
  detail: NetworkEventDetail | null;
  onClose: () => void;
}) {
  if (!detail) return null;
  const e = detail.event;
  return (
    <JsonModal
      data={{
        event: {
          id: e.id,
          timestamp: e.timestamp,
          source_ip: e.source_ip,
          destination_ip: e.destination_ip,
          source_port: e.source_port,
          destination_port: e.destination_port,
          protocol: e.protocol,
          connection_id: e.connection_id,
          syscall_name: e.syscall_name,
          description: e.description,
          analysis_run_id: e.analysis_run_id,
        },
        related_detections: detail.related_detections,
        related_alerts: detail.related_alerts,
      }}
      onClose={onClose}
    />
  );
}

function IPDetailModal({
  detail,
  onClose,
}: {
  detail: NetworkIPDetail | null;
  onClose: () => void;
}) {
  if (!detail) return null;
  return (
    <JsonModal
      data={{
        ip_address: detail.ip_address,
        first_seen: detail.first_seen,
        last_seen: detail.last_seen,
        total_events: detail.total_events,
        unique_destinations: detail.unique_destinations,
        unique_sources: detail.unique_sources,
        unique_ports: detail.unique_ports,
        protocols: detail.protocols,
        related_detections: detail.related_detections,
        related_alerts: detail.related_alerts,
      }}
      onClose={onClose}
    />
  );
}

export default function NetworkPage() {
  const [tab, setTab] = useState<Tab>("overview");
  const [loading, setLoading] = useState(true);

  const [summary, setSummary] = useState<NetworkSummary | null>(null);
  const [events, setEvents] = useState<NetworkEventListResponse | null>(null);
  const [ports, setPorts] = useState<NetworkPortRecord[]>([]);
  const [portsTotal, setPortsTotal] = useState(0);
  const [portsPages, setPortsPages] = useState(1);
  const [protocols, setProtocols] = useState<NetworkProtocolRecord[]>([]);
  const [talkers, setTalkers] = useState<NetworkTopTalker[]>([]);
  const [timeline, setTimeline] = useState<NetworkTimelinePoint[]>([]);
  const [timelineInterval, setTimelineInterval] = useState("none");

  const [eventPage, setEventPage] = useState(1);
  const [portPage, setPortPage] = useState(1);
  const [eventSearch, setEventSearch] = useState("");
  const [eventSearchInput, setEventSearchInput] = useState("");
  const [srcIpFilter, setSrcIpFilter] = useState("");
  const [dstIpFilter, setDstIpFilter] = useState("");
  const [portFilter, setPortFilter] = useState("");
  const [protoFilter, setProtoFilter] = useState("");
  const [ipSearchInput, setIpSearchInput] = useState("");
  const [portSearchInput, setPortSearchInput] = useState("");

  const [eventDetail, setEventDetail] = useState<NetworkEventDetail | null>(null);
  const [ipDetail, setIpDetail] = useState<NetworkIPDetail | null>(null);

  const loadSummary = useCallback(async () => {
    try {
      setSummary(await networkService.getSummary());
    } catch {
      toast.error("Failed to load network summary");
    }
  }, []);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const data = await networkService.getEvents({
        page: eventPage,
        page_size: 20,
        search: eventSearch || undefined,
        source_ip: srcIpFilter || undefined,
        destination_ip: dstIpFilter || undefined,
        destination_port: portFilter ? Number(portFilter) : undefined,
        protocol: protoFilter || undefined,
      });
      setEvents(data);
    } catch {
      toast.error("Failed to load network events");
    } finally {
      setLoading(false);
    }
  }, [eventPage, eventSearch, srcIpFilter, dstIpFilter, portFilter, protoFilter]);

  const loadPorts = useCallback(async () => {
    setLoading(true);
    try {
      const data = await networkService.getPorts({ page: portPage, page_size: 20 });
      setPorts(data.items);
      setPortsTotal(data.total);
      setPortsPages(data.total_pages);
    } catch {
      toast.error("Failed to load port data");
    } finally {
      setLoading(false);
    }
  }, [portPage]);

  const loadProtocols = useCallback(async () => {
    setLoading(true);
    try {
      const data = await networkService.getProtocols();
      setProtocols(data.items);
    } catch {
      toast.error("Failed to load protocol data");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadTalkers = useCallback(async () => {
    setLoading(true);
    try {
      const data = await networkService.getTopTalkers({ limit: 25 });
      setTalkers(data.items);
    } catch {
      toast.error("Failed to load top talkers");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadTimeline = useCallback(async () => {
    setLoading(true);
    try {
      const data = await networkService.getTimeline();
      setTimeline(data.items);
      setTimelineInterval(data.interval);
    } catch {
      toast.error("Failed to load timeline");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  useEffect(() => {
    if (tab === "events") loadEvents();
    else if (tab === "ports") loadPorts();
    else if (tab === "protocols") loadProtocols();
    else if (tab === "talkers") loadTalkers();
    else if (tab === "timeline") loadTimeline();
  }, [tab, loadEvents, loadPorts, loadProtocols, loadTalkers, loadTimeline]);

  const handleEventSearch = () => {
    setEventPage(1);
    setEventSearch(eventSearchInput);
  };

  const handleIPSearch = async () => {
    if (!ipSearchInput.trim()) return;
    try {
      const data = await networkService.getIPDetail(ipSearchInput.trim());
      setIpDetail(data);
    } catch {
      toast.error("Failed to load IP details");
    }
  };

  const handlePortSearch = async () => {
    if (!portSearchInput.trim()) return;
    const portNum = Number(portSearchInput.trim());
    if (isNaN(portNum)) {
      toast.error("Please enter a valid port number");
      return;
    }
    setLoading(true);
    try {
      const data = await networkService.getEvents({ destination_port: portNum, page_size: 100 });
      setEvents(data);
    } catch {
      toast.error("Failed to load events for port");
    } finally {
      setLoading(false);
    }
  };

  const handleEventClick = async (id: string) => {
    try {
      const data = await networkService.getEventDetail(id);
      setEventDetail(data);
    } catch {
      toast.error("Failed to load event detail");
    }
  };

  const maxTimeline = useMemo(() => {
    if (!timeline.length) return 1;
    return Math.max(...timeline.map((t) => t.event_count), 1);
  }, [timeline]);

  const maxTalker = useMemo(() => {
    if (!talkers.length) return 1;
    return Math.max(...talkers.map((t) => t.connection_count), 1);
  }, [talkers]);

  return (
    <div className="flex flex-col gap-6 p-6">
      <div>
        <h1 className="text-xl font-bold text-white">Network Analysis</h1>
        <p className="text-sm text-neutral-500">
          Investigate network events, connections, and traffic patterns from uploaded analysis data.
        </p>
      </div>

      <div className="flex flex-wrap gap-1 rounded-xl border border-white/[0.06] bg-white/[0.02] p-1">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
              tab === t.key
                ? "bg-primary/20 text-primary"
                : "text-neutral-400 hover:text-white hover:bg-white/[0.04]"
            }`}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>

      {loading && <LoadingBar />}

      {tab === "overview" && summary && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
            <StatCard label="Total Events" value={summary.total_events} />
            <StatCard label="Unique Source IPs" value={summary.unique_source_ips} />
            <StatCard label="Unique Dest IPs" value={summary.unique_destination_ips} />
            <StatCard label="Unique Ports" value={summary.unique_ports} />
            <StatCard label="Protocols" value={summary.protocols_observed.length} />
          </div>
          {summary.protocols_observed.length > 0 && (
            <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
              <h3 className="mb-2 text-sm font-medium text-neutral-400">Observed Protocols</h3>
              <div className="flex flex-wrap gap-2">
                {summary.protocols_observed.map((p) => (
                  <span key={p} className="rounded-md bg-primary/10 px-2 py-1 text-xs text-primary">
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}
          {summary.total_events === 0 && (
            <Empty text="No network events found. Upload a trace file with network data to begin analysis." />
          )}
        </div>
      )}

      {tab === "events" && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label className="mb-1 block text-xs text-neutral-500">Search</label>
              <input
                value={eventSearchInput}
                onChange={(e) => setEventSearchInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleEventSearch()}
                placeholder="IP, protocol, connection..."
                className="h-9 rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 text-sm text-white placeholder:text-neutral-600"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-neutral-500">Source IP</label>
              <input
                value={srcIpFilter}
                onChange={(e) => { setSrcIpFilter(e.target.value); setEventPage(1); }}
                placeholder="e.g. 10.0.0.1"
                className="h-9 rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 text-sm text-white placeholder:text-neutral-600"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-neutral-500">Destination IP</label>
              <input
                value={dstIpFilter}
                onChange={(e) => { setDstIpFilter(e.target.value); setEventPage(1); }}
                placeholder="e.g. 192.168.1.1"
                className="h-9 rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 text-sm text-white placeholder:text-neutral-600"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-neutral-500">Dest Port</label>
              <input
                value={portFilter}
                onChange={(e) => { setPortFilter(e.target.value); setEventPage(1); }}
                placeholder="443"
                className="h-9 w-20 rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 text-sm text-white placeholder:text-neutral-600"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-neutral-500">Protocol</label>
              <input
                value={protoFilter}
                onChange={(e) => { setProtoFilter(e.target.value); setEventPage(1); }}
                placeholder="TCP"
                className="h-9 w-24 rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 text-sm text-white placeholder:text-neutral-600"
              />
            </div>
            <button
              onClick={handleEventSearch}
              className="h-9 rounded-lg bg-primary/20 px-4 text-sm text-primary hover:bg-primary/30"
            >
              Search
            </button>
          </div>

          {events && events.items.length > 0 ? (
            <>
              <div className="text-xs text-neutral-500">{events.total} events found</div>
              <div className="overflow-x-auto rounded-xl border border-white/[0.06]">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-left text-xs text-neutral-500">
                      <th className="px-4 py-3">Timestamp</th>
                      <th className="px-4 py-3">Source</th>
                      <th className="px-4 py-3">Destination</th>
                      <th className="px-4 py-3">Src Port</th>
                      <th className="px-4 py-3">Dst Port</th>
                      <th className="px-4 py-3">Protocol</th>
                      <th className="px-4 py-3">Detection</th>
                      <th className="px-4 py-3">Alert</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.items.map((ev) => (
                      <tr
                        key={ev.id}
                        onClick={() => handleEventClick(ev.id)}
                        className="cursor-pointer border-b border-white/[0.03] hover:bg-white/[0.02]"
                      >
                        <td className="px-4 py-2.5 text-neutral-300">{formatTs(ev.timestamp)}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-blue-400">{ev.source_ip ?? "—"}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-orange-400">{ev.destination_ip ?? "—"}</td>
                        <td className="px-4 py-2.5 text-neutral-400">{ev.source_port ?? "—"}</td>
                        <td className="px-4 py-2.5 text-neutral-400">{ev.destination_port ?? "—"}</td>
                        <td className="px-4 py-2.5">
                          {ev.protocol ? (
                            <span className="rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary">{ev.protocol}</span>
                          ) : (
                            "—"
                          )}
                        </td>
                        <td className="px-4 py-2.5">
                          {ev.detection_id ? (
                            <span className="rounded bg-red-500/10 px-1.5 py-0.5 text-xs text-red-400">Yes</span>
                          ) : (
                            <span className="text-neutral-600">—</span>
                          )}
                        </td>
                        <td className="px-4 py-2.5">
                          {ev.alert_id ? (
                            <span className="rounded bg-orange-500/10 px-1.5 py-0.5 text-xs text-orange-400">Yes</span>
                          ) : (
                            <span className="text-neutral-600">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={events.page} totalPages={events.total_pages} onChange={setEventPage} />
            </>
          ) : (
            !loading && <Empty text="No network events match the current filters." />
          )}
        </div>
      )}

      {tab === "ips" && (
        <div className="space-y-4">
          <div className="flex items-end gap-3">
            <div>
              <label className="mb-1 block text-xs text-neutral-500">Investigate IP</label>
              <input
                value={ipSearchInput}
                onChange={(e) => setIpSearchInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleIPSearch()}
                placeholder="e.g. 10.0.0.1"
                className="h-9 rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 text-sm text-white placeholder:text-neutral-600"
              />
            </div>
            <button
              onClick={handleIPSearch}
              className="h-9 rounded-lg bg-primary/20 px-4 text-sm text-primary hover:bg-primary/30"
            >
              Investigate
            </button>
          </div>

          {ipDetail ? (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-white">{ipDetail.ip_address}</h3>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
                <StatCard label="First Seen" value={formatTs(ipDetail.first_seen)} />
                <StatCard label="Last Seen" value={formatTs(ipDetail.last_seen)} />
                <StatCard label="Total Events" value={ipDetail.total_events} />
                <StatCard label="Unique Destinations" value={ipDetail.unique_destinations} />
                <StatCard label="Unique Sources" value={ipDetail.unique_sources} />
                <StatCard label="Unique Ports" value={ipDetail.unique_ports} />
                <StatCard label="Related Detections" value={ipDetail.related_detections} />
                <StatCard label="Related Alerts" value={ipDetail.related_alerts} />
              </div>
              {ipDetail.protocols.length > 0 && (
                <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
                  <h4 className="mb-2 text-sm font-medium text-neutral-400">Protocols Used</h4>
                  <div className="flex flex-wrap gap-2">
                    {ipDetail.protocols.map((p) => (
                      <span key={p} className="rounded-md bg-primary/10 px-2 py-1 text-xs text-primary">{p}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <Empty text="Enter an IP address to investigate its network activity." />
          )}
        </div>
      )}

      {tab === "ports" && (
        <div className="space-y-4">
          <div className="flex items-end gap-3">
            <div>
              <label className="mb-1 block text-xs text-neutral-500">Investigate Port</label>
              <input
                value={portSearchInput}
                onChange={(e) => setPortSearchInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handlePortSearch()}
                placeholder="e.g. 443"
                className="h-9 w-24 rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 text-sm text-white placeholder:text-neutral-600"
              />
            </div>
            <button
              onClick={handlePortSearch}
              className="h-9 rounded-lg bg-primary/20 px-4 text-sm text-primary hover:bg-primary/30"
            >
              Lookup
            </button>
          </div>

          {ports.length > 0 ? (
            <>
              <div className="text-xs text-neutral-500">{portsTotal} unique ports observed</div>
              <div className="overflow-x-auto rounded-xl border border-white/[0.06]">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-left text-xs text-neutral-500">
                      <th className="px-4 py-3">Port</th>
                      <th className="px-4 py-3">Protocol</th>
                      <th className="px-4 py-3">Events</th>
                      <th className="px-4 py-3">Unique Sources</th>
                      <th className="px-4 py-3">Unique Destinations</th>
                      <th className="px-4 py-3">First Seen</th>
                      <th className="px-4 py-3">Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ports.map((p) => (
                      <tr key={p.port} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                        <td className="px-4 py-2.5 font-mono font-bold text-white">{p.port}</td>
                        <td className="px-4 py-2.5">
                          {p.protocol ? (
                            <span className="rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary">{p.protocol}</span>
                          ) : "—"}
                        </td>
                        <td className="px-4 py-2.5 text-neutral-300">{p.event_count}</td>
                        <td className="px-4 py-2.5 text-neutral-300">{p.unique_sources}</td>
                        <td className="px-4 py-2.5 text-neutral-300">{p.unique_destinations}</td>
                        <td className="px-4 py-2.5 text-neutral-400">{formatTs(p.first_seen)}</td>
                        <td className="px-4 py-2.5 text-neutral-400">{formatTs(p.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={portPage} totalPages={portsPages} onChange={setPortPage} />
            </>
          ) : (
            !loading && <Empty text="No port data available. Upload a trace with network events to begin." />
          )}
        </div>
      )}

      {tab === "protocols" && (
        <div className="space-y-4">
          {protocols.length > 0 ? (
            <>
              <div className="overflow-x-auto rounded-xl border border-white/[0.06]">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-left text-xs text-neutral-500">
                      <th className="px-4 py-3">Protocol</th>
                      <th className="px-4 py-3">Event Count</th>
                      <th className="px-4 py-3">Percentage</th>
                    </tr>
                  </thead>
                  <tbody>
                    {protocols.map((p) => (
                      <tr key={p.protocol} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                        <td className="px-4 py-2.5">
                          <span className="rounded bg-primary/10 px-1.5 py-0.5 text-xs font-medium text-primary">{p.protocol}</span>
                        </td>
                        <td className="px-4 py-2.5 text-neutral-300">{p.event_count}</td>
                        <td className="px-4 py-2.5">
                          <div className="flex items-center gap-2">
                            <div className="h-2 w-32 overflow-hidden rounded-full bg-white/[0.06]">
                              <div
                                className="h-full rounded-full bg-primary/60"
                                style={{ width: `${p.percentage}%` }}
                              />
                            </div>
                            <span className="text-xs text-neutral-400">{p.percentage}%</span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            !loading && <Empty text="No protocol data available." />
          )}
        </div>
      )}

      {tab === "talkers" && (
        <div className="space-y-4">
          {talkers.length > 0 ? (
            <>
              <div className="overflow-x-auto rounded-xl border border-white/[0.06]">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-left text-xs text-neutral-500">
                      <th className="px-4 py-3">IP Address</th>
                      <th className="px-4 py-3">Connections</th>
                      <th className="px-4 py-3">Unique Destinations</th>
                      <th className="px-4 py-3">Unique Sources</th>
                      <th className="px-4 py-3">Unique Ports</th>
                      <th className="px-4 py-3">Direction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {talkers.map((t) => (
                      <tr key={t.ip_address} className="border-b border-white/[0.03] hover:bg-white/[0.02]">
                        <td className="px-4 py-2.5 font-mono text-xs text-blue-400">{t.ip_address}</td>
                        <td className="px-4 py-2.5">
                          <div className="flex items-center gap-2">
                            <div className="h-2 w-24 overflow-hidden rounded-full bg-white/[0.06]">
                              <div
                                className="h-full rounded-full bg-orange-500/60"
                                style={{ width: `${(t.connection_count / maxTalker) * 100}%` }}
                              />
                            </div>
                            <span className="text-neutral-300">{t.connection_count}</span>
                          </div>
                        </td>
                        <td className="px-4 py-2.5 text-neutral-300">{t.unique_destinations}</td>
                        <td className="px-4 py-2.5 text-neutral-300">{t.unique_sources}</td>
                        <td className="px-4 py-2.5 text-neutral-300">{t.unique_ports}</td>
                        <td className="px-4 py-2.5">
                          <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-xs text-neutral-400">{t.direction}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            !loading && <Empty text="No top talker data available." />
          )}
        </div>
      )}

      {tab === "timeline" && (
        <div className="space-y-4">
          {timeline.length > 0 ? (
            <>
              <div className="text-xs text-neutral-500">
                Aggregated by: <span className="text-neutral-400">{timelineInterval}</span> |{" "}
                {timeline.length} time buckets
              </div>
              <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
                <div className="flex items-end gap-1" style={{ height: 200 }}>
                  {timeline.map((point, i) => (
                    <div
                      key={i}
                      className="group relative flex-1"
                      style={{ height: `${(point.event_count / maxTimeline) * 100}%`, minHeight: 2 }}
                    >
                      <div className="h-full w-full rounded-t bg-primary/40 transition-colors group-hover:bg-primary/60" />
                      <div className="pointer-events-none absolute bottom-full left-1/2 mb-2 hidden -translate-x-1/2 whitespace-nowrap rounded bg-neutral-800 px-2 py-1 text-xs text-white group-hover:block">
                        {point.event_count} events
                        <br />
                        {formatTs(point.timestamp)}
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-2 flex justify-between text-xs text-neutral-600">
                  <span>{formatTs(timeline[0]?.timestamp)}</span>
                  <span>{formatTs(timeline[timeline.length - 1]?.timestamp)}</span>
                </div>
              </div>
            </>
          ) : (
            !loading && <Empty text="No timeline data available. Upload a trace with timestamped network events." />
          )}
        </div>
      )}

      {eventDetail && <EventDetailModal detail={eventDetail} onClose={() => setEventDetail(null)} />}
      {ipDetail && <IPDetailModal detail={ipDetail} onClose={() => setIpDetail(null)} />}
    </div>
  );
}
