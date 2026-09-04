import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  auditService,
  AUDIT_ACTIONS_BY_CATEGORY,
  AUDIT_CATEGORIES,
  AUDIT_SEVERITIES,
  TIME_PRESETS,
  type AuditLogRecord,
  type AuditLogFilters,
} from "@/services/auditService";

const RESULT_OPTIONS = [
  { value: "", label: "All Results" },
  { value: "SUCCESS", label: "Success" },
  { value: "FAILURE", label: "Failure" },
];

const SEVERITY_COLORS: Record<string, string> = {
  info: "text-slate-400 bg-slate-500/10",
  medium: "text-yellow-400 bg-yellow-500/10",
  high: "text-red-400 bg-red-500/10",
};

const CATEGORY_COLORS: Record<string, string> = {
  AUTHENTICATION: "text-blue-400 bg-blue-500/10",
  USER_MANAGEMENT: "text-teal-400 bg-teal-500/10",
  INGESTION: "text-yellow-400 bg-yellow-500/10",
  ANALYSIS: "text-purple-400 bg-purple-500/10",
  DETECTION: "text-red-400 bg-red-500/10",
  ALERT: "text-orange-400 bg-orange-500/10",
  SETTINGS: "text-indigo-400 bg-indigo-500/10",
  ADMINISTRATION: "text-cyan-400 bg-cyan-500/10",
  SYSTEM: "text-slate-400 bg-slate-500/10",
  NETWORK: "text-emerald-400 bg-emerald-500/10",
};

const RESULT_COLORS: Record<string, string> = {
  SUCCESS: "text-emerald-400 bg-emerald-500/10",
  FAILURE: "text-red-400 bg-red-500/10",
};

function formatTimestamp(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function formatResource(type: string | null, id: string | null): string {
  if (!type) return "-";
  return id ? `${type} #${id.slice(0, 8)}` : type;
}

function describeAction(action: string): string {
  return action
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLogRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<AuditLogRecord | null>(null);

  const [category, setCategory] = useState("");
  const [action, setAction] = useState("");
  const [result, setResult] = useState("");
  const [severity, setSeverity] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [userId, setUserId] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [fromTs, setFromTs] = useState("");
  const [toTs, setToTs] = useState("");
  const [activePreset, setActivePreset] = useState<string | null>(null);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    try {
      const filters: AuditLogFilters = {
        page,
        page_size: 20,
        category: category || undefined,
        action: action || undefined,
        result: result || undefined,
        severity: severity || undefined,
        ip_address: ipAddress || undefined,
        search: search || undefined,
        actor_user_id: userId || undefined,
        resource_type: resourceType || undefined,
        from_timestamp: fromTs || undefined,
        to_timestamp: toTs || undefined,
      };
      const data = await auditService.getAuditLogs(filters);
      setLogs(data.items);
      setTotal(data.total);
      setTotalPages(data.total_pages);
    } catch {
      toast.error("Failed to load audit logs.");
    } finally {
      setLoading(false);
    }
  }, [page, category, action, result, severity, ipAddress, search, userId, resourceType, fromTs, toTs]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  const applyPreset = (label: string, range: { from: string; to: string }) => {
    setActivePreset(label);
    setFromTs(range.from);
    setToTs(range.to);
    setPage(1);
  };

  const clearFilters = () => {
    setCategory("");
    setAction("");
    setResult("");
    setSeverity("");
    setIpAddress("");
    setSearch("");
    setSearchInput("");
    setUserId("");
    setResourceType("");
    setFromTs("");
    setToTs("");
    setActivePreset(null);
    setPage(1);
  };

  const handleSearch = () => {
    setSearch(searchInput);
    setPage(1);
  };

  const handleExport = async () => {
    try {
      const filters: AuditLogFilters = {
        category: category || undefined,
        action: action || undefined,
        result: result || undefined,
        severity: severity || undefined,
        ip_address: ipAddress || undefined,
        search: search || undefined,
        actor_user_id: userId || undefined,
        resource_type: resourceType || undefined,
        from_timestamp: fromTs || undefined,
        to_timestamp: toTs || undefined,
      };
      await auditService.exportCsv(filters);
      toast.success("Audit log export started.");
    } catch {
      toast.error("Failed to export audit logs.");
    }
  };

  const actionOptions = category
    ? AUDIT_ACTIONS_BY_CATEGORY[category] ?? [{ value: "", label: "All Actions" }]
    : [{ value: "", label: "All Actions" }];

  const hasFilters = category || action || result || severity || ipAddress || search || userId || resourceType || fromTs || toTs;

  return (
    <div className="mx-auto w-full max-w-[1400px] space-y-6 p-4 md:p-6 lg:p-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Audit Logs</h1>
          <p className="text-slate-400 mt-1">{total} events recorded</p>
        </div>
        <Button variant="outline" size="sm" onClick={handleExport}>
          Export CSV
        </Button>
      </div>

      {/* Time Presets */}
      <div className="flex flex-wrap gap-2">
        {TIME_PRESETS.map((preset) => {
          const range = preset.getRange();
          return (
            <Button
              key={preset.label}
              variant="outline"
              size="sm"
              onClick={() => applyPreset(preset.label, range)}
              className={activePreset === preset.label ? "border-primary text-primary" : ""}
            >
              {preset.label}
            </Button>
          );
        })}
        <Button variant="ghost" size="sm" onClick={() => { setFromTs(""); setToTs(""); setActivePreset(null); setPage(1); }}>
          Clear Time
        </Button>
      </div>

      {/* Filters */}
      <div className="rounded-2xl border bg-card p-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <Input value={searchInput} onChange={setSearchInput} onSearch={handleSearch} placeholder="Search events…" className="flex-1" />
          <Button variant="outline" onClick={handleSearch}>Search</Button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-8 gap-3">
          <select value={category} onChange={(e) => { setCategory(e.target.value); setAction(""); setPage(1); }} className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground">
            {AUDIT_CATEGORIES.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>

          <select value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }} className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground">
            {actionOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>

          <select value={result} onChange={(e) => { setResult(e.target.value); setPage(1); }} className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground">
            {RESULT_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>

          <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground">
            {AUDIT_SEVERITIES.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>

          <input value={userId} onChange={(e) => { setUserId(e.target.value); setPage(1); }} placeholder="Actor User ID" className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground" />

          <input value={ipAddress} onChange={(e) => { setIpAddress(e.target.value); setPage(1); }} placeholder="IP Address" className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground" />

          <select value={resourceType} onChange={(e) => { setResourceType(e.target.value); setPage(1); }} className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground">
            <option value="">All Resources</option>
            <option value="USER">User</option>
            <option value="ANALYSIS_RUN">Analysis Run</option>
            <option value="DETECTION">Detection</option>
            <option value="ALERT">Alert</option>
            <option value="SYSTEM">System</option>
          </select>

          {hasFilters && (
            <Button variant="ghost" size="sm" onClick={clearFilters} className="text-slate-400">
              Clear All
            </Button>
          )}
        </div>

        {/* Custom Time Range */}
        <div className="flex flex-col sm:flex-row gap-3 items-end">
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-400">From (UTC)</span>
            <input
              type="datetime-local"
              value={fromTs ? fromTs.slice(0, 19) : ""}
              onChange={(e) => { setFromTs(e.target.value ? e.target.value + "Z" : ""); setActivePreset(null); setPage(1); }}
              className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground"
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-400">To (UTC)</span>
            <input
              type="datetime-local"
              value={toTs ? toTs.slice(0, 19) : ""}
              onChange={(e) => { setToTs(e.target.value ? e.target.value + "Z" : ""); setActivePreset(null); setPage(1); }}
              className="h-9 rounded-lg border border-border bg-input px-2 text-sm text-foreground"
            />
          </label>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-2xl border bg-card">
        {loading ? (
          <div className="p-8 text-center text-slate-400">Loading…</div>
        ) : logs.length === 0 ? (
          <div className="p-8 text-center text-slate-400">No audit events found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 text-slate-400">
                  <th className="text-left px-4 py-3 font-medium">Timestamp</th>
                  <th className="text-left px-4 py-3 font-medium">Actor</th>
                  <th className="text-left px-4 py-3 font-medium">Category</th>
                  <th className="text-left px-4 py-3 font-medium">Action</th>
                  <th className="text-left px-4 py-3 font-medium">Resource</th>
                  <th className="text-left px-4 py-3 font-medium">Result</th>
                  <th className="text-left px-4 py-3 font-medium">Severity</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr
                    key={log.id}
                    className="border-b border-slate-800 hover:bg-slate-800/50 cursor-pointer"
                    onClick={() => setSelected(log)}
                  >
                    <td className="px-4 py-3 text-slate-300 font-mono text-xs">{formatTimestamp(log.timestamp)}</td>
                    <td className="px-4 py-3 text-slate-300">{log.actor_email ?? "system"}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${CATEGORY_COLORS[log.category] ?? "text-slate-400 bg-slate-500/10"}`}>
                        {log.category}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300 text-xs">{describeAction(log.action)}</td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs">{formatResource(log.resource_type, log.resource_id)}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${RESULT_COLORS[log.result] ?? ""}`}>
                        {log.result}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${SEVERITY_COLORS[log.severity] ?? ""}`}>
                        {log.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700">
            <span className="text-sm text-slate-400">Page {page} of {totalPages} ({total} total)</span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>Previous</Button>
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>Next</Button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setSelected(null)}>
          <div className="bg-card border rounded-2xl p-6 max-w-xl w-full mx-4 max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-slate-100">Audit Event Detail</h2>
              <Button variant="ghost" size="sm" onClick={() => setSelected(null)}>Close</Button>
            </div>

            <dl className="space-y-3 text-sm">
              <DetailRow label="Timestamp" value={formatTimestamp(selected.timestamp) + " UTC"} />
              <DetailRow label="Created At" value={formatTimestamp(selected.created_at) + " UTC"} />
              <DetailRow label="Actor" value={selected.actor_email ?? "system"} />
              <DetailRow label="Actor User ID" value={selected.actor_user_id ?? "system"} />
              <DetailRow label="Actor Type" value={selected.actor_type} />
              <DetailRow label={
                <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${CATEGORY_COLORS[selected.category] ?? ""}`}>{selected.category}</span>
              } value={describeAction(selected.action)} />
              <DetailRow label="Result" value={<span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${RESULT_COLORS[selected.result] ?? ""}`}>{selected.result}</span>} />
              <DetailRow label="Severity" value={<span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${SEVERITY_COLORS[selected.severity] ?? ""}`}>{selected.severity}</span>} />
              <DetailRow label="Resource" value={formatResource(selected.resource_type, selected.resource_id)} />
              <DetailRow label="IP Address" value={selected.ip_address ?? "N/A"} />
              <DetailRow label="User Agent" value={selected.user_agent ?? "N/A"} />
              <DetailRow label="Request ID" value={selected.request_id ?? "N/A"} />
              {selected.description && <DetailRow label="Description" value={selected.description} />}

              {selected.metadata_json && Object.keys(selected.metadata_json).length > 0 && (
                <div>
                  <dt className="text-slate-400 text-xs font-medium uppercase tracking-wider mb-1">Metadata</dt>
                  <dd className="bg-slate-900 rounded-lg p-3 font-mono text-xs text-slate-300 whitespace-pre-wrap overflow-x-auto">
                    {JSON.stringify(selected.metadata_json, null, 2)}
                  </dd>
                </div>
              )}
            </dl>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailRow({ label, value }: { label: React.ReactNode; value: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <dt className="text-slate-400 text-xs font-medium uppercase tracking-wider w-32 shrink-0">{label}</dt>
      <dd className="text-slate-200">{value}</dd>
    </div>
  );
}

function Input({ value, onChange, onSearch, placeholder, className }: { value: string; onChange: (v: string) => void; onSearch: () => void; placeholder: string; className?: string }) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => e.key === "Enter" && onSearch()}
      placeholder={placeholder}
      className={`h-9 rounded-lg border border-border bg-input px-3 text-sm text-foreground outline-none focus:ring-2 focus:ring-ring ${className ?? ""}`}
    />
  );
}
