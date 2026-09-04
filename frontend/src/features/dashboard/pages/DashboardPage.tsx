import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Database,
  FileSearch,
  RefreshCw,
  Server,
  ShieldAlert,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { systemService } from "@/services/systemService";

function MetricCard({
  label,
  value,
  icon: Icon,
  description,
  iconClass,
}: {
  label: string;
  value: string;
  icon: typeof Activity;
  description: string;
  iconClass: string;
}) {
  return (
    <div className="ops-stat rounded-2xl border p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            {label}
          </p>
          <p className="mt-3 text-3xl font-semibold tracking-tight">
            {value}
          </p>
          <p className="mt-2 text-xs text-muted-foreground">
            {description}
          </p>
        </div>
        <div className={`flex size-11 shrink-0 items-center justify-center rounded-2xl ${iconClass}`}>
          <Icon className="size-5" />
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const statusQuery = useQuery({
    queryKey: ["system-status"],
    queryFn: systemService.getStatus,
    retry: 1,
  });
  const summaryQuery = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: systemService.getDashboardSummary,
    retry: 1,
  });
  const isRefreshing = statusQuery.isFetching || summaryQuery.isFetching;
  const summary = summaryQuery.data;

  function refresh() {
    void statusQuery.refetch();
    void summaryQuery.refetch();
  }

  return (
    <div className="mx-auto w-full max-w-[1400px] space-y-6 p-4 md:p-6 lg:p-8">
      <section className="ops-hero flex flex-col gap-5 rounded-2xl border p-6 shadow-[0_12px_35px_rgba(72,53,35,0.06)] md:flex-row md:items-end md:justify-between md:p-8">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-primary">
            Sentinel workspace
          </p>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight md:text-4xl">
            Security Overview
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
            A clear view of persisted host-trace analysis and the current detection pipeline state.
          </p>
        </div>
        <Button variant="outline" onClick={refresh} disabled={isRefreshing} className="bg-secondary hover:bg-accent">
          <RefreshCw className={`mr-2 size-4 ${isRefreshing ? "animate-spin" : ""}`} />
          Refresh status
        </Button>
      </section>

      {statusQuery.isError ? (
        <section role="alert" className="rounded-2xl border border-destructive/40 bg-destructive/10 p-5 text-sm">
          <p className="font-medium">Backend unavailable</p>
          <p className="mt-1 text-muted-foreground">Start the FastAPI service to view application status and persisted analysis metrics.</p>
        </section>
      ) : (
        <section className="grid gap-4 md:grid-cols-3">
          <div className="ops-surface rounded-2xl border p-4">
            <div className="flex items-center gap-2 text-sm font-medium"><Server className="size-4 text-[#22C55E]" /> API</div>
            <p className="mt-3 capitalize text-sm font-semibold text-[#22C55E]">{statusQuery.data?.api_status ?? "Checking"}</p>
          </div>
          <div className="ops-surface rounded-2xl border p-4">
            <div className="flex items-center gap-2 text-sm font-medium"><Database className="size-4 text-[#22C55E]" /> Database</div>
            <p className="mt-3 capitalize text-sm font-semibold text-[#22C55E]">{statusQuery.data?.database_status ?? "Checking"}</p>
          </div>
          <div className="ops-surface rounded-2xl border p-4">
            <div className="flex items-center gap-2 text-sm font-medium"><ShieldAlert className="size-4 text-[#F5C542]" /> LIGHT-HIDS</div>
            <p className="mt-3 capitalize text-sm font-semibold text-[#F5C542]">{statusQuery.data?.light_hids_status?.replace("_", " ") ?? "Checking"}</p>
            <p className="mt-1 text-xs text-muted-foreground">{statusQuery.data?.light_hids_message}</p>
          </div>
        </section>
      )}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Analysis runs" value={summary ? String(summary.analysis_runs) : "—"} icon={FileSearch} description="Persisted host-trace analyses" iconClass="bg-[#FF7A00]/10 text-[#FF7A00]" />
        <MetricCard label="Events ingested" value={summary ? summary.analyzed_events.toLocaleString() : "—"} icon={Activity} description="Validated system-call events" iconClass="bg-[#3B9EFF]/10 text-[#3B9EFF]" />
        <MetricCard label="Detections" value={summary ? String(summary.detections) : "—"} icon={ShieldAlert} description="No detection engine enabled yet" iconClass="bg-[#8B5CF6]/10 text-[#8B5CF6]" />
        <MetricCard label="Open alerts" value={summary ? String(summary.open_alerts) : "—"} icon={AlertTriangle} description="Alerts begin with real detections" iconClass="bg-[#FF3B30]/10 text-[#FF3B30]" />
      </section>

      <section className="ops-surface rounded-2xl border p-6">
        <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-primary">Current capability</p>
        <h2 className="mt-2 text-xl font-semibold">Host-trace ingestion is connected end to end.</h2>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
          Upload a host trace from Analysis. The backend validates its structure, records event and sequence counts, stores the analysis run, and returns those records here. LIGHT-HIDS inference will be added as its own verified pipeline.
        </p>
      </section>
    </div>
  );
}
