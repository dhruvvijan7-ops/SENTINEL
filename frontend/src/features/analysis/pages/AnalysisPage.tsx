import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, FileJson2, FileSpreadsheet, RefreshCw, Upload, XCircle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { analysisService } from "@/services/analysisService";

function formatDate(value: string) {
  return new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

type InputType = "json" | "csv";

const INPUT_OPTIONS: Array<{ value: InputType; label: string; accept: string; hint: string; icon: typeof FileJson2 }> = [
  { value: "json", label: "JSON", accept: "application/json,.json", hint: "UTF-8 JSON with a sequences array, up to 10 MB.", icon: FileJson2 },
  { value: "csv", label: "CSV", accept: "text/csv,.csv", hint: "System-call CSV with trace_id and syscall_name columns.", icon: FileSpreadsheet },
];

export default function AnalysisPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [inputType, setInputType] = useState<InputType>("json");

  const currentOption = INPUT_OPTIONS.find((o) => o.value === inputType)!;

  const runsQuery = useQuery({ queryKey: ["analysis-runs"], queryFn: analysisService.getRuns });
  const upload = useMutation({
    mutationFn: analysisService.uploadHostTrace,
    onSuccess: () => {
      setSelectedFile(null);
      void queryClient.invalidateQueries({ queryKey: ["analysis-runs"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
  });

  const handleTypeChange = (type: InputType) => {
    setInputType(type);
    setSelectedFile(null);
    if (inputRef.current) inputRef.current.value = "";
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setSelectedFile(file);
  };

  const submit = () => {
    if (selectedFile) {
      upload.mutate(selectedFile);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[1400px] space-y-6 p-4 md:p-6 lg:p-8">
      <section className="ops-hero flex flex-col gap-4 rounded-2xl border p-6 shadow-[0_12px_35px_rgba(72,53,35,0.06)] sm:flex-row sm:items-end sm:justify-between md:p-8">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-primary">Data ingestion</p>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight md:text-4xl">Host Trace Analysis</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
            Import system-call traces for detection analysis. Supports JSON and CSV formats including CHASE-LB datasets.
          </p>
        </div>
        <Button variant="outline" className="bg-secondary hover:bg-accent" onClick={() => void runsQuery.refetch()} disabled={runsQuery.isFetching}>
          <RefreshCw className={`mr-2 size-4 ${runsQuery.isFetching ? "animate-spin" : ""}`} /> Refresh
        </Button>
      </section>

      <section className="ops-surface rounded-2xl border p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-start gap-3">
            <div className="flex size-11 shrink-0 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-lg shadow-orange-950/15">
              <currentOption.icon className="size-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">Upload a host trace</h2>
              <p className="mt-1 text-sm text-muted-foreground">{currentOption.hint}</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex rounded-lg border border-border bg-input p-0.5">
              {INPUT_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => handleTypeChange(opt.value)}
                  className={[
                    "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                    inputType === opt.value
                      ? "bg-primary text-primary-foreground shadow-sm"
                      : "text-muted-foreground hover:text-foreground",
                  ].join(" ")}
                >
                  {opt.label}
                </button>
              ))}
            </div>
            <input ref={inputRef} type="file" accept={currentOption.accept} className="hidden" onChange={handleFileChange} />
            <Button variant="outline" className="bg-secondary hover:bg-accent" onClick={() => inputRef.current?.click()} disabled={upload.isPending}>
              <Upload className="mr-2 size-4" /> Choose {currentOption.label}
            </Button>
            <Button onClick={submit} disabled={!selectedFile || upload.isPending}>
              {upload.isPending ? "Analyzing\u2026" : "Start analysis"}
            </Button>
          </div>
        </div>
        {selectedFile && (
          <p className="mt-5 rounded-xl border border-primary/20 bg-primary/5 px-4 py-3 text-sm">
            Selected: <span className="font-medium">{selectedFile.name}</span> · {(selectedFile.size / 1024).toFixed(1)} KB
          </p>
        )}
        {upload.isError && (
          <p role="alert" className="mt-4 flex items-center gap-2 text-sm text-destructive">
            <XCircle className="size-4" />{upload.error.message}
          </p>
        )}
        {upload.isSuccess && (
          <p className="mt-4 flex items-center gap-2 text-sm text-[#22C55E]">
            <CheckCircle2 className="size-4" />Trace validated and saved. Detections generated by the analysis engine.
          </p>
        )}
      </section>

      <section className="ops-surface overflow-hidden rounded-2xl border">
        <div className="border-b px-6 py-5"><p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-primary">Recent activity</p><h2 className="mt-2 text-lg font-semibold">Analysis history</h2><p className="mt-1 text-sm text-muted-foreground">Persisted backend records, newest first.</p></div>
        {runsQuery.isLoading ? <div className="flex h-44 items-center justify-center text-sm text-muted-foreground">Loading analysis records\u2026</div> : runsQuery.isError ? <div className="flex h-44 items-center justify-center text-sm text-destructive">Unable to reach the Sentinel API.</div> : runsQuery.data?.length === 0 ? <div className="flex h-44 flex-col items-center justify-center gap-2 text-center"><FileJson2 className="size-8 text-muted-foreground" /><p className="font-medium">No analysis runs yet</p><p className="text-sm text-muted-foreground">Upload a supported trace to create the first persisted record.</p></div> : <div className="divide-y">{runsQuery.data?.map((run) => <div key={run.id} className="grid gap-3 px-6 py-5 text-sm transition-colors hover:bg-muted/50 md:grid-cols-[1.5fr_repeat(3,1fr)] md:items-center"><div><p className="font-medium">{run.file_name}</p><p className="mt-1 text-xs text-muted-foreground">{formatDate(run.submitted_at)} · {run.source_type.replace("_", " ")}</p></div><p><span className="text-muted-foreground">Events </span>{run.event_count.toLocaleString()}</p><p><span className="text-muted-foreground">Sequences </span>{run.sequence_count.toLocaleString()}</p><p className="font-medium text-[#22C55E]">{run.status}</p></div>)}</div>}
      </section>
    </div>
  );
}
