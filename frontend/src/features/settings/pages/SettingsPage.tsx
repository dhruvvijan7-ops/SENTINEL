import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCircle2, Save, Settings2, Lock } from "lucide-react";

import { Button } from "@/components/ui/button";
import { systemService } from "@/services/systemService";
import { useAuthStore } from "@/store/authStore";

export default function SettingsPage() {
  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === "admin";

  const settingsQuery = useQuery({ queryKey: ["system-settings"], queryFn: systemService.getSettings });
  const [maxUploadMb, setMaxUploadMb] = useState<number | null>(null);
  const [historyLimit, setHistoryLimit] = useState<number | null>(null);

  const effectiveMaxUploadMb = maxUploadMb ?? settingsQuery.data?.max_upload_mb ?? 10;
  const effectiveHistoryLimit = historyLimit ?? settingsQuery.data?.analysis_history_limit ?? 50;

  const saveSettings = useMutation({
    mutationFn: () => systemService.updateSettings({ max_upload_mb: effectiveMaxUploadMb, analysis_history_limit: effectiveHistoryLimit }),
  });

  return <div className="mx-auto w-full max-w-[1100px] space-y-6 p-4 md:p-6 lg:p-8">
    <section className="ops-hero rounded-2xl border p-6 shadow-[0_12px_35px_rgba(72,53,35,0.06)] md:p-8"><div className="flex size-11 items-center justify-center rounded-2xl bg-primary text-primary-foreground"><Settings2 className="size-5" /></div><p className="mt-5 text-[11px] font-semibold uppercase tracking-[0.2em] text-primary">Application configuration</p><h1 className="mt-3 text-3xl font-semibold tracking-tight md:text-4xl">Settings</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">These persisted settings affect real API behavior for trace ingestion and history retrieval.</p></section>

    {!isAdmin && (
      <div className="flex items-center gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-400">
        <Lock className="size-4 shrink-0" />
        <span>Only administrators can modify system settings. You can view the current configuration below.</span>
      </div>
    )}

    <section className="ops-surface rounded-2xl border p-6"><h2 className="text-lg font-semibold">Ingestion limits</h2><p className="mt-1 text-sm text-muted-foreground">Keep local development responsive while analysing traces.</p>{settingsQuery.isLoading ? <p className="py-8 text-sm text-muted-foreground">Loading settings…</p> : settingsQuery.isError ? <p className="py-8 text-sm text-destructive">Unable to reach the Sentinel API.</p> : <div className="mt-6 grid gap-5 md:grid-cols-2"><label className="space-y-2"><span className="text-sm font-medium">Maximum trace upload (MB)</span><input type="number" min="1" max="100" value={effectiveMaxUploadMb} onChange={(event) => setMaxUploadMb(Number(event.target.value))} disabled={!isAdmin} className="h-10 w-full rounded-lg border border-border bg-input px-3 text-foreground outline-none focus:ring-2 focus:ring-ring disabled:opacity-50 disabled:cursor-not-allowed" /><span className="block text-xs text-muted-foreground">Applied when the backend validates uploaded trace files.</span></label><label className="space-y-2"><span className="text-sm font-medium">Analysis history limit</span><input type="number" min="10" max="500" value={effectiveHistoryLimit} onChange={(event) => setHistoryLimit(Number(event.target.value))} disabled={!isAdmin} className="h-10 w-full rounded-lg border border-border bg-input px-3 text-foreground outline-none focus:ring-2 focus:ring-ring disabled:opacity-50 disabled:cursor-not-allowed" /><span className="block text-xs text-muted-foreground">Maximum persisted runs returned by the Analysis page.</span></label></div>}<div className="mt-7 flex flex-wrap items-center gap-3">{isAdmin && <Button onClick={() => saveSettings.mutate()} disabled={settingsQuery.isLoading || saveSettings.isPending}><Save className="mr-2 size-4" />{saveSettings.isPending ? "Saving…" : "Save settings"}</Button>}{saveSettings.isSuccess && <p className="flex items-center gap-2 text-sm text-[#22C55E]"><CheckCircle2 className="size-4" />Settings saved to the backend.</p>}{saveSettings.isError && <p className="text-sm text-destructive">Could not save settings.</p>}</div></section>
  </div>;
}
