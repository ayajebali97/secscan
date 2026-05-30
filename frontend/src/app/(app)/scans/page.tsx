"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Clock, Target } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { cn, formatDate } from "@/lib/utils";
import type { ScanList } from "@/types";

const STATUS_STYLE = {
  completed: { bg: "bg-emerald-500/10", text: "text-emerald-500", dot: "bg-emerald-500" },
  running: { bg: "bg-yellow-500/10", text: "text-yellow-500", dot: "bg-yellow-500 animate-pulse" },
  pending: { bg: "bg-blue-500/10", text: "text-blue-500", dot: "bg-blue-500 animate-pulse" },
  failed: { bg: "bg-red-500/10", text: "text-red-500", dot: "bg-red-500" },
  cancelled: { bg: "bg-slate-500/10", text: "text-slate-400", dot: "bg-slate-400" },
} as const;

const SCAN_DEFAULT_STYLE = STATUS_STYLE.cancelled;

export default function ScansPage() {
  const [page, setPage] = useState(1);
  const ps = 20;

  const { data, isLoading } = useQuery<ScanList>({
    queryKey: ["scans", { page, ps }],
    queryFn: async () => (await api.get(`/scans?page=${page}&page_size=${ps}`)).data,
    refetchInterval: 8_000,
  });
  const totalPages = data ? Math.max(1, Math.ceil(data.total / ps)) : 1;

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between pb-2">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">Scans</h1>
          <p className="text-sm text-muted-foreground mt-1">
            {data?.total ?? 0} total scan{(data?.total ?? 0) !== 1 ? "s" : ""}
          </p>
        </div>
        <Link href="/scans/new">
          <Button className="gap-2 shadow-sm hover:shadow-md"><Target className="h-4 w-4" /> New Scan</Button>
        </Link>
      </div>

      <div className="rounded-lg border border-border bg-card shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-16">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          </div>
        ) : !data?.items?.length ? (
          <div className="py-16 text-center">
            <Target className="mx-auto mb-3 h-10 w-10 text-muted-foreground/40" />
            <p className="text-muted-foreground">No scans yet.</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/30 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                    <th className="px-5 py-3 font-semibold">Target</th>
                    <th className="px-5 py-3 font-semibold">Status</th>
                    <th className="px-5 py-3 font-semibold">Risk</th>
                    <th className="px-5 py-3 font-semibold">Modules</th>
                    <th className="px-5 py-3 font-semibold">Date</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {data.items.map((scan) => {
                    const st = (STATUS_STYLE as Record<string, { bg: string; text: string; dot: string }>)[scan.status] ?? SCAN_DEFAULT_STYLE;
                    return (
                      <tr key={scan.id} className="cursor-pointer transition-colors hover:bg-muted/40" onClick={() => (window.location.href = `/scans/${scan.id}`)}>
                        <td className="px-5 py-3">
                          <p className="font-medium text-foreground">{scan.target_host}</p>
                          <p className="max-w-xs truncate text-xs text-muted-foreground mt-0.5">{scan.target_url}</p>
                        </td>
                        <td className="px-5 py-3">
                          <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold capitalize", st.bg, st.text)}>
                            <span className={cn("h-1.5 w-1.5 rounded-full", st.dot)} />
                            {scan.status}
                          </span>
                        </td>
                        <td className="px-5 py-3">
                          {scan.risk_score != null ? (
                            <span className={cn(
                              "font-bold",
                              scan.risk_score >= 7.5 ? "text-red-500" : scan.risk_score >= 5 ? "text-orange-500" : scan.risk_score >= 2.5 ? "text-yellow-500" : "text-emerald-500"
                            )}>
                              {scan.risk_score.toFixed(1)}
                            </span>
                          ) : <span className="text-muted-foreground">-</span>}
                        </td>
                        <td className="px-5 py-3 text-xs text-muted-foreground">
                          {scan.modules.length} module{scan.modules.length !== 1 ? "s" : ""}
                        </td>
                        <td className="whitespace-nowrap px-5 py-3 text-xs text-muted-foreground">
                          {formatDate(scan.created_at)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t px-5 py-3">
              <p className="text-xs text-muted-foreground">Page {page} of {totalPages}</p>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>Prev</Button>
                <Button size="sm" variant="outline" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>Next</Button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
