"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Shield,
  ShieldAlert,
  Target,
} from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  PieChart,
  Pie,
} from "recharts";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { cn, formatDate } from "@/lib/utils";
import type { Scan, ScanList, ScanStats } from "@/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  info: "#64748b",
};

const STATUS_STYLE = {
  completed: { bg: "bg-emerald-500/10", text: "text-emerald-500" },
  running: { bg: "bg-yellow-500/10", text: "text-yellow-500" },
  pending: { bg: "bg-blue-500/10", text: "text-blue-500" },
  failed: { bg: "bg-red-500/10", text: "text-red-500" },
  cancelled: { bg: "bg-slate-500/10", text: "text-slate-400" },
} as const;

const DEFAULT_STYLE = STATUS_STYLE.cancelled;

export default function DashboardPage() {
  const { data: stats } = useQuery<ScanStats>({
    queryKey: ["stats"],
    queryFn: async () => (await api.get("/scans/stats/summary")).data,
    refetchInterval: 15_000,
  });
  const { data: recent } = useQuery<ScanList>({
    queryKey: ["scans", "recent"],
    queryFn: async () => (await api.get("/scans?page=1&page_size=8")).data,
    refetchInterval: 10_000,
  });

  const sevData = useMemo(
    () => SEVERITY_ORDER.map((s) => ({
      severity: s.charAt(0).toUpperCase() + s.slice(1),
      count: stats?.severity_counts[s] ?? 0,
      fill: SEV_COLORS[s],
    })),
    [stats]
  );

  const pieData = useMemo(() => {
    if (!stats?.status_counts) return [];
    return Object.entries(stats.status_counts).map(([k, v]) => ({ name: k, value: v }));
  }, [stats]);

  const totalVulns = Object.values(stats?.severity_counts ?? {}).reduce((a, b) => a + b, 0);
  const critHigh = (stats?.severity_counts?.critical ?? 0) + (stats?.severity_counts?.high ?? 0);
  const riskLabel =
    (stats?.average_risk_score ?? 0) >= 7.5 ? "Critical" :
    (stats?.average_risk_score ?? 0) >= 5 ? "High" :
    (stats?.average_risk_score ?? 0) >= 2.5 ? "Medium" : "Low";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-4 pb-2">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">Security Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">Overview of your application security posture.</p>
        </div>
        <Link href="/scans/new">
          <Button className="gap-2 shadow-sm hover:shadow-md">
            <Target className="h-4 w-4" /> New Scan
          </Button>
        </Link>
      </div>

      {/* Stat Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          icon={<Activity className="h-5 w-5" />}
          label="Total Scans"
          value={stats?.total_scans ?? 0}
          accent="text-primary"
          bg="bg-primary/10"
        />
        <StatCard
          icon={<ShieldAlert className="h-5 w-5" />}
          label="Total Findings"
          value={totalVulns}
          sub={critHigh > 0 ? `${critHigh} critical/high` : undefined}
          accent={critHigh > 0 ? "text-red-500" : "text-foreground"}
          bg={critHigh > 0 ? "bg-red-500/10" : "bg-muted"}
        />
        <StatCard
          icon={<Shield className="h-5 w-5" />}
          label="Avg Risk Score"
          value={stats?.average_risk_score?.toFixed(1) ?? "-"}
          sub={`/ 10.0 (${riskLabel})`}
          accent={
            (stats?.average_risk_score ?? 0) >= 7.5 ? "text-red-500" :
            (stats?.average_risk_score ?? 0) >= 5 ? "text-orange-500" :
            (stats?.average_risk_score ?? 0) >= 2.5 ? "text-yellow-500" : "text-emerald-500"
          }
          bg="bg-muted"
        />
        <StatCard
          icon={<CheckCircle2 className="h-5 w-5" />}
          label="Completed"
          value={stats?.status_counts?.completed ?? 0}
          accent="text-emerald-500"
          bg="bg-emerald-500/10"
        />
      </div>

      {/* Charts Row */}
      <div className="grid gap-4 lg:grid-cols-5">
        {/* Severity Bar Chart */}
        <div className="rounded-lg border border-border bg-card p-5 shadow-sm hover:shadow-md transition-all duration-200 lg:col-span-3">
          <h3 className="mb-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Findings by Severity
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevData} barSize={36}>
                <CartesianGrid strokeDasharray="3 3" opacity={0.1} vertical={false} stroke="hsl(var(--border))" />
                <XAxis dataKey="severity" tick={{ fontSize: 12 }} axisLine={false} tickLine={false} stroke="hsl(var(--muted-foreground))" />
                <YAxis allowDecimals={false} tick={{ fontSize: 12 }} axisLine={false} tickLine={false} stroke="hsl(var(--muted-foreground))" />
                <Tooltip cursor={{ fill: "hsl(var(--muted))" }} contentStyle={{ borderRadius: 8, border: "1px solid hsl(var(--border))", background: "hsl(var(--card))", boxShadow: "0 2px 8px rgb(0 0 0 / 0.1)" }} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {sevData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Scan Status Pie */}
        <div className="rounded-lg border border-border bg-card p-5 shadow-sm hover:shadow-md transition-all duration-200 lg:col-span-2">
          <h3 className="mb-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Scan Status
          </h3>
          {pieData.length > 0 ? (
            <div className="flex flex-col items-center">
              <div className="h-40 w-40">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={35} outerRadius={65} paddingAngle={3}>
                      {pieData.map((d, i) => {
                        const c = d.name === "completed" ? "#10b981" : d.name === "running" ? "#eab308" : d.name === "failed" ? "#ef4444" : d.name === "pending" ? "#3b82f6" : "#94a3b8";
                        return <Cell key={i} fill={c} stroke="transparent" />;
                      })}
                    </Pie>
                    <Tooltip contentStyle={{ borderRadius: 8, border: "1px solid hsl(var(--border))", background: "hsl(var(--card))", boxShadow: "0 2px 8px rgb(0 0 0 / 0.1)" }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-3 flex flex-wrap justify-center gap-3">
                {pieData.map((d) => {
                  const st = (STATUS_STYLE as Record<string, { bg: string; text: string }>)[d.name] ?? DEFAULT_STYLE;
                  return (
                    <span key={d.name} className={cn("rounded-full px-2.5 py-1 text-xs font-semibold capitalize transition-all duration-200", st.bg, st.text)}>
                      {d.name}: {d.value}
                    </span>
                  );
                })}
              </div>
            </div>
          ) : (
            <p className="py-8 text-center text-sm text-muted-foreground">No scans yet.</p>
          )}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="rounded-lg border border-border bg-card shadow-sm overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-5 py-4 bg-card/50">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Recent Scans
          </h3>
          <Link href="/scans">
            <Button variant="ghost" size="sm" className="gap-1 text-xs">
              View all <ArrowRight className="h-3 w-3" />
            </Button>
          </Link>
        </div>
        <div className="divide-y">
          {!recent?.items?.length ? (
            <div className="px-5 py-12 text-center">
              <Target className="mx-auto mb-3 h-10 w-10 text-muted-foreground/50" />
              <p className="text-muted-foreground">No scans yet. Launch your first scan.</p>
              <Link href="/scans/new">
                <Button className="mt-4" size="sm">Start scanning</Button>
              </Link>
            </div>
          ) : (
            recent.items.map((scan: Scan) => {
              const st = (STATUS_STYLE as Record<string, { bg: string; text: string }>)[scan.status] ?? DEFAULT_STYLE;
              return (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="flex items-center gap-4 px-5 py-3 transition-colors hover:bg-accent/50"
                >
                  <div className={cn("flex h-9 w-9 items-center justify-center rounded-lg", st.bg)}>
                    {scan.status === "completed" ? <CheckCircle2 className={cn("h-4 w-4", st.text)} /> :
                     scan.status === "running" || scan.status === "pending" ? <Clock className={cn("h-4 w-4", st.text)} /> :
                     <AlertTriangle className={cn("h-4 w-4", st.text)} />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{scan.target_host}</p>
                    <p className="text-xs text-muted-foreground">{formatDate(scan.created_at)}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    {scan.risk_score != null && (
                      <span className={cn(
                        "text-sm font-bold",
                        scan.risk_score >= 7.5 ? "text-red-500" : scan.risk_score >= 5 ? "text-orange-500" : scan.risk_score >= 2.5 ? "text-yellow-500" : "text-emerald-500"
                      )}>
                        {scan.risk_score.toFixed(1)}
                      </span>
                    )}
                    <span className={cn("rounded-full px-2 py-0.5 text-[11px] font-semibold capitalize", st.bg, st.text)}>
                      {scan.status}
                    </span>
                  </div>
                </Link>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({
  icon, label, value, sub, accent = "text-foreground", bg = "bg-muted",
}: {
  icon: React.ReactNode; label: string; value: number | string; sub?: string; accent?: string; bg?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-5 shadow-sm hover:shadow-md hover:border-secondary/50 transition-all duration-200">
      <div className="flex items-center gap-3">
        <div className={cn("flex h-10 w-10 items-center justify-center rounded-lg transition-all duration-200", bg, accent)}>{icon}</div>
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
          <p className={cn("text-2xl font-bold mt-0.5", accent)}>
            {value}
            {sub && <span className="ml-1 text-xs font-normal text-muted-foreground">{sub}</span>}
          </p>
        </div>
      </div>
    </div>
  );
}
