"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Bug,
  ChevronDown,
  ChevronRight,
  Download,
  ExternalLink,
  Globe,
  Lock,
  Monitor,
  Network,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { useParams, useRouter } from "next/navigation";
import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { toast } from "@/components/ui/toaster";
import { api, apiError } from "@/lib/api";
import { cn, formatDate } from "@/lib/utils";
import type { ScanDetail, Severity, Vulnerability } from "@/types";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_STYLE: Record<string, string> = {
  critical: "bg-red-600 text-white border-red-500",
  high: "bg-orange-600 text-white border-orange-500",
  medium: "bg-yellow-500 text-black border-yellow-400",
  low: "bg-blue-600 text-white border-blue-500",
  info: "bg-slate-600 text-white border-slate-500",
};
const SEV_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-400",
  low: "bg-blue-500",
  info: "bg-slate-400",
};

const MODULE_LABELS: Record<string, { label: string; icon: typeof Globe }> = {
  dns_recon: { label: "DNS Recon", icon: Globe },
  headers: { label: "HTTP Headers", icon: Shield },
  ssl: { label: "SSL/TLS", icon: Lock },
  ports: { label: "Port Scanner", icon: Server },
  web_vuln: { label: "Web Vulnerabilities", icon: ShieldAlert },
  subdomain: { label: "Subdomains", icon: Network },
  fingerprint: { label: "Fingerprint", icon: Monitor },
  cve_lookup: { label: "CVE Detector", icon: Bug },
};

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [activeModule, setActiveModule] = useState<string | null>(null);

  const { data: scan } = useQuery<ScanDetail>({
    queryKey: ["scan", params.id],
    queryFn: async () => (await api.get(`/scans/${params.id}`)).data,
    refetchInterval: (q) => {
      const d = q.state.data as ScanDetail | undefined;
      return d && ["completed", "failed", "cancelled"].includes(d.status)
        ? false
        : 2500;
    },
    enabled: Boolean(params.id),
  });

  const cancelMut = useMutation({
    mutationFn: () => api.post(`/scans/${params.id}/cancel`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["scan", params.id] }); toast({ title: "Scan cancelled" }); },
    onError: (e) => toast({ title: "Cancel failed", description: apiError(e), variant: "destructive" }),
  });
  const deleteMut = useMutation({
    mutationFn: () => api.delete(`/scans/${params.id}`),
    onSuccess: () => { toast({ title: "Scan deleted" }); router.replace("/scans"); },
    onError: (e) => toast({ title: "Delete failed", description: apiError(e), variant: "destructive" }),
  });

  const sevCounts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    scan?.vulnerabilities?.forEach((v) => c[v.severity]++);
    return c;
  }, [scan]);

  const modules = useMemo(() => {
    const map = new Map<string, Vulnerability[]>();
    scan?.vulnerabilities?.forEach((v) => {
      const arr = map.get(v.module) || [];
      arr.push(v);
      map.set(v.module, arr);
    });
    return map;
  }, [scan]);

  const filteredVulns = useMemo(() => {
    if (!scan) return [];
    let vulns = scan.vulnerabilities || [];
    if (activeModule) vulns = vulns.filter((v) => v.module === activeModule);
    return vulns.sort(
      (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
    );
  }, [scan, activeModule]);

  const dnsInfo = useMemo(() => {
    const dnsFindings = scan?.vulnerabilities?.filter(
      (v) => v.module === "dns_recon" && v.evidence?.dns_records
    );
    return dnsFindings?.[0]?.evidence as Record<string, unknown> | undefined;
  }, [scan]);

  const portInfo = useMemo(() => {
    const pf = scan?.vulnerabilities?.find(
      (v) => v.module === "ports" && v.evidence?.open_ports
    );
    return pf?.evidence as Record<string, unknown> | undefined;
  }, [scan]);

  if (!scan) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          <p className="text-muted-foreground">Loading scan...</p>
        </div>
      </div>
    );
  }

  const toggle = (id: string) =>
    setExpanded((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const isRunning = scan.status === "pending" || scan.status === "running";

  async function downloadPdf() {
    try {
      const r = await api.get(`/reports/scan/${scan!.id}/pdf`, { responseType: "blob" });
      const url = URL.createObjectURL(r.data);
      const a = document.createElement("a");
      a.href = url; a.download = `secscan-${scan!.target_host}.pdf`;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } catch (e) { toast({ title: "Report unavailable", description: apiError(e), variant: "destructive" }); }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-xl border border-border/50 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 p-6 text-white shadow-2xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <div className={cn("h-3 w-3 rounded-full", isRunning ? "animate-pulse bg-yellow-400" : scan.status === "completed" ? "bg-emerald-400" : "bg-red-400")} />
              <span className="text-sm font-medium uppercase tracking-wider text-slate-300">
                {scan.status}
              </span>
            </div>
            <h1 className="mt-2 break-all text-2xl font-bold tracking-tight md:text-3xl">
              {scan.target_host}
            </h1>
            <p className="mt-1 break-all text-sm text-slate-400">{scan.target_url}</p>
            <p className="mt-1 text-xs text-slate-500">
              {formatDate(scan.created_at)}
              {scan.finished_at && ` \u2022 Duration: ${Math.round((new Date(scan.finished_at).getTime() - new Date(scan.started_at || scan.created_at).getTime()) / 1000)}s`}
            </p>
          </div>
          <div className="flex gap-2">
            {scan.status === "completed" && (
              <Button onClick={downloadPdf} size="sm" className="bg-emerald-600 hover:bg-emerald-700">
                <Download className="h-4 w-4" /> PDF
              </Button>
            )}
            {isRunning && (
              <Button variant="outline" size="sm" onClick={() => cancelMut.mutate()} disabled={cancelMut.isPending} className="border-slate-600 text-slate-300">
                <X className="h-4 w-4" /> Cancel
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={() => { if(confirm("Delete?")) deleteMut.mutate(); }} disabled={deleteMut.isPending} className="border-red-800 text-red-400 hover:bg-red-900/40">
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {isRunning && (
          <div className="mt-4">
            <div className="mb-1 flex justify-between text-sm text-slate-300">
              <span>Scanning: {scan.current_module || "initializing..."}</span>
              <span>{scan.progress}%</span>
            </div>
            <Progress value={scan.progress} className="h-2" />
          </div>
        )}

        {/* Risk Score + Severity Counts */}
        <div className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-7">
          <div className="col-span-2 flex items-center gap-4 rounded-lg border border-slate-700 bg-slate-800/50 p-4">
            <div className="relative flex h-16 w-16 items-center justify-center">
              <svg viewBox="0 0 36 36" className="h-16 w-16 -rotate-90">
                <circle cx="18" cy="18" r="15.9" fill="none" stroke="currentColor" strokeWidth="3" className="text-slate-700" />
                <circle cx="18" cy="18" r="15.9" fill="none" strokeWidth="3" strokeDasharray={`${(scan.risk_score ?? 0) * 10}, 100`}
                  className={cn(
                    "transition-all duration-1000",
                    (scan.risk_score ?? 0) >= 7.5 ? "text-red-500" : (scan.risk_score ?? 0) >= 5 ? "text-orange-500" : (scan.risk_score ?? 0) >= 2.5 ? "text-yellow-400" : "text-emerald-400"
                  )} strokeLinecap="round" />
              </svg>
              <span className="absolute text-lg font-bold">{scan.risk_score?.toFixed(1) ?? "-"}</span>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-400">Risk Score</p>
              <p className="text-sm text-slate-300">{(scan.risk_score ?? 0) >= 7.5 ? "Critical Risk" : (scan.risk_score ?? 0) >= 5 ? "High Risk" : (scan.risk_score ?? 0) >= 2.5 ? "Medium Risk" : "Low Risk"}</p>
            </div>
          </div>
          {SEV_ORDER.map((s) => (
            <div key={s} className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/50 p-3">
              <div className={cn("h-2.5 w-2.5 rounded-full", SEV_DOT[s])} />
              <div>
                <p className="text-lg font-bold">{sevCounts[s]}</p>
                <p className="text-[10px] uppercase tracking-wider text-slate-400">{s}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* DNS & Network Info Panel */}
      {(dnsInfo || portInfo) && (
        <div className="grid gap-4 md:grid-cols-2">
          {dnsInfo && (
            <div className="rounded-xl border bg-card p-5 shadow-sm">
              <div className="mb-3 flex items-center gap-2">
                <Globe className="h-5 w-5 text-primary" />
                <h3 className="font-semibold">DNS & Network</h3>
              </div>
              <div className="space-y-2 text-sm">
                {(dnsInfo.resolved_ips as string[])?.length > 0 && (
                  <InfoRow label="IP Address(es)" value={(dnsInfo.resolved_ips as string[]).join(", ")} />
                )}
                {(dnsInfo.reverse_dns as Record<string, string>) && Object.entries(dnsInfo.reverse_dns as Record<string, string | null>).filter(([,v]) => v).map(([ip, host]) => (
                  <InfoRow key={ip} label={`rDNS (${ip})`} value={host!} />
                ))}
                {(dnsInfo.dns_records as Record<string, string[]>)?.NS && (
                  <InfoRow label="Nameservers" value={(dnsInfo.dns_records as Record<string, string[]>).NS!.join(", ")} />
                )}
                {(dnsInfo.dns_records as Record<string, string[]>)?.MX && (
                  <InfoRow label="Mail Servers" value={(dnsInfo.dns_records as Record<string, string[]>).MX!.join(", ")} />
                )}
                {(dnsInfo.dns_records as Record<string, string[]>)?.SOA && (
                  <InfoRow label="SOA" value={(dnsInfo.dns_records as Record<string, string[]>).SOA![0] ?? ""} />
                )}
              </div>
            </div>
          )}
          {portInfo && (
            <div className="rounded-xl border bg-card p-5 shadow-sm">
              <div className="mb-3 flex items-center gap-2">
                <Server className="h-5 w-5 text-primary" />
                <h3 className="font-semibold">Open Ports ({(portInfo.open_ports as Array<Record<string, unknown>>)?.length ?? 0})</h3>
              </div>
              <div className="max-h-56 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-xs uppercase text-muted-foreground">
                      <th className="py-1.5">Port</th>
                      <th className="py-1.5">Service</th>
                      <th className="py-1.5">Banner</th>
                    </tr>
                  </thead>
                  <tbody>
                    {((portInfo.open_ports as Array<Record<string, unknown>>) || []).map((p) => (
                      <tr key={String(p.port)} className="border-b border-border/30">
                        <td className="py-1.5 font-mono font-medium">{String(p.port)}</td>
                        <td className="py-1.5 text-muted-foreground">{String(p.service)}</td>
                        <td className="max-w-[200px] truncate py-1.5 font-mono text-xs text-muted-foreground">{p.banner ? String(p.banner) : "-"}</td>
                      </tr>
                    ))}
                    {((portInfo.open_ports as Array<Record<string, unknown>>) || []).length === 0 && (
                      <tr><td colSpan={3} className="py-3 text-center text-muted-foreground">No open ports found</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                Scanned {String(portInfo.total_scanned ?? "?")} ports on {String(portInfo.ip ?? portInfo.hostname ?? "")}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Module Tabs */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-card p-2">
        <button
          onClick={() => setActiveModule(null)}
          className={cn(
            "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
            activeModule === null ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent"
          )}
        >
          <Search className="h-3.5 w-3.5" /> All ({scan.vulnerabilities?.length ?? 0})
        </button>
        {Array.from(modules.entries()).map(([mod, vulns]) => {
          const info = MODULE_LABELS[mod] || { label: mod, icon: Shield };
          const Icon = info.icon;
          const hasCrit = vulns.some((v) => v.severity === "critical" || v.severity === "high");
          return (
            <button
              key={mod}
              onClick={() => setActiveModule(mod === activeModule ? null : mod)}
              className={cn(
                "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                mod === activeModule ? "bg-primary text-primary-foreground" : hasCrit ? "text-red-500 hover:bg-red-50 dark:hover:bg-red-950/30" : "text-muted-foreground hover:bg-accent"
              )}
            >
              <Icon className="h-3.5 w-3.5" /> {info.label} ({vulns.length})
            </button>
          );
        })}
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredVulns.length === 0 && !isRunning && (
          <div className="flex flex-col items-center justify-center rounded-xl border bg-card py-16 text-center">
            <ShieldCheck className="mb-3 h-12 w-12 text-emerald-500" />
            <p className="text-lg font-medium">No findings</p>
            <p className="text-sm text-muted-foreground">No vulnerabilities detected{activeModule ? " for this module" : ""}.</p>
          </div>
        )}
        {filteredVulns.map((v) => {
          const isCve = v.module === "cve_lookup" && !!v.evidence?.cve_id;
          const cveId = v.evidence?.cve_id as string | undefined;
          const cvssScore = v.evidence?.cvss_score as number | undefined;
          const cvssSev = v.evidence?.cvss_severity as string | undefined;
          const fixedIn = v.evidence?.fixed_in as string | undefined;
          const detectedVer = v.evidence?.detected_version as string | undefined;
          const cveProduct = v.evidence?.product as string | undefined;
          const cveSource = v.evidence?.source as string | undefined;
          return (
          <div key={v.id} className={cn("overflow-hidden rounded-lg border bg-card shadow-sm transition-shadow hover:shadow-md", isCve && "border-l-4", isCve && v.severity === "critical" && "border-l-red-500", isCve && v.severity === "high" && "border-l-orange-500", isCve && v.severity === "medium" && "border-l-yellow-400")}>
            <button
              type="button"
              onClick={() => toggle(v.id)}
              className="flex w-full items-start gap-3 p-4 text-left transition-colors hover:bg-accent/50"
            >
              <span className={cn("mt-0.5 inline-flex items-center rounded px-2 py-0.5 text-[11px] font-bold uppercase", SEV_STYLE[v.severity])}>
                {v.severity}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="font-medium leading-snug">{v.title}</p>
                  {isCve && cvssScore != null && (
                    <CvssBadge score={cvssScore} severity={cvssSev} />
                  )}
                  {isCve && (
                    <span className="rounded-full bg-indigo-900 px-2 py-0.5 text-[10px] font-semibold uppercase text-indigo-200">
                      NVD
                    </span>
                  )}
                </div>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {MODULE_LABELS[v.module]?.label ?? v.module}
                  {v.owasp_category && v.owasp_category !== "Informational" && (
                    <> &middot; {v.owasp_category}</>
                  )}
                  {!isCve && v.cvss_score != null && <> &middot; CVSS {v.cvss_score.toFixed(1)}</>}
                  {isCve && cveProduct && <> &middot; {cveProduct} {detectedVer}</>}
                </p>
              </div>
              {expanded.has(v.id) ? <ChevronDown className="mt-1 h-4 w-4 flex-shrink-0 text-muted-foreground" /> : <ChevronRight className="mt-1 h-4 w-4 flex-shrink-0 text-muted-foreground" />}
            </button>
            {expanded.has(v.id) && (
              <div className="border-t bg-muted/20 px-4 py-4">
                {isCve && (
                  <div className="mb-4 flex flex-wrap gap-3 rounded-lg border border-slate-700 bg-slate-900 p-3">
                    {cveId && (
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-slate-400">CVE ID</p>
                        <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 font-mono text-sm font-bold text-red-400 hover:text-red-300 hover:underline">
                          {cveId} <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                    )}
                    {cveProduct && (
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-slate-400">Product</p>
                        <p className="text-sm font-medium text-slate-200">{cveProduct}</p>
                      </div>
                    )}
                    {detectedVer && (
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-slate-400">Detected Ver.</p>
                        <p className="font-mono text-sm font-medium text-yellow-400">{detectedVer}</p>
                      </div>
                    )}
                    {fixedIn && (
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-slate-400">Fixed In</p>
                        <p className="font-mono text-sm font-medium text-emerald-400">{fixedIn}</p>
                      </div>
                    )}
                    {cvssScore != null && (
                      <div>
                        <p className="text-[10px] uppercase tracking-wider text-slate-400">CVSS Score</p>
                        <CvssBadge score={cvssScore} severity={cvssSev} large />
                      </div>
                    )}
                  </div>
                )}
                <div className="grid gap-4 md:grid-cols-2">
                  <DetailSection title="Description" content={v.description} />
                  {v.remediation && <DetailSection title="Remediation" content={v.remediation} />}
                </div>
                {v.reference_url && (
                  <div className="mt-3">
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Reference</p>
                    <a href={v.reference_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-sm text-primary hover:underline">
                      {v.reference_url} <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                )}
                {v.evidence && Object.keys(v.evidence).length > 0 && !isCve && (
                  <div className="mt-3">
                    <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Evidence</p>
                    <pre className="max-h-64 overflow-auto rounded-md border bg-slate-950 p-3 font-mono text-xs text-slate-300">
                      {JSON.stringify(v.evidence, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
          );
        })}
      </div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="whitespace-nowrap text-xs font-medium text-muted-foreground">{label}</span>
      <span className="break-all text-right font-mono text-xs">{value}</span>
    </div>
  );
}

function DetailSection({ title, content }: { title: string; content: string }) {
  return (
    <div>
      <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{title}</p>
      <p className="whitespace-pre-wrap text-sm leading-relaxed">{content}</p>
    </div>
  );
}

function CvssBadge({ score, severity, large }: { score: number; severity?: string; large?: boolean }) {
  const s = severity?.toUpperCase() ?? (score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW");
  const colors: Record<string, string> = {
    CRITICAL: "bg-red-600 text-white",
    HIGH: "bg-orange-600 text-white",
    MEDIUM: "bg-yellow-500 text-black",
    LOW: "bg-blue-600 text-white",
  };
  return (
    <span className={cn(
      "inline-flex items-center gap-1 rounded-full font-bold",
      colors[s] || "bg-slate-600 text-white",
      large ? "px-3 py-1 text-sm" : "px-2 py-0.5 text-[10px]",
    )}>
      {score.toFixed(1)}
    </span>
  );
}
