export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ScanStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type ScanModule =
  | "headers"
  | "ssl"
  | "ports"
  | "web_vuln"
  | "subdomain"
  | "fingerprint"
  | "dns_recon"
  | "cve_lookup";

export type UserRole = "admin" | "analyst" | "viewer";

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  is_verified: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface Vulnerability {
  id: string;
  module: string;
  title: string;
  description: string;
  severity: Severity;
  owasp_category: string;
  cvss_score: number | null;
  evidence: Record<string, unknown> | null;
  remediation: string | null;
  reference_url: string | null;
  created_at: string;
}

export interface Scan {
  id: string;
  target_url: string;
  target_host: string;
  status: ScanStatus;
  modules: string[];
  depth: string;
  progress: number;
  current_module: string | null;
  risk_score: number | null;
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface ScanDetail extends Scan {
  vulnerabilities: Vulnerability[];
}

export interface ScanList {
  items: Scan[];
  total: number;
  page: number;
  page_size: number;
}

export interface ScanStats {
  total_scans: number;
  status_counts: Record<string, number>;
  severity_counts: Record<Severity, number>;
  average_risk_score: number | null;
  max_severity_score: number;
}
