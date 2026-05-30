import Link from "next/link";
import { Shield, Lock, Activity, FileText } from "lucide-react";

import { Button } from "@/components/ui/button";

export default function HomePage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      <header className="container flex items-center justify-between py-6">
        <div className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-primary" />
          <span className="text-xl font-bold">SecScan</span>
        </div>
        <nav className="flex items-center gap-3">
          <Link href="/login">
            <Button variant="ghost" className="text-white hover:bg-white/10">
              Sign in
            </Button>
          </Link>
          <Link href="/register">
            <Button>Get started</Button>
          </Link>
        </nav>
      </header>

      <section className="container mt-16 max-w-4xl text-center">
        <h1 className="text-5xl font-bold tracking-tight md:text-6xl">
          Find vulnerabilities before <span className="text-primary">attackers do</span>
        </h1>
        <p className="mx-auto mt-6 max-w-2xl text-lg text-slate-300">
          SecScan audits web applications for OWASP Top 10 issues, TLS
          misconfigurations, exposed services, and outdated components -- and
          delivers actionable PDF reports for your team.
        </p>
        <div className="mt-10 flex justify-center gap-4">
          <Link href="/register">
            <Button size="lg" className="text-base">
              Start scanning
            </Button>
          </Link>
          <Link href="/login">
            <Button size="lg" variant="outline" className="border-white/20 bg-transparent text-base text-white hover:bg-white/10">
              I already have an account
            </Button>
          </Link>
        </div>
      </section>

      <section className="container mt-24 grid gap-6 pb-24 md:grid-cols-3">
        <Feature
          icon={<Shield className="h-6 w-6" />}
          title="OWASP Top 10 coverage"
          body="Active probes for XSS, SQL injection, open redirects, CORS misconfigs, sensitive paths, and more."
        />
        <Feature
          icon={<Lock className="h-6 w-6" />}
          title="TLS & headers audit"
          body="Inspects certificates, weak protocols, ciphers, HSTS, CSP, and a full battery of HTTP security headers."
        />
        <Feature
          icon={<Activity className="h-6 w-6" />}
          title="Recon & fingerprinting"
          body="Subdomain enumeration via CT logs, port scanning, and technology fingerprinting with version detection."
        />
        <Feature
          icon={<FileText className="h-6 w-6" />}
          title="PDF audit reports"
          body="Executive-ready PDF reports mapped to OWASP 2021 categories with remediation guidance."
        />
        <Feature
          icon={<Lock className="h-6 w-6" />}
          title="Hardened by design"
          body="JWT auth, rate limiting, strict CSP, non-root containers, SSRF-prevention, and full security headers."
        />
        <Feature
          icon={<Activity className="h-6 w-6" />}
          title="Async scan engine"
          body="Distributed scanning powered by Celery workers, with real-time progress tracking."
        />
      </section>
    </div>
  );
}

function Feature({
  icon,
  title,
  body,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
}) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/5 p-6 backdrop-blur">
      <div className="mb-3 inline-flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
        {icon}
      </div>
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="mt-2 text-sm text-slate-300">{body}</p>
    </div>
  );
}
