"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { toast } from "@/components/ui/toaster";
import { api, apiError } from "@/lib/api";

const MODULES: { id: string; label: string; help: string }[] = [
  { id: "dns_recon", label: "DNS Reconnaissance", help: "A/AAAA/MX/NS/TXT/SOA records, reverse DNS, SPF/DMARC check." },
  { id: "headers", label: "Security Headers", help: "CSP, HSTS, X-Frame-Options, X-CTO, Referrer-Policy audit." },
  { id: "ssl", label: "SSL/TLS Analyzer", help: "Certificate expiry, SAN, weak protocols & ciphers." },
  { id: "ports", label: "Port Scanner", help: "TCP port scan with service detection & banner grabbing." },
  { id: "web_vuln", label: "Web Vulnerabilities", help: "XSS, SQLi, open redirect, CORS, 60+ sensitive paths." },
  { id: "subdomain", label: "Subdomain Enum", help: "CT log (crt.sh) + wordlist DNS brute-force." },
  { id: "fingerprint", label: "Tech Fingerprint", help: "Detect web server, CMS, frameworks, JS libraries." },
  { id: "cve_lookup", label: "CVE Detector", help: "Cross-reference detected tech versions against NVD for known CVEs." },
];

const schema = z.object({
  target_url: z
    .string()
    .url("Enter a full URL (https://example.com)")
    .refine((u) => /^https?:\/\//i.test(u), "URL must start with http(s)://"),
  modules: z.array(z.string()).min(1, "Select at least one module"),
  depth: z.enum(["quick", "standard", "deep"]),
});
type Input = z.infer<typeof schema>;

export default function NewScanPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  const {
    register,
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<Input>({
    resolver: zodResolver(schema),
    defaultValues: {
      target_url: "",
      modules: ["dns_recon", "headers", "ssl", "ports", "web_vuln", "subdomain", "fingerprint", "cve_lookup"],
      depth: "standard",
    },
  });

  async function onSubmit(values: Input) {
    setLoading(true);
    try {
      const { data } = await api.post("/scans", values);
      toast({
        title: "Scan started",
        description: `Target: ${data.target_host}`,
      });
      router.replace(`/scans/${data.id}`);
    } catch (err) {
      toast({
        title: "Could not start scan",
        description: apiError(err),
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-3xl">
      <h1 className="mb-1 text-3xl font-bold">New scan</h1>
      <p className="mb-6 text-muted-foreground">
        Run a security audit against a target you own or are explicitly
        authorized to scan.
      </p>

      <form onSubmit={handleSubmit(onSubmit)} noValidate>
        <Card>
          <CardHeader>
            <CardTitle>Target</CardTitle>
            <CardDescription>
              Provide the full URL including the protocol. Private/internal
              addresses are blocked.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="target_url">URL</Label>
              <Input
                id="target_url"
                placeholder="https://example.com"
                {...register("target_url")}
              />
              {errors.target_url && (
                <p className="text-sm text-destructive">
                  {errors.target_url.message}
                </p>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Modules</CardTitle>
            <CardDescription>
              Pick which checks to run. More modules increase scan duration.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Controller
              control={control}
              name="modules"
              render={({ field }) => (
                <div className="grid gap-3 md:grid-cols-2">
                  {MODULES.map((m) => {
                    const checked = field.value.includes(m.id);
                    return (
                      <label
                        key={m.id}
                        className="flex cursor-pointer items-start gap-3 rounded-md border bg-card p-4 transition-colors hover:bg-accent"
                      >
                        <Checkbox
                          checked={checked}
                          onCheckedChange={(c) => {
                            if (c) field.onChange([...field.value, m.id]);
                            else field.onChange(field.value.filter((x: string) => x !== m.id));
                          }}
                        />
                        <div>
                          <p className="font-medium">{m.label}</p>
                          <p className="text-xs text-muted-foreground">{m.help}</p>
                        </div>
                      </label>
                    );
                  })}
                </div>
              )}
            />
            {errors.modules && (
              <p className="mt-2 text-sm text-destructive">{errors.modules.message}</p>
            )}
          </CardContent>
        </Card>

        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Scan depth</CardTitle>
            <CardDescription>
              Depth controls aggressiveness and runtime.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Controller
              control={control}
              name="depth"
              render={({ field }) => (
                <RadioGroup
                  value={field.value}
                  onValueChange={field.onChange}
                  className="grid gap-3 md:grid-cols-3"
                >
                  {[
                    { value: "quick", label: "Quick", help: "Fast surface check" },
                    { value: "standard", label: "Standard", help: "Recommended" },
                    { value: "deep", label: "Deep", help: "Time-based SQLi, larger port range" },
                  ].map((d) => (
                    <label
                      key={d.value}
                      className="flex cursor-pointer items-start gap-3 rounded-md border bg-card p-4"
                    >
                      <RadioGroupItem value={d.value} className="mt-1" />
                      <div>
                        <p className="font-medium">{d.label}</p>
                        <p className="text-xs text-muted-foreground">{d.help}</p>
                      </div>
                    </label>
                  ))}
                </RadioGroup>
              )}
            />
          </CardContent>
          <CardFooter className="justify-end">
            <Button type="submit" disabled={loading}>
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              Start scan
            </Button>
          </CardFooter>
        </Card>
      </form>
    </div>
  );
}
