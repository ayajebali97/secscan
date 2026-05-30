"use client";

import { useQuery } from "@tanstack/react-query";
import {
  LayoutDashboard,
  LogOut,
  PlusCircle,
  Search,
  Shield,
} from "lucide-react";
import Link from "next/link";
import { useRouter, usePathname } from "next/navigation";
import { useEffect } from "react";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth";

const nav = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/scans", label: "Scans", icon: Search },
  { href: "/scans/new", label: "New Scan", icon: PlusCircle },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { accessToken, user, clear, setUser } = useAuthStore();

  useEffect(() => {
    if (!accessToken) {
      router.replace("/login");
    }
  }, [accessToken, router]);

  useQuery({
    queryKey: ["me"],
    enabled: Boolean(accessToken) && !user,
    queryFn: async () => {
      const { data } = await api.get("/users/me");
      setUser(data);
      return data;
    },
  });

  if (!accessToken) return null;

  function handleLogout() {
    clear();
    router.replace("/login");
  }

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 flex-shrink-0 border-r border-border bg-card md:flex md:flex-col shadow-sm">
        <div className="flex h-16 items-center gap-2 border-b border-border px-6 bg-card/50">
          <Shield className="h-6 w-6 text-primary" />
          <span className="text-lg font-bold text-foreground">SecScan</span>
        </div>
        <nav className="flex-1 space-y-1 p-3">
          {nav.map((item) => {
            const Icon = item.icon;
            const active = pathname === item.href || pathname?.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-all duration-200",
                  active
                    ? "bg-primary/10 text-primary shadow-sm"
                    : "text-muted-foreground hover:bg-muted/60 hover:text-foreground"
                )}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-border bg-muted/20 p-3">
          <div className="mb-3 rounded-lg px-2 py-2">
            <p className="truncate font-medium text-foreground text-sm">{user?.full_name || user?.email}</p>
            <p className="text-xs text-muted-foreground mt-0.5">{user?.role}</p>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleLogout}
            className="w-full justify-start text-muted-foreground hover:text-foreground hover:bg-muted/60"
          >
            <LogOut className="h-4 w-4" /> Sign out
          </Button>
        </div>
      </aside>

      <main className="flex-1 overflow-x-hidden bg-background">
        <div className="container py-8 px-4 md:px-6">{children}</div>
      </main>
    </div>
  );
}
