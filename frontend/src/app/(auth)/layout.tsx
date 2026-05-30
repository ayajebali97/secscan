import { Shield } from "lucide-react";
import Link from "next/link";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-slate-50 to-background">
      <div className="container flex min-h-screen flex-col items-center justify-center py-8 px-4">
        <Link href="/" className="mb-8 flex items-center gap-2 text-foreground hover:opacity-80 transition-opacity">
          <Shield className="h-7 w-7 text-primary" />
          <span className="text-2xl font-bold">SecScan</span>
        </Link>
        {children}
      </div>
    </div>
  );
}
