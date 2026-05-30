import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date): string {
  const d = typeof date === "string" ? new Date(date) : date;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-red-900 text-white";
    case "high":
      return "bg-red-600 text-white";
    case "medium":
      return "bg-amber-500 text-white";
    case "low":
      return "bg-blue-600 text-white";
    default:
      return "bg-slate-500 text-white";
  }
}
