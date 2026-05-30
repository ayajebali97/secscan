"use client";

import * as React from "react";
import * as ToastPrimitive from "@radix-ui/react-toast";

import { cn } from "@/lib/utils";

type Toast = {
  id: string;
  title: string;
  description?: string;
  variant?: "default" | "destructive";
};

type ToastContextValue = {
  toasts: Toast[];
  push: (toast: Omit<Toast, "id">) => void;
};

const ToastContext = React.createContext<ToastContextValue | null>(null);

let toastListener: ((t: Omit<Toast, "id">) => void) | null = null;

export function toast(t: Omit<Toast, "id">) {
  toastListener?.(t);
}

export function Toaster() {
  const [toasts, setToasts] = React.useState<Toast[]>([]);

  const push = React.useCallback((t: Omit<Toast, "id">) => {
    const id = Math.random().toString(36).slice(2);
    setToasts((cur) => [...cur, { id, ...t }]);
    setTimeout(() => {
      setToasts((cur) => cur.filter((x) => x.id !== id));
    }, 5000);
  }, []);

  React.useEffect(() => {
    toastListener = push;
    return () => {
      toastListener = null;
    };
  }, [push]);

  return (
    <ToastContext.Provider value={{ toasts, push }}>
      <ToastPrimitive.Provider swipeDirection="right">
        {toasts.map((t) => (
          <ToastPrimitive.Root
            key={t.id}
            className={cn(
              "group pointer-events-auto relative flex w-full items-center justify-between space-x-4 overflow-hidden rounded-md border p-4 pr-6 shadow-lg transition-all",
              t.variant === "destructive"
                ? "border-destructive bg-destructive text-destructive-foreground"
                : "border bg-background text-foreground"
            )}
          >
            <div className="grid gap-1">
              <ToastPrimitive.Title className="text-sm font-semibold">
                {t.title}
              </ToastPrimitive.Title>
              {t.description && (
                <ToastPrimitive.Description className="text-sm opacity-90">
                  {t.description}
                </ToastPrimitive.Description>
              )}
            </div>
          </ToastPrimitive.Root>
        ))}
        <ToastPrimitive.Viewport className="fixed bottom-0 right-0 z-[100] flex max-h-screen w-full flex-col-reverse gap-2 p-4 sm:bottom-4 sm:right-4 sm:top-auto sm:flex-col md:max-w-[420px]" />
      </ToastPrimitive.Provider>
    </ToastContext.Provider>
  );
}
