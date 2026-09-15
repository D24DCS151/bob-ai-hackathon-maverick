/**
 * THREATICAP Root Layout
 * 
 * Defines the HTML structure, meta tags, and provides the
 * React Query Provider for the entire application.
 * Dark mode is set via the theme store with system fallback.
 */

import "./globals.css";
import { ThemeProvider } from "next-themes";
import { ReactQueryProvider } from "@tanstack/react-query";
import { useEffect } from "react";
import { useThemeStore } from "@/stores/theme";
import { CommanderProvider, useCommanderStore } from "@/stores/commander";
import { SelectedThreatProvider, useSelectedThreat } from "@/stores/selected-threat";
import { TlpFilterProvider, useTlpFilter } from "@/stores/tlp-filter";
import { MitreTacticProvider, useMitreTactic } from "@/stores/mitre-tactic";
import { toast } from "@/lib/api/service";

export const metadata = {
  title: "THREATICAP v3.0",
  description:
    "Threat Intelligence Correlation & Alert Prioritisation System - Command & Control",
  keywords: [
    "threat-intelligence",
    "cyber-defence",
    "att&ck",
    "malware-analysis",
    "incident-response",
    "command-control",
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { mode } = useThemeStore();

  // Set dark mode class on mount
  useEffect(() => {
    const setDarkMode = () => {
      if (mode === "dark") {
        document.documentElement.classList.add("dark");
      } else if (mode === "light") {
        document.documentElement.classList.remove("dark");
      } else {
        // system mode - let the browser decide
        if (
          window.matchMedia("(prefers-color-scheme: dark)").matches
        ) {
          document.documentElement.classList.add("dark");
        } else {
          document.documentElement.classList.remove("dark");
        }
      }
    };

    setDarkMode();

    const observer = new MutationObserver(setDarkMode);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeClass: true,
    });

    return () => observer.disconnect();
  }, [mode]);

  return (
    <html lang="en" suppressHydrationWarning={true}>
      <body
        className=" antialiased bg-navy-950 text-white min-h-screen"
      >
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
        >
          <CommanderProvider>
            <SelectedThreatProvider>
              <TlpFilterProvider>
                <MitreTacticProvider>
                  <ReactQueryProvider
                    defaultOptions={queries: {
                      queries: {
                        staleTime: 30_000,
                        retry: 2,
                        retryDelay: 500,
                      },
                    }}
                  >
                    {children}
                  </ReactQueryProvider>
                </MitreTacticProvider>
              </TlpFilterProvider>
            </SelectedThreatProvider>
          </CommanderProvider>
        </ThemeProvider>

        {/* Global toast container */}
        <div
          id="toast-container"
          className="fixed top-4 right-4 z-50 flex flex-col gap-2 pointer-events-none"
        />
      </body>
    </html>
  );
}