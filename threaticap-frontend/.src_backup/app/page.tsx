/* eslint-disable */
import { useInView } from "react-intersection-observer";
import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import {
  useThreats,
  useHealth,
  useMetrics,
  useCommanderStore,
  useSelectedThreat,
  useTlpFilter,
  useMitreTactic,
  stores,
} from "@/lib/api/service";
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from "@/components/ui/card";
import { ProgressRing } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "@/lib/api/service";

export default function OperationsDashboard() {
  const {
    data: threats,
    isLoading,
    isError,
  } = useThreats(
    {},
    { enabled: false } // Will be loaded on mount via useEffect
  );

  const { data: health } = useHealth();
  const { data: metrics } = useMetrics();

  const { active: commanderActive, threatId: commanderThreatId } =
    useCommanderStore();

  const { threatId: selectedThreatId } = useSelectedThreat();
  const { tlps } = useTlpFilter();
  const { tactics } = useMitreTactic();

  // Initialize threats load on mount
  useEffect(() => {
    // Trigger threat fetch
    if (!isLoading && !isError) {
      // Query will run
    }
  }, []);

  // Load threats after mount
  useEffect(() => {
    // The useThreats query should be enabled
  }, []);

  // Card data helpers
  const criticalCount = threats?.threats?.filter(
    (t) => t.priority_score.priority_tier === "CRITICAL"
  ).length || 0;

  const highCount = threats?.threats?.filter(
    (t) => t.priority_score.priority_tier === "HIGH"
  ).length || 0;

  const mediumCount = threats?.threats?.filter(
    (t) => t.priority_score.priority_tier === "MEDIUM"
  ).length || 0;

  const lowCount = threats?.threats?.filter(
    (t) => t.priority_score.priority_tier === "LOW"
    ).length || 0;

  const totalThreats = criticalCount + highCount + mediumCount + lowCount;

  const avgConfidence =
    threats?.threats?.reduce(
      (sum, t) => sum + t.priority_score.final_score,
      0,
    ) / Math.max(1, totalThreats) || 0;

  const alerts24h = metrics?.alerts_total || 0;

  // Commander mode handler
  const handleCommanderSelect = (threatId: string) => {
    useCommanderStore.getState().setActive(true, threatId);
    useSelectedThreat.getState().setThreatId(threatId);
  };

  return (
    <section className="p-4 md:p-6">
      {/* Header with Commander Mode toggle */}
      <header className="mb-6 flex flex-col md:flex-row items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tighter">
            THREATICAP Operations Dashboard
          </h1>
          {commanderActive && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                useCommanderStore.getState().setActive(false);
                useSelectedThreat.getState().setThreatId(null);
              }}
              className="flex items-center gap-1"
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
              >
                <line x1="3" y1="3" x2="21" y2="21"/>
                <line x1="3" y2="21" x2="21" y2="3"/>
              </svg>
              Exit Commander Mode
            </Button>
          )}
        </div>

        {/* Summary cards grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Critical Card */}
          <Card className="group border-critical-500/20">
            <CardHeader className="p-3">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-critical-500 animate-pulse-slow"></div>
                <span className="text-sm font-medium text-critical-400">
                  {criticalCount} CRITICAL
                </span>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold mt-1">{criticalCount}</p>
              <p className="text-xs text-muted-foreground">Active threats</p>
            </CardContent>
          </Card>

          {/* High Card */}
          <Card className="group border-orange-500/20">
            <CardHeader className="p-3">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-orange-400 animate-pulse-slow" style="animation-delay: 0.1s"></div>
                <span className="text-sm font-medium text-orange-300">
                  {highCount} HIGH
                </span>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold mt-1">{highCount}</p>
              <p className="text-xs text-muted-foreground">Active threats</p>
            </CardContent>
          </Card>

          {/* Medium Card */}
          <Card className="group border-yellow-500/20">
            <CardHeader className="p-3">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-yellow-400 animate-pulse-slow" style="animation-delay: 0.2s"></div>
                <span className="text-sm font-medium text-yellow-300">
                  {mediumCount} MEDIUM
                </span>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold mt-1">{mediumCount}</p>
              <p className="text-xs text-muted-foreground">Active threats</p>
            </CardContent>
          </Card>

          {/* Low Card */}
          <Card className="group border-blue-500/20">
            <CardHeader className="p-3">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse-slow" style="animation-delay: 0.3s"></div>
                <span className="text-sm font-medium text-blue-300">
                  {lowCount} LOW
                </span>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold mt-1">{lowCount}</p>
              <p className="text-xs text-muted-foreground">Active threats</p>
            </CardContent>
          </Card>
        </div>

        {/* Additional metrics row */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4 md:mt-0">
          {/* Avg Confidence Card */}
          <Card>
            <CardHeader className="p-3">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-cyan-400"></div>
                <span className="text-sm font-medium text-cyan-300">
                  Avg Confidence
                </span>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold">{Math.round(avgConfidence)}</p>
              <p className="text-xs text-muted-foreground">/100</p>
            </CardContent>
          </Card>

          {/* Alerts 24h Card */}
          <Card>
            <CardHeader className="p-3">
              <div className="flex items-center gap-2">
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  className="animate-spin"
                >
                  <circle
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="var(--primary)"
                    stroke-width="3"
                    opacity="0.6"
                  />
                </svg>
                <span className="text-sm font-medium text-muted-foreground">
                  Alerts (24h)
                </span>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold">{alerts24h}</p>
              <p className="text-xs text-muted-foreground">ingested</p>
            </CardContent>
          </Card>
        </div>
      </header>

      {/* Priority Distribution Chart Section */}
      <div className="mt-6 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {/* Priority distribution mini-bars */}
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((tier, idx) => (
          <Card key={tier} className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium">
                {tier} {"▲".repeat(3)}
              </span>
              <span className="text-xs text-muted-foreground">
                {threats?.threats?.filter(
                  (t) => t.priority_score.priority_tier === tier
                ).length || 0}
              </span>
            </div>
            <div className="h-2 bg-navy-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-opacity-100 rounded-full"
                style={{
                  width: `${threats?.threats?.filter(
                    (t) => t.priority_score.priority_tier === tier
                  ).length / Math.max(1, totalThreats || 1) * 100}%`,
                  backgroundTier: tier,
                }}
              >
              </div>
            </div>
          </Card>
        ))}

        {/* Recent BLUF Cards */}
      </div>

      {/* Recent Critical/High BLUF cards section */}
      <div className="mt-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
          >
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="18" x2="18" y2="6"/>
          </svg>
          Recent BLUF Cards
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {threats?.threats
            .filter(
              (t) =>
                t.priority_score.priority_tier === "CRITICAL" ||
                t.priority_score.priority_tier === "HIGH"
            )
            .slice(0, 6)
            .map((threat) => (
              <BlufPreviewCard
                key={threat.threat_id}
                threat={threat}
                onSelect={() => {
                  useCommanderStore.getState().setActive(true, threat.threat_id);
                  useSelectedThreat.getState().setThreatId(threat.threat_id);
                }}
              />
            ))}
        </div>

        {/* Empty state */}
        {totalThreats === 0 && (
          <div className="mt-6 p-6 text-muted-foreground/60 text-center">
            <svg
              width="48"
              height="48"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="1"
              className="mx-auto mb-3 opacity-40"
            >
              <circle cx="12" cy="12" r="10"/>
              <line x1="8" y1="12" x2="16" y2="12"/>
              <line x1="12" y1="8" x2="12" y2="16"/>
            </svg>
            <p>No correlated threats found</p>
            <p className="mt-2 text-sm">The threat queue will appear here as alerts are ingested and correlated.</p>
          </div>
        )}
      </div>

      {/* System Health Indicator */}
      {health && (
        <div className="mt-6 p-4 rounded-lg border bg-navy-800/50">
          <div className="flex items-center gap-3">
            <div className="w-3 h-3 rounded-full">
              {health.status === "HEALTHY"
                ? /* green */ ""
                : health.status === "DEGRADED"
                  ? /* orange */ ""
                  : /* red */ ""}
              </div>
              <div>
                <p className="font-medium">{health.status}</p>
                <p className="text-xs text-muted-foreground">
                  {Math.round(health.uptime_seconds / 60)} uptime min
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Live Activity Feed (Audit events) */}
      <div className="mt-6">
        <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
          >
            <polyline points="22 12 18 12 15 15 9 3 6 12 2 12"/>
            <polyline points="y2 12 8 12 5 15 10 20 15 15 20 20 10 20 20 20 12 22 12"/>
          </svg>
          Live Activity Feed
        </h2>
        <div className="h-96 border rounded-lg bg-navy-800 overflow-hidden">
          <div className="p-4 pt-0">
            {isError
              ? (
                <p className="text-muted-foreground/60">Error loading activity feed</p>
              )
              : isLoading
                ? (
                  <div className="flex items-center justify-center h-full">
                    <ProgressRing size="24" className="mr-2"/>
                    <span className="text-muted-foreground">Loading audit events...</span>
                  </div>
                )
                : threats?.audit_records
                  ?.slice(0, 10)
                  .map(
                    (record: any, idx: number) => (
                      <div
                        key={record.audit_id}
                        className="flex items-start gap-3 py-2 border-b border-navy-800/20 last:border-0"
                      >
                        <div className="w-2 h-2 rounded-full bg-cyan-400 flex-shrink-0 mt-1"
                          style={{ animationDelay: `${idx * 0.1}s` }}
                        ></div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">
                            {record.summary || record.event_type}
                          </p>
                          <p className="text-xs text-muted-foreground truncate">
                            {new Date(record.timestamp).toLocaleTimeString()}
                          </p>
                        </div>
                      </div>
                    )
                  )
                  : (
                  <p className="text-muted-foreground/60 p-2">No recent audit events</p>
                )}
          </div>
        </div>
      </div>
    </section>
  );
}

/* BLUF Preview Card Component */
function BlufPreviewCard({
  threat,
  onSelect,
}: {
  threat: CorrelatedThreat;
  onSelect: () => void;
}) {
  const tierColors = {
    CRITICAL: "critical-500",
    HIGH: "orange-400",
    MEDIUM: "yellow-400",
    LOW: "blue-400",
  };

  return (
    <Card onClick={onSelect} className="cursor-pointer hover:opacity-80 transition-opacity">
      <CardHeader className="p-3">
        <div className="flex items-center gap-2">
          <div
            className={`w-2 h-2 rounded-full ${tierColors[threat.priority_score.priority_tier]} animate-pulse-slow`}
          />
          <span className="text-sm font-medium truncate">
            {threat.title || threat.id}
          </span>
        </div>
      </CardHeader>
      <CardContent className="p-3 text-sm">
        <p className="line-clamp-2 text-muted-foreground/80">
          {threat.bottom_line || "Bottom line loading..."}
        </p>
        <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
          <span>
            {threat.priority_score.priority_tier} • 
            {Math.round(threat.priority_score.final_score)} confidence
          </span>
        </div>
      </CardContent>
    </Card>
  );
}