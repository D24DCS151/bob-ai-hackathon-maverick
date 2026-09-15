/**
 * THREATICAP API Service
 * 
 * Encapsulates all API calls for the THREATICAP frontend.
 * Wraps the low-level request function with React Query–compatible
 * methods and provides typed endpoints matching the backend v1 API.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { 
  alert, 
  api, 
  type CorrelatedThreat, 
  type BlufReport, 
  type PriorityTier,
  type Role,
  type Verdict,
  type TLP,
  type PriorityScore,
  type AnalystFeedback,
  type AuditRecord,
  type ThreatListResponse,
  type PipelineRunResponse,
  type AlertSubmitResponse,
  type BlufReportListResponse,
  type HealthResponse,
  type MetricsResponse,
  type ErrorResponse,
  type FeedbackSubmitResponse,
  type ThreatListFilters,
  type AlertListFilters,
  type CommanderBluf
} from "../types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080";

// ===== Threats =====

export interface UseThreatsOptions extends Partial<ThreatListFilters> {
  enabled?: boolean;
}

export function useThreats(filters: ThreatListFilters = {}, options: UseThreatsOptions = {}) {
  return useQuery<ThreatListResponse, Error>({
    queryKey: ["threats", filters],
    queryFn: () => fetchThreats(filters),
    staleTime: 30_000,
    ...options,
  });
}

export function useThreatDetail(
  threatId: string,
  enabled: boolean = true
) {
  return useQuery<ThreatDetailResponse, Error>({
    queryKey: ["threat", threatId],
    queryFn: () => fetchThreatDetail(threatId),
    enabled,
    staleTime: 60_000,
  });
}

export function useBlufReport(
  threatId: string,
  format: "json" | "text" = "json",
  enabled: boolean = true
) {
  return useQuery<BlufReport, Error>({
    queryKey: ["bluf", threatId, format],
    queryFn: () => fetchBlufReport(threatId, format),
    enabled,
    staleTime: 60_000,
  });
}

export function useAttackGraph(threatId: string, enabled: boolean = true) {
  return useQuery<any, Error>({
    queryKey: ["attack-graph", threatId],
    queryFn: () => fetchAttackGraph(threatId),
    enabled,
    staleTime: 120_000,
  });
}

export function useFeedbackHistory(threatId: string, enabled: boolean = true) {
  return useQuery<AnalystFeedback[], Error>({
    queryKey: ["feedback", threatId],
    queryFn: () => fetchFeedbackHistory(threatId),
    enabled,
    staleTime: 60_000,
  });
}

// ===== Alerts =====

export interface UseAlertsOptions extends Partial<AlertListFilters> {
  enabled?: boolean;
}

export function useAlerts(filters: AlertListFilters = {}, options: UseAlertsOptions = {}) {
  return useQuery<any[], Error>({
    queryKey: ["alerts", filters],
    queryFn: () => fetchAlerts(filters),
    staleTime: 30_000,
    ...options,
  });
}

export function useAlertDetail(alertId: string, enabled: boolean = true) {
  return useQuery<any, Error>({
    queryKey: ["alert", alertId],
    queryFn: () => fetchAlertDetail(alertId),
    enabled,
    staleTime: 60_000,
  });
}

// ===== Pipeline =====

export function useRunPipelineMutation() {
  const queryClient = useQueryClient();

  return useMutation<PipelineRunResponse, Error, { alert_limit?: number }>({
    mutationFn: ({ alert_limit }) => runPipeline(alert_limit),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["threats"] });
      queryClient.invalidateQueries({ queryKey: ["metrics"] });
      toast.success("Pipeline run completed", {
        description: `Processed ${data.alerts_processed} alerts, created ${data.threats_created} threats`,
      });
    },
    onError: (error: Error) => {
      toast.error("Pipeline run failed", {
        description: error.message,
      });
    },
  });
}

// ===== Reports =====

export function useReports(enabled: boolean = true) {
  return useQuery<BlufReportListResponse, Error>({
    queryKey: ["reports"],
    queryFn: () => fetchReports(),
    enabled,
    staleTime: 60_000,
  });
}

export function useReportDetail(reportId: string, enabled: boolean = true) {
  return useQuery<any, Error>({
    queryKey: ["report", reportId],
    queryFn: () => fetchReportDetail(reportId),
    enabled,
    staleTime: 60_000,
  });
}

// ===== Health & Metrics =====

export function useHealth() {
  return useQuery<HealthResponse, Error>({
    queryKey: ["health"],
    queryFn: () => fetchHealth(),
    staleTime: 15_000,
  });
}

export function useMetrics() {
  return useQuery<MetricsResponse, Error>({
    queryKey: ["metrics"],
    queryFn: () => fetchMetrics(),
    staleTime: 30_000,
  });
}

// ===== Commander Mode =====

export function useCommanderBluf(threatId: string) {
  const { data: bluf } = useBlufReport(threatId, "text", true);
  
  return {
    bottomLine: bluf?.bottom_line || "Loading BLUF...",
    priorityTier: (bluf?.priority_tier as PriorityTier) || "LOW",
    confidenceLevel: bluf?.confidence_level || "LOW",
    tlp: bluf?.tlp || "TLP:AMBER",
    keyEvidence: bluf?.key_evidence || [],
    immediateActions: bluf?.immediate_actions || [],
  };
}

// ===== Mutation: Analyst Feedback =====

export function useSubmitFeedback() {
  const queryClient = useQueryClient();

  return useMutation<FeedbackSubmitResponse, Error, {
    threatId: string;
    verdict: Verdict;
    confidence?: number;
    notes?: string;
  }>({
    mutationFn: ({
      threatId,
      verdict,
      confidence = 100,
      notes,
    }) => submitFeedback(threatId, verdict, confidence, notes),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["feedback", variables.threatId] });
      queryClient.invalidateQueries({ queryKey: ["threats"] });
      toast.success("Feedback submitted", {
        description: `${variables.verdict.replace("_", " ")} - Feedback recorded`,
      });
    },
    onError: (error: Error) => {
      toast.error("Feedback submission failed", {
        description: error.message,
      });
    },
  });
}

// ===== Mutation: API Key Creation (Admin) =====

export function useCreateApiKey() {
  const queryClient = useQueryClient();

  return useMutation<{ api_key: string }, Error, { name: string; role: Role }>({
    mutationFn: ({ name, role }) => createApiKey(name, role),
    onSuccess: (data) => {
      toast.success("API key created", {
        description: "Key has been generated and stored securely",
      });
      queryClient.invalidateQueries({ queryKey: ["system", "api-keys"] });
    },
    onError: (error: Error) => {
      toast.error("API key creation failed", {
        description: error.message,
      });
    },
  });
}

// ===== Raw API Functions =====

async function fetchThreats(filters: ThreatListFilters): Promise<ThreatListResponse> {
  const params = new URLSearchParams();

  if (filters.tier) params.append("tier", filters.tier);
  if (filters.status) params.append("status", filters.status);
  if (filters.mitre_tactic) params.append("mitre_tactic", filters.mitre_tactic);
  if (filters.source) params.append("source", filters.source);
  if (filters.time_range) params.append("time_range", filters.time_range);

  return api.request<ThreatListResponse>(`/threats?${params.toString()}`);
}

async function fetchThreatDetail(threatId: string): Promise<ThreatDetailResponse> {
  return api.request<ThreatDetailResponse>(`/threats/${threatId}`);
}

async function fetchBlufReport(threatId: string, format: "json" | "text"): Promise<BlufReport> {
  const fmt = format === "text" ? "?format=text" : "";
  return api.request<BlufReport>(`/threats/${threatId}/bluf${fmt}`);
}

async function fetchAttackGraph(threatId: string): Promise<any> {
  return api.request<any>(`/threats/${threatId}/graph`);
}

async function fetchFeedbackHistory(threatId: string): Promise<AnalystFeedback[]> {
  return api.request<AnalystFeedback[]>(`/threats/${threatId}/feedback`);
}

async function fetchAlerts(filters: AlertListFilters): Promise<any[]> {
  const params = new URLSearchParams();

  if (filters.source_type) params.append("source_type", filters.source_type);
  if (filters.severity) params.append("severity", filters.severity);
  if (filters.time_range) params.append("time_range", filters.time_range);

  return api.request<any[]>(`/alerts?${params.toString()}`);
}

async function fetchAlertDetail(alertId: string): Promise<any> {
  return api.request<any>(`/alerts/${alertId}`);
}

async function fetchReports(): Promise<BlufReportListResponse> {
  return api.request<BlufReportListResponse>(`/reports`);
}

async function fetchReportDetail(reportId: string): Promise<any> {
  return api.request<any>(`/reports/${reportId}`);
}

async function fetchHealth(): Promise<HealthResponse> {
  return api.request<HealthResponse>(`/health`);
}

async function fetchMetrics(): Promise<MetricsResponse> {
  return api.request<MetricsResponse>(`/metrics`);
}

async function runPipeline(
  alert_limit?: number
): Promise<PipelineRunResponse> {
  return api.request<PipelineRunResponse>(
    `/pipeline/run`,
    {
      method: "POST",
      body: JSON.stringify({ alert_limit }),
    }
  );
}

async function submitFeedback(
  threatId: string,
  verdict: Verdict,
  confidence: number,
  notes?: string
): Promise<FeedbackSubmitResponse> {
  return api.request<FeedbackSubmitResponse>(
    `/threats/${threatId}/feedback`,
    {
      method: "POST",
      body: JSON.stringify({ verdict, confidence, notes }),
    }
  );
}

async function createApiKey(
  name: string,
  role: Role
): Promise<{ api_key: string }> {
  return api.request<{ api_key: string }>(
    "/admin/api-keys",
    {
      method: "POST",
      body: JSON.stringify({ name, role }),
    }
  );
}

// ===== Toast Notification System =====

let toastTimeouts: NodeJS.Timeout[] = [];

export function toast({
  title = "THREATICAP",
  description = "",
  variant = "default",
  duration = 5000,
}: {
  title?: string;
  description?: string;
  variant?: "default" | "destructive";
  duration?: number;
}) {
  // Remove any existing toasts
  toastTimeouts.forEach(clearTimeout);
  toastTimeouts = [];

  const toastId = `toast-${Date.now()}-${Math.random().toString(36).slice(2)}`;

  const container = document.getElementById("toast-container")!;
  
  const toastEl = document.createElement("div");
  toastEl.setAttribute("role", "alert");
  toastEl.setAttribute("aria-live", "polite");
  toastEl.setAttribute("aria-atomic", "true");
  toastEl.className = `toast toast-${variant} fade-in`;
  toastEl.setAttribute("data-toast-id", toastId);

  toastEl.innerHTML = `
    <div class="toast-title">${title}</div>
    <div class="toast-description">${description}</div>
    <button 
      class="toast-close" 
      aria-label="Close toast" 
      onClick="this.parentElement.remove()"
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="18" y1="6" x2="6" y2="18"/>
        <line x1="6" y1="18" x2="18" y2="6"/>
      </svg>
    </button>
  `;

  container.appendChild(toastEl);

  const timeout = setTimeout(() => {
    toastEl.style.opacity = "0";
    toastEl.style.transform = "translateX(100%)";
    toastEl.style.transition = "all 0.3s ease-out";
    setTimeout(() => toastEl.remove(), 300);
  }, duration);

  toastTimeouts.push(timeout);

  return toastId;
}

// Export to global for inline close
(window as any).toast = toast;