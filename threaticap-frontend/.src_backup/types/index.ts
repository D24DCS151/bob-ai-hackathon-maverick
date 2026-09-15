/**
 * THREATICAP API Types
 * 
 * Strong TypeScript types matching the backend Pydantic v2 models.
 * These types ensure type safety across the frontend and enable
 * autocomplete and compile-time checking for all API responses.
 */

// ===== Authentication Types =====

export type Role = "READER" | "ANALYST" | "OPERATOR" | "ADMIN";

export type Verdict = "TRUE_POSITIVE" | "FALSE_POSITIVE" | "BENIGN" | "NEEDS_REVIEW";

export type TLP = "TLP:RED" | "TLP:AMBER" | "TLP:GREEN" | "TLP:CLEAR";

export type ClearanceLevel = "UNCLASSIFIED" | "CONFIDENTIAL" | "SECRET" | "TOP_SECRET";

// ===== Core Data Models =====

export interface Observable {
  observable_id: string;
  type: ObservableType;
  value: string;
  confidence: number;
  context?: string;
  first_seen?: string;
  last_seen?: string;
  tags?: string[];
}

export enum ObservableType {
  IP = "IP",
  DOMAIN = "DOMAIN",
  HASH = "HASH",
  FILEPATH = "FILEPATH",
  MACHINE_NAME = "MACHINE_NAME",
  REGISTRY_KEY = "REGISTRY_KEY",
  USER_AGENT = "USER_AGENT",
  CVE = "CVE",
  URL = "URL",
  EMAIL = "EMAIL",
  PATH = "PATH",
}

export interface AssetContext {
  asset_id: string;
  hostname?: string;
  ip_addresses: string[];
  owner?: string;
  classification?: ClearanceLevel;
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  network_segment?: string;
  tags?: string[];
}

export interface Alert {
  alert_id: string;
  source_type: "SIEM" | "EDR" | "INTEL" | "SATELLITE" | "TAXII" | "CUSTOM";
  source_id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  title: string;
  description?: string;
  event_time?: string;
  observables?: Observable[];
  asset_context?: AssetContext;
  mitre_technique_ids?: string[];
  tlp: TLP;
  source_url?: string;
}

export enum PriorityTier {
  CRITICAL = "CRITICAL",
  HIGH = "HIGH",
  MEDIUM = "MEDIUM",
  LOW = "LOW",
}

export interface ScoreComponent {
  name: string;
  raw_value: number;
  weight: number;
  weighted_value: number;
  description?: string;
}

export interface PriorityScore {
  final_score: number;
  priority_tier: PriorityTier;
  components: ScoreComponent[];
  mission_impact_multiplier: number;
  degraded_missions?: string[];
  false_positive_adjustment: number;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic?: string;
  sub_techniques?: MitreTechnique[];
  severity?: "LOW" | "MEDIUM" | "HIGH";
}

export interface CorrelatedThreat {
  threat_id: string;
  title: string;
  status: "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";
  priority_score: PriorityScore;
  bottom_line: string;
  tlp: TLP;
  mitre_technique_ids: string[];
  evidence_links: EvidenceLink[];
  confidence: number;
  false_positive_probability: number;
  affected_assets: string[];
  shared_observables: string[];
  mission_impact?: string;
  created_at: string;
  updated_at: string;
}

export interface EvidenceLink {
  alert_id: string;
  source_ref?: string;
  source_type?: string;
  relevance: number;
  contributing_observables: string[];
}

export interface BlufReport {
  report_id: string;
  threat_id: string;
  bottom_line: string;
  priority_tier: PriorityTier;
  confidence_level: "LOW" | "MEDIUM" | "HIGH";
  tlp: TLP;
  key_evidence: string[];
  mitre_technique_ids: string[];
  immediate_actions: string[];
  investigation_steps: string[];
  priority_justification: string;
  score_breakdown?: Record<string, number>;
  mission_impact_multiplier: number;
  campaign_narrative?: string;
  kill_chain_completion?: number;
  adversary_objective?: string;
}

export interface AnalystFeedback {
  feedback_id: string;
  threat_id: string;
  analyst_id: string;
  verdict: Verdict;
  confidence: number;
  notes?: string;
  created_at: string;
}

export interface AuditRecord {
  audit_id: string;
  event_type: string;
  timestamp: string;
  actor: string;
  component: string;
  alert_id?: string;
  threat_id?: string;
  report_id?: string;
  summary: string;
  detail?: string;
  previous_state?: string;
  new_state?: string;
}

// ===== API Response Types =====

export interface AlertSubmitResponse {
  accepted: boolean;
  rejected: boolean;
  errors?: string[];
  alert_ids: string[];
  threats_created: number;
}

export interface PipelineRunResponse {
  alerts_processed: number;
  threats_created: number;
  tier_breakdown: Record<PriorityTier, number>;
  top_threats: CorrelatedThreat[];
  errors?: string[];
  message?: string;
}

export interface ThreatListResponse {
  total: number;
  limit: number;
  offset: number;
  threats: CorrelatedThreat[];
}

export interface ThreatDetailResponse {
  threat: CorrelatedThreat;
  score?: PriorityScore;
  audit_records: AuditRecord[];
}

export interface BlufReportListResponse {
  total: number;
  reports: BlufReport[];
}

export interface HealthResponse {
  status: "HEALTHY" | "DEGRADED" | "UNHEALTHY";
  version: string;
  uptime_seconds: number;
  alerts_stored: number;
  threats_stored: number;
}

export interface MetricsResponse {
  alerts_total: number;
  threats_total: number;
  reports_total: number;
  threat_by_tier: Record<PriorityTier, number>;
  uptime_seconds: number;
}

export interface ErrorResponse {
  error: string;
  detail?: string;
  request_id: string;
}

export interface FeedbackSubmitResponse {
  feedback_id: string;
  threat_id: string;
  verdict: Verdict;
  confirmed: boolean;
}

// ===== Filter and Query Types =====

export interface ThreatListFilters {
  tier?: PriorityTier;
  status?: "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";
  mitre_tactic?: string;
  source?: string;
  time_range?: "24h" | "7d" | "30d" | "90d";
}

export interface AlertListFilters {
  source_type?: "SIEM" | "EDR" | "INTEL" | "SATELLITE" | "TAXII" | "CUSTOM";
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  time_range?: "24h" | "7d" | "30d" | "90d";
}

// ===== Commander Mode Types =====

export interface CommanderBluf {
  threat_id: string;
  bottom_line: string;
  priority_tier: PriorityTier;
  confidence_level: BlufReport["confidence_level"];
  tlp: TLP;
  key_evidence: string[];
  immediate_actions: string[];
}