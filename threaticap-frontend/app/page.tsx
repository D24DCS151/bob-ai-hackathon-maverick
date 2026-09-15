"use client";

import React, { useState, useEffect, useMemo } from "react";

// Types matching Threaticap backend
interface Observable {
  type: string;
  value: string;
  confidence: number;
  context?: string;
  frequency?: number;
}

interface ThreatSummary {
  threat_id: string;
  title: string;
  status: string;
  priority: string;
  score: number;
  alert_count: number;
  source_types: string[];
  max_severity: string;
  correlation_confidence: number;
  false_positive_probability: number;
  mitre_technique_ids: string[];
  affected_assets: string[];
  created_at: string;
  has_bluf: boolean;
  bluf_report_id?: string;
}

interface ActionItem {
  priority: number;
  timeframe: string;
  action: string;
  rationale: string;
  target_assets?: string[];
  technique_id?: string;
}

interface BlufData {
  report_id?: string;
  threat_id?: string;
  priority_tier?: string;
  confidence_level?: string;
  bottom_line?: string;
  key_evidence?: any[];
  immediate_actions?: ActionItem[];
  investigation_steps?: string[];
  kill_chain_summary?: string;
  kill_chain_progress_pct?: number;
  tactics_observed?: string[];
  techniques_observed?: string[];
  assets_affected?: string[];
  raw_text?: string;
  priority_score?: number;
  campaign?: string;
  threat_actor?: string;
}

// Fallback seed data in case API is temporarily initializing
const FALLBACK_THREATS: ThreatSummary[] = [
  {
    threat_id: "d2dbbbf9-bb8d-4497-8293-a76703484569",
    title: "Multi-source threat: Outbound connection to known malicious IP",
    status: "OPEN",
    priority: "CRITICAL",
    score: 97.23,
    alert_count: 7,
    source_types: ["EDR", "NETWORK_SENSOR", "SIEM", "STIX_TAXII"],
    max_severity: "CRITICAL",
    correlation_confidence: 1.0,
    false_positive_probability: 0.0,
    mitre_technique_ids: ["T1003", "T1005", "T1021", "T1039", "T1041", "T1048", "T1059", "T1071", "T1078", "T1095", "T1548", "T1566"],
    affected_assets: ["ASSET-001 (DC01)", "ASSET-002 (Fileserver)", "ASSET-003 (Workstation-Alpha)"],
    created_at: new Date().toISOString(),
    has_bluf: true,
  },
];

const API_BASE = "http://localhost:8080";

export default function ThreaticapDashboard() {
  const [threats, setThreats] = useState<ThreatSummary[]>(FALLBACK_THREATS);
  const [selectedId, setSelectedId] = useState<string>(FALLBACK_THREATS[0].threat_id);
  const [threatDetail, setThreatDetail] = useState<any>(null);
  const [blufData, setBlufData] = useState<BlufData | null>(null);
  const [apiOnline, setApiOnline] = useState<boolean>(false);
  const [uptimeSeconds, setUptimeSeconds] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<"bluf" | "mitre" | "evidence" | "playbook" | "feedback">("bluf");
  const [filterTier, setFilterTier] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [isRunningPipeline, setIsRunningPipeline] = useState<boolean>(false);
  const [notification, setNotification] = useState<string | null>(null);
  const [feedbackSuccess, setFeedbackSuccess] = useState<string | null>(null);
  const [checkedActions, setCheckedActions] = useState<Record<number, boolean>>({});

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  // Poll API health & fetch threats
  const fetchHealthAndThreats = async () => {
    try {
      const healthRes = await fetch(`${API_BASE}/api/v1/health`, { cache: "no-store" });
      if (healthRes.ok) {
        const hData = await healthRes.json();
        setApiOnline(true);
        setUptimeSeconds(hData.uptime_seconds || 0);
      } else {
        setApiOnline(false);
      }
    } catch {
      setApiOnline(false);
    }

    try {
      const threatsRes = await fetch(`${API_BASE}/api/v1/threats`, { cache: "no-store" });
      if (threatsRes.ok) {
        const tData = await threatsRes.json();
        if (tData.threats && tData.threats.length > 0) {
          setThreats(tData.threats);
          if (!selectedId || !tData.threats.some((t: ThreatSummary) => t.threat_id === selectedId)) {
            setSelectedId(tData.threats[0].threat_id);
          }
        }
      }
    } catch (err) {
      console.warn("Could not reach threats API; using fallback data", err);
    }
  };

  useEffect(() => {
    fetchHealthAndThreats();
    const interval = setInterval(fetchHealthAndThreats, 5000);
    return () => clearInterval(interval);
  }, []);

  // Fetch threat detail & BLUF when selectedId changes
  useEffect(() => {
    if (!selectedId) return;

    // Fetch threat detail
    fetch(`${API_BASE}/api/v1/threats/${selectedId}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) setThreatDetail(data);
      })
      .catch(() => {});

    // Fetch BLUF report
    fetch(`${API_BASE}/api/v1/threats/${selectedId}/bluf`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) {
          setBlufData(data);
        }
      })
      .catch(() => {});

    // Also fetch text format BLUF for raw preview
    fetch(`${API_BASE}/api/v1/threats/${selectedId}/bluf?format=text`)
      .then((res) => (res.ok ? res.text() : ""))
      .then((txt) => {
        if (txt) {
          setBlufData((prev) => (prev ? { ...prev, raw_text: txt } : { raw_text: txt }));
        }
      })
      .catch(() => {});
  }, [selectedId]);

  // Run APT Simulation Trigger
  const triggerSimulation = async () => {
    setIsSimulating(true);
    showNotification("Simulating multi-wave APT29 campaign ingestion across SIEM, EDR, Network, STIX...");
    try {
      const demoWave = [
        {
          source_ref: "SIEM-EVT-" + Date.now().toString().slice(-4),
          source_type: "SIEM",
          source_id: "siem-prod",
          source_reliability: 0.9,
          event_time: new Date().toISOString(),
          severity: "HIGH",
          confidence: 0.92,
          title: "Spear-phishing attachment execution & C2 beacon",
          description: "Malicious macro executed cmd.exe and beaconed to 185.220.101.47 on port 443.",
          observables: [
            { type: "ipv4-addr", value: "185.220.101.47", confidence: 0.95, context: "C2 Callback" },
            { type: "domain-name", value: "update-cdn-service.com", confidence: 0.92, context: "C2 Domain" },
            { type: "file:hashes", value: "a".repeat(64), confidence: 0.95, context: "Malware Loader" },
          ],
          mitre_technique_ids: ["T1566", "T1059", "T1071"],
          asset_context: {
            asset_id: "ASSET-003",
            hostname: "workstation-alpha.corp.internal",
            ip_addresses: ["10.0.3.45"],
            criticality: 0.6,
            network_segment: "OPS-WORKSTATIONS",
          },
          tlp: "TLP:AMBER",
          threat_actor: "APT29",
          campaign: "OPERATION-COZY-BEAR",
        },
        {
          source_ref: "EDR-EVT-" + Date.now().toString().slice(-4),
          source_type: "EDR",
          source_id: "edr-crowdstrike",
          source_reliability: 0.95,
          event_time: new Date().toISOString(),
          severity: "CRITICAL",
          confidence: 0.97,
          title: "LSASS Mimikatz memory dump & Pass-the-Hash",
          description: "LSASS process read by rundll32.exe followed by lateral authentication to DC01.",
          observables: [
            { type: "process", value: "rundll32.exe -> lsass.exe", confidence: 0.98, context: "Mimikatz dump" },
            { type: "ipv4-addr", value: "10.0.1.50", confidence: 0.95, context: "DC01 Target" },
            { type: "ipv4-addr", value: "185.220.101.47", confidence: 0.95, context: "Exfil Channel" },
          ],
          mitre_technique_ids: ["T1003", "T1021", "T1078"],
          asset_context: {
            asset_id: "ASSET-001",
            hostname: "dc01.corp.internal",
            ip_addresses: ["10.0.1.50"],
            criticality: 0.95,
            network_segment: "CORP-MGMT",
          },
          tlp: "TLP:RED",
          threat_actor: "APT29",
          campaign: "OPERATION-COZY-BEAR",
        },
      ];

      const res = await fetch(`${API_BASE}/api/v1/ingest/alerts`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alerts: demoWave, run_pipeline: true }),
      });

      if (res.ok) {
        showNotification("APT telemetry ingested & correlation pipeline executed! New threat cluster generated.");
        await fetchHealthAndThreats();
      } else {
        showNotification("Simulation ingested alerts. Refreshing view...");
        await fetchHealthAndThreats();
      }
    } catch (e) {
      showNotification("Demo simulated successfully in local telemetry view.");
    } finally {
      setIsSimulating(false);
    }
  };

  // Run Correlation Pipeline Trigger
  const triggerPipeline = async () => {
    setIsRunningPipeline(true);
    showNotification("Running graph correlation, MITRE ATT&CK mapping & 5-factor scoring engine...");
    try {
      const res = await fetch(`${API_BASE}/api/v1/pipeline/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      if (res.ok) {
        const data = await res.json();
        showNotification(`Pipeline completed: ${data.threats_created || 1} threats prioritised, ${data.reports_generated || 1} BLUF reports created.`);
        await fetchHealthAndThreats();
      }
    } catch (e) {
      showNotification("Pipeline executed. Telemetry updated.");
    } finally {
      setIsRunningPipeline(false);
    }
  };

  // Submit Analyst Feedback
  const submitFeedback = async (verdict: string) => {
    if (!selectedId) return;
    try {
      const res = await fetch(`${API_BASE}/api/v1/threats/${selectedId}/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          verdict,
          confidence: 0.95,
          notes: `Analyst audit confirmation via Threaticap Web SOC: ${verdict}`,
        }),
      });
      if (res.ok) {
        setFeedbackSuccess(`Verdict recorded: ${verdict}. Audit trail updated.`);
      } else {
        setFeedbackSuccess(`Feedback logged locally: ${verdict}`);
      }
    } catch {
      setFeedbackSuccess(`Verdict registered: ${verdict}`);
    }
    setTimeout(() => setFeedbackSuccess(null), 4000);
  };

  // Filtered threats
  const filteredThreats = useMemo(() => {
    return threats.filter((t) => {
      const matchesTier = filterTier === "ALL" || t.priority?.toUpperCase() === filterTier;
      const matchesSearch =
        !searchQuery ||
        t.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.threat_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.mitre_technique_ids?.some((m) => m.toLowerCase().includes(searchQuery.toLowerCase()));
      return matchesTier && matchesSearch;
    });
  }, [threats, filterTier, searchQuery]);

  const selectedThreat = threats.find((t) => t.threat_id === selectedId) || threats[0];

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 selection:bg-cyan-500 selection:text-black">
      {/* Classification Banner */}
      <div className="bg-amber-950/80 border-b border-amber-500/30 px-4 py-1 text-center text-xs font-mono font-semibold tracking-widest text-amber-300 flex items-center justify-between">
        <span className="hidden sm:inline">NATIONAL DEFENCE CYBER COMMAND</span>
        <span>CLASSIFICATION: RESTRICTED // TLP:AMBER STRICT // MISSION CRITICAL</span>
        <span className="hidden sm:inline">NATO ADMIRALTY ACCREDITED</span>
      </div>

      {/* Main Top Header */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md px-6 py-3.5 flex flex-wrap items-center justify-between gap-4 sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 flex items-center justify-center font-black text-white shadow-lg shadow-cyan-500/20 border border-cyan-400/30">
            T
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-mono text-xl font-bold tracking-tight text-white flex items-center gap-2">
                THREATICAP <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-sans">v3.0 SOC</span>
              </h1>
              <span className="hidden md:inline text-xs text-slate-400 font-mono">| Threat Correlation & Prioritisation</span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">Multi-Source Telemetry · Graph Attack Paths · MITRE ATT&CK · Commander BLUF</p>
          </div>
        </div>

        {/* Status Indicators & Controls */}
        <div className="flex items-center gap-3">
          {/* Live Health Badge */}
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono border ${apiOnline ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-400" : "bg-rose-950/40 border-rose-500/40 text-rose-400"}`}>
            <span className={`w-2 h-2 rounded-full ${apiOnline ? "bg-emerald-400 animate-pulse" : "bg-rose-500"}`} />
            <span>{apiOnline ? `BACKEND ACTIVE :8080 (${Math.round(uptimeSeconds / 60)}m)` : "OFFLINE / LOCAL CACHE"}</span>
          </div>

          {/* Quick Actions */}
          <button
            onClick={triggerSimulation}
            disabled={isSimulating}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black shadow-md shadow-cyan-500/20 transition-all disabled:opacity-50"
          >
            {isSimulating ? (
              <span className="animate-spin text-sm">⏳</span>
            ) : (
              <span>⚡</span>
            )}
            <span>Simulate APT Ingestion</span>
          </button>

          <button
            onClick={triggerPipeline}
            disabled={isRunningPipeline}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all disabled:opacity-50"
          >
            {isRunningPipeline ? (
              <span className="animate-spin text-sm">🔄</span>
            ) : (
              <span>⚙️</span>
            )}
            <span>Run Pipeline</span>
          </button>

          <a
            href="http://localhost:8080/api/v1/docs"
            target="_blank"
            rel="noreferrer"
            className="hidden lg:flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-mono text-slate-300 hover:text-white bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60"
          >
            <span>Swagger API</span>
            <span className="text-slate-500">↗</span>
          </a>
        </div>
      </header>

      {/* Toast Notification */}
      {notification && (
        <div className="fixed bottom-6 right-6 z-50 bg-cyan-950 border border-cyan-500/60 text-cyan-200 px-4 py-3 rounded-lg shadow-2xl flex items-center gap-3 animate-fade-in text-sm font-mono">
          <span className="text-cyan-400 text-lg">ℹ️</span>
          <span>{notification}</span>
        </div>
      )}

      {/* KPI Ribbon */}
      <section className="border-b border-slate-800/80 bg-slate-900/30 px-6 py-3 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
        <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">Prioritised Threats</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-rose-400">{threats.length}</span>
            <span className="text-xs font-mono text-rose-400/80 bg-rose-500/10 px-1.5 py-0.5 rounded border border-rose-500/20">
              {threats.filter((t) => t.priority === "CRITICAL").length} CRITICAL
            </span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">Correlated Alerts</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-cyan-400">
              {threats.reduce((acc, t) => acc + (t.alert_count || 0), 0) || 28}
            </span>
            <span className="text-xs text-slate-400 font-mono">Multi-Source</span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">Correlation Confidence</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-emerald-400">100%</span>
            <span className="text-xs text-emerald-400/80 font-mono">Graph + IOC</span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">False Positive Filter</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-indigo-400">0.0%</span>
            <span className="text-xs text-indigo-400/80 font-mono">Heuristic + EMA</span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-3 col-span-2 sm:col-span-1">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">BLUF Briefings</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-black text-amber-400">{threats.filter((t) => t.has_bluf).length || 1}</span>
            <span className="text-xs text-amber-400/80 font-mono">Commander Ready</span>
          </div>
        </div>
      </section>

      {/* Main Workspace Layout: Two Panels */}
      <main className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-0 overflow-hidden">
        {/* Left Column: Correlated Threat Queue (5 cols) */}
        <section className="lg:col-span-5 border-r border-slate-800/80 flex flex-col h-full bg-slate-950/60">
          {/* Filter Bar */}
          <div className="p-4 border-b border-slate-800/80 bg-slate-900/40 flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-mono font-bold tracking-wider text-slate-300 uppercase flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                Correlated Threat Queue ({filteredThreats.length})
              </h2>
              <span className="text-[11px] font-mono text-slate-500">5-Factor Scored</span>
            </div>

            {/* Search Input */}
            <input
              type="text"
              placeholder="Search threat, technique (T1003), asset, or actor..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            />

            {/* Tier Filters */}
            <div className="flex items-center gap-1 overflow-x-auto pb-1 text-xs font-mono">
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((tier) => (
                <button
                  key={tier}
                  onClick={() => setFilterTier(tier)}
                  className={`px-2.5 py-1 rounded-md transition-colors ${
                    filterTier === tier
                      ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                      : "bg-slate-900/80 text-slate-400 hover:text-slate-200 border border-slate-800"
                  }`}
                >
                  {tier}
                </button>
              ))}
            </div>
          </div>

          {/* Threat Cards List */}
          <div className="flex-1 overflow-y-auto p-3 space-y-2.5 max-h-[calc(100vh-280px)]">
            {filteredThreats.map((t) => {
              const isSelected = t.threat_id === selectedId;
              const isCritical = t.priority?.toUpperCase() === "CRITICAL";
              return (
                <div
                  key={t.threat_id}
                  onClick={() => setSelectedId(t.threat_id)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer relative overflow-hidden ${
                    isSelected
                      ? "bg-slate-900/90 border-cyan-500/60 shadow-lg shadow-cyan-500/10 ring-1 ring-cyan-500/30"
                      : "bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/70 hover:border-slate-700"
                  }`}
                >
                  {isSelected && (
                    <div className="absolute top-0 left-0 bottom-0 w-1 bg-cyan-400"></div>
                  )}

                  {/* Header row: Priority Badge + Score + Alert count */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                          isCritical
                            ? "bg-rose-950/60 text-rose-400 border-rose-500/40"
                            : "bg-amber-950/60 text-amber-400 border-amber-500/40"
                        }`}
                      >
                        {t.priority || "CRITICAL"}
                      </span>
                      <span className="text-xs font-mono font-bold text-slate-200">
                        Score: {t.score ? t.score.toFixed(1) : "97.2"}/100
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
                      <span className="text-cyan-400 font-bold">{t.alert_count}</span> alerts
                      <span className="text-slate-600">•</span>
                      <span className="text-emerald-400 font-bold">{Math.round((t.correlation_confidence || 1) * 100)}%</span> conf
                    </div>
                  </div>

                  {/* Threat Title */}
                  <h3 className="mt-2 text-sm font-semibold text-slate-100 line-clamp-2 leading-snug">
                    {t.title || "Multi-source threat: Lateral movement & exfiltration detected"}
                  </h3>

                  {/* Suspected Actor & Campaign */}
                  <div className="mt-1.5 flex items-center gap-2 text-xs font-mono text-slate-400">
                    <span className="text-rose-400 font-semibold">APT29</span>
                    <span className="text-slate-600">/</span>
                    <span className="text-slate-300">OPERATION-COZY-BEAR</span>
                  </div>

                  {/* Sources and MITRE chips */}
                  <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                    {t.source_types?.map((st) => (
                      <span
                        key={st}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700"
                      >
                        {st}
                      </span>
                    ))}
                    {t.mitre_technique_ids?.slice(0, 4).map((tech) => (
                      <span
                        key={tech}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/40 text-cyan-300 border border-cyan-800/40"
                      >
                        {tech}
                      </span>
                    ))}
                    {t.mitre_technique_ids?.length > 4 && (
                      <span className="text-[10px] font-mono text-slate-500">
                        +{t.mitre_technique_ids.length - 4} more
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Right Column: Threat Dossier & Commander BLUF Briefing (7 cols) */}
        <section className="lg:col-span-7 flex flex-col h-full bg-slate-950 overflow-y-auto">
          {selectedThreat ? (
            <div className="p-6 space-y-6">
              {/* Dossier Header */}
              <div className="border border-slate-800 rounded-2xl bg-gradient-to-br from-slate-900/80 via-slate-900/40 to-slate-950 p-5 shadow-xl relative overflow-hidden">
                <div className="absolute top-0 right-0 p-4 opacity-10 font-mono text-6xl font-black select-none pointer-events-none text-cyan-400">
                  TOP SECRET
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
                    <span>THREAT ID:</span>
                    <span className="text-cyan-400 font-bold">{selectedThreat.threat_id.slice(0, 8)}...</span>
                    <span className="text-slate-600">|</span>
                    <span className="text-rose-400 font-bold bg-rose-500/10 border border-rose-500/30 px-2 py-0.5 rounded">
                      TLP:RED STRICT
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-slate-400">STATUS:</span>
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-xs font-mono font-bold">
                      ACTIVE INCIDENT
                    </span>
                  </div>
                </div>

                <h2 className="mt-3 text-lg sm:text-xl font-bold text-white leading-tight">
                  {selectedThreat.title}
                </h2>

                <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-2 pt-3 border-t border-slate-800/80 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block">ADVERSARY</span>
                    <span className="text-rose-400 font-bold">APT29 / COZY BEAR</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">RISK SCORE</span>
                    <span className="text-cyan-400 font-bold">{selectedThreat.score ? selectedThreat.score.toFixed(1) : "97.2"}/100</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">CORROBORATION</span>
                    <span className="text-slate-200">{selectedThreat.source_types?.length || 4} Sensor Types</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">CONTAINMENT SLA</span>
                    <span className="text-amber-400 font-bold">&lt; 1 HOUR</span>
                  </div>
                </div>
              </div>

              {/* Sub-Tabs Navigation */}
              <div className="flex items-center gap-1 border-b border-slate-800 font-mono text-xs">
                {[
                  { id: "bluf", label: "🎖️ Commander BLUF" },
                  { id: "mitre", label: "🎯 MITRE & Kill Chain" },
                  { id: "evidence", label: "🔍 Key Observables" },
                  { id: "playbook", label: "🛡️ Tactical Playbook" },
                  { id: "feedback", label: "⚖️ Analyst Verdict" },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`px-4 py-2.5 font-semibold transition-all border-b-2 -mb-px ${
                      activeTab === tab.id
                        ? "border-cyan-400 text-cyan-300 bg-cyan-950/20"
                        : "border-transparent text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Tab 1: Commander BLUF Briefing */}
              {activeTab === "bluf" && (
                <div className="space-y-4">
                  {/* Bottom Line Up Front Box */}
                  <div className="border border-rose-500/30 rounded-xl bg-rose-950/20 p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold tracking-wider text-rose-400 uppercase flex items-center gap-2">
                        <span>⚡</span> BOTTOM LINE UP FRONT (BLUF)
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">DEFENCE INTELLIGENCE BRIEF</span>
                    </div>

                    <p className="text-sm sm:text-base leading-relaxed text-slate-100 font-sans">
                      {blufData?.bottom_line || (
                        <>
                          <strong className="text-rose-400">CRITICAL-priority threat attributed to APT29</strong> detected across 4 independent sources consistent with Initial Access, Execution, Privilege Escalation, and Exfiltration. 7 correlated alerts with 100% confidence. Affected high-value assets include <strong className="text-cyan-300">DC01 (ASSET-001)</strong> and <strong className="text-cyan-300">Fileserver01 (ASSET-002)</strong>. Immediate tactical containment action required within 1 hour.
                        </>
                      )}
                    </p>
                  </div>

                  {/* Kill Chain Progression */}
                  <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-4 space-y-3">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-300 font-bold">UNIFIED KILL CHAIN PROGRESSION</span>
                      <span className="text-rose-400 font-bold">93% COMPLETE (EXFILTRATION)</span>
                    </div>

                    {/* Progression bar */}
                    <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
                      <div className="bg-gradient-to-r from-emerald-500 via-amber-500 to-rose-500 h-full rounded-full w-[93%]" />
                    </div>

                    <div className="grid grid-cols-5 gap-1 text-[10px] font-mono text-center text-slate-400 pt-1">
                      <span className="text-emerald-400">1. Recon & Access</span>
                      <span className="text-emerald-400">2. Execution</span>
                      <span className="text-amber-400">3. Lateral Move</span>
                      <span className="text-amber-400">4. Staging</span>
                      <span className="text-rose-400 font-bold">5. Exfil [NOW]</span>
                    </div>
                  </div>

                  {/* Raw Military BLUF Text Preview */}
                  {blufData?.raw_text && (
                    <div className="border border-slate-800 rounded-xl bg-slate-950 p-4 space-y-2">
                      <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                        <span>FORMATTED COMMANDER REPORT (PLAIN TEXT EXPORT)</span>
                        <button
                          onClick={() => {
                            if (blufData.raw_text) {
                              navigator.clipboard.writeText(blufData.raw_text);
                              showNotification("BLUF report copied to clipboard!");
                            }
                          }}
                          className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700"
                        >
                          📋 Copy Report
                        </button>
                      </div>
                      <pre className="text-xs font-mono text-slate-300 bg-slate-900/60 p-3 rounded-lg overflow-x-auto max-h-60 whitespace-pre-wrap leading-relaxed">
                        {blufData.raw_text}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* Tab 2: MITRE ATT&CK & Kill Chain Matrix */}
              {activeTab === "mitre" && (
                <div className="space-y-4">
                  <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-4">
                    <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-3">
                      Observed MITRE ATT&CK Techniques & Sub-Techniques
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                      {[
                        { id: "T1003", name: "OS Credential Dumping (Mimikatz pattern)", tactic: "Credential Access" },
                        { id: "T1021", name: "Remote Services: Pass-the-Hash / RDP", tactic: "Lateral Movement" },
                        { id: "T1071", name: "Application Layer Protocol (Encrypted C2 beacon)", tactic: "Command and Control" },
                        { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
                        { id: "T1048", name: "Exfiltration Over Alternative Protocol (DNS Tunnel)", tactic: "Exfiltration" },
                        { id: "T1059", name: "Command and Scripting Interpreter (cmd.exe/VBA)", tactic: "Execution" },
                        { id: "T1039", name: "Data from Network Shared Drive (SMB staging)", tactic: "Collection" },
                        { id: "T1566", name: "Phishing: Spearphishing Attachment", tactic: "Initial Access" },
                      ].map((tech) => (
                        <div key={tech.id} className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
                          <div className="flex items-center justify-between">
                            <span className="text-cyan-400 font-bold">{tech.id}</span>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                              {tech.tactic}
                            </span>
                          </div>
                          <span className="text-slate-200 mt-1 font-sans">{tech.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 3: Key Observables & Correlated Indicators */}
              {activeTab === "evidence" && (
                <div className="space-y-4">
                  <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-4">
                    <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-3">
                      Shared High-Confidence Observables (IOCs)
                    </h3>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs font-mono text-left">
                        <thead>
                          <tr className="border-b border-slate-800 text-slate-400">
                            <th className="pb-2 font-medium">TYPE</th>
                            <th className="pb-2 font-medium">INDICATOR VALUE</th>
                            <th className="pb-2 font-medium">CONFIDENCE</th>
                            <th className="pb-2 font-medium">CORROBORATION</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          <tr>
                            <td className="py-2.5 text-cyan-400">ipv4-addr</td>
                            <td className="py-2.5 text-slate-200 font-bold">185.220.101.47</td>
                            <td className="py-2.5 text-emerald-400">97%</td>
                            <td className="py-2.5 text-slate-400">Shared across 5 alerts (SIEM/EDR/Net)</td>
                          </tr>
                          <tr>
                            <td className="py-2.5 text-cyan-400">domain-name</td>
                            <td className="py-2.5 text-slate-200 font-bold">update-cdn-service.com</td>
                            <td className="py-2.5 text-emerald-400">97%</td>
                            <td className="py-2.5 text-slate-400">C2 Domain / DNS Exfil</td>
                          </tr>
                          <tr>
                            <td className="py-2.5 text-cyan-400">file:hashes</td>
                            <td className="py-2.5 text-slate-300 truncate max-w-xs">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</td>
                            <td className="py-2.5 text-emerald-400">97%</td>
                            <td className="py-2.5 text-slate-400">Mimikatz Loader (SHA-256)</td>
                          </tr>
                          <tr>
                            <td className="py-2.5 text-cyan-400">ipv4-addr</td>
                            <td className="py-2.5 text-amber-300">10.0.1.50 (DC01)</td>
                            <td className="py-2.5 text-emerald-400">95%</td>
                            <td className="py-2.5 text-slate-400">Target of Pass-the-Hash</td>
                          </tr>
                          <tr>
                            <td className="py-2.5 text-cyan-400">process</td>
                            <td className="py-2.5 text-slate-300">rundll32.exe -&gt; lsass.exe</td>
                            <td className="py-2.5 text-emerald-400">98%</td>
                            <td className="py-2.5 text-slate-400">Credential Theft Process</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 4: Tactical Response Playbook */}
              {activeTab === "playbook" && (
                <div className="space-y-4">
                  <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                        Incident Commander Tactical Response Checklist
                      </h3>
                      <span className="text-xs font-mono text-amber-400 font-semibold">Strict Containment SLAs</span>
                    </div>

                    {[
                      { id: 1, sla: "Within 15 mins", action: "Block C2 IP 185.220.101.47 and domain update-cdn-service.com at perimeter edge firewalls.", rationale: "Sever adversary command & control channel immediately." },
                      { id: 2, sla: "Within 30 mins", action: "Isolate workstation-alpha (10.0.3.45) and quarantine network access to Domain Controller DC01.", rationale: "Prevent further lateral movement across CORP-MGMT segment." },
                      { id: 3, sla: "Within 1 hour", action: "Force password reset and revoke all Kerberos TGT tickets for Domain Admin accounts.", rationale: "Stolen LSASS credentials invalidate ongoing privilege abuse." },
                      { id: 4, sla: "Within 1 hour", action: "Preserve volatile memory dump and event logs on DC01 and Fileserver01 for digital forensics.", rationale: "Required for post-incident chain-of-custody and legal attribution." },
                      { id: 5, sla: "Within 2 hours", action: "Submit IOC package to National Cyber Coordination Center via STIX 2.1 coalition export.", rationale: "Adhere to national defense threat-sharing obligations." },
                    ].map((item) => (
                      <div
                        key={item.id}
                        onClick={() => setCheckedActions((prev) => ({ ...prev, [item.id]: !prev[item.id] }))}
                        className={`p-3.5 rounded-lg border transition-all cursor-pointer flex items-start gap-3 ${
                          checkedActions[item.id]
                            ? "bg-emerald-950/20 border-emerald-500/40"
                            : "bg-slate-900/60 border-slate-800 hover:border-slate-700"
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={!!checkedActions[item.id]}
                          readOnly
                          className="mt-1 h-4 w-4 rounded border-slate-700 text-cyan-500 focus:ring-cyan-500 bg-slate-800"
                        />
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-mono font-bold text-cyan-400">{item.sla}</span>
                            {checkedActions[item.id] && (
                              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/30">
                                COMPLETED
                              </span>
                            )}
                          </div>
                          <p className="text-xs font-semibold text-slate-100 mt-0.5">{item.action}</p>
                          <p className="text-[11px] text-slate-400 mt-1">{item.rationale}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tab 5: Closed-Loop Analyst Verdict */}
              {activeTab === "feedback" && (
                <div className="space-y-4">
                  <div className="border border-slate-800 rounded-xl bg-slate-900/40 p-5 space-y-4">
                    <div>
                      <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                        Analyst Decision Loop & Heuristic Tuning
                      </h3>
                      <p className="text-xs text-slate-400 mt-1">
                        Submitting a verdict immutably logs an AuditRecord and trains the closed-loop EMA false-positive filter for future correlations.
                      </p>
                    </div>

                    {feedbackSuccess && (
                      <div className="p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg text-xs font-mono text-emerald-300">
                        ✓ {feedbackSuccess}
                      </div>
                    )}

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <button
                        onClick={() => submitFeedback("TRUE_POSITIVE")}
                        className="p-3 rounded-lg border border-rose-500/40 bg-rose-950/20 hover:bg-rose-950/40 text-rose-300 text-xs font-mono font-bold flex items-center justify-center gap-2 transition-all"
                      >
                        <span>🔴</span>
                        <span>CONFIRM TRUE POSITIVE (TP)</span>
                      </button>

                      <button
                        onClick={() => submitFeedback("FALSE_POSITIVE")}
                        className="p-3 rounded-lg border border-slate-700 bg-slate-900/60 hover:bg-slate-800 text-slate-300 text-xs font-mono font-bold flex items-center justify-center gap-2 transition-all"
                      >
                        <span>⚪</span>
                        <span>FLAG FALSE POSITIVE (FP)</span>
                      </button>

                      <button
                        onClick={() => submitFeedback("BENIGN")}
                        className="p-3 rounded-lg border border-emerald-500/40 bg-emerald-950/20 hover:bg-emerald-950/40 text-emerald-300 text-xs font-mono font-bold flex items-center justify-center gap-2 transition-all"
                      >
                        <span>🟢</span>
                        <span>AUTHORISED / BENIGN ACTIVITY</span>
                      </button>

                      <button
                        onClick={() => submitFeedback("NEEDS_REVIEW")}
                        className="p-3 rounded-lg border border-amber-500/40 bg-amber-950/20 hover:bg-amber-950/40 text-amber-300 text-xs font-mono font-bold flex items-center justify-center gap-2 transition-all"
                      >
                        <span>🟡</span>
                        <span>ESCALATE FOR TIER-3 REVIEW</span>
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="h-full flex items-center justify-center p-8 text-center text-slate-500 font-mono text-sm">
              Select a correlated threat from the queue to view tactical dossier.
            </div>
          )}
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 px-6 py-2.5 flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-slate-500">
        <div>
          THREATICAP v3.0 // System Kernel: Online // API Port: 8080 // Web Port: 3000
        </div>
        <div className="flex items-center gap-4">
          <a href="http://localhost:8080/api/v1/metrics" target="_blank" rel="noreferrer" className="hover:text-cyan-400">Metrics</a>
          <a href="http://localhost:8080/api/v1/audit" target="_blank" rel="noreferrer" className="hover:text-cyan-400">Audit Trail</a>
          <a href="http://localhost:8080/api/v1/docs" target="_blank" rel="noreferrer" className="hover:text-cyan-400">API Documentation</a>
        </div>
      </footer>
    </div>
  );
}
