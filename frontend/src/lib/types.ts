// Типы ответов gateway API (ТЗ §7).

export type Confidence = "high" | "medium" | "low";
export type Priority = "critical" | "high" | "medium" | "low";
export type Posture = Priority | "none";

export interface ScanCreated {
  job_id: number;
  status: string;
}

export interface ProgressEvent {
  job_id: number;
  event: "started" | "source" | "persisted" | "matching" | "done" | "failed";
  source?: string | null;
  status?: string | null;
  message?: string | null;
  counts?: Record<string, number> | null;
}

export interface SourcesResponse {
  core: string[];
  optional: { name: string; enabled: boolean }[];
}

export interface Vuln {
  service_id: number;
  ip: string | null;
  port: number;
  product: string | null;
  version: string | null;
  cve_id: string;
  match_confidence: Confidence;
  severity: string | null;
  cvss_version: string | null;
  cvss_score: number | null;
  description: string | null;
  risk_score: number;
  priority: Priority;
}

export interface Report {
  job: {
    id: number;
    target: string;
    type: string;
    status: string;
    created_at: string;
    finished_at: string | null;
    degraded_sources: Record<string, string> | null;
  };
  summary: {
    domains: number;
    ips: number;
    services: number;
    vulnerabilities: number;
    by_severity: { critical: number; high: number; medium: number; low: number; unknown: number };
    by_confidence: { high: number; medium: number; low: number };
    by_priority: { critical: number; high: number; medium: number; low: number };
    max_risk_score: number;
    risk_posture: Posture;
  };
  exec_summary: string;
  top_risks: Vuln[];
  assets: {
    domains: { id: number; fqdn: string }[];
    ips: { id: number; address: string; org_name: string | null; country: string | null }[];
    services: {
      id: number;
      ip: string | null;
      port: number;
      product: string | null;
      version: string | null;
      cpe_uri: string | null;
      source: string | null;
    }[];
  };
  vulnerabilities: Vuln[];
  disclaimer: string;
}

// AI-анализ сценариев атак (Этап 6, оборонительно/гипотетически).
export interface AttackScenario {
  title: string;
  likelihood: "high" | "medium" | "low";
  based_on: string[];
  attack_path: string[];
  impact: string;
  remediation: string[];
}
export interface AttackAnalysisResult {
  overall_assessment: string;
  scenarios: AttackScenario[];
}
export interface AnalyzeResponse {
  target: string | null;
  model: string;
  findings_analyzed: number;
  disclaimer: string;
  analysis: AttackAnalysisResult | null;
  note?: string;
}

export interface GraphNode {
  data: { id: string; label: string; type: string; [k: string]: unknown };
}
export interface GraphEdge {
  data: { id: string; source: string; target: string; type: string; [k: string]: unknown };
}
export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
