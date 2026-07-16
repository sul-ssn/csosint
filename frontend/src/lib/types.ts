// Типы ответов gateway API.

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
  epss_score: number | null;
  epss_percentile: number | null;
  kev: boolean;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_required_action: string | null;
  kev_ransomware_use: string | null;
  risk_score: number;
  priority: Priority;
  risk_factors: { factor: string; impact: number; detail: string }[];
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
    known_exploited: number;
    high_epss: number;
  };
  exec_summary: string;
  top_risks: Vuln[];
  history: {
    baseline: boolean;
    reliable: boolean;
    suppressed_removed: number;
    previous_job: { id: number; created_at: string; finished_at: string | null } | null;
    summary: {
      added: number;
      changed: number;
      removed: number;
      total: number;
      by_type: Record<string, number>;
    };
    changes: {
      status: "added" | "changed" | "removed";
      entity_type: string;
      entity_key: string;
      before: Record<string, unknown> | null;
      after: Record<string, unknown> | null;
      changed_fields: string[];
    }[];
  };
  deep_analysis: {
    summary: {
      findings: number;
      critical_findings: number;
      high_findings: number;
      attack_paths: number;
      high_likelihood_paths: number;
    };
    findings: {
      id: string;
      category: "exposure" | "hygiene" | "misconfiguration";
      kind: string;
      severity: Priority;
      title: string;
      asset: string;
      confidence: Confidence;
      evidence: string[];
      remediation: string;
    }[];
    attack_paths: {
      id: string;
      title: string;
      likelihood: "high" | "medium" | "low";
      risk_score: number;
      confidence: Confidence;
      nodes: { type: string; label: string }[];
      evidence: string[];
      impact: string;
      remediation: string;
    }[];
  };
  assets: {
    domains: { id: number; fqdn: string }[];
    ips: {
      id: number;
      address: string;
      org_name: string | null;
      country: string | null;
      asn: string | null;
      network_cidr: string | null;
      network_start: string | null;
      network_end: string | null;
    }[];
    certificates: {
      id: number;
      fingerprint: string;
      issuer: string | null;
      not_before: string | null;
      not_after: string | null;
      source: string;
      domains: string[];
    }[];
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
