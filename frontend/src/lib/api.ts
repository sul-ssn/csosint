// Клиент gateway API. База настраивается через NEXT_PUBLIC_API_URL (self-host).

import type { Graph, Report, ScanCreated, SourcesResponse } from "@/lib/types";

export const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export function wsBase(): string {
  return API_BASE.replace(/^http/, "ws");
}

async function asJson<T>(res: Response): Promise<T> {
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export async function createScan(target: string, type: string): Promise<ScanCreated> {
  const res = await fetch(`${API_BASE}/api/v1/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ target, type }),
  });
  return asJson<ScanCreated>(res);
}

export async function getReport(jobId: number): Promise<Report> {
  return asJson<Report>(await fetch(`${API_BASE}/api/v1/report/${jobId}`));
}

export async function getGraphByScan(jobId: number): Promise<Graph> {
  return asJson<Graph>(await fetch(`${API_BASE}/api/v1/graph/scan/${jobId}`));
}

export async function getSources(): Promise<SourcesResponse> {
  return asJson<SourcesResponse>(await fetch(`${API_BASE}/api/v1/sources`));
}
