"use client";

import { useParams } from "next/navigation";
import { useCallback, useState } from "react";

import GraphView from "@/components/GraphView";
import ReportView from "@/components/ReportView";
import ScanProgress from "@/components/ScanProgress";
import { getGraphByScan, getReport } from "@/lib/api";
import type { Graph, Report } from "@/lib/types";

export default function ScanPage() {
  const params = useParams();
  const jobId = Number(params.jobId as string);

  const [report, setReport] = useState<Report | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onDone = useCallback(
    async (ok: boolean) => {
      if (!ok) setError("Скан завершился с ошибкой — показываю, что успели собрать.");
      setLoading(true);
      try {
        const [r, g] = await Promise.all([getReport(jobId), getGraphByScan(jobId)]);
        setReport(r);
        setGraph(g);
      } catch (e) {
        setError(e instanceof Error ? e.message : "не удалось загрузить отчёт");
      } finally {
        setLoading(false);
      }
    },
    [jobId],
  );

  return (
    <>
      <h1>Скан #{jobId}</h1>
      {!report && <ScanProgress jobId={jobId} onDone={onDone} />}
      {loading && <p className="muted">Загрузка отчёта…</p>}
      {error && <p style={{ color: "var(--high)" }}>{error}</p>}
      {report && <ReportView report={report} />}
      {graph && graph.nodes.length > 0 && <GraphView graph={graph} />}
    </>
  );
}
