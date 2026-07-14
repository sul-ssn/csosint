"use client";

import { useState } from "react";

import { analyzeReport } from "@/lib/api";
import type { AnalyzeResponse } from "@/lib/types";

type State = "idle" | "loading" | "done" | "error";

export default function AttackAnalysisView({ jobId }: { jobId: number }) {
  const [state, setState] = useState<State>("idle");
  const [data, setData] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState("");

  async function run() {
    setState("loading");
    setError("");
    try {
      setData(await analyzeReport(jobId));
      setState("done");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(
        msg.startsWith("501")
          ? "AI-анализ не сконфигурирован: задайте ANTHROPIC_API_KEY на gateway."
          : msg,
      );
      setState("error");
    }
  }

  return (
    <div className="panel">
      <div className="ai-head">
        <strong>AI-анализ сценариев атак</strong>
        <button className="ai-btn" onClick={run} disabled={state === "loading"}>
          {state === "loading" ? "Анализирую…" : state === "done" ? "Повторить" : "Запустить"}
        </button>
      </div>
      <p className="muted" style={{ marginTop: 6 }}>
        Оборонительно и гипотетически: по «потенциальным» находкам строятся возможные пути атаки
        и приоритетные меры устранения.
      </p>

      {state === "error" && <p className="disclaimer">{error}</p>}

      {state === "done" && data?.analysis && (
        <>
          <p style={{ marginTop: 10 }}>{data.analysis.overall_assessment}</p>
          <div className="scenario-list">
            {data.analysis.scenarios.map((s, i) => (
              <div className="scenario" key={i}>
                <div className="scenario-head">
                  <span className={`badge ${s.likelihood}`}>{s.likelihood}</span>
                  <strong>{s.title}</strong>
                  <span className="muted">{s.based_on.join(", ")}</span>
                </div>
                <ol className="attack-path">
                  {s.attack_path.map((step, j) => (
                    <li key={j}>{step}</li>
                  ))}
                </ol>
                <p className="muted">
                  <b>Воздействие:</b> {s.impact}
                </p>
                <b>Устранение:</b>
                <ul className="remediation">
                  {s.remediation.map((r, j) => (
                    <li key={j}>{r}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <p className="disclaimer" style={{ marginTop: 10 }}>
            {data.disclaimer}
          </p>
          <p className="muted">
            Модель: {data.model} · находок в анализе: {data.findings_analyzed}
          </p>
        </>
      )}

      {state === "done" && !data?.analysis && (
        <p className="muted">{data?.note ?? "Нет находок для анализа."}</p>
      )}
    </div>
  );
}
