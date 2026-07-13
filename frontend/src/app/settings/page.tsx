"use client";

import { useEffect, useState } from "react";

import { getSources } from "@/lib/api";
import type { SourcesResponse } from "@/lib/types";

export default function SettingsPage() {
  const [sources, setSources] = useState<SourcesResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getSources()
      .then(setSources)
      .catch((e) => setError(e instanceof Error ? e.message : "ошибка"));
  }, []);

  return (
    <>
      <h1>Источники данных</h1>
      <p className="muted">
        Ядро работает без ключей. Опциональные источники включаются, если в{" "}
        <code>.env</code> сервера задан их API-ключ (self-host).
      </p>
      {error && <p style={{ color: "var(--high)" }}>Не удалось загрузить: {error}</p>}
      {sources && (
        <>
          <div className="panel">
            <strong>Core (всегда включены)</strong>
            <p style={{ marginBottom: 0 }}>
              {sources.core.map((s) => (
                <span key={s} className="badge low" style={{ marginRight: 8 }}>
                  {s}
                </span>
              ))}
            </p>
          </div>
          <div className="panel">
            <strong>Опциональное обогащение</strong>
            <table style={{ marginTop: 10 }}>
              <thead>
                <tr>
                  <th>Источник</th>
                  <th>Статус</th>
                </tr>
              </thead>
              <tbody>
                {sources.optional.map((o) => (
                  <tr key={o.name}>
                    <td>{o.name}</td>
                    <td>
                      <span className={`badge ${o.enabled ? "high" : "low"}`}>
                        {o.enabled ? "включён" : "skipped (нет ключа)"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
