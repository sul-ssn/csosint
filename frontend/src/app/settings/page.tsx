"use client";

import { useEffect, useState } from "react";

import { getSources } from "@/lib/api";
import type { SourcesResponse } from "@/lib/types";

// Метаданные опциональных источников: какой env-ключ и что даёт.
const META: Record<string, { env: string[]; desc: string }> = {
  shodan: {
    env: ["SHODAN_API_KEY"],
    desc: "Полные данные host(ip): баннеры и доп. поля сверх бесплатного InternetDB.",
  },
  censys: {
    env: ["CENSYS_API_ID", "CENSYS_API_SECRET"],
    desc: "Хосты, сервисы и сертификаты — альтернатива и дополнение к Shodan.",
  },
  securitytrails: {
    env: ["SECURITYTRAILS_API_KEY"],
    desc: "Пассивный DNS и историчные поддомены — сверх Certificate Transparency.",
  },
  virustotal: {
    env: ["VIRUSTOTAL_API_KEY"],
    desc: "Пассивный DNS, resolutions и поддомены.",
  },
};

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
      <div className="hero">
        <span className="kicker">self-host · ключи у вас</span>
        <h1>Источники и API-ключи</h1>
        <p className="lead">
          Ядро работает без ключей. Чтобы включить опциональный источник или AI-анализ, добавьте его
          ключ в файл <code>.env</code> рядом с сервисом gateway и перезапустите его — статус ниже
          обновится.
        </p>
      </div>

      <div className="callout">
        <b>Как включить →</b> впишите ключ в <code>csosint/.env</code>, затем перезапустите gateway.
        <br />
        Например: <code>SHODAN_API_KEY=xxxxxxxx</code> · при Docker: <code>docker compose up -d</code>{" "}
        подхватит переменные из <code>.env</code>.
      </div>

      {error && <p style={{ color: "var(--crit)" }}>Не удалось загрузить статус: {error}</p>}

      {sources && (
        <>
          <div className="panel">
            <strong>Core — всегда включены, без ключей</strong>
            <p style={{ margin: "10px 0 0" }}>
              {sources.core.map((s) => (
                <span key={s} className="badge ok" style={{ marginRight: 8 }}>
                  {s}
                </span>
              ))}
            </p>
          </div>

          <div className="panel">
            <strong>Опциональное обогащение</strong>
            <p className="muted" style={{ marginTop: 4 }}>
              Нет ключа → источник тихо пропускается (graceful degradation), скан не падает.
            </p>
            {sources.optional.map((o) => {
              const m = META[o.name] ?? { env: [], desc: "" };
              return (
                <div className="src-card" key={o.name}>
                  <span className="src-name">{o.name}</span>
                  <span className={`badge ${o.enabled ? "ok" : "low"}`}>
                    {o.enabled ? "✓ включён" : "не задан"}
                  </span>
                  <span className="src-desc">{m.desc}</span>
                  <span className="env-hint">
                    <span className="muted">ключ в .env:</span>
                    {m.env.map((k) => (
                      <span className="env-key" key={k}>
                        {k}
                      </span>
                    ))}
                  </span>
                </div>
              );
            })}
          </div>

          <div className="panel">
            <strong>AI-анализ сценариев атак</strong>
            <div className="src-card">
              <span className="src-name">Anthropic (Claude)</span>
              <span className="badge low">задаётся в .env</span>
              <span className="src-desc">
                Включает кнопку «AI-анализ» в отчёте — оборонительный разбор путей атаки. Без ключа
                эндпоинт отдаёт 501.
              </span>
              <span className="env-hint">
                <span className="muted">ключ в .env:</span>
                <span className="env-key">ANTHROPIC_API_KEY</span>
                <span className="muted">модель (опц.):</span>
                <span className="env-key">ANTHROPIC_MODEL=claude-opus-4-8</span>
              </span>
            </div>
          </div>
        </>
      )}
    </>
  );
}
