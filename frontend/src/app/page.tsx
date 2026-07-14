"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { createScan } from "@/lib/api";

const CAPS = [
  {
    ic: "🛰️",
    t: "Attack Surface Management",
    d: "Поддомены, IP, открытые порты и версии сервисов — карта внешней поверхности атаки.",
  },
  {
    ic: "🛡️",
    t: "Vulnerability Intelligence",
    d: "Сопоставление «сервис + версия → CVE» с CVSS и приоритизацией по риску.",
  },
  {
    ic: "🧠",
    t: "AI-сценарии атак",
    d: "Оборонительный разбор: вероятные пути атаки и меры устранения (опц., свой ключ).",
  },
];

export default function HomePage() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [type, setType] = useState("domain");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { job_id } = await createScan(target.trim(), type);
      router.push(`/scan/${job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "ошибка запуска");
      setBusy(false);
    }
  }

  return (
    <>
      <div className="hero">
        <span className="kicker">Passive recon · без сканирования целей</span>
        <h1>Разведка поверхности атаки и CVE-аналитика</h1>
        <p className="lead">
          Введите домен или IP — OSPC соберёт публичные данные (InternetDB, Certificate Transparency,
          DNS/RDAP), сопоставит сервисы с известными уязвимостями, приоритизирует по риску и построит
          граф связей. Пакеты на цель не отправляются.
        </p>
      </div>

      <div className="cap-grid">
        {CAPS.map((c) => (
          <div className="cap" key={c.t}>
            <span className="ic">{c.ic}</span>
            <b>{c.t}</b>
            <small>{c.d}</small>
          </div>
        ))}
      </div>

      <form className="panel" onSubmit={submit}>
        <div className="ai-head" style={{ marginBottom: 12 }}>
          <strong>Запустить пассивный скан</strong>
          <span className="pill">только публичные данные</span>
        </div>
        <div className="scan-form">
          <select value={type} onChange={(e) => setType(e.target.value)} aria-label="Тип цели">
            <option value="domain">домен</option>
            <option value="ip">IP</option>
            <option value="org">организация</option>
          </select>
          <input
            style={{ flex: 1, minWidth: 260 }}
            placeholder={type === "ip" ? "8.8.8.8" : "example.com"}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            required
          />
          <button type="submit" disabled={busy || target.trim().length === 0}>
            {busy ? "Запуск…" : "Сканировать →"}
          </button>
        </div>
        <div className="examples">
          <span className="muted">Примеры:</span>
          {["example.com", "cloudflare.com", "8.8.8.8"].map((ex) => (
            <button
              type="button"
              className="chip"
              key={ex}
              onClick={() => {
                setType(/^\d/.test(ex) ? "ip" : "domain");
                setTarget(ex);
              }}
            >
              {ex}
            </button>
          ))}
          <span className="muted">
            · или откройте <Link href="/scan/1">демо-отчёт</Link>
          </span>
        </div>
        {error && (
          <p style={{ color: "var(--crit)", marginBottom: 0, marginTop: 12 }}>
            Не удалось запустить: {error}
          </p>
        )}
      </form>
    </>
  );
}
