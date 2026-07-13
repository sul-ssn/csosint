"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createScan } from "@/lib/api";

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
      <h1>Пассивный скан цели</h1>
      <p className="muted">
        Только публичные данные, без прямого сканирования. Введите домен или IP —
        соберём поверхность атаки и сопоставим сервисы с известными CVE.
      </p>
      <form className="panel" onSubmit={submit}>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
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
            {busy ? "Запуск…" : "Сканировать"}
          </button>
        </div>
        {error && (
          <p style={{ color: "var(--high)", marginBottom: 0 }}>Не удалось запустить: {error}</p>
        )}
      </form>
    </>
  );
}
