import type { Metadata } from "next";
import Link from "next/link";

import "./globals.css";

export const metadata: Metadata = {
  title: "OSPC — Open Source Passive Cybersecurity",
  description: "Пассивная разведка поверхности атаки и CVE-аналитика (self-host)",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ru">
      <body>
        <header className="nav">
          <Link href="/" className="brand">
            OSPC
          </Link>
          <span className="tag">Open Source Passive Cybersecurity · self-host</span>
          <Link href="/" className="nav-link">
            Новый скан
          </Link>
          <Link href="/scan/1" className="nav-link">
            Демо-отчёт
          </Link>
          <Link href="/settings" className="nav-link">
            Источники и ключи
          </Link>
        </header>
        <main>{children}</main>
        <footer className="foot">
          Только публичные данные, без прямого сканирования целей. Результаты матчинга —
          «potentially vulnerable» (возможен бэкпорт-патч), не подтверждение. Инструмент для анализа
          своей инфраструктуры и легального OSINT.
        </footer>
      </body>
    </html>
  );
}
