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
          <Link href="/">Новый скан</Link>
          <Link href="/settings">Источники</Link>
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
