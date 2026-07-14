"use client";

import { useMemo, useState } from "react";

import type { Graph, Priority, Report, Vuln } from "@/lib/types";

import AttackAnalysisView from "./AttackAnalysisView";
import GraphView from "./GraphView";

function Stat({ value, label }: { value: number; label: string }) {
  return (
    <div className="stat">
      {value}
      <small>{label}</small>
    </div>
  );
}

// severity/priority используют одну палитру бейджей (critical/high/medium/low)
function SevChip({ tier, value, label }: { tier: string; value: number; label: string }) {
  return (
    <div className="sev-chip">
      <span className={`badge ${tier}`}>{value}</span>
      <small>{label}</small>
    </div>
  );
}

function cvssText(v: Vuln): string {
  const s = v.cvss_score ?? null;
  return `${s ?? "—"}${v.severity ? ` ${v.severity}` : ""}`;
}

function nvdLink(cve: string) {
  return (
    <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer">
      {cve}
    </a>
  );
}

const POSTURE_LABEL: Record<string, string> = {
  critical: "критическая",
  high: "высокая",
  medium: "средняя",
  low: "низкая",
  none: "уязвимостей нет",
};

type Section = "overview" | "vulnerabilities" | "assets" | "graph";

const NAV: { id: Section; label: string }[] = [
  { id: "overview", label: "Обзор" },
  { id: "vulnerabilities", label: "Уязвимости" },
  { id: "assets", label: "Активы" },
  { id: "graph", label: "Карта связей" },
];

export default function ReportView({ report, graph }: { report: Report; graph: Graph | null }) {
  const { summary, assets, vulnerabilities, top_risks, exec_summary, job, disclaimer } = report;
  const sev = summary.by_severity;
  const posture = summary.risk_posture as Priority | "none";
  const [section, setSection] = useState<Section>("overview");
  const [severity, setSeverity] = useState("all");
  const [query, setQuery] = useState("");
  const filteredVulns = useMemo(() => {
    const q = query.trim().toLowerCase();
    return vulnerabilities.filter((v) => {
      const sevMatch = severity === "all" || (v.severity ?? "unknown").toLowerCase() === severity;
      const text = `${v.cve_id} ${v.product ?? ""} ${v.version ?? ""} ${v.ip ?? ""} ${v.port}`.toLowerCase();
      return sevMatch && (!q || text.includes(q));
    });
  }, [query, severity, vulnerabilities]);

  const servicesByIp = useMemo(() => {
    return assets.ips.map((ip) => ({
      ...ip,
      services: assets.services.filter((service) => service.ip === ip.address),
    }));
  }, [assets]);

  return (
    <div className="report-workspace">
      <nav className="report-tabs" aria-label="Разделы отчёта">
        {NAV.map((item) => (
          <button
            type="button"
            key={item.id}
            className={section === item.id ? "active" : ""}
            onClick={() => setSection(item.id)}
          >
            {item.label}
            {item.id === "vulnerabilities" && <span>{summary.vulnerabilities}</span>}
            {item.id === "assets" && <span>{summary.ips + summary.services}</span>}
          </button>
        ))}
      </nav>

      {section === "overview" && <div className="report-section">
      <section className="overview-hero">
        <div className="overview-copy">
          <span className="section-kicker">Состояние безопасности</span>
        <div className="posture-row">
          <span className={`badge ${posture === "none" ? "low" : posture}`}>
            риск: {POSTURE_LABEL[posture] ?? posture}
          </span>
          <span className="muted">Оценка {summary.max_risk_score}/100</span>
        </div>
        <p className="exec-summary">{exec_summary}</p>
        </div>
        <div className={`risk-dial ${posture}`}>
          <strong>{summary.max_risk_score}</strong><span>/100</span>
          <small>макс. риск</small>
        </div>
      </section>

      <section className="metric-grid">
        <div className="stat-row">
          <Stat value={summary.domains} label="домены" />
          <Stat value={summary.ips} label="IP" />
          <Stat value={summary.services} label="сервисы" />
          <Stat value={summary.vulnerabilities} label="потенциальные CVE" />
        </div>
        <div className="severity-card">
          <div className="card-label">Распределение уязвимостей</div>
        <div className="sev-row">
          <SevChip tier="critical" value={sev.critical} label="critical" />
          <SevChip tier="high" value={sev.high} label="high" />
          <SevChip tier="medium" value={sev.medium} label="medium" />
          <SevChip tier="low" value={sev.low} label="low" />
          <SevChip tier="low" value={sev.unknown} label="unknown" />
        </div>
        </div>
      </section>

        {job.degraded_sources && Object.keys(job.degraded_sources).length > 0 && (
          <div className="source-warning">
            <b>Неполные данные</b><span>
            {Object.entries(job.degraded_sources)
              .map(([s, r]) => `${s} (${r})`)
              .join(", ")}
            </span>
          </div>
        )}

      {top_risks.length > 0 && (
        <section className="report-card">
          <div className="section-head"><div><span className="section-kicker">Приоритет</span><h2>Требуют внимания</h2></div><button className="text-btn" onClick={() => setSection("vulnerabilities")}>Все уязвимости →</button></div>
          <div className="risk-list">
            {top_risks.map((v, i) => (
              <div className="risk-item" key={`top-${v.service_id}-${v.cve_id}-${i}`}>
                <span className={`badge ${v.priority}`}>{v.priority}</span>
                <span className="risk-main"><b>{nvdLink(v.cve_id)}</b><small>{v.product ?? "Неизвестный сервис"}{v.version ? ` ${v.version}` : ""}</small></span>
                <span className="risk-host mono">{v.ip}:{v.port}</span>
                <span className="risk-cvss"><b>{v.cvss_score ?? "—"}</b><small>CVSS</small></span>
                <span className="risk-score"><b>{v.risk_score}</b><small>RISK</small></span>
              </div>
            ))}
          </div>
        </section>
      )}

      <AttackAnalysisView jobId={job.id} />
      <p className="disclaimer">{disclaimer}</p>
      </div>}

      {section === "vulnerabilities" && <section className="report-section report-card">
        <div className="section-head"><div><span className="section-kicker">Матчинг CPE / NVD</span><h2>Потенциальные уязвимости</h2><p>{vulnerabilities.length} совпадений, отсортированных по уровню риска</p></div></div>
        <div className="table-toolbar">
          <input placeholder="Поиск по CVE, сервису или хосту" value={query} onChange={(e) => setQuery(e.target.value)} />
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">Все уровни</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option>
          </select>
        </div>
        {vulnerabilities.length === 0 ? (
          <div className="empty-state"><b>Совпадений не найдено</b><span>Проверенные сервисы не совпали с локальной базой NVD.</span></div>
        ) : (
          <div className="table-scroll"><table className="data-table">
            <thead>
              <tr>
                <th>Приоритет</th>
                <th>Risk</th>
                <th>CVE</th>
                <th>CVSS</th>
                <th>Достоверность</th>
                <th>Сервис</th>
                <th>Хост</th>
              </tr>
            </thead>
            <tbody>{filteredVulns.map((v, i) => (
                <tr key={`${v.service_id}-${v.cve_id}-${i}`}>
                  <td>
                    <span className={`badge ${v.priority}`}>{v.priority}</span>
                  </td>
                  <td>{v.risk_score}</td>
                  <td>{nvdLink(v.cve_id)}</td>
                  <td>{cvssText(v)}</td>
                  <td>
                    <span className={`badge ${v.match_confidence}`}>{v.match_confidence}</span>
                  </td>
                  <td>
                    {v.product ?? "—"}
                    {v.version ? ` ${v.version}` : ""}
                    {v.description && <small className="cell-description">{v.description}</small>}
                  </td>
                  <td className="muted">
                    {v.ip}:{v.port}
                  </td>
                </tr>
              ))}</tbody>
          </table></div>
        )}
        {vulnerabilities.length > 0 && filteredVulns.length === 0 && <div className="empty-state"><b>Ничего не найдено</b><span>Измените запрос или фильтр уровня риска.</span></div>}
        <p className="disclaimer compact">{disclaimer}</p>
      </section>}

      {section === "assets" && <section className="report-section">
        <div className="section-head page-section-head"><div><span className="section-kicker">Инвентаризация</span><h2>Обнаруженные активы</h2><p>Хосты и сервисы, найденные в публичных источниках</p></div></div>
        {assets.domains.length > 0 && <div className="domain-strip"><span>Домены</span>{assets.domains.map((d) => <code key={d.id}>{d.fqdn}</code>)}</div>}
        <div className="asset-grid">
          {servicesByIp.map((ip) => <article className="asset-card" key={ip.id}>
            <div className="asset-head"><div><span className="asset-icon">IP</span><b className="mono">{ip.address}</b></div><span>{ip.country ?? "—"}</span></div>
            <p>{ip.org_name ?? "Организация не определена"}</p>
            <div className="service-list">{ip.services.length ? ip.services.map((s) => <div key={s.id}><span className="port mono">{s.port}</span><span><b>{s.product ?? "Неизвестный сервис"}</b><small>{s.version ?? s.source ?? "Версия не определена"}</small></span><span className="source-tag">{s.source ?? "source"}</span></div>) : <span className="muted">Сервисы не обнаружены</span>}</div>
          </article>)}
        </div>
      </section>}

      {section === "graph" && <section className="report-section graph-section">
        <div className="section-head page-section-head"><div><span className="section-kicker">Визуализация инфраструктуры</span><h2>Карта связей</h2><p>Выберите узел, чтобы увидеть его свойства и непосредственные связи</p></div></div>
        {graph && graph.nodes.length > 0 ? <GraphView graph={graph} /> : <div className="empty-state"><b>Граф пока пуст</b><span>Для этой цели не найдено связанных активов.</span></div>}
      </section>}
    </div>
  );
}
