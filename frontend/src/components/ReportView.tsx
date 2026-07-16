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

function ExploitSignals({ vuln }: { vuln: Vuln }) {
  return <span className="exploit-signals">
    {vuln.kev && <span className="intel-badge kev" title={vuln.kev_required_action ?? "Known Exploited Vulnerability"}>KEV</span>}
    {vuln.epss_score != null && <span className={`intel-badge epss ${vuln.epss_score >= .1 ? "hot" : ""}`} title={`EPSS percentile ${((vuln.epss_percentile ?? 0) * 100).toFixed(1)}%`}>EPSS {(vuln.epss_score * 100).toFixed(1)}%</span>}
    {vuln.kev_ransomware_use?.toLowerCase() === "known" && <span className="intel-badge ransomware">RANSOMWARE</span>}
  </span>;
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

const ENTITY_LABEL: Record<string, string> = {
  domain: "Домен",
  ip: "IP-адрес",
  resolution: "DNS-связь",
  service: "Сервис",
  dns: "DNS-записи",
  vulnerability: "CVE",
};

const CHANGE_LABEL = { added: "Добавлено", changed: "Изменено", removed: "Исчезло" };

type Section = "overview" | "analysis" | "vulnerabilities" | "assets" | "graph";

const NAV: { id: Section; label: string }[] = [
  { id: "overview", label: "Обзор" },
  { id: "analysis", label: "Анализ" },
  { id: "vulnerabilities", label: "Уязвимости" },
  { id: "assets", label: "Активы" },
  { id: "graph", label: "Карта связей" },
];

export default function ReportView({ report, graph }: { report: Report; graph: Graph | null }) {
  const { summary, assets, vulnerabilities, top_risks, exec_summary, job, disclaimer } = report;
  const history = report.history;
  const deep = report.deep_analysis;
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
            {item.id === "analysis" && deep && <span>{deep.summary.findings + deep.summary.attack_paths}</span>}
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

      {(summary.known_exploited > 0 || summary.high_epss > 0) && <div className="intel-summary">
        <span className="intel-icon">!</span>
        <div><b>Есть признаки реальной эксплуатации</b><small>{summary.known_exploited} CVE входят в CISA KEV · {summary.high_epss} имеют EPSS ≥ 10%</small></div>
      </div>}

      {history && <section className="report-card changes-card">
        <div className="section-head">
          <div>
            <span className="section-kicker">Мониторинг поверхности</span>
            <h2>Что изменилось</h2>
            <p>{history.previous_job ? `По сравнению со сканом #${history.previous_job.id}` : "Первый снимок этой цели"}</p>
          </div>
          {history.baseline && <div className="change-counters">
            <span className="added">+{history.summary.added}<small>новых</small></span>
            <span className="changed">{history.summary.changed}<small>изменено</small></span>
            <span className="removed">−{history.summary.removed}<small>исчезло</small></span>
          </div>}
        </div>
        {history.baseline && !history.reliable && <div className="history-quality">
          Сравнение частичное: один или несколько источников недоступны.
          {history.suppressed_removed > 0 && ` ${history.suppressed_removed} неподтверждённых исчезновений скрыто.`}
        </div>}
        {!history.baseline ? (
          <div className="baseline-state"><b>Базовый снимок создан</b><span>Изменения появятся после следующего сканирования этой цели.</span></div>
        ) : history.summary.total === 0 ? (
          <div className="baseline-state stable"><b>Изменений не обнаружено</b><span>Наблюдаемая поверхность атаки осталась стабильной.</span></div>
        ) : (
          <div className="change-list">
            {history.changes.slice(0, 8).map((change) => <div className="change-row" key={`${change.status}:${change.entity_type}:${change.entity_key}`}>
              <span className={`change-status ${change.status}`}>{CHANGE_LABEL[change.status]}</span>
              <span className="change-kind">{ENTITY_LABEL[change.entity_type] ?? change.entity_type}</span>
              <b className="mono">{change.entity_key}</b>
              {change.changed_fields.length > 0 && <span className="change-fields">{change.changed_fields.join(", ")}</span>}
            </div>)}
            {history.changes.length > 8 && <div className="more-changes">Ещё {history.changes.length - 8} изменений</div>}
          </div>
        )}
      </section>}

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
                <span className="risk-main"><b>{nvdLink(v.cve_id)}</b><small>{v.product ?? "Неизвестный сервис"}{v.version ? ` ${v.version}` : ""}</small><ExploitSignals vuln={v} /></span>
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

      {section === "analysis" && <section className="report-section analysis-section">
        <div className="section-head page-section-head"><div><span className="section-kicker">Детерминированные правила</span><h2>Глубокий анализ поверхности</h2><p>Экспозиции, гигиена и вероятные пути атаки с доказательствами</p></div></div>
        {!deep ? <div className="empty-state"><b>Анализ недоступен</b><span>Перезапустите gateway и обновите отчёт.</span></div> : <>
          <div className="analysis-metrics">
            <div><strong>{deep.summary.findings}</strong><span>наблюдений</span></div>
            <div><strong>{deep.summary.critical_findings + deep.summary.high_findings}</strong><span>high / critical</span></div>
            <div><strong>{deep.summary.attack_paths}</strong><span>путей атаки</span></div>
            <div><strong>{deep.summary.high_likelihood_paths}</strong><span>high likelihood</span></div>
          </div>

          <div className="analysis-layout">
            <div className="analysis-column">
              <div className="analysis-title"><span>Exposure findings</span><b>{deep.findings.length}</b></div>
              {deep.findings.length === 0 ? <div className="mini-empty">Значимых экспозиций по текущим правилам не найдено.</div> : deep.findings.map((finding) => <article className="finding-card" key={finding.id}>
                <div className="finding-head"><span className={`badge ${finding.severity}`}>{finding.severity}</span><span className="finding-category">{finding.category}</span><span className={`confidence-dot ${finding.confidence}`}>{finding.confidence}</span></div>
                <h3>{finding.title}</h3><code>{finding.asset}</code>
                <div className="evidence-list">{finding.evidence.map((item) => <span key={item}>{item}</span>)}</div>
                <div className="remediation-box"><b>Что сделать</b><span>{finding.remediation}</span></div>
              </article>)}
            </div>

            <div className="analysis-column paths-column">
              <div className="analysis-title"><span>Attack paths</span><b>{deep.attack_paths.length}</b></div>
              {deep.attack_paths.length === 0 ? <div className="mini-empty">Приоритетных путей атаки не построено.</div> : deep.attack_paths.map((path) => <article className="path-card" key={path.id}>
                <div className="path-head"><span className={`badge ${path.likelihood}`}>{path.likelihood}</span><b>{path.title}</b><span className="path-risk">{path.risk_score}</span></div>
                <div className="path-flow">{path.nodes.map((node, index) => <div className="path-step" key={`${node.type}:${node.label}`}><span className={`path-node ${node.type}`}>{node.label}</span>{index < path.nodes.length - 1 && <i>→</i>}</div>)}</div>
                <details className="path-details"><summary>Доказательства и меры</summary><div><b>Evidence</b>{path.evidence.map((item) => <span key={item}>{item}</span>)}<b>Воздействие</b><span>{path.impact}</span><b>Что сделать</b><span>{path.remediation}</span></div></details>
              </article>)}
            </div>
          </div>
        </>}
      </section>}

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
                <th>Эксплуатация</th>
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
                  <td><ExploitSignals vuln={v} /></td>
                  <td>
                    <span className={`badge ${v.match_confidence}`}>{v.match_confidence}</span>
                  </td>
                  <td>
                    {v.product ?? "—"}
                    {v.version ? ` ${v.version}` : ""}
                    {v.description && <small className="cell-description">{v.description}</small>}
                    {v.risk_factors?.length > 0 && <small className="risk-explanation">{v.risk_factors.map((factor) => factor.detail).join(" · ")}</small>}
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
            <p>{ip.org_name ?? "Организация не определена"}{ip.asn ? ` · ${ip.asn}` : ""}{ip.network_cidr ? ` · ${ip.network_cidr}` : ""}</p>
            <div className="service-list">{ip.services.length ? ip.services.map((s) => <div key={s.id}><span className="port mono">{s.port}</span><span><b>{s.product ?? "Неизвестный сервис"}</b><small>{s.version ?? s.source ?? "Версия не определена"}</small></span><span className="source-tag">{s.source ?? "source"}</span></div>) : <span className="muted">Сервисы не обнаружены</span>}</div>
          </article>)}
        </div>
        {assets.certificates?.length > 0 && <div className="certificate-grid">
          {assets.certificates.map((cert) => <article className="certificate-card" key={cert.id}>
            <div><span className="cert-icon">TLS</span><b>{cert.issuer ?? "Issuer не определён"}</b></div>
            <code>{cert.fingerprint}</code>
            <span>{cert.domains.length} доменов · до {cert.not_after ? new Date(cert.not_after).toLocaleDateString("ru-RU") : "—"}</span>
          </article>)}
        </div>}
      </section>}

      {section === "graph" && <section className="report-section graph-section">
        <div className="section-head page-section-head"><div><span className="section-kicker">Визуализация инфраструктуры</span><h2>Карта связей</h2><p>Выберите узел, чтобы увидеть его свойства и непосредственные связи</p></div></div>
        {graph && graph.nodes.length > 0 ? <GraphView graph={graph} /> : <div className="empty-state"><b>Граф пока пуст</b><span>Для этой цели не найдено связанных активов.</span></div>}
      </section>}
    </div>
  );
}
