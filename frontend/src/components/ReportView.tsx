import type { Report } from "@/lib/types";

function Stat({ value, label }: { value: number; label: string }) {
  return (
    <div className="stat">
      {value}
      <small>{label}</small>
    </div>
  );
}

export default function ReportView({ report }: { report: Report }) {
  const { summary, assets, vulnerabilities, job, disclaimer } = report;
  return (
    <>
      <div className="panel">
        <div className="stat-row">
          <Stat value={summary.domains} label="домены" />
          <Stat value={summary.ips} label="IP" />
          <Stat value={summary.services} label="сервисы" />
          <Stat value={summary.vulnerabilities} label="CVE (potential)" />
          <Stat value={summary.high} label="high" />
          <Stat value={summary.medium} label="medium" />
          <Stat value={summary.low} label="low" />
        </div>
        {job.degraded_sources && Object.keys(job.degraded_sources).length > 0 && (
          <p className="muted" style={{ marginBottom: 0 }}>
            Деградация источников:{" "}
            {Object.entries(job.degraded_sources)
              .map(([s, r]) => `${s} (${r})`)
              .join(", ")}
          </p>
        )}
      </div>

      <p className="disclaimer">{disclaimer}</p>

      <div className="panel">
        <strong>Потенциальные уязвимости</strong>
        {vulnerabilities.length === 0 ? (
          <p className="muted">Совпадений не найдено.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Достоверность</th>
                <th>CVSS</th>
                <th>Сервис</th>
                <th>Хост</th>
              </tr>
            </thead>
            <tbody>
              {vulnerabilities.map((v, i) => (
                <tr key={`${v.service_id}-${v.cve_id}-${i}`}>
                  <td>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {v.cve_id}
                    </a>
                  </td>
                  <td>
                    <span className={`badge ${v.match_confidence}`}>{v.match_confidence}</span>
                  </td>
                  <td>
                    {v.cvss_score ?? "—"}
                    {v.severity ? ` ${v.severity}` : ""}
                  </td>
                  <td>
                    {v.product ?? "—"}
                    {v.version ? ` ${v.version}` : ""}
                  </td>
                  <td className="muted">
                    {v.ip}:{v.port}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <strong>Активы</strong>
        <p className="muted" style={{ marginTop: 8 }}>
          Домены: {assets.domains.map((d) => d.fqdn).join(", ") || "—"}
        </p>
        <table>
          <thead>
            <tr>
              <th>Хост</th>
              <th>Порт</th>
              <th>Сервис</th>
              <th>Источник</th>
            </tr>
          </thead>
          <tbody>
            {assets.services.map((s) => (
              <tr key={s.id}>
                <td>{s.ip}</td>
                <td>{s.port}</td>
                <td>
                  {s.product ?? "—"}
                  {s.version ? ` ${s.version}` : ""}
                </td>
                <td className="muted">{s.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
