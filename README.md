# OSPC — Open Source Passive Cybersecurity

> Self-hosted платформа **разведки поверхности атаки** и **risk-based CVE-аналитики**:
> агрегирует публичные данные (InternetDB, NVD, Certificate Transparency,
> DNS/RDAP, FIRST EPSS, CISA KEV), сопоставляет сервисы с уязвимостями, отслеживает
> изменения и строит объяснимый граф инфраструктуры — **без прямого сканирования целей**.

![python](https://img.shields.io/badge/python-3.12-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![style](https://img.shields.io/badge/lint-ruff-000000)
<!-- CI-бейдж активируется после пуша: -->
<!-- ![ci](https://github.com/<user>/csosint/actions/workflows/ci.yml/badge.svg) -->

---

> ⚠️ **Дисклеймер (важно).** OSPC работает только с публичными данными и **не
> сканирует цели**. Инструмент — для анализа **своей** инфраструктуры и легального
> OSINT/bug-bounty в рамках правил программ. Результаты матчинга —
> «**potentially vulnerable**»: наличие версии с известной CVE не означает, что
> хост реально уязвим (возможен бэкпорт-патч). Это оценка вероятности, не
> подтверждение.

**Модель — self-host:** публичного инстанса нет, вы запускаете стек у себя со
своими API-ключами (см. `.env.example`).

## Что это

- **Attack Surface Management (ASM)** — карта своей внешней поверхности атаки.
- **Vulnerability Intelligence** — корреляция «сервис + версия → CVE» с CVSS,
  EPSS и подтверждённой эксплуатацией CISA KEV.
- **Passive OSINT / recon** — разведка по уже собранным публичным источникам.
- **Change Detection** — сравнение последовательных сканов и история активов.
- **Infrastructure Intelligence** — сертификаты, ASN, netblock и связанные домены.
- **Explainable Analysis** — exposure findings, evidence, remediation и attack paths.

**Чем OSPC НЕ является:** не сканер (не nmap/masscan), не эксплойт-фреймворк, не
замена активному пентесту. Держимся слов **passive**, **potential**,
**intelligence** — в этом и ценность, и легальность проекта.

## Возможности

- Пассивный сбор доменов, IP, портов, сервисов, DNS/RDAP и CT-сертификатов.
- Опциональное обогащение через Shodan, Censys, SecurityTrails и VirusTotal.
- Локальная копия NVD с резюмируемым bootstrap/incremental sync.
- CPE-матчинг с диапазонами версий и confidence `high/medium/low`.
- Ежедневное обогащение CVE через FIRST EPSS и официальный CISA KEV feed.
- Объяснимый risk score: CVSS × confidence + EPSS + KEV + ransomware signal.
- История сканов: новые, изменившиеся и исчезнувшие активы; защита от ложных
  removals при деградации источников.
- Детерминированные findings для публичных БД/admin/remote-access портов,
  неизвестных версий, dev/staging-активов и сертификатов.
- Attack paths с evidence, likelihood, impact и remediation.
- Инфраструктурный граф: домены, IP, сервисы, CVE, сертификаты, организации,
  страны, ASN и netblock-кластеры.
- Контекстный поиск по графу с раскрытием окружения на 1–3 шага.
- Опциональный оборонительный AI-анализ с собственным Anthropic API key.

## Стек

Python 3.12 · FastAPI · Pydantic v2 · Celery + Redis · PostgreSQL 16 ·
SQLAlchemy 2 / Alembic · uv (workspace-монорепо) · Next.js 14 + Cytoscape.js ·
Docker Compose.

## Структура

```
libs/common/              общие модули: config, db, ORM, schemas, events, health
services/gateway/         API Gateway (BFF) — вход, оркестрация scan, граф, отчёт, WS
services/cve_service/     NVD sync, CPE-матчинг, FIRST EPSS и CISA KEV
services/collector_service/ пассивный сбор, snapshots, CT, DNS/RDAP, enrichment
frontend/                 Next.js UI — scan, history, analysis, assets, graph
migrations/               Alembic
tests/                    unit/API tests без обязательной внешней сети
```

> Код лежит в namespace `csosint` (исторический слаг репозитория); публичное имя
> проекта — **OSPC**.

## Быстрый старт (Docker)

```bash
cp .env.example .env      # при желании впишите свои API-ключи
docker compose up --build # PG, Redis, миграции, gateway (:8000), cve (:8001),
                          # collector (:8002), UI (:3000)
```

UI: `http://localhost:3000` · Health: `curl localhost:8000/health`
Docs (OpenAPI): `http://localhost:8000/docs`

После первого наполнения NVD можно отдельно обновить exploitation intelligence:

```bash
curl -X POST http://localhost:8001/intel/sync
```

## Локальная разработка (без Docker)

```bash
uv sync --all-packages                       # единый .venv на монорепо
uv run ruff check . && uv run pytest         # линт + 152+ теста
uv run uvicorn gateway.main:app --reload     # gateway на :8000
```

Миграции (нужен запущенный PostgreSQL):
```bash
uv run alembic upgrade head
```

Frontend (нужен Node 20+):
```bash
cd frontend && npm install && npm run dev   # UI на :3000, ждёт gateway на :8000
```

## Технические документы

- `design-cpe-matching.md` — алгоритм сопоставления сервисов и CPE.
- `design-nvd-sync.md` — стратегия bootstrap/incremental sync NVD.

## Источники данных

Без ключей работают InternetDB, NVD, crt.sh/CertSpotter, DNS/RDAP, FIRST EPSS
и CISA KEV. При наличии пользовательских ключей подключаются Shodan, Censys,
SecurityTrails и VirusTotal. Сбои отдельных источников не прерывают весь scan:
система возвращает частичный результат и явно отмечает degraded sources.

## Легальность и этика

Только публичные данные; уважение rate limits и ToS источников; результаты
матчинга помечаются как potential. Активного сканирования, проверки exploitability
на цели и эксплуатации в проекте нет by design. DNS/RDAP обращаются к публичной
инфраструктуре резолверов и регистраторов, поэтому passive не означает zero-touch.

## Лицензия

[MIT](LICENSE) — свободное использование, модификация и распространение с
сохранением копирайта.
