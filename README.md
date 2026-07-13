# OSPC — Open Source Passive Cybersecurity

> Пассивная платформа **разведки поверхности атаки** и **CVE-аналитики**:
> агрегирует публичные данные (InternetDB, NVD, Certificate Transparency,
> DNS/RDAP), сопоставляет обнаруженные сервисы с известными уязвимостями и строит
> граф связей инфраструктуры — **без прямого сканирования целей**.

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
- **Vulnerability Intelligence** — корреляция «сервис + версия → CVE» с CVSS.
- **Passive OSINT / recon** — разведка по уже собранным публичным источникам.

**Чем OSPC НЕ является:** не сканер (не nmap/masscan), не эксплойт-фреймворк, не
замена активному пентесту. Держимся слов **passive**, **potential**,
**intelligence** — в этом и ценность, и легальность проекта.

## Статус

**Этап 0** каркас · **1** матчинг · **2** сбор · **3** граф · **4** frontend — готово ✔

### Этап 1 — CVE-база и матчинг

- **Синк NVD** (`cve_service.nvd`): устойчивый клиент API 2.0 (rate-limit, ретраи,
  уважение `Retry-After`), парсинг CVE + распаковка `configurations` в
  `cve_cpe_match`, резюмируемый bootstrap + суточный инкремент с дисциплиной
  курсора и идемпотентным upsert.
- **Матчинг** (`cve_service.matching`): `product → vendor:product`
  (alias → словарь → фаззи с порогом), сравнение версий через `univers`,
  тест диапазонов `including/excluding`, штраф за AND-конфигурации, корзины
  `match_confidence` (high/medium/low), дедуп по CVE.
- **API cve-service**: `/sync/run`, `/sync/status`, `/cve/{id}`,
  `/match/{service_id}` (+ GET). Celery-таски: `nvd_sync`, `match_service`.

### Этап 2 — сбор данных

- **collector-service**: пассивный сбор активов по цели (домен/IP). Core-источники
  без ключей — **InternetDB** (порты/CPE), **Certificate Transparency** (crt.sh
  с фолбэком на certspotter), **DNS** (dnspython) и **RDAP** (владелец/страна по IP).
  Опциональное обогащение по своему ключу — **Shodan, Censys, SecurityTrails,
  VirusTotal** (нет ключа → источник тихо `skipped`).
- **Отказоустойчивость**: единый http-хелпер с timeout + экспоненциальным retry
  (`tenacity`); падение/пропуск источника пишется в `scan_jobs.degraded_sources`
  и не роняет задачу (graceful degradation, ТЗ §4).
- **Провенанс**: у сервисов проставлен `source`; при конфликте по IP наблюдения
  не перетираются (COALESCE). Повторный скан идемпотентен.
- **Оркестрация**: `POST /api/v1/scan` создаёт `scan_job` и ставит сбор в очередь;
  `GET /api/v1/scan/{job_id}` — статус (+ `degraded_sources`). После сбора
  collector автоматически чейнит матчинг новых сервисов в cve-service.
- Покрыто юнит-тестами (respx-парсеры источников, degraded/skip-логика пайплайна,
  DNS на фейковом резолвере) — без сети.

### Этап 3 — граф связей

- **Граф в PostgreSQL** (`gateway.graph`, ТЗ §2.3): отдельной графовой СУБД нет —
  связная компонента активов считается **рекурсивным CTE** (`WITH RECURSIVE`) по
  двудольному графу `domain ↔ ip` (общий host связывает разные домены), а сервисы
  и CVE подтягиваются листовыми джойнами.
- **Формат Cytoscape**: результат — `{nodes, edges}` с типами узлов
  (domain/ip/service/cve) и рёбер (resolves/runs/vulnerable); сборка JSON — чистая
  функция, покрыта юнит-тестами.
- **Эндпоинты gateway**: `GET /api/v1/graph/domain/{fqdn}`,
  `/api/v1/graph/ip/{address}`, `/api/v1/graph/scan/{job_id}`.

### Этап 4 — Frontend + realtime

- **Backend-энейблеры**: `GET /api/v1/report/{job_id}` (активы + «потенциальные»
  CVE + дисклеймер), `GET /api/v1/sources` (статус core/опциональных источников),
  **WS `/ws/scan/{job_id}`** — прогресс в реальном времени через `Celery → Redis
  pub/sub → gateway WS → браузер` (общий контракт события в `csosint_common.events`).
- **Next.js 14** (`frontend/`, App Router + TS): форма цели, live-прогресс сбора
  по WS, страница отчёта (сводка/уязвимости/активы), визуализация графа на
  **Cytoscape.js**, страница статуса источников. Тёмная тема, self-host (база API —
  `NEXT_PUBLIC_API_URL`).

Дальше — Этап 5 (SSRF-guard, rate-limit, полировка/доки) по роадмапу ТЗ §8.

## Стек

Python 3.12 · FastAPI · Pydantic v2 · Celery + Redis · PostgreSQL 16 ·
SQLAlchemy 2 / Alembic · uv (workspace-монорепо) · Next.js 14 + Cytoscape.js ·
Docker Compose.

## Структура

```
libs/common/              общие модули (config, db, models §5, schemas, events, health)
services/gateway/         API Gateway (BFF) — вход, оркестрация scan, граф, отчёт, WS
services/cve_service/     синк NVD + матчинг product+version→CVE
services/collector_service/ пассивный сбор: InternetDB, CT, DNS/RDAP + опц. обогащение
frontend/                 Next.js 14 UI — форма, прогресс (WS), отчёт, граф
migrations/               Alembic
docs → specification, design-cpe-matching.md, design-nvd-sync.md
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

## Локальная разработка (без Docker)

```bash
uv sync --all-packages                       # единый .venv на монорепо
uv run ruff check . && uv run pytest         # линт + тесты
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

## Проектные документы

- `specification` — ТЗ (архитектура, решения, роадмап)
- `design-cpe-matching.md` — алгоритм матчинга сервис→CVE (§6)
- `design-nvd-sync.md` — наполнение локальной базы NVD (§4.2)

## Легальность и этика

См. ТЗ §9. Кратко: только публичные данные; уважение rate-limits и ToS
источников; результаты помечаются как potential; активного сканирования/
эксплуатации в проекте нет by design.

## Лицензия

[MIT](LICENSE) — свободное использование, модификация и распространение с
сохранением копирайта.
