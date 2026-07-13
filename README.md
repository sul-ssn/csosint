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

Этап 1 (CVE-база и матчинг) — готово ✔

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
- Покрыто юнит-тестами (парсинг, границы версий, золотые кейсы вроде Heartbleed,
  идемпотентность/резюмируемость синка) — сеть/БД в тестах не трогаются.

Дальше — Этап 2 (сбор данных: recon/dns/cert) по роадмапу ТЗ §8.

## Стек

Python 3.12 · FastAPI · Pydantic v2 · Celery + Redis · PostgreSQL 16 ·
SQLAlchemy 2 / Alembic · uv (workspace-монорепо) · Docker Compose.

## Структура

```
libs/common/          общие модули (config, db, models §5, schemas, health)
services/gateway/     API Gateway (BFF) — единая точка входа
services/cve_service/ синк NVD + матчинг product+version→CVE
migrations/           Alembic
docs → specification, design-cpe-matching.md, design-nvd-sync.md
```

> Код лежит в namespace `csosint` (исторический слаг репозитория); публичное имя
> проекта — **OSPC**.

## Быстрый старт (Docker)

```bash
cp .env.example .env      # при желании впишите свои API-ключи
docker compose up --build # PG, Redis, миграции, gateway (:8000), cve-service (:8001)
```

Health: `curl localhost:8000/health` · `curl localhost:8000/health/ready`
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
