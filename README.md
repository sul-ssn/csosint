# CSOSINT — CVE Intelligence Platform

Опенсорс-платформа **пассивной** кибераналитики: агрегирует публичные данные
(InternetDB, NVD, Certificate Transparency, DNS/RDAP), сопоставляет обнаруженные
сервисы с известными CVE и строит граф связей инфраструктуры — **без прямого
сканирования целей**.

> ⚠️ **Дисклеймер (важно).** Инструмент работает только с публичными данными и
> **не сканирует цели**. Предназначен для анализа **своей** инфраструктуры и
> легального OSINT/bug-bounty в рамках правил программ. Результаты матчинга —
> «**potentially vulnerable**»: наличие версии с известной CVE не означает, что
> хост реально уязвим (возможен бэкпорт-патч). Это оценка вероятности, не
> подтверждение.

**Модель — self-host:** публичного инстанса нет, вы запускаете стек у себя со
своими API-ключами (см. `.env.example`).

## Статус

Этап 0 (каркас) — инфраструктура, `libs/common`, gateway и cve-service со
скелетом, миграции, CI. Логика синка NVD и матчинга — Этап 1.

## Стек

Python 3.12 · FastAPI · Pydantic v2 · Celery + Redis · PostgreSQL 16 ·
SQLAlchemy 2 / Alembic · uv (workspace-монорепо) · Docker Compose.

## Структура

```
libs/common/         общие модули (config, db, models §5, schemas, health)
services/gateway/    API Gateway (BFF) — единая точка входа
services/cve_service/ синк NVD + матчинг product+version→CVE
migrations/          Alembic
docs → specification, design-cpe-matching.md, design-nvd-sync.md
```

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
