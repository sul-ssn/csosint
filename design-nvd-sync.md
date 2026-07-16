# Дизайн: синхронизация базы NVD

Наполняет локальную копию CVE, по которой работает матчинг
([design-cpe-matching.md](design-cpe-matching.md)). Без этого матчить нечего.
Живёт в **cve-service**, Этап 1 роадмапа (недели 2–4).

**Принцип:** не дёргать NVD на каждый пользовательский запрос. Один раз —
полный bootstrap в PostgreSQL, дальше — инкрементальные догрузки по расписанию.
Матчинг ходит только в локальную базу: быстро и без лимитов.

---

## 1. NVD API 2.0 — что дёргаем

**CVE API:** `https://services.nvd.nist.gov/rest/json/cves/2.0`

| Параметр | Смысл |
|----------|-------|
| `resultsPerPage` | размер страницы, **макс 2000** |
| `startIndex` | смещение для пагинации |
| `lastModStartDate` / `lastModEndDate` | окно по дате модификации (инкремент); **макс диапазон 120 дней** |
| `pubStartDate` / `pubEndDate` | по дате публикации (не используем) |

Ответ (обёртка):
```jsonc
{
  "resultsPerPage": 2000, "startIndex": 0, "totalResults": 267000,
  "timestamp": "2026-07-13T...",
  "vulnerabilities": [ { "cve": { … } }, … ]
}
```
Пагинация: идём `startIndex += resultsPerPage`, пока `startIndex < totalResults`.

**Лимиты (критично):**
- без ключа: **5 запросов / 30 сек** (rolling);
- с бесплатным ключом: **50 / 30 сек** — ключ обязателен;
- NVD флакает: частые `503`/таймауты. Держим настраиваемую паузу между запросами
  (0.6–6 с) + жёсткий бэкофф на ошибки.

**Объём:** ~250–280k CVE → при 2000/страница это ~130–140 страниц. Полный
bootstrap реалистично — **десятки минут, планируй до часа** с ретраями.

**CPE API** (для словаря, см. §7): `.../rest/json/cpes/2.0`, `resultsPerPage`
макс **10000**.

---

## 2. Стратегия: bootstrap + инкремент

```
        ┌────────────────────────────────────────────┐
        │  sync_state пуст?                            │
        └───────────────┬──────────────────┬──────────┘
                    да  │              нет  │
                        ▼                   ▼
              FULL BOOTSTRAP        INCREMENTAL (по расписанию)
       (пагинация всей базы)   (lastModStartDate = курсор, End = now)
                        │                   │
                        └─────────┬─────────┘
                                  ▼
                    upsert cve_records + пересборка cve_cpe_match
                                  ▼
                    продвинуть курсор ТОЛЬКО после успеха окна
```

- **Bootstrap:** пройти всю базу постранично один раз.
- **Инкремент:** `lastModStartDate = last_success_cursor`, `lastModEndDate = now`.
  Дневное окно всегда влезает в лимит 120 дней. Запускается Celery-beat раз в
  сутки (или чаще — NVD обновляется постоянно, но суточного интервала достаточно).

---

## 3. Состояние синка и резюмируемость

Таблица курсора — **источник истины для «где мы остановились»**:

```
sync_state (
  source            text primary key,     -- 'nvd_cve' | 'nvd_cpe'
  phase             text,                  -- 'bootstrap' | 'incremental'
  last_mod_cursor   timestamptz,           -- до какого lastModified база актуальна
  bootstrap_index   int,                   -- startIndex последней закоммиченной страницы
  status            text,                  -- 'idle'|'running'|'failed'
  last_run_at       timestamptz,
  last_error        text
)
```

**Резюмируемость:**
- Bootstrap падает на странице N → `bootstrap_index` указывает на последнюю
  **закоммиченную** страницу; следующий запуск продолжает с неё, а не с нуля.
- **Курсор `last_mod_cursor` продвигаем ТОЛЬКО после того, как всё окно
  полностью обработано и закоммичено.** Иначе при сбое посреди окна получим
  дыру. Частичный прогресс внутри окна безопасен за счёт идемпотентного upsert
  (§8) — переобработать страницу не вредно.
- **Небольшой overlap:** `lastModStartDate` берём с запасом назад на несколько
  минут от прошлого `End` — защита от гонки «CVE изменилась между чтением и
  записью». Дубликаты гасит upsert.

---

## 4. Rate-limit и ретраи

- **Лимитер:** токен-бакет под тариф (с ключом ≤50/30с). Плюс настраиваемый
  `min_delay` между запросами (дефолт консервативный).
- **Ретраи (`tenacity`):** экспоненциальный бэкофф + jitter на `429/503/5xx/
  timeout/ConnectionError`. Уважать заголовок `Retry-After`, если пришёл.
- **Не ретраим** `403` (плохой ключ) и `404` — это конфиг-ошибки, падаем громко.
- Лимит попыток на страницу; исчерпан → помечаем `sync_state.status='failed'`,
  курсор не двигаем, следующий запуск подхватит.

---

## 5. Парсинг CVE → `cve_records`

Из каждого элемента `vulnerabilities[].cve`:

```
cve_id       = cve.id
description  = descriptions[lang=en].value
published    = cve.published
modified     = cve.lastModified
raw          = cve                      ← весь JSON в jsonb (см. ниже)
+ CVSS (см. приоритет)
```

**Приоритет CVSS** — берём первый доступный по убыванию, тип `Primary` важнее:
```
metrics.cvssMetricV31 → V30 → V2   (V40 когда появится — выше всех)
храним: cvss_version, cvss_score (baseScore),
        severity (baseSeverity), cvss_vector (vectorString)
```

**Храним сырой JSON (`cve_records.raw jsonb`).** Причина: если поменяется логика
распаковки `configurations` или CVSS, пересоберём `cve_cpe_match` из локального
`raw` **без повторного похода в NVD**. Учитывая флакость API — сильно окупается.

---

## 6. Распаковка `configurations` → `cve_cpe_match`

Ключевой шаг для матчинга. Структура в API 2.0 — два уровня, где может быть AND:

```jsonc
"configurations": [{
  "operator": "AND",              // (опц.) AND между дочерними nodes — «running on»
  "nodes": [{
    "operator": "OR",             // операция над cpeMatch внутри узла
    "negate": false,
    "cpeMatch": [{
      "vulnerable": true,
      "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
      "versionStartIncluding": "2.0",
      "versionEndExcluding": "2.15.0",
      "matchCriteriaId": "…"
    }]
  }]
}]
```

Разворачиваем в плоские строки, **сохраняя группировку** (нужна для AND-логики
§8 матчинга):

```
cve_cpe_match (
  id, cve_id,
  config_idx      int,      -- индекс конфигурации в массиве
  node_idx        int,      -- индекс узла в конфигурации
  config_operator text,     -- AND|OR|NULL  (уровень «running on»)
  node_operator   text,     -- AND|OR
  vulnerable_bool bool,
  cpe_uri         text,
  vendor          text,     -- денормализация из cpe_uri (индекс!)
  product         text,     -- денормализация
  part            text,     -- a|o|h
  version_start   text, version_start_type text,   -- including|excluding
  version_end     text, version_end_type   text
)
```
Индекс `(part, vendor, product) WHERE vulnerable_bool` — под выборку кандидатов
(§6 матчинга). `vendor/product/part` парсим из `cpe_uri` при вставке.

Так по `config_idx`/`config_operator` матчинг видит, что уязвимый `log4j`-CPE
стоит в AND с «running on»-условием, и корректно понижает confidence (§8 матчинга).

---

## 7. CPE Dictionary: полный словарь или производный набор? **[решение]**

Для маппинга `product → vendor:product` (§4 матчинга) нужны кандидатные
`vendor:product`. Два пути:

| Подход | Объём | Плюсы / минусы |
|--------|-------|----------------|
| **Полный CPE-словарь** (`cpes/2.0`, ~1.3M) | тяжёлый, ~130 стр. | есть человекочитаемые `titles` для фаззи-матча; но 90% продуктов без CVE нам не нужны |
| **Производный набор из `cve_cpe_match`** (рекоменд.) | лёгкий | ровно те `vendor:product`, у которых ВООБЩЕ есть CVE (только они и могут сматчиться); нет titles → фаззим по `product`-компоненте CPE |

**Рекомендация:** основной индекс продуктов строим из `DISTINCT vendor, product`
таблицы `cve_cpe_match` — это именно релевантное подмножество. Полный словарь с
`titles` подтягиваем **опционально/позже** только для улучшения фаззи-матча.
Экономит ~130 страниц загрузки и 1.3M строк на старте.

```sql
-- производный индекс продуктов (материализуем после каждого синка)
CREATE MATERIALIZED VIEW product_index AS
SELECT DISTINCT part, vendor, product FROM cve_cpe_match;
```

---

## 8. Идемпотентность и транзакции

- **Upsert CVE:** `INSERT ... ON CONFLICT (cve_id) DO UPDATE`. Повторная
  обработка страницы безвредна → резюмируемость безопасна.
- **`cve_cpe_match` пересобираем целиком на CVE:** в одной транзакции
  `DELETE WHERE cve_id=? ; INSERT ...`. Модифицированная CVE могла сменить
  конфигурации — старые строки не должны «залипнуть».
- **Гранулярность коммита — страница** (или батч CVE). Прогресс переживает сбой.

```
BEGIN
  upsert cve_records (все CVE страницы)
  for cve in page: replace cve_cpe_match(cve)
  update sync_state.bootstrap_index / last_run_at
COMMIT
```

---

## 9. Оркестрация

- **Celery-beat:**
  - `nvd_bootstrap` — разово при пустом `sync_state` (или ручной триггер);
  - `nvd_incremental` — по расписанию (раз в сутки дефолт).
- **Redis-lock** на `source='nvd_cve'`: два синка не пересекаются
  (bootstrap длинный — важно).
- Синк изолирован от пользовательских запросов: пользователь всегда матчится по
  уже накопленной базе, даже если синк в процессе.

---

## 10. Псевдокод

```python
def sync_nvd():
    st = load_sync_state("nvd_cve")
    if st.phase == "bootstrap" or st is None:
        run_bootstrap(st)
    else:
        run_incremental(st)

def run_bootstrap(st):
    idx = st.bootstrap_index or 0
    total = None
    while total is None or idx < total:
        page = fetch_cves(startIndex=idx, resultsPerPage=2000)  # retry+limiter
        total = page.totalResults
        with tx():
            upsert_page(page.vulnerabilities)      # cve_records + cve_cpe_match
            idx += page.resultsPerPage
            save_state(bootstrap_index=idx, status="running")
    finalize(phase="incremental", last_mod_cursor=now(), bootstrap_index=None)

def run_incremental(st):
    start = st.last_mod_cursor - timedelta(minutes=OVERLAP)   # защита от гонки
    end   = now()
    idx = 0; total = None
    while total is None or idx < total:
        page = fetch_cves(lastModStartDate=start, lastModEndDate=end,
                          startIndex=idx, resultsPerPage=2000)
        total = page.totalResults
        with tx():
            upsert_page(page.vulnerabilities)
            idx += page.resultsPerPage
    save_state(last_mod_cursor=end, status="idle", phase="incremental")  # курсор — в конце!
```

Даты — в UTC, форматируем с явным смещением (NVD требует ISO-8601 с offset).

---

## 11. Граничные случаи и операционка

- **Пустое инкрементальное окно** (`totalResults=0`) — норм, просто двигаем курсор.
- **CVE без `configurations`** (REJECTED/AWAITING, только описание) — сохраняем
  `cve_records`, `cve_cpe_match` пустой. Не падать.
- **CVE без CVSS** (не проанализирована) — `cvss_*` = NULL, severity `UNKNOWN`.
- **Отозванные CVE** (`vulnStatus: Rejected`) — сохраняем, помечаем; матчинг их
  исключает.
- **Смена схемы NVD** — сырой `raw jsonb` позволяет пересобрать без ре-фетча.
- **Дырка после сбоя** — исключена дисциплиной «курсор двигаем только по успеху
  окна» + overlap.
- **Диапазон >120 дней** (если база протухла надолго) — бьём инкремент на
  под-окна ≤120 дней.

---

## 12. Тесты

- **Парсинг фикстур** (записанные ответы NVD, `respx`/сохранённый JSON):
  - CVE с `versionEndExcluding` → одна строка `cve_cpe_match` с корректными
    границами;
  - CVE с AND-конфигурацией (`log4j` running-on) → `config_operator=AND`
    сохранён;
  - CVE без `configurations`/без CVSS → не падает, NULL-поля;
  - приоритет CVSS: есть и v2, и v3.1 → выбран v3.1.
- **Идемпотентность:** дважды применить ту же страницу → нет дублей, `cve_cpe_match`
  консистентен.
- **Резюмируемость:** прервать bootstrap на середине → повторный запуск
  продолжает с `bootstrap_index`, итог совпадает с непрерывным прогоном.
- **Курсор:** сбой внутри окна не двигает `last_mod_cursor`.
- Лимитер/ретрай: замоканные `503`→успех проверяют бэкофф.

---

## 13. Статус документа

- Описывает наполнение таблиц `cve_records`,
  `cve_cpe_match`); питает **§6 / [design-cpe-matching.md](design-cpe-matching.md)**.
- Реализация — **cve-service**, Этап 1 (недели 2–4): порядок работ —
  сначала синк (этот док), потом матчинг (предыдущий док).

**Комплект проектных документов на сейчас:**
2. [design-cpe-matching.md](design-cpe-matching.md) — ядро матчинга (§6).
3. [design-nvd-sync.md](design-nvd-sync.md) — наполнение базы (§4.2). ← этот.

Следующие кандидаты на детализацию (если понадобится): **recon-service**
(InternetDB + опц. источники, кэш, дедуп/провенанс) или **correlator-service**
(рекурсивные CTE графа + формат JSON для Cytoscape).
