# Дизайн: матчинг «сервис → CVE»

Техническое ядро проекта. Задача: по наблюдённому сервису (`product`, `version`,
иногда готовый `cpe`) выдать список **потенциально** применимых CVE с оценкой
достоверности `match_confidence`. Здесь — как именно.

> Ключевое ограничение: результат — **«potentially vulnerable»**, не подтверждение.
> Версия с известной CVE ≠ уязвимый хост (бэкпорт-патчи). Это оценка вероятности.

---

## 0. Почему это сложно (чтобы решения ниже были понятны)

1. **`product` — свободный текст.** Shodan/InternetDB отдают `"Apache httpd"`,
   `"nginx"`, `"OpenSSH"`. В NVD же ключ — canonical CPE `vendor:product`, и он
   неинтуитивен: `nginx → f5:nginx` (вендор f5!), `OpenSSH → openbsd:openssh`,
   `MySQL → oracle:mysql`. Строкой это не вывести — нужен словарь + фаззи-матч.
2. **Версии — не semver.** `2.4.41 (Ubuntu)`, `1.0.2k-fips`, эпохи, буквенные
   суффиксы. `tuple(map(int, ...))` ломается. Нужна библиотека сравнения версий.
3. **Применимость CVE — это диапазоны, а не значения.** У CVE есть
   `versionStartIncluding/Excluding` и `versionEndIncluding/Excluding` +
   AND/OR-логика конфигураций. Наивный «версия == версия» промахнётся мимо
   большинства реальных CVE.

---

## 1. Входы и выходы

**Вход** — строка таблицы `services`:
```
product   : "Apache httpd"        (свободный текст, может быть NULL)
version   : "2.4.41 (Ubuntu)"     (свободный текст, может быть NULL)
cpe_uri   : "cpe:2.3:a:apache:http_server:2.4.41:*:..."  (от InternetDB, если есть)
source    : internetdb | shodan | censys
```

**Выход** — строки `service_cve`:
```
service_id, cve_id, match_confidence (high|medium|low), matched_cpe, matched_at
```

**Локальные справочные данные:**
- `cve_cpe_match` — распакованные `cpeMatch` из NVD: `cpe_uri`, `vulnerable_bool`,
  `version_start`, `version_start_type` (`including|excluding`), `version_end`,
  `version_end_type`, + к какому `cve_id` и к какому узлу (`node_operator`) относится.
- `cpe_dictionary` — официальный CPE-словарь NVD (`vendor`, `product`, `title`).
- `alias_map` — **ручная** таблица высокочастотных синонимов (см. §3).

---

## 2. Структура данных NVD, которую распаковываем при синке

Каждая CVE (API 2.0) содержит `configurations[]`, внутри `nodes[]`, внутри
`cpeMatch[]`. Разворачиваем это в плоские строки `cve_cpe_match` на этапе синка:

```jsonc
"configurations": [{
  "nodes": [{
    "operator": "OR",            // OR | AND
    "negate": false,
    "cpeMatch": [{
      "vulnerable": true,
      "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
      "versionStartIncluding": "2.4.0",
      "versionEndExcluding":  "2.4.52",
      "matchCriteriaId": "…"
    }]
  }]
}]
```

Каждый `cpeMatch` с `vulnerable:true` → строка в `cve_cpe_match`. Поле
`operator` узла сохраняем — понадобится для AND-конфигураций (§7).

**Формат CPE 2.3** (11 полей после `cpe:2.3:`):
```
cpe:2.3: part : vendor : product : version : update : edition : language
       : sw_edition : target_sw : target_hw : other
part = a (app) | o (OS) | h (hardware);   * = ANY,   - = N/A
```

---

## 3. Пайплайн (обзор)

```
service (product, version, cpe_uri?)
      │
      ▼  (A) есть cpe_uri от InternetDB? ── да ──► взять как есть ──┐
      │  нет                                                        │
      ▼                                                             │
 (B) product → {vendor:product}  [alias → cpe_dict → fuzzy]         │
      │  (может дать 0..N кандидатов; nginx → 2 вендора)            │
      ▼                                                             │
 (C) version → нормализованная версия (univers GenericVersion)      │
      │                                                             ▼
      └──────────────►  (D) выборка кандидатов из cve_cpe_match ◄───┘
                              по vendor:product + part, vulnerable=true
                                     │
                                     ▼
                        (E) тест «версия ∈ диапазон?» по границам
                                     │
                                     ▼
                        (F) AND-узлы: непроверенная ветка → штраф
                                     │
                                     ▼
                        (G) confidence → high | medium | low | REJECT
                                     │
                                     ▼
                        dedupe: лучший confidence на (service, cve)
```

---

## 4. Стадия B: `product` → `vendor:product` (фаззи-часть)

Порядок попыток, от точного к рискованному; **как только сработало — стоп**:

1. **alias_map (ручная, приоритетная).** Небольшой YAML высокочастотных
   продуктов, выверенный по реальным CPE из NVD. Именно он закрывает 80%
   попаданий и убирает самые злые ловушки:
   ```yaml
   "apache httpd":  [apache:http_server]
   "apache":        [apache:http_server]
   "nginx":         [f5:nginx, nginx:nginx]      # старые CVE — nginx:nginx, новые — f5:nginx
   "openssh":       [openbsd:openssh]
   "openssl":       [openssl:openssl]
   "mysql":         [oracle:mysql]
   "mariadb":       [mariadb:mariadb]
   "postgresql":    [postgresql:postgresql]
   "exim":          [exim:exim]
   "microsoft-iis": [microsoft:internet_information_services]
   ```
   Значение — **список** (одно `product` → несколько canonical, как nginx).
2. **cpe_dictionary, точное совпадение** нормализованного имени
   (`lower`, убрать `httpd/server/daemon`, схлопнуть пробелы/дефисы) с
   `product`/`title` из словаря.
3. **cpe_dictionary, фаззи** (токены + Jaccard/Levenshtein) с **порогом**.
   Ниже порога — **не матчим** (пустой результат лучше ложного).

Метод, которым получили CPE (`alias|dict_exact|dict_fuzzy|from_internetdb`),
сохраняем — он входит в формулу confidence (§8).

Если `cpe_uri` уже пришёл от InternetDB — стадию B пропускаем, но всё равно
можем нормализовать `vendor:product` через словарь для консистентности.

---

## 5. Стадия C: версия — извлечение и сравнение

**Извлечение.** `version` замусорен: `"2.4.41 (Ubuntu)"`, `"1.0.2k-fips"`,
`"OpenSSH_8.2p1"`. Достаём ядро версии регуляркой, **сохраняя** значимый
суффикс (`p1`, `k`), отбрасывая дистро-скобки (`(Ubuntu)`, `+deb10u1`).

**Сравнение — библиотекой, не руками.** Берём `univers.versions.GenericVersion`
(из nexB `univers`, создана ровно под vuln-диапазоны). `packaging.version` (PEP
440) не годится — падает `InvalidVersion` на многих не-Python версиях.

```python
from univers.versions import GenericVersion
GenericVersion("1.0.2k") < GenericVersion("1.0.2l")   # True
GenericVersion("2.4.41") < GenericVersion("2.4.52")   # True
```

Если версию распарсить не удалось → `version = None` (влияет на confidence, §8).

---

## 6. Стадия D: выборка кандидатов CVE

```sql
SELECT * FROM cve_cpe_match
WHERE part = :part            -- 'a' обычно
  AND vendor = :vendor
  AND product = :product
  AND vulnerable_bool = true;
```
(`vendor`/`product` можно хранить отдельными колонками в `cve_cpe_match` рядом с
`cpe_uri` — денормализация ради скорости; индекс по `(vendor, product)`.)

Для nginx (два кандидата) — объединяем результаты обоих `vendor:product`.

---

## 7. Стадия E: тест «версия ∈ диапазон»

У каждой строки-кандидата два варианта:

**(1) Точная версия в самом CPE** (`criteria.version != *` и границ нет):
```
match ⇔ ver_eq(observed_version, criteria.version)
```
Если `observed_version is None` → сравнить нечем → пропускаем (`None`).

**(2) Версия-wildcard + границы** (`criteria.version == *`, есть
`version_start`/`version_end`): проверяем попадание в интервал по типам границ:

| Поле | Условие |
|------|---------|
| `versionStartIncluding = X` | `observed >= X` |
| `versionStartExcluding = X` | `observed > X` |
| `versionEndIncluding = Y`   | `observed <= Y` |
| `versionEndExcluding = Y`   | `observed < Y` |

Отсутствующая граница — не ограничивает с этой стороны. Если `version == *` и
границ вообще нет → уязвимы **все** версии продукта (редко; матчим, но confidence
занижаем и помечаем «all versions»).

Если `observed_version is None` при вариантах с диапазоном → матч по одному
только продукту: это шумно, по умолчанию **REJECT** (или собираем в свёрнутый
блок «product-level, версия неизвестна» — см. §11).

```python
def version_applies(observed, row) -> bool | None:
    crit = parse_cpe(row.cpe_uri)
    if crit.version not in ("*", "-") and not row.has_range():
        if observed is None:
            return None
        return ver_eq(observed, crit.version)          # вариант (1)
    if observed is None:
        return None                                    # только продукт → выше REJECT
    return in_range(observed,                          # вариант (2)
                    row.version_start, row.version_start_type,
                    row.version_end,   row.version_end_type)
```

---

## 8. Стадия F: AND-узлы (конфигурации «running on»)

Узел с `operator: AND` означает «уязвимо, только если одновременно присутствуют
CPE-1 И CPE-2» (типично: приложение НА конкретной ОС). Мы обычно знаем только
одну сторону (сам сервис), про ОS-ветку данных нет.

Решение v1 (консервативно, но без потери находок):
- матчим по известной ветке,
- **непроверенная AND-ветка → штраф к confidence** и пометка в отчёте
  «conditional on `<другой CPE>`».
- `negate: true`-узлы редки → в v1 игнорируем (не матчим по ним).

---

## 9. Стадия G: формула `match_confidence`

Считаем очки, затем в корзину. Прозрачно и легко тюнится по тестам.

| Фактор | Значение | Очки |
|--------|----------|------|
| Маппинг продукта | `from_internetdb` или `alias` или `dict_exact` | +2 |
|                  | `dict_fuzzy` (выше порога) | +1 |
| Версия | распознана точно | +2 |
|        | распознана, но неоднозначна (напр. только `2.4`) | +1 |
|        | отсутствует | 0 |
| Тип совпадения | точное равенство версии (вариант 1) | +2 |
|                | попадание в ограниченный диапазон (есть ≥1 граница) | +1 |
|                | `*` без границ («all versions») | 0 |
| Узел | одиночный OR, `vulnerable:true` | +1 |
|      | AND с непроверенной веткой | −1 |

**Корзины:**
```
high    : score >= 5
medium  : 3 <= score <= 4
low     : 1 <= score <= 2
REJECT  : score <= 0   ИЛИ продукт не сматчен   ИЛИ версия отсутствует при диапазоне
```

`high` по смыслу = «продукт уверенно опознан + версия точная + попадает в
границы». `low` = «фаззи-продукт / широкий диапазон / условие AND не проверено».

---

## 10. Сводный псевдокод

```python
def match_service_to_cves(service) -> list[Match]:
    # (A/B) кандидатные CPE
    if service.cpe_uri:
        cpes, method = [parse_cpe(service.cpe_uri)], "from_internetdb"
    else:
        cpes, method = map_product_to_cpe(service.product)   # alias→dict→fuzzy
    if not cpes:
        return []

    version = normalize_version(service.version)   # GenericVersion | None

    out = {}
    for cpe in cpes:
        for row in query_candidates(cpe):          # стадия D
            applies = version_applies(version, row)  # стадия E
            if not applies:                          # None или False
                continue
            score = confidence_score(method, version, row)  # стадии F+G
            conf  = to_bucket(score)
            if conf == "REJECT":
                continue
            # dedupe: держим лучший confidence на (service, cve)
            best = out.get(row.cve_id)
            if best is None or rank(conf) > rank(best.confidence):
                out[row.cve_id] = Match(service.id, row.cve_id, conf, row.cpe_uri)
    return list(out.values())
```

---

## 11. Граничные случаи (зафиксировать в тестах)

- **Дистро-суффиксы:** `2.4.41 (Ubuntu)`, `1.4.6+deb10u1` → отбросить окружение,
  сохранить ядро версии.
- **Буквенные версии OpenSSL:** `1.0.2k` — обязателен `univers`, не int-tuple.
- **Старые CVE перечисляют версии поштучно**, а не диапазоном (`1.0.1`, `1.0.1a`,
  … как отдельные `cpeMatch` с точной версией) — вариант (1) стадии E это ловит.
- **Только продукт без версии** → не заливать пользователя всеми CVE продукта:
  по умолчанию REJECT; опционально — свёрнутый блок «версия неизвестна, N CVE у
  продукта» с явной пометкой.
- **Несколько вендоров (nginx)** → объединяем, но фаззи/множественность держим
  в уме при confidence.
- **CVSS-версия:** при выгрузке в отчёт берём приоритет v3.1 → v3.0 → v2, храним
  `cvss_version`+вектор (уже в схеме §5).
- **`negate:true` / deprecated CPE** → v1 пропускает.

---

## 12. Тестовая стратегия и золотые примеры

Юнит-тесты матчинга — на фиксированных парах, сеть не трогаем. Плюс
**кросс-чек**: свой вывод сверяем со списком `vulns` из InternetDB.

**Золотые кейсы ( handcrafted, проверяемые по NVD):**

| Продукт+версия | Ожидаем | Что проверяет |
|----------------|---------|---------------|
| `OpenSSL 1.0.1` | `CVE-2014-0160` (Heartbleed) | диапазон `>=1.0.1, <=1.0.1f`, буквенные версии |
| `OpenSSL 1.0.1g` | **НЕ** Heartbleed | верхняя граница `excluding`, отсечение |
| `Apache httpd 2.4.41` | набор CVE с `versionEndExcluding 2.4.52` | `alias apache→apache:http_server`, диапазон |
| `nginx 1.20.0` | CVE и по `f5:nginx`, и по `nginx:nginx` | мульти-вендор |
| `OpenSSH_8.2p1` | CVE OpenSSH | `openbsd:openssh`, суффикс `p1`, парсинг баннера |

Heartbleed как эталон границ:
```
observed = 1.0.1     → in_range(>=1.0.1 incl, <=1.0.1f incl) = True  ✓ high
observed = 1.0.1f    → True   ✓
observed = 1.0.1g    → False  ✓ (не матчим — патч)
```

Также тесты на:
- каждый тип границы (`Including`/`Excluding`, start/end);
- AND-узел → понижение confidence;
- отсутствующую версию → REJECT;
- фаззи-маппинг ниже порога → пустой результат (нет ложняка).

---

## 13. Что осознанно упрощаем в v1

- AND-конфигурации не подтверждаем полностью (нет данных об ОС) — только штраф +
  пометка. Не завышаем уверенность.
- `negate`, deprecated CPE, экзотические `update/edition`-поля — вне v1.
- Фаззи-маппинг продукта — консервативный порог: лучше пропустить, чем дать
  ложную CVE. Точность важнее полноты (проект про доверие к выводу).
- Единица confidence — эвристика на очках, а не вероятностная модель. Достаточно
  для «potential» и легко калибруется по золотым кейсам.

---

## Следующий шаг

Этот документ детализирует **§6** и опирается на схему **§5** (`cve_cpe_match`,
`cpe_dictionary`) и стратегию синка **§4.2**. Реализуется в **cve-service**,
Этап 1 роадмапа (недели 2–4).

Следующий разумный артефакт — спецификация **NVD-синка** (полная + инкрементальная
загрузка, резюмируемость, распаковка `configurations` в `cve_cpe_match`), т.к.
без наполненной базы матчить нечего.
