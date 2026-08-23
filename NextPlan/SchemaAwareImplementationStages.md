# План імплементації schema-aware аналізатора

## 1. Мета

Розширити поточний AST-only аналізатор так, щоб він:

- використовував типи, nullability, PK, FK, UNIQUE та індекси;
- коректно зв’язував AST-вирази з таблицями й колонками;
- підтверджував, спростовував або не робив висновок за відсутності доказів;
- повертав evidence і незалежний risk vector;
- підтримував контрольоване порівняння C0–C3 для наступної статті;
- повністю зберігав поточну AST-only поведінку як baseline C0.

Це не має бути просто додаванням PK/FK до наявних евристик. Основний результат —
вимірювання того, коли schema context:

1. прибирає false positives;
2. знаходить нові ризики;
3. змінює тип ризику;
4. змушує аналізатор повернути `unknown`.

## 2. Основні архітектурні правила

### 2.1. Поточний аналізатор залишається baseline

Наявний `antipattern_detector.py` фіксується як `legacy-c0-v1`.
Schema-aware функціональність додається поруч, без переписування C0.

Виклик без schema context повинен працювати як зараз:

```python
detect_antipatterns(sql, dialect="sqlite")
```

### 2.2. Rule engine не працює з БД напряму

Rule engine отримує лише:

- SQL AST;
- immutable `SchemaContext`;
- результат lineage resolution;
- заздалегідь зібрані evidence.

Він не повинен:

- відкривати DB connection;
- виконувати gold SQL;
- запускати `EXPLAIN`;
- матеріалізувати DDL.

### 2.3. Чотири стани рішення

Кожна query–rule proposition має один із станів:

- `present` — достатні докази підтверджують ризик;
- `absent` — правило застосовне, але докази спростовують ризик;
- `unknown` — правило застосовне, але фактів недостатньо або вони суперечливі;
- `not_applicable` — у SQL немає конструкції, до якої застосовується правило.

Технічні помилки зберігаються окремо:

- `parse_failed`;
- `context_failed`;
- `resolver_failed`;
- `rule_failed`;
- `not_evaluated`.

Нові schema-only правила у C0 отримують `not_evaluated`, а не `absent`.

### 2.4. Risk vector

Ризик оцінюється незалежно за напрямами:

```json
{
  "correctness": "none|low|medium|high|unknown",
  "performance": "none|low|medium|high|unknown",
  "portability": "none|low|medium|high|unknown",
  "maintainability": "none|low|medium|high|unknown"
}
```

Єдиний Critical/High/Medium/Low severity залишається лише для backward compatibility.

### 2.5. Provenance і reliability не змішуються

Кожен schema fact має окремо:

- provenance: звідки отриманий факт;
- reliability: що саме дозволено з нього зробити висновок.

Приклад provenance:

- `benchmark_metadata`;
- `ddl`;
- `materialized_catalog`;
- `native_catalog`;
- `observed_rows`.

Приклад reliability:

- completeness: `complete|partial|unknown`;
- consistency: `not_checked|consistent|violated|not_checkable`;
- authority: `declared|observed|derived`.

Порожній список FK або індексів не означає автоматично, що їх немає. Це можна
стверджувати лише для джерела, повного для відповідної групи фактів.

## 3. Експериментальні умови

Початковий C1 потрібно розділити за джерелами:

- `C0` — frozen AST-only baseline;
- `C1M` — benchmark metadata;
- `C1D` — DDL declarations, за потреби через materialized empty DB;
- `C2` — native catalog shipped database;
- `C3` — C2 плюс consistency checks populated instance.

Для Gretel основними є C0 і C1D. Gretel не об’єднується зі Spider/BIRD у спільний
primary quality показник.

Додаткова lineage ablation:

- `base_only` — лише прості qualified base-table references;
- `full_lineage` — aliases, unqualified columns, CTE, derived tables і nested scopes.

## 4. Цільова структура модулів

```text
src/text2sql_antipattern/
  schema/
    models.py
    provenance.py
    reliability.py
    cache.py
    manifest.py
    providers/
      base.py
      benchmark.py
      ddl_sqlite.py
      native_sqlite.py
    validation/
      sqlite_consistency.py

  lineage/
    models.py
    resolver.py
    base_only.py

  analyzers/
    query_antipattern/          # frozen C0
    schema_aware/
      analyzer.py
      candidates.py
      decisions.py
      registry.py
      rules/
        not_in.py
        group_by.py
        ordering.py
        sargability.py
        joins.py
        distinct.py
        fanout.py
        scalar_subquery.py
    plan_evidence/
      analyzer.py
      sqlite.py

  experiments/
    conditions.py
    migrations.py
    sampling.py
    statistics.py
```

## 5. Що перевикористати з базового проєкту

Переносити вибірково:

- read-only SQLite catalog reflection;
- DDL materialization;
- schema identity як основу, але з новим canonical hash;
- ідею `DbManager`/adapter abstraction;
- schema-health перевірки, потрібні для C3.

Перед використанням потрібно виправити:

- schema hash має враховувати nullability, PK, FK, UNIQUE та indexes;
- reflection має коректно підтримувати composite constraints;
- cache має використовувати source checksum і extractor version, а не лише `db_id`;
- empty database не може бути evidence про фактичні дані.

Не переносити:

- LLM judge і prompt generation;
- вибірки реальних значень для prompt;
- PostgreSQL provisioning у першій версії;
- mutable dictionary-shaped schema як публічну модель;
- query execution усередині schema-aware rules.

## 6. Стадії імплементації

## Stage 0 — Initial specification і feasibility inventory

### Роботи

1. Зафіксувати primary unit: `query–rule proposition`.
2. Визначити stable key:
   - dataset/version;
   - item ID;
   - db ID;
   - query block ID;
   - AST location;
   - rule ID і version;
   - condition;
   - resolver mode.
3. Затвердити чотири decision states і reason codes.
4. Формально описати predicates дев’яти primary rule families.
5. Закріпити dataset snapshots, checksums і доступні SQLite databases.
6. Перевірити реальну доступність Spider/BIRD/Gretel assets.
7. Визначити development, pilot і holdout partitions.

### Результат

- `experiments/rule_specs/`;
- dataset manifests;
- початкова annotation guideline;
- документ із condition capabilities.

### Acceptance criteria

- кожний dataset item можна зв’язати з pinned source;
- для кожного condition чітко визначено доступні evidence;
- holdout не використовується під час розробки;
- немає невизначеного трактування `unknown` і `not_applicable`.

## Stage 1 — Freeze C0 baseline

### Роботи

1. Зафіксувати поточну версію `sqlglot`.
2. Не змінювати поведінку наявних 14 правил.
3. Створити golden outputs для наявних regression fixtures.
4. Зберігати:
   - code commit;
   - config hash;
   - parser version;
   - normalized output hash.
5. Позначити поточний detector як `legacy-c0-v1`.

### Результат

Відтворюваний AST-only baseline для порівняння.

### Acceptance criteria

- усі поточні тести проходять без змін;
- повторний запуск дає ідентичні нормалізовані C0 outputs;
- C0 не імпортує schema-aware providers;
- C0 фізично не може отримати catalog evidence.

## Stage 2 — Core decision та evidence models

### Роботи

Додати immutable моделі:

- `Provenance`;
- `Reliability`;
- `SchemaFact`;
- `SchemaContext`;
- `LineageBinding`;
- `RuleDecision`;
- `DecisionEvidence`;
- `RiskVector`;
- `EvaluationStatus`.

Кожне рішення повинно містити:

- rule і rule-spec version;
- query/AST location;
- decision state;
- reason code;
- evidence references;
- risk vector;
- condition;
- schema-context version;
- resolver version.

### Acceptance criteria

- deterministic JSON serialization;
- `present` і `absent` завжди мають evidence;
- `unknown` завжди має reason code;
- `not_applicable` не має risk score;
- empty collection не використовується як невідома відсутність факту;
- conflicted fact не породжує впевнений висновок без explicit policy.

## Stage 3 — Schema acquisition

### Роботи

1. Додати `SchemaContextProvider` protocol.
2. Реалізувати:
   - benchmark metadata provider;
   - native SQLite provider;
   - restricted DDL materializer;
   - DDL/materialized SQLite provider.
3. Відображати:
   - tables і columns;
   - raw і normalized types;
   - nullability;
   - primary keys;
   - composite keys;
   - unique constraints/indexes;
   - foreign keys;
   - ordinary та expression indexes, якщо підтримуються.
4. Додати immutable cache за:
   - condition;
   - source checksum;
   - schema hash;
   - extractor version.
5. Deduplicate Gretel DDL за canonical hash.

### Acceptance criteria

- native і еквівалентний materialized fixture дають однакові declared facts;
- порядок колонок composite keys зберігається;
- partial metadata позначається як partial;
- DDL failure має structured reason;
- немає silent fallback між providers;
- empty materialized DB не створює observed evidence;
- cache hit дає ідентичний context.

## Stage 4 — Scope і lineage resolver

### Роботи

Реалізувати:

- lexical scope для кожного `SELECT`;
- table aliases;
- qualified та unqualified columns;
- ambiguity detection;
- CTE output lineage;
- derived-table lineage;
- projection aliases;
- `USING`;
- nested і correlated scopes;
- composite-key propagation;
- outer-join null introduction;
- stable query-block та AST-location IDs.

Підтримати два режими:

- `base_only`;
- `full_lineage`.

### Acceptance criteria

- ambiguous column ніколи не прив’язується через guessing;
- unsupported expression повертає structured unresolved reason;
- fixtures покривають aliases, shadowing, CTE, derived tables і correlation;
- результат resolver є deterministic;
- не менше 95% exact lineage accuracy на preregistered challenge set.

## Stage 5 — Перший end-to-end vertical slice

Перший slice має перевірити всі основні можливості архітектури, а не кількість правил.

### Правила slice

1. `nullable_not_in`
   - демонструє suppression false positive;
   - nullable → `present`;
   - proven NOT NULL → `absent`;
   - incomplete metadata → `unknown`.

2. `functional_dependency_group_by`
   - демонструє використання PK/UNIQUE/composite key;
   - окремо оцінює correctness і portability.

3. `scalar_subquery_multiplicity`
   - демонструє нове finding, якого не було у C0;
   - unique predicate → `absent`;
   - multiple rows permitted → `present`;
   - incomplete uniqueness facts → `unknown`.

### Реалізація

Для кожного правила розділити:

1. candidate extraction з AST;
2. lineage resolution;
3. condition-specific decision;
4. evidence і risk mapping.

### Acceptance criteria

- для кожного правила є fixtures для всіх чотирьох decision states;
- зміна одного schema fact змінює лише очікуване рішення;
- syntax-only negative controls не змінюються між C0–C3;
- legacy C0 outputs залишаються незмінними;
- pipeline працює end-to-end: config → context → lineage → decision → DuckDB.

## Stage 6 — Решта refined rule families

### 6.1. Total-order-aware LIMIT/OFFSET

Визначати не лише наявність `ORDER BY`, а чи задає він повний порядок на результуючому
grain.

Приклад:

```sql
ORDER BY rating
LIMIT 10
```

Якщо `rating` не унікальний, результат може бути нестабільним.

### 6.2. Type/index-aware SARGability

Враховувати:

- тип колонки;
- implicit conversions;
- ordinary index;
- expression index;
- dialect coercion.

Не стверджувати, що функція завжди шкодить продуктивності.

### 6.3. Schema-grounded join diagnosis

Враховувати:

- column ownership;
- FK paths;
- composite keys;
- альтернативні declared relationships.

Відсутність FK не є доказом неправильного JOIN.

### 6.4. Key-aware redundant DISTINCT

Позначати `DISTINCT` як redundant лише тоді, коли projection і joins доведено
зберігають унікальний grain.

### Acceptance criteria

- кожне правило має versioned proposition;
- C0 і schema-aware умови порівнюють однакову proposition або явно позначені як різні;
- incomplete facts дають `unknown`;
- correctness/performance/portability не змішуються в один severity.

## Stage 7 — Нові schema-aware rule families

### 7.1. Fan-out і chasm

Виявляти агрегацію після one-to-many або many-to-many JOIN, яка може множити значення.

Schema facts доводять можливість multiplicity, але не завжди доводять фактичне
множення рядків у конкретному snapshot.

### 7.2. Join-key mismatch

Виявляти JOIN, який не використовує очікуваний key relationship або використовує
неповний composite key.

Результат за замовчуванням є candidate correctness risk, а не автоматично доведена
семантична помилка.

### 7.3. Potential multi-row scalar subquery

Визначати, чи scalar subquery гарантовано повертає не більше одного рядка.

### Acceptance criteria

- підтримуються composite keys;
- альтернативні declared relationships не ігноруються;
- нові правила не отримують штучного C0=`absent`;
- для sqlsure існує явне mapping спільних propositions.

## Stage 8 — C3 consistency validation

### Роботи

Для populated SQLite snapshots перевіряти:

- PK/UNIQUE duplicates;
- NOT NULL violations;
- FK integrity;
- суперечності між declarations і data.

При conflict:

1. declaration не перезаписується;
2. створюється окремий schema-conflict record;
3. consistency стає `violated`;
4. залежне rule decision переходить у `unknown`;
5. snapshot-only observation зберігається окремо.

### Acceptance criteria

- seeded violations знаходяться тестами;
- C2 facts залишаються immutable;
- conflict змінює лише залежні decisions;
- empty DB не дозволяється як C3 source;
- validation не виконує gold SQL.

## Stage 9 — Optional plan evidence

### Роботи

Додати окремий analyzer для SQLite `EXPLAIN QUERY PLAN`:

- лише allowlisted read-only statements;
- окреме зберігання plan evidence;
- відсутність DB imports у schema-aware rules;
- logical decision не залежить від увімкнення цього analyzer.

Основне застосування:

- SARGability;
- leading-wildcard LIKE;
- `SELECT *`;
- перевірка використання індексів.

### Acceptance criteria

- вимкнення plan analyzer не змінює logical decisions;
- declaration-only і plan-confirmed risks розрізняються;
- SQLite evidence не переноситься автоматично на PostgreSQL.

## Stage 10 — Storage, reporting і backward compatibility

### Нові нормалізовані таблиці DuckDB

- `run_manifests`;
- `schema_contexts`;
- `schema_facts`;
- `schema_conflicts`;
- `lineage_resolutions`;
- `rule_decisions`;
- `decision_evidence`;
- `plan_evidence`;
- `annotation_units`;
- `annotations`.

Не потрібно безкінечно розширювати поточну wide Boolean table.

### Backward compatibility

- старі configs запускають лише C0;
- старий `detect_antipatterns()` API зберігається;
- legacy Boolean metrics доступні як compatibility output/view;
- schema-aware режим вмикається explicit config;
- schema-aware failures не змінюють legacy result мовчки.

### Acceptance criteria

- різні conditions і resolver modes можуть зберігатися в одному artifact;
- JSONL і DuckDB representations узгоджені;
- migration matrices будуються без parsing JSON blobs;
- повторний run не створює непомітні дублікати;
- precision завжди показується разом із coverage та abstention.

## Stage 11 — Development pilot

### Дані

- synthetic causal fixtures;
- Spider Train;
- окремий невеликий pilot set, який не входить у final holdout.

### Перевірки

- nullability change;
- unique ↔ non-unique;
- FK present ↔ absent;
- one-to-one ↔ one-to-many;
- type compatible ↔ incompatible;
- no index ↔ ordinary/expression index;
- complete ↔ partial metadata;
- base-only ↔ full-lineage.

### Go/no-go criteria

- 100% очікуваних transitions на matched fixtures;
- нуль migrations у syntax-only negative controls;
- context coverage не менше 95% на eligible Spider Train items;
- full-lineage resolution не менше 90% applicable references;
- достатня кількість decision migrations для primary rules;
- annotation pilot має κ або Krippendorff’s α не менше 0.67;
- sampling weights та denominators можна повністю відтворити.

Після pilot дозволяється уточнити rule specifications. Після цього робиться final freeze.

## Stage 12 — Final freeze і full study

### Freeze

Зафіксувати:

- code commit;
- rule specifications;
- condition definitions;
- resolver versions;
- risk rubric;
- manifests і checksums;
- annotation guideline;
- sampling plan;
- statistical scripts.

Після freeze зміна decision logic вимагає нової version і повного rerun.

### Full runs

- Spider: доступні C0, C1M, C1D, C2, C3;
- BIRD: frozen historical snapshot для sqlsure comparison і окремий corrected snapshot;
- Gretel: C0 і C1D;
- base-only/full-lineage ablation;
- cold-cache і warm-cache performance runs.

### Baselines

- frozen UJIT C0;
- sqlsure на matched propositions;
- C++ SqlCheck лише для overlapping syntax rules;
- DBMS prepare/resolution;
- execution evidence окремо, якщо доступне.

Не обчислювати глобальний F1 між несумісними taxonomies.

### Human evaluation

Основна одиниця annotation — query–rule proposition.

Два незалежні reviewers:

- не бачать назву detector;
- не бачать condition;
- не бачать generated decision;
- отримують SQL, AST location, schema evidence і lineage;
- після незалежної розмітки проходять adjudication.

### Statistics

Публікувати:

- applicability coverage;
- decision coverage;
- abstention rate;
- selective precision;
- selective accuracy;
- weighted recall/F1 лише за коректного probability sampling;
- migrations між conditions;
- clustered bootstrap by `db_id`;
- inter-annotator agreement.

## Stage 13 — Reproducibility artifact і стаття

Artifact повинен містити:

- frozen source code та environment;
- dataset manifests/checksums;
- schema-source completeness declarations;
- serialized contexts;
- rule specifications;
- matched fixtures;
- outputs усіх conditions;
- baseline wrappers;
- raw reviewer labels;
- adjudication log;
- inclusion probabilities;
- statistical scripts;
- generated tables і figures;
- deviations та limitations.

### Final Definition of Done

Робота готова до публікації, якщо:

1. clean rebuild відтворює aggregate tables;
2. усі denominators узгоджуються з manifests;
3. немає silent schema fallback;
4. C0 не отримує catalog evidence;
5. `unknown`, `not_applicable` і failures рахуються окремо;
6. C1M і C1D не змішані у primary analysis;
7. precision не подається без coverage;
8. Gretel не об’єднаний із human gold SQL у спільний quality claim;
9. старі AST-only regression tests проходять;
10. негативні або статистично незначущі результати також збережені.

## 7. Рекомендований порядок PR

1. **PR 1:** Stage 0–1 — manifests, specification і frozen C0.
2. **PR 2:** Stage 2 — decision/evidence models.
3. **PR 3:** Stage 3 — SQLite/DDL schema acquisition.
4. **PR 4:** Stage 4 — lineage resolver.
5. **PR 5:** Stage 5 — перший vertical slice.
6. **PR 6:** Stage 6 — решта refined rules.
7. **PR 7:** Stage 7–9 — new rules, C3, optional plan evidence.
8. **PR 8:** Stage 10 — normalized storage/reporting.
9. **PR 9:** Stage 11 — pilot і final freeze.
10. **PR 10:** Stage 12–13 — full study та reproducibility artifact.

Найближча практична точка старту: Stage 0 і Stage 1. До імплементації catalog та
rules необхідно спочатку зафіксувати baseline, dataset manifests і точну семантику
рішень.
