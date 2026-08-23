# AGENTS.md — памятка для ИИ-агентов, работающих с этим репозиторием

## Что это за проект

**pcap-analyzer** — анализатор сетевых дампов (pcap/pcapng) с веб-интерфейсом
и CLI. Разбор пакетов делегируется **tshark**, вся логика и отчётность — на
**Python 3.14**. Результат — отчёт на русском языке в двух форматах:

* **HTML** — один автономный файл (инлайновые CSS и SVG, без CDN и внешних
  скриптов);
* **PDF** — тот же контент через WeasyPrint и печатную таблицу стилей.

Единственная внешняя python-зависимость — **weasyprint**
(`requirements.txt`); системные библиотеки Pango/GDK-Pixbuf и шрифты с
кириллицей ставятся apt-пакетами (см. `Dockerfile`).

Ветки анализа (протоколы): `modbus` (Modbus/TCP, порт 502) и `s7comm`
(Siemens S7 Communication, порт 102), реестр — `BRANCHES` в
`analyzer/branches/__init__.py`.

## Ключевые соглашения

* Весь пользовательский вывод, комментарии и документация — **на русском языке**.
* Никаких новых python-зависимостей без веской причины: кроме weasyprint,
  проект должен работать на стандартной библиотеке. Лениво импортировать
  weasyprint там, где PDF не обязателен (`cli.py`, ветка экспорта веб-GUI).
* HTML-отчёт всегда остаётся одним файлом: стили в `<style>`, графики —
  инлайновый SVG (`analyzer/report/components.py`). Не подключать внешние ресурсы.
  PDF строится из этого же HTML (`render_document`) — единый источник контента;
  печатная специфика только через `_PRINT_CSS` в `analyzer/report/pdf_report.py`.
* Любые эмпирические пороги правил рекомендаций выносятся в
  `analyzer/config.py` (класс `Config`), не хардкодятся в логике.
* Данные из tshark читаем потоково (`tshark_runner.stream_fields`) — файлы
  бывают по сотням тысяч пакетов, всё в память грузить нельзя. То же касается
  загрузки pcap в веб-GUI: multipart разбирается потоком с учётом
  Content-Length (`webapp/server.parse_multipart_file`, чтение `read1`).
* Идентификаторы файлов в веб-GUI валидируются регуляркой `^[A-Za-z0-9_-]+$`
  перед любым построением путей.

## Структура

```
analyzer/
├── cli.py                # argparse: analyze | serve | branches
├── config.py             # пороги правил рекомендаций
├── tshark_runner.py      # запуск tshark -T fields, стриминг строк-словарей
├── report/
│   ├── components.py     # esc/fmt_*, kpi_cards, table_html, cmd_block,
│   │                     # timeline_svg/vbar_svg/hbar_svg/coverage_svg
│   ├── html_report.py    # render_document(BranchResult) -> один HTML-файл
│   └── pdf_report.py     # render_pdf_bytes/render_pdf_file: HTML -> PDF
├── webapp/
│   ├── server.py         # http.server: загрузка, очередь анализа, /view, /export
│   └── page.py           # одностраничный интерфейс (всё инлайном)
└── branches/
    ├── base.py           # BaseBranch, BranchResult, Section, Recommendation, KpiItem
    ├── __init__.py       # BRANCHES = {"modbus": ModbusTcpAnalyzer}, get_branch()
    └── modbus_tcp.py     # два прохода по pcap + правила рекомендаций
```

## Как проверять изменения

Тестового фреймворка нет; минимальная регрессия — прогон на образцах:

```bash
# локально (нужен tshark в PATH; для PDF — weasyprint из requirements.txt);
# <образец>.pcap — любой pcap из pcap-sample/
python3 -m analyzer branches
python3 -m analyzer analyze pcap-sample/<образец>.pcap -o /tmp/report -f both

# веб-GUI: загрузить образец через POST /api/upload, дождаться done,
# проверить /view/<id> и /export/<id>?fmt=pdf
python3 -m analyzer serve --port 8125 --data-dir /tmp/webdata --samples-dir pcap-sample
```

Критерии корректности (сверяются с tshark напрямую):

* `Modbus-запросов` ≈ `tshark -r <файл> -Y "mbtcp && tcp.dstport==502" | wc -l`;
* пары клиент→сервер не содержат «перевёрнутых» направлений;
* HTML валиден: нет незакрытых тегов (проверить любым парсером);
* отчёты открываются офлайн; HTML содержит блоки команд tshark;
* PDF: кириллица извлекается (например, pypdf), футер «страница N из M»,
  таблицы/графики на месте.

Контрольные значения привязаны к двум образцам из `pcap-sample/`
(большой и малый; при замене образцов значения пересчитать по tshark):

* большой: ~291 тыс. пакетов, 69 896 запросов, 5 серверов, 1 клиент,
  медиана RTT ~20 мс; единственный SYN к порту 502, остальные соединения
  установлены до начала захвата — правило переподключений НЕ срабатывает
  (порог `conn_churn_pair_min` в `Config`); 15 рекомендаций;
* малый: 13 111 запросов, медиана RTT ~1.9 мс, 49 SYN (одна пара),
  53 потока закрыл клиент; рекомендаций 6 (5 warning, включая
  «Частые переподключения», 1 info), критичных нет.

## Docker

```bash
docker compose up --build          # веб-интерфейс на :8000 (сервис web)
PCAP_FILE=… REPORT_FILE=… FORMAT=both docker compose run --rm analyzer analyze \
    /data/$PCAP_FILE -o /output/$REPORT_FILE -f $FORMAT
```

Образ: `python:3.14-slim` + `tshark`, `libpango-*`, `libgdk-pixbuf`,
`fonts-dejavu-core` из apt + pip-зависимости из `requirements.txt`.
ENTRYPOINT — `python -m analyzer`; сервис `web` по умолчанию запускает
подкоманду `serve` (том `webdata`, образцы из `./pcap-sample` read-only).
Batch-анализ — профиль `batch` (`docker compose run --rm analyzer …`),
аргументы CLI передаются в `command:`/`docker run`.

## Типовые задачи агента

### Добавить новую ветку анализа (например, s7comm)

1. Создать `analyzer/branches/s7comm.py`, класс наследует `BaseBranch`
   (`name = "s7comm"`, метод `analyze(pcap_path, cfg, progress, tshark_bin)`).
2. Вернуть `BranchResult`: заполнить `kpi`, список `Section`
   (id, заголовок, готовый HTML, команды tshark для проверки) и
   `Recommendation` (severity: critical/warning/info).
3. Зарегистрировать класс в `BRANCHES`. CLI и веб-GUI подхватят ветку
   автоматически (в интерфейсе появится в выпадающем списке `/api/branches`).
4. Прогнать на образце, убедиться что отчёты HTML и PDF собираются и секции
   на месте.

### Изменить пороги рекомендаций

Только через `Config` в `analyzer/config.py`; после изменения — перезапустить
анализ обоих образцов и проверить, что рекомендации ожидаемо появляются/исчезают.

### Изменить оформление PDF

Правки только в `_PRINT_CSS` (`analyzer/report/pdf_report.py`): @page, поля,
нумерация, запрет разрывов (`.rec`, `.cmd-row`, `tr { page-break-inside }`).
Контент трогать нельзя — он общий с HTML.

### Починить сопоставление запросов и ответов

Логика — `_pass_modbus` в `branches/modbus_tcp.py`. Приоритет определения
направления: порт 502 → наличие `modbus.request_frame`. Сопоставление — по
номеру кадра запроса, резерв — FIFO по ключу `(stream, trans_id, unit_id)`.

## Чего не делать

* Не добавлять внешние python-пакеты сверх weasyprint без веской причины.
* Не переводить комментарии/вывод на английский.
* Не коммитить pcap-файлы, содержимое `output/` и `webdata/`.
* Не ломать потоковую обработку: никаких «прочитать весь tshark-вывод или
  загружаемый файл в список/память».
* Не отделять PDF от HTML: у отчётов один источник контента —
  `render_document(BranchResult)`.
