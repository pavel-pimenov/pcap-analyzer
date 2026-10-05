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

Ветки анализа (протоколы): `modbus` (Modbus/TCP, порт 502), `s7comm`
(Siemens S7 Communication, порт 102), **sinec-h1** (SINEC H1 / S5
fetch-write, порт 2000), **coilers** (телеграммы прокатного стана, по
конфигурации `Coilers.xml`), **services** (TCP/UDP-сервисы без дизассемблера),
реестр — `BRANCHES` в `analyzer/branches/__init__.py`.

## Ключевые соглашения

* Весь пользовательский вывод, комментарии и документация — **на русском языке**.
* Никаких новых python-зависимостей без веской причины: кроме weasyprint,
  проект должен работать на стандартной библиотеке. Лениво импортировать
  weasyprint там, где PDF не обязателен (`cli.py`, ветка экспорта веб-GUI).
* HTML-отчёт всегда остаётся одним файлом: стили в `<style>`, графики —
  инлайновый SVG (`analyzer/report/components.py`). Не подключать внешние ресурсы.
  PDF строится из этого же HTML (`render_document`) — единый источник контента;
  печатная специфика только через `_PRINT_CSS` в `analyzer/report/pdf_report.py`.
* В любом блоке отчёта, где показан исполняемый код (команды tshark и т.п.),
  всегда добавлять иконку «копировать в буфер обмена» — `COPY_BTN` из
  `analyzer/report/components.py` внутри обёртки `<div class="cmd-line">`;
  обработчик — инлайновый `_CLIPBOARD_JS` в `html_report.py`, на печать
  кнопка скрывается в `_PRINT_CSS`.
* Числовые метрики для трендов ветка складывает в `BranchResult.metrics`
  (ключи — латиницей; человекочитаемые названия — в
  `report/trend_report.py::METRIC_TITLES`). Трендам не нужен Гант:
  `Config.skip_gantt` (build_trend включает сам).
* Время в отчётах — через `base.epoch_to_str` (зона: `--tz` /
  `Config.display_tz_offset`, `base.set_display_tz` до запуска анализа).
* Выборки значений (RTT, интервалы) — только через `Reservoir`
  (лимиты из Config), никаких «всех значений в список».
* Цвета серверов (PLC) едины на весь документ: ветки вызывают
  `BaseBranch._set_servers(...)` (после прохода, где известны пары), ячейки
  с IP сервера — только через `BaseBranch._srv_cell(ip)`. Карта цветов
  попадает в `BranchResult.server_colors` и рисуется легендой в шапке
  отчёта; новые таблицы с колонкой сервера обязаны использовать `_srv_cell`.
* Любые эмпирические пороги правил рекомендаций выносятся в
  `analyzer/config.py` (класс `Config`), не хардкодятся в логике.
* Данные из tshark читаем потоково (`tshark_runner.stream_fields`) — файлы
  бывают по сотням тысяч пакетов, всё в память грузить нельзя. То же касается
  загрузки pcap в веб-GUI: multipart разбирается потоком с учётом
  Content-Length (`webapp/server.parse_multipart_uploads` — несколько файлов
  за один запрос, чтение `read1`; `parse_multipart_file` — обёртка первого
  файла для тестов). Архивы (zip/tar[.gz]/.gz) распаковываются по одному
  члену в `_extract_archive` (защита от zip-slip, лимиты `ARCHIVE_MAX_*`);
  файлы одного запроса связаны пакетом `batch` (сводка — `GET /api/batches`),
  `?as_series=1` собирает из загруженных серию, пересчёт группы из истории —
  `POST /api/groups/<id>/rerun`.
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
│   │                     # timeline_svg/vbar_svg/hbar_svg/coverage_svg,
│   │                     # gantt_svg; WARM_TINTS/WARM_STRONG — цвета PLC
│   ├── html_report.py    # render_document(BranchResult) -> один HTML-файл
│   ├── pdf_report.py     # HTML -> PDF (_PRINT_CSS)
│   ├── trend_report.py   # render_trend_html: серия -> графики + матрица правил
│   └── diff_report.py    # render_diff_html: «до/после» (ΔKPI, статусы правил)
├── trend.py              # серии дампов → точки тренда (build_trend, --jobs N)
├── webapp/
│   ├── server.py         # http.server: файлы/группы(серии,дифф), /view, /export,
│   │                     # /api/series, /api/diff, токен (--token), HTTP/1.1
│   └── page.py           # одностраничный интерфейс (всё инлайном)
└── branches/
    ├── base.py           # BaseBranch, BranchResult, Section, Recommendation, KpiItem,
    │                     # Reservoir, общие утилиты (to_int/percentile/…), Гант-хелперы
    ├── __init__.py       # BRANCHES: modbus / s7comm / sinec-h1 /
    │                     #   coilers / services
    ├── modbus_tcp.py     # два прохода по pcap + правила рекомендаций
    ├── s7comm.py         # ветка S7comm (Siemens, порт 102)
    ├── sinec_h1.py       # ветка SINEC H1 (S5 fetch/write, порт 2000)
    ├── coilers.py        # ветка телеграмм прокатного стана (Coilers.xml)
    └── services.py       # ветка TCP/UDP-сервисов без дизассемблера
```

## Как проверять изменения

Полноценного фреймворка нет. Минимальная проверка — smoke-тесты
(`tests/test_smoke.py`, unittest, только stdlib), затем прогон на образцах:

```bash
# smoke-тесты (unittest, только stdlib; tshark/weasyprint опциональны —
# без них соответствующие тесты пропускаются)
python3 -m unittest discover -s tests -t . -v
```

```bash
# локально (нужен tshark в PATH; для PDF — weasyprint из requirements.txt);
# <образец>.pcap — любой pcap из pcap-sample/
python3 -m analyzer branches
python3 -m analyzer analyze pcap-sample/<образец>.pcap -o /tmp/report -f both

# веб-GUI: загрузить образец через POST /api/upload, дождаться done,
# проверить /view/<id> и /export/<id>?fmt=pdf
python3 -m analyzer serve --port 8125 --data-dir /tmp/webdata --samples-dir pcap-sample

# тренды и сравнение серий (параллельно):
python3 -m analyzer trend "pcap-sample/plc_cgn_*.pcap" -b s7comm --jobs 4 -o /tmp/trend.html
python3 -m analyzer diff "dump/before_*.pcap" "dump/after_*.pcap" -b modbus -o /tmp/diff.html

# сравнение карт опроса двух станций:
python3 -m analyzer overlap dump/a.pcap dump/b.pcap -o /tmp/overlap.html

# конфигурация порогов и зона времени:
python3 -m analyzer analyze <pcap> --config thresholds.toml --tz 3 -o /tmp/r.html
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

Для `sinec-h1` контрольные значения — два образца из
`pcap-sample/siemns-fetch-write-ods/` (при замене пересчитать по tshark):

* `tcpdump_odskc2_and_one_plc_lb_v1.pcap` — 96 запросов, 0 видимых ответов,
  4560 запрошенных слов, медиана ACK ~22.8 мс (нижняя оценка), p95 ~51 мс,
  цикл ~2076 мс, неразобранных байт 0, неотвеченных 0; 3 рекомендации
  (все info: чтение целого диапазона, запас PLC, односторонний захват);
* `tcpdump_odskc2_and_one_plc_lb.pcap` — 34 запроса / 34 ответа, по 1615
  слов, медиана RTT ~41 мс, p95 ~106 мс, цикл ~2064 мс, коды ответа только
  `0x00`, mismatch размеров 0, сирот 0, неразобранных байт 0;
  4 рекомендации (1 warning «PLC отвечает медленно», 3 info, включая
  «большая часть значений не меняется»).

Значения блоков видны только в двустороннем файле: DB200 (52 слова) не
менялся ни разу, DB201 (43 слова) — 93% слов изменились.

## Docker

```bash
docker compose up --build -d     # веб-интерфейс на :8000 (сервис web, restart)
PCAP_FILE=… REPORT_FILE=… FORMAT=both docker compose run --rm analyzer analyze \
    /data/$PCAP_FILE -o /output/$REPORT_FILE -f $FORMAT
```

Образ: `python:3.14-slim` + `tshark`, `libpango-*`, `libgdk-pixbuf`,
`fonts-dejavu-core` из apt + pip-зависимости из `requirements.txt`.
ENTRYPOINT — `python -m analyzer`; сервис `web` по умолчанию запускает
подкоманду `serve` (том `webdata`, образцы из `./pcap-sample` read-only).
Параметры развёртывания — через `.env` (`WEB_IP`, `WEB_PORT`, `WEB_TOKEN`,
см. `.env.example`); издалека — `docker compose up --build -d` с `restart`.
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

### Добавить метрику в тренды
1. В конце `analyze()` ветки дополнить `result.metrics["ключ"] = float`.
2. Название по ключу — в `METRIC_TITLES` (trend_report.py).
График появится автоматически у trend/diff.

### Починить сопоставление Job/Ack_Data (S7)
Логика — `_pass_s7`: сопоставление по `(tcp.stream, s7comm.header.pduref)`;
очередь на ключ ограничена (`s7_max_pending_per_ref`), RTT выше
`s7_rtt_sanity_max_sec` считается потерянной транзакцией. Значения чтений
достаются вручную из `tcp.payload` (`_value_digests`) — полей с байтами
данных в tshark нет; длины элементов берутся из `s7comm.data.length`.

### Починить сопоставление запросов и ответов

Логика — `_pass_modbus` в `branches/modbus_tcp.py`. Приоритет определения
направления: порт 502 → наличие `modbus.request_frame`. Сопоставление — по
номеру кадра запроса, резерв — FIFO по ключу `(stream, trans_id, unit_id)`.

### Разбор сообщений SINEC H1

Логика — `parse_h1_messages(buf, expect_data=…)` в `branches/sinec_h1.py`.
Тонкости формата, которые обязаны учитываться:

* tshark разбирает только первое сообщение сегмента, остальные идут как `Data`,
  поэтому ветка читает `tcp.payload` и разбирает цепочку сама;
* в одном сообщении может быть несколько блоков адреса `03 08` (чтение двух DB
  одной командой) — `H1Message.addrs`, `words` = сумма `dlen` по всем блокам;
* у ответа на чтение блока адреса нет, а данные идут после объявленной длины
  единым хвостом без заголовка: длина берётся из сопоставленного запроса,
  который лежит в начале FIFO (`pair.fifo`, записи `(opcode, ts, words)`);
* в одном сегменте ответов может быть несколько — callback `expect_data`
  держит курсор `seen` по FIFO, сама очередь уменьшается позже, в
  `_on_response`;
* номера транзакции в протоколе нет, сопоставление строго FIFO; отличить
  ретрай запроса от нового запроса невозможно;
* отклик по ACK считается только для чистых ACK (`tcp.len == 0`): у кадра с
  payload `tcp.ack` подтверждает байты обратного направления, то есть собственный
  запрос.

## Чего не делать

* Не добавлять внешние python-пакеты сверх weasyprint без веской причины.
* Не переводить комментарии/вывод на английский.
* Не коммитить pcap-файлы, содержимое `output/` и `webdata/`.
* Не ломать потоковую обработку: никаких «прочитать весь tshark-вывод или
  загружаемый файл в список/память».
* Не отделять PDF от HTML: у отчётов один источник контента —
  `render_document(BranchResult)`.
