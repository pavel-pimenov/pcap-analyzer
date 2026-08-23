"""PDF-версия отчёта: конвертация готового HTML через WeasyPrint.

HTML-отчёт (`html_report.render_document`) остаётся единым источником
контента; для PDF к нему добавляется печатная таблица стилей: страница A4,
поля, нумерация страниц, шрифт с поддержкой кириллицы, запрет разрыва
внутри карточек и команд.

WeasyPrint — единственная внешняя зависимость проекта (requirements.txt);
кроме python-пакета нужны системные библиотеки Pango/GDK-Pixbuf и шрифты
(в Docker-образ ставятся apt-пакетами, см. Dockerfile). Импорт сделан
ленивым, чтобы команды без PDF (например, `-f html` или `branches`)
работали и без установленного weasyprint.
"""

from __future__ import annotations

from ..branches.base import BranchResult
from .html_report import render_document

_PRINT_CSS = """\
@page {
  size: A4 landscape;              /* альбомная: широкие таблицы помещаются */
  margin: 12mm 10mm 15mm;
  @bottom-left {
    content: "pcap-analyzer";
    font-size: 7pt; color: #9ca3af;
  }
  @bottom-center {
    content: "страница " counter(page) " из " counter(pages);
    font-size: 7pt; color: #6b7280;
  }
}
body { background: #ffffff; font-size: 6pt;
       font-family: "DejaVu Sans", Arial, sans-serif; }
.wrap { max-width: none; padding: 0; margin: 0; }
header.report { border-radius: 8pt; padding: 12pt 16pt; margin-bottom: 10pt; }
header.report h1 { font-size: 11pt; }
header.report .meta, header.report .legend { font-size: 5.5pt; }
section.card { border: none; padding: 0; margin-bottom: 10pt;
               page-break-inside: auto; }
h2 { font-size: 9pt; border-bottom: 0.5pt solid #e5e7eb; padding-bottom: 2pt; }
h3.subhead { font-size: 7pt; margin: 8pt 0 4pt; }
.kpi { page-break-inside: avoid; padding: 6pt 8pt; }
.kpi-value { font-size: 11pt; }
.kpi-label { font-size: 5.5pt; }
.kpi-hint { font-size: 5pt; }
tr { page-break-inside: avoid; }
/* Широкие таблицы: на печати горизонтальной прокрутки нет. Авто-раскладка
   с уменьшенным шрифтом и компактными отступами позволяет колонкам занять
   ровно столько, сколько нужно содержимому (IP и коды не переносятся),
   и при этом вся таблица помещается в полосу набора */
.table-scroll { overflow-x: visible; }
table.data-table { font-size: 4.5pt; width: 100%; }
table.data-table th { white-space: normal !important;
                      overflow-wrap: anywhere !important;
                      padding: 1.5pt 2pt; }
table.data-table td { padding: 1.5pt 2pt; overflow-wrap: anywhere; }
/* Кнопки «копировать в буфер» — интерактив экранного HTML, на печати не нужны */
.copy-btn { display: none !important; }
.rec { page-break-inside: avoid; }
.cmd-row { page-break-inside: avoid; }
.cmd-desc { font-size: 5.5pt; }
pre.cmd { white-space: pre-wrap; word-break: break-all; font-size: 5pt; }
.chart-box svg { max-width: 100%; height: auto; }
a { color: #2563eb; text-decoration: none; }
nav.toc { display: none; }
footer.report { display: none; }
"""


def render_pdf_bytes(result: BranchResult) -> bytes:
    """Собрать HTML-отчёт и отдать его в виде PDF (байты)."""
    try:
        from weasyprint import CSS, HTML
    except ImportError as e:  # подсказка вместо трейсбека с cryptic ModuleNotFoundError
        raise RuntimeError(
            "Для экспорта в PDF требуется пакет WeasyPrint "
            "(pip install weasyprint), а также системные библиотеки Pango "
            "(в Debian/Ubuntu: apt install libpango-1.0-0 libpangocairo-1.0-0 "
            "libgdk-pixbuf-2.0-0 fonts-dejavu-core)."
        ) from e

    html = render_document(result)
    doc = HTML(string=html, base_url=".").render(
        stylesheets=[CSS(string=_PRINT_CSS)])
    return doc.write_pdf()


def render_pdf_file(result: BranchResult, out_path) -> None:
    """Собрать PDF-отчёт и записать его в файл."""
    data = render_pdf_bytes(result)
    out_path = __import__("pathlib").Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
