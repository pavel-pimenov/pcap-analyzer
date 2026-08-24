"""Smoke-тесты pcap-analyzer (только стандартная библиотека).

Запуск из корня репозитория:

    python3 -m unittest discover -s tests -t . -v

Интеграционные тесты пропускаются, если в PATH нет tshark или нет
каталога с образцами (по умолчанию ./pcap-sample, можно переопределить
переменной окружения PCAP_SAMPLES).
"""

from __future__ import annotations

import html.parser
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyzer.branches import BRANCHES, get_branch            # noqa: E402
from analyzer.config import Config, DEFAULT_CONFIG            # noqa: E402
from analyzer.report.components import (                      # noqa: E402
    cmd_block, ensure_field_headers, example_cmd, gantt_svg, limit_example)

SAMPLES = Path(os.environ.get("PCAP_SAMPLES", ROOT / "pcap-sample"))
HAS_TSHARK = shutil.which("tshark") is not None


def _pick_sample(*needles: str) -> Path | None:
    """Первый подходящий pcap по подстроке имени (или самый маленький)."""
    if not SAMPLES.is_dir():
        return None
    pcaps = sorted(p for p in SAMPLES.iterdir()
                   if p.suffix.lower() in {".pcap", ".pcapng", ".cap"})
    if not pcaps:
        return None
    for n in needles:
        for p in pcaps:
            if n in p.name.lower():
                return p
    return min(pcaps, key=lambda p: p.stat().st_size)


def _tshark_count(pcap: Path, display: str) -> int:
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-Y", display, "-T", "fields",
         "-e", "frame.number"],
        capture_output=True, text=True, timeout=600, check=True)
    return sum(1 for ln in out.stdout.splitlines() if ln.strip())


# ---------------------------------------------------------------------------
# Быстрые юнит-тесты (без tshark)
# ---------------------------------------------------------------------------

class HelpersTest(unittest.TestCase):
    def test_field_headers_added_to_pure_fields_cmd(self):
        cmd = 'tshark -r f.pcap -Y "mbtcp" -T fields -e frame.number'
        self.assertTrue(ensure_field_headers(cmd).endswith("-E header=y"))

    def test_field_headers_skip_pipeline(self):
        cmd = ('tshark -r f.pcap -T fields -e ip.src '
               "| sort | uniq -c | sort -rn")
        self.assertNotIn("-E header=y", ensure_field_headers(cmd))

    def test_limit_appends_head(self):
        self.assertTrue(limit_example("tshark -r f.pcap").endswith("| head -25"))

    def test_limit_skips_existing_limiter(self):
        c = "tshark -r f.pcap | wc -l"
        self.assertEqual(limit_example(c), c)
        c2 = "tshark -r f.pcap | sort -u"
        self.assertTrue(limit_example(c2).endswith("| head -25"))

    def test_example_cmd_full_chain(self):
        out = example_cmd('tshark -r f.pcap -Y "mbtcp" -T fields -e frame.len')
        self.assertIn("-E header=y | head -25", out)

    def test_gantt_burst_annotation_only_for_merged_groups(self):
        rows = [{
            "label": ":1 → 10.0.0.1", "color": "#123456",
            "span": (0.0, 0.5),
            # пачка из 4 близких запросов + один редкий одиночный
            "ticks": [0.100, 0.102, 0.104, 0.106, 0.400],
        }]
        svg = gantt_svg(rows, 0.0, 1.0, bursts=True)
        self.assertIn(">4 зап.</text>", svg)          # пачка подписана
        self.assertIn("<polygon", svg)                # стрелка вниз
        self.assertNotIn(">1 зап.</text>", svg)       # одиночный — без подписи

    def test_gantt_empty_rows(self):
        self.assertEqual(gantt_svg([], 0.0, 1.0), "")

    def test_config_upload_limit(self):
        self.assertGreater(DEFAULT_CONFIG.max_upload_bytes, 0)


class BranchRegistryTest(unittest.TestCase):
    def test_modbus_registered(self):
        self.assertIn("modbus", BRANCHES)
        self.assertIsNotNone(get_branch("modbus"))


# ---------------------------------------------------------------------------
# Интеграционные тесты (нужны tshark и образцы)
# ---------------------------------------------------------------------------

def _balanced_html(text: str) -> bool:
    """Проверка парности основных контейнерных тегов HTML-отчёта."""
    stack: list[str] = []
    void = {"br", "hr", "img", "input", "meta", "link", "col"}

    class P(html.parser.HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag not in void:
                stack.append(tag)

        def handle_startendtag(self, tag, attrs):
            pass

        def handle_endtag(self, tag):
            if tag in void:
                return
            if stack and stack[-1] == tag:
                stack.pop()
            else:
                raise ValueError(f"непарный тег </{tag}>, стек: {stack[-3:]}")

    p = P(convert_charrefs=True)
    p.feed(text)
    p.close()
    return not stack


@unittest.skipUnless(HAS_TSHARK, "нет tshark в PATH")
@unittest.skipUnless(SAMPLES.is_dir(), f"нет каталога образцов: {SAMPLES}")
class ModbusAnalyzeTest(unittest.TestCase):
    """Анализ modbus на самом маленьком образце + критерии из AGENTS.md."""

    @classmethod
    def setUpClass(cls):
        # предпочитаем образцы с ожидаемым Modbus-трафиком
        cls.pcap = (_pick_sample("cote", "modbus", "mbtcp")
                    or min(
                        (p for p in SAMPLES.iterdir()
                         if p.suffix.lower() in {".pcap", ".pcapng", ".cap"}),
                        key=lambda p: p.stat().st_size))
        if _tshark_count(cls.pcap, "mbtcp && tcp.dstport==502") == 0:
            raise unittest.SkipTest(f"в {cls.pcap.name} нет Modbus/TCP")
        from analyzer.tshark_runner import find_tshark
        branch = get_branch("modbus")
        cls.result = branch.analyze(
            cls.pcap, DEFAULT_CONFIG, progress=lambda m, pct=None: None,
            tshark_bin=find_tshark(None))
        from analyzer.report import render_document
        cls.html = render_document(cls.result)

    def test_requests_match_tshark(self):
        expected = _tshark_count(self.pcap, "mbtcp && tcp.dstport==502")
        reqs = next(
            (int(re.sub(r"\D", "", str(v.value))) for v in self.result.kpi
             if "запрос" in v.label.lower()
             and re.search(r"\d", str(v.value))), None)
        self.assertIsNotNone(reqs, "в KPI нет счётчика запросов")
        self.assertEqual(reqs, expected,
                         "число Modbus-запросов расходится с tshark")

    def test_kpi_and_sections_present(self):
        self.assertTrue(self.result.kpi)
        self.assertTrue(self.result.sections)
        ids = [s.id for s in self.result.sections]
        self.assertIn("general", ids)

    def test_html_is_balanced_and_has_key_blocks(self):
        self.assertTrue(_balanced_html(self.html), "HTML содержит непарные теги")
        for frag in ('id="general"', "cmd-line", "copy-btn", "csv-btn"):
            self.assertIn(frag, self.html)

    def test_examples_have_header_and_limit(self):
        codes = re.findall(r"<code>(tshark[^<]*)</code>", self.html)
        self.assertTrue(codes)
        for c in codes:
            tail = c.rsplit("|", 1)[-1]
            if "-T fields" in c and "|" not in c.split("-T fields")[1]:
                self.assertIn("-E header=y", c)
            self.assertTrue(re.search(r"\b(head|tail|wc)\b", tail),
                            f"команда без ограничителя вывода: {c[:80]}")


@unittest.skipUnless(HAS_TSHARK, "нет tshark в PATH")
class ServicesAnalyzeTest(unittest.TestCase):
    """Ветка services: сервисы и направления на синтетическом дампе Modbus."""

    @classmethod
    def setUpClass(cls):
        from tests import pcapgen
        cls.pcap = Path(os.environ.get("PCAPGEN_OUT", "/tmp/services_fix.pcap"))
        pcapgen.write_modbus_pcap(cls.pcap)
        from analyzer.tshark_runner import find_tshark
        cls.tshark = find_tshark(None)

    def test_service_502_bidirectional(self):
        from analyzer.branches.services import ServicesAnalyzer
        b = ServicesAnalyzer()
        b.cfg = DEFAULT_CONFIG
        b.tshark = self.tshark
        b.pcap_str = str(self.pcap)
        b.progress = lambda m, pct=None: None
        b._pass_general()
        svc = b._tcp_services.get(("10.0.0.1", 502))
        self.assertIsNotNone(svc, "сервис :502 не найден на дампе Modbus")
        # клиент .10 -> сервер .1; обе стороны передают полезную нагрузку
        self.assertEqual(svc.req_pkts, 110)
        self.assertGreater(svc.resp_pkts, 0)
        self.assertEqual(svc.silent_streams, 0)
        self.assertFalse(svc.one_way_streams)
        # строгий цикл фазы C даёт периодику
        self.assertGreater(len(svc.intervals), 50)

    def test_reports_render(self):
        from analyzer.branches.services import ServicesAnalyzer
        from analyzer.report import render_document
        b = ServicesAnalyzer()
        b.cfg = DEFAULT_CONFIG
        result = b.analyze(self.pcap, DEFAULT_CONFIG,
                           progress=lambda m, pct=None: None,
                           tshark_bin=self.tshark)
        html = render_document(result)
        self.assertTrue(_balanced_html(html))

    def test_arp_noise_detected_and_reported(self):
        from tests import pcapgen
        from analyzer.branches.services import ServicesAnalyzer
        pcap2 = self.pcap.with_name("services_fix_arp.pcap")
        pcapgen.write_modbus_pcap(pcap2, arp_noise=150)
        b = ServicesAnalyzer()
        b.cfg = DEFAULT_CONFIG
        result = b.analyze(pcap2, DEFAULT_CONFIG,
                           progress=lambda m, pct=None: None,
                           tshark_bin=self.tshark)
        self.assertEqual(b._arp["req"], 150)
        self.assertEqual(b._arp["targets"]["10.9.9.9"], 150)
        ids = {r.id for r in result.recommendations}
        self.assertIn("svc-arp-storm", ids)          # 150 кадров за ~2 с
        self.assertIn("svc-arp-unanswered", ids)     # ответов нет вовсе
        # виновник с целями попал в evidence шторма
        storm = next(r for r in result.recommendations if r.id == "svc-arp-storm")
        self.assertTrue(any("aa:00:bb:00:cc:01" in e for e in storm.evidence))


@unittest.skipUnless(HAS_TSHARK, "нет tshark в PATH")
class TrendSeriesTest(unittest.TestCase):
    """Тренд по серии из трёх сгенерированных дампов с шагом 5 минут."""

    def runTest(self):  # noqa: N802
        import tempfile
        from tests import pcapgen
        from analyzer.branches import get_branch
        from analyzer.config import DEFAULT_CONFIG
        from analyzer.trend import build_trend
        from analyzer.report import render_trend_html

        tmp = Path(tempfile.mkdtemp(prefix="trend-"))
        paths = []
        for i, ts in enumerate((1735000000, 1735000300, 1735000600)):
            p = tmp / f"series_{i}.pcap"
            pcapgen.write_modbus_pcap(p, base_ts=ts)
            paths.append(p)
        branch = get_branch("modbus")
        points, took = build_trend(paths, branch, DEFAULT_CONFIG,
                                   progress=lambda m, pct=None: None)
        self.assertEqual(len(points), 3)
        for pt in points:
            self.assertGreater(pt.metrics.get("reqs", 0), 100)
            self.assertIsNotNone(pt.start_ts)
        html = render_trend_html(points, branch.title, str(tmp / "*.pcap"))
        self.assertIn("Тренды по серии дампов", html)
        self.assertGreaterEqual(html.count('id="m-reqs"'), 1)


@unittest.skipUnless(HAS_TSHARK, "нет tshark в PATH")
class TrendParallelTest(unittest.TestCase):
    """--jobs 2 даёт те же точки, что и последовательная обработка."""

    def runTest(self):  # noqa: N802
        import tempfile
        from tests import pcapgen
        from analyzer.branches import get_branch
        from analyzer.config import DEFAULT_CONFIG
        from analyzer.trend import build_trend

        tmp = Path(tempfile.mkdtemp(prefix="trendpar-"))
        paths = []
        for i, ts in enumerate((1735000000, 1735000300, 1735000600)):
            p = tmp / f"p_{i}.pcap"
            pcapgen.write_modbus_pcap(p, base_ts=ts)
            paths.append(p)
        branch = get_branch("modbus")

        def prog(m, pct=None):
            pass

        seq, _ = build_trend(paths, branch, DEFAULT_CONFIG, progress=prog)
        par, _ = build_trend(paths, branch, DEFAULT_CONFIG, progress=prog,
                             jobs=3)
        self.assertEqual([pt.path for pt in par], paths)   # порядок входа
        for a, b in zip(seq, par):
            self.assertEqual(a.metrics, b.metrics)
            self.assertEqual(a.rec_ids, b.rec_ids)


@unittest.skipUnless(HAS_TSHARK, "нет tshark в PATH")
class S7commAnalyzeTest(unittest.TestCase):
    """s7comm на первом образце, где такой трафик есть."""

    def runTest(self):  # noqa: N802 — динамический skip внутри
        pcap = None
        pcaps = sorted(p for p in SAMPLES.iterdir()
                       if p.suffix.lower() in {".pcap", ".pcapng", ".cap"}
                       ) if SAMPLES.is_dir() else []
        for p in pcaps:
            probe = subprocess.run(
                ["tshark", "-r", str(p), "-Y", "s7comm", "-c", "1",
                 "-T", "fields", "-e", "frame.number"],
                capture_output=True, text=True, timeout=600)
            if any(ln.strip() for ln in probe.stdout.splitlines()):
                pcap = p
                break
        if pcap is None:
            self.skipTest("нет образца с S7comm-трафиком")
        from analyzer.tshark_runner import find_tshark
        result = get_branch("s7comm").analyze(
            pcap, DEFAULT_CONFIG, progress=lambda m, pct=None: None,
            tshark_bin=find_tshark(None))
        self.assertTrue(result.sections)
        from analyzer.report import render_document
        html = render_document(result)
        self.assertTrue(_balanced_html(html))


try:
    import weasyprint  # noqa: F401
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


@unittest.skipUnless(HAS_TSHARK, "нет tshark в PATH")
@unittest.skipUnless(HAS_WEASYPRINT, "weasyprint не установлен")
class PdfSmokeTest(unittest.TestCase):
    def runTest(self):  # noqa: N802
        pcap = _pick_sample()
        if pcap is None:
            self.skipTest("нет образцов")
        from analyzer.report.pdf_report import render_pdf_bytes
        from analyzer.tshark_runner import find_tshark
        result = get_branch("modbus").analyze(
            pcap, DEFAULT_CONFIG, progress=lambda m, pct=None: None,
            tshark_bin=find_tshark(None))
        data = render_pdf_bytes(result)
        self.assertTrue(data.startswith(b"%PDF"), "это не PDF")


if __name__ == "__main__":
    unittest.main(verbosity=2)
