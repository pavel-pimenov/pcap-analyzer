"""Юнит-тесты чистой логики: перцентили, Reservoir, merge_ranges,
правила рекомендаций Modbus и потоковый разбор multipart (без tshark).

Запуск: python3 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import io
import re as _re_mod  # noqa: F401 (используется в тестах ниже)
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyzer.branches.base import (                             # noqa: E402
    Reservoir, percentile)
from analyzer.branches.modbus_tcp import (                       # noqa: E402
    GeneralStats, ModbusTcpAnalyzer, PairStats, PollTarget, merge_ranges)
from analyzer.report import TrendPoint                        # noqa: E402
from analyzer.config import Config                               # noqa: E402


def _branch() -> ModbusTcpAnalyzer:
    """Ветка с подставленными атрибутами — только для правил (без tshark)."""
    b = ModbusTcpAnalyzer()
    b.cfg = Config()
    b.pcap = Path("sample.pcap")
    b.pcap_str = "sample.pcap"
    b.tshark = "tshark"
    b.progress = lambda m, pct=None: None
    return b


class PercentileTest(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(percentile([], 50))

    def test_single_value(self):
        self.assertEqual(percentile([5.0], 95), 5.0)

    def test_exact_index(self):
        self.assertEqual(percentile([1.0, 2.0, 3.0], 50), 2.0)

    def test_interpolation(self):
        # k = 0.5 → середина между 10 и 20
        self.assertAlmostEqual(percentile([10.0, 20.0], 50), 15.0)

    def test_p95(self):
        vals = [float(i) for i in range(1, 101)]      # 1..100
        self.assertAlmostEqual(percentile(vals, 95), 95.05)


class ReservoirTest(unittest.TestCase):
    def test_cap_respected_and_seen_counted(self):
        r = Reservoir(10)
        for v in range(1000):
            r.add(float(v))
        self.assertEqual(len(r), 10)
        self.assertEqual(r.seen, 1000)
        vals = list(r)
        self.assertTrue(all(0 <= v < 1000 for v in vals))

    def test_deterministic(self):
        a, b = Reservoir(8), Reservoir(8)
        for i in range(500):
            a.add(i)
            b.add(i)
        self.assertEqual(list(a), list(b))

    def test_small_cap_keeps_prefix(self):
        r = Reservoir(3)
        for v in (9.0, 8.0, 7.0, 6.0):
            r.add(v)
        self.assertEqual(len(r), 3)
        self.assertEqual(sorted(r), [7.0, 8.0, 9.0])   # первые три сохранились

    def test_zero_cap_keeps_nothing(self):
        r = Reservoir(0)
        for v in range(5):
            r.add(float(v))
        self.assertEqual(len(r), 0)


class MergeRangesTest(unittest.TestCase):
    def test_disjoint(self):
        out = merge_ranges({(0, 3): 1.0, (10, 12): 2.0})
        self.assertEqual(out, [(0, 3, 1.0), (10, 12, 2.0)])

    def test_overlap_merges_and_sums(self):
        out = merge_ranges({(0, 4): 1.0, (2, 6): 3.0})
        self.assertEqual(out, [(0, 6, 4.0)])

    def test_adjacent_merges(self):
        out = merge_ranges({(0, 5): 1.0, (5, 8): 1.0})
        self.assertEqual(out, [(0, 8, 2.0)])

    def test_contained_range(self):
        out = merge_ranges({(0, 10): 2.0, (3, 5): 7.0})
        self.assertEqual(out, [(0, 10, 9.0)])


# ---------------------------------------------------------------------------
# Правила рекомендаций (на синтетических агрегатах)
# ---------------------------------------------------------------------------

def _gen(duration: float, syn502=None) -> GeneralStats:
    g = GeneralStats()
    g.first_ts = 0.0
    g.last_ts = duration
    g.syn502 = syn502 or []
    return g


class ConnChurnRuleTest(unittest.TestCase):
    def test_no_syns_no_rule(self):
        self.assertEqual(_branch()._rule_conn_churn(_gen(600.0)), [])

    def test_high_rate_is_critical(self):
        # 200 SYN за 10 мин = 20/мин ≥ порог ×3 → critical
        syn = [(i * 3.0, "10.0.0.9", "10.0.0.1") for i in range(200)]
        recs = _branch()._rule_conn_churn(_gen(600.0, syn))
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "critical")

    def test_repeated_pair_is_warning(self):
        # 3 SYN одной пары за 10 мин: частота низкая, но повторы ловятся
        syn = [(i * 100.0, "10.0.0.9", "10.0.0.1") for i in range(3)]
        recs = _branch()._rule_conn_churn(_gen(600.0, syn))
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "warning")
        self.assertIn("Повторные подключения", recs[0].problem)

    def test_short_capture_not_scaled(self):
        # 2 SYN за 5 секунд не должны давать «частоту» 24/мин
        syn = [(0.0, "c", "s"), (1.0, "c", "s")]
        self.assertEqual(_branch()._rule_conn_churn(_gen(5.0, syn)), [])


class SlowServersRuleTest(unittest.TestCase):
    def _mb_with_rtts(self, rtts):
        ps = PairStats(rtts=Reservoir(len(rtts)))
        for v in rtts:
            ps.rtts.add(v)
        return {("10.0.0.9", "10.0.0.1"): ps}

    def test_fast_server_no_rule(self):
        mb = {"pairs": self._mb_with_rtts([0.01] * 100)}
        self.assertEqual(_branch()._rule_slow_servers(mb), [])

    def test_slow_p95_triggers(self):
        rtts = [0.01] * 94 + [0.5] * 6                   # p95 ≈ 500 мс
        recs = _branch()._rule_slow_servers({"pairs": self._mb_with_rtts(rtts)})
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].id, "slow-servers")


class ExceptionsRuleTest(unittest.TestCase):
    def _mb(self, exc: int, resp: int) -> dict:
        from collections import Counter as _C
        return {"exc_total": exc, "resp_total": resp,
                "exc_counter": _C({("10.0.0.1", 1, 2): exc}),
                "exc_targets": _C({("10.0.0.9", "10.0.0.1", 1, 3,
                                    200, 1, 2): exc})}

    def test_below_threshold_silent(self):
        self.assertEqual(_branch()._rule_exceptions(self._mb(1, 1000)), [])

    def test_warning_above_threshold(self):
        recs = _branch()._rule_exceptions(self._mb(10, 1000))   # 1%
        self.assertEqual(recs[0].severity, "warning")

    def test_critical_at_high_rate(self):
        recs = _branch()._rule_exceptions(self._mb(60, 1000))   # 6%
        self.assertEqual(recs[0].severity, "critical")


class NoResponseRuleTest(unittest.TestCase):
    def _mb(self, no_resp: int) -> dict:
        ps = PairStats(no_resp=no_resp)
        return {"pairs": {("10.0.0.9", "10.0.0.1"): ps}, "req_total": 1000}

    def test_below_threshold_silent(self):
        self.assertEqual(_branch()._rule_no_response(self._mb(4)), [])

    def test_fires_and_escalates(self):
        self.assertEqual(
            _branch()._rule_no_response(self._mb(10))[0].severity, "warning")
        self.assertEqual(
            _branch()._rule_no_response(self._mb(60))[0].severity, "critical")


class PollPressureRuleTest(unittest.TestCase):
    def test_interval_le_factor_times_rtt(self):
        b = _branch()
        ps = PairStats(rtts=Reservoir(100))
        for _ in range(20):
            ps.rtts.add(0.002)                    # медиана RTT 2 мс
        target = PollTarget("10.0.0.9", "10.0.0.1", 1, 3, 300, 1,
                            intervals=Reservoir(100))
        for _ in range(15):
            target.intervals.add(0.003)           # интервал 3 мс ≤ 2×RTT
        mb = {"pairs": {("10.0.0.9", "10.0.0.1"): ps},
              "poll_targets": {"k": target}}
        recs = b._rule_poll_pressure(mb)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].id, "poll-pressure")

    def test_calm_polling_silent(self):
        b = _branch()
        ps = PairStats(rtts=Reservoir(100))
        for _ in range(20):
            ps.rtts.add(0.002)
        target = PollTarget("10.0.0.9", "10.0.0.1", 1, 3, 300, 1,
                            intervals=Reservoir(100))
        for _ in range(15):
            target.intervals.add(1.0)             # 1 c >> 2×RTT
        mb = {"pairs": {("10.0.0.9", "10.0.0.1"): ps},
              "poll_targets": {"k": target}}
        self.assertEqual(b._rule_poll_pressure(mb), [])


class MergeSmallReadsRuleTest(unittest.TestCase):
    def test_clustered_reads_recommended(self):
        b = _branch()
        items = [(i * 0.02, i % 40, 1) for i in range(40)]   # окно 0,8 с
        mb = {
            "small_reads": {("10.0.0.9", "10.0.0.1", 1): items},
            "small_reads_total": {("10.0.0.9", "10.0.0.1", 1): 40},
        }
        recs = b._rule_merge_small_reads(mb)
        self.assertEqual(len(recs), 1)
        self.assertIn("~98%", recs[0].problem)

    def test_few_reads_skipped(self):
        b = _branch()
        mb = {
            "small_reads": {("10.0.0.9", "10.0.0.1", 1): [(i * 0.02, i, 1)
                                                          for i in range(10)]},
            "small_reads_total": {("10.0.0.9", "10.0.0.1", 1): 10},
        }
        self.assertEqual(b._rule_merge_small_reads(mb), [])


class WriteBatchingRuleTest(unittest.TestCase):
    def test_single_write_spam_recommended(self):
        b = _branch()
        key = ("10.0.0.9", "10.0.0.1", 1)
        mb = {
            "writes_single": {key: [(i * 0.02, i % 20) for i in range(15)]},
            "writes_single_total": {key: 15},
            "writes_coil": {},
        }
        recs = b._rule_write_batching(mb)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "info")
        self.assertIn("FC16", recs[0].advice)


class StaticRegistersRuleTest(unittest.TestCase):
    def test_share_threshold(self):
        b = _branch()
        vt = {}
        for reg in range(4):                      # 40% статичных ≥ 30%
            vt[(("10.0.0.1"), 1, 3, reg)] = [5, 1, 100]
        for reg in range(4, 10):
            vt[(("10.0.0.1"), 1, 3, reg)] = [5, 50, 100]
        recs = b._rule_static_registers({"valtrack": vt})
        self.assertEqual(len(recs), 1)
        self.assertIn("не меняются", recs[0].title)

    def test_too_few_candidates_silent(self):
        b = _branch()
        vt = {(("10.0.0.1"), 1, 3, 1): [5, 0, 100]}
        self.assertEqual(b._rule_static_registers({"valtrack": vt}), [])


class SharedRegistersRuleTest(unittest.TestCase):
    def test_two_clients_on_same_range(self):
        rk = ("10.0.0.1", 1, 3, 0, 10)
        mb = {
            "range_clients": {rk: {"10.0.0.9", "10.0.0.11"}},
            "reads": {rk: [120, 1200]},
        }
        recs = _branch()._rule_shared_registers(mb)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].id, "shared-registers")

    def test_single_client_silent(self):
        rk = ("10.0.0.1", 1, 3, 0, 10)
        mb = {
            "range_clients": {rk: {"10.0.0.9"}},
            "reads": {rk: [120, 1200]},
        }
        self.assertEqual(_branch()._rule_shared_registers(mb), [])


# ---------------------------------------------------------------------------
# Потоковый разбор multipart/form-data (веб-GUI)
# ---------------------------------------------------------------------------

BOUNDARY = b"----analyzerTestBoundary42"


def _multipart_body(payload: bytes, filename: str = "dump.pcap") -> bytes:
    return b"".join([
        b"--" + BOUNDARY + b"\r\n",
        b'Content-Disposition: form-data; name="file"; filename="'
        + filename.encode() + b'"\r\n',
        b"Content-Type: application/octet-stream\r\n",
        b"\r\n",
        payload,
        b"\r\n--" + BOUNDARY + b"--\r\n",
    ])


class MultipartParserTest(unittest.TestCase):
    def _parse(self, body: bytes, limit: int | None = None):
        from analyzer.webapp import server as srv

        old = None
        if limit is not None:
            old = srv.MAX_UPLOAD_BYTES
            srv.MAX_UPLOAD_BYTES = limit
        try:
            with tempfile.TemporaryDirectory() as td:
                dest = Path(td) / "out.part"
                name, size = srv.parse_multipart_file(
                    io.BufferedReader(io.BytesIO(body)),
                    BOUNDARY, dest, len(body))
                data = dest.read_bytes()
            return name, size, data
        finally:
            if old is not None:
                srv.MAX_UPLOAD_BYTES = old

    def test_payload_roundtrip(self):
        payload = b"PCAPDATA" * 5000
        name, size, data = self._parse(_multipart_body(payload))
        self.assertEqual(name, "dump.pcap")
        self.assertEqual(size, len(payload))
        self.assertEqual(data, payload)

    def test_binary_payload_with_boundaries_inside(self):
        payload = bytes(range(256)) * 64 + b"\r\n--x\r\n"
        _n, size, data = self._parse(_multipart_body(payload))
        self.assertEqual(size, len(payload))
        self.assertEqual(data, payload)

    def test_missing_terminator_raises(self):
        body = _multipart_body(b"abc")[:-len(b"\r\n--" + BOUNDARY + b"--\r\n")]
        with self.assertRaises(ValueError):
            self._parse(body)

    def test_size_limit_enforced(self):
        payload = b"x" * 100_000
        with self.assertRaises(ValueError):
            self._parse(_multipart_body(payload), limit=50_000)


class ExcTargetsTableTest(unittest.TestCase):
    """Таблица «кто и какими запросами вызывает исключения»."""

    def test_table_shows_client_and_range(self):
        from analyzer.branches.modbus_tcp import GeneralStats
        b = _branch()
        gen = GeneralStats()
        gen.first_ts, gen.last_ts = 0.0, 600.0
        from collections import Counter as _C
        mb = {
            "exc_counter": _C({("10.0.0.1", 1, 2): 7}),
            "exc_targets": {("10.0.0.9", "10.0.0.1", 1, 3, 200, 4, 2): 7},
            "unanswered_frames": [],
            "pairs": {},
            "req_total": 500,
        }
        html = b._sec_errors(gen, mb).body_html
        self.assertIn("какими запросами вызывает", html)
        self.assertIn("10.0.0.9", html)
        self.assertIn("200&ndash;203", html)
        recs = b._rule_exceptions(mb | {"exc_total": 10, "resp_total": 100})
        self.assertTrue(recs[0].evidence[0].startswith("10.0.0.9 →"))


class ConnectionsTableTest(unittest.TestCase):
    """Таблица соединений: RST показывается независимо от «кто закрыл первым»."""

    def _modbus_html(self):
        b = _branch()
        gen = GeneralStats()
        gen.first_ts, gen.last_ts = 0.0, 600.0
        gen.syn502 = [(1.0, "10.0.0.9", "10.0.0.1")]
        gen.streams502 = {"0": {
            "client": "10.0.0.9", "server": "10.0.0.1", "sport": 49152,
            "first": 1.0, "last": 60.0,
            "closed_by": "10.0.0.9",          # первым закрыл клиент (FIN)
            "rst_srv": True, "rst_cli": False,  # но RST пришёл от сервера
        }}
        return b._sec_connections(gen, {"stream_reqs": {}}).body_html

    def test_rst_column_present_despite_client_first_close(self):
        html = self._modbus_html()
        self.assertIn("RST от сервера", html)
        self.assertIn("Первым закрыл: клиент", html)

    def test_s7_rst_column_present(self):
        from analyzer.branches.s7comm import S7CommAnalyzer, GeneralStats as G7
        b = S7CommAnalyzer()
        b.cfg = Config()
        b.pcap = Path("sample.pcap")
        gen = G7()
        gen.first_ts, gen.last_ts = 0.0, 600.0
        gen.syn102 = [(1.0, "10.0.0.9", "10.0.0.1")]
        gen.streams102 = {"0": {
            "client": "10.0.0.9", "server": "10.0.0.1",
            "first": 1.0, "last": 60.0,
            "req_bytes": 100, "resp_bytes": 200,
            "closed_by": "10.0.0.9",
            "rst_srv": True, "rst_cli": False,
        }}
        html = b._sec_connections(gen, {"s7_streams": {"0"}}).body_html
        self.assertIn("RST от сервера", html)


class TrendRenderTest(unittest.TestCase):
    """Трендовый отчёт строится из точек без tshark."""

    def test_render_structure(self):
        from analyzer.report import TrendPoint, render_trend_html
        pts = []
        for i, ts in enumerate((1735000000, 1735000300, 1735000600)):
            pt = TrendPoint(
                path=Path(f"/tmp/fake_{i}.pcap"), start_ts=float(ts),
                metrics={"reqs": 100.0 + i, "rtt_med_ms": 20.0 + i},
                took_s=1.0)
            if i == 1:
                pt.rec_ids.add("conn-churn")
                pt.rule_info["conn-churn"] = ("warning", "Частые переподключения")
            pts.append(pt)
        html = render_trend_html(pts, "Анализ Modbus/TCP", "/tmp/fake_*.pcap")
        self.assertIn("Тренды по серии дампов", html)
        self.assertEqual(html.count('<section class="card" id="m-'), 2)
        self.assertIn("conn-churn", html)
        self.assertIn("Частые переподключения", html)
        # матрица: три колонки файлов
        self.assertIn("<th>Правило</th><th>1</th><th>2</th><th>3</th>", html)


class OverlapBlocksTest(unittest.TestCase):
    """Слияние регистров двух сторон в канонические блоки."""

    def test_merge_and_split_by_max_words(self):
        from analyzer.overlap import _block_rate, canonical_blocks
        cov_a = {("10.0.0.1", 1, 3, r): 10.0 for r in (1, 2, 3, 4)}
        # сторона Б читает только 5-й регистр → блок склеится до 1..5
        cov_b = {("10.0.0.1", 1, 3, 5): 6.0}
        blocks = canonical_blocks(cov_a, cov_b, max_words=125)
        self.assertEqual(len(blocks), 1)
        b = blocks[0]
        self.assertEqual((b["start"], b["len"]), (1, 5))
        self.assertAlmostEqual(b["rate"], 10.0)   # максимум из сторон

    def test_long_run_split_into_chunks(self):
        from analyzer.overlap import canonical_blocks
        cov = {("s", 1, 4, r): 1.0 for r in range(300)}
        blocks = canonical_blocks(cov, {}, max_words=125)
        self.assertEqual([b["len"] for b in blocks], [125, 125, 50])
        self.assertEqual(blocks[0]["start"], 0)
        self.assertEqual(blocks[2]["start"], 250)

    def test_block_rate_ignores_zero_registers(self):
        from analyzer.overlap import _block_rate
        cov = {("s", 1, 3, 7): 12.0}
        # в блоке 7..9 активен только один регистр
        self.assertAlmostEqual(_block_rate(cov, "s", 1, 3, 7, 9), 12.0)

    def test_runs_str(self):
        from analyzer.overlap import _runs_str
        self.assertEqual(_runs_str([1, 2, 3, 7]), "1&ndash;3, 7")


class VerdictBlockTest(unittest.TestCase):
    """Блок «Вывод» в шапке отчёта строится из рекомендаций."""

    def _render(self, recs):
        from analyzer.branches.base import BranchResult, Recommendation
        from analyzer.report.html_report import render_document
        result = BranchResult(branch_name="modbus",
                              branch_title="Т", pcap_path=Path("x.pcap"),
                              pcap_size_bytes=1)
        result.recommendations = recs
        return render_document(result)

    def test_counts_and_top_titles(self):
        from analyzer.branches.base import Recommendation
        html = self._render([
            Recommendation(id="a", severity="warning",
                           title="Первое предупреждение",
                           problem="p", advice="a"),
            Recommendation(id="b", severity="critical",
                           title="Критичная штука", problem="p", advice="a"),
            Recommendation(id="ok", severity="info",
                           title="Явных проблем не обнаружено",
                           problem="", advice=""),
        ])
        v = _re_mod.search(r'id="verdict".*?</section>', html,
                           _re_mod.S).group(0)
        plain = _re_mod.sub(r"<[^>]+>", " ", v)
        self.assertIn("Критичных:", plain.replace("  ", " "))
        self.assertIn("1", plain)
        self.assertIn("важных:", plain)
        self.assertIn("Критичная штука", plain)
        self.assertNotIn("Явных проблем", plain)   # ok-заглушка не считается

    def test_empty_state(self):
        html = self._render([])
        self.assertIn("не выявили проблем", html)


class TrendAnomaliesTest(unittest.TestCase):
    """Детектор выбросов в трендах (MAD)."""

    def test_spike_detected_flat_not(self):
        from analyzer.report.trend_report import find_anomalies
        self.assertEqual(find_anomalies([10, 11, 10, 12, 10, 95, 11]), [5])
        self.assertEqual(find_anomalies([5.0] * 8), [])
        self.assertEqual(find_anomalies([]), [])

    def test_render_marks_and_section(self):
        from analyzer.report import TrendPoint, render_trend_html
        pts = []
        vals = [100, 101, 99, 300]           # выброс на 4-й точке
        for i, (ts, reqs) in enumerate(zip((1735000000, 1735000300,
                                            1735000600, 1735000900), vals)):
            pts.append(TrendPoint(path=Path(f"/tmp/a_{i}.pcap"),
                                  start_ts=float(ts),
                                  metrics={"reqs": float(reqs)}))
        html = render_trend_html(pts, "Т", "маска", anomaly_k=5.0)
        self.assertIn('id="anomalies"', html)
        # красная точка-выброс на графике
        self.assertIn('fill="#dc2626"', html)
        self.assertIn("Аномалии в рядах", html)


class BaselineTest(unittest.TestCase):
    """Эталонный снимок: агрегация и восстановление точки."""

    def _points(self):
        pts = []
        for i, (ts, reqs) in enumerate(
                ((1735000000, 100.0), (1735000300, 104.0))):
            pt = TrendPoint(path=Path(f"/tmp/b_{i}.pcap"),
                            start_ts=float(ts),
                            metrics={"reqs": reqs, "unans_pct": 20.0})
            pt.rec_ids.add("conn-churn")
            pt.rule_info["conn-churn"] = ("warning", "Частые переподключения")
            pts.append(pt)
        return pts

    def test_snapshot_roundtrip(self):
        from analyzer.trend import point_from_snapshot, snapshot_from_points
        snap = snapshot_from_points(self._points(), "modbus")
        self.assertEqual(snap["branch"], "modbus")
        self.assertEqual(snap["files"], 2)
        self.assertAlmostEqual(snap["metrics"]["reqs"], 102.0)
        self.assertIn("conn-churn", snap["rules"])
        pt = point_from_snapshot(snap, label="эталон:b.json")
        self.assertEqual(pt.metrics["reqs"], 102.0)
        self.assertIn("conn-churn", pt.rec_ids)

    def test_diff_against_baseline_render(self):
        from analyzer.report import render_diff_html
        from analyzer.trend import point_from_snapshot, snapshot_from_points
        snap = snapshot_from_points(self._points(), "modbus")
        new_pt = TrendPoint(path=Path("new.pcap"), start_ts=1735003600.0,
                            metrics={"reqs": 120.0, "unans_pct": 4.0})
        html = render_diff_html(self._points(),
                                [point_from_snapshot(snap, "эталон")],
                                "серия", "эталон", "Анализ Modbus/TCP")
        self.assertIn("Сравнение периодов", html)
        # правило было в эталоне и в серии — «в обоих периодах»
        self.assertIn("в обоих периодах", html)


class VersionSyncTest(unittest.TestCase):
    """Версия в pyproject.toml совпадает с analyzer.__version__."""

    def test_versions_match(self):
        import tomllib
        import analyzer
        data = tomllib.load(open(ROOT / "pyproject.toml", "rb"))
        self.assertEqual(data["project"]["version"], analyzer.__version__)


class CsvButtonTest(unittest.TestCase):
    """Кнопка CSV есть в HTML и скрыта печатной таблицей стилей."""

    def test_print_css_hides_csv_button(self):
        from analyzer.report.pdf_report import _PRINT_CSS
        self.assertIn(".csv-btn", _PRINT_CSS)


class LoadConfigTest(unittest.TestCase):
    """Загрузка порогов из TOML поверх значений по умолчанию."""

    def test_load_and_override(self):
        import tempfile
        from analyzer.config import DEFAULT_CONFIG, load_config
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "c.toml"
            f.write_text("[modbus]\nslow_rtt_p95_ms = 150.0\n"
                         "[services]\narp_storm_per_min = 60\n")
            cfg = load_config(f)
        self.assertEqual(cfg.slow_rtt_p95_ms, 150.0)
        self.assertEqual(cfg.arp_storm_per_min, 60.0)
        # не заданные ключи остались дефолтными
        self.assertEqual(cfg.gantt_window_sec,
                         DEFAULT_CONFIG.gantt_window_sec)

    def test_unknown_key_rejected(self):
        import tempfile
        from analyzer.config import load_config
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "bad.toml"
            f.write_text("no_such_key = 1\n")
            with self.assertRaises(ValueError) as ctx:
                load_config(f)
            self.assertIn("no_such_key", str(ctx.exception))

    def test_bad_type_rejected(self):
        import tempfile
        from analyzer.config import load_config
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "bad2.toml"
            f.write_text('slow_rtt_p95_ms = "быстро"\n')
            with self.assertRaises(ValueError):
                load_config(f)


class DiffRenderTest(unittest.TestCase):
    """Дифф-отчёт: статусы правил и оценка метрик без tshark."""

    def test_render_statuses_and_deltas(self):
        from analyzer.report import TrendPoint, render_diff_html

        def pt(i, ts, metrics, recs):
            p = TrendPoint(path=Path(f"/tmp/d{i}.pcap"), start_ts=float(ts),
                           metrics=dict(metrics))
            for rid in recs:
                p.rec_ids.add(rid)
                p.rule_info[rid] = (
                    ("warning", "Старое правило") if rid == "old-rule"
                    else ("info", "Новое правило"))
            return p

        a = [pt(0, 1735000000, {"unans_pct": 20.0, "rtt_med_ms": 40.0},
                ["old-rule"]),
             pt(1, 1735000300, {"unans_pct": 22.0, "rtt_med_ms": 42.0},
                ["old-rule"])]
        b = [pt(2, 1735003600, {"unans_pct": 5.0, "rtt_med_ms": 39.0},
                ["new-rule"])]
        html = render_diff_html(a, b, "до", "после", "Анализ S7comm")
        self.assertIn("Сравнение периодов", html)
        # правило исчезло
        self.assertIn("исчез", html)
        # правило появилось
        self.assertIn("появился", html)
        # доля безответов упала с ~21% до 5% -> «лучше»
        self.assertIn("лучше", html)
        # RTT почти не изменилось (40->39 при размахе) — без оценки «хуже»
        self.assertIn("delta good", html)
        self.assertNotIn("delta bad", html)
        self.assertIn("улучшилось", html)
        self.assertIn("перестало срабатывать", html)


# ---------------------------------------------------------------------------
# SINEC H1 (S5 fetch/write): разбор сообщений и правила (без tshark)
# ---------------------------------------------------------------------------

#: Чтение DB200 DW0–51 и DB201 DW0–42 — как в образце pcap-sample
H1_READ_DB200 = bytes.fromhex("533510010305030801c800000034ff02")
H1_READ_DB201 = bytes.fromhex("533510010305030801c90000002bff02")
H1_WRITE_DB10 = bytes.fromhex("5335100103030308010a0000000aff02")


def h1_response(opcode: int, retcode: int) -> bytes:
    """Ответ H1: сигнатура, длина, блоки кода операции, кода ответа, хвост.

    Длина блока включает собственный заголовок (тип + длина), поэтому
    блок «код операции» с одним байтом — это ``01 03 <код>``.
    """
    body = bytes([0x01, 0x03, opcode, 0x0F, 0x03, retcode, 0xFF, 0x02])
    return b"S5" + bytes([len(body) + 3]) + body


def h1_addr(org: int, db: int, dwnr: int, dlen: int) -> bytes:
    """Блок адреса H1: тип памяти, номер блока, первое слово, длина."""
    return (bytes([0x03, 0x08, org, db]) + dwnr.to_bytes(2, "big")
            + dlen.to_bytes(2, "big"))


def h1_multi_read(*addrs) -> bytes:
    """Запрос чтения нескольких областей одним сообщением."""
    body = bytes([0x01, 0x03, 0x05]) + b"".join(addrs) + bytes([0xFF, 0x02])
    return b"S5" + bytes([len(body) + 3]) + body


def h1_read_response(dlen: int, retcode: int = 0) -> bytes:
    """Настоящий ответ PLC на чтение: заголовок без данных + сырой хвост.

    В ответе нет блока адреса и нет длины — возвращённые слова идут следом
    без заголовка блока, поэтому ``parse_h1_messages`` берёт их объём из
    ``expect_data`` (2 × dlen сопоставленного запроса).
    """
    body = bytes([0x01, 0x03, 0x06, 0x0F, 0x03, retcode,
                  0xFF, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00])
    head = b"S5" + bytes([len(body) + 3]) + body
    return head + bytes((i * 7) % 256 for i in range(2 * dlen))


def _expect_from_fifo(fifo):
    """Обратный вызов разбора с курсором — как в ветке sinec-h1."""
    from analyzer.branches.sinec_h1 import OP_READ_REQ, OP_READ_RSP
    state = {"seen": 0}

    def expect(msg):
        if msg.opcode != OP_READ_RSP:
            return 0
        for i in range(state["seen"], len(fifo)):
            if fifo[i][0] == OP_READ_REQ:
                state["seen"] = i + 1
                return 2 * fifo[i][2]
        return None
    return expect


def h1_write_request(*addrs, words=()) -> bytes:
    """Запрос записи: блоки адреса, затем блоки данных 0x09.

    Каждая группа ``words`` кладётся в свой блок 0x09 — так выглядит запись
    в H1: длина объявлена в заголовке сообщения, поэтому слова известны из
    блоков адреса.
    """
    data = b"".join(bytes([0x09, 2 + 2 * len(group)])
                    + b"".join(v.to_bytes(2, "big") for v in group)
                    for group in words)
    body = bytes([0x01, 0x03, 0x03]) + b"".join(addrs) + data + bytes([0xFF, 0x02])
    return b"S5" + bytes([len(body) + 3]) + body


def h1_read_response_words(values, retcode: int = 0) -> bytes:
    """Ответ PLC на чтение с заданными значениями слов."""
    body = bytes([0x01, 0x03, 0x06, 0x0F, 0x03, retcode,
                  0xFF, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00])
    head = b"S5" + bytes([len(body) + 3]) + body
    return head + b"".join(v.to_bytes(2, "big") for v in values)


def _res(values, cap: int = 100) -> Reservoir:
    """Reservoir, наполненный готовыми значениями."""
    r = Reservoir(cap)
    for v in values:
        r.add(v)
    return r


class H1ParserTest(unittest.TestCase):
    """Разбор цепочки сообщений H1 из tcp.payload."""

    def test_read_request(self):
        from analyzer.branches.sinec_h1 import parse_h1_messages
        msgs, used = parse_h1_messages(H1_READ_DB200)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(used, len(H1_READ_DB200))
        m = msgs[0]
        self.assertEqual(m.opcode, 5)                  # чтение, запрос
        self.assertTrue(m.is_request)
        self.assertFalse(m.is_response)
        self.assertEqual(m.org, 0x01)                  # DB
        self.assertEqual(m.db, 200)
        self.assertEqual(m.dwnr, 0)
        self.assertEqual(m.dlen, 52)
        self.assertEqual(m.words, 52)
        self.assertIsNone(m.retcode)
        self.assertFalse(m.error)
        self.assertFalse(m.truncated)
        self.assertEqual(m.area(), "DB200")
        self.assertEqual(m.op_key(), (5, 0x01, 200, 0, 52))

    def test_two_messages_in_one_segment(self):
        """Батчинг: два запроса в одном TCP-сегменте (главная причина)."""
        from analyzer.branches.sinec_h1 import parse_h1_messages
        buf = H1_READ_DB200 + H1_READ_DB201
        msgs, used = parse_h1_messages(buf)
        self.assertEqual(len(msgs), 2)
        self.assertEqual(used, len(buf))
        self.assertEqual([m.db for m in msgs], [200, 201])
        self.assertEqual([m.dlen for m in msgs], [52, 43])

    def test_trailing_foreign_payload_ignored(self):
        from analyzer.branches.sinec_h1 import parse_h1_messages
        tail = bytes.fromhex("deadbeef0102")
        msgs, used = parse_h1_messages(H1_READ_DB200 + tail)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(used, len(H1_READ_DB200),
                         "хвост чужого payload не должен consumption'ить")

    def test_truncated_message_not_parsed(self):
        from analyzer.branches.sinec_h1 import parse_h1_messages
        msgs, used = parse_h1_messages(H1_READ_DB200[:-4])
        self.assertEqual(msgs, [])
        self.assertEqual(used, 0)

    def test_block_overrun_marked_truncated(self):
        """Блок объявлен длиннее сообщения — сообщение не отбрасываем."""
        from analyzer.branches.sinec_h1 import parse_h1_messages
        bad = bytearray(H1_READ_DB200)
        bad[4] = 0x20                                 # длина блока адреса
        msgs, _used = parse_h1_messages(bytes(bad))
        self.assertEqual(len(msgs), 1)
        self.assertTrue(msgs[0].truncated)

    def test_response_retcode(self):
        from analyzer.branches.sinec_h1 import parse_h1_messages
        for code, is_err in ((0x00, False), (0x02, True), (0xFF, True)):
            msgs, _ = parse_h1_messages(h1_response(6, code))
            m = msgs[0]
            self.assertEqual(m.opcode, 6)              # чтение, ответ
            self.assertTrue(m.is_response)
            self.assertEqual(m.retcode, code)
            self.assertEqual(m.error, is_err)
            self.assertTrue(m.ret_text)

    def test_unknown_opcode_survives(self):
        from analyzer.branches.sinec_h1 import parse_h1_messages
        body = bytes([0x01, 0x03, 0x63, 0xFF, 0x02])
        msgs, used = parse_h1_messages(b"S5" + bytes([len(body) + 3]) + body)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(used, 8)
        m = msgs[0]
        self.assertEqual(m.opcode, 0x63)
        self.assertIsNone(m.org)                       # блока адреса не было
        self.assertFalse(m.is_request)
        self.assertFalse(m.is_response)
        self.assertFalse(m.truncated)

    def test_describe_message_rows(self):
        from analyzer.branches.sinec_h1 import describe_message
        rows = describe_message(H1_READ_DB200)
        text = " ".join(t for _o, _b, t in rows)
        self.assertIn("S5", text)
        self.assertIn("чтение", text)
        self.assertIn("DB200", text)
        self.assertIn("52 слов", text)
        self.assertIn("конец сообщения", text)
        self.assertEqual(describe_message(b"\x00\x01"), [])

    def test_read_response_data_taken_from_matched_request(self):
        """Ответ на чтение: данных нет в заголовке — длина из FIFO."""
        from analyzer.branches.sinec_h1 import (OP_READ_REQ,
                                                 parse_h1_messages)
        buf = h1_read_response(52)
        fifo = [(OP_READ_REQ, 0.0, 52)]
        msgs, used = parse_h1_messages(buf, expect_data=_expect_from_fifo(fifo))
        self.assertEqual(len(msgs), 1)
        self.assertEqual(used, len(buf), "хвост данных должен быть разобран")
        m = msgs[0]
        self.assertEqual(m.opcode, 6)
        self.assertEqual(m.retcode, 0)
        self.assertFalse(m.error)
        self.assertEqual(len(m.data), 104)
        self.assertEqual(m.data_words, 52)
        self.assertIsNone(m.org, "в ответе нет блока адреса")

    def test_two_responses_in_one_segment(self):
        """Два ответа в сегменте: каждому — своя длина из своей очереди."""
        from analyzer.branches.sinec_h1 import (OP_READ_REQ,
                                                 parse_h1_messages)
        buf = h1_read_response(52) + h1_read_response(43)
        fifo = [(OP_READ_REQ, 0.0, 52), (OP_READ_REQ, 1.0, 43)]
        msgs, used = parse_h1_messages(buf, expect_data=_expect_from_fifo(fifo))
        self.assertEqual(len(msgs), 2)
        self.assertEqual(used, len(buf))
        self.assertEqual([m.data_words for m in msgs], [52, 43])
        self.assertNotEqual(msgs[0].data, msgs[1].data)

    def test_error_response_data_left_to_segment_end(self):
        """Без сопоставленного запроса отклик приходит один — данные целиком."""
        from analyzer.branches.sinec_h1 import parse_h1_messages
        buf = h1_read_response(52, retcode=0x02)
        msgs, used = parse_h1_messages(buf)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(used, len(buf))
        self.assertTrue(msgs[0].error)
        self.assertEqual(msgs[0].data_words, 52)

    def test_describe_message_data_row(self):
        """Хвост ответа показывается отдельной строкой разбора."""
        from analyzer.branches.sinec_h1 import (describe_message,
                                                 parse_h1_messages)
        buf = h1_read_response(4)
        msgs, _ = parse_h1_messages(buf)
        rows = describe_message(msgs[0].raw, msgs[0].data)
        text = " ".join(t for _o, _b, t in rows)
        self.assertIn("возвращённые данные идут после неё", text)
        self.assertIn("8 Б = 4 слов", text)
        # без хвоста терминатор читается как конец сообщения
        only = describe_message(msgs[0].raw)
        self.assertIn("конец сообщения",
                      " ".join(t for _o, _b, t in only))

    def test_read_two_areas_in_one_request(self):
        """Два блока адреса в одном запросе: оба сохранены, слова summed."""
        from analyzer.branches.sinec_h1 import parse_h1_messages
        buf = h1_multi_read(h1_addr(0x01, 200, 0, 52),
                            h1_addr(0x01, 201, 0, 43))
        msgs, used = parse_h1_messages(buf)
        self.assertEqual(used, len(buf))
        m = msgs[0]
        self.assertTrue(m.multi_addr)
        self.assertEqual(m.addrs, [(1, 200, 0, 52), (1, 201, 0, 43)])
        self.assertEqual(m.words, 95, "сумма по обоим блокам")
        # синонимы остались от первого блока — на них завязаны h1.* поля tshark
        self.assertEqual((m.org, m.db, m.dwnr, m.dlen), (1, 200, 0, 52))
        self.assertEqual(m.areas_text(), "DB200 DW0–51 + DB201 DW0–42")

    def test_multi_area_op_key_and_helpers(self):
        from analyzer.branches.sinec_h1 import (op_all_addrs, op_areas, op_label,
                                                 op_name, op_words,
                                                 parse_h1_messages)
        m = parse_h1_messages(
            h1_multi_read(h1_addr(0x01, 200, 0, 52),
                          h1_addr(0x01, 201, 0, 43)))[0][0]
        op = m.op_key()
        self.assertEqual(op_name(op), "чтение DB200 DW0–51 + DB201 DW0–42")
        self.assertEqual(op_label(op), "чтение DB200 DW0-51 + DB201 DW0-42")
        self.assertEqual(op_words(op), 95, "слова суммируются по обоим блокам")
        self.assertEqual(op_all_addrs(op),
                         [(1, 200, 0, 52), (1, 201, 0, 43)])
        self.assertEqual(op_areas(op), [(0, 52), (0, 43)])
        # одиночная операция даёт прежний короткий ключ
        one = parse_h1_messages(H1_READ_DB200)[0][0].op_key()
        self.assertEqual(one, (5, 1, 200, 0, 52))

    def test_multi_area_response_data_length(self):
        """Ответ на комбинированный запрос: данных 2 × суммы dlen."""
        from analyzer.branches.sinec_h1 import (OP_READ_REQ,
                                                 parse_h1_messages)
        buf = h1_multi_read(h1_addr(0x01, 200, 0, 52),
                            h1_addr(0x01, 201, 0, 43)) + h1_read_response(95)
        fifo = [(OP_READ_REQ, 0.0, 95)]
        msgs, used = parse_h1_messages(buf, expect_data=_expect_from_fifo(fifo))
        self.assertEqual(used, len(buf))
        self.assertEqual(len(msgs), 2)
        self.assertEqual(msgs[1].data_words, 95)
        self.assertEqual(len(msgs[1].data), 190)

    def test_single_area_key_shape_unchanged(self):
        """Обычный запрос не должен ломать форму ключа операции."""
        from analyzer.branches.sinec_h1 import (op_all_addrs, op_areas, op_words,
                                                 parse_h1_messages)
        op = parse_h1_messages(H1_READ_DB200)[0][0].op_key()
        self.assertEqual(len(op), 5)
        self.assertEqual(op_words(op), 52)
        self.assertEqual(op_all_addrs(op), [(1, 200, 0, 52)])
        self.assertEqual(op_areas(op), [(0, 52)])

    def test_op_name_and_label(self):
        from analyzer.branches.sinec_h1 import op_label, op_name
        self.assertEqual(op_name((5, 0x01, 200, 0, 52)), "чтение DB200 DW0–51")
        self.assertEqual(op_name((5, 0x01, 201, 0, 1)), "чтение DB201 DW0")
        self.assertEqual(op_name((3, 0x01, 10, 4, 1), dash="-"),
                         "запись DB10 DW4")
        # по умолчанию — обычное тире, а не HTML-сущность: результат
        # попадает и в текст KPI, и в C.esc(...)
        self.assertNotIn("&", op_name((5, 0x01, 200, 0, 52)))
        self.assertEqual(op_label((5, 0x01, 200, 0, 52)), "DB200@0..51")
        # для записи метка-подпись не строится, остаётся читаемое имя операции
        self.assertEqual(op_label((3, 0x02, 8, 0, 4)), "запись MB8 DW0-3")

    def test_write_request_data_block(self):
        """Запись: блоки 0x09 разбираются в слова, объём сверяется с dlen."""
        from analyzer.branches.sinec_h1 import parse_h1_messages
        buf = h1_write_request(h1_addr(1, 10, 4, 2), words=[[1000, 2000]])
        msgs, used = parse_h1_messages(buf)
        self.assertEqual(used, len(buf))
        m = msgs[0]
        self.assertEqual(m.opcode, 3)
        self.assertTrue(m.is_write)
        self.assertEqual(m.addrs, [(1, 10, 4, 2)])
        self.assertEqual(m.wdata_words, 2)
        self.assertEqual(m.write_values, [1000, 2000])
        self.assertTrue(m.write_words_ok)

    def test_write_request_several_data_blocks(self):
        """Несколько блоков данных подряд — слова собираются в один хвост."""
        from analyzer.branches.sinec_h1 import parse_h1_messages
        buf = h1_write_request(h1_addr(1, 10, 0, 2), h1_addr(1, 11, 0, 1),
                               words=[[7, 8], [9]])
        m = parse_h1_messages(buf)[0][0]
        self.assertEqual(m.addrs, [(1, 10, 0, 2), (1, 11, 0, 1)])
        self.assertEqual(m.words, 3)
        self.assertEqual(m.write_values, [7, 8, 9])
        self.assertTrue(m.write_words_ok)

    def test_write_request_data_shorter_than_dlen(self):
        """Объём данных не совпадает с dlen — write_words_ok должно быть False."""
        from analyzer.branches.sinec_h1 import parse_h1_messages
        buf = h1_write_request(h1_addr(1, 10, 0, 4), words=[[1, 2]])
        m = parse_h1_messages(buf)[0][0]
        self.assertEqual(m.wdata_words, 2)
        self.assertEqual(m.words, 4)
        self.assertFalse(m.write_words_ok)

    def test_describe_message_write_rows(self):
        """Разбор записи по байтам показывает и адрес, и данные."""
        from analyzer.branches.sinec_h1 import describe_message
        buf = h1_write_request(h1_addr(1, 10, 4, 2), words=[[0x0A, 0x0B]])
        rows = describe_message(buf)
        types = [raw[0] for off, raw, _note in rows if off >= 3]
        self.assertIn(0x03, types, "блок адреса должен быть в разборе")
        self.assertIn(0x09, types, "блок данных записи должен быть в разборе")
        notes = " ".join(note for _b, _r, note in rows)
        self.assertIn("блок данных записи", notes)
        self.assertIn("10, 11", notes)


def _h1_branch():
    """Ветка sinec-h1 с подставленными атрибутами — только для правил."""
    from analyzer.branches.sinec_h1 import SinecH1Analyzer
    b = SinecH1Analyzer()
    b.cfg = Config()
    b.pcap = Path("sample.pcap")
    b.pcap_str = "sample.pcap"
    b.tshark = "tshark"
    b.progress = lambda m, pct=None: None
    return b


def _h1_pair(**kw):
    """Агрегат пары клиент→PLC для правил рекомендаций."""
    from analyzer.branches.sinec_h1 import _PairStats
    p = _PairStats(client="10.0.0.1", server="10.0.0.2",
                   server_ports={2000})
    for k, v in kw.items():
        setattr(p, k, v)
    return p


class H1RuleTest(unittest.TestCase):
    """Пороги правил ветки sinec-h1 (без tshark)."""

    def test_errors_below_threshold_silent(self):
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            req_msgs=100, resp_msgs=100,
            retcodes=Counter({0x00: 100}))}
        self.assertEqual(b._rule_errors(_General()), [])

    def test_errors_warning_and_critical(self):
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            req_msgs=100, resp_msgs=100,
            retcodes=Counter({0x00: 96, 0x02: 4}))}
        recs = b._rule_errors(_General())
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "warning")
        self.assertIn("не существует", " ".join(recs[0].evidence))
        b.cfg.critical_rate_pct = 1.0
        self.assertEqual(b._rule_errors(_General())[0].severity, "critical")

    def test_unanswered_below_threshold_silent(self):
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            req_msgs=1000, req_segs=1000, unacked=1)}   # 0.1% < 0.5%
        self.assertEqual(b._rule_unanswered(_General()), [])

    def test_unanswered_fires_with_examples(self):
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            req_msgs=100, req_segs=100, unacked=12, unacked_bytes=384,
            unacked_frames=[1, 2, 3])}
        recs = b._rule_unanswered(_General())
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "warning")
        self.assertIn("1, 2, 3", " ".join(recs[0].evidence))

    def test_slow_response_by_visible_rtt(self):
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        b.cfg.slow_rtt_p95_ms = 50.0
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            req_msgs=10, resp_msgs=10,
            rtt=_res([0.20, 0.25, 0.30, 0.31, 0.9]))}
        self.assertEqual(len(b._rule_slow_response(_General())), 1)

    def test_fast_response_silent(self):
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        b.cfg.slow_rtt_p95_ms = 50.0
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            req_msgs=10, resp_msgs=10,
            rtt=_res([0.001] * 10))}
        self.assertEqual(b._rule_slow_response(_General()), [])

    def test_repeats_only_on_adjacent_duplicates(self):
        """Фиксированная карта опроса чередует операции — это не повтор."""
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        alternating = _h1_pair(req_msgs=100)
        alternating.repeat_msgs = 0
        b._pairs = {("10.0.0.1", "10.0.0.2"): alternating}
        self.assertEqual(b._rule_repeats(_General()), [])

        stuck = _h1_pair(req_msgs=100, repeat_msgs=90, repeat_run_max=90,
                         repeat_examples=[7, 8])
        b._pairs = {("10.0.0.1", "10.0.0.2"): stuck}
        recs = b._rule_repeats(_General())
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "info")
        self.assertIn("7, 8", " ".join(recs[0].evidence))

    def test_retrans_needs_enough_traffic(self):
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        pair = _h1_pair(req_msgs=20, resp_msgs=20, retrans=2)
        b._pairs = {("10.0.0.1", "10.0.0.2"): pair}
        self.assertEqual(b._rule_retrans(_General()), [],
                         "на малом объёме шум ретраев не показываем")
        pair.req_msgs = pair.resp_msgs = 1000
        pair.retrans = 60                       # 3% — ниже порога 5%
        self.assertEqual(b._rule_retrans(_General()), [])
        pair.retrans = 120                      # 6% — warning
        recs = b._rule_retrans(_General())
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "warning")

    def test_one_sided_only_when_no_pair_answers(self):
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(req_msgs=10)}
        self.assertEqual(len(b._rule_one_sided(_General())), 1)
        b._pairs[("10.0.0.1", "10.0.0.2")].resp_msgs = 10
        self.assertEqual(b._rule_one_sided(_General()), [])

    def test_churn_requires_syns_and_rate(self):
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        gen = _General(first_ts=0.0, last_ts=600.0)     # 10 минут
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(req_msgs=100)}
        self.assertEqual(b._rule_churn(gen), [], "без SYN переподключений нет")
        gen.syn_to_ip["10.0.0.2"] = 20           # 2/мин — ниже порога 6/мин
        self.assertEqual(b._rule_churn(gen), [])
        gen.syn_to_ip["10.0.0.2"] = 90           # 9/мин
        recs = b._rule_churn(gen)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "warning")
        self.assertIn("2000", " ".join(recs[0].commands))


class H1ValuesTest(unittest.TestCase):
    """Учёт значений блоков памяти и записи (без tshark)."""

    def test_value_tracking_marks_stable_words(self):
        """Слова, не менявшиеся между чтениями, видно как статичные."""
        from analyzer.branches.sinec_h1 import SinecH1Analyzer, _BlockTrack
        pair = _h1_pair()
        b = SinecH1Analyzer()
        b.cfg = Config()
        addr = ((0x01, 200, 0, 4),)
        for vals in ([1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 9, 4]):
            data = b"".join(v.to_bytes(2, "big") for v in vals)
            b._track_values(pair, data, addr, 4, 10)
        track = pair.blocks[(0x01, 200, 0, 4)]
        self.assertEqual(track.reads, 3)
        self.assertEqual(track.changes, 1)
        self.assertEqual(track.changed_reads, 1)
        self.assertEqual(track.static_words, 3)
        self.assertAlmostEqual(track.static_share, 0.75)
        self.assertIsInstance(track, _BlockTrack)

    def test_value_tracking_respects_limits(self):
        """Слишком много диапазонов или слишком длинные — не отслеживаем."""
        from analyzer.branches.sinec_h1 import SinecH1Analyzer
        b = SinecH1Analyzer()
        b.cfg = Config()
        b.BLOCK_TRACK_MAX = 2
        pair = _h1_pair()
        data = b"\x00\x01" * 4
        for db in (1, 2, 3):
            b._track_values(pair, data, ((0x01, db, 0, 4),), 4, 10)
        self.assertEqual(len(pair.blocks), 2, "третий диапазон уже не пишем")

        pair2 = _h1_pair()
        b2 = SinecH1Analyzer()
        b2.cfg = Config()
        b2.BLOCK_WORDS_MAX = 8
        b2._track_values(pair2, b"\x00\x01" * 64, ((0x01, 1, 0, 64),), 64, 10)
        self.assertEqual(pair2.blocks, {}, "длинный диапазон пропускаем")

    def test_write_request_accounted(self):
        """Запись попадает в счётчики пары вместе со словами данных."""
        from analyzer.branches.sinec_h1 import parse_h1_messages
        msg = parse_h1_messages(
            h1_write_request(h1_addr(1, 10, 4, 2), words=[[5, 6]]))[0][0]
        pair = _h1_pair()
        pair.write_msgs = 1
        pair.write_words = msg.wdata_words
        self.assertEqual(pair.write_words, 2)
        self.assertTrue(msg.write_words_ok)

    def test_timer_quantum_rule(self):
        """Период, не кратный кванту таймера, — предупреждение."""
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        good = _h1_pair(period=_res([0.032] * 40))       # ровно квант
        b._pairs = {("10.0.0.1", "10.0.0.2"): good}
        self.assertEqual(b._rule_timer_quantum(_General()), [])

        # 96 мс = ровно 3 кванта — тоже молчим
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            period=_res([0.096] * 40))}
        self.assertEqual(b._rule_timer_quantum(_General()), [])

        # 25 мс против кванта 32 мс: отклонение 7 мс = 28% периода
        bad = _h1_pair(period=_res([0.025] * 40))
        b._pairs = {("10.0.0.1", "10.0.0.2"): bad}
        recs = b._rule_timer_quantum(_General())
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "info")
        self.assertIn("не кратен", recs[0].title)

    def test_timer_quantum_rule_severity_scales(self):
        from analyzer.branches.sinec_h1 import _General
        b = _h1_branch()
        # 150 мс: ближайшее кратное 160 мс, отклонение 10 мс = 6.7% периода
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            period=_res([0.150] * 40))}
        self.assertEqual(b._rule_timer_quantum(_General()), [])

        # 2000 мс: ближайшее кратное 1984 мс, отклонение 16 мс = 0.8%
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            period=_res([2.0] * 40))}
        self.assertEqual(b._rule_timer_quantum(_General()), [])

        # 20 мс против кванта 32 мс: отклонение 12 мс = 60% периода
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            period=_res([0.020] * 40))}
        recs = b._rule_timer_quantum(_General())
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "warning")

    def test_static_blocks_rule(self):
        """Диапазон, который не меняется, — повод перевести в медленный цикл."""
        from analyzer.branches.sinec_h1 import _BlockTrack, _General
        b = _h1_branch()
        track = _BlockTrack(words=8)
        track.update(1, [1, 2, 3, 4, 5, 6, 7, 8])
        for _ in range(9):
            track.update(2, [1, 2, 3, 4, 5, 6, 7, 8])
        pair = _h1_pair(resp_msgs=10, req_msgs=10)
        pair.blocks[(0x01, 200, 0, 8)] = track
        b._pairs = {("10.0.0.1", "10.0.0.2"): pair}
        recs = b._rule_static_blocks(_General())
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].severity, "info")
        self.assertIn("DB200", " ".join(recs[0].evidence))

    def test_static_blocks_rule_needs_reads_and_size(self):
        """Мало прочтений или слишком короткий диапазон — не показываем."""
        from analyzer.branches.sinec_h1 import _BlockTrack, _General
        b = _h1_branch()
        few = _BlockTrack(words=8)
        few.update(1, [1] * 8)
        pair = _h1_pair(resp_msgs=2, req_msgs=2)
        pair.blocks[(0x01, 200, 0, 8)] = few
        b._pairs = {("10.0.0.1", "10.0.0.2"): pair}
        self.assertEqual(b._rule_static_blocks(_General()), [])

        small = _BlockTrack(words=2)
        for _ in range(10):
            small.update(1, [1, 2])
        pair2 = _h1_pair(resp_msgs=10, req_msgs=10)
        pair2.blocks[(0x01, 200, 0, 2)] = small
        b._pairs = {("10.0.0.1", "10.0.0.2"): pair2}
        self.assertEqual(b._rule_static_blocks(_General()), [])

    def test_close_accounting_by_initiator(self):
        """FIN клиента, FIN PLC и RST считаются раздельно."""
        from analyzer.branches.sinec_h1 import SinecH1Analyzer
        b = SinecH1Analyzer()
        b.cfg = Config()
        pair = _h1_pair()
        b._pairs = {("10.0.0.1", "10.0.0.2"): pair}
        b._dir_role = {
            ("10.0.0.1", "10.0.0.2", 1): "client",
            ("10.0.0.2", "10.0.0.1", 1): "server",
            ("10.0.0.1", "10.0.0.2", 2): "client",
            ("10.0.0.2", "10.0.0.1", 2): "server",
            ("10.0.0.1", "10.0.0.2", 3): "client",
            ("10.0.0.2", "10.0.0.1", 3): "server",
        }
        pair.streams = {1, 2, 3}
        base = {"tcp.len": "0", "frame.number": "1"}
        b._on_close({**base, "tcp.flags.fin": "1", "tcp.flags.reset": "0"},
                    "10.0.0.1", "10.0.0.2", 1, 100.0)
        b._on_close({**base, "tcp.flags.fin": "1", "tcp.flags.reset": "0"},
                    "10.0.0.2", "10.0.0.1", 2, 101.0)
        b._on_close({**base, "tcp.flags.fin": "0", "tcp.flags.reset": "1"},
                    "10.0.0.2", "10.0.0.1", 3, 102.0)
        self.assertEqual(pair.streams_closed[1], ("клиент", 100.0))
        self.assertEqual(pair.streams_closed[2], ("PLC", 101.0))
        self.assertEqual(pair.streams_closed[3], ("rst", 102.0))
        # ничего не закрыто — текст объясняет, что это нормально
        pair2 = _h1_pair(streams={1})
        self.assertIn("открытым", b._streams_txt([pair2]))
        self.assertIn("осталось открытыми 0",
                      b._streams_txt([_h1_pair(streams={1},
                                               streams_closed={1: ("клиент", 1.0)})]))

    def test_return_codes_cover_access_errors(self):
        """Коды 0x01–0x0C расшифрованы, помечены как проблемы доступа."""
        from analyzer.branches.sinec_h1 import ACCESS_CODES, RETURN_CODES
        for code in range(0x01, 0x0D):
            self.assertIn(code, RETURN_CODES, f"код 0x{code:02x} не описан")
        self.assertIn(0x01, ACCESS_CODES)
        self.assertNotIn(0x00, ACCESS_CODES)
        self.assertNotIn(0x02, ACCESS_CODES, "нет блока — это не доступ")


class H1RegistrationTest(unittest.TestCase):
    """Ветка зарегистрирована и подписи метрик на месте."""

    def test_registered(self):
        from analyzer.branches import BRANCHES
        self.assertIn("sinec-h1", BRANCHES)
        self.assertEqual(BRANCHES["sinec-h1"].name, "sinec-h1")

    def test_metric_titles_cover_metrics(self):
        from analyzer.report.trend_report import METRIC_TITLES
        for key in ("h1_msgs", "h1_period_ms", "h1_ack_p95_ms",
                    "h1_busy_pct", "h1_ops", "h1_unans_pct",
                    "h1_words_per_s", "h1_write_msgs"):
            self.assertIn(key, METRIC_TITLES)

    def test_all_metrics_have_titles(self):
        """Каждая метрика ветки подписана в METRIC_TITLES (для trend/diff)."""
        from analyzer.branches.sinec_h1 import SinecH1Analyzer
        from analyzer.report.trend_report import METRIC_TITLES
        b = _h1_branch()
        from analyzer.branches.sinec_h1 import _General
        b._pairs = {("10.0.0.1", "10.0.0.2"): _h1_pair(
            req_msgs=10, resp_msgs=10, req_words=520, write_msgs=2)}
        metrics = b._metrics(_General(first_ts=0.0, last_ts=10.0))
        self.assertTrue(metrics)
        for key in metrics:
            self.assertIn(key, METRIC_TITLES, f"нет подписи для метрики {key}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
