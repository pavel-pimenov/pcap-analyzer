"""Юнит-тесты чистой логики: перцентили, Reservoir, merge_ranges,
правила рекомендаций Modbus и потоковый разбор multipart (без tshark).

Запуск: python3 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyzer.branches.base import (                             # noqa: E402
    Reservoir, percentile)
from analyzer.branches.modbus_tcp import (                       # noqa: E402
    GeneralStats, ModbusTcpAnalyzer, PairStats, PollTarget, merge_ranges)
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
        return {"exc_total": exc, "resp_total": resp,
                "exc_counter": {(("10.0.0.1"), 1, 2): exc}}

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
