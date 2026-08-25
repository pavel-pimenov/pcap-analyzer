"""Пороговые значения и константы для правил рекомендаций.

Все значения можно менять здесь, не трогая логику анализа.
"""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # --- Ограничения разбора -------------------------------------------------
    max_intervals_per_target: int = 5000   # максимум интервалов опроса на цель
    max_rtts_per_pair: int = 20000         # максимум времён отклика на пару
    timeline_bucket_sec: int = 60          # ширина бакета графика активности, сек
    gantt_window_sec: float = 10.0         # ширина окна диаграммы Ганта, сек
    gantt_zoom_sec: float = 1.0            # ширина «зум-»диаграммы Ганта, сек
    gantt_burst_sec: float = 0.1           # ширина окна «пачки» запросов, сек
    max_rows_per_table: int = 25           # максимум строк в таблицах отчёта
    max_upload_bytes: int = 1 << 30        # лимит загрузки pcap в веб-GUI

    # --- Ограничения структур прохода (память) --------------------------------
    valtrack_max_registers: int = 300_000  # максимум отслеживаемых регистров
    small_reads_max_items: int = 400_000   # буфер мелких чтений на пару
    writes_single_max_items: int = 200_000 # буфер одиночных записей на пару
    pending_fifo_max_keys: int = 50_000    # ключи FIFO-страховки сопоставления
    unanswered_examples: int = 10          # примеров кадров без ответа в отчёте

    # --- Правило: объединение мелких чтений ----------------------------------
    small_read_max_words: int = 4          # запрос с <=N регистров считается «мелким»
    batch_max_words: int = 125             # лимит регистров в одном Modbus-запросе чтения
    merge_window_sec: float = 1.0          # окно группировки мелких запросов
    merge_saving_pct: float = 20.0         # порог выгоды для рекомендации, % сокращения запросов
    merge_reads_min_total: int = 20        # минимум мелких чтений для оценки правила

    # --- Правило: шторм одиночных записей (FC5/FC6 -> FC16) -------------------
    write_spam_min_ops: int = 10           # минимум одиночных записей за захват
    write_batch_max_words: int = 123       # лимит регистров в FC16

    # --- Правило: частые переподключения --------------------------------------
    conn_churn_per_min: float = 6.0        # SYN к порту 502 чаще N/мин
    conn_churn_pair_min: int = 3           # ...или одна пара подключилась >= N раз
    short_stream_sec: float = 60.0         # «короткое» соединение

    # --- Правило: медленные серверы ------------------------------------------
    slow_rtt_p95_ms: float = 100.0         # p95 времени отклика выше порога

    # --- Правило: доля исключений/таймаутов ----------------------------------
    exception_rate_pct: float = 0.5        # доля ответов-исключений, %
    no_response_rate_pct: float = 0.5      # доля запросов без ответа, %
    critical_rate_pct: float = 5.0         # доля для уровня «критично», %

    # --- Правило: статичные регистры -----------------------------------------
    static_reg_min_reads: int = 20         # минимум чтений регистра для оценки
    static_reg_change_pct: float = 5.0     # значение меняется реже чем в N% чтений -> статичный
    static_reg_min_candidates: int = 10    # минимум кандидатов для правила
    static_share_pct: float = 30.0         # доля статичных среди кандидатов, %

    # --- Правило: давление опроса ----------------------------------------------
    poll_pressure_factor: float = 2.0      # интервал опроса ≤ N×RTT — давление
    poll_pressure_min_intervals: int = 10  # минимум интервалов на цель для оценки

    # --- Ветка S7comm ----------------------------------------------------------
    s7_item_error_pct: float = 0.5         # доля ответов с ошибками элементов, %
    s7_setup_comm_warn: int = 5            # повторных установок связи для рекомендации
    s7_single_read_min: int = 50           # минимум чтений Read Var для совета о группировке
    s7_single_read_pct: float = 80.0       # доля запросов с одним элементом, %
    s7_no_response_warn_pct: float = 10.0  # доля Job без Ack_Data для warning, %
    s7_dead_min_syns: int = 5              # SYN к «молчащему» узлу :102 для рекомендации
    s7_max_pending_per_ref: int = 8        # очередь Job на один (поток, pduref)
    s7_rtt_sanity_max_sec: float = 30.0    # RTT выше — считаем транзакцию потерянной
    s7_pipeline_warn_depth: int = 8        # p95 незакрытых Job на пару для предупреждения

    # --- Ветка сервисов (TCP/UDP) ---------------------------------------------
    svc_heartbeat_max_bytes: int = 16      # нагрузка ≤N байт — «сердцебиение»
    svc_cyclic_cv_strict: float = 0.25     # CV ниже — строгий цикл опроса
    svc_cyclic_cv_moderate: float = 0.60   # CV ниже — умеренная регулярность
    svc_min_msgs_for_period: int = 20      # минимум сообщений для оценки периодики
    svc_retrans_warn_pct: float = 5.0      # доля ретрансляций для предупреждения, %
    svc_one_way_pct: float = 99.0          # перекос направления потока, %
    svc_one_way_min_kb: int = 64           # минимальный объём одностороннего потока, КБ
    arp_storm_per_min: float = 30.0        # ARP-кадров в минуту для предупреждения

    # --- Прочее ---------------------------------------------------------------
    top_registers_limit: int = 20          # топ-N регистров в отчёте
    skip_gantt: bool = False               # пропускать диаграммы Ганта (режим трендов)
    display_tz_offset: float | None = None  # зона показа времени, часов от UTC
    trend_anomaly_k: float = 5.0           # порог выброса в трендах, масштабов MAD


# Экземпляр по умолчанию
DEFAULT_CONFIG = Config()


def load_config(path: Path) -> Config:
    """Загрузить конфигурацию из TOML-файла поверх значений по умолчанию.

    В файле задаются только те пороги, которые нужно переопределить:

        [modbus]
        slow_rtt_p95_ms = 150.0

        [services]
        arp_storm_per_min = 60.0

    Имена секций игнорируются (удобно группировать по веткам), ключи
    должны совпадать с полями Config. Неизвестный ключ или неверный тип —
    ошибка с понятным сообщением.
    """
    with open(path, "rb") as f:
        data = tomllib.load(f)
    flat: dict[str, object] = {}
    for section, values in data.items():
        if not isinstance(values, dict):
            raise ValueError(
                f"{path}: секция [{section}] должна содержать пары "
                "ключ=значение")
        flat.update(values)
    defaults = DEFAULT_CONFIG
    valid = {f.name: f.type for f in
             __import__("dataclasses").fields(Config)}
    unknown = sorted(set(flat) - set(valid))
    if unknown:
        raise ValueError(
            f"{path}: неизвестные ключи: {', '.join(unknown)}. Допустимо: "
            + ", ".join(sorted(valid)))
    coerced: dict[str, object] = {}
    hints = {f.name: f.type for f in
             __import__("dataclasses").fields(defaults)}
    for k, v in flat.items():
        hint = str(hints[k])
        if hint.startswith("bool"):
            if not isinstance(v, bool):
                # допускаем строки «true/false» из других форматов
                if isinstance(v, str) and v.lower() in ("true", "false"):
                    v = v.lower() == "true"
                else:
                    raise ValueError(f"{path}: {k} ожидает true/false")
        elif hint.startswith("int"):
            if not isinstance(v, int) or isinstance(v, bool):
                raise ValueError(f"{path}: {k} ожидает целое число")
        elif hint.startswith("float"):
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError(f"{path}: {k} ожидает число")
            v = float(v)
        coerced[k] = v
    return replace_cfg(defaults, **coerced)


def replace_cfg(cfg: Config, **kw) -> Config:
    """dataclasses.replace без импорта в нескольких местах."""
    from dataclasses import replace
    return replace(cfg, **kw)
