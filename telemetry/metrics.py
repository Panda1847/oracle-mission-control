"""In-memory metrics registry with Prometheus-style export."""

from __future__ import annotations

from collections import defaultdict
from threading import RLock
from typing import Dict, Iterable, Tuple


def _key(name: str, labels: dict | None) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
    normalized = tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items()))
    return name, normalized


class MetricRegistry:
    """Lightweight counter/gauge/histogram registry for dashboard and API use."""

    def __init__(self):
        self._lock = RLock()
        self._counters = defaultdict(float)
        self._gauges = defaultdict(float)
        self._histograms = defaultdict(list)

    def inc(self, name: str, amount: float = 1.0, labels: dict | None = None):
        with self._lock:
            self._counters[_key(name, labels)] += amount

    def set_gauge(self, name: str, value: float, labels: dict | None = None):
        with self._lock:
            self._gauges[_key(name, labels)] = value

    def observe(self, name: str, value: float, labels: dict | None = None):
        with self._lock:
            self._histograms[_key(name, labels)].append(float(value))

    def snapshot(self) -> Dict[str, dict]:
        with self._lock:
            counters = {self._format_metric(name, labels): value for (name, labels), value in self._counters.items()}
            gauges = {self._format_metric(name, labels): value for (name, labels), value in self._gauges.items()}
            histograms = {
                self._format_metric(name, labels): {
                    "count": len(values),
                    "min": min(values) if values else 0.0,
                    "max": max(values) if values else 0.0,
                    "avg": (sum(values) / len(values)) if values else 0.0,
                }
                for (name, labels), values in self._histograms.items()
            }
        return {"counters": counters, "gauges": gauges, "histograms": histograms}

    def prometheus_text(self) -> str:
        payload = []
        snapshot = self.snapshot()
        for section_name, section in snapshot.items():
            for metric_name, value in section.items():
                if isinstance(value, dict):
                    for stat_name, stat_value in value.items():
                        payload.append(f"{metric_name}_{stat_name} {stat_value}")
                else:
                    payload.append(f"{metric_name} {value}")
        return "\n".join(payload)

    def _format_metric(self, name: str, labels: Iterable[Tuple[str, str]]) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{key}="{value}"' for key, value in labels)
        return f"{name}{{{label_str}}}"


GLOBAL_METRICS = MetricRegistry()

