"""Sample whole-machine available RAM and NVIDIA memory during one host-side run."""
from __future__ import annotations

import shutil
import subprocess
import threading
import time

from .telemetry import available_memory_bytes


class ResourceWindow:
    """Opt-in operator telemetry. The sampling thread lasts for the context only."""

    def __init__(self, interval=2.0):
        self.interval = interval
        self._stop = threading.Event()
        self._thread = None
        self._gpu_binary = shutil.which('nvidia-smi')
        self._previous = None
        self.metrics = {
            'scope': 'Host-wide available RAM and NVIDIA GPU memory, including other processes',
            'target_interval_s': interval, 'samples': 0, 'ram_samples': 0, 'gpu_samples': 0,
            'max_sample_gap_s': None, 'minimum_available_ram_bytes': None,
            'gpu_peak_used_mib_by_index': {}, 'gpu_total_mib_by_index': {},
        }

    def _read_gpus(self):
        if not self._gpu_binary:
            return {}
        try:
            raw = subprocess.run([self._gpu_binary, '--query-gpu=index,memory.used,memory.total',
                                  '--format=csv,noheader,nounits'], check=True, capture_output=True,
                                 text=True, timeout=3, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            devices = {}
            for line in raw.stdout.splitlines():
                index, used, total = map(int, line.split(','))
                if index < 0 or not 0 <= used <= total or total == 0 or index in devices:
                    return {}
                devices[index] = (used, total)
            return devices
        except (OSError, subprocess.SubprocessError, ValueError):
            return {}

    def _sample(self):
        now = time.monotonic()
        metrics = self.metrics
        if self._previous is not None:
            gap = round(now - self._previous, 4)
            metrics['max_sample_gap_s'] = max(metrics['max_sample_gap_s'] or 0, gap)
        self._previous = now
        metrics['samples'] += 1
        available = available_memory_bytes()
        if available is not None:
            metrics['ram_samples'] += 1
            old = metrics['minimum_available_ram_bytes']
            metrics['minimum_available_ram_bytes'] = available if old is None else min(old, available)
        devices = self._read_gpus()
        metrics['gpu_samples'] += bool(devices)
        for index, (used, total) in devices.items():
            peak = metrics['gpu_peak_used_mib_by_index']
            peak[str(index)] = max(peak.get(str(index), 0), used)
            metrics['gpu_total_mib_by_index'][str(index)] = total

    def _collect(self):
        while not self._stop.wait(self.interval):
            self._sample()

    def __enter__(self):
        self._sample()
        self._thread = threading.Thread(target=self._collect, name='host-resource-observer', daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()
        self._sample()
