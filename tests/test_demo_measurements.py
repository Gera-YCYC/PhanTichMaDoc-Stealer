import pytest

from stealer_agent.resource_window import ResourceWindow
from stealer_agent.yara_case import select_row


def test_yara_sample_match_requires_both_identities_and_consistent_rule_list():
    row = {'sample': 'case.bin', 'sha256': 'a' * 64, 'matched': True, 'rules': ['LabCorpus_01']}
    assert select_row({'results': [row]}, 'case.bin', 'a' * 64) == row
    with pytest.raises(ValueError, match='one scanned file'):
        select_row({'results': [row]}, 'case.bin', 'b' * 64)
    with pytest.raises(ValueError, match='Invalid YARA'):
        select_row({'results': [{**row, 'matched': False}]}, 'case.bin', 'a' * 64)


def test_missing_gpu_does_not_become_a_zero_memory_measurement(monkeypatch):
    monkeypatch.setattr('stealer_agent.resource_window.shutil.which', lambda name: None)
    monkeypatch.setattr('stealer_agent.resource_window.available_memory_bytes', lambda: None)
    with ResourceWindow(30) as observer:
        pass
    assert observer.metrics['samples'] >= 2 and observer.metrics['gpu_samples'] == 0
    assert observer.metrics['minimum_available_ram_bytes'] is None
    assert observer.metrics['gpu_peak_used_mib_by_index'] == {} and not observer._thread.is_alive()
