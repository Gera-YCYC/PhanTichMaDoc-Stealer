import json
import shutil

import pytest

from scripts import replay_card_report as replay


def test_measured_reporter_loads_only_after_all_dependency_hashes_match():
    callback, manifest, path = replay.select_reporter('operations', True)
    assert callback.__module__ == '_stealer_report_measured_v1.operation_assertions'
    assert path.endswith('/source/stealer_agent/operation_assertions.py')
    assert 'stealer_agent/grounding.py' in manifest
    _, _, current = replay.select_reporter('operations')
    assert current == 'stealer_agent/operation_assertions.py'
    with pytest.raises(ValueError): replay.select_reporter('cards', True)


def test_modified_dependency_cannot_be_presented_as_measured_revision(tmp_path, monkeypatch):
    folder = replay.ROOT / 'eval/reproductions/operation-assertions-v1'
    manifest = json.loads((folder / 'manifest.json').read_text())
    for name in manifest:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(replay.ROOT / name, target)
    target_folder = tmp_path / 'eval/reproductions/operation-assertions-v1'
    shutil.copytree(folder, target_folder)
    (target_folder / 'source/stealer_agent/grounding.py').write_text('changed dependency', encoding='utf8')
    monkeypatch.setattr(replay, 'ROOT', tmp_path)
    with pytest.raises(ValueError, match='dependency changed'):
        replay.select_reporter('operations', True)
