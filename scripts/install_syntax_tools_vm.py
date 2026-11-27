"""Fixed offline upgrade path; no packages, sample paths or commands from the SLM."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile

assets = Path('/home/labadmin/syntax-tools')
destination = Path('/opt/stealer-lab/deps').resolve()
manifest = json.loads((assets/'syntax-assets.json').read_text())
if len(manifest) != 3:
    raise ValueError('Expected three parser assets')
for row in manifest:
    if Path(row['file']).name != row['file'] or not row['file'].startswith(('tree_sitter-', 'tree_sitter_python-', 'tree_sitter_c_sharp-')):
        raise ValueError('Unexpected wheel path')
    path = assets/row['file']
    if path.stat().st_size != row['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
        raise ValueError('Wheel hash mismatch')
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            name = PurePosixPath(entry.filename)
            if name.is_absolute() or '..' in name.parts or '\\' in entry.filename or stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError('Invalid wheel member')
            if not (destination/entry.filename).resolve().is_relative_to(destination):
                raise ValueError('Wheel escapes dependencies directory')
        archive.extractall(destination)
(destination/'syntax-assets.json').write_text(json.dumps(manifest, indent=2))
print('Installed three verified parser wheels into project dependencies; no network used.')
