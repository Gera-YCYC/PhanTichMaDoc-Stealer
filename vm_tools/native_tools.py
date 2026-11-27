"""Fixed-argument DIE/FLOSS adapters with pinned executables and bounded output."""
import hashlib
import json
from pathlib import Path
from .runner import bounded_process


class NativeTools:
    def __init__(self, config):
        self.config = config

    def available(self, name):
        try:
            return Path(self.config.get(name, '')).is_file() and len(self.config.get(name+'_sha256', '')) == 64
        except OSError:
            return False

    def analyze(self, name, data, sample, *, is_dotnet=False):
        if name not in ('diec', 'floss') or not self.available(name):
            raise FileNotFoundError('Pinned native tool is unavailable')
        exe = Path(self.config[name]).resolve()
        with exe.open('rb') as handle:
            if hashlib.file_digest(handle, 'sha256').hexdigest() != self.config[name+'_sha256']:
                raise ValueError('Native tool executable differs from installed digest')
        digest = hashlib.sha256(data).hexdigest()
        work = Path(self.config['evidence_dir'])
        snapshot = work/'inputs'/digest/sample
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        if not snapshot.exists():
            snapshot.write_bytes(data)
        if hashlib.sha256(snapshot.read_bytes()).hexdigest() != digest:
            raise ValueError('Immutable sample snapshot changed')
        limits = ['Static tool output is evidence of file properties/strings, not proof of executed behavior']
        if name == 'diec':
            database = Path(self.config['diec_database']).resolve()
            libraries = Path(self.config['diec_library_dir']).resolve()
            if not database.is_dir() or not libraries.is_dir():
                raise FileNotFoundError('Pinned DIE database/libraries are unavailable')
            argv = [str(exe), '--json', '--database', str(database), str(snapshot.resolve())]
            env = {'LD_LIBRARY_PATH':str(libraries)}
        else:
            argv = [str(exe), '--json', '--quiet']
            if is_dotnet:
                argv.extend(['--only', 'static'])
                limits.append('Managed .NET uses FLOSS static strings only; native x86 emulation is not CIL string deobfuscation')
            argv.extend(['--', str(snapshot.resolve())])
            env = {'FLOSS_LOAD_VIV_WORKSPACE':'0', 'PYTHONDONTWRITEBYTECODE':'1'}
            limits.append('Existing .viv workspaces are disabled; native decoded/stack analysis uses emulation, never launches the sample')
        raw = bounded_process(argv, work/'work', timeout=self.config.get('tool_timeout_s',90),
                              max_bytes=16_000_000 if name == 'floss' else 2_000_000,
                              memory_limit=True, env_overrides=env,
                              address_space_limit=4_000_000_000 if name == 'diec' else 1_500_000_000)
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError('Native tool did not return a JSON object')
        if name == 'floss':
            if not isinstance(parsed, dict) or not isinstance(parsed.get('strings'), dict):
                raise ValueError('FLOSS did not return expected structured strings')
            rows, counts, clipped = [], {}, 0
            fields = ('string','offset','encoding','address','address_type','decoded_at','decoding_routine',
                      'function','program_counter','frame_offset')
            for category in ('static_strings','stack_strings','tight_strings','decoded_strings'):
                values = parsed['strings'].get(category, [])
                if not isinstance(values, list):
                    raise ValueError('Invalid FLOSS string category')
                counts[category] = len(values)
                for item in values[:150]:
                    if not isinstance(item, dict):
                        raise ValueError('Invalid FLOSS string record')
                    row = {'category':category}
                    for field in fields:
                        value = item.get(field)
                        if isinstance(value, str):
                            clipped += len(value) > 1500
                            row[field] = value[:1500]
                        elif isinstance(value, (int, float)):
                            row[field] = value
                    rows.append(row)
            parsed = {'tool':'floss', 'mode':'managed_static_only' if is_dotnet else 'native_default',
                      'counts':counts, 'strings':rows, 'values_truncated':clipped}
            if any(n > 150 for n in counts.values()) or clipped:
                limits.append('Model evidence capped at 150 strings per category and 1500 characters per value; counts retain full tool totals')
        backend = name+'/'+self.config.get(name+'_version', 'unknown')
        return json.dumps(parsed, ensure_ascii=False, indent=2), backend, limits
