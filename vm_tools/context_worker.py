"""Fixed entry point for bounded source parsing inside the analysis VM."""
import json
from pathlib import Path
import sys
from .syntax_context import related_contexts

if len(sys.argv) != 2:
    raise SystemExit('Expected one trusted snapshot path')
path = Path(sys.argv[1])
if not path.is_absolute() or path.stat().st_size > 5_000_000:
    raise SystemExit('Invalid context snapshot')
request = json.loads(path.read_text(encoding='utf-8'))
print(json.dumps(related_contexts(request['record'], request['anchors']), ensure_ascii=False))
