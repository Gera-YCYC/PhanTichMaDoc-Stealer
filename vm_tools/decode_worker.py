"""Invoked only by the bounded VM runner with an internally generated record path."""
import json
from pathlib import Path
import sys
from .literal_decoder import recover

if __name__=='__main__':
    path=Path(sys.argv[1])
    if path.stat().st_size>4_000_000: raise ValueError('Input evidence exceeds bound')
    print(recover(json.loads(path.read_text(encoding='utf-8'))))
