"""Keep the course registry ID on the controller side of a single analysis."""
from dataclasses import dataclass
import json
from pathlib import Path

from .demo_samples import CLEAN, MALWARE


@dataclass(frozen=True)
class SampleBinding:
    sample: str

    @property
    def alias(self):
        return "case.py" if self.sample.lower().endswith(".py") else "case.bin"

    def contains_registry_data(self, value):
        text = json.dumps(value, ensure_ascii=False).casefold()
        return any(term.casefold() in text for term in (Path(self.sample).stem, CLEAN, MALWARE))

    def check_request(self, fields):
        for key, value in fields.items():
            if self.contains_registry_data(value):
                raise RuntimeError(f"Registry identifier in {key}; stopped before inference")

    def vm_arguments(self, arguments):
        if arguments.get("sample") != self.alias:
            raise ValueError("Model attempted to change the authorized sample ID")
        return {**arguments, "sample": self.sample}
