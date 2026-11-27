"""Use pinned pyinstxtractor parser, extract only bounded entry scripts. Never load bytecode.

PYZ library extraction is deliberately not attempted by this adapter. Python version and
coverage are returned explicitly; pycdc may reject unsupported bytecode versions.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import zlib


def bounded_inflate(data, limit):
    dec = zlib.decompressobj()
    result = dec.decompress(data, limit + 1)
    if len(result) > limit or dec.unconsumed_tail or not dec.eof:
        raise ValueError("Compressed entry exceeds bound or is truncated")
    return result


def unpack(parser_path, sample, output):
    spec = importlib.util.spec_from_file_location("trusted_pyinstxtractor", parser_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    archive = module.PyInstArchive(str(sample))
    if not archive.open():
        raise ValueError("Cannot open input snapshot")
    try:
        if not archive.checkFile() or not archive.getCArchiveInfo():
            raise ValueError("Not a validated PyInstaller archive")
        if not 0 < archive.tableOfContentsSize <= 1_000_000 or archive.overlayPos < 0:
            raise ValueError("Invalid archive TOC")
        if archive.tableOfContentsPos < archive.overlayPos or archive.tableOfContentsPos + archive.tableOfContentsSize > archive.fileSize:
            raise ValueError("TOC is outside input")
        archive.parseTOC()
        if len(archive.tocList) > 5000:
            raise ValueError("Archive has too many entries")
        for entry in archive.tocList:
            if entry.position < archive.overlayPos or entry.cmprsdDataSize < 0 or entry.position + entry.cmprsdDataSize > archive.fileSize:
                raise ValueError("Entry bounds invalid")
        magic = None
        for entry in archive.tocList:
            if entry.typeCmprsData in (b'z', b'Z'):
                archive.fPtr.seek(entry.position)
                payload = archive.fPtr.read(entry.cmprsdDataSize)
                if entry.cmprsFlag:
                    payload = bounded_inflate(payload, 64_000_000)
                if payload[:4] == b'PYZ\0' and payload[6:8] == b'\r\n':
                    magic = payload[4:8]
                    break
        if magic is None:
            raise ValueError("No verified Python magic in PYZ; cannot create a valid pyc header")
        output.mkdir(parents=True, exist_ok=False)
        entries = []
        scripts = [e for e in archive.tocList if e.typeCmprsData == b's']
        if not scripts or len(scripts) > 32:
            raise ValueError("Unsupported entry-script count")
        total = 0
        for index, entry in enumerate(scripts):
            archive.fPtr.seek(entry.position)
            payload = archive.fPtr.read(entry.cmprsdDataSize)
            if entry.cmprsFlag:
                payload = bounded_inflate(payload, 4_000_000)
            if len(payload) != entry.uncmprsdDataSize or len(payload) > 4_000_000:
                raise ValueError("Script size mismatch")
            total += len(payload)
            if total > 32_000_000:
                raise ValueError("Extracted scripts exceed budget")
            header = magic + (b'\0' * (12 if (archive.pymaj, archive.pymin) >= (3, 7) else 8))
            name = f"entry_{index:02d}.pyc"
            target = output / name
            target.write_bytes(header + payload)
            entries.append({"entry_index": index, "archive_name": entry.name[:150],
                            "application_entry": not entry.name.startswith(('pyiboot', 'pyi_rth_')),
                            "artifact": name, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
        return {"python_version": f"{archive.pymaj}.{archive.pymin}", "entries": entries,
                "archive_entry_count": len(archive.tocList), "coverage": "entry scripts only; PYZ libraries not extracted"}
    finally:
        archive.close()


if __name__ == "__main__":
    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        result = unpack(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    print(json.dumps(result, ensure_ascii=False))
