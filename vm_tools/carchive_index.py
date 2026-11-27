"""Read a bounded PyInstaller 2.1+ CArchive TOC, never decompress or execute.

Wire layout: PyInstaller v6.7.0 PyInstaller/archive/readers.py. Only metadata
coordinates are used; these names identify a build, not malicious behavior.
"""
import struct

MAGIC = b'MEI\x0c\x0b\x0a\x0b\x0e'
COOKIE = struct.Struct('!8sIIii64s')
ENTRY = struct.Struct('!iIIIBB')


def application_names(data):
    position = data.rfind(MAGIC)
    if position < 0:
        return {'status': 'not_detected', 'application_entries': []}
    if position + COOKIE.size > len(data):
        raise ValueError('Truncated CArchive cookie')
    _, length, toc, size, version, library = COOKIE.unpack_from(data, position)
    base = position + COOKIE.size - length
    start, end = base + toc, base + toc + size
    if not (0 <= base <= start < end <= position and 0 < size <= 1_000_000 and
            20 <= version <= 3999 and library.rstrip(b'\x00')):
        raise ValueError('CArchive cookie bounds invalid')
    current, count, rows = start, 0, []
    while current < end:
        if count >= 5000 or current + ENTRY.size > end:
            raise ValueError('CArchive TOC count/header limit')
        entry_size, offset, compressed, uncompressed, flag, kind = ENTRY.unpack_from(data, current)
        if not (ENTRY.size < entry_size <= end-current and flag in (0, 1) and
                base <= base+offset <= position and base+offset+compressed <= position):
            raise ValueError('CArchive entry bounds invalid')
        raw_name = data[current+ENTRY.size:current+entry_size].rstrip(b'\x00')
        if b'\x00' in raw_name:
            raise ValueError('CArchive entry has an embedded terminator')
        if kind == ord('s') and 4 <= len(raw_name) <= 149 and all(32 <= c <= 126 for c in raw_name):
            name = raw_name.decode('ascii')
            if not name.startswith(('pyiboot', 'pyi_rth_')):
                # Include the actual TOC type byte. This is a byte substring in the
                # original archive, not a filename invented from decompiled source.
                rows.append({'value': 's'+name, 'encoding': 'ascii', 'offset': current+ENTRY.size-1,
                             'selection_score': 100, 'kind': 'application_entry_identity',
                             'archive_name': name})
        current += entry_size
        count += 1
    if len(rows) > 32:
        raise ValueError('Too many application scripts')
    return {'status': 'validated_toc', 'python_version_code': version,
            'entry_count': count, 'application_entries': rows}
