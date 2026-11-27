"""Bounded UTF-8 and ASCII-range UTF-16LE strings, with original byte offsets.

This reads data only. It does not decode obfuscation or replace FLOSS.
"""
import re

BACKEND = 'native-utf8-utf16le/2'
MAX_STRINGS = 700
MAX_VALUE_CHARS = 1500
# surrogateescape represents each invalid byte by one low surrogate. Treat it
# as a boundary, never drop it and join two unrelated fragments into a string.
UTF8_RUN = re.compile(r'[^\x00-\x1f\x7f-\x9f\udc80-\udcff\u2028\u2029\ufeff]{5,}')
ASCII_WIDE = re.compile(rb'(?:[\x20-\x7e]\x00){5,}')


def extract_strings(data):
    decoded = data.decode('utf-8', errors='surrogateescape')
    rows, limits = [], []
    char_cursor = byte_cursor = 0
    values_truncated = False
    for index, match in enumerate(UTF8_RUN.finditer(decoded)):
        if index >= MAX_STRINGS:
            limits.append('UTF-8 collection capped at 700 strings')
            break
        byte_cursor += len(decoded[char_cursor:match.start()].encode('utf-8', errors='surrogateescape'))
        value = match.group()
        encoding = 'ascii' if value.isascii() else 'utf-8'
        rows.append(f'offset=0x{byte_cursor:x} encoding={encoding} value={value[:MAX_VALUE_CHARS]}')
        values_truncated |= len(value) > MAX_VALUE_CHARS
        byte_cursor += len(value.encode('utf-8'))
        char_cursor = match.end()
    del decoded
    for index, match in enumerate(ASCII_WIDE.finditer(data)):
        if index >= MAX_STRINGS:
            limits.append('UTF-16LE collection capped at 700 strings')
            break
        value = match.group().decode('utf-16le')
        rows.append(f'offset=0x{match.start():x} encoding=utf-16le value={value[:MAX_VALUE_CHARS]}')
        values_truncated |= len(value) > MAX_VALUE_CHARS
    if values_truncated:
        limits.append('One or more values truncated at 1500 characters')
    limits.append('UTF-16LE scan covers ASCII-range characters only; other wide characters and encoded/decoded strings may be missed')
    return '\n'.join(rows), BACKEND, limits
