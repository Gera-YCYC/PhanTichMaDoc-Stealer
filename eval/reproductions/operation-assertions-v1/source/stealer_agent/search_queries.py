"""Bounded literal navigation choices from projected, already retrieved text.

Lexical hints only: a matching identifier is not a resolved call or behavior.
The VM owns source parsing and literal search; this module neither opens samples
nor executes expressions. Quoted/comment text is excluded from name suggestions.
"""
import re

SEEDS = ('Login Data','password_value','cookie','token','UploadFile','urlbot',
         'webhook','SmtpClient','NetworkCredential','requests','send',
         'CryptUnprotectData','CopyFromScreen','Local State','base64','sendmail',
         'smtp','execute(','decrypt_password')
STRINGS = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' ''', re.VERBOSE)
CALL = re.compile(r'(?<![\w.])([A-Za-z_][A-Za-z_0-9]{2,79})\s*\(')
DEFINITION = re.compile(r'\bdef\s+([A-Za-z_][A-Za-z_0-9]{2,79})\s*\(')
SKIP = {'print','range','enumerate','isinstance','len','str','int','bytes','list',
        'dict','set','tuple','super','except','while','for','with','if','switch',
        'using','typeof','nameof','return','foreach','catch'}


def query_options(record, previous, *, limit=40):
    if not 1 <= limit <= 40:
        raise ValueError('Invalid query-choice budget')
    used = {query.strip().casefold() for query in previous}
    found, declared = {}, set()
    # Recent returned rows first; then earlier bounded observations. No reads
    # from the private full source store and no raw pre-projection strings.
    rows=record.get('line_map',{})
    numbers=list(dict.fromkeys(record.get('latest_lines',[])+sorted(rows,reverse=True)))[:800]
    for number in numbers:
        line=rows.get(number,'')
        if len(line)>2000 or '[REDACTED-' in line or line.lstrip().startswith(('#','//','/*','*')):
            continue
        code=STRINGS.sub('""',line).split('#',1)[0].split('//',1)[0]
        declared.update(DEFINITION.findall(code))
        for name in CALL.findall(code):
            if name not in SKIP and not name.startswith('__'):
                found.setdefault(name,number)
    names=sorted(found,key=lambda name:(name in declared,-found[name],name))[:24]
    # Keep a small stable set of first-search hints; source-derived names can
    # replace them as evidence arrives, without an unbounded decoding grammar.
    candidates=[]
    for value in [*names,*SEEDS]:
        if value.casefold() not in used and value.casefold() not in {s.casefold() for s in candidates}:
            candidates.append(value)
        if len(candidates)>=limit:
            break
    return candidates
