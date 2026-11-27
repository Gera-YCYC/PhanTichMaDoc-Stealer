"""Lock 37 signed OS tools and one official PyInstaller app before a frozen-rule scan."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
URL = 'https://github.com/yt-dlp/yt-dlp/releases/download/2024.08.06/'
DIGEST = '468a6f8bf1d156ad173e000a40f696d4fbd69c5aa7360229329b9063a388e7d0'


def main():
    stage = ROOT/'private/clean-challenge'
    windows = json.loads((stage/'windows-manifest.json').read_text(encoding='utf-8-sig'))
    if len(windows['rows']) != 37:
        raise ValueError('Expected exactly 37 signed OS files')
    app = stage/'clean_ytdlp_20240806.bin'
    sums = stage/'yt-dlp-2024.08.06.SHA2-256SUMS'
    if not sums.exists():
        urllib.request.urlretrieve(URL+'SHA2-256SUMS', sums)
    published = dict(line.split()[::-1] for line in sums.read_text().splitlines() if line.strip())
    if published.get('yt-dlp.exe') != DIGEST:
        raise ValueError('Official checksum differs from pinned release')
    if not app.exists():
        urllib.request.urlretrieve(URL+'yt-dlp.exe', app)
    if app.stat().st_size != 19_170_563 or hashlib.sha256(app.read_bytes()).hexdigest() != DIGEST:
        raise ValueError('Official app size/hash mismatch')
    for row in windows['rows']:
        data = (stage/row['sample']).read_bytes()
        if (hashlib.sha256(data).hexdigest() != row['sha256'] or len(data) != row['bytes'] or
                row['signature_status'] != 'Valid' or 'O=Microsoft Corporation' not in row['publisher']):
            raise ValueError('Clean Windows provenance mismatch')
    app_row = {'sample': app.name, 'sha256': DIGEST, 'bytes': app.stat().st_size, 'positive': False,
               'source': URL+'yt-dlp.exe', 'checksum_source': URL+'SHA2-256SUMS',
               'build_source': 'https://github.com/yt-dlp/yt-dlp/blob/2024.08.06/.github/workflows/build.yml',
               'version': '2024.08.06', 'packaging': 'PyInstaller 6.7.0 / Python 3.8 per official build workflow',
               'label_basis': 'Official open-source media downloader, expected non-stealer; not a claim every use is harmless',
               'signature_verification': 'Pinned SHA256 equals HTTPS official checksum; GPG signature not verified'}
    rows = windows['rows'] + [app_row]
    if len({r['sha256'] for r in rows}) != 38:
        raise ValueError('Challenge contains duplicate bytes')
    old = json.loads((ROOT/'eval/corpora/real-yara-v1.json').read_text())
    lock = {'schema_version': 1, 'dataset_origin': 'real-clean-challenge-38/2',
            'corpora': {'training': old['corpora']['training'], 'holdout': [
                {k: r[k] for k in ('sample', 'sha256', 'positive')} for r in rows]},
            'source_manifest': {'rows': rows, 'sample_execution': False},
            'prior_clean_hashes': [r['sha256'] for r in old['corpora']['holdout']],
            'selection_basis': 'All 31 explicitly named Framework64 utilities plus six OS tools and one historical official PyInstaller app; selected before frozen-rule scan',
            'limits': ['Includes eight previously tested negatives plus 30 new challenge negatives.',
                       'Five malware specimens remain development; no unseen positive sensitivity.',
                       'One clean PyInstaller app is a hard negative, not complete Python ecosystem coverage.',
                       'Do not use challenge outcome to tune and still call the same set unseen holdout.']}
    output = ROOT/'eval/corpora/real-yara-challenge-v2.json'
    if output.exists() and json.loads(output.read_text()) != lock:
        raise ValueError('Existing lock differs; use a new revision')
    output.write_text(json.dumps(lock, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'clean': len(rows), 'new_clean': 30, 'lock': str(output)}))


if __name__ == '__main__':
    main()
