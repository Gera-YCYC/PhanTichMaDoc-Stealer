"""Download the actual model parts and encrypted public samples from the pinned Release."""
import argparse
import json
from pathlib import Path
from urllib.parse import quote
from fetch_setup_assets import fetch

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--verify-only',action='store_true')
    args=parser.parse_args()
    lock=json.loads((ROOT/'config/release-assets.lock.json').read_text())
    base=ROOT/'private/release-assets'
    for asset in lock['assets']:
        item={**asset,'path':asset['file'],
              'url':'https://github.com/'+lock['repository']+'/releases/download/'+quote(lock['tag'],safe='')+'/'+quote(asset['file'],safe='')}
        fetch(item,base,args.verify_only)
        print('Verified '+asset['file'],flush=True)
    print('Encrypted samples remain encrypted on host. Import only with import_release_samples.py.')


if __name__=='__main__':
    main()
