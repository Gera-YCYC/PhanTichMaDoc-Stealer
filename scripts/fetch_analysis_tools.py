"""Fetch hash-pinned official Linux tool assets on the host, not in the VM."""
import argparse
import concurrent.futures
import json
from pathlib import Path
from fetch_setup_assets import fetch

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    assets = json.loads((ROOT/'config/analysis-tools.lock.json').read_text())['assets']
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(fetch, item, ROOT/'private/lab-assets/analysis-tools', args.verify_only) for item in assets]
        for item, future in zip(assets, futures):
            future.result()
            print('Verified '+item['path'], flush=True)


if __name__ == '__main__':
    main()
