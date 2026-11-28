"""Recompute coursework metrics from the submitted, hash-linked public reviews."""
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.journal import dump_json

EVIDENCE = ROOT / 'deliverables/real-demo-evidence'
PROFILES = ROOT / 'eval/reference_units'
DEFAULT_PROFILES = ('python2024.atomic-v3.json', 'gomorrah.atomic-v1.json',
                    'agenttesla.atomic-v1.json', 'mercurial.atomic-v1.json')


def read(path):
    return json.loads(path.read_bytes())


def metrics(count):
    tp, fp, fn = count['correct'], count['incorrect'] + count['unsupported'], count['missed']
    return {**{key: count[key] for key in ('correct', 'incorrect', 'unsupported', 'missed')},
            'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def summarize_public_batch(batch_path, profiles, evidence=EVIDENCE, *, review_directories=None):
    batch = read(batch_path)
    corpus = read(ROOT/'eval/corpora/real-yara-development-v3.json')['corpora']
    labels = {r['sha256']: ('malicious' if r['positive'] else 'benign')
              for partition in corpus.values() for r in partition}
    refs = {read(p)['sample_sha256']: p for p in profiles}
    runs = batch['runs']
    unique = {r['sample_sha256'] for r in runs}
    fingerprints = {(r['model']['digest'], r['source_manifest_sha256'], r['config_sha256_excluding_sample'])
                    for r in runs}
    if (len(unique) != len(runs) or unique != set(refs) or len(refs) != len(profiles)
            or len(fingerprints) != 1 or not all(next(iter(fingerprints)))):
        raise ValueError('Supply one reference per distinct sample for one model, code and configuration')
    stages = ('raw', 'after_filter')
    categories = ('declared_units', 'ioc_and_attack')
    atomic = {s: {k: Counter() for k in categories} for s in stages}
    claims = {s: Counter() for s in stages}
    cases = []
    classified = 0
    for row in runs:
        rid, sample = row['run_id'], row['sample_sha256']
        if not re.fullmatch(r'\d{8}T\d{6}_[0-9a-f]{8}', rid) or row['journal']['chain_verified'] is not True:
            raise ValueError('A verified run identifier is required')
        profile = read(refs[sample])
        if profile.get('scoring_ready') is not True or profile['model_self_review_used_as_truth'] is not False:
            raise ValueError('Reference cannot be scored')
        identity = sha256(refs[sample].read_bytes()).hexdigest()
        empty = row['status'] == 'incomplete' and row['raw_report_available'] and row['proposed_claims'] == 0
        if not empty and not row['status'].startswith('completed'):
            raise ValueError('Unreviewed failure with unknown predictions: ' + rid)
        endpoint = review_directories[rid] if review_directories is not None else evidence / rid
        if empty:
            if row['accepted_claims'] or row['rejected_claims']:
                raise ValueError('Empty report counts differ')
            for stage in stages:
                atomic[stage]['declared_units']['missed'] += len(profile['units'])
                atomic[stage]['ioc_and_attack']['missed'] += sum(u['kind'] in ('ioc', 'attack') for u in profile['units'])
        else:
            score = read(endpoint/'atomic-score.json')
            sentences = read(endpoint/'claim-score.json')
            audit = read(endpoint/'source-audit.json')
            if (score['profile_sha256'] != identity or score['profile_id'] != profile['profile_id']
                    or audit['journal_sha256'] != row['journal']['sha256']
                    or any(obj['run_id'] != rid or obj['raw_report_sha256'] != row['raw_report_sha256']
                           for obj in (score, sentences, audit))
                    or audit['sample_sha256'] != sample or sentences['sample_sha256'] != sample
                    or sentences['checked_verdict'] != row['verdict']):
                raise ValueError('Review and batch describe different runs: ' + rid)
            for stage, expected in zip(stages, (row['proposed_claims'], row['accepted_claims'])):
                by_sentence = sentences[stage]
                if expected != by_sentence['claim_count'] or expected != sum(by_sentence['counts'].values()):
                    raise ValueError('Claim counts differ: ' + rid)
                claims[stage].update(by_sentence['counts'])
                claims[stage]['cited'] += by_sentence['verified_tool_citation_count']
                for key, data in (('declared_units', score[stage]), ('ioc_and_attack', score['rubric_ioc_attack'][stage])):
                    ref_count = sum(key == 'declared_units' or u['kind'] in ('ioc', 'attack') for u in profile['units'])
                    if data['correct'] + data['missed'] != ref_count:
                        raise ValueError('Reference counts differ: ' + rid)
                    atomic[stage][key].update({k: data[k] for k in ('correct','incorrect','unsupported','missed')})
        classified += row['verdict'] == labels[sample]
        cases.append({'run_id': rid, 'sample_sha256': sample, 'profile_sha256': identity,
                      'reference_count': len(profile['units']), 'empty_report': empty,
                      'expected_verdict': labels[sample], 'verdict': row['verdict']})
    scored = {}
    for stage in stages:
        c = claims[stage]
        n = c['correct'] + c['incorrect'] + c['unsupported']
        scored[stage] = {k: metrics(v) for k, v in atomic[stage].items()} | {
            'sentences': {'count': n, 'correct': c['correct'], 'incorrect': c['incorrect'],
                          'unsupported': c['unsupported'], 'citations': c['cited'],
                          'citation_rate': c['cited']/n if n else None,
                          'source_supported_rate': c['correct']/n if n else None,
                          'hallucination_rate': c['unsupported']/n if n else None}}
    return {'source_batch_sha256': sha256(batch_path.read_bytes()).hexdigest(), 'cases': cases,
            'correct_verdicts': classified, 'total_attempts': len(runs), 'label_source': 'real-yara-development-v3',
            **scored, 'scope': 'Micro counts on declared development references, including omissions in empty reports. '
            'Public metadata check. Semantic labels are project source reviews, not an independent grade.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', type=Path, default=EVIDENCE/'coverage-v11-batch.json')
    parser.add_argument('--profile', type=Path, action='append', help='One frozen profile per sample')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = summarize_public_batch(args.batch, args.profile or [PROFILES/p for p in DEFAULT_PROFILES])
    if args.output:
        dump_json(args.output, report)
    print(json.dumps({key: report[key] for key in ('total_attempts','correct_verdicts','raw','after_filter')}, indent=2))
