#!/usr/bin/env python3
"""Validate reviewed archive labels and quarantine related reserved records."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath

import archive_inventory
import corpus


def validate_reviews(reviews, roots):
    seen = set()
    for review in reviews:
        key = review['archive_sha256']
        if key in seen:
            raise ValueError('duplicate archive review')
        seen.add(key)
        if not review.get('source_files'):
            raise ValueError('source review requires evidence files')
        root = next((base / key for base in roots if (base / key).is_dir()), None)
        if root is None:
            raise ValueError('reviewed source unavailable')
        for source in review['source_files']:
            path = PurePosixPath(source['path'])
            if path.is_absolute() or '..' in path.parts or '\\' in str(path):
                raise ValueError('unsafe evidence path')
            file = root / path
            if file.is_symlink() or not file.resolve().is_relative_to(root.resolve()):
                raise ValueError('evidence escapes reviewed source')
            if hashlib.sha256(file.read_bytes()).hexdigest() != source['sha256']:
                raise ValueError('reviewed source hash mismatch')


def regroup(records, inspections, reviews):
    """Use reviewed payload files as anchors; never label a neighbor by association."""
    groups = archive_inventory.Groups(r['sha256'] for r in records)
    reviewed = {r['archive_sha256']: r for r in reviews}
    anchors = {s['sha256'] for r in reviews for s in r['source_files'] if s['path'] != 'package.json'}
    normalized = set()
    for inspection in inspections.values():
        for source in inspection.get('coverage', {}).get('files', []):
            if source.get('sha256') in anchors and source.get('normalized_sha256'):
                normalized.add(source['normalized_sha256'])
    seen, links = {}, []
    for record in records:
        key = record['sha256']
        keys = [('metadata', record['group'])]
        keys += [('reviewed-source', h) for h in record.get('evidence_hashes', []) if h in anchors]
        for source in inspections.get(key, {}).get('coverage', {}).get('files', []):
            if source.get('sha256') in anchors:
                keys.append(('reviewed-source', source['sha256']))
            if source.get('normalized_sha256') in normalized:
                keys.append(('reviewed-normalized-source', source['normalized_sha256']))
        if key in reviewed:
            keys += [('reviewed-source', s['sha256']) for s in reviewed[key]['source_files'] if s['path'] != 'package.json']
        for edge in set(keys):
            if edge in seen:
                prior = seen[edge]
                groups.join(key, prior)
                if edge[0] != 'metadata':
                    links.append({'left': prior, 'right': key, 'basis': edge[0], 'source_hash': edge[1]})
            else:
                seen[edge] = key
    exposed = {groups.root(r['sha256']) for r in records
               if r['split'] != 'reserved' or r['sha256'] in inspections or r['sha256'] in reviewed}
    rows = []
    for record in records:
        key, original = record['sha256'], record['split']
        group = groups.root(key)
        split = 'quarantined_related' if original == 'reserved' and group in exposed else original
        review = reviewed.get(key)
        rows.append({'sha256': key, 'name': record['name'], 'version': record['version'],
                     'original_split': original, 'split': split, 'leakage_group': group,
                     'label_status': review['label_status'] if review else 'unreviewed',
                     'reviewed_family': review['family'] if review else None})
    return rows, sorted(links, key=lambda r: (r['left'], r['right'], r['basis']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--inspection', type=Path, action='append', required=True)
    parser.add_argument('--reviews', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output exists; preserve prior runs')
    records = json.loads(args.inventory.read_text())['packages']
    reviews = json.loads(args.reviews.read_text())['cases']
    validate_reviews(reviews, args.source_root)
    inspections = {}
    for directory in args.inspection:
        for path in directory.glob('*.json'):
            value = json.loads(path.read_text())
            if 'sha256' in value:
                inspections[value['sha256']] = value
    rows, links = regroup(records, inspections, reviews)
    args.output.mkdir(parents=True)
    corpus.write_json(args.output / 'summary.json', {
        'inventory_sha256': archive_inventory.digest(args.inventory.read_bytes()),
        'reviews_sha256': archive_inventory.digest(args.reviews.read_bytes()),
        'records': len(rows), 'reviewed': len(reviews),
        'label_statuses': dict(Counter(r['label_status'] for r in rows)),
        'splits': dict(Counter(r['split'] for r in rows)),
        'leakage_groups': len({r['leakage_group'] for r in rows}),
        'code_links': len(links),
        'interpretation': 'Groups prevent validation leakage. They do not establish common malicious intent or campaign attribution. Unopened reserved code can retain unknown overlap.',
    })
    corpus.write_json(args.output / 'links.json', links)
    with (args.output / 'inventory.jsonl').open('w') as output:
        for row in rows:
            output.write(json.dumps(row, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
