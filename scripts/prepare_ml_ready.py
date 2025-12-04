#!/usr/bin/env python3
"""
Read a JSON file (Elasticsearch hits or list of documents), filter documents
that produce an ML input via `classify_log.classify_log`, and write matching
documents to `logs/ML-Ready-Logs` as a JSONL file and individual JSON files.

Usage:
  python scripts/prepare_ml_ready.py --input logs/ECS-Logs/modsecurity.json
"""

import os
import sys
import json
import argparse

# Ensure repo root is on sys.path so we can import classify_log when running from scripts/
script_dir = os.path.dirname(__file__)
repo_root = os.path.abspath(os.path.join(script_dir, '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

# Import classify_log from the repo (file defines classify_log at module level)
from classify_log import classify_log


def load_input(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # If this is an ES response (dict with hits.hits), extract hits
    if isinstance(data, dict):
        # Common shapes: {"hits": {"hits": [...]}} or array of hits
        if 'hits' in data and isinstance(data['hits'], dict) and 'hits' in data['hits']:
            return data['hits']['hits']
        # If already a single hit/dict, wrap
        return [data]
    elif isinstance(data, list):
        return data
    else:
        raise ValueError('Unsupported JSON input shape')


def ensure_outdir(path):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def write_results(outdir, matched_docs):
    ml_ready_path = os.path.join(outdir, 'ml_ready.jsonl')
    with open(ml_ready_path, 'w', encoding='utf-8') as out_f:
        for i, doc in enumerate(matched_docs):
            json.dump(doc, out_f, ensure_ascii=False)
            out_f.write('\n')

    # Also write individual files for convenience
    for i, doc in enumerate(matched_docs):
        fn = os.path.join(outdir, f'doc_{i+1}.json')
        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)

    return ml_ready_path, len(matched_docs)


def main():
    parser = argparse.ArgumentParser(description='Prepare ML-ready logs from a JSON file.')
    parser.add_argument('--input', '-i', required=True, help='Input JSON file (ES hits or array)')
    parser.add_argument('--outdir', '-o', default='logs/ML-Ready-Logs', help='Output folder')
    args = parser.parse_args()

    try:
        docs = load_input(args.input)
    except Exception as e:
        print(f'Error loading input: {e}', file=sys.stderr)
        sys.exit(2)

    ensure_outdir(args.outdir)

    matched = []
    for i, doc in enumerate(docs):
        # If ES _source wrapped hits (common), try to use the hit dict as-is
        try:
            result = classify_log(doc)
        except Exception as e:
            print(f'Warning: classify_log threw on item {i}: {e}', file=sys.stderr)
            result = None

        if result:
            # Attach ml info to the doc for downstream use
            # result is typically {'ml': {'prediction': {'input': '...'}}}
            doc['_ml'] = result['ml']
            matched.append(doc)

    ml_path, count = write_results(args.outdir, matched)
    print(f'Wrote {count} matched documents to {args.outdir} (jsonl: {ml_path})')


if __name__ == '__main__':
    main()
