#!/usr/bin/env python3
"""
CLI tool to classify log documents based on index and fields, mimicking the Painless script logic.
Reads a JSON document from stdin or file, applies classification rules, and outputs the ML input text if applicable.
"""

import json
import sys
import argparse

def classify_log(doc):
    """
    Classify a log document and return a dict with 'ml.prediction.input' if it matches supported sources.
    Returns None if no match or skipped.
    """
    # Handle Elasticsearch hit format - extract raw log from fields.event.original
    # Preserve original _index (if present) so downstream detection still works.
    if isinstance(doc, dict) and 'fields' in doc and 'event.original' in doc['fields']:
        original_index = doc.get('_index')
        try:
            raw_log_str = doc['fields']['event.original'][0]
            parsed = json.loads(raw_log_str)
            # keep original metadata (like _index) so we can still infer source
            if original_index:
                parsed['_index'] = original_index
            doc = parsed
        except (json.JSONDecodeError, IndexError, KeyError, TypeError):
            pass  # Fall back to original doc

    # Try to get index; if missing, attempt to infer source from keys
    idx = (doc.get('_index') or '').lower()

    def infer_index_from_doc(d):
        # Simple heuristics to guess pipeline/source when `_index` is not present
        if not isinstance(d, dict):
            return ''
        if 'suricata' in d or 'suricata.eve.event_type' in d or d.get('event_type') in ("alert", "flow", "dns", "tls"):
            return 'suricata'
        if 'zeek' in d or (isinstance(d.get('_path'), str) and 'zeek' in d.get('_path').lower()):
            return 'zeek'
        if d.get('rule') and d.get('act'):
            return 'pfsense'
        if d.get('remote_addr') or d.get('request'):
            return 'nginx'
        if 'modsec' in d or 'modsecurity' in d:
            return 'modsecurity'
        if 'mysql' in d or d.get('log', {}).get('logger') == 'mysql':
            return 'mysql'
        if d.get('event', {}).get('provider') == 'windows' or 'windows' in ''.join(d.keys()):
            return 'windows'
        return ''

    if not idx:
        idx = infer_index_from_doc(doc)
    if not idx:
        return None

    # Only process prioritized indices
    prioritized = [
        'wazuh', 'zeek', 'suricata', 'pfsense', 'modsecurity',
        'apache', 'nginx', 'mysql', 'windows'
    ]
    if not any(p in idx for p in prioritized):
        return None

    # Initialize ml.prediction if needed
    ml_input = None

    # ========================= SURICATA =========================
    if 'suricata' in idx:
        # Suricata event_type may be nested under suricata.eve.event_type
        # or present at top-level after parsing event.original
        event_type = (
            doc.get('suricata', {}).get('eve', {}).get('event_type') or
            doc.get('event_type') or
            (doc.get('suricata.eve.event_type') if isinstance(doc.get('suricata.eve.event_type'), str) else None) or
            (doc.get('fields', {}).get('suricata.eve.event_type', [None])[0] if isinstance(doc.get('fields', {}).get('suricata.eve.event_type'), list) else None)
        )
        if event_type in [None, 'stats', 'flow', 'netflow', 'fileinfo', 'dns']:
            return None
        if event_type == 'alert' and (doc.get('rule', {}).get('name') or doc.get('suricata.eve.alert.signature') or doc.get('suricata.eve.alert.signature')):
            rule_name = doc.get('rule', {}).get('name') or doc.get('suricata.eve.alert.signature') or doc.get('suricata.eve.alert.signature')
            ml_input = (
                'Suricata Alert: ' + rule_name +
                ' | Category: ' + (doc.get('rule', {}).get('category') or doc.get('suricata.eve.alert.category') or 'Unknown') +
                ' | ' + (doc.get('src_ip') or doc.get('source', {}).get('ip') or '-') +
                ' -> ' + (doc.get('dest_ip') or doc.get('destination', {}).get('ip') or '-')
            )

    # ========================= ZEEK =========================
    if 'zeek' in idx:
        kind = doc.get('event', {}).get('kind')
        if kind != 'alert':
            return None
        if not doc.get('zeek', {}).get('notice'):
            return None
        rule = doc.get('rule', {})
        if rule.get('name') and rule.get('description'):
            ml_input = (
                'Zeek Alert: ' + rule['name'] +
                ' | Description: ' + rule['description'] +
                ' | Peer: ' + (doc.get('zeek', {}).get('notice', {}).get('peer_descr') or '-')
            )
        elif doc.get('zeek', {}).get('notice', {}).get('msg'):
            ml_input = 'Zeek Notice: ' + doc['zeek']['notice']['msg']

    # ========================= PFSENSE =========================
    if 'pfsense' in idx:
        action = doc.get('event', {}).get('action', '').lower()
        if action not in ['block', 'reject']:
            return None
        ml_input = (
            "pfSense: " + action.upper() + " " +
            (doc.get('source', {}).get('ip') or "-") + ":" + (doc.get('source', {}).get('port') or "-") +
            " -> " +
            (doc.get('destination', {}).get('ip') or "-") + ":" + (doc.get('destination', {}).get('port') or "-") +
            " | Proto: " + (doc.get('network', {}).get('transport') or "-")
        )

    # ========================= WAZUH =========================
    rule_desc = doc.get('rule', {}).get('description')
    full_log = doc.get('full_log')
    if rule_desc and full_log:
        ml_input = 'Alert: ' + rule_desc + ' | Log: ' + full_log

    # ========================= APACHE =========================
    if 'apache' in idx:
        level = doc.get('log', {}).get('level')
        msg = doc.get('message')
        is_alert = (
            level in ['error', 'crit', 'alert', 'emerg', 'warning'] or
            (msg and any(kw in msg.lower() for kw in ['error', 'failed', 'attack', 'denied', 'modsecurity']))
        )
        if not is_alert:
            return None
        ml_input = (
            "Apache Alert: " + (msg or "-") +
            " | Level: " + (level or "-") +
            " | Host: " + (doc.get('host', {}).get('hostname') or "-")
        )

    # ========================= MYSQL =========================
    if 'mysql' in idx:
        level = doc.get('log', {}).get('level')
        if level != 'Warning':
            return None
        ml_input = "MySQL Warning: " + (doc.get('message') or "-") + " | Level: " + level

    # ========================= NGINX =========================
    if 'nginx' in idx:
        level = doc.get('log', {}).get('level') or ""
        msg = doc.get('message') or ""
        if level == "notice":
            return None
        if any(kw in msg for kw in ['version', 'loaded', 'built', 'using']):
            return None
        ml_input = "Nginx Error: " + msg + " | Level: " + level

    # ========================= FIREWALL KHÁC =========================
    if doc.get('observer', {}).get('type') == 'firewall' and doc.get('event', {}).get('action'):
        action = doc['event']['action']
        ml_input = (
            'Firewall ' + action + ': ' +
            (doc.get('source', {}).get('ip') or '-') + ':' + (doc.get('source', {}).get('port') or '-') +
            ' -> ' +
            (doc.get('destination', {}).get('ip') or '-') + ':' + (doc.get('destination', {}).get('port') or '-')
        )

    # ========================= WINDOWS =========================
    if 'windows' in idx:
        level = doc.get('log', {}).get('level')
        kind = doc.get('event', {}).get('kind')
        action = doc.get('event', {}).get('action')
        msg = doc.get('message')
        is_alert = (
            kind == 'alert' or
            level in ['warning', 'error', 'critical'] or
            (msg and any(kw in msg for kw in ['detect', 'malware', 'threat', 'blocked', 'quarantine', 'virus'])) or
            (action and any(kw in action for kw in ['Detected', 'Blocked', 'Quarantined']))
        )
        if not is_alert:
            return None
        ml_input = (
            'Windows Alert: ' +
            (doc.get('event', {}).get('code') or '-') +
            ' | Provider: ' + (doc.get('event', {}).get('provider') or '-') +
            ' | Message: ' + (msg or '-')
        )

    # ========================= MODSECURITY =========================
    if 'modsecurity' in idx:
        messages = doc.get('modsec', {}).get('audit', {}).get('messages')
        if not messages:
            return None
        query = doc.get('url', {}).get('query')
        if not query or not query.strip():
            return None
        msgs = "; ".join(messages)
        ml_input = (
            "ModSecurity Alert: " + msgs +
            " | URL: " + (doc.get('url', {}).get('original') or "-") +
            " | Query: " + query +
            " | SourceIP: " + (doc.get('source', {}).get('ip') or "-") +
            " | SourcePort: " + (doc.get('source', {}).get('port') or "-")
        )

    # Generic fallback: use original event/message if nothing matched
    if ml_input is None:
        original = doc.get('event', {}).get('original')
        message = doc.get('message')
        if original or message:
            ml_input = original or message

    if ml_input:
        return {'ml': {'prediction': {'input': ml_input}}}
    return None

def main():
    parser = argparse.ArgumentParser(description="Classify log documents for ML input.")
    parser.add_argument('--input', '-i', type=str, help="Path to JSON file (default: stdin)")
    args = parser.parse_args()

    try:
        if args.input:
            with open(args.input, 'r') as f:
                data = json.load(f)
        else:
            data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input: {e}", file=sys.stderr)
        sys.exit(1)

    # Handle both single dict and list of dicts (Elasticsearch format)
    if isinstance(data, dict):
        docs = [data]
    elif isinstance(data, list):
        docs = data
    else:
        print("Error: Input must be a JSON object (dict) or array of objects.", file=sys.stderr)
        sys.exit(1)

    results = []
    for doc in docs:
        if not isinstance(doc, dict):
            print(f"Warning: Skipping non-dict item: {type(doc).__name__}", file=sys.stderr)
            continue
        result = classify_log(doc)
        if result:
            results.append(result)

    if results:
        print(json.dumps(results, indent=2))
    else:
        print("No ML input generated (skipped or no match)", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()