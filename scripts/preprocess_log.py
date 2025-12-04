"""
Elasticsearch Log Processor with Painless Logic
Query logs from Elasticsearch and process them with the same logic as Painless script
"""

import json
import sys
from pathlib import Path
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
from typing import List, Dict, Any


def safe_get_dot(ctx_flat, *keys, default=None):
    """Safely get value using dot notation from flattened Elasticsearch fields"""
    # Try dot notation first (e.g., 'rule.name')
    dot_key = '.'.join(keys)
    if dot_key in ctx_flat:
        value = ctx_flat[dot_key]
        return value if value is not None else default
    
    # Try nested access as fallback
    current = ctx_flat
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
        if current is None:
            return default
    return current if current is not None else default


def flatten_doc(hit: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten Elasticsearch document to simple dict with single values"""
    
    # Try 'fields' first (search API format), then '_source' (direct doc format)
    source = hit.get('fields', hit.get('_source', {}))
    
    # If we have 'fields' format, flatten arrays
    if 'fields' in hit:
        flattened = {}
        for key, value in source.items():
            # Elasticsearch fields format: arrays with single values
            if isinstance(value, list) and len(value) == 1:
                flattened[key] = value[0]
            else:
                flattened[key] = value
    else:
        # If we have '_source' format, flatten nested structure
        def flatten(obj, parent_key=''):
            items = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_key = f"{parent_key}.{k}" if parent_key else k
                    if isinstance(v, dict):
                        items.extend(flatten(v, new_key).items())
                    elif isinstance(v, list) and len(v) == 1:
                        items.append((new_key, v[0]))
                    else:
                        items.append((new_key, v))
            return dict(items)
        
        flattened = flatten(source)
    
    # Add metadata
    flattened['_index'] = hit.get('_index')
    flattened['_id'] = hit.get('_id')
    
    return flattened


def process_log(ctx: Dict[str, Any], idx: str) -> str | None:
    """
    Process a single log entry following Painless script logic
    Returns ml_input string or None if should be skipped
    """
    
    if idx is None:
        return None
    
    idx = idx.lower()
    
    # Check if this is a priority index
    priority_keywords = [
        'wazuh', 'zeek', 'suricata', 'pfsense', 'modsecurity',
        'apache', 'nginx', 'mysql', 'windows'
    ]
    
    hit = any(keyword in idx for keyword in priority_keywords)
    if not hit:
        return None
    
    # ========================= SURICATA =========================
    if 'suricata' in idx:
        event_type = safe_get_dot(ctx, 'suricata', 'eve', 'event_type')
        
        # Skip unimportant events
        skip_events = ['stats', 'flow', 'netflow', 'fileinfo', 'dns']
        if event_type is None or event_type in skip_events:
            return None
        
        # Suricata alert - ONLY if event_type == 'alert' AND rule.name exists
        if event_type == 'alert' and safe_get_dot(ctx, 'rule', 'name') is not None:
            return (
                f"Suricata Alert: {safe_get_dot(ctx, 'rule', 'name')}"
                f" | Category: {safe_get_dot(ctx, 'rule', 'category', default='Unknown')}"
                f" | {safe_get_dot(ctx, 'source', 'ip', default='-')}"
                f" -> {safe_get_dot(ctx, 'destination', 'ip', default='-')}"
            )
        
        return None
    
    # ========================= ZEEK =========================
    if 'zeek' in idx:
        # Only accept real alerts: must have event.kind = "alert"
        kind = safe_get_dot(ctx, 'event', 'kind')
        if kind is None or kind != 'alert':
            return None
        
        # Must have a Zeek notice
        if safe_get_dot(ctx, 'zeek', 'notice') is None:
            return None
        
        # Must have both name + description (alert-level messages)
        if safe_get_dot(ctx, 'rule', 'name') is not None and safe_get_dot(ctx, 'rule', 'description') is not None:
            return (
                f"Zeek Alert: {safe_get_dot(ctx, 'rule', 'name')}"
                f" | Description: {safe_get_dot(ctx, 'rule', 'description')}"
                f" | Peer: {safe_get_dot(ctx, 'zeek', 'notice', 'peer_descr', default='-')}"
            )
        
        # Fallback: use Zeek Notice message only when it's alert-level
        notice_msg = safe_get_dot(ctx, 'zeek', 'notice', 'msg')
        if notice_msg is not None:
            return f"Zeek Notice: {notice_msg}"
        
        return None
    
    # ========================= PFSENSE =========================
    if 'pfsense' in idx:
        # Normalize action safely
        action = safe_get_dot(ctx, 'event', 'action')
        if action is None:
            return None
        
        action = action.lower()
        
        # Only accept block / reject
        if action not in ['block', 'reject']:
            return None
        
        # Build ML input safely
        return (
            f"pfSense: {action.upper()} "
            f"{safe_get_dot(ctx, 'source', 'ip', default='-')}:{safe_get_dot(ctx, 'source', 'port', default='-')}"
            f" -> "
            f"{safe_get_dot(ctx, 'destination', 'ip', default='-')}:{safe_get_dot(ctx, 'destination', 'port', default='-')}"
            f" | Proto: {safe_get_dot(ctx, 'network', 'transport', default='-')}"
        )
    
    # ========================= WAZUH =========================
    # NOTE: This applies to ALL indices, not just wazuh!
    if safe_get_dot(ctx, 'rule', 'description') is not None and safe_get_dot(ctx, 'full_log') is not None:
        return f"Alert: {safe_get_dot(ctx, 'rule', 'description')} | Log: {safe_get_dot(ctx, 'full_log')}"
    
    # ========================= APACHE =========================
    if 'apache' in idx:
        level = safe_get_dot(ctx, 'log', 'level')
        msg = safe_get_dot(ctx, 'message')
        
        # Only keep real errors or alerts
        is_alert = False
        
        if level is not None and level in ['error', 'crit', 'alert', 'emerg', 'warning']:
            is_alert = True
        
        if msg is not None:
            msg_lower = msg.lower()
            if any(keyword in msg_lower for keyword in ['error', 'failed', 'attack', 'denied', 'modsecurity']):
                is_alert = True
        
        if not is_alert:
            return None
        
        return (
            f"Apache Alert: {msg or '-'}"
            f" | Level: {level or '-'}"
            f" | Host: {safe_get_dot(ctx, 'host', 'hostname', default='-')}"
        )
    
    # ========================= MYSQL =========================
    if 'mysql' in idx:
        level = safe_get_dot(ctx, 'log', 'level')
        
        # Only process MySQL warnings
        if level is None or level != 'Warning':
            return None
        
        return f"MySQL Warning: {safe_get_dot(ctx, 'message', default='-')} | Level: {level}"
    
    # ========================= NGINX =========================
    if 'nginx' in idx:
        level = safe_get_dot(ctx, 'log', 'level', default='')
        msg = safe_get_dot(ctx, 'message', default='')
        
        # Skip everything if level = notice (too noisy)
        if level == 'notice':
            return None
        
        # Skip startup/version messages
        skip_keywords = ['version', 'loaded', 'built', 'using']
        if any(keyword in msg for keyword in skip_keywords):
            return None
        
        # If got here → it's a real error
        return f"Nginx Error: {msg} | Level: {level}"
    
    # ========================= FIREWALL KHÁC =========================
    # NOTE: This also applies to ALL indices, not just firewall!
    if safe_get_dot(ctx, 'observer', 'type') == 'firewall' and safe_get_dot(ctx, 'event', 'action') is not None:
        return (
            f"Firewall {safe_get_dot(ctx, 'event', 'action')}: "
            f"{safe_get_dot(ctx, 'source', 'ip', default='-')}:{safe_get_dot(ctx, 'source', 'port', default='-')}"
            f" -> "
            f"{safe_get_dot(ctx, 'destination', 'ip', default='-')}:{safe_get_dot(ctx, 'destination', 'port', default='-')}"
        )
    
    # ========================= WINDOWS =========================
    if 'windows' in idx:
        # Only keep security alerts
        level = safe_get_dot(ctx, 'log', 'level')
        kind = safe_get_dot(ctx, 'event', 'kind')
        action = safe_get_dot(ctx, 'event', 'action')
        msg = safe_get_dot(ctx, 'message')
        
        # Must be alert-level or contain detection keywords
        is_alert = False
        
        if kind is not None and kind == 'alert':
            is_alert = True
        
        if level is not None and level in ['warning', 'error', 'critical']:
            is_alert = True
        
        if msg is not None:
            if any(keyword in msg.lower() for keyword in ['detect', 'malware', 'threat', 'blocked', 'quarantine', 'virus']):
                is_alert = True
        
        if action is not None:
            if any(keyword in action for keyword in ['Detected', 'Blocked', 'Quarantined']):
                is_alert = True
        
        if not is_alert:
            return None
        
        # Build ML input
        return (
            f"Windows Alert: {safe_get_dot(ctx, 'event', 'code', default='-')}"
            f" | Provider: {safe_get_dot(ctx, 'event', 'provider', default='-')}"
            f" | Message: {msg or '-'}"
        )
    
    # ========================= MODSECURITY =========================
    if 'modsecurity' in idx:
        # Must have ModSecurity messages (real alerts)
        messages = safe_get_dot(ctx, 'modsec', 'audit', 'messages')
        if messages is None or (isinstance(messages, list) and len(messages) == 0):
            return None
        
        # Must have a query string
        query = safe_get_dot(ctx, 'url', 'query')
        if query is None or (isinstance(query, str) and query.strip() == ''):
            return None
        
        # Build message list
        if isinstance(messages, list):
            msgs = "; ".join(str(m) for m in messages)
        else:
            msgs = str(messages)
        
        return (
            f"ModSecurity Alert: {msgs}"
            f" | URL: {safe_get_dot(ctx, 'url', 'original', default='-')}"
            f" | Query: {query}"
            f" | SourceIP: {safe_get_dot(ctx, 'source', 'ip', default='-')}"
            f" | SourcePort: {safe_get_dot(ctx, 'source', 'port', default='-')}"
        )
    
    # ========================= GENERIC FALLBACK =========================
    # Generic fallback: use original event/message if nothing matched
    event_original = safe_get_dot(ctx, 'event', 'original')
    message = safe_get_dot(ctx, 'message')
    
    if event_original is not None or message is not None:
        return event_original if event_original is not None else message
    
    return None


def query_and_process_logs(
    es_host: str,
    es_user: str,
    es_password: str,
    index_pattern: str,
    query: Dict[str, Any],
    output_file: str,
    max_docs: int = 10000
):
    """
    Query Elasticsearch and process logs with Painless logic
    
    Args:
        es_host: Elasticsearch host (e.g., 'https://localhost:9200')
        es_user: Elasticsearch username
        es_password: Elasticsearch password
        index_pattern: Index pattern to query (e.g., 'logs-*', 'suricata-*')
        query: Elasticsearch query dict
        output_file: Output JSON file path
        max_docs: Maximum number of documents to process
    """
    
    # Connect to Elasticsearch
    print(f"Connecting to Elasticsearch at {es_host}...")
    es = Elasticsearch(
        [es_host],
        basic_auth=(es_user, es_password),
        verify_certs=False,  # Set to True in production with proper certs
        request_timeout=30
    )
    
    # Check connection
    if not es.ping():
        raise ConnectionError("Could not connect to Elasticsearch!")
    
    print(f"✓ Connected to Elasticsearch")
    print(f"✓ Querying index pattern: {index_pattern}")
    
    # Query logs using scroll API
    results = []
    processed_count = 0
    ml_count = 0
    skipped_count = 0
    
    print(f"Processing documents...")
    
    # Use scan helper for efficient scrolling
    for hit in scan(
        es,
        index=index_pattern,
        query=query,
        size=500,  # Batch size
        scroll='2m'
    ):
        if processed_count >= max_docs:
            print(f"Reached max documents limit: {max_docs}")
            break
        
        # Flatten document
        ctx = flatten_doc(hit)
        idx = ctx.get('_index')
        
        # Process with Painless logic
        ml_input = process_log(ctx, idx)
        
        # Build result document
        result_doc = {
            '_index': hit.get('_index'),
            '_id': hit.get('_id')
        }
        
        # Preserve original format (fields or _source)
        if 'fields' in hit:
            result_doc['fields'] = hit['fields']
        if '_source' in hit:
            result_doc['_source'] = hit['_source']
        
        if ml_input:
            result_doc['ml_input'] = ml_input
            ml_count += 1
        else:
            skipped_count += 1
        
        results.append(result_doc)
        processed_count += 1
        
        # Progress indicator
        if processed_count % 100 == 0:
            print(f"  Processed: {processed_count} | With ml_input: {ml_count} | Skipped: {skipped_count}")
    
    # Write to JSON file
    print(f"\nWriting results to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"\n{'='*60}")
    print(f"✓ Done!")
    print(f"✓ Total processed: {processed_count} documents")
    print(f"✓ With ml_input: {ml_count} documents")
    print(f"✓ Skipped: {skipped_count} documents")
    print(f"✓ Output saved to: {output_file}")
    print(f"{'='*60}")


def main():
    """
    Main function with example usage
    """
    
    if len(sys.argv) < 2:
        print("""
Usage: python script.py <config_mode>

Modes:
  1. query    - Query from Elasticsearch and save to JSON
  2. process  - Process existing JSON file (offline mode)

Examples:
  # Query from Elasticsearch
  python script.py query
  
  # Process existing JSON file
  python script.py process input.json output.json
""")
        sys.exit(1)
    
    mode = sys.argv[1]
    
    if mode == 'query':
        # Configuration - EDIT THESE VALUES
        ES_HOST = 'https://localhost:9200'
        ES_USER = 'elastic'
        ES_PASSWORD = 'your_password_here'
        
        # Index pattern to query
        INDEX_PATTERN = 'logs-*'  # or 'suricata-*', 'windows-*', etc.
        
        # Elasticsearch query
        QUERY = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "now-7d",  # Last 7 days
                        "lte": "now"
                    }
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ]
        }
        
        # Output file
        OUTPUT_FILE = 'ml_ready_logs.json'
        
        # Maximum documents to process
        MAX_DOCS = 10000
        
        # Run query
        query_and_process_logs(
            es_host=ES_HOST,
            es_user=ES_USER,
            es_password=ES_PASSWORD,
            index_pattern=INDEX_PATTERN,
            query=QUERY,
            output_file=OUTPUT_FILE,
            max_docs=MAX_DOCS
        )
    
    elif mode == 'process':
        # Process existing JSON file (offline mode)
        if len(sys.argv) < 4:
            print("Usage: python script.py process <input.json> <output.json>")
            sys.exit(1)
        
        input_file = sys.argv[2]
        output_file = sys.argv[3]
        
        print(f"Reading {input_file}...")
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle different JSON formats
        if isinstance(data, list):
            documents = data
        elif isinstance(data, dict) and 'hits' in data:
            documents = data.get('hits', {}).get('hits', [])
        else:
            documents = [data]
        
        print(f"Processing {len(documents)} documents...")
        results = []
        ml_count = 0
        skipped_count = 0
        
        for doc in documents:
            # Flatten document
            ctx = flatten_doc(doc)
            idx = ctx.get('_index')
            
            # Process
            ml_input = process_log(ctx, idx)
            
            if ml_input:
                doc['ml_input'] = ml_input
                ml_count += 1
            else:
                skipped_count += 1
            
            results.append(doc)
        
        # Write output
        print(f"Writing to {output_file}...")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        print(f"\n✓ Done! Processed {len(results)} documents")
        print(f"✓ With ml_input: {ml_count}")
        print(f"✓ Skipped: {skipped_count}")
    
    else:
        print(f"Unknown mode: {mode}")
        print("Use 'query' or 'process'")
        sys.exit(1)


if __name__ == "__main__":
    main()