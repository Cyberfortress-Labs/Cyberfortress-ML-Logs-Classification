"""
Simple Batch Log Processor - Process all logs in one script
No subprocess calls, pure Python processing
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any


def safe_get_dot(ctx_flat, *keys, default=None):
    """Safely get value using dot notation from flattened Elasticsearch fields"""
    dot_key = '.'.join(keys)
    if dot_key in ctx_flat:
        value = ctx_flat[dot_key]
        return value if value is not None else default
    
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
    source = hit.get('fields', hit.get('_source', {}))
    
    if 'fields' in hit:
        flattened = {}
        for key, value in source.items():
            if isinstance(value, list) and len(value) == 1:
                flattened[key] = value[0]
            else:
                flattened[key] = value
    else:
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
    
    flattened['_index'] = hit.get('_index')
    flattened['_id'] = hit.get('_id')
    
    return flattened


def process_log(ctx: Dict[str, Any], idx: str) -> str | None:
    """Process a single log entry following Painless script logic"""
    
    if idx is None:
        return None
    
    idx = idx.lower()
    
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
        skip_events = ['stats', 'flow', 'netflow', 'fileinfo', 'dns']
        if event_type is None or event_type in skip_events:
            return None
        
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
        kind = safe_get_dot(ctx, 'event', 'kind')
        if kind is None or kind != 'alert':
            return None
        
        if safe_get_dot(ctx, 'zeek', 'notice') is None:
            return None
        
        if safe_get_dot(ctx, 'rule', 'name') is not None and safe_get_dot(ctx, 'rule', 'description') is not None:
            return (
                f"Zeek Alert: {safe_get_dot(ctx, 'rule', 'name')}"
                f" | Description: {safe_get_dot(ctx, 'rule', 'description')}"
                f" | Peer: {safe_get_dot(ctx, 'zeek', 'notice', 'peer_descr', default='-')}"
            )
        
        notice_msg = safe_get_dot(ctx, 'zeek', 'notice', 'msg')
        if notice_msg is not None:
            return f"Zeek Notice: {notice_msg}"
        
        return None
    
    # ========================= PFSENSE =========================
    if 'pfsense' in idx:
        action = safe_get_dot(ctx, 'event', 'action')
        if action is None:
            return None
        
        action = action.lower()
        if action not in ['block', 'reject']:
            return None
        
        return (
            f"pfSense: {action.upper()} "
            f"{safe_get_dot(ctx, 'source', 'ip', default='-')}:{safe_get_dot(ctx, 'source', 'port', default='-')}"
            f" -> "
            f"{safe_get_dot(ctx, 'destination', 'ip', default='-')}:{safe_get_dot(ctx, 'destination', 'port', default='-')}"
            f" | Proto: {safe_get_dot(ctx, 'network', 'transport', default='-')}"
        )
    
    # ========================= WAZUH =========================
    if safe_get_dot(ctx, 'rule', 'description') is not None and safe_get_dot(ctx, 'full_log') is not None:
        return f"Alert: {safe_get_dot(ctx, 'rule', 'description')} | Log: {safe_get_dot(ctx, 'full_log')}"
    
    # ========================= APACHE =========================
    if 'apache' in idx:
        level = safe_get_dot(ctx, 'log', 'level')
        msg = safe_get_dot(ctx, 'message')
        
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
        if level is None or level != 'Warning':
            return None
        return f"MySQL Warning: {safe_get_dot(ctx, 'message', default='-')} | Level: {level}"
    
    # ========================= NGINX =========================
    if 'nginx' in idx:
        level = safe_get_dot(ctx, 'log', 'level', default='')
        msg = safe_get_dot(ctx, 'message', default='')
        
        if level == 'notice':
            return None
        
        skip_keywords = ['version', 'loaded', 'built', 'using']
        if any(keyword in msg for keyword in skip_keywords):
            return None
        
        return f"Nginx Error: {msg} | Level: {level}"
    
    # ========================= FIREWALL =========================
    if safe_get_dot(ctx, 'observer', 'type') == 'firewall' and safe_get_dot(ctx, 'event', 'action') is not None:
        return (
            f"Firewall {safe_get_dot(ctx, 'event', 'action')}: "
            f"{safe_get_dot(ctx, 'source', 'ip', default='-')}:{safe_get_dot(ctx, 'source', 'port', default='-')}"
            f" -> "
            f"{safe_get_dot(ctx, 'destination', 'ip', default='-')}:{safe_get_dot(ctx, 'destination', 'port', default='-')}"
        )
    
    # ========================= WINDOWS =========================
    if 'windows' in idx:
        level = safe_get_dot(ctx, 'log', 'level')
        kind = safe_get_dot(ctx, 'event', 'kind')
        action = safe_get_dot(ctx, 'event', 'action')
        msg = safe_get_dot(ctx, 'message')
        
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
        
        return (
            f"Windows Alert: {safe_get_dot(ctx, 'event', 'code', default='-')}"
            f" | Provider: {safe_get_dot(ctx, 'event', 'provider', default='-')}"
            f" | Message: {msg or '-'}"
        )
    
    # ========================= MODSECURITY =========================
    if 'modsecurity' in idx:
        messages = safe_get_dot(ctx, 'modsec', 'audit', 'messages')
        if messages is None or (isinstance(messages, list) and len(messages) == 0):
            return None
        
        query = safe_get_dot(ctx, 'url', 'query')
        if query is None or (isinstance(query, str) and query.strip() == ''):
            return None
        
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
    
    # ========================= FALLBACK =========================
    event_original = safe_get_dot(ctx, 'event', 'original')
    message = safe_get_dot(ctx, 'message')
    
    if event_original is not None or message is not None:
        return event_original if event_original is not None else message
    
    return None


def process_file(input_file: Path, output_file: Path) -> dict:
    """Process a single JSON file"""
    try:
        # Read input
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle different JSON formats
        if isinstance(data, list):
            documents = data
        elif isinstance(data, dict) and 'hits' in data:
            documents = data.get('hits', {}).get('hits', [])
        else:
            documents = [data]
        
        # Process
        results = []
        ml_count = 0
        skipped_count = 0
        
        for doc in documents:
            ctx = flatten_doc(doc)
            idx = ctx.get('_index')
            ml_input = process_log(ctx, idx)
            
            if ml_input:
                doc['ml_input'] = ml_input
                ml_count += 1
            else:
                skipped_count += 1
            
            results.append(doc)
        
        # Write output
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        return {
            'success': True,
            'total': len(results),
            'ml_input': ml_count,
            'skipped': skipped_count,
            'error': None
        }
    
    except Exception as e:
        return {
            'success': False,
            'total': 0,
            'ml_input': 0,
            'skipped': 0,
            'error': str(e)
        }


def main():
    """Main batch processor"""
    
    if len(sys.argv) < 2:
        print("""
Simple Batch Log Processor

Usage:
    python prepare_ml_ready.py <input_dir> [output_dir]

Arguments:
    input_dir   Directory containing input JSON files (required)
    output_dir  Directory to save processed files (default: logs/ml_ready_logs)

Example:
    python prepare_ml_ready.py logs/ecs_logs
    python prepare_ml_ready.py logs/ecs_logs logs/processed
""")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) >= 3 else 'logs/ml_ready_logs'
    
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    if not input_path.exists():
        print(f"[X] Error: Input directory not found: {input_dir}")
        sys.exit(1)
    
    output_path.mkdir(parents=True, exist_ok=True)
    
    json_files = list(input_path.glob('*.json'))
    
    if not json_files:
        print(f"[X] No JSON files found in {input_dir}")
        sys.exit(1)
    
    print("=" * 70)
    print("BATCH LOG PROCESSOR")
    print("=" * 70)
    print(f"Input:  {input_path.absolute()}")
    print(f"Output: {output_path.absolute()}")
    print(f"Files:  {len(json_files)}")
    print("=" * 70)
    print()
    
    results = []
    total_processed = 0
    total_ml_input = 0
    total_skipped = 0
    failed_files = []
    
    start_time = datetime.now()
    
    for i, input_file in enumerate(json_files, 1):
        output_filename = f"{input_file.stem}_ml_input.json"
        output_file = output_path / output_filename
        
        print(f"[{i}/{len(json_files)}] {input_file.name}")
        
        stats = process_file(input_file, output_file)
        
        if stats['success']:
            print(f"    [OK] {stats['ml_input']} with ml_input, {stats['skipped']} skipped")
            total_processed += stats['total']
            total_ml_input += stats['ml_input']
            total_skipped += stats['skipped']
        else:
            print(f"    [X] Failed: {stats['error']}")
            failed_files.append(input_file.name)
        
        results.append({
            'input_file': input_file.name,
            'output_file': output_filename,
            'stats': stats
        })
    
    duration = (datetime.now() - start_time).total_seconds()
    
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Files:     {len(json_files)} total, {len(json_files)-len(failed_files)} success, {len(failed_files)} failed")
    print(f"Documents: {total_processed} total")
    print(f"ML Input:  {total_ml_input} ({total_ml_input/total_processed*100:.1f}%)" if total_processed > 0 else "ML Input:  0")
    print(f"Skipped:   {total_skipped} ({total_skipped/total_processed*100:.1f}%)" if total_processed > 0 else "Skipped:   0")
    print(f"Time:      {duration:.1f}s ({duration/len(json_files):.1f}s/file)")
    print("=" * 70)
    
    if failed_files:
        print("\nFailed files:")
        for f in failed_files:
            print(f"  - {f}")
    
    # Save report
    report_file = output_path / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report = {
        'timestamp': datetime.now().isoformat(),
        'input_dir': str(input_path.absolute()),
        'output_dir': str(output_path.absolute()),
        'total_files': len(json_files),
        'successful': len(json_files) - len(failed_files),
        'failed': len(failed_files),
        'total_documents': total_processed,
        'total_ml_input': total_ml_input,
        'total_skipped': total_skipped,
        'processing_time_seconds': duration,
        'failed_files': failed_files,
        'results': results
    }
    
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    print(f"\nReport: {report_file.name}")


if __name__ == "__main__":
    main()