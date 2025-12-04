"""
Extract ML Input
Read all processed log files and extract only ml_input fields
Consolidate into a single file for ML training
"""

import json
import sys
from pathlib import Path
from datetime import datetime


def extract_ml_inputs_from_file(file_path: Path) -> list:
    """
    Extract all ml_input fields from a single JSON file
    
    Returns:
        list: List of dicts with ml_input and metadata
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle different JSON formats
        if isinstance(data, list):
            documents = data
        elif isinstance(data, dict) and 'hits' in data:
            documents = data.get('hits', {}).get('hits', [])
        else:
            documents = [data]
        
        ml_inputs = []
        
        for doc in documents:
            # Check if document has ml_input
            if 'ml_input' in doc:
                ml_input_entry = {
                    'ml_input': doc['ml_input'],
                    'source_index': doc.get('_index', 'unknown'),
                    'source_id': doc.get('_id', 'unknown'),
                    'source_file': file_path.name
                }
                ml_inputs.append(ml_input_entry)
        
        return ml_inputs
    
    except Exception as e:
        print(f"    [!] Error reading {file_path.name}: {e}")
        return []


def extract_all_ml_inputs(
    input_dir: str = 'assets/eval_logs/processed_logs',
    output_file: str = 'logs/ml_input.json',
    include_metadata: bool = True
):
    """
    Extract all ml_input fields from processed logs
    
    Args:
        input_dir: Directory containing processed JSON files
        output_file: Output file path for consolidated ml_inputs
        include_metadata: Include source_index, source_id, source_file metadata
    """
    
    input_path = Path(input_dir)
    output_path = Path(output_file)
    
    # Validate input directory
    if not input_path.exists():
        print(f"[X] Error: Input directory not found: {input_dir}")
        sys.exit(1)
    
    # Find all JSON files (exclude reports)
    json_files = [
        f for f in input_path.glob('*.json')
        if not f.name.startswith('report_')
    ]
    
    if not json_files:
        print(f"[X] No JSON files found in {input_dir}")
        sys.exit(1)
    
    print("=" * 70)
    print("ML INPUT EXTRACTOR")
    print("=" * 70)
    print(f"Input directory: {input_path.absolute()}")
    print(f"Output file:     {output_path.absolute()}")
    print(f"Found {len(json_files)} files to process")
    print("=" * 70)
    print()
    
    all_ml_inputs = []
    file_stats = []
    
    # Process each file
    for i, json_file in enumerate(json_files, 1):
        print(f"[{i}/{len(json_files)}] Processing: {json_file.name}")
        
        ml_inputs = extract_ml_inputs_from_file(json_file)
        
        if ml_inputs:
            print(f"    [OK] Extracted {len(ml_inputs)} ml_input entries")
            all_ml_inputs.extend(ml_inputs)
            file_stats.append({
                'file': json_file.name,
                'count': len(ml_inputs)
            })
        else:
            print(f"    [!] No ml_input fields found")
            file_stats.append({
                'file': json_file.name,
                'count': 0
            })
    
    print()
    print("=" * 70)
    print("CONSOLIDATING DATA")
    print("=" * 70)
    
    # Create output directory if needed
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Simple TXT mode
    if '--simple-txt' in sys.argv:
        simple_list = [entry['ml_input'] for entry in all_ml_inputs]

        # Force .txt extension
        if not output_path.suffix:
            output_path = output_path.with_suffix('.txt')

        with open(output_path, "w", encoding="utf-8") as f:
            for line in simple_list:
                clean_line = " ".join(str(line).splitlines())  # remove newlines
                f.write(f"ml_input: {clean_line}\n")

        print(f"[OK] Saved TXT simple output: {output_path}")
        return len(all_ml_inputs)


    # JSON modes
    if include_metadata:
        # Full JSON format
        output_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_entries': len(all_ml_inputs),
                'source_directory': str(input_path.absolute()),
                'file_statistics': file_stats
            },
            'ml_inputs': all_ml_inputs
        }
    else:
        # Only list of ml_input
        output_data = [entry['ml_input'] for entry in all_ml_inputs]

    # Write JSON
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

    print(f"[OK] Saved JSON output: {output_path}")


    
    print(f"Total ml_input entries: {len(all_ml_inputs)}")
    print(f"Output saved to: {output_path}")
    print("=" * 70)
    
    # Print statistics by file
    print()
    print("Statistics by file:")
    print("-" * 70)
    for stat in sorted(file_stats, key=lambda x: x['count'], reverse=True):
        if stat['count'] > 0:
            print(f"  {stat['file']:40s} {stat['count']:6d} entries")
    print("-" * 70)
    print(f"  {'TOTAL':40s} {len(all_ml_inputs):6d} entries")
    print()
    
    return len(all_ml_inputs)


def main():
    """Main function with command line interface"""
    
    if len(sys.argv) < 1:
        print("""
ML Input Extractor - Extract all ml_input fields from processed logs

Usage:
    python extract_ml_input.py [input_dir] [output_file] [--simple]

Arguments:
    input_dir    Directory with processed JSON files (default: assets/eval_logs/processed_logs)
    output_file  Output JSON file path (default: assets/eval_input/ml_input.json)
    --simple     Output simple format (just ml_input strings, no metadata)

Examples:
    # Use defaults
    python extract_ml_input.py
    
    # Custom paths
    python extract_ml_input.py assets/eval_logs/processed_logs assets/eval_input/eval_data.json
    
    # Simple format (no metadata)
    python extract_ml_input.py assets/eval_logs/processed_logs assets/eval_input/eval_data.txt --simple-txt
""")
        sys.exit(1)
    
    # Parse arguments
    input_dir = sys.argv[1] if len(sys.argv) >= 2 else 'assets/eval_logs/processed_logs'
    output_file = sys.argv[2] if len(sys.argv) >= 3 else 'assets/eval_input/eval_data.json'
    if '--simple-txt' in sys.argv:
        include_metadata = False
    elif '--simple' in sys.argv:
        include_metadata = False
    else:
        include_metadata = True
    
    try:
        total = extract_all_ml_inputs(input_dir, output_file, include_metadata)
        
        if total > 0:
            print(f"[OK] Successfully extracted {total} ml_input entries")
            sys.exit(0)
        else:
            print(f"[!] No ml_input entries found")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\n[!] Extraction interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[X] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()