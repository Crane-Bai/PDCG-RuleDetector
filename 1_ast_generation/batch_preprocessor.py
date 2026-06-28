import os
import sys
import json
import multiprocessing
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
import argparse
import time

from preprocessor import process_package


def process_single_package(package_info):
    """
    Wrapper for processing a single package in a worker process.

    Args:
        package_info (tuple): (package_dir, package_name, package_type)

    Returns:
        dict: processing result
    """
    package_dir, package_name, package_type = package_info

    try:
        js_files = process_package(package_dir)

        behavior_virtual_files = [f for f in js_files if '_virtual_behavior_script.js' in f]
        placeholder_virtual_files = [f for f in js_files if '_virtual_placeholder_script.js' in f]
        has_behavior_virtual = len(behavior_virtual_files) > 0
        has_placeholder_virtual = len(placeholder_virtual_files) > 0
        has_any_virtual = has_behavior_virtual or has_placeholder_virtual

        return {
            'package_name': package_name,
            'package_type': package_type,
            'package_dir': package_dir,
            'status': 'success',
            'js_files_count': len(js_files),
            'js_files': js_files,
            'has_virtual_file': has_any_virtual,
            'has_behavior_virtual': has_behavior_virtual,
            'has_placeholder_virtual': has_placeholder_virtual,
            'behavior_virtual_count': len(behavior_virtual_files),
            'placeholder_virtual_count': len(placeholder_virtual_files),
            'error': None
        }

    except Exception as e:
        return {
            'package_name': package_name,
            'package_type': package_type,
            'package_dir': package_dir,
            'status': 'error',
            'js_files_count': 0,
            'js_files': [],
            'has_virtual_file': False,
            'has_behavior_virtual': False,
            'has_placeholder_virtual': False,
            'behavior_virtual_count': 0,
            'placeholder_virtual_count': 0,
            'error': str(e)
        }


def collect_packages(base_dir):
    """
    Collect packages under benign/ and malicious/ directories.
    """
    packages = []
    base_path = Path(base_dir)

    for package_type in ['malicious', 'benign']:
        type_dir = base_path / package_type

        if not type_dir.exists():
            print(f"Warning: directory not found: {type_dir}")
            continue

        print(f"Collecting {package_type} packages...")

        for package_dir in type_dir.iterdir():
            if package_dir.is_dir():
                packages.append((
                    str(package_dir),
                    package_dir.name,
                    package_type
                ))

    return packages


def collect_packages_direct(base_dir):
    """
    Collect all packages directly under a directory without benign/malicious split.
    """
    packages = []
    base_path = Path(base_dir)

    if not base_path.exists():
        print(f"Error: directory not found: {base_path}")
        return packages

    print(f"Collecting all packages directly under: {base_dir}")

    for package_dir in base_path.iterdir():
        if package_dir.is_dir():
            packages.append((
                str(package_dir),
                package_dir.name,
                'unknown'
            ))

    return packages


def save_results(results, output_file):
    """Save processing results to a JSON file."""
    total_packages = len(results)
    successful_packages = len([r for r in results if r['status'] == 'success'])
    failed_packages = len([r for r in results if r['status'] == 'error'])
    packages_with_virtual_files = len([r for r in results if r['has_virtual_file']])
    packages_with_behavior_virtual = len([r for r in results if r.get('has_behavior_virtual', False)])
    packages_with_placeholder_virtual = len([r for r in results if r.get('has_placeholder_virtual', False)])

    malicious_packages = [r for r in results if r['package_type'] == 'malicious']
    benign_packages = [r for r in results if r['package_type'] == 'benign']
    unknown_packages = [r for r in results if r['package_type'] == 'unknown']

    malicious_with_virtual = len([r for r in malicious_packages if r['has_virtual_file']])
    benign_with_virtual = len([r for r in benign_packages if r['has_virtual_file']])
    unknown_with_virtual = len([r for r in unknown_packages if r['has_virtual_file']])

    malicious_with_behavior = len([r for r in malicious_packages if r.get('has_behavior_virtual', False)])
    benign_with_behavior = len([r for r in benign_packages if r.get('has_behavior_virtual', False)])
    unknown_with_behavior = len([r for r in unknown_packages if r.get('has_behavior_virtual', False)])

    malicious_with_placeholder = len([r for r in malicious_packages if r.get('has_placeholder_virtual', False)])
    benign_with_placeholder = len([r for r in benign_packages if r.get('has_placeholder_virtual', False)])
    unknown_with_placeholder = len([r for r in unknown_packages if r.get('has_placeholder_virtual', False)])

    summary = {
        'processing_summary': {
            'total_packages': total_packages,
            'successful_packages': successful_packages,
            'failed_packages': failed_packages,
            'success_rate': round(successful_packages / total_packages * 100, 2) if total_packages > 0 else 0,
            'packages_with_virtual_files': packages_with_virtual_files,
            'virtual_file_rate': round(packages_with_virtual_files / total_packages * 100, 2) if total_packages > 0 else 0,
            'packages_with_behavior_virtual': packages_with_behavior_virtual,
            'behavior_virtual_rate': round(packages_with_behavior_virtual / total_packages * 100, 2) if total_packages > 0 else 0,
            'packages_with_placeholder_virtual': packages_with_placeholder_virtual,
            'placeholder_virtual_rate': round(packages_with_placeholder_virtual / total_packages * 100, 2) if total_packages > 0 else 0
        },
        'by_type': {
            'malicious': {
                'total': len(malicious_packages),
                'with_virtual_files': malicious_with_virtual,
                'virtual_file_rate': round(malicious_with_virtual / len(malicious_packages) * 100, 2) if malicious_packages else 0,
                'with_behavior_virtual': malicious_with_behavior,
                'behavior_virtual_rate': round(malicious_with_behavior / len(malicious_packages) * 100, 2) if malicious_packages else 0,
                'with_placeholder_virtual': malicious_with_placeholder,
                'placeholder_virtual_rate': round(malicious_with_placeholder / len(malicious_packages) * 100, 2) if malicious_packages else 0
            },
            'benign': {
                'total': len(benign_packages),
                'with_virtual_files': benign_with_virtual,
                'virtual_file_rate': round(benign_with_virtual / len(benign_packages) * 100, 2) if benign_packages else 0,
                'with_behavior_virtual': benign_with_behavior,
                'behavior_virtual_rate': round(benign_with_behavior / len(benign_packages) * 100, 2) if benign_packages else 0,
                'with_placeholder_virtual': benign_with_placeholder,
                'placeholder_virtual_rate': round(benign_with_placeholder / len(benign_packages) * 100, 2) if benign_packages else 0
            },
            'unknown': {
                'total': len(unknown_packages),
                'with_virtual_files': unknown_with_virtual,
                'virtual_file_rate': round(unknown_with_virtual / len(unknown_packages) * 100, 2) if unknown_packages else 0,
                'with_behavior_virtual': unknown_with_behavior,
                'behavior_virtual_rate': round(unknown_with_behavior / len(unknown_packages) * 100, 2) if unknown_packages else 0,
                'with_placeholder_virtual': unknown_with_placeholder,
                'placeholder_virtual_rate': round(unknown_with_placeholder / len(unknown_packages) * 100, 2) if unknown_packages else 0
            }
        },
        'detailed_results': results
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)


def print_summary(results):
    """Print a processing summary."""
    total = len(results)
    successful = len([r for r in results if r['status'] == 'success'])
    failed = len([r for r in results if r['status'] == 'error'])
    with_virtual = len([r for r in results if r['has_virtual_file']])
    with_behavior = len([r for r in results if r.get('has_behavior_virtual', False)])
    with_placeholder = len([r for r in results if r.get('has_placeholder_virtual', False)])

    malicious = [r for r in results if r['package_type'] == 'malicious']
    benign = [r for r in results if r['package_type'] == 'benign']
    unknown = [r for r in results if r['package_type'] == 'unknown']

    malicious_virtual = len([r for r in malicious if r['has_virtual_file']])
    benign_virtual = len([r for r in benign if r['has_virtual_file']])
    unknown_virtual = len([r for r in unknown if r['has_virtual_file']])

    malicious_behavior = len([r for r in malicious if r.get('has_behavior_virtual', False)])
    benign_behavior = len([r for r in benign if r.get('has_behavior_virtual', False)])
    unknown_behavior = len([r for r in unknown if r.get('has_behavior_virtual', False)])

    malicious_placeholder = len([r for r in malicious if r.get('has_placeholder_virtual', False)])
    benign_placeholder = len([r for r in benign if r.get('has_placeholder_virtual', False)])
    unknown_placeholder = len([r for r in unknown if r.get('has_placeholder_virtual', False)])

    print("\n" + "=" * 60)
    print("Batch preprocessing summary")
    print("=" * 60)

    if total == 0:
        print("No packages were processed.")
        return

    print(f"Total packages: {total}")
    print(f"Successfully processed: {successful} ({successful/total*100:.1f}%)")
    print(f"Failed: {failed} ({failed/total*100:.1f}%)")
    print(f"Packages with virtual files: {with_virtual} ({with_virtual/total*100:.1f}%)")
    print(f"  Behavior virtual files: {with_behavior} ({with_behavior/total*100:.1f}%)")
    print(f"  Placeholder virtual files: {with_placeholder} ({with_placeholder/total*100:.1f}%)")

    print("\nBy type:")

    if len(malicious) > 0:
        print(f"  Malicious: {len(malicious)}")
        print(f"    With any virtual file: {malicious_virtual} ({malicious_virtual/len(malicious)*100:.1f}%)")
        print(f"    With behavior virtual file: {malicious_behavior} ({malicious_behavior/len(malicious)*100:.1f}%)")
        print(f"    With placeholder virtual file: {malicious_placeholder} ({malicious_placeholder/len(malicious)*100:.1f}%)")
    else:
        print("  Malicious: 0")

    if len(benign) > 0:
        print(f"  Benign: {len(benign)}")
        print(f"    With any virtual file: {benign_virtual} ({benign_virtual/len(benign)*100:.1f}%)")
        print(f"    With behavior virtual file: {benign_behavior} ({benign_behavior/len(benign)*100:.1f}%)")
        print(f"    With placeholder virtual file: {benign_placeholder} ({benign_placeholder/len(benign)*100:.1f}%)")
    else:
        print("  Benign: 0")

    if len(unknown) > 0:
        print(f"  Unknown/direct: {len(unknown)}")
        print(f"    With any virtual file: {unknown_virtual} ({unknown_virtual/len(unknown)*100:.1f}%)")
        print(f"    With behavior virtual file: {unknown_behavior} ({unknown_behavior/len(unknown)*100:.1f}%)")
        print(f"    With placeholder virtual file: {unknown_placeholder} ({unknown_placeholder/len(unknown)*100:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description='Batch NPM package preprocessor')
    parser.add_argument('--base_dir', required=True, help='Base directory containing packages')
    parser.add_argument('--output', default='batch_preprocessing_results.json', help='Output JSON file')
    parser.add_argument('--workers', type=int, default=max(1, multiprocessing.cpu_count() - 1), help='Number of worker processes')
    parser.add_argument('--sample', type=int, default=0, help='Only process the first N packages (0 = all)')
    parser.add_argument('--mode', choices=['classified', 'direct'], default='classified', help='Package collection mode')
    args = parser.parse_args()

    if args.mode == 'classified':
        packages = collect_packages(args.base_dir)
    else:
        packages = collect_packages_direct(args.base_dir)

    if args.sample > 0:
        packages = packages[:args.sample]

    print(f"Collected {len(packages)} packages")
    print(f"Using {args.workers} worker processes")

    results = []
    start = time.time()

    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(process_single_package, pkg): pkg for pkg in packages}
        for future in tqdm(as_completed(futures), total=len(futures), desc='Processing packages'):
            results.append(future.result())

    elapsed = time.time() - start
    print(f"Processing finished in {elapsed:.1f}s")

    save_results(results, args.output)
    print_summary(results)
    print(f"Results saved to: {args.output}")


if __name__ == '__main__':
    main()
