#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
sqlmap_bulk_host.py - Batch sqlmap scan with host replacement

This script allows you to use sqlmap's -m (bulk file) and -r (request file) 
parameters together by replacing the Host header in the request file for each 
target in the bulk file.

Usage:
    python sqlmap_bulk_host.py -m hosts.txt -r request.txt -- --batch --level=3
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def replace_host_in_request(request_content, new_host):
    """
    Replace the Host header in HTTP request content.
    
    Args:
        request_content (str): Original HTTP request content
        new_host (str): New host value (format: host:port)
    
    Returns:
        str: Modified request content with replaced Host header
    """
    # Match Host: xxx line (case-insensitive, supports spaces)
    # Pattern matches: Host: xxx, host: xxx, HOST: xxx, etc.
    pattern = r'(?i)^(Host:\s*).*$'
    replacement = r'\1' + new_host
    
    modified = re.sub(pattern, replacement, request_content, flags=re.MULTILINE)
    
    # If Host header was not found, add it after the first line (request line)
    if modified == request_content:
        lines = request_content.split('\n')
        if len(lines) > 0:
            # Find where to insert Host header (after request line, before other headers)
            insert_pos = 1
            for i, line in enumerate(lines[1:], start=1):
                if ':' in line and not line.strip().startswith('HTTP/'):
                    insert_pos = i
                    break
                elif not line.strip():
                    insert_pos = i
                    break
            
            lines.insert(insert_pos, f'Host: {new_host}')
            modified = '\n'.join(lines)
    
    return modified


def read_request_file(filepath):
    """
    Read HTTP request file content.
    
    Args:
        filepath (str): Path to the request file
    
    Returns:
        str: Request file content
    
    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Request file not found: {filepath}")
    except IOError as e:
        raise IOError(f"Error reading request file {filepath}: {e}")


def read_bulk_file(filepath):
    """
    Read bulk file and extract host:port targets.
    
    Args:
        filepath (str): Path to the bulk file
    
    Returns:
        list: List of host:port strings
    
    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            targets = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    targets.append(line)
            return targets
    except FileNotFoundError:
        raise FileNotFoundError(f"Bulk file not found: {filepath}")
    except IOError as e:
        raise IOError(f"Error reading bulk file {filepath}: {e}")


def run_sqlmap(request_file, sqlmap_path, sqlmap_args):
    """
    Run sqlmap with the given request file and arguments.
    
    Args:
        request_file (str): Path to the request file
        sqlmap_path (str): Path to sqlmap.py
        sqlmap_args (list): Additional arguments to pass to sqlmap
    
    Returns:
        subprocess.CompletedProcess: Result of the subprocess call
    """
    # Build command: python sqlmap.py -r <request_file> [other_args]
    cmd = [sys.executable, sqlmap_path, '-r', request_file] + sqlmap_args
    
    print(f"Running: {' '.join(cmd)}")
    
    # Run sqlmap and show output in real-time
    result = subprocess.run(
        cmd,
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True
    )
    
    return result


def process_bulk_scan(bulk_file, request_template, sqlmap_path, sqlmap_args):
    """
    Process bulk scan: replace Host header for each target and run sqlmap.
    
    Args:
        bulk_file (str): Path to bulk file containing host:port list
        request_template (str): Path to HTTP request file template
        sqlmap_path (str): Path to sqlmap.py
        sqlmap_args (list): Additional arguments to pass to sqlmap
    
    Returns:
        dict: Statistics about the scan (successful, failed, total)
    """
    # Read bulk file
    print(f"[*] Reading bulk file: {bulk_file}")
    targets = read_bulk_file(bulk_file)
    
    if not targets:
        print("[-] No targets found in bulk file!")
        return {'total': 0, 'successful': 0, 'failed': 0}
    
    print(f"[*] Found {len(targets)} target(s)")
    
    # Read request template
    print(f"[*] Reading request template: {request_template}")
    template = read_request_file(request_template)
    
    # Statistics
    stats = {'total': len(targets), 'successful': 0, 'failed': 0}
    successful_targets = []  # 记录成功的资产
    temp_files = []
    
    try:
        # Process each target
        for i, target in enumerate(targets, 1):
            print(f"\n{'='*60}")
            print(f"[{i}/{len(targets)}] Processing target: {target}")
            print(f"{'='*60}")
            
            # Validate target format (basic check)
            if ':' not in target:
                print(f"[-] Invalid target format (expected host:port): {target}")
                stats['failed'] += 1
                continue
            
            # Replace Host header
            try:
                modified_request = replace_host_in_request(template, target)
            except Exception as e:
                print(f"[-] Error replacing Host header: {e}")
                stats['failed'] += 1
                continue
            
            # Create temporary file
            try:
                # Use a more descriptive temp file name for debugging
                safe_target = target.replace(':', '_').replace('/', '_')
                temp_file = tempfile.NamedTemporaryFile(
                    mode='w',
                    delete=False,
                    suffix='.txt',
                    prefix=f'sqlmap_request_{safe_target}_',
                    dir=os.getcwd()
                )
                temp_file.write(modified_request)
                temp_file.close()
                temp_path = temp_file.name
                temp_files.append(temp_path)
                
                print(f"[*] Created temporary request file: {temp_path}")
            except Exception as e:
                print(f"[-] Error creating temporary file: {e}")
                stats['failed'] += 1
                continue
            
            # Run sqlmap
            try:
                result = run_sqlmap(temp_path, sqlmap_path, sqlmap_args)
                
                if result.returncode == 0:
                    print(f"[+] Scan completed successfully for {target}")
                    stats['successful'] += 1
                    successful_targets.append(target)  # 记录成功的资产
                else:
                    print(f"[-] Scan failed for {target} (exit code: {result.returncode})")
                    stats['failed'] += 1
            except KeyboardInterrupt:
                print("\n[!] Interrupted by user")
                raise
            except Exception as e:
                print(f"[-] Error running sqlmap: {e}")
                stats['failed'] += 1
            finally:
                # Clean up temporary file
                try:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                        print(f"[*] Cleaned up temporary file: {temp_path}")
                except Exception as e:
                    print(f"[!] Warning: Could not delete temporary file {temp_path}: {e}")
    
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Cleaning up...")
    finally:
        # Clean up any remaining temporary files
        for temp_path in temp_files:
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except Exception:
                pass
    
    stats['successful_targets'] = successful_targets  # 将成功资产列表添加到返回结果
    return stats


def parse_args():
    """
    Parse command line arguments.
    
    Returns:
        tuple: (parsed_args, sqlmap_args)
    """
    parser = argparse.ArgumentParser(
        description='Batch sqlmap scan with host replacement',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python sqlmap_bulk_host.py -m hosts.txt -r request.txt -- --batch --level=3
  
  # Specify sqlmap path
  python sqlmap_bulk_host.py -m hosts.txt -r request.txt --sqlmap /path/to/sqlmap.py -- --batch
  
  # With additional sqlmap options
  python sqlmap_bulk_host.py -m hosts.txt -r request.txt -- --batch --level=5 --risk=3 --threads=10
        """
    )
    
    parser.add_argument(
        '-m', '--bulkfile',
        required=True,
        help='Bulk file containing host:port list (one per line)'
    )
    
    parser.add_argument(
        '-r', '--request',
        required=True,
        help='HTTP request file template'
    )
    
    parser.add_argument(
        '--sqlmap',
        default='sqlmap.py',
        help='Path to sqlmap.py (default: sqlmap.py)'
    )
    
    # Parse known arguments, remaining arguments will be passed to sqlmap
    args, sqlmap_args = parser.parse_known_args()
    
    # Remove '--' separator if present
    if '--' in sqlmap_args:
        separator_index = sqlmap_args.index('--')
        sqlmap_args = sqlmap_args[separator_index + 1:]
    
    return args, sqlmap_args


def validate_args(args):
    """
    Validate command line arguments.
    
    Args:
        args: Parsed arguments
    
    Raises:
        ValueError: If validation fails
    """
    # Check if bulk file exists
    if not os.path.exists(args.bulkfile):
        raise ValueError(f"Bulk file not found: {args.bulkfile}")
    
    # Check if request file exists
    if not os.path.exists(args.request):
        raise ValueError(f"Request file not found: {args.request}")
    
    # Check if sqlmap exists
    if not os.path.exists(args.sqlmap):
        raise ValueError(f"sqlmap.py not found: {args.sqlmap}")


def main():
    """Main entry point."""
    try:
        # Parse arguments
        args, sqlmap_args = parse_args()
        
        # Validate arguments
        validate_args(args)
        
        # Print configuration
        print("="*60)
        print("sqlmap Bulk Host Replacement Tool")
        print("="*60)
        print(f"Bulk file: {args.bulkfile}")
        print(f"Request template: {args.request}")
        print(f"sqlmap path: {args.sqlmap}")
        print(f"sqlmap arguments: {' '.join(sqlmap_args) if sqlmap_args else '(none)'}")
        print("="*60)
        
        # Process bulk scan
        stats = process_bulk_scan(
            args.bulkfile,
            args.request,
            args.sqlmap,
            sqlmap_args
        )
        
        # Print summary
        print("\n" + "="*60)
        print("Scan Summary")
        print("="*60)
        print(f"Total targets: {stats['total']}")
        print(f"Successful: {stats['successful']}")
        print(f"Failed: {stats['failed']}")
        print("="*60)
        
        # 将成功的资产写入result.txt
        if 'successful_targets' in stats and stats['successful_targets']:
            result_file = 'result.txt'
            try:
                with open(result_file, 'w', encoding='utf-8') as f:
                    for target in stats['successful_targets']:
                        f.write(target + '\n')
                print(f"\n[+] Successfully saved {len(stats['successful_targets'])} successful targets to {result_file}")
            except Exception as e:
                print(f"\n[!] Warning: Could not write to {result_file}: {e}")
        else:
            print(f"\n[*] No successful targets to save")
        
        # Exit with appropriate code
        sys.exit(0 if stats['failed'] == 0 else 1)
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
