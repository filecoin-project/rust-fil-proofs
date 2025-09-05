#!/usr/bin/env python3
"""
Compare two Cargo.lock files and show version differences.

This script is useful for reviewing changes between releases, particularly
to ensure that dependency updates are minimal and intentional.

Usage: 
    python3 scripts/compare-locks.py <old-lock> <new-lock>

Example:
    python3 scripts/compare-locks.py releases/Cargo.lock.v19.0.0 releases/Cargo.lock.v19.0.1
"""

import sys
import re
from collections import defaultdict

def parse_lock_file(filepath):
    """Parse a Cargo.lock file and return a dict of package -> version."""
    packages = defaultdict(list)
    current_pkg = None
    current_version = None
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line == '[[package]]':
                if current_pkg and current_version:
                    packages[current_pkg].append(current_version)
                current_pkg = None
                current_version = None
            elif line.startswith('name = '):
                match = re.search(r'name = "([^"]+)"', line)
                if match:
                    current_pkg = match.group(1)
            elif line.startswith('version = '):
                match = re.search(r'version = "([^"]+)"', line)
                if match:
                    current_version = match.group(1)
    
    # Don't forget the last package
    if current_pkg and current_version:
        packages[current_pkg].append(current_version)
    
    return packages

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 scripts/compare-locks.py <old-lock> <new-lock>")
        sys.exit(1)
    
    old_file = sys.argv[1]
    new_file = sys.argv[2]
    
    try:
        old_pkgs = parse_lock_file(old_file)
        new_pkgs = parse_lock_file(new_file)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    print(f"Comparing Cargo.lock files")
    print(f"  Old: {old_file}")
    print(f"  New: {new_file}")
    print("=" * 60)
    print()
    
    # Find changes
    all_packages = set(old_pkgs.keys()) | set(new_pkgs.keys())
    changes = []
    workspace_changes = []
    external_changes = []
    
    for pkg in sorted(all_packages):
        old_versions = sorted(old_pkgs.get(pkg, []))
        new_versions = sorted(new_pkgs.get(pkg, []))
        
        if old_versions != new_versions:
            # Package changed
            if old_versions and new_versions:
                # Updated
                if len(old_versions) == 1 and len(new_versions) == 1:
                    change = f"{pkg}: {old_versions[0]} → {new_versions[0]}"
                else:
                    # Multiple versions exist
                    change = f"{pkg}: {old_versions} → {new_versions}"
                
                changes.append(change)
                
                # Categorize
                if pkg.startswith(('fil-proofs-', 'filecoin-', 'storage-proofs-')) or pkg in ['fr32', 'sha2raw']:
                    workspace_changes.append(change)
                else:
                    external_changes.append(change)
            elif new_versions:
                changes.append(f"{pkg}: (new) {new_versions}")
            else:
                changes.append(f"{pkg}: {old_versions} (removed)")
    
    if changes:
        print("All changes:")
        for change in changes:
            print(f"  • {change}")
        print()
        
        if workspace_changes:
            print(f"Workspace packages ({len(workspace_changes)}):")
            for change in workspace_changes:
                print(f"  • {change}")
            print()
        
        if external_changes:
            print(f"External dependencies ({len(external_changes)}):")
            for change in external_changes:
                print(f"  • {change}")
        else:
            print("External dependencies: No changes (workspace-only update)")
    else:
        print("No changes detected")
    
    print()
    print("=" * 60)
    print(f"Summary: {len(changes)} package(s) changed")

if __name__ == '__main__':
    main()