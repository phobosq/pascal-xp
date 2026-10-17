#!/usr/bin/env python3
"""Fail closed when focused RVA manifest does not match input driver bytes."""
import argparse
import hashlib
import json
from pathlib import Path

def verify(manifest, platform, path):
    expected = manifest['input_sha256'][platform].lower()
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        raise ValueError('%s SHA256 mismatch: expected %s, got %s; refusing stale RVA trace' % (platform, expected, actual))
    if not manifest['platforms'][platform]['focus_addresses']:
        raise ValueError('empty focused RVA target list')
    return actual

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--manifest', required=True)
    p.add_argument('--platform', required=True, choices=['xp','win7'])
    p.add_argument('--input', required=True)
    a = p.parse_args()
    m = json.loads(Path(a.manifest).read_text())
    print('%s SHA256 verified: %s' % (a.platform, verify(m, a.platform, a.input)))

if __name__ == '__main__':
    main()
