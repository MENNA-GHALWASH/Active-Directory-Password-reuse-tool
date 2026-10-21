#!/usr/bin/env python3
"""
Read impacket-secretsdump -just-dc output from stdin (piped from
password_reuse.sh) and build a structured map:

    {
      "DOMAIN\\username": {
          "rid": "500",
          "lmhash": "...",
          "nthash": "..."
      },
      ...
    }

Also reports NT-hash reuse across accounts.
"""

import re
import sys
from collections import defaultdict

# DOMAIN\user:rid:lmhash:nthash:::  (single colon separators)
LINE_RE = re.compile(
    r'^(?P<user>[^:]+):(?P<rid>\d+):(?P<lmhash>[0-9a-fA-F]+):(?P<nthash>[0-9a-fA-F]+):'
)


def parse_stream(stream):
    """Consume an iterable of text lines, return a dict of parsed hashes."""
    hashes = {}
    skipped = 0

    for line_no, raw in enumerate(stream, 1):
        line = raw.strip()
        if not line:
            continue
        m = LINE_RE.match(line)
        if not m:
            # Informational lines from impacket, banners, etc.
            skipped += 1
            continue
        user = m.group('user')
        hashes[user] = {
            'rid':    m.group('rid'),
            'lmhash': m.group('lmhash'),
            'nthash': m.group('nthash'),
        }

    return hashes, skipped


def report_reuse(hashes):
    """Group accounts by NT hash and print those shared by >1 user."""
    by_nt = defaultdict(list)
    for user, info in hashes.items():
        by_nt[info['nthash']].append(user)

    reused = {h: users for h, users in by_nt.items() if len(users) > 1}
    if not reused:
        print("[+] No NT-hash reuse detected.", file=sys.stderr)
        return reused

    print(f"[!] {len(reused)} NT hash(es) reused across multiple accounts:", file=sys.stderr)
    for h, users in reused.items():
        print(f"    {h}  ->  {', '.join(sorted(users))}", file=sys.stderr)
    return reused


def main():
    # If a filename is given, read it; otherwise read stdin (piped mode).
    if len(sys.argv) >= 2:
        with open(sys.argv[1], 'r', encoding='utf-8', errors='ignore') as f:
            hashes, skipped = parse_stream(f)
    else:
        hashes, skipped = parse_stream(sys.stdin)

    if not hashes:
        print("[!] No hash lines found in input.", file=sys.stderr)
        sys.exit(2)

    print(f"[+] Parsed {len(hashes)} accounts ({skipped} non-hash lines skipped).",
          file=sys.stderr)
    report_reuse(hashes)

    import json
    out_path = "parsed_hashes.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=2)
    print(f"[+] Wrote map to {out_path}", file=sys.stderr)

    # Hand the map to the rest of your program here, e.g.:
    #   from detector import score
    #   score(hashes)


if __name__ == '__main__':
    main()
