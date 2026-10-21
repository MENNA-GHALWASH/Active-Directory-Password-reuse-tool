#!/usr/bin/env python3
"""
Read parsed_hashes.json (produced by parse_hashes.py) and detect
NT-hash reuse across enabled accounts.

Note on RIDs: Samba's pdbedit reports RID 0xFFFFFFFF (4294967295)
for every account, so RID-based privilege detection doesn't work
against a Samba DC. We match by account name instead.
"""

import json
from collections import defaultdict

PRIVILEGED_NAME_HINTS = ("administrator", "admin", "krbtgt", "domain admin")


def _is_privileged(username: str) -> bool:
    bare = username.split("\\")[-1].lower()
    return any(hint in bare for hint in PRIVILEGED_NAME_HINTS)


def detect_reuse(json_path: str = "parsed_hashes.json"):
    with open(json_path, "r", encoding="utf-8") as f:
        hashes = json.load(f)

    by_nt = defaultdict(list)
    for user, info in hashes.items():
        by_nt[info["nthash"]].append(user)

    findings = []
    for nt, users in by_nt.items():
        if len(users) < 2:
            continue

        has_priv = any(_is_privileged(u) for u in users)
        has_std = any(not _is_privileged(u) for u in users)

        if has_priv and has_std:
            severity = "HIGH"
        elif has_priv:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        findings.append({
            "users": [
                {"username": u, "account_type": "privileged" if _is_privileged(u) else "user"}
                for u in users
            ],
            "hash": nt[:3] + "***",
            "severity": severity,
            "recommendation": (
                "Reset affected passwords via approved account recovery. "
                "Investigate whether the shared hash corresponds to a "
                "shared or default password."
            ),
        })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: order[f["severity"]])
    return findings


if __name__ == "__main__":
    for finding in detect_reuse():
        print(finding)
