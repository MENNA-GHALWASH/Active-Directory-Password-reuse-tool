
import csv
from collections import defaultdict

def detect_reuse(csv_path):
    groups = defaultdict(list)

    with open(csv_path, newline="", encoding="utf-8") as file:
        for user in csv.DictReader(file):
            if user["enabled"].lower() != "true":
                continue

            groups[user["hash"]].append(user)

    findings = []

    for hash_value, users in groups.items():
        if len(users) < 2:
            continue

        has_privileged = any(
            user["account_type"] == "privileged"
            for user in users
        )
        has_standard = any(
            user["account_type"] == "user"
            for user in users
        )

        severity = (
            "HIGH"
            if has_privileged and has_standard
            else "REVIEW"
        )

        findings.append({
            "users": [user["username"] for user in users],
            "hash": hash_value[:3] + "***",
            "severity": severity,
            "recommendation": (
                "Review access and reset affected passwords "
                "through the approved account recovery process."
            )
        })

    return findings


if __name__ == "__main__":
    for finding in detect_reuse("users.csv"):
        print(finding)
