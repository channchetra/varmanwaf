#!/usr/bin/env python3
"""Aggregate waf-bench replay JSONL results into a markdown summary.

Usage: summarize.py results/g1.jsonl results/g2.jsonl ... > summary.md

Verdict buckets come straight from replay.py. Two reporting calibres:

  strict  — only `blocked` (403/503) counts as blocked
  wide    — `blocked` + `protocol_reject` + `error` count as blocked
            (calibre used when reconciling against the official blazehttp
            binary, which cannot distinguish proxy-layer rejections)
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

VERDICTS = ["blocked", "passed", "protocol_reject", "rate_limited", "error"]


def load(paths):
    groups = defaultdict(list)
    for path in paths:
        with open(path) as handle:
            for line in handle:
                line = line.strip()
                if line:
                    record = json.loads(line)
                    groups[record["group"]].append(record)
    return groups


def percentile(values, pct):
    if not values:
        return 0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(len(ordered) * pct / 100))
    return ordered[idx]


def wide_blocked(record):
    return record["verdict"] in ("blocked", "protocol_reject", "error") or (
        record["verdict"].startswith("status_")
        and record.get("detail", "").endswith(("reset", "timeout"))
    )


def group_summary(records):
    black = [r for r in records if r["expected"] == "black"]
    white = [r for r in records if r["expected"] == "white"]
    black_blocked = sum(1 for r in black if r["verdict"] == "blocked")
    white_blocked = sum(1 for r in white if r["verdict"] == "blocked")
    black_wide = sum(1 for r in black if wide_blocked(r))
    white_wide = sum(1 for r in white if wide_blocked(r))
    latencies = [r["latency_ms"] for r in records]
    errors = sum(1 for r in records if r["verdict"] == "error")
    return {
        "total": len(records),
        "black": len(black),
        "white": len(white),
        "black_blocked": black_blocked,
        "white_blocked": white_blocked,
        "black_wide": black_wide,
        "white_wide": white_wide,
        "block_rate_strict": 100.0 * black_blocked / len(black) if black else 0,
        "fp_rate_strict": 100.0 * white_blocked / len(white) if white else 0,
        "block_rate_wide": 100.0 * black_wide / len(black) if black else 0,
        "fp_rate_wide": 100.0 * white_wide / len(white) if white else 0,
        "p50": percentile(latencies, 50),
        "p95": percentile(latencies, 95),
        "error_rate": 100.0 * errors / len(records) if records else 0,
    }


def category_table(records, expected):
    """rows: category -> {n, blocked, wide, examples[list of (file, verdict)]}"""
    rows = defaultdict(lambda: {"n": 0, "blocked": 0, "wide": 0, "examples": []})
    for r in records:
        if r["expected"] != expected:
            continue
        row = rows[r["category"]]
        row["n"] += 1
        if r["verdict"] == "blocked":
            row["blocked"] += 1
        elif wide_blocked(r):
            row["wide"] += 1
        if expected == "white" and r["verdict"] == "blocked" and len(row["examples"]) < 5:
            row["examples"].append(r["file"])
        if expected == "black" and r["verdict"] == "passed" and len(row["examples"]) < 5:
            row["examples"].append(r["file"])
    return rows


def main():
    groups = load([Path(p) for p in sys.argv[1:]])
    if not groups:
        print("no results given", file=sys.stderr)
        return

    print("# waf-bench summary\n")
    print("## Overall (per group)\n")
    print("| group | total | black | white | black blocked (strict) | block rate | "
          "white blocked (strict) | FP rate | block rate (wide) | FP rate (wide) | "
          "p50 ms | p95 ms | error % |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for group in sorted(groups):
        s = group_summary(groups[group])
        print(
            f"| {group} | {s['total']} | {s['black']} | {s['white']} "
            f"| {s['black_blocked']} | {s['block_rate_strict']:.1f}% "
            f"| {s['white_blocked']} | {s['fp_rate_strict']:.2f}% "
            f"| {s['block_rate_wide']:.1f}% | {s['fp_rate_wide']:.2f}% "
            f"| {s['p50']} | {s['p95']} | {s['error_rate']:.2f}% |"
        )

    for group in sorted(groups):
        records = groups[group]
        print(f"\n## {group}: black samples by category\n")
        print("| category | n | blocked (strict) | +wide | block rate |")
        print("|---|---|---|---|---|")
        for category, row in sorted(
            category_table(records, "black").items(),
            key=lambda item: -item[1]["n"],
        ):
            rate = 100.0 * row["blocked"] / row["n"] if row["n"] else 0
            print(
                f"| {category} | {row['n']} | {row['blocked']} | {row['wide']} "
                f"| {rate:.1f}% |"
            )

        print(f"\n## {group}: white false positives by category\n")
        print("| category | n | blocked | FP rate | examples |")
        print("|---|---|---|---|---|")
        for category, row in sorted(
            category_table(records, "white").items(),
            key=lambda item: -item[1]["blocked"],
        ):
            if row["blocked"] == 0:
                continue
            rate = 100.0 * row["blocked"] / row["n"] if row["n"] else 0
            examples = ", ".join(f"`{e}`" for e in row["examples"])
            print(f"| {category} | {row['n']} | {row['blocked']} | {rate:.2f}% | {examples} |")

        print(f"\n## {group}: missed black samples (passed) by category\n")
        print("| category | missed | example files |")
        print("|---|---|---|")
        for category, row in sorted(
            category_table(records, "black").items(),
            key=lambda item: -item[1]["n"],
        ):
            missed = row["n"] - row["blocked"]
            if missed == 0:
                continue
            examples = ", ".join(f"`{e}`" for e in row["examples"])
            print(f"| {category} | {missed} | {examples} |")


if __name__ == "__main__":
    main()
