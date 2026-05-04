#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.modules.syzbotCrawler import Crawler  # noqa: E402


def parse_args():
    parser = argparse.ArgumentParser(
        description="Crawl syzbot cases and keep ARM/ARM64 cases only."
    )
    parser.add_argument(
        "--url",
        default="https://syzkaller.appspot.com/upstream/fixed",
        help="Syzbot list URL.",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=9999,
        help="Maximum number of cases to retrieve.",
    )
    parser.add_argument(
        "--keyword",
        action="append",
        default=[""],
        help="Filter case title by keyword. Can be provided multiple times.",
    )
    parser.add_argument(
        "--deduplicate",
        action="append",
        default=[],
        help="Deduplicate keyword rules. Can be provided multiple times.",
    )
    parser.add_argument(
        "--crawler-sleep",
        type=int,
        default=5,
        help="Sleep seconds between crawling case details.",
    )
    parser.add_argument(
        "--filter-by-reported",
        type=int,
        default=-1,
        help="Filter by reported days (same as main crawler).",
    )
    parser.add_argument(
        "--filter-by-closed",
        type=int,
        default=-1,
        help="Filter by closed days (same as main crawler).",
    )
    parser.add_argument(
        "--include-high-risk",
        action="store_true",
        help="Include high risk impacted cases.",
    )
    parser.add_argument(
        "--allcase",
        action="store_true",
        help="Keep all crash rows in detail page (do not force upstream-only row).",
    )
    parser.add_argument(
        "--arch-regex",
        default=r"(arm64|aarch64|\\barm\\b)",
        help="Regex used to match manager field.",
    )
    parser.add_argument(
        "--output",
        default="work/Syzbot_ARM_cases_get-basic-info.json",
        help="Output json path.",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Allow missing config/syz_repro/log/report (disabled by default).",
    )
    parser.add_argument(
        "--save-all",
        action="store_true",
        help="Also save all crawled cases before ARM filtering.",
    )
    parser.add_argument(
        "--all-output",
        default="work/Syzbot_ALL_cases_get-basic-info.json",
        help="Path used when --save-all is enabled.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging from crawler.",
    )
    return parser.parse_args()


def resolve_output_path(path):
    if os.path.isabs(path):
        return path
    return os.path.join(PROJECT_ROOT, path)


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def is_non_empty_text(value):
    return isinstance(value, str) and value.strip() != ""


def is_complete_case(case_info):
    required_fields = ["config", "syz_repro", "log", "report"]
    for field in required_fields:
        if not is_non_empty_text(case_info.get(field, "")):
            return False
    return True


def main():
    args = parse_args()

    crawler = Crawler(
        url=args.url,
        keyword=args.keyword,
        max_retrieve=args.max,
        deduplicate=args.deduplicate,
        ignore_batch=[],
        filter_by_reported=args.filter_by_reported,
        filter_by_closed=args.filter_by_closed,
        sleeptime=args.crawler_sleep,
        include_high_risk=args.include_high_risk,
        debug=args.debug,
    )

    # Need detail mode so each case has manager field for architecture filtering.
    crawler.run(OnlyTitle=False, AllCase=args.allcase)

    all_cases = crawler.cases
    arch_re = re.compile(args.arch_regex, re.IGNORECASE)

    arm_cases = {}
    incomplete_count = 0
    for case_hash, case_info in all_cases.items():
        manager = case_info.get("manager", "")
        if arch_re.search(manager):
            if not args.allow_incomplete and not is_complete_case(case_info):
                incomplete_count += 1
                continue
            arm_cases[case_hash] = case_info

    output_path = resolve_output_path(args.output)
    save_json(output_path, arm_cases)

    if args.save_all:
        all_output_path = resolve_output_path(args.all_output)
        save_json(all_output_path, all_cases)
        print(f"[*] Saved all crawled cases to: {all_output_path}")

    print(f"[*] Total crawled cases: {len(all_cases)}")
    print(f"[*] ARM matched cases: {len(arm_cases)}")
    if not args.allow_incomplete:
        print(f"[*] ARM incomplete cases skipped: {incomplete_count}")
    print(f"[*] ARM cases saved to: {output_path}")


if __name__ == "__main__":
    main()
