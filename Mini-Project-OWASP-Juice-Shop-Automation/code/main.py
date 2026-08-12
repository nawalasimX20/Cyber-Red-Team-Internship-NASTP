#!/usr/bin/env python3
"""
main.py - interactive entry point.

Flow:
  1. Connect + register a throwaway test account on the target Juice Shop.
  2. Show a menu of the 10 OWASP Top 10:2025 categories.
  3. User picks one, several, or all of them (repeatable - can run more
     categories after seeing live results, before finishing).
  4. Each test prints live as it runs: the request that was sent and what
     came back (pass/fail), same as a manual tester narrating their steps.
  5. When the user chooses "Finish & view report", every result collected
     in the session (across however many rounds they ran) is written to
     juice_report.json and juice_report.html and the path is printed.

Usage:
    python3 main.py --url http://localhost:3000
"""

import argparse
import sys

from client import JuiceShopClient
from modules import CATEGORY_MODULES
from report import save_json, save_html

RESULT_ICON = {"VULNERABLE": "\033[91m[VULNERABLE]\033[0m",
               "NOT TRIGGERED": "\033[92m[NOT TRIGGERED]\033[0m",
               "INFO": "\033[94m[INFO]\033[0m"}


def print_menu():
    print("\n============================================================")
    print(" OWASP Juice Shop - Automated OWASP Top 10:2025 Tester")
    print("============================================================")
    for key, (label, _) in CATEGORY_MODULES.items():
        print(f"  {key}  {label}")
    print("  ALL  Run every category")
    print("  R    Show report so far (generates it without ending the session)")
    print("  Q    Finish and write the final report")
    print("============================================================")


def run_category(client, key, all_results):
    label, func = CATEGORY_MODULES[key]
    print(f"\n--- Running {label} ---")
    results = func(client)
    for r in results:
        print(f"  > {r['request']}")
        print(f"    {RESULT_ICON.get(r['result'], r['result'])}  {r['test_name']}")
    all_results.extend(results)
    print(f"--- {label}: {len(results)} test(s) completed ---")
    return results


def generate_report(client, all_results, final=False):
    if not all_results:
        print("\nNo tests have been run yet - nothing to report.")
        return
    json_path = save_json(all_results, "juice_report.json")
    html_path = save_html(all_results, client.base_url, "juice_report.html")
    tag = "FINAL " if final else ""
    print(f"\n{tag}Report generated:")
    print(f"  JSON : {json_path}")
    print(f"  HTML : {html_path}  (open in a browser for the color-coded scorecard)")


def main():
    parser = argparse.ArgumentParser(description="Automated OWASP Top 10:2025 tester for OWASP Juice Shop")
    parser.add_argument("--url", default="http://localhost:3000", help="Base URL of the target Juice Shop instance")
    args = parser.parse_args()

    print(f"Target: {args.url}")
    print("Connecting and registering a throwaway test account...")
    client = JuiceShopClient(args.url)
    ok, resp = client.register_test_account()
    if ok:
        print(f"  Logged in as {client.email}")
    else:
        print(f"  Could not authenticate (status {getattr(resp, 'status_code', '?')}). "
              f"Unauthenticated-only tests will still run.")

    all_results = []

    while True:
        print_menu()
        choice = input("Select a category (or ALL / R / Q): ").strip().upper()

        if choice == "Q":
            generate_report(client, all_results, final=True)
            print("\nSession ended.")
            break
        elif choice == "R":
            generate_report(client, all_results, final=False)
        elif choice == "ALL":
            for key in CATEGORY_MODULES:
                run_category(client, key, all_results)
        elif choice in CATEGORY_MODULES:
            run_category(client, choice, all_results)
        else:
            print(f"'{choice}' is not a valid option - pick one of the codes shown above.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
