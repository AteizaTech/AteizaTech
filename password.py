#!/usr/bin/env python3
"""
Security Checker CLI
Password strength/breach checking + malicious URL detection (heuristic + VirusTotal).
"""

import re
import csv
import time
import hashlib
import argparse
import requests
from pathlib import Path
from urllib.parse import urlparse

# ---------- Password checks ----------

def check_password_strength(password):
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Use at least 12 characters")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add an uppercase letter")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add a lowercase letter")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add a number")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add a special character")

    ratings = {0: "Very Weak", 1: "Weak", 2: "Weak", 3: "Moderate", 4: "Strong", 5: "Very Strong"}
    return ratings[score], feedback


def check_pwned(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        return None, f"Could not reach HIBP API: {e}"

    hashes = (line.split(":") for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return int(count), None

    return 0, None


# ---------- URL / link heuristics ----------

SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".click", ".gq", ".tk", ".work", ".country"}
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
PHISHING_KEYWORDS = {"login", "verify", "account", "update", "secure", "banking", "confirm", "signin"}
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def analyze_url_heuristics(url):
    flags = []
    score = 0

    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname or ""
    full_url = url.lower()

    if parsed.scheme != "https":
        flags.append("URL does not use HTTPS")
        score += 1

    if IP_PATTERN.match(hostname):
        flags.append("Uses a raw IP address instead of a domain name")
        score += 3

    if "@" in url:
        flags.append("Contains '@' symbol, which can hide the real destination")
        score += 3

    if any(shortener in hostname for shortener in SHORTENER_DOMAINS):
        flags.append("Uses a URL shortener, which can mask the real destination")
        score += 2

    if any(full_url.endswith(tld) or f"{tld}/" in full_url for tld in SUSPICIOUS_TLDS):
        flags.append("Uses a TLD commonly associated with spam/phishing")
        score += 2

    if hostname.count(".") >= 3:
        flags.append("Unusually many subdomains — often used to imitate a trusted domain")
        score += 2

    if any(keyword in hostname for keyword in PHISHING_KEYWORDS):
        flags.append("Domain contains a keyword commonly used in phishing (e.g. 'login', 'verify')")
        score += 2

    if len(url) > 100:
        flags.append("Unusually long URL")
        score += 1

    if score >= 5:
        verdict = "High risk"
    elif score >= 2:
        verdict = "Suspicious"
    else:
        verdict = "Low risk"

    return verdict, flags, score


# ---------- VirusTotal (optional layer) ----------

def check_virustotal(url, api_key):
    """Free tier: 4 requests/minute. Caller is responsible for rate limiting."""
    headers = {"x-apikey": api_key}
    try:
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10,
        )
        if submit_resp.status_code != 200:
            return None, f"Submission failed: HTTP {submit_resp.status_code}"

        url_id = submit_resp.json()["data"]["id"]

        report_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{url_id}",
            headers=headers,
            timeout=10,
        )
        if report_resp.status_code != 200:
            return None, f"Report fetch failed: HTTP {report_resp.status_code}"

        stats = report_resp.json()["data"]["attributes"]["stats"]
        return stats, None
    except requests.RequestException as e:
        return None, f"Network error: {e}"


# ---------- Batch mode ----------

def process_batch(input_path, output_path="url_scan_results.csv", api_key=None):
    input_file = Path(input_path)

    if not input_file.exists():
        print(f"File not found: {input_path}")
        return

    with open(input_file, "r") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not urls:
        print("No URLs found in the file.")
        return

    print(f"\nScanning {len(urls)} URL(s)...\n")
    results = []
    # Free VirusTotal tier: 4 requests/minute -> 15s between calls, minimum
    vt_delay_seconds = 15

    for i, url in enumerate(urls, start=1):
        verdict, flags, score = analyze_url_heuristics(url)
        row = {
            "url": url,
            "heuristic_verdict": verdict,
            "heuristic_score": score,
            "flags": "; ".join(flags) if flags else "None",
            "vt_malicious": "",
            "vt_suspicious": "",
            "vt_harmless": "",
            "vt_error": "",
        }

        marker = {"High risk": "🚨", "Suspicious": "⚠️ ", "Low risk": "✅"}[verdict]
        print(f"[{i}/{len(urls)}] {marker} {verdict:10} (score {score})  {url}")

        if api_key:
            stats, error = check_virustotal(url, api_key)
            if error:
                row["vt_error"] = error
                print(f"    VirusTotal: {error}")
            else:
                row["vt_malicious"] = stats.get("malicious", 0)
                row["vt_suspicious"] = stats.get("suspicious", 0)
                row["vt_harmless"] = stats.get("harmless", 0)
                print(f"    VirusTotal: {stats.get('malicious', 0)} malicious, "
                      f"{stats.get('suspicious', 0)} suspicious, "
                      f"{stats.get('harmless', 0)} harmless")

            if i < len(urls):
                time.sleep(vt_delay_seconds)

        results.append(row)

    fieldnames = ["url", "heuristic_verdict", "heuristic_score", "flags",
                  "vt_malicious", "vt_suspicious", "vt_harmless", "vt_error"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    high_risk = sum(1 for r in results if r["heuristic_verdict"] == "High risk")
    suspicious = sum(1 for r in results if r["heuristic_verdict"] == "Suspicious")

    print(f"\nSummary: {high_risk} high risk, {suspicious} suspicious, "
          f"{len(results) - high_risk - suspicious} low risk")
    print(f"Full results saved to {output_path}")


# ---------- CLI ----------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Security Checker — password strength/breach checks and malicious URL detection."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    pw_parser = subparsers.add_parser("password", help="Check password strength and breach status")
    pw_parser.add_argument("--value", help="Password to check (omit to be prompted, safer for shared terminals)")

    url_parser = subparsers.add_parser("url", help="Check a single URL")
    url_parser.add_argument("value", help="URL to check")
    url_parser.add_argument("--vt-key", help="VirusTotal API key for an additional cross-check")

    batch_parser = subparsers.add_parser("batch", help="Check a file of URLs, one per line")
    batch_parser.add_argument("file", help="Path to text file of URLs")
    batch_parser.add_argument("--output", default="url_scan_results.csv", help="Output CSV path")
    batch_parser.add_argument("--vt-key", help="VirusTotal API key to enable cross-checking (rate-limited)")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "password":
        password = args.value or input("Enter a password to check: ")
        rating, tips = check_password_strength(password)
        print(f"\nPassword strength: {rating}")
        if tips:
            print("Suggestions:")
            for tip in tips:
                print(f"- {tip}")

        print("\nChecking against known data breaches...")
        count, error = check_pwned(password)
        if error:
            print(error)
        elif count and count > 0:
            print(f"⚠️  This password has appeared in {count:,} known data breaches.")
        else:
            print("✅ This password was not found in any known breach.")

    elif args.command == "url":
        verdict, flags, score = analyze_url_heuristics(args.value)
        print(f"Verdict: {verdict} (score {score})")
        if flags:
            print("Reasons:")
            for flag in flags:
                print(f"- {flag}")

        if args.vt_key:
            stats, error = check_virustotal(args.value, args.vt_key)
            if error:
                print(f"VirusTotal: {error}")
            else:
                print(f"VirusTotal: {stats.get('malicious', 0)} malicious, "
                      f"{stats.get('suspicious', 0)} suspicious, "
                      f"{stats.get('harmless', 0)} harmless")

    elif args.command == "batch":
        process_batch(args.file, args.output, api_key=args.vt_key)


if __name__ == "__main__":
    main()