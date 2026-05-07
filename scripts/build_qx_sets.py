from pathlib import Path
import csv
import io
import re
import requests

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "sources" / "rules-source.conf"
DIST = ROOT / "dist"
DIST.mkdir(exist_ok=True)

UA = {"User-Agent": "Mozilla/5.0"}

def parse_csv_line(line: str):
    try:
        return next(csv.reader(io.StringIO(line), skipinitialspace=True))
    except Exception:
        return []

def is_comment(line: str) -> bool:
    s = line.strip()
    return s.startswith("#") or s.startswith(";") or s.startswith("//")

def is_blank(line: str) -> bool:
    return line.strip() == ""

def is_online_ref(line: str) -> bool:
    fields = parse_csv_line(line)
    if len(fields) < 2:
        return False
    kind = fields[0].strip().upper()
    target = fields[1].strip()
    return kind in {"RULE-SET", "DOMAIN-SET"} and target.startswith(("http://", "https://"))

def extract_url(line: str) -> str | None:
    fields = parse_csv_line(line)
    if len(fields) < 2:
        return None
    target = fields[1].strip()
    return target if target.startswith(("http://", "https://")) else None

def extract_title_from_comments(comments):
    for c in comments:
        t = c.strip()
        if t.startswith("#"):
            t = t.lstrip("#").strip()
            if t:
                return t
    return "ruleset"

def sanitize_filename(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    name = re.sub(r"\s+", "", name)
    return name[:80] if len(name) > 80 else name

def normalize_policy(p: str) -> str:
    p = (p or "").strip().upper()
    if p in {"REJECT", "REJECT-DROP", "REJECT-NO-DROP"}:
        return "reject"
    if p == "DIRECT":
        return "direct"
    if p == "PROXY":
        return "proxy"
    return "proxy"

def extract_policy(line: str) -> str:
    fields = parse_csv_line(line)
    if len(fields) < 3:
        return "proxy"
    return normalize_policy(fields[2])

def fetch_text(url: str) -> str:
    r = requests.get(url, headers=UA, timeout=60)
    r.raise_for_status()
    return r.text

def normalize_qx_rule(line: str, default_policy="proxy"):
    s = line.strip().replace("\ufeff", "")
    if not s or is_comment(s):
        return None

    if s.startswith("DOMAIN-SUFFIX,"):
        return "host-suffix," + s.split(",", 1)[1] + f",{default_policy}"
    if s.startswith("DOMAIN,"):
        return "host," + s.split(",", 1)[1] + f",{default_policy}"
    if s.startswith("DOMAIN-KEYWORD,"):
        return "host-keyword," + s.split(",", 1)[1] + f",{default_policy}"

    if s.startswith("IP-CIDR6,"):
        return "ip6-cidr," + s.split(",", 1)[1] + f",{default_policy}"
    if s.startswith("IP-CIDR,"):
        return "ip-cidr," + s.split(",", 1)[1] + f",{default_policy}"
    if s.startswith("GEOIP,"):
        parts = s.split(",")
        if len(parts) >= 2:
            return f"geoip,{parts[1].strip()},{default_policy}"

    if s.startswith(("USER-AGENT,", "URL-REGEX,", "PROCESS-NAME,")):
        return s.lower() + f",{default_policy}"

    if s.startswith(("host-suffix,", "host,", "host-keyword,", "ip-cidr,", "ip6-cidr,", "geoip,", "user-agent,", "url-regex,", "process-name,")):
        parts = s.split(",")
        if len(parts) >= 2:
            base = ",".join(parts[:-1]).lower()
            return f"{base},{default_policy}"

    if s.startswith(("FINAL,", "MATCH,")):
        return s.lower()

    return None

def convert_remote_rules(text: str, policy="proxy"):
    out = []
    seen = set()
    for raw in text.splitlines():
        conv = normalize_qx_rule(raw, policy)
        if conv and conv not in seen:
            seen.add(conv)
            out.append(conv)
    return out

def flush_set(title, rules):
    if not title:
        return
    path = DIST / f"{sanitize_filename(title)}.txt"
    path.write_text("\n".join(rules).rstrip() + "\n", encoding="utf-8")

def main():
    lines = SRC.read_text(encoding="utf-8").splitlines()

    pending_comments = []
    current_title = None
    current_rules = []

    for raw in lines:
        line = raw.rstrip()

        if is_blank(line):
            if pending_comments and pending_comments[-1] != "":
                pending_comments.append("")
            continue

        if is_comment(line):
            pending_comments.append(line)
            continue

        if is_online_ref(line):
            if current_title and current_rules:
                flush_set(current_title, current_rules)

            url = extract_url(line)
            policy = extract_policy(line)
            title = extract_title_from_comments(pending_comments)
            current_title = title
            current_rules = list(pending_comments)
            pending_comments = []

            try:
                remote = fetch_text(url)
                current_rules.extend(convert_remote_rules(remote, policy=policy))
            except Exception as e:
                current_rules.append(f"# fetch failed: {url} ({e})")
            continue

        pending_comments = []

    if current_title and current_rules:
        flush_set(current_title, current_rules)

if __name__ == "__main__":
    main()
