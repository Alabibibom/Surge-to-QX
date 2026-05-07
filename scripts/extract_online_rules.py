from pathlib import Path
import csv
import io
import re
import requests

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "sources" / "rules-source.conf"
DIST = ROOT / "dist"
OUT = DIST / "online-qx.conf"

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

def fetch_text(url: str) -> str:
    r = requests.get(url, headers=UA, timeout=60)
    r.raise_for_status()
    return r.text

def convert_rule_line(line: str):
    s = line.strip()
    if not s or is_comment(s):
        return None

    s = s.replace("\ufeff", "")

    if s.startswith(("DOMAIN,", "host,")):
        return "HOST," + s.split(",", 1)[1]

    if s.startswith(("DOMAIN-SUFFIX,", "domain-suffix,")):
        return "HOST-SUFFIX," + s.split(",", 1)[1]

    if s.startswith(("DOMAIN-KEYWORD,", "host-keyword,")):
        return "HOST-KEYWORD," + s.split(",", 1)[1]

    if s.startswith(("DOMAIN-SET,", "host-set,")):
        return "HOST-SUFFIX," + s.split(",", 1)[1]

    if s.startswith(("IP-CIDR6,",)):
        return s.replace("IP-CIDR6,", "IP6-CIDR,", 1)

    if s.startswith(("IP-CIDR,",)):
        return s

    if s.startswith(("GEOIP,",)):
        return s

    if s.startswith(("USER-AGENT,", "USER-AGENT-KEYWORD,", "URL-REGEX,", "PROCESS-NAME,")):
        return s

    if s.startswith(("HOST,", "HOST-SUFFIX,", "HOST-KEYWORD,", "IP-CIDR,", "IP6-CIDR,", "IP-CIDR6,", "GEOIP,", "USER-AGENT,", "URL-REGEX,", "PROCESS-NAME,")):
        return s

    if s.startswith("#"):
        return s

    return None

def convert_content(text: str):
    out = []
    seen = set()
    for raw in text.splitlines():
        line = raw.rstrip()
        if is_blank(line):
            if out and out[-1] != "":
                out.append("")
            continue
        if is_comment(line):
            out.append(line)
            continue

        conv = convert_rule_line(line)
        if conv and conv not in seen:
            seen.add(conv)
            out.append(conv)
    while out and out[-1] == "":
        out.pop()
    return out

def main():
    src_lines = SRC.read_text(encoding="utf-8").splitlines()
    output = []
    pending_comments = []

    for raw in src_lines:
        line = raw.rstrip()

        if is_blank(line):
            if pending_comments and pending_comments[-1] != "":
                pending_comments.append("")
            continue

        if is_comment(line):
            pending_comments.append(line)
            continue

        if is_online_ref(line):
            url = extract_url(line)
            if pending_comments:
                if output and output[-1] != "":
                    output.append("")
                output.extend(pending_comments)
            pending_comments = []
            try:
                remote = fetch_text(url)
                converted = convert_content(remote)
                if converted:
                    output.extend(converted)
            except Exception as e:
                output.append(f"# fetch failed: {url} ({e})")
        else:
            pending_comments = []

    while output and output[-1] == "":
        output.pop()

    OUT.write_text("\n".join(output) + "\n", encoding="utf-8")
    print(f"generated: {OUT}")

if __name__ == "__main__":
    main()
