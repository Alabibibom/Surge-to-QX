from pathlib import Path
import csv
import io
import requests
import re

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "sources" / "rules-source.conf"
DIST = ROOT / "dist"
OUT = DIST / "online-qx.conf"

DIST.mkdir(exist_ok=True)
UA = {"User-Agent": "Mozilla/5.0"}

QX_RULE_PREFIXES = (
    "HOST,",
    "HOST-SUFFIX,",
    "HOST-KEYWORD,",
    "IP-CIDR,",
    "IP6-CIDR,",
    "GEOIP,",
    "USER-AGENT,",
    "URL-REGEX,",
    "PROCESS-NAME,",
    "FINAL,",
    "MATCH,",
)

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
    if len(fi
