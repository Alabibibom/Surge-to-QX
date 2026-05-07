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

def sanitize_filename(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    name = re.sub(r"\s+", "", name)
    return name[:80] if len(name) > 80 else name

def extract_ref(line: str):
    fields = parse_csv_line(line)
    if len(fields) < 2:
        return None, None, None
    kind = fields[0].strip().upper()
    target = fields[1].strip()
    policy = fields[2].strip() if len(fields) >= 3 else "PROXY"
    if kind in {"RULE-SET", "DOMAIN-SET"}:
        return kind, target, policy
    return None, None, None

def normalize_policy(policy: str) -> str:
    p = (policy or "").strip()
    pu = p.upper()
    if pu in {"REJECT", "REJECT-DROP", "REJECT-NO-DROP"}:
        return "reject"
    if pu == "DIRECT":
        return "direct"
    if pu == "PROXY":
        return "proxy"
    return p

def normalize_qx_rule(line: str, policy="proxy", ref_kind="RULE-SET"):
    s = line.strip().replace("\ufeff", "")
    if not s or s.startswith(("#", ";", "//")):
        return None

    if ref_kind == "DOMAIN-SET":
        if "," not in s and not s.startswith(("[", "]", "payload:")):
            s = s.lstrip(".")
            return f"host-suffix,{s},{policy}"

    if s.startswith("DOMAIN-SUFFIX,"):
        return "host-suffix," + s.split(",", 1)[1] + f",{policy}"
    if s.startswith("DOMAIN,"):
        return "host," + s.split(",", 1)[1] + f",{policy}"
    if s.startswith("DOMAIN-KEYWORD,"):
        return "host-keyword," + s.split(",", 1)[1] + f",{policy}"
    if s.startswith("IP-CIDR6,"):
        return "ip6-cidr," + s.split(",", 1)[1] + f",{policy}"
    if s.startswith("IP-CIDR,"):
        return "ip-cidr," + s.split(",", 1)[1] + f",{policy}"
    if s.startswith("GEOIP,"):
        parts = s.split(",")
        if len(parts) >= 2:
            return f"geoip,{parts[1].strip()},{policy}"

    lower = s.lower()
    if lower.startswith(("host-suffix,", "host,", "host-keyword,", "ip-cidr,", "ip6-cidr,", "geoip,", "user-agent,", "url-regex,", "process-name,")):
        parts = s.split(",")
        if len(parts) >= 2:
            base = ",".join(parts[:-1])
            return f"{base},{policy}"

    return None

def read_source_text(target: str) -> str:
    if target.startswith(("http://", "https://")):
        r = requests.get(target, headers=UA, timeout=60)
        r.raise_for_status()
        return r.text

    local_path = SRC.parent / target
    if local_path.exists():
        return local_path.read_text(encoding="utf-8")
    return ""

def main():
    lines = SRC.read_text(encoding="utf-8").splitlines()
    groups = {}
    current_title = None

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        if line.startswith("#"):
            title = line.lstrip("#").strip()
            if title:
                current_title = title
                groups.setdefault(current_title, [])
            continue

        kind, target, raw_policy = extract_ref(line)
        if not kind:
            continue
        if not current_title:
            continue

        policy = normalize_policy(raw_policy)
        text = read_source_text(target)
        for row in text.splitlines():
            qx = normalize_qx_rule(row, policy=policy, ref_kind=kind)
            if qx:
                groups[current_title].append(qx)

    for title, rules in groups.items():
        seen = set()
        merged = []
        for r in rules:
            if r not in seen:
                seen.add(r)
                merged.append(r)
        if merged:
            out = DIST / f"{sanitize_filename(title)}.txt"
            out.write_text("\n".join(merged) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
