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
COMMENT_PREFIXES = ("#", ";", "//")


def parse_csv_line(line: str):
    try:
        return next(csv.reader(io.StringIO(line), skipinitialspace=True))
    except Exception:
        return []


def sanitize_filename(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    name = re.sub(r"\s+", "", name)
    return name[:120] if len(name) > 120 else name


def is_comment(line: str) -> bool:
    s = line.strip()
    return s.startswith(COMMENT_PREFIXES)


def extract_title(line: str):
    s = line.strip()
    if s.startswith("#"):
        t = s[1:].strip()
        return t or None
    return None


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


def strip_inline_comment(line: str) -> str:
    s = line.strip()
    if not s:
        return ""
    if s.startswith(COMMENT_PREFIXES):
        return ""
    return s


def parse_payload_yaml_line(line: str):
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if s.lower() == "payload:":
        return None
    if s.startswith("- "):
        item = s[2:].strip()
        if (item.startswith('"') and item.endswith('"')) or (item.startswith("'") and item.endswith("'")):
            item = item[1:-1]
        return item.strip()
    return None


def normalize_qx_rule(line: str, policy="proxy", ref_kind="RULE-SET"):
    raw = line.replace("\ufeff", "").strip()
    if not raw:
        return None

    payload_item = parse_payload_yaml_line(raw)
    if payload_item is not None:
        raw = payload_item.strip()

    s = strip_inline_comment(raw)
    if not s:
        return None

    parts = [p.strip() for p in s.split(",")]
    if not parts:
        return None

    head = parts[0].lower()

    qx_heads = {
        "user-agent",
        "host",
        "host-keyword",
        "host-wildcard",
        "host-suffix",
        "ip6-cidr",
        "ip-cidr",
        "geoip",
        "ip-asn",
        "url-regex",
        "process-name",
        "final",
        "match",
    }

    surge_to_qx = {
        "domain": "host",
        "domain-keyword": "host-keyword",
        "domain-suffix": "host-suffix",
        "host": "host",
        "host-keyword": "host-keyword",
        "host-wildcard": "host-wildcard",
        "host-suffix": "host-suffix",
        "ip-cidr6": "ip6-cidr",
        "ip6-cidr": "ip6-cidr",
        "ip-cidr": "ip-cidr",
        "geoip": "geoip",
        "ip-asn": "ip-asn",
        "user-agent": "user-agent",
        "url-regex": "url-regex",
        "process-name": "process-name",
        "final": "final",
        "match": "match",
    }

    if head in surge_to_qx:
        qx_head = surge_to_qx[head]

        if qx_head in {"final", "match"}:
            if len(parts) >= 2:
                return ",".join([qx_head, parts[1]] + parts[2:])
            return qx_head

        if len(parts) < 2:
            return None

        value = parts[1].strip()

        if qx_head == "host-suffix":
            value = value.lstrip(".")
        elif qx_head == "ip-asn":
            value = value.upper().removeprefix("AS")

        if not value:
            return None

        extras = parts[3:] if len(parts) >= 4 else []
        return ",".join([qx_head, value, policy] + extras)

    if ref_kind == "DOMAIN-SET":
        if "," not in s:
            value = s.lstrip(".").strip()
            if value:
                return f"host-suffix,{value},{policy}"

        if head in {"domain-suffix", "host-suffix"} and len(parts) >= 2:
            value = parts[1].lstrip(".")
            extras = parts[3:] if len(parts) >= 4 else []
            return ",".join(["host-suffix", value, policy] + extras) if value else None

        if head in {"domain", "host"} and len(parts) >= 2:
            value = parts[1]
            extras = parts[3:] if len(parts) >= 4 else []
            return ",".join(["host", value, policy] + extras) if value else None

        if head in {"domain-keyword", "host-keyword"} and len(parts) >= 2:
            value = parts[1]
            extras = parts[3:] if len(parts) >= 4 else []
            return ",".join(["host-keyword", value, policy] + extras) if value else None

        if head == "host-wildcard" and len(parts) >= 2:
            value = parts[1]
            extras = parts[3:] if len(parts) >= 4 else []
            return ",".join(["host-wildcard", value, policy] + extras) if value else None

    if ref_kind == "RULE-SET":
        if re.fullmatch(r"AS\d+", s.upper()):
            return f"ip-asn,{s.upper().removeprefix('AS')},{policy}"
        if re.fullmatch(r"\d+", s):
            return f"ip-asn,{s},{policy}"

    return None


def read_source_text(target: str) -> str:
    if target.startswith(("http://", "https://")):
        r = requests.get(target, headers=UA, timeout=90)
        r.raise_for_status()
        return r.text

    local_path = SRC.parent / target
    if local_path.exists():
        return local_path.read_text(encoding="utf-8")
    return ""


def merge_unique(lines):
    seen = set()
    out = []
    for line in lines:
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def main():
    if not SRC.exists():
        raise FileNotFoundError(f"source file not found: {SRC}")

    lines = SRC.read_text(encoding="utf-8").splitlines()
    groups = {}
    current_title = None

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        title = extract_title(line)
        if title:
            current_title = title
            groups.setdefault(current_title, [])
            continue

        kind, target, raw_policy = extract_ref(line)
        if not kind or not current_title:
            continue

        policy = normalize_policy(raw_policy)

        try:
            text = read_source_text(target)
        except Exception as e:
            groups[current_title].append(f"# fetch failed: {target} ({e})")
            continue

        converted = []
        for row in text.splitlines():
            qx = normalize_qx_rule(row, policy=policy, ref_kind=kind)
            if qx:
                converted.append(qx)

        groups[current_title].extend(converted)

    for title, rules in groups.items():
        fail_notes = [r for r in rules if r.startswith("# fetch failed:")]
        clean_rules = [r for r in rules if not r.startswith("# fetch failed:")]
        clean_rules = merge_unique(clean_rules)

        if not clean_rules and not fail_notes:
            continue

        out_path = DIST / f"{sanitize_filename(title)}.txt"
        content_lines = []
        content_lines.extend(fail_notes)
        content_lines.extend(clean_rules)
        out_path.write_text("\n".join(content_lines).rstrip() + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
