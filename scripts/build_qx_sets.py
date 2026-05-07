from pathlib import Path
import csv
import io
import re
import shutil
import requests

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "sources" / "rules-source.conf"
DIST = ROOT / "dist"

UA = {"User-Agent": "Mozilla/5.0"}

POLICY_ALIASES = {
    "REJECT": "reject",
    "REJECT-DROP": "reject",
    "REJECT-NO-DROP": "reject",
    "DIRECT": "DIRECT",
    "PROXY": "PROXY",
}

COMMENT_POLICY_NAMES = {
    "DIRECT", "PROXY", "REJECT", "REJECT-DROP", "REJECT-NO-DROP",
    "国内", "国外", "苹果进阶", "微软", "测速", "规则订阅与OB与GitHub",
    "reject", "direct", "proxy"
}

BAD_VALUE_CHARS = set(" #*/:@\\\t\r\n")


def prepare_dist():
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True, exist_ok=True)


def parse_csv_line(line: str):
    try:
        return next(csv.reader(io.StringIO(line), skipinitialspace=True))
    except Exception:
        return []


def sanitize_filename(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    name = re.sub(r"\s+", "", name)
    return name[:120] if len(name) > 120 else name


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
    if pu in POLICY_ALIASES:
        return POLICY_ALIASES[pu]
    return p


def strip_trailing_comment(s: str) -> str:
    s = s.strip()
    if not s:
        return ""

    s = re.split(r"\s+#", s, maxsplit=1)[0].strip()
    s = re.split(r"\s+//", s, maxsplit=1)[0].strip()
    s = re.sub(
        r",\s*(?:DIRECT|PROXY|REJECT|REJECT-DROP|REJECT-NO-DROP|国内|国外|苹果进阶|微软|测速|规则订阅与OB与GitHub)\s*$",
        "",
        s
    )
    return s.strip()


def trim_last_policy_token(rest: str) -> str:
    parts = [p.strip() for p in rest.split(",")]
    if len(parts) <= 1:
        return rest.strip()
    if parts[-1] in COMMENT_POLICY_NAMES:
        return ",".join(parts[:-1]).strip()
    return rest.strip()


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


def is_ipv6_value(value: str) -> bool:
    return ":" in value


def is_valid_domain_value(value: str) -> bool:
    v = value.strip().lower().lstrip(".")
    if not v:
        return False
    if any(ch in v for ch in BAD_VALUE_CHARS):
        return False
    if "." not in v:
        return False
    if v.startswith(".") or v.endswith("."):
        return False
    return True


def normalize_ip_rule(head: str, rest: str, policy: str):
    value = rest.split(",", 1)[0].strip()
    if not value:
        return None
    if head in {"ip-cidr6", "ip6-cidr"}:
        return f"ip6-cidr,{value},{policy}"
    if head == "ip-cidr":
        if is_ipv6_value(value):
            return f"ip6-cidr,{value},{policy}"
        return f"ip-cidr,{value},{policy}"
    return None


def normalize_qx_rule(line: str, policy="PROXY", ref_kind="RULE-SET"):
    raw = line.replace("\ufeff", "").strip()
    if not raw:
        return None

    payload_item = parse_payload_yaml_line(raw)
    if payload_item is not None:
        raw = payload_item.strip()

    s = strip_trailing_comment(raw)
    if not s:
        return None

    if ref_kind == "DOMAIN-SET" and "," not in s:
        value = s.lstrip(".").strip()
        return f"host-suffix,{value},{policy}" if is_valid_domain_value(value) else None

    if "," not in s:
        up = s.upper()
        if ref_kind == "RULE-SET":
            if re.fullmatch(r"AS\d+", up):
                return f"ip-asn,{up.removeprefix('AS')},{policy}"
            if re.fullmatch(r"\d+", up):
                return f"ip-asn,{up},{policy}"
        return None

    head, rest = s.split(",", 1)
    head = head.strip().lower()
    rest = trim_last_policy_token(rest)

    if head in {"domain-suffix", "host-suffix"}:
        value = rest.split(",", 1)[0].strip().lstrip(".")
        return f"host-suffix,{value},{policy}" if is_valid_domain_value(value) else None

    if head in {"domain", "host"}:
        value = rest.split(",", 1)[0].strip()
        return f"host,{value},{policy}" if is_valid_domain_value(value) else None

    if head in {"domain-keyword", "host-keyword"}:
        value = rest.split(",", 1)[0].strip()
        return f"host-keyword,{value},{policy}" if value and " " not in value else None

    if head == "host-wildcard":
        value = rest.split(",", 1)[0].strip()
        return f"host-wildcard,{value},{policy}" if is_valid_domain_value(value.replace("*", "")) else None

    if head in {"ip-cidr6", "ip6-cidr", "ip-cidr"}:
        return normalize_ip_rule(head, rest, policy)

    if head == "geoip":
        value = rest.split(",", 1)[0].strip()
        return f"geoip,{value},{policy}" if value else None

    if head == "ip-asn":
        value = rest.split(",", 1)[0].strip().upper().removeprefix("AS")
        return f"ip-asn,{value},{policy}" if value else None

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

    prepare_dist()
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

        for row in text.splitlines():
            qx = normalize_qx_rule(row, policy=policy, ref_kind=kind)
            if qx:
                groups[current_title].append(qx)

    for title, rules in groups.items():
        fail_notes = [r for r in rules if r.startswith("# fetch failed:")]
        clean_rules = [r for r in rules if not r.startswith("# fetch failed:")]
        clean_rules = merge_unique(clean_rules)

        if not clean_rules and not fail_notes:
            continue

        out_path = DIST / f"{sanitize_filename(title)}.txt"
        out_path.write_text("\n".join(fail_notes + clean_rules).rstrip() + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
