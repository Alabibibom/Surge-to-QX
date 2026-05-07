from pathlib import Path
import csv
import io
import re
import shutil
import ipaddress
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

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]$", re.I)
HOST_WILDCARD_RE = re.compile(r"^\*\.([a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]$", re.I)
ASN_RE = re.compile(r"^(?:AS)?(\d+)$", re.I)
GEOIP_RE = re.compile(r"^[A-Za-z]{2}$")


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
    return s.strip()


def trim_last_policy_token(rest: str) -> str:
    parts = [p.strip() for p in rest.split(",")]
    while len(parts) > 1 and parts[-1] in COMMENT_POLICY_NAMES:
        parts.pop()
    return ",".join(parts).strip()


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


def clean_value(v: str) -> str:
    return v.strip().strip('"').strip("'")


def normalize_domain_like(value: str):
    v = clean_value(value).lstrip(".").rstrip(".").lower()
    if not v:
        return None
    return v


def is_valid_domain(value: str) -> bool:
    v = normalize_domain_like(value)
    if not v:
        return False
    if any(x in v for x in (" ", "/", "\\", "@", "#", ",")):
        return False
    return bool(DOMAIN_RE.fullmatch(v))


def is_valid_host_keyword(value: str) -> bool:
    v = clean_value(value)
    if not v:
        return False
    if any(x in v for x in ("\n", "\r", "#", ",")):
        return False
    return True


def is_valid_host_wildcard(value: str) -> bool:
    v = clean_value(value).lower()
    if not v or any(x in v for x in (" ", "/", "\\", "@", "#", ",")):
        return False
    return bool(HOST_WILDCARD_RE.fullmatch(v))


def normalize_asn(value: str):
    v = clean_value(value).upper()
    m = ASN_RE.fullmatch(v)
    if not m:
        return None
    return m.group(1)


def normalize_geoip(value: str):
    v = clean_value(value).upper()
    if GEOIP_RE.fullmatch(v):
        return v
    return None


def normalize_cidr(value: str):
    v = clean_value(value)
    try:
        net = ipaddress.ip_network(v, strict=False)
        if net.version == 4:
            return "ip-cidr", str(net)
        return "ip6-cidr", str(net)
    except Exception:
        return None


def normalize_ip_rule(head: str, rest: str, policy: str):
    value = clean_value(rest.split(",", 1)[0])
    if not value:
        return None

    if head in {"ip-cidr6", "ip6-cidr"}:
        try:
            net = ipaddress.IPv6Network(value, strict=False)
            return f"ip6-cidr,{net},{policy}"
        except Exception:
            return None

    if head == "ip-cidr":
        result = normalize_cidr(value)
        if not result:
            return None
        qx_type, cidr = result
        return f"{qx_type},{cidr},{policy}"

    return None


def normalize_qx_rule(line: str, policy="PROXY", ref_kind="RULE-SET"):
    raw = line.replace("\ufeff", "").strip()
    if not raw:
        return None

    payload_item = parse_payload_yaml_line(raw)
    if payload_item is not None:
        raw = payload_item

    s = strip_trailing_comment(raw)
    if not s:
        return None

    if ref_kind == "DOMAIN-SET" and "," not in s:
        value = normalize_domain_like(s)
        if value and is_valid_domain(value):
            return f"host-suffix,{value},{policy}"
        return None

    if "," not in s:
        up = s.upper()
        asn = normalize_asn(up)
        if ref_kind == "RULE-SET" and asn:
            return f"ip-asn,{asn},{policy}"
        return None

    head, rest = s.split(",", 1)
    head = head.strip().lower()
    rest = trim_last_policy_token(rest)

    if head in {"domain-suffix", "host-suffix"}:
        value = normalize_domain_like(rest.split(",", 1)[0])
        if value and is_valid_domain(value):
            return f"host-suffix,{value},{policy}"
        return None

    if head in {"domain", "host"}:
        value = normalize_domain_like(rest.split(",", 1)[0])
        if value and is_valid_domain(value):
            return f"host,{value},{policy}"
        return None

    if head in {"domain-keyword", "host-keyword"}:
        value = clean_value(rest.split(",", 1)[0])
        if is_valid_host_keyword(value):
            return f"host-keyword,{value},{policy}"
        return None

    if head == "host-wildcard":
        value = clean_value(rest.split(",", 1)[0]).lower()
        if is_valid_host_wildcard(value):
            return f"host-wildcard,{value},{policy}"
        return None

    if head in {"ip-cidr6", "ip6-cidr", "ip-cidr"}:
        return normalize_ip_rule(head, rest, policy)

    if head == "geoip":
        value = normalize_geoip(rest.split(",", 1)[0])
        if value:
            return f"geoip,{value},{policy}"
        return None

    if head == "ip-asn":
        value = normalize_asn(rest.split(",", 1)[0])
        if value:
            return f"ip-asn,{value},{policy}"
        return None

    if head in {"process-name", "url-regex", "user-agent", "final", "match"}:
        return None

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
