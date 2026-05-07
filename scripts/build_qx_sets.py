def strip_trailing_comment(s: str) -> str:
    s = s.strip()
    if not s:
        return ""

    in_regex = False
    escaped = False
    i = 0
    while i < len(s):
        ch = s[i]

        if ch == "\\" and not escaped:
            escaped = True
            i += 1
            continue

        if ch == "," and not escaped:
            pass

        if ch == "/" and not escaped:
            if i + 1 < len(s) and s[i + 1] == "/":
                prev = s[i - 1] if i > 0 else ""
                if prev not in {":", "\\"}:
                    return s[:i].rstrip()

        if ch == "#" and not escaped:
            prev = s[i - 1] if i > 0 else ""
            if prev.isspace() or i == 0:
                return s[:i].rstrip()

        escaped = False
        i += 1

    return s.strip()


def split_rule_head_value(s: str):
    if "," not in s:
        return s.strip().lower(), ""
    head, rest = s.split(",", 1)
    return head.strip().lower(), rest.strip()


def trim_last_policy_token(value: str) -> str:
    parts = [p.strip() for p in value.split(",")]
    if len(parts) <= 1:
        return value.strip()

    last = parts[-1].strip()
    if last in {
        "direct", "proxy", "reject", "reject-drop", "reject-no-drop",
        "国内", "国外", "苹果进阶", "微软", "测速", "规则订阅与OB与GitHub"
    }:
        return ",".join(parts[:-1]).strip()

    return value.strip()


def normalize_qx_rule(line: str, policy="proxy", ref_kind="RULE-SET"):
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
        if value:
            return f"host-suffix,{value},{policy}"
        return None

    head, rest = split_rule_head_value(s)
    rest = trim_last_policy_token(rest)

    if head in {"domain-suffix", "host-suffix"}:
        value = rest.split(",", 1)[0].strip().lstrip(".")
        return f"host-suffix,{value},{policy}" if value else None

    if head in {"domain", "host"}:
        value = rest.split(",", 1)[0].strip()
        return f"host,{value},{policy}" if value else None

    if head in {"domain-keyword", "host-keyword"}:
        value = rest.split(",", 1)[0].strip()
        return f"host-keyword,{value},{policy}" if value else None

    if head == "host-wildcard":
        value = rest.split(",", 1)[0].strip()
        return f"host-wildcard,{value},{policy}" if value else None

    if head in {"ip-cidr6", "ip6-cidr"}:
        value = rest.split(",", 1)[0].strip()
        return f"ip6-cidr,{value},{policy}" if value else None

    if head == "ip-cidr":
        value = rest.split(",", 1)[0].strip()
        return f"ip-cidr,{value},{policy}" if value else None

    if head == "geoip":
        value = rest.split(",", 1)[0].strip()
        return f"geoip,{value},{policy}" if value else None

    if head == "ip-asn":
        value = rest.split(",", 1)[0].strip().upper().removeprefix("AS")
        return f"ip-asn,{value},{policy}" if value else None

    if head == "process-name":
        value = rest.split(",", 1)[0].strip()
        return f"process-name,{value},{policy}" if value else None

    if head == "user-agent":
        value = rest.split(",", 1)[0].strip()
        return f"user-agent,{value},{policy}" if value else None

    if head == "url-regex":
        value = rest.strip()
        if value:
            return f"url-regex,{value},{policy}"
        return None

    if head in {"final", "match"}:
        value = rest.split(",", 1)[0].strip() if rest else policy
        return f"{head},{value}" if value else head

    if ref_kind == "RULE-SET":
        if re.fullmatch(r"AS\d+", s.upper()):
            return f"ip-asn,{s.upper().removeprefix('AS')},{policy}"
        if re.fullmatch(r"\d+", s):
            return f"ip-asn,{s},{policy}"

    return None
