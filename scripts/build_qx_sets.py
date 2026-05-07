def is_ipv6_cidr(value: str) -> bool:
    v = value.strip()
    return ":" in v


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
        if value:
            return f"host-suffix,{value},{policy}"
        return None

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
        if ":" in value:
            return f"ip6-cidr,{value},{policy}"
        return f"ip-cidr,{value},{policy}" if value else None

    if head == "geoip":
        value = rest.split(",", 1)[0].strip()
        return f"geoip,{value},{policy}" if value else None

    if head == "ip-asn":
        value = rest.split(",", 1)[0].strip().upper().removeprefix("AS")
        return f"ip-asn,{value},{policy}" if value else None

    if head in {"process-name", "url-regex", "user-agent", "final", "match"}:
        return None

    return None
