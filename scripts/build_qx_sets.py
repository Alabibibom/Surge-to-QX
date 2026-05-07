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
        "ip-cidr6": "ip6-cidr",
        "ip-cidr": "ip-cidr",
        "geoip": "geoip",
        "ip-asn": "ip-asn",
        "user-agent": "user-agent",
        "url-regex": "url-regex",
        "process-name": "process-name",
        "host": "host",
        "host-keyword": "host-keyword",
        "host-wildcard": "host-wildcard",
        "host-suffix": "host-suffix",
        "final": "final",
        "match": "match",
    }

    if head in surge_to_qx:
        qx_head = surge_to_qx[head]

        if len(parts) < 2 and qx_head not in {"final", "match"}:
            return None

        if qx_head in {"final", "match"}:
            if len(parts) >= 2:
                extras = parts[2:] if len(parts) > 2 else []
                return ",".join([qx_head, parts[1]] + extras)
            return qx_head

        value = parts[1]

        if qx_head == "host-suffix":
            value = value.lstrip(".")
        elif qx_head == "ip-asn":
            value = value.upper().removeprefix("AS")

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
            return ",".join(["host-suffix", value, policy] + extras)

        if head in {"domain", "host"} and len(parts) >= 2:
            value = parts[1]
            extras = parts[3:] if len(parts) >= 4 else []
            return ",".join(["host", value, policy] + extras)

        if head in {"domain-keyword", "host-keyword"} and len(parts) >= 2:
            value = parts[1]
            extras = parts[3:] if len(parts) >= 4 else []
            return ",".join(["host-keyword", value, policy] + extras)

        if head == "host-wildcard" and len(parts) >= 2:
            value = parts[1]
            extras = parts[3:] if len(parts) >= 4 else []
            return ",".join(["host-wildcard", value, policy] + extras)

    if ref_kind == "RULE-SET":
        if re.fullmatch(r"AS\d+", s.upper()):
            return f"ip-asn,{s.upper().removeprefix('AS')},{policy}"
        if re.fullmatch(r"\d+", s):
            return f"ip-asn,{s},{policy}"

    return None
