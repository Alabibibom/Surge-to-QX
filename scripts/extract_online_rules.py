from pathlib import Path
import csv
import io
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

def extract_policy(line: str) -> str:
    fields = parse_csv_line(line)
    if len(fields) < 3:
        return "PROXY"
    p = fields[2].strip()
    if p in {"DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP", "PROXY"}:
        return p
    return "PROXY"

def fetch_text(url: str) -> str:
    r = requests.get(url, headers=UA, timeout=60)
    r.raise_for_status()
    return r.text

def normalize_qx_rule(line: str, default_policy="PROXY"):
    s = line.strip().replace("\ufeff", "")
    
    # 核心：直接丢弃所有远程文件里的注释和空行！
    if not s or is_comment(s):
        return None

    if s.startswith("DOMAIN-SUFFIX,"):
        return "HOST-SUFFIX," + s.split(",", 1)[1] + f",{default_policy}"
    if s.startswith("DOMAIN,"):
        return "HOST," + s.split(",", 1)[1] + f",{default_policy}"
    if s.startswith("DOMAIN-KEYWORD,"):
        return "HOST-KEYWORD," + s.split(",", 1)[1] + f",{default_policy}"
    if s.startswith("IP-CIDR6,"):
        return "IP6-CIDR," + s.split(",", 1)[1] + f",{default_policy}"
    if s.startswith("IP-CIDR,"):
        return "IP-CIDR," + s.split(",", 1)[1] + f",{default_policy}"
    if s.startswith("GEOIP,"):
        parts = s.split(",")
        if len(parts) >= 2:
            return f"GEOIP,{parts[1]},{default_policy}"

    if s.startswith(("USER-AGENT,", "URL-REGEX,", "PROCESS-NAME,")):
        return s + f",{default_policy}"

    if s.startswith("HOST-SUFFIX,") or s.startswith("HOST,") or s.startswith("HOST-KEYWORD,"):
        if s.count(",") >= 2:
            return s.rsplit(",", 1)[0] + f",{default_policy}"

    if s.startswith("FINAL,") or s.startswith("MATCH,"):
        return s

    # 任何不认识的格式（包括作者夹带的私货乱码），一律抛弃
    return None

def convert_remote_rules(text: str, policy="PROXY"):
    out = []
    seen = set()
    for raw in text.splitlines():
        # 调用上面的函数，如果是垃圾注释/不支持的格式/空行，返回 None 就会被丢掉
        conv = normalize_qx_rule(raw, policy)
        if conv and conv not in seen:
            seen.add(conv)
            out.append(conv)
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
            # 这里保留的是你自己在 sources/rules-source.conf 里写的注释
            pending_comments.append(line)
            continue

        if is_online_ref(line):
            url = extract_url(line)
            policy = extract_policy(line)
            if pending_comments:
                if output and output[-1] != "":
                    output.append("")
                output.extend(pending_comments)
            pending_comments = []
            
            try:
                remote = fetch_text(url)
                # 转换远程规则，抛弃所有原作者加的废话
                converted = convert_remote_rules(remote, policy=policy)
                if converted:
                    output.extend(converted)
            except Exception as e:
                output.append(f"# fetch failed: {url} ({e})")
        else:
            # 如果是本地规则或者SYSTEM等不要的内容，连带它前面的注释也扔掉
            pending_comments = []

    while output and output[-1] == "":
        output.pop()

    OUT.write_text("\n".join(output) + "\n", encoding="utf-8")
    print(f"generated: {OUT}")

if __name__ == "__main__":
    main()
