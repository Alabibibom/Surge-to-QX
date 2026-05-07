from pathlib import Path
import csv
import io
import re
import requests

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "sources" / "rules-source.conf"
DIST = ROOT / "dist"
DIST.mkdir(exist_ok=True)

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

def parse_csv_line(line: str):
    try:
        return next(csv.reader(io.StringIO(line), skipinitialspace=True))
    except Exception:
        return line.split(",")

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

def sanitize_filename(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    name = re.sub(r"\s+", "", name)
    return name[:80] if len(name) > 80 else name

def normalize_policy(p: str) -> str:
    """保留自定义策略组名称，只标准化 REJECT 和 DIRECT"""
    p_upper = (p or "").strip().upper()
    if p_upper in {"REJECT", "REJECT-DROP", "REJECT-NO-DROP"}:
        return "reject"
    if p_upper == "DIRECT":
        return "direct"
    if p_upper == "PROXY":
        return "proxy"
    # 对于 "国内"、"国外"、"苹果进阶" 等自定义策略，原样返回
    return p.strip()

def normalize_qx_rule(line: str, policy="proxy", ref_kind="RULE-SET"):
    s = line.strip().replace("\ufeff", "")
    if not s or s.startswith(("#", ";", "//")):
        return None

    # 处理纯域名列表 (DOMAIN-SET)
    if ref_kind == "DOMAIN-SET":
        if "," not in s and not s.startswith(("[", "]", "payload:")):
            s = s.lstrip(".") # 去掉可能存在的头部点号
            return f"host-suffix,{s},{policy}"

    # 标准化常规规则
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

    # 如果已经是 QX 格式，直接替换掉末尾的 policy 确保符合你的设定
    lower_s = s.lower()
    if lower_s.startswith(("host-suffix,", "host,", "host-keyword,", "ip-cidr,", "ip6-cidr,", "geoip,", "user-agent,", "url-regex,", "process-name,")):
        parts = s.split(",")
        if len(parts) >= 2:
            base = ",".join(parts[:-1]) # 保留域名的原始大小写
            return f"{base},{policy}"

    return None

def convert_remote_rules(text: str, policy="proxy", ref_kind="RULE-SET"):
    out = []
    for raw in text.splitlines():
        conv = normalize_qx_rule(raw, policy=policy, ref_kind=ref_kind)
        if conv:
            out.append(conv)
    return out

def main():
    lines = SRC.read_text(encoding="utf-8").splitlines()
    
    rules_by_title = {}
    current_title = "未命名规则"
    
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
            
        # 1. 遇到标题注释，更新 current_title
        if line.startswith(("#", ";", "//")):
            t = line.lstrip("#;//").strip()
            if t:
                current_title = t
            if current_title not in rules_by_title:
                rules_by_title[current_title] = []
            continue
            
        # 2. 遇到规则行，提取并下载
        ref_kind, url, raw_policy = extract_ref(line)
        if ref_kind:
            policy = normalize_policy(raw_policy)
            
            if current_title not in rules_by_title:
                rules_by_title[current_title] = []
                
            try:
                if url.startswith("http"):
                    print(f"[{current_title}] 正在拉取: {url}")
                    r = requests.get(url, headers=UA, timeout=60)
                    r.raise_for_status()
                    remote_text = r.text
                else:
                    # 针对你里面 RULE-SET,VPS.txt 这种本地文件的支持
                    local_path = SRC.parent / url
                    if local_path.exists():
                        print(f"[{current_title}] 读取本地: {url}")
                        remote_text = local_path.read_text(encoding="utf-8")
                    else:
                        print(f"[{current_title}] 跳过缺失的本地文件: {url}")
                        remote_text = ""

                # 3. 把转换后的规则追加到同一个标题的列表中（这样 Telegram 下的 3 个 URL 会合并在一起）
                converted = convert_remote_rules(remote_text, policy=policy, ref_kind=ref_kind)
                rules_by_title[current_title].extend(converted)
                
            except Exception as e:
                print(f"拉取失败 {url}: {e}")
                rules_by_title[current_title].append(f"# 拉取失败: {url} ({e})")

    # 4. 全部处理完后，循环字典写入最终文件
    for title, rules in rules_by_title.items():
        if not rules:
            continue
            
        # 去重，同时保持顺序
        seen = set()
        unique_rules = []
        for r in rules:
            if r not in seen:
                seen.add(r)
                unique_rules.append(r)
                
        safe_title = sanitize_filename(title)
        path = DIST / f"{safe_title}.txt"
        path.write_text("\n".join(unique_rules).rstrip() + "\n", encoding="utf-8")
        print(f"==> 成功生成: {path.name} (共 {len(unique_rules)} 条规则)")

if __name__ == "__main__":
    main()
