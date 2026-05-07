from pathlib import Path
import csv
import io

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "sources" / "rules-source.conf"
DIST = ROOT / "dist"
OUT = DIST / "online-only.conf"

DIST.mkdir(exist_ok=True)

def parse_csv_line(line: str):
    try:
        return next(csv.reader(io.StringIO(line), skipinitialspace=True))
    except Exception:
        return []

def is_comment(line: str) -> bool:
    s = line.strip()
    return s.startswith("#") or s.startswith(";")

def is_blank(line: str) -> bool:
    return line.strip() == ""

def is_online_rule(line: str) -> bool:
    fields = parse_csv_line(line)
    if len(fields) < 2:
        return False
    kind = fields[0].strip().upper()
    target = fields[1].strip()
    return kind in {"RULE-SET", "DOMAIN-SET"} and target.startswith(("http://", "https://"))

def normalize_blank_lines(lines):
    cleaned = []
    last_blank = True
    for line in lines:
        if is_blank(line):
            if not last_blank:
                cleaned.append("")
            last_blank = True
        else:
            cleaned.append(line.rstrip())
            last_blank = False
    while cleaned and cleaned[-1] == "":
        cleaned.pop()
    return cleaned

def main():
    if not SRC.exists():
        raise FileNotFoundError(f"source file not found: {SRC}")

    lines = SRC.read_text(encoding="utf-8").splitlines()
    output = []
    pending_comments = []

    for raw in lines:
        line = raw.rstrip()

        if is_blank(line):
            if pending_comments and (not pending_comments or pending_comments[-1] != ""):
                pending_comments.append("")
            continue

        if is_comment(line):
            pending_comments.append(line)
            continue

        if is_online_rule(line):
            if output and output[-1] != "" and pending_comments:
                output.append("")
            output.extend(pending_comments)
            output.append(line)
            pending_comments = []
        else:
            pending_comments = []

    result = normalize_blank_lines(output)
    OUT.write_text("\n".join(result) + "\n", encoding="utf-8")
    print(f"generated: {OUT}")

if __name__ == "__main__":
    main()
