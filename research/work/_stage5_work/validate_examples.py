import json, re, sys
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator

doc = Path("stage-5-dynamic-rule-engine.md").read_text(encoding="utf-8")

# Extract section 11 example blocks: from '## 11.' to '## 12.'
m = re.search(r"## 11\. Worked Rule Examples.*?(?=\n---\n\n## 12\.)", doc, re.S)
assert m, "section 11 not found"
sec11 = m.group(0)
blocks = re.findall(r"```yaml\n(.*?)```", sec11, re.S)
print(f"example blocks found: {len(blocks)}")

schema = json.loads(Path("rule_schema.json").read_text(encoding="utf-8"))
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)

fail = 0
for i, b in enumerate(blocks, 1):
    first = next((l for l in b.splitlines() if l.strip() and not l.strip().startswith("#")), "?")
    try:
        doc_obj = yaml.safe_load(b)
    except Exception as e:
        print(f"[{i}] YAML PARSE FAIL: {e}  ({first})")
        fail += 1
        continue
    errs = sorted(validator.iter_errors(doc_obj), key=lambda e: list(e.path))
    if errs:
        fail += 1
        print(f"[{i}] SCHEMA FAIL id={doc_obj.get('id')} kind={doc_obj.get('kind')}")
        for e in errs[:6]:
            print("    -", "/".join(map(str, e.path)) or "<root>", ":", e.message[:160])
    else:
        print(f"[{i}] OK  {doc_obj.get('id'):8}  {doc_obj.get('kind')}")

# Also parse the governance YAML blocks (decisions / open_questions / not_verified)
for name in ("DECISIONS", "OPEN QUESTIONS", "NOT VERIFIED"):
    mm = re.search(rf"## (?:\d+\. )?{name}\n\n```yaml\n(.*?)```", doc, re.S)
    if not mm:
        print(f"BLOCK {name}: NOT FOUND")
        fail += 1
        continue
    try:
        data = yaml.safe_load(mm.group(1))
        key = list(data.keys())[0]
        print(f"BLOCK {name}: OK ({len(data[key])} items under '{key}')")
    except Exception as e:
        print(f"BLOCK {name}: PARSE FAIL {e}")
        fail += 1

print("RESULT:", "FAIL" if fail else "ALL OK")
sys.exit(1 if fail else 0)
