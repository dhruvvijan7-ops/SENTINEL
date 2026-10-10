import re

p = r'C:\Users\dhruv\OneDrive\Desktop\College\Light HIDS\stage-1-landscape-and-rule-engine-decision.md'
t = open(p, encoding='utf-8').read()

# YAML block parse
m = re.search('```yaml\n(.*?)```', t, re.S)
try:
    import yaml
    d = yaml.safe_load(m.group(1))
    print('YAML OK, decisions:', len(d['decisions']))
    print('ids:', [x['id'] for x in d['decisions']])
except ImportError:
    print('pyyaml not installed; block length', len(m.group(1)))
except Exception as e:
    print('YAML ERROR:', e)

order = ['## 1. Verification Log', '## 2. Licence Register', '## 3. Capability Matrix',
         '## 4. Minimum Viable Light-HIDS Scope', '## 5. Rule-Engine Decision Record',
         '## 6. Canonical Rule Representation', '## 7. Lessons', '## 8. DECISIONS']
pos = [t.find(s) for s in order]
print('order ok:', all(x > 0 for x in pos) and pos == sorted(pos))

print('labels: VERIFIED=%d UNVERIFIED=%d INFERRED=%d P-T-B=%d' % (
    len(re.findall(r'\bVERIFIED\b', t)), t.count('UNVERIFIED'),
    len(re.findall(r'\bINFERRED\b', t)), t.count('PROPOSED - TO BENCHMARK')))

# encoding sanity: em-dash and section sign present as unicode
print('em-dash count:', t.count('\u2014'), '| section-sign count:', t.count('\u00a7'))
print('replacement chars (bad):', t.count('\ufffd'))

# lessons check: 5 tools x (3 ADOPT + 3 AVOID)
sec7 = t[t.find('## 7. Lessons'):t.find('## 8. DECISIONS')]
tools = ['### 7.1', '### 7.2', '### 7.3', '### 7.4', '### 7.5']
idx = [sec7.find(x) for x in tools] + [len(sec7)]
for i in range(5):
    chunk = sec7[idx[i]:idx[i + 1]]
    print('7.%d adopt=%d avoid=%d' % (i + 1, chunk.count('ADOPT') // 1 or len(re.findall(r'^\d+\. \*\*', chunk, re.M)) and len(re.findall(r'ADOPT', chunk)), len(re.findall(r'AVOID', chunk))))

# count numbered items between ADOPT/AVOID markers per tool
for i in range(5):
    chunk = sec7[idx[i]:idx[i + 1]]
    a = chunk.find('**ADOPT**')
    b = chunk.find('**AVOID**')
    adopt_items = len(re.findall(r'^\d+\. \*\*', chunk[a:b], re.M))
    avoid_items = len(re.findall(r'^\d+\. \*\*', chunk[b:], re.M))
    print('tool 7.%d: adopt items=%d, avoid items=%d' % (i + 1, adopt_items, avoid_items))

# unresolved marker check
print('TODO/CONTINUE markers left:', t.count('CONTINUE'), t.count('TODO'))
