import json

base = r'C:\Users\dhruv\OneDrive\Desktop\College\Light HIDS\_stage1_work'
d = json.load(open(base + r'\verification_raw.json', encoding='utf-8'))
d2 = json.load(open(base + r'\verification_raw2.json', encoding='utf-8'))

print('RAW1 (%d):' % len(d))
for k, v in d.items():
    api = v.get('api') or {}
    rel = v.get('latest_release') or {}
    lc = v.get('last_commit_atom') or v.get('last_commit') or {}
    sha = (v.get('head_sha') or '?')[:10]
    relt = str(rel.get('title'))[:40]
    reld = str(rel.get('updated'))[:10]
    lcd = str(lc.get('updated'))[:10]
    print('%-20s | %-7s | %-10s | rel=%-40s %s | lastcommit=%s | spdx=%-16s | %-12s | licfile=%s det=%s' % (
        k, v.get('default_branch', '?'), sha, relt, reld, lcd,
        api.get('spdx', '?'), api.get('language', '?'),
        v.get('license_file', '-'), v.get('license_detected', '-')))

print()
print('RAW2 (%d):' % len(d2))
for k, v in d2.items():
    api = v.get('api') or {}
    lc = v.get('last_commit') or {}
    lic = v.get('license') or {}
    sha = (v.get('head_sha') or '?')[:10]
    print('%-20s | %-7s | %-10s | lastcommit=%s | spdx=%-16s | %-12s | licfile=%s' % (
        k, v.get('default_branch', '?'), sha, str(lc.get('updated'))[:10],
        api.get('spdx', '?'), api.get('language', '?'), lic.get('file', '-')))

f = json.load(open(base + r'\fixes.json', encoding='utf-8'))
print()
print('releases_full:')
for k, v in f['releases_full'].items():
    if isinstance(v, dict):
        print(' ', k, '->', str(v.get('tag_name'))[:30], v.get('published_at'), '|', str(v.get('name'))[:60])
print('fixes licenses keys:', list(f['licenses'].keys()))
