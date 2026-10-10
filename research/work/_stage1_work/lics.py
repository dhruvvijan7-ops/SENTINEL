import json, urllib.request

d = json.load(open(r'C:\Users\dhruv\OneDrive\Desktop\College\Light HIDS\_stage1_work\verification_raw.json', encoding='utf-8'))
for k in ['sigma2sql', 'python-stix2', 'openioc', 'tripwire-oss', 'deepbluecli', 'sysmon-config-swiftonsecurity', 'sigma-specification', 'sigma-rules', 'osquery']:
    v = d.get(k, {})
    print(k, '->', v.get('url'), '| branch:', v.get('default_branch'), '| err:', str(v.get('error'))[:120])

print()
def get(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'sentinel/1.0'})
        return urllib.request.urlopen(req, timeout=30).read().decode('utf-8', 'replace')
    except Exception as e:
        return 'FAIL: %s' % e

for repo in ['SigmaHQ/pySigma-pipeline-windows', 'SigmaHQ/pySigma-pipeline-sysmon']:
    found = False
    for fn in ['LICENSE', 'LICENSE.txt', 'COPYING', 'pyproject.toml']:
        t = get('https://raw.githubusercontent.com/%s/main/%s' % (repo, fn))
        if not t.startswith('FAIL'):
            print('==', repo, fn, '==')
            print(t[:500])
            found = True
            break
    if not found:
        print('==', repo, 'no licence/pyproject file found ==')
