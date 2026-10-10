import json, re
from pathlib import Path

d = json.load(open(Path(__file__).with_name('local_eventfields.json'), encoding='utf-8-sig'))
pat = re.compile(r'<Data Name=["\']([^"\']+)["\']>(.*?)</Data>', re.S)

for l in d['logs']:
    rows = []
    for e in l.get('events', []):
        if not e.get('found'):
            continue
        fields = pat.findall(e.get('sample_xml') or '')
        rows.append((e['id'], fields))
    if rows:
        print('==', l['log'])
        for eid, fields in rows:
            names = [n for n, v in fields]
            print(f'  id {eid}: {names}')
            for n, v in fields:
                v = (v[:70] + '...') if len(v) > 70 else v
                print(f'      {n} = {v!r}')
