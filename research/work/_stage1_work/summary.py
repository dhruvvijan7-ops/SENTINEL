import json
d = json.load(open('_stage1_work/verification_raw.json', encoding='utf-8'))
for k, v in d.items():
    a = v['api']; rel = v['latest_release']; cm = v['last_commit_atom']
    sha = (v['head_sha'] or '')[:12]
    rel_s = f"{rel['title']}@{rel['updated']}" if rel else "NO_RELEASE"
    cm_s = cm['updated'] if cm else "NONE"
    print(f"{k:26} | br={v['default_branch']} | sha={sha} | lang={a.get('language')} | spdx_api={a.get('spdx')} | lic={v['license_file']}:{v['license_detected']} | rel={rel_s} | lastcommit={cm_s} | arch={a.get('archived')} | err={a.get('error')} | markers={','.join(v['lang_markers'])}")
