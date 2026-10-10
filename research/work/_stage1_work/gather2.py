import json, re, subprocess, time, urllib.request, urllib.error

UA = {"User-Agent": "sentinel-research/1.0"}

REPOS = {
    "deepbluecli": "https://github.com/sans-blue-team/DeepBlueCLI",
    "openioc11": "https://github.com/fireeye/OpenIOC_1.1",
    "stix2-python": "https://github.com/oasis-open/cti-python-stix2",
    "tripwire-oss": "https://github.com/Tripwire/tripwire-open-source",
    "pysigma-sqlite-wagga40": "https://github.com/wagga40/pySigma-backend-sqlite",
    "pysigma-athena": "https://github.com/SigmaHQ/pySigma-backend-athena",
    "pysigma-sqlite-denizenb": "https://github.com/DenizenB/pySigma-backend-sqlite",
}

def http(url):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return -1, ""

def lsremote(url):
    out = subprocess.run(["git", "ls-remote", "--symref", url, "HEAD"],
                         capture_output=True, text=True, timeout=60).stdout
    branch, sha = None, None
    for line in out.splitlines():
        if line.startswith("ref:"):
            m = re.match(r"ref:\s+refs/heads/(\S+)\s+HEAD", line)
            if m: branch = m.group(1)
        elif line.endswith("\tHEAD"):
            sha = line.split("\t")[0]
    return branch, sha

def atom_first(url):
    st, body = http(url)
    if st != 200: return None
    entries = body.split("<entry>")[1:]
    if not entries: return None
    e = entries[0]
    t = re.search(r"<title>(.*?)</title>", e, re.S)
    u = re.search(r"<updated>(.*?)</updated>", e, re.S)
    i = re.search(r"<id>(.*?)</id>", e, re.S)
    sha = i.group(1).split("/")[-1] if (i and "Commit/" in i.group(1)) else None
    return {"title": t.group(1).strip() if t else None, "updated": u.group(1) if u else None, "sha": sha}

def api_repo(url):
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)", url)
    st, body = http(f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}")
    if st != 200: return {"error": st}
    d = json.loads(body)
    return {"language": d.get("language"), "spdx": (d.get("license") or {}).get("spdx_id"),
            "default_branch": d.get("default_branch"), "pushed_at": d.get("pushed_at"),
            "archived": d.get("archived"), "description": d.get("description")}

results = {}
for name, url in REPOS.items():
    branch, sha = lsremote(url)
    api = api_repo(url)
    rel = atom_first(f"{url}/releases.atom")
    cm = atom_first(f"{url}/commits/{branch}.atom") if branch else None
    # license
    lic = None
    for p in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]:
        st, b = http(f"https://raw.githubusercontent.com/{re.match(r'https://github.com/([^/]+/[^/]+)',url).group(1)}/{sha}/{p}")
        if st == 200 and b:
            lic = {"file": p, "head": b[:200].replace("\n"," | ")}
            break
    results[name] = {"url": url, "default_branch": branch, "head_sha": sha, "api": api,
                     "latest_release": rel, "last_commit": cm, "license": lic}
    print(name, "ok", flush=True)
    time.sleep(0.3)

json.dump(results, open("_stage1_work/verification_raw2.json", "w", encoding="utf-8"), indent=2)
for k, v in results.items():
    a = v["api"]; rel = v["latest_release"]; cm = v["last_commit"]
    print(f"{k:24} br={v['default_branch']} sha={(v['head_sha'] or '')[:10]} lang={a.get('language')} spdx={a.get('spdx')} rel={(rel['title']+'@'+rel['updated']) if rel else None} lastcommit={cm['updated'] if cm else None} lic={(v['license'] or {}).get('file')}")
