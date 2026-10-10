import json, re, urllib.request, urllib.error, urllib.parse

UA = {"User-Agent": "sentinel-research/1.0"}

def http(url):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return -1, str(e)

out = {}

# 1) searches for missing repos
for q in ["DeepBlueCLI", "openioc in:name", "cti-stix2", "tripwire in:name", "sigma sql backend", "pysigma backend sql"]:
    st, body = http("https://api.github.com/search/repositories?q=" + urllib.parse.quote(q) + "&per_page=8")
    if st == 200:
        d = json.loads(body)
        out.setdefault("searches", {})[q] = [
            {"full_name": it["full_name"], "url": it["html_url"], "desc": (it.get("description") or "")[:120],
             "archived": it["archived"], "license": (it.get("license") or {}).get("spdx_id"),
             "pushed_at": it["pushed_at"]}
            for it in d.get("items", [])]
    else:
        out.setdefault("searches", {})[q] = f"HTTP {st}"
    print(q, "->", st)

# 2) full release list for repos where latest was RC
for name, url in [("wazuh", "wazuh/wazuh"), ("falco", "falcosecurity/falco"), ("misp", "MISP/MISP")]:
    st, body = http(f"https://github.com/{url}/releases.atom")
    entries = body.split("<entry>")[1:]
    lst = []
    for e in entries:
        t = re.search(r"<title>(.*?)</title>", e, re.S)
        u = re.search(r"<updated>(.*?)</updated>", e, re.S)
        lst.append((t.group(1).strip() if t else None, u.group(1) if u else None))
    out.setdefault("releases_full", {})[name] = lst[:15]

# 3) license raw texts that failed detection
raws = {
    "osquery": ("osquery/osquery", "d9db97e3a86c"),  # need full sha
    "sigma-spec": ("SigmaHQ/sigma-specification", "ba9251aa834b"),
    "sigma-rules": ("SigmaHQ/sigma", "8a4813404ea3"),
    "elastic-detection-rules": ("elastic/detection-rules", "bc5b7c3e9579"),
}
def raw(repo, sha, path):
    st, b = http(f"https://raw.githubusercontent.com/{repo}/{sha}/{path}")
    return st, b

# get full shas
import subprocess
full = {}
for name, (repo, short) in list(raws.items()):
    outp = subprocess.run(["git", "ls-remote", f"https://github.com/{repo}.git", "HEAD"],
                          capture_output=True, text=True).stdout.split()
    full[name] = outp[0] if outp else short

for name, repo in [("osquery", "osquery/osquery"), ("sigma-spec", "SigmaHQ/sigma-specification"),
                   ("sigma-rules", "SigmaHQ/sigma"), ("elastic-detection-rules", "elastic/detection-rules"),
                   ("chainsaw", "WithSecureLabs/chainsaw"), ("zircolite", "wagga40/Zircolite"),
                   ("velociraptor", "Velocidex/velociraptor"), ("wazuh", "wazuh/wazuh"),
                   ("hayabusa", "Yamato-Security/hayabusa"), ("sysmon-modular", "olafhartong/sysmon-modular"),
                   ("duckdb", "duckdb/duckdb")]:
    sha = full.get(name)
    if not sha:
        outp = subprocess.run(["git", "ls-remote", f"https://github.com/{repo}.git", "HEAD"],
                              capture_output=True, text=True).stdout.split()
        sha = outp[0] if outp else None
    got = {}
    for p in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.LESSER"]:
        st, b = raw(repo, sha, p)
        if st == 200 and b:
            got["file"] = p
            got["head"] = b[:300].replace("\n", " | ")
            # search for key markers
            low = b.lower()
            got["has_drl"] = "detection rule license" in low
            got["has_elastic"] = "elastic license" in low[:3000]
            got["has_agpl" ] = "affero" in low[:3000]
            break
    out.setdefault("licenses", {})[name] = got

json.dump(out, open("_stage1_work/fixes.json", "w", encoding="utf-8"), indent=2)
print("OK")
