import json, re, subprocess, sys, time, urllib.request, urllib.error

UA = {"User-Agent": "sentinel-research/1.0"}

REPOS = {
    # products / HIDS
    "wazuh": "https://github.com/wazuh/wazuh",
    "ossec-hids": "https://github.com/ossec/ossec-hids",
    "falco": "https://github.com/falcosecurity/falco",
    "falco-rules": "https://github.com/falcosecurity/rules",
    "tetragon": "https://github.com/cilium/tetragon",
    "osquery": "https://github.com/osquery/osquery",
    "velociraptor": "https://github.com/Velocidex/velociraptor",
    "sysmon-config-swiftonsecurity": "https://github.com/SwiftOnSecurity/sysmon-config",
    "sysmon-modular": "https://github.com/olafhartong/sysmon-modular",
    "aide": "https://github.com/aide/aide",
    "openscap": "https://github.com/OpenSCAP/openscap",
    "tripwire-oss": "https://github.com/tripwire/tripwire",
    # offline EVTX / sigma hunters
    "chainsaw": "https://github.com/WithSecureLabs/chainsaw",
    "hayabusa": "https://github.com/Yamato-Security/hayabusa",
    "zircolite": "https://github.com/wagga40/Zircolite",
    "deepbluecli": "https://github.com/ericzimmer/DeepBlueCLI",
    "evtx-omerbenamram": "https://github.com/omerbenamram/evtx",
    "python-evtx": "https://github.com/williballenthin/python-evtx",
    # sigma ecosystem
    "sigma-specification": "https://github.com/SigmaHQ/sigma-specification",
    "pysigma": "https://github.com/SigmaHQ/pySigma",
    "sigma-rules": "https://github.com/SigmaHQ/sigma",
    "sigma-cli": "https://github.com/SigmaHQ/sigma-cli",
    # other formats
    "yara": "https://github.com/VirusTotal/yara",
    "yarax": "https://github.com/VirusTotal/yara-x",
    "suricata": "https://github.com/OISF/suricata",
    "elastic-detection-rules": "https://github.com/elastic/detection-rules",
    "misp": "https://github.com/MISP/MISP",
    "python-stix2": "https://github.com/oasis-tc/cti-stix2",
    "openioc": "https://github.com/fireeye/openioc",
    "duckdb": "https://github.com/duckdb/duckdb",
    "sigma2sql": "https://github.com/Security-Bits/sigma2sql",
}

LANG_MARKERS = [
    ("pyproject.toml", "Python"), ("setup.py", "Python"),
    ("Cargo.toml", "Rust"), ("go.mod", "Go"),
    ("package.json", "JS/TS"), ("tsconfig.json", "JS/TS"),
    ("CMakeLists.txt", "C/C++"), ("configure.ac", "C/C++"),
    ("Makefile.am", "C/C++"), ("pom.xml", "Java"),
    ("*.csproj", "C#"),
]

def http(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return -1, str(e)

def lsremote(url):
    try:
        out = subprocess.run(["git", "ls-remote", "--symref", url, "HEAD"],
                             capture_output=True, text=True, timeout=60)
        branch, sha = None, None
        for line in out.stdout.splitlines():
            if line.startswith("ref:"):
                m = re.match(r"ref:\s+refs/heads/(\S+)\s+HEAD", line)
                if m: branch = m.group(1)
            elif line.endswith("\tHEAD"):
                sha = line.split("\t")[0]
        return branch, sha
    except Exception as e:
        return None, None

def atom_first(url, kind):
    st, body = http(url)
    if st != 200 or not body:
        return None
    entries = body.split("<entry>")[1:]
    if not entries:
        return None
    e = entries[0]
    title = re.search(r"<title>(.*?)</title>", e, re.S)
    upd = re.search(r"<updated>(.*?)</updated>", e, re.S)
    ident = re.search(r"<id>(.*?)</id>", e, re.S)
    sha = None
    if ident and "Commit/" in ident.group(1):
        sha = ident.group(1).rstrip("/").split("/")[-1]
    return {"title": title.group(1).strip() if title else None,
            "updated": upd.group(1) if upd else None,
            "sha": sha, "entry_id": ident.group(1) if ident else None}

def api_repo(url):
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)", url)
    st, body = http(f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}")
    if st != 200:
        return {"error": st}
    d = json.loads(body)
    return {"language": d.get("language"),
            "spdx": (d.get("license") or {}).get("spdx_id"),
            "default_branch": d.get("default_branch"),
            "pushed_at": d.get("pushed_at"),
            "archived": d.get("archived"),
            "description": d.get("description"),
            "html_url": d.get("html_url")}

def detect_spdx(text):
    head = text[:4000].lower()
    if "mozilla public license" in head[:600]: return "MPL-2.0"
    if "apache license" in head[:600] and "version 2.0" in head[:800]:
        return "Apache-2.0"
    if "gnu affero general public license" in head[:600]: return "AGPL-3.0"
    if "gnu lesser general public license" in head[:600]:
        if "version 3" in head[:900]: return "LGPL-3.0"
        if "version 2.1" in head[:900]: return "LGPL-2.1"
    if "gnu general public license" in head[:600]:
        later = "or (at your option) any later version" in head or "either version" in head
        if "version 3" in head[:900]: return "GPL-3.0-or-later" if later else "GPL-3.0-only"
        if "version 2" in head[:900]: return "GPL-2.0-or-later" if later else "GPL-2.0-only"
    if "permission is hereby granted, free of charge" in head:
        if "sublicense" in head and "patent" in head: return "Apache-2.0"
        if "without restriction" in head:
            return "MIT-or-BSD (manual review)"
    if "redistribution and use in source and binary forms" in head:
        if "neither the name" in head: return "BSD-3-Clause"
        return "BSD-2-Clause"
    if "isc license" in head: return "ISC"
    if "eclipse public license" in head[:600]:
        if "version 2.0" in head[:900]: return "EPL-2.0"
        return "EPL"
    return "UNDETECTED"

def license_file(owner, repo, sha):
    for p in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md", "LICENCE.md"]:
        st, body = http(f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{p}")
        if st == 200 and body:
            return p, detect_spdx(body), len(body)
    return None, None, 0

def main():
    results = {}
    for name, url in REPOS.items():
        m = re.match(r"https://github\.com/([^/]+)/([^/]+)", url)
        owner, repo = m.group(1), m.group(2)
        print(f"== {name}", flush=True)
        branch, sha = lsremote(url)
        api = api_repo(url)
        rel = atom_first(f"https://github.com/{owner}/{repo}/releases.atom", "rel")
        br = branch or (api.get("default_branch") if "default_branch" in api else None)
        commits = atom_first(f"https://github.com/{owner}/{repo}/commits/{br}.atom", "commit") if br else None
        lf, ldet, llen = (license_file(owner, repo, sha) if sha else (None, None, 0))
        # language markers
        markers = []
        if sha:
            for path, lang in LANG_MARKERS:
                st, _ = http(f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}")
                if st == 200:
                    markers.append(f"{path}({lang})")
        results[name] = {
            "url": url, "default_branch": br, "head_sha": sha,
            "api": api, "latest_release": rel, "last_commit_atom": commits,
            "license_file": lf, "license_detected": ldet, "license_len": llen,
            "lang_markers": markers,
        }
        time.sleep(0.4)
    with open("_stage1_work/verification_raw.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("DONE", len(results))

if __name__ == "__main__":
    main()
