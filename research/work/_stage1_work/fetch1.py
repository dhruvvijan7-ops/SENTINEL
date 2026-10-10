import urllib.request, re, sys
UA = {"User-Agent": "sentinel/1.0"}
def get(u):
    try:
        return urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=30).read().decode("utf-8", "replace")
    except Exception as e:
        return f"ERR {e}"

which = sys.argv[1]
if which == "sigma-releases":
    b = get("https://github.com/SigmaHQ/sigma/releases.atom")
    for e in b.split("<entry>")[1:9]:
        t = re.search(r"<title>(.*?)</title>", e, re.S).group(1).strip()
        u = re.search(r"<updated>(.*?)</updated>", e, re.S).group(1)
        print(t, "@", u)
elif which == "drl":
    print(get("https://raw.githubusercontent.com/SigmaHQ/Detection-Rule-License/main/LICENSE.md")[:3000])
elif which == "drl-repo":
    # metadata for DRL repo
    import subprocess
    out = subprocess.run(["git", "ls-remote", "--symref", "https://github.com/SigmaHQ/Detection-Rule-License.git", "HEAD"], capture_output=True, text=True).stdout
    print(out)
