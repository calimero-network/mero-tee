#!/usr/bin/env python3
"""Pin a Hugging Face model repo to one commit and list its files with digests.

The GPU model probe (scripts/release/model/run-gpu-model-probe.sh) downloads
weights on the VM and refuses any file that does not match this list, so what
the probe measures is exactly what this run pinned. A large file's sha256 is
its LFS object id, which the Hub reports without a download; a small one
(config, tokenizer) is fetched here and hashed.

Usage: resolve-hf-files.py <repo> <revision> <out.json>
Fails, listing the closest repos, if <repo> does not exist.
"""

import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://huggingface.co/api"


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "mero-tee-gpu-model-probe"})
    token = os.environ.get("HF_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def main():
    repo, revision, out = sys.argv[1:4]
    try:
        info = json.loads(get(f"{API}/models/{repo}/revision/{urllib.parse.quote(revision, safe='')}"))
    except urllib.error.HTTPError as err:
        if err.code in (401, 404):
            name = repo.split("/")[-1].split("-GPTQ")[0].split("-AWQ")[0]
            query = urllib.parse.urlencode({"search": name, "limit": 30})
            found = json.loads(get(f"{API}/models?{query}"))
            names = "\n  ".join(m["id"] for m in found) or "(none)"
            sys.exit(f"{repo}@{revision} not found on the Hub. Repos matching {name!r}:\n  {names}")
        raise
    sha = info["sha"]
    tree = json.loads(get(f"{API}/models/{repo}/tree/{sha}?recursive=true"))
    files = []
    for entry in tree:
        if entry.get("type") != "file":
            continue
        path = entry["path"]
        lfs = entry.get("lfs")
        if lfs:
            digest = lfs["oid"]
        else:
            body = get(f"https://huggingface.co/{repo}/resolve/{sha}/{urllib.parse.quote(path)}")
            digest = hashlib.sha256(body).hexdigest()
        files.append({"path": path, "size": entry.get("size", 0), "sha256": digest})
    total = sum(f["size"] for f in files)
    with open(out, "w") as fh:
        json.dump({"repo": repo, "revision": sha, "files": files}, fh, indent=1)
    print(f"{repo}@{sha}: {len(files)} files, {total / 1e9:.1f} GB")


if __name__ == "__main__":
    main()
