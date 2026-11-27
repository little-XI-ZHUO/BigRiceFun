"""Create the GitHub repository and push, using the credential Git Credential Manager already holds.

usage: python -I tools/setup_remote.py <repo-name> [--public]
"""
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"


def token():
    """Ask git for the stored github.com credential (no token ever hits disk)."""
    p = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=github.com\n\n",
                       capture_output=True, text=True)
    for line in p.stdout.splitlines():
        if line.startswith("password="):
            return line[len("password="):].strip()
    raise SystemExit("no github.com credential found in Git Credential Manager")


def api(tok, method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers={
        "Authorization": "Bearer " + tok,
        "Accept": "application/vnd.github+json",
        "User-Agent": "BigRiceScan-setup",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            body = r.read().decode()
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:500]
        raise SystemExit("GitHub API %s %s -> HTTP %d\n%s" % (method, path, e.code, detail))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    name = args[0] if args else "BigRiceScan"
    public = "--public" in sys.argv
    tok = token()

    user = api(tok, "GET", "/user")
    login = user["login"]
    print("authenticated as", login)

    try:
        repo = api(tok, "GET", "/repos/%s/%s" % (login, name))
        print("repository already exists:", repo["html_url"], "| private:", repo["private"])
    except SystemExit:
        repo = api(tok, "POST", "/user/repos", {
            "name": name,
            "description": "Intranet web asset mapping with web weak-credential and "
                           "unauthorized-access auditing. Offline, GUI, no AI needed.",
            "private": not public,
            "has_issues": True,
            "has_wiki": False,
            "auto_init": False,
            "license_template": "mit",
        })
        print("created:", repo["full_name"], "| private:", repo["private"], "|", repo["html_url"])

    remote = "https://github.com/%s/%s.git" % (login, repo["name"])
    subprocess.run(["git", "remote", "remove", "origin"], cwd=os.getcwd(),
                   capture_output=True)
    subprocess.run(["git", "remote", "add", "origin", remote], check=True)
    print("remote set to", remote)

    r = subprocess.run(["git", "push", "-u", "origin", "HEAD"], capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip())
    if r.returncode != 0:
        raise SystemExit("push failed")
    print("pushed:", repo["html_url"])


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
