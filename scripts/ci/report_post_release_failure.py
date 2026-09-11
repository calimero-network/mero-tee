#!/usr/bin/env python3
"""File (or update) a GitHub issue when a post-release probe fails.

A post-release probe runs *after* the release is published, triggered by
``workflow_run``. That means its result is attached to nothing a release
consumer ever looks at: not the PR (there is none), not the release page, not
the tag's commit status. A red run leaves a red row in the Actions tab and
nothing else -- which is exactly how an anti-fake assertion failed against a
published image and went unread (calimero-network/mero-tee#251).

So say it out loud, where it survives: one open issue per (workflow, release).
Repeat failures for the same release comment on that issue rather than opening
another, so a flaky probe cannot bury the tracker.

The issue is deliberately NOT auto-closed on a later success. A probe that
failed against a published artifact stays a question for a human even after a
re-run goes green -- the artifact did not change, and "it passed the second
time" is a finding, not a resolution.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

API_ROOT = "https://api.github.com"

# Stamped into the issue body so a later run can find its own issue without
# depending on the title, which humans rename.
MARKER_TEMPLATE = "<!-- post-release-probe-failure:{workflow}:{version} -->"


def api_request(
    token: str, method: str, url: str, payload: Optional[Dict[str, Any]] = None
) -> Any:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url=url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read().decode("utf-8")
    return json.loads(body) if body else None


def find_existing_issue(
    token: str, api_root: str, repo: str, marker: str
) -> Optional[Dict[str, Any]]:
    """Return the open issue carrying `marker`, if one exists.

    Listing and matching locally rather than using the search API: search is
    eventually consistent, and an issue opened minutes ago by the previous
    failing run may not be indexed yet. That would open a duplicate -- the one
    thing this function exists to prevent.
    """
    page = 1
    while page <= 10:
        issues: List[Dict[str, Any]] = api_request(
            token,
            "GET",
            f"{api_root}/repos/{repo}/issues?state=open&per_page=100&page={page}",
        )
        if not issues:
            return None
        for issue in issues:
            # The issues endpoint returns PRs too; they cannot carry our marker,
            # but skip them explicitly rather than relying on that.
            if "pull_request" in issue:
                continue
            if marker in (issue.get("body") or ""):
                return issue
        if len(issues) < 100:
            return None
        page += 1
    return None


def build_body(args: argparse.Namespace, marker: str) -> str:
    lines = [
        marker,
        "",
        f"`{args.workflow}` failed against release **{args.tag or args.version}**, "
        "which is already published.",
        "",
        "| | |",
        "| --- | --- |",
        f"| Release | `{args.tag or args.version}` |",
        f"| Version | `{args.version}` |",
        f"| Workflow | `{args.workflow}` |",
        f"| Failed job | `{args.job}` |",
        f"| Run | {args.run_url} |",
    ]
    if args.artifacts_hint:
        lines.append(f"| Artifacts | {args.artifacts_hint} |")
    lines += [
        "",
        "### Why this is an issue and not just a red run",
        "",
        "This probe runs after publication, so its result is not attached to a "
        "pull request, the release page, or the tag's commit status. Without "
        "this issue the only trace is a row in the Actions tab.",
        "",
        "### What to check",
        "",
        "1. Open the run above and read the failing step's assertion — not just "
        "the job conclusion.",
        "2. Download the run's artifacts before they expire (90 days by "
        "default) — they carry the verifier output that says *which* assertion "
        "failed.",
        "3. Decide whether the published artifact is affected. If it is, that "
        "is a release problem, not a CI problem.",
        "",
        "_Filed automatically. Repeat failures for this release comment here "
        "rather than opening another issue. This is not auto-closed on a later "
        "green run: the published artifact does not change when CI is re-run._",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", default="")
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--artifacts-hint", default="")
    parser.add_argument("--label", action="append", default=[])
    parser.add_argument(
        "--api-root",
        default=os.environ.get("GITHUB_API_URL", API_ROOT),
        help="Override for testing against a local stand-in.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    api_root = args.api_root.rstrip("/")

    token = os.environ.get("GH_TOKEN", "")
    if not token and not args.dry_run:
        print("::error::GH_TOKEN is required to file the failure issue.")
        return 1

    marker = MARKER_TEMPLATE.format(workflow=args.workflow, version=args.version)
    body = build_body(args, marker)
    title = f"Post-release probe failed for {args.tag or args.version}"

    if args.dry_run:
        print(f"[dry-run] title: {title}")
        print(body)
        return 0

    try:
        existing = find_existing_issue(token, api_root, args.repo, marker)
        if existing:
            number = existing["number"]
            api_request(
                token,
                "POST",
                f"{api_root}/repos/{args.repo}/issues/{number}/comments",
                {"body": f"Failed again.\n\n- Run: {args.run_url}\n- Job: `{args.job}`"},
            )
            print(f"Commented on existing issue #{number}: {existing.get('html_url')}")
            return 0

        payload: Dict[str, Any] = {"title": title, "body": body}
        if args.label:
            payload["labels"] = args.label
        created = api_request(
            token, "POST", f"{api_root}/repos/{args.repo}/issues", payload
        )
        print(f"Opened issue #{created['number']}: {created.get('html_url')}")
        return 0
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        # Never fail the workflow over the reporting step: the probe failure is
        # the finding, and masking it behind a reporting error helps nobody.
        print(f"::warning::Could not file the failure issue (HTTP {exc.code}): {detail}")
        return 0
    except urllib.error.URLError as exc:
        print(f"::warning::Could not file the failure issue: {exc}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
