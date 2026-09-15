#!/usr/bin/env python3
"""Parse every Ansible template with the delimiters Ansible will actually use.

`${#arr[@]}` is bash's array length. `{#` is Jinja's comment-open. A bash
script written as a `.j2` therefore renders fine right up until someone counts
an array, at which point Jinja swallows the rest of the file hunting for `#}`
and the render fails with "Missing end of comment tag".

That is not hypothetical. It landed in `fleet-sidecar.sh.j2` and took out the
node-image release for 2.3.55 and 2.3.56 -- and because `Release mero-kms`
refuses to publish without `mero-tee-v<version>/published-mrtds.json`, every
later push to master went red too, on a job whose message named a missing
release rather than a broken template.

Nothing caught it earlier, and the reason is worth stating: the four
`fleet-sidecar-*-test.sh` harnesses do substitute the template's variables, but
they do it with `sed`. That exercises the bash and says nothing about whether
Jinja can parse the file. The break needed a GCP VM, a packer build and five
minutes to surface, and only on the read-only profiles -- the sidecar task is
`when: merod_mode == "read-only"`, so the `debug` profile went green beside it.

So this checks the one thing those harnesses cannot: that each template parses.
It reads the delimiters out of the `template:` task itself rather than assuming
the defaults, because a task may legitimately move them (the sidecar does), and
a checker that assumed defaults would report a failure Ansible will not have.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import jinja2
    import yaml
except ImportError as exc:  # pragma: no cover - environment problem, not a finding
    print(f"[FAIL] missing dependency: {exc}. Install with: pip install jinja2 pyyaml")
    raise SystemExit(2)

REPO_ROOT = Path(__file__).resolve().parents[2]
ANSIBLE_ROOT = REPO_ROOT / "mero-tee" / "ansible"

# Ansible's template module exposes exactly these delimiter overrides.
DELIMITERS = (
    "variable_start_string",
    "variable_end_string",
    "block_start_string",
    "block_end_string",
    "comment_start_string",
    "comment_end_string",
)


def iter_tasks(doc):
    """Yield every task mapping in a tasks file or playbook, including blocks."""
    if isinstance(doc, list):
        for item in doc:
            yield from iter_tasks(item)
    elif isinstance(doc, dict):
        yield doc
        for key in ("block", "rescue", "always", "tasks", "pre_tasks", "post_tasks", "handlers"):
            if key in doc:
                yield from iter_tasks(doc[key])


def template_tasks():
    """(template path, delimiter overrides, where it was declared) for each task."""
    for tasks_file in sorted(ANSIBLE_ROOT.rglob("*.yml")):
        if "templates" in tasks_file.parts:
            continue
        try:
            docs = list(yaml.safe_load_all(tasks_file.read_text()))
        except yaml.YAMLError as exc:
            yield None, None, f"{tasks_file.relative_to(REPO_ROOT)}: unparseable YAML: {exc}"
            continue

        for doc in docs:
            for task in iter_tasks(doc):
                spec = task.get("template") or task.get("ansible.builtin.template")
                if not isinstance(spec, dict) or "src" not in spec:
                    continue
                src = str(spec["src"])
                where = f"{tasks_file.relative_to(REPO_ROOT)} ({task.get('name', 'unnamed task')})"
                if "{{" in src:
                    yield None, None, f"{where}: src is computed ({src!r}); cannot check statically"
                    continue
                # `src` resolves against the role's own templates/ directory.
                role_dir = tasks_file.parent.parent
                path = role_dir / "templates" / src
                if not path.is_file():
                    path = tasks_file.parent / src
                overrides = {k: spec[k] for k in DELIMITERS if k in spec}
                yield path, overrides, where


def main() -> int:
    if not ANSIBLE_ROOT.is_dir():
        print(f"[FAIL] no ansible tree at {ANSIBLE_ROOT}")
        return 2

    failures: list[str] = []
    checked: set[Path] = set()

    for path, overrides, where in template_tasks():
        if path is None:
            failures.append(f"[FAIL] {where}")
            continue
        if not path.is_file():
            failures.append(f"[FAIL] {where}: template not found at {path.relative_to(REPO_ROOT)}")
            continue

        checked.add(path.resolve())
        rel = path.relative_to(REPO_ROOT)
        try:
            jinja2.Environment(**overrides).parse(path.read_text())
        except jinja2.TemplateSyntaxError as exc:
            failures.append(f"[FAIL] {rel}:{exc.lineno}: {exc.message}  (rendered by {where})")
            continue

        shown = ", ".join(f"{k}={v!r}" for k, v in overrides.items()) or "default delimiters"
        print(f"[ OK ] {rel}  ({shown})")

    # A template no task renders is never checked here and never shipped by
    # Ansible either, so it is dead rather than merely unverified.
    for path in sorted(ANSIBLE_ROOT.rglob("*.j2")):
        if path.resolve() not in checked:
            failures.append(
                f"[FAIL] {path.relative_to(REPO_ROOT)}: no `template:` task renders this file"
            )

    if failures:
        print()
        for line in failures:
            print(line)
        print(f"\n{len(failures)} problem(s). Ansible would fail the same way, mid-image-build.")
        return 1

    print(f"\nAll {len(checked)} Ansible template(s) parse.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
