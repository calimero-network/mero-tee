#!/usr/bin/env python3
"""Render what an Ansible image playbook writes into a directory tree, without
running Ansible against a VM.

The mkosi image builds (mero-tee/mkosi-*) take their files from the same roles
the Packer build runs, so the two cannot drift while both exist. This reads a
playbook's roles and, for the tasks that only put files in place, does the
same thing into OUT:

  copy (content: or src:), template, file (directory, link, touch, absent),
  get_url + unarchive (from a download cache, sha256-checked against the task's
  checksum), set_fact (with lookup('file', ...)), and assert, which fails the
  render as it would fail the Packer build

Everything else is reported, not run: systemd enable/mask go to the manifest
for mkosi's postinst, as do the users `user` tasks create or lock, paths a `file: state=absent` removes go to it as well
(the image build removes them from the packages' files too), apt/package names to its package list, and commands,
GRUB edits and the like are listed as skipped so none disappears
silently. `when:` conditions and `loop:`/`with_items:` are evaluated with the
playbook's vars and each role's defaults.

  render_role_tree.py PLAYBOOK --out OUT --manifest MANIFEST_JSON \\
      --cache DOWNLOAD_DIR [--fetch] [-e key=value ...] [--role ROLE ...]
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import jinja2
import yaml

SKIPPED_MODULES = {
    "command", "shell", "slurp", "stat", "find", "package_facts",
    "lineinfile", "replace", "debug", "fail", "wait_for",
}
TEMPLATE_STRINGS = (
    "comment_start_string", "comment_end_string", "variable_start_string",
    "variable_end_string", "block_start_string", "block_end_string",
)
TASK_KEYWORDS = {
    "name", "when", "become", "register", "tags", "loop", "with_items", "vars",
    "notify", "changed_when", "failed_when", "ignore_errors", "no_log",
    "environment", "args", "retries", "delay", "until", "check_mode",
    "loop_control", "delegate_to", "listen",
}


class Renderer:
    def __init__(self, playbook, out, cache, extra_vars, fetch=False):
        self.fetch = fetch
        self.playbook = Path(playbook).resolve()
        self.base = self.playbook.parent
        self.out = Path(out)
        self.cache = Path(cache)
        self.env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
        self.env.filters.update(
            bool=lambda v: v if isinstance(v, bool) else str(v).strip().lower() in ("1", "true", "yes", "on"),
            regex_replace=lambda v, pattern, repl="": re.sub(pattern, repl, str(v)),
            basename=os.path.basename,
            to_json=json.dumps,
            from_json=json.loads,
            b64decode=lambda v: base64.b64decode(str(v)).decode(),
        )
        self.env.tests.update(
            search=lambda v, pattern: re.search(pattern, str(v)) is not None,
            match=lambda v, pattern: re.match(pattern, str(v)) is not None,
        )
        # lookup('file', path): a file on the build host, relative to the playbook.
        self.env.globals["lookup"] = self.lookup
        self.vars = {
            "playbook_dir": str(self.base),
            "build_inputs": json.loads((self.base / "build-inputs.lock.json").read_text()),
        }
        self.extra = extra_vars
        self.registered = set()
        # set_fact results: they outlive the role that sets them, as in Ansible.
        self.facts = {}
        # get_url dest -> the cache file it names (an archive may be saved
        # under another name than the URL's).
        self.fetched = {}
        self.manifest = {"packages": [], "enable": [], "mask": [], "removed": [], "users": [], "skipped": [], "written": []}

    # --- templating -----------------------------------------------------------
    def render(self, value, scope):
        if isinstance(value, str):
            if "{{" not in value and "{%" not in value:
                return value
            result = self.env.from_string(value).render(**scope)
            # A var that is a whole expression keeps its type, as in Ansible.
            if re.fullmatch(r"\s*\{\{.*\}\}\s*", value, re.S):
                stripped = result.strip()
                if stripped in ("True", "False"):
                    return stripped == "True"
                if stripped.startswith(("[", "{")):
                    try:
                        return yaml.safe_load(stripped)
                    except yaml.YAMLError:
                        pass
            return result
        if isinstance(value, list):
            return [self.render(v, scope) for v in value]
        if isinstance(value, dict):
            return {k: self.render(v, scope) for k, v in value.items()}
        return value

    def resolve(self, layers):
        """Merge var layers (lowest first), extra vars on top, then render
        each var until it is stable, so vars may refer to one another."""
        scope = {}
        for layer in layers:
            scope.update(layer or {})
        scope.update(self.facts)
        scope.update(self.extra)
        scope.update(self.vars)
        for _ in range(8):
            changed = False
            for key, value in list(scope.items()):
                if key in self.extra:
                    continue
                try:
                    rendered = self.render(value, scope)
                except jinja2.UndefinedError:
                    continue
                if rendered != value:
                    scope[key], changed = rendered, True
            if not changed:
                break
        return scope

    def condition(self, when, scope):
        conditions = when if isinstance(when, list) else [when]
        for c in conditions:
            if isinstance(c, bool):
                if not c:
                    return False
                continue
            if not self.env.compile_expression(str(c))(**scope):
                return False
        return True

    def lookup(self, kind, path):
        if kind != "file":
            raise ValueError(f"no rendering for lookup({kind!r})")
        path = Path(path)
        return (path if path.is_absolute() else self.base / path).read_text().rstrip("\n")

    # --- paths ------------------------------------------------------------------
    def target(self, path):
        path = str(path)
        if not path.startswith("/"):
            raise ValueError(f"not an absolute path: {path}")
        return self.out / path.lstrip("/")

    def note(self, dest, how):
        self.manifest["written"].append({"path": str(dest), "by": how})

    @staticmethod
    def chmod(path, mode):
        if mode is not None:
            os.chmod(path, int(str(mode), 8))

    # --- modules ----------------------------------------------------------------
    def do_copy(self, args, role_dir):
        dest = self.target(args["dest"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        if "content" in args:
            dest.write_text(args["content"])
        else:
            # Ansible looks in the role's files/ first, then beside it.
            src = role_dir / "files" / args["src"]
            if not src.exists():
                src = role_dir / args["src"]
            if src.is_dir():
                shutil.copytree(src, dest, dirs_exist_ok=True)
            else:
                shutil.copyfile(src, dest)
        self.chmod(dest, args.get("mode"))
        self.note(args["dest"], "copy")

    def do_template(self, args, role_dir, scope):
        dest = self.target(args["dest"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        source = (role_dir / "templates" / args["src"]).read_text()
        # The template module's own Jinja settings: trim_blocks on by default,
        # and per-task delimiters.
        options = {"trim_blocks": args.get("trim_blocks", True), "lstrip_blocks": args.get("lstrip_blocks", False)}
        for key in TEMPLATE_STRINGS:
            if key in args:
                options[key] = args[key]
        env = self.env.overlay(**options)
        dest.write_text(env.from_string(source).render(**scope))
        self.chmod(dest, args.get("mode"))
        self.note(args["dest"], "template")

    def do_file(self, args):
        path = args.get("path") or args.get("dest") or args.get("name")
        dest = self.target(path)
        state = args.get("state", "file")
        if state == "directory":
            dest.mkdir(parents=True, exist_ok=True)
            self.chmod(dest, args.get("mode"))
        elif state == "link":
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.is_symlink() or dest.exists():
                dest.unlink()
            dest.symlink_to(args["src"])
        elif state == "touch":
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.touch()
            self.chmod(dest, args.get("mode"))
        elif state == "absent":
            # Also from the image: what a role removes may come from a package.
            self.manifest["removed"].append(str(path))
            if dest.is_dir() and not dest.is_symlink():
                shutil.rmtree(dest)
            elif dest.exists() or dest.is_symlink():
                dest.unlink()
        else:
            self.chmod(dest, args.get("mode"))
        self.note(path, f"file:{state}")

    def cached(self, name, sha256=None):
        path = self.cache / name
        if not path.exists():
            raise FileNotFoundError(f"{name} is not in the download cache {self.cache}")
        if sha256:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != sha256:
                raise ValueError(f"{name}: sha256 {actual} is not the pinned {sha256}")
        return path

    def do_get_url(self, args):
        checksum = str(args.get("checksum", ""))
        if not checksum.startswith("sha256:"):
            raise ValueError(f"{args['url']}: no sha256 checksum; refusing an unpinned download")
        name = args["url"].rsplit("/", 1)[1]
        if self.fetch and not (self.cache / name).exists():
            self.cache.mkdir(parents=True, exist_ok=True)
            subprocess.run(["curl", "-fsSL", "--retry", "4", "-o", str(self.cache / name), args["url"]], check=True)
        self.cached(name, checksum.split(":", 1)[1])
        if "dest" in args:
            self.fetched[str(args["dest"])] = name
        self.manifest.setdefault("downloads", []).append({"url": args["url"], "sha256": checksum.split(":", 1)[1]})

    def do_unarchive(self, args, role_dir):
        src = str(args["src"])
        if args.get("remote_src"):
            # What a get_url task put on the VM: from the download cache.
            archive = self.cached(self.fetched.get(src, Path(src).name))
        else:
            # A file on the build host, as Ansible copies it over.
            archive = Path(src) if Path(src).is_absolute() else role_dir / "files" / src
            if not archive.exists():
                raise FileNotFoundError(f"unarchive: {src} does not exist on the build host")
        dest = self.target(args["dest"])
        dest.mkdir(parents=True, exist_ok=True)
        options = args.get("extra_opts") or []
        include = args.get("include") or []
        options = options if isinstance(options, list) else [options]
        include = include if isinstance(include, list) else [include]
        listed = subprocess.run(["tar", "-xvf", str(archive), "-C", str(dest), *options, *include],
                                check=True, capture_output=True, text=True).stdout.split()
        if args.get("mode") is not None:
            # As in Ansible, mode applies to every extracted file, not only dest.
            # tar -v prints member names before --strip-components, so strip them here.
            strip = next((int(o.split("=", 1)[1]) for o in options if o.startswith("--strip-components=")), 0)
            for member in listed:
                parts = member.rstrip("/").split("/")[strip:]
                path = dest.joinpath(*parts) if parts else None
                if path and path.exists() and not path.is_symlink():
                    self.chmod(path, args["mode"])
        self.note(args["dest"], f"unarchive:{archive.name}")

    def do_systemd(self, args):
        name = args.get("name")
        if args.get("masked"):
            self.manifest["mask"].append(name)
        if args.get("enabled"):
            self.manifest["enable"].append(name)

    # --- driver -----------------------------------------------------------------
    def run_tasks(self, tasks, role, role_dir, scope):
        for task in tasks or []:
            if "block" in task:
                if "when" in task and not self.condition(task["when"], scope):
                    continue
                self.run_tasks(task["block"], role, role_dir, scope)
                continue
            if "register" in task:
                self.registered.add(task["register"])
            modules = [k for k in task if k not in TASK_KEYWORDS]
            if len(modules) != 1:
                raise ValueError(f"{role}: task {task.get('name')!r} has modules {modules}")
            module = modules[0].replace("ansible.builtin.", "").replace("community.general.", "")
            loop = task.get("loop", task.get("with_items"))
            try:
                items = self.render(loop, scope) if loop is not None else [None]
            except jinja2.UndefinedError as error:
                # A loop over a registered result (a probe we skip).
                self.manifest["skipped"].append({"role": role, "task": task.get("name"), "why": f"loop: {error}"})
                continue
            for item in items:
                local = dict(scope, item=item) if item is not None else scope
                if "when" in task:
                    try:
                        if not self.condition(task["when"], local):
                            continue
                    except jinja2.UndefinedError as error:
                        # A condition on a registered result (a probe we skip).
                        self.manifest["skipped"].append({"role": role, "task": task.get("name"), "why": f"condition: {error}"})
                        continue
                args = task[modules[0]]
                if module == "assert":
                    # The build's own checks hold here too; one on a registered
                    # result (a probe we skip) is skipped with it.
                    try:
                        held = self.condition(args["that"], local)
                    except jinja2.UndefinedError as error:
                        # Or on the build host's facts (package_facts and the
                        # like), which build.sh checks from mkosi's manifest.
                        if not (any(f"'{name}'" in str(error) for name in self.registered)
                                or re.match(r"'ansible_\w+' is undefined", str(error))):
                            raise
                        self.manifest["skipped"].append({"role": role, "task": task.get("name"), "why": f"assert: {error}"})
                        continue
                    if not held:
                        raise ValueError(f"{role}: {task.get('name')}: {self.render(args.get('fail_msg', 'assertion failed'), local)}")
                    continue
                if module == "set_fact":
                    facts = {k: self.render(v, local) for k, v in args.items() if k != "cacheable"}
                    self.facts.update(facts)
                    scope.update(facts)
                    continue
                if module == "stat" and task.get("delegate_to") == "localhost" and "register" in task:
                    # A file on the build host: stat it here, so the asserts on it hold.
                    path = Path(self.render(args["path"], local))
                    result = {"exists": path.exists()}
                    if path.is_file():
                        result["checksum"] = hashlib.new(args.get("checksum_algorithm", "sha1"), path.read_bytes()).hexdigest()
                    self.facts[task["register"]] = scope[task["register"]] = {"stat": result}
                    continue
                if module in SKIPPED_MODULES:
                    self.manifest["skipped"].append({"role": role, "task": task.get("name"), "module": module})
                    continue
                try:
                    args = self.render(args if isinstance(args, dict) else {"_raw": args}, local)
                except jinja2.UndefinedError as error:
                    # Only a registered result may be missing; any other var is a real gap.
                    if not any(f"'{name}'" in str(error) for name in self.registered):
                        raise
                    self.manifest["skipped"].append({"role": role, "task": task.get("name"), "why": f"args: {error}"})
                    continue
                if module in ("apt", "package"):
                    names = args.get("name") or args.get("pkg") or []
                    names = names if isinstance(names, list) else [names]
                    state = args.get("state", "present")
                    if names:
                        self.manifest["packages"].append({"role": role, "names": names, "state": state})
                elif module == "copy":
                    self.do_copy(args, role_dir)
                elif module == "template":
                    self.do_template(args, role_dir, local)
                elif module == "file":
                    self.do_file(args)
                elif module == "get_url":
                    self.do_get_url(args)
                elif module == "unarchive":
                    self.do_unarchive(args, role_dir)
                elif module in ("systemd", "systemd_service", "service"):
                    self.do_systemd(args)
                elif module == "user":
                    # For mkosi.postinst: users are made in the image, not here.
                    self.manifest["users"].append(
                        {k: args[k] for k in ("name", "system", "shell", "create_home", "password_lock", "state") if k in args})
                else:
                    raise ValueError(f"{role}: no rendering for module {module!r} (task {task.get('name')!r})")

    def run(self, only_roles):
        plays = yaml.safe_load(self.playbook.read_text())
        for play in plays:
            play_scope = self.resolve([play.get("vars")])
            if not only_roles:
                self.run_tasks(play.get("pre_tasks"), "pre_tasks", self.base, play_scope)
            for entry in play.get("roles", []):
                ref = entry["role"] if isinstance(entry, dict) else entry
                role = Path(ref).name
                if only_roles and role not in only_roles:
                    continue
                role_dir = (self.base / ref).resolve()
                defaults = role_dir / "defaults" / "main.yml"
                role_vars = role_dir / "vars" / "main.yml"
                layers = [
                    yaml.safe_load(defaults.read_text()) if defaults.exists() else {},
                    play.get("vars"),
                    yaml.safe_load(role_vars.read_text()) if role_vars.exists() else {},
                    # The entry's own vars, minus the ones that only pass an
                    # extra var through under its own name.
                    {k: v for k, v in (entry.get("vars") or {}).items() if v != "{{ %s }}" % k}
                    if isinstance(entry, dict) else {},
                ]
                scope = self.resolve(layers)
                if isinstance(entry, dict) and "when" in entry and not self.condition(entry["when"], scope):
                    self.manifest.setdefault("roles_skipped", []).append(role)
                    continue
                self.manifest.setdefault("roles", []).append(role)
                tasks = yaml.safe_load((role_dir / "tasks" / "main.yml").read_text())
                self.run_tasks(tasks, role, role_dir, scope)
            if not only_roles:
                self.run_tasks(play.get("post_tasks"), "post_tasks", self.base, play_scope)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("playbook")
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--fetch", action="store_true", help="download what the cache lacks (still sha256-checked)")
    parser.add_argument("-e", dest="extra", action="append", default=[], help="key=value (YAML-parsed value)")
    parser.add_argument("--role", action="append", default=[], help="only render these roles")
    args = parser.parse_args()
    extra = {}
    for pair in args.extra:
        key, _, value = pair.partition("=")
        extra[key] = yaml.safe_load(value) if value else ""
    renderer = Renderer(args.playbook, args.out, args.cache, extra, args.fetch)
    renderer.run(set(args.role))
    Path(args.manifest).write_text(json.dumps(renderer.manifest, indent=2))
    print(f"rendered {len(renderer.manifest['written'])} paths from {len(renderer.manifest.get('roles', []))} roles; "
          f"{len(renderer.manifest['skipped'])} tasks skipped (see {args.manifest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
