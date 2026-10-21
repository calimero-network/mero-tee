#!/usr/bin/env python3
"""The model a private inference TD serves (docs/design/private-inference.md).

inference-init runs it to turn instance metadata into the canonical
configuration it measures (`config`), to fetch the weights (`download`) and
check their digest (`digest`), and the vLLM unit runs it to start vLLM from
that configuration (`serve`), so what runs is exactly what was measured.
Operators run `digest` on a local snapshot to learn the `model-sha256` to set
(scripts/inference/model-digest.sh).

Metadata is written by whoever runs the VM, so every value is checked here and
anything unexpected stops the boot.

  inference_model.py config --out config.json      (MODEL_REPO, MODEL_REVISION,
                                                     MODEL_SHA256, SERVED_MODEL_NAME,
                                                     ENGINE_ARGS from the environment)
  inference_model.py download --config config.json --dir DIR   (HF_TOKEN optional)
  inference_model.py digest DIR
  inference_model.py serve --config config.json --dir DIR
"""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = 1
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
REVISION = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
SERVED_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
PARSER = re.compile(r"[a-z0-9_]{1,40}")

# The files a download keeps, and so the files the digest covers. Never `*.py`:
# a repository's code does not run here (no trust-remote-code).
KEPT = ("*.safetensors", "*.json", "*.model", "*.tiktoken", "*.txt", "*.jinja")


def _int(low, high):
    def check(value):
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"must be an integer from {low} to {high}")
        return value
    return check


def _float(low, high):
    def check(value):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
            raise ValueError(f"must be a number from {low} to {high}")
        return value
    return check


def _choice(*choices):
    def check(value):
        if value not in choices:
            raise ValueError(f"must be one of {', '.join(choices)}")
        return value
    return check


def _bool(value):
    if not isinstance(value, bool):
        raise ValueError("must be true or false")
    return value


def _pattern(pattern):
    def check(value):
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise ValueError(f"must match {pattern.pattern}")
        return value
    return check


# The vLLM flags whoever runs the VM may set, and what each may be. Anything
# else (trust-remote-code, a chat template path, a download directory) is
# refused: it would change what the TD runs without changing the image.
ENGINE_ARGS = {
    "max-model-len": _int(256, 1 << 21),
    "max-num-seqs": _int(1, 4096),
    "max-num-batched-tokens": _int(256, 1 << 21),
    "tensor-parallel-size": _int(1, 8),
    "seed": _int(0, (1 << 31) - 1),
    "gpu-memory-utilization": _float(0.1, 0.98),
    "dtype": _choice("auto", "bfloat16", "float16"),
    "quantization": _choice("fp8", "awq", "awq_marlin", "gptq", "gptq_marlin", "compressed-tensors"),
    "kv-cache-dtype": _choice("auto", "fp8", "fp8_e4m3", "fp8_e5m2"),
    "enable-prefix-caching": _bool,
    "enable-auto-tool-choice": _bool,
    "enforce-eager": _bool,
    "tool-call-parser": _pattern(PARSER),
    "reasoning-parser": _pattern(PARSER),
    "generation-config": _choice("auto", "vllm"),
}


class ConfigError(ValueError):
    pass


def canonical(obj):
    """The bytes that are hashed and measured: sorted keys, no spaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def build_config(repo, revision, weights_sha256, served_name="", engine_args=""):
    """The configuration a TD serves, from metadata values (strings)."""
    repo, revision, weights_sha256 = repo.strip(), revision.strip(), weights_sha256.strip().lower()
    if not REPO.fullmatch(repo):
        raise ConfigError(f"model-repo '{repo}' is not owner/name")
    if not REVISION.fullmatch(revision):
        raise ConfigError(f"model-revision '{revision}' is not a 40-hex commit (a branch or tag could move)")
    if not SHA256.fullmatch(weights_sha256):
        raise ConfigError("model-sha256 is not 64 hex digits")
    served_name = served_name.strip() or repo.split("/", 1)[1].lower()
    if not SERVED_NAME.fullmatch(served_name):
        raise ConfigError(f"served-model-name '{served_name}' must match {SERVED_NAME.pattern}")
    engine = {}
    if engine_args.strip():
        try:
            given = json.loads(engine_args)
        except json.JSONDecodeError as e:
            raise ConfigError(f"engine-args is not JSON: {e}") from None
        if not isinstance(given, dict):
            raise ConfigError("engine-args must be a JSON object")
        for name, value in given.items():
            check = ENGINE_ARGS.get(name)
            if check is None:
                raise ConfigError(f"engine-args: '{name}' is not allowed (allowed: {', '.join(sorted(ENGINE_ARGS))})")
            try:
                engine[name] = check(value)
            except ValueError as e:
                raise ConfigError(f"engine-args: {name} {e}") from None
    return {
        "engine": engine,
        "repo": repo,
        "revision": revision,
        "schema": SCHEMA,
        "servedModelName": served_name,
        "weightsSha256": weights_sha256,
    }


def kept(path):
    return any(Path(path).match(pattern) for pattern in KEPT)


def weights_digest(directory):
    """SHA-256 over `<sha256>  <relative path>\\n` for every kept file, by path."""
    root = Path(directory)
    lines = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative.startswith(".") or "/." in relative or not kept(relative):
            continue
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                digest.update(block)
        lines.append(f"{digest.hexdigest()}  {relative}\n")
    if not lines:
        raise ConfigError(f"no model files in {directory}")
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def vllm_argv(config, model_dir):
    """vLLM's OpenAI server on loopback, from the measured configuration."""
    argv = [
        # `vllm serve`, through the module its console script runs.
        "-m", "vllm.entrypoints.cli.main", "serve", str(model_dir),
        "--host", "127.0.0.1",
        "--port", "8000",
        "--served-model-name", config["servedModelName"],
        # Prompts stay out of the journal: vLLM logs requests only with
        # --enable-log-requests, which is never passed, and no access log.
        "--disable-uvicorn-access-log",
    ]
    for name, value in sorted(config["engine"].items()):
        if isinstance(value, bool):
            if value:
                argv.append(f"--{name}")
        else:
            argv += [f"--{name}", str(value)]
    return argv


def load_config(path):
    text = Path(path).read_text()
    config = json.loads(text)
    if canonical(config) != text:
        raise ConfigError(f"{path} is not in canonical form")
    # Re-check: the unit must never start from a file it could not have written.
    again = build_config(config["repo"], config["revision"], config["weightsSha256"],
                         config["servedModelName"], json.dumps(config["engine"]))
    if again != config:
        raise ConfigError(f"{path} does not validate")
    return config


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("config")
    p.add_argument("--out", required=True)
    p = sub.add_parser("download")
    p.add_argument("--config", required=True)
    p.add_argument("--dir", required=True)
    p = sub.add_parser("digest")
    p.add_argument("dir")
    p = sub.add_parser("serve")
    p.add_argument("--config", required=True)
    p.add_argument("--dir", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "config":
            config = build_config(
                os.environ.get("MODEL_REPO", ""),
                os.environ.get("MODEL_REVISION", ""),
                os.environ.get("MODEL_SHA256", ""),
                os.environ.get("SERVED_MODEL_NAME", ""),
                os.environ.get("ENGINE_ARGS", ""),
            )
            Path(args.out).write_text(canonical(config))
            print(config["servedModelName"])
        elif args.command == "download":
            config = load_config(args.config)
            # Only in the image: the baked site-packages.
            from huggingface_hub import snapshot_download

            snapshot_download(
                repo_id=config["repo"],
                revision=config["revision"],
                local_dir=args.dir,
                allow_patterns=list(KEPT),
                token=os.environ.get("HF_TOKEN") or False,
            )
            actual = weights_digest(args.dir)
            if actual != config["weightsSha256"]:
                raise ConfigError(
                    f"the weights of {config['repo']}@{config['revision']} hash to {actual}, "
                    f"not model-sha256 {config['weightsSha256']}"
                )
            print(actual)
        elif args.command == "digest":
            print(weights_digest(args.dir))
        elif args.command == "serve":
            config = load_config(args.config)
            command = [sys.executable] + vllm_argv(config, args.dir)
            os.execv(sys.executable, command)
    except ConfigError as e:
        print(f"inference_model: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
