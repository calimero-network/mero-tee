#!/usr/bin/env python3
"""Unit tests for the inference image's model configuration
(mero-tee/ansible/roles/mero-inference/files/inference_model.py): what
metadata may set, the canonical bytes that are measured, the weights digest,
and the vLLM command line built from them.

  python3 scripts/ci/tests/inference-model-test.py
"""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "mero-tee/ansible/roles/mero-inference/files"))
import inference_model as m  # noqa: E402

REV = "a" * 40
SHA = "b" * 64


class Config(unittest.TestCase):
    def test_minimal(self):
        config = m.build_config("Qwen/Qwen3-8B", REV, SHA)
        self.assertEqual(config["servedModelName"], "qwen3-8b")
        self.assertEqual(config["engine"], {})
        self.assertEqual(
            m.canonical(config),
            '{"engine":{},"repo":"Qwen/Qwen3-8B","revision":"%s","schema":1,'
            '"servedModelName":"qwen3-8b","weightsSha256":"%s"}' % (REV, SHA),
        )

    def test_vector_shared_with_mdma(self):
        # The same configuration mdma's browser code hashes (cloud/src/lib),
        # so a digest pinned there matches what the TD measures.
        config = m.build_config(
            "Qwen/Qwen3-8B", REV, SHA, "qwen", '{"max-model-len": 32768, "gpu-memory-utilization": 0.9}'
        )
        text = m.canonical(config)
        self.assertEqual(
            text,
            '{"engine":{"gpu-memory-utilization":0.9,"max-model-len":32768},"repo":"Qwen/Qwen3-8B",'
            '"revision":"%s","schema":1,"servedModelName":"qwen","weightsSha256":"%s"}' % (REV, SHA),
        )
        self.assertEqual(len(hashlib.sha256(text.encode()).hexdigest()), 64)

    def test_refuses_what_could_move_or_run_code(self):
        bad = [
            ("Qwen", REV, SHA, "", ""),
            ("Qwen/Qwen3-8B", "main", SHA, "", ""),
            ("Qwen/Qwen3-8B", REV, "abc", "", ""),
            ("Qwen/Qwen3-8B", REV, SHA, "Has Spaces", ""),
            ("Qwen/Qwen3-8B", REV, SHA, "", '{"trust-remote-code": true}'),
            ("Qwen/Qwen3-8B", REV, SHA, "", '{"chat-template": "/tmp/x"}'),
            ("Qwen/Qwen3-8B", REV, SHA, "", '{"max-model-len": "32768"}'),
            ("Qwen/Qwen3-8B", REV, SHA, "", '{"max-model-len": true}'),
            ("Qwen/Qwen3-8B", REV, SHA, "", '{"gpu-memory-utilization": 1.5}'),
            ("Qwen/Qwen3-8B", REV, SHA, "", '{"quantization": "bitsandbytes"}'),
            ("Qwen/Qwen3-8B", REV, SHA, "", '{"tool-call-parser": "../x"}'),
            ("Qwen/Qwen3-8B", REV, SHA, "", "[1]"),
            ("Qwen/Qwen3-8B", REV, SHA, "", "{"),
            ("../etc/passwd", REV, SHA, "", ""),
        ]
        for args in bad:
            with self.subTest(args=args), self.assertRaises(m.ConfigError):
                m.build_config(*args)

    def test_load_refuses_a_non_canonical_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            config = m.build_config("Qwen/Qwen3-8B", REV, SHA)
            path.write_text(json.dumps(config, indent=1))
            with self.assertRaises(m.ConfigError):
                m.load_config(path)
            path.write_text(m.canonical(config))
            self.assertEqual(m.load_config(path), config)
            config["engine"] = {"trust-remote-code": True}
            path.write_text(m.canonical(config))
            with self.assertRaises(m.ConfigError):
                m.load_config(path)


class Digest(unittest.TestCase):
    def test_covers_kept_files_by_path(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sub").mkdir()
            (root / "model.safetensors").write_bytes(b"weights")
            (root / "config.json").write_text("{}")
            (root / "sub" / "tokenizer.json").write_text("[]")
            (root / "modeling.py").write_text("import os")
            (root / ".cache").mkdir()
            (root / ".cache" / "x.json").write_text("cache")
            lines = "".join(
                f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                for name, data in sorted(
                    [("config.json", b"{}"), ("model.safetensors", b"weights"), ("sub/tokenizer.json", b"[]")]
                )
            )
            expected = hashlib.sha256(lines.encode()).hexdigest()
            self.assertEqual(m.weights_digest(root), expected)
            # A file outside the kept set changes nothing; a kept one does.
            (root / "README.md").write_text("hi")
            self.assertEqual(m.weights_digest(root), expected)
            (root / "config.json").write_text('{"x":1}')
            self.assertNotEqual(m.weights_digest(root), expected)

    def test_an_empty_directory_has_no_digest(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(m.ConfigError):
            m.weights_digest(d)


class Argv(unittest.TestCase):
    def test_loopback_and_measured_flags_only(self):
        config = m.build_config(
            "Qwen/Qwen3-8B",
            REV,
            SHA,
            "",
            '{"max-model-len": 8192, "enable-prefix-caching": true, "enforce-eager": false, "dtype": "bfloat16"}',
        )
        argv = m.vllm_argv(config, "/mnt/model/weights")
        self.assertEqual(argv[:5], ["-m", "vllm.entrypoints.cli.main", "serve", "/mnt/model/weights", "--host"])
        self.assertEqual(argv[argv.index("--host") + 1], "127.0.0.1")
        self.assertIn("--enable-prefix-caching", argv)
        self.assertNotIn("--enforce-eager", argv)
        self.assertEqual(argv[argv.index("--max-model-len") + 1], "8192")
        self.assertEqual(argv[argv.index("--served-model-name") + 1], "qwen3-8b")
        self.assertNotIn("--trust-remote-code", argv)


if __name__ == "__main__":
    unittest.main(verbosity=1)
