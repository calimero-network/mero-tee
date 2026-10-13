#!/usr/bin/env python3
"""Hyperfeed-shaped load against a vLLM server, at rising concurrency.

A turn is modelled as the agents design prices it: a prompt of IN tokens whose
first PREFIX tokens are shared by every request (the Hyperfeed brief, which the
prefix cache reads once) and an answer of exactly OUT tokens. For each
concurrency level it reports time to first token, per-request decode speed,
and the server's total throughput, from which turns per day follow.

Runs on the probe VM with the interpreter vLLM was installed into (it needs
aiohttp and transformers, both vLLM dependencies). Prints one JSON object.
"""

import argparse
import asyncio
import json
import random
import statistics
import time

import aiohttp
from transformers import AutoTokenizer


def text_of(tok, n, seed):
    rng = random.Random(seed)
    words = ["feed", "issue", "merge", "review", "context", "agent", "deploy", "status",
             "thread", "reply", "proposal", "watch", "release", "branch", "summary", "owner"]
    ids = []
    while len(ids) < n:
        chunk = " ".join(rng.choice(words) for _ in range(512))
        ids.extend(tok.encode(chunk, add_special_tokens=False))
    return tok.decode(ids[:n])


async def one(session, url, model, prompt, out_tokens):
    body = {
        "model": model,
        "prompt": prompt,
        "max_tokens": out_tokens,
        "min_tokens": out_tokens,
        "ignore_eos": True,
        "temperature": 0.2,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    start = time.perf_counter()
    first = None
    usage = {}
    async with session.post(url, json=body) as resp:
        resp.raise_for_status()
        async for raw in resp.content:
            line = raw.decode().strip()
            if not line.startswith("data:") or line == "data: [DONE]":
                continue
            chunk = json.loads(line[5:])
            if chunk.get("usage"):
                usage = chunk["usage"]
            if first is None and any(c.get("text") for c in chunk.get("choices", [])):
                first = time.perf_counter()
    end = time.perf_counter()
    done = usage.get("completion_tokens", out_tokens)
    return {
        "ttft": (first or end) - start,
        "decode_tps": (done - 1) / (end - first) if first and end > first and done > 1 else 0.0,
        "prompt_tokens": usage.get("prompt_tokens", 0),
        "completion_tokens": done,
        "latency": end - start,
    }


async def level(url, model, prompts, out_tokens, concurrency):
    sem = asyncio.Semaphore(concurrency)
    timeout = aiohttp.ClientTimeout(total=1800)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async def run(p):
            async with sem:
                return await one(session, url, model, p, out_tokens)
        t0 = time.perf_counter()
        results = await asyncio.gather(*(run(p) for p in prompts))
        wall = time.perf_counter() - t0
    ttft = sorted(r["ttft"] for r in results)
    q = lambda xs, f: xs[min(len(xs) - 1, int(f * len(xs)))]
    tokens = sum(r["prompt_tokens"] + r["completion_tokens"] for r in results)
    return {
        "concurrency": concurrency,
        "requests": len(results),
        "wall_s": round(wall, 2),
        "turns_per_s": round(len(results) / wall, 3),
        "turns_per_day_full_load": round(len(results) / wall * 86400),
        "ttft_p50_s": round(q(ttft, 0.5), 2),
        "ttft_p95_s": round(q(ttft, 0.95), 2),
        "decode_tps_per_user_p50": round(statistics.median(r["decode_tps"] for r in results), 1),
        "total_tokens_per_s": round(tokens / wall),
        "output_tokens_per_s": round(sum(r["completion_tokens"] for r in results) / wall),
        "prompt_tokens_mean": round(statistics.mean(r["prompt_tokens"] for r in results)),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000/v1/completions")
    ap.add_argument("--model", default="probe")
    ap.add_argument("--tokenizer", required=True)
    ap.add_argument("--input-tokens", type=int, default=10000)
    ap.add_argument("--prefix-tokens", type=int, default=4000)
    ap.add_argument("--output-tokens", type=int, default=500)
    ap.add_argument("--levels", default="1,8,16,32,48")
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.tokenizer)
    prefix = text_of(tok, args.prefix_tokens, seed=0)
    unique = args.input_tokens - args.prefix_tokens
    report = {"shape": {"input": args.input_tokens, "prefix": args.prefix_tokens,
                        "output": args.output_tokens}, "levels": []}
    seed = 1
    for c in (int(x) for x in args.levels.split(",")):
        n = max(2 * c, 8)
        prompts = []
        for _ in range(n):
            prompts.append(prefix + "\n" + text_of(tok, unique, seed=seed))
            seed += 1
        try:
            report["levels"].append(asyncio.run(level(args.url, args.model, prompts,
                                                      args.output_tokens, c)))
        except Exception as err:  # a level that fails ends the sweep, not the report
            report["levels"].append({"concurrency": c, "error": repr(err)[:500]})
            break
    print(json.dumps(report))


if __name__ == "__main__":
    main()
