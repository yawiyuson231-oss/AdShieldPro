#!/usr/bin/env python3
"""Fit the small, offline AETHER task-intent model. No dependencies or device data.

    python3 tools/train_aether_tasks.py         # regenerate the shipped weights
    python3 tools/train_aether_tasks.py --check # check reproducibility and held-out behavior

Examples are hand-written. The holdout is a development regression set, never used in fitting.
Feature extraction and scoring mirror AetherTaskModel.kt; the Android JVM test evaluates the
same holdout with the packaged model to catch any drift between the two implementations.
"""
from __future__ import annotations

import argparse
import math
import random
import re
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tools/aether_agent"
ASSET = ROOT / "app/src/main/assets/aether/task_model.tsv"
LABELS = ("CHECK_PHONE", "AUDIT_APPS", "SCAN_LINK", "BENCHMARK_DNS", "ENABLE_ALIAS_SHIELD", "SECURITY_REVIEW", "SCAN_FILE", "UNSUPPORTED")
# Operating point for a suggestion, not a claim of calibrated confidence. Never used for approval.
MIN_PROBABILITY = 0.60
MIN_GAP = 0.28


def words(request: str) -> list[str]:
    text = unicodedata.normalize("NFKC", request).lower().replace("’", "'")
    text = re.sub(r"\b(?:https?://|www\.)\S+", " link ", text, flags=re.ASCII)
    return re.findall(r"[a-z0-9]+(?:'[a-z]+)?", text)


def features(tokens: list[str]) -> list[str]:
    if len(tokens) < 2:
        return []
    # Within-word 5-grams share weights across forms such as resolver/resolvers.
    subwords = {f"~{word[i:i + 5]}" for token in tokens for word in [f"^{token}$"] for i in range(len(word) - 4)}
    return sorted(set(tokens) | {f"{a}_{b}" for a, b in zip(tokens, tokens[1:])} | subwords)


def explicit_enable(tokens: list[str]) -> bool:
    # Privacy setting changes need explicit affirmative language IN ADDITION to approval.
    text = " ".join(tokens)
    requested = re.search(r"\b(enable|activate|turn on|switch on|buksan|pabukas|i on)\b", text)
    names_setting = re.search(r"\b(alias|aliases|cname|cnames)\b", text)
    negated = re.search(r"\b(never|not|no|off|disable|disabling|wag|huwag|ayaw)\b|n't\b", text)
    explanation = re.search(r"\b(why|how|what|whether|paano|bakit)\b", text)
    return bool(requested and names_setting and not negated and not explanation)


def examples(name: str) -> list[tuple[int, str]]:
    rows = []
    for line in (DATA / name).read_text(encoding="utf-8").splitlines():
        label, request = line.split("\t", 1)
        assert len(request) <= 240 and features(words(request)), request
        rows.append((LABELS.index(label), request))
    assert set(label for label, _ in rows) == set(range(len(LABELS)))
    assert len({tuple(features(words(text))) for _, text in rows}) == len(rows), f"duplicate features in {name}"
    return rows


def probabilities(scores: list[float]) -> list[float]:
    peak = max(scores)
    exp = [math.exp(value - peak) for value in scores]
    total = sum(exp)
    return [value / total for value in exp]


def scores(active: list[str], weights: dict[str, list[float]]) -> list[float]:
    out = weights["@bias"].copy()
    scale = math.sqrt(len(active))
    for name in active:
        if name in weights:
            for k, value in enumerate(weights[name]):
                out[k] += value / scale
    return out


def fit(rows: list[tuple[int, str]]) -> dict[str, list[float]]:
    # Multinomial logistic regression: optimize cross entropy with sparse weight decay.
    data = [(label, features(words(text))) for label, text in rows]
    weights = {name: [0.0] * len(LABELS) for _, active in data for name in active}
    weights["@bias"] = [0.0] * len(LABELS)
    rng = random.Random(173)
    for epoch in range(120):
        rng.shuffle(data)
        step = 0.48 / (1 + 0.018 * epoch)
        for label, active in data:
            p = probabilities(scores(active, weights))
            delta = [step * (int(k == label) - p[k]) for k in range(len(LABELS))]
            for k, change in enumerate(delta):
                weights["@bias"][k] += change
            scale = math.sqrt(len(active))
            for name in active:
                for k, change in enumerate(delta):
                    weights[name][k] = 0.9995 * weights[name][k] + change / scale
    return {name: [float(f"{value:.6f}") for value in row] for name, row in weights.items()}


def predict(text: str, weights: dict[str, list[float]]) -> int:
    unsupported = LABELS.index("UNSUPPORTED")
    tokens = words(text)
    text = " ".join(tokens)
    if len(tokens) < 2 or re.match(r"^(please )?(do not|don't|never|avoid|stop|skip|cancel|wag|huwag|ayaw|open|visit|launch|download|upload|install|uninstall|delete|remove|quarantine)\b", text):
        return unsupported
    active = features(tokens)
    if sum(name in weights for name in active) < 2:
        return unsupported
    p = probabilities(scores(active, weights))
    top, second = sorted(range(len(LABELS)), key=p.__getitem__, reverse=True)[:2]
    if p[top] < MIN_PROBABILITY or p[top] - p[second] < MIN_GAP:
        return unsupported
    if LABELS[top] == "ENABLE_ALIAS_SHIELD" and not explicit_enable(tokens):
        return unsupported
    selected_file = re.search(r"\b(files?|archives?|attachments?|documents?|dokumento\w*|pdf|apks?|xapk|zip|(application|downloaded|local|saved|package) installer|spreadsheet|screenshot)\b", text)
    if LABELS[top] == "SECURITY_REVIEW":
        narrow = re.search(r"\b(only|just|without|except|skip|exclude|excluding|avoid|not|no|never|lang|lamang|wag|huwag|ayaw)\b|n't\b", text)
        broad = re.search(r"\b(security review|security checkup|combined security|overall (mobile |device |phone )?security)\b", text)
        phone = re.search(r"\b(protection|protect|shield|shielding|wifi|adshield|settings|device security|phone security|network security|seguridad ng phone)\b", text)
        apps = re.search(r"\b(apps?|applications?|permissions?)\b", text)
        if narrow or selected_file or not (broad or (phone and apps)):
            return unsupported
    if LABELS[top] == "AUDIT_APPS" and selected_file:
        return unsupported
    if LABELS[top] == "SCAN_FILE" and not selected_file:
        return unsupported
    return top


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    train = examples("train.tsv")
    holdout = examples("holdout.tsv")
    assert {tuple(features(words(text))) for _, text in train}.isdisjoint(tuple(features(words(text))) for _, text in holdout)
    weights = fit(train)
    lines = ["\t".join(("aether-intent-v2", *LABELS))]
    lines.extend("\t".join((name, *(f"{value:.6f}" for value in row))) for name, row in sorted(weights.items()))
    artifact = "\n".join(lines) + "\n"
    if args.check:
        if ASSET.read_bytes() != artifact.encode("ascii"):
            raise SystemExit("AETHER model differs from fitted weights; regenerate it without --check.")
    else:
        ASSET.write_bytes(artifact.encode("ascii"))
    unsupported = LABELS.index("UNSUPPORTED")
    matched = wrong = abstained = 0
    per_label: dict[int, list[int]] = {}
    for expected, prompt in holdout:
        prediction = predict(prompt, weights)
        matched += int(prediction == expected)
        wrong += int(prediction != expected and prediction != unsupported)
        abstained += int(prediction == unsupported and expected != unsupported)
        if expected != unsupported:
            counts = per_label.setdefault(expected, [0, 0])
            counts[0] += int(prediction == expected)
            counts[1] += 1
        if prediction != expected:
            print(f"  {LABELS[expected]} -> {LABELS[prediction]}: {prompt}")
    print(f"{len(train)} training examples, {len(weights) - 1} features, {len(artifact)} bytes")
    print(f"Holdout: {matched}/{len(holdout)} matched; {wrong} wrong suggestions; {abstained} supported requests declined.")
    for label, (hit, total) in per_label.items():
        print(f"  {LABELS[label]}: {hit}/{total} supported requests matched")
    if args.check and (
        wrong != 0 or abstained > 9 or any(hit * 10 < total * 7 for hit, total in per_label.values())
    ):
        raise SystemExit("AETHER intent holdout regressed (no wrong tasks, at most nine declines, at least 70% per task).")


if __name__ == "__main__":
    main()
