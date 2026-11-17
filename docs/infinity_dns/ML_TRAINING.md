# Infinity DNS — TinyML Training Guide

How the `TfliteDomainClassifier` fallback weights were distilled and how to reproduce the full `.tflite`.

---

## Data

* **Positive:** HaGeZi Multi + TIF (367k) — all `||domain^` SLDs.
* **Negative:** Tranco top 50k + allowlist (clean web). Deduplicated, registrable-domain level.
* **Split:** 80/10/10 train/val/test, stratified.

## Features (13 scalars, no tokenizer)

`[lengthNorm, labelCountNorm, maxLabelNorm, hyphenNorm, digitRatio, entropyNorm, tldRisk, depthNorm, consecutiveHyphenFlag, punycodeFlag, hexPatternFlag, base64Flag, highRiskTldFlag]`

Exactly `DomainIntelligenceEngine.DomainFeatures` + `vectorize()` — training and inference share the vectorizer.

## Model

```python
# train.py (offline, not in APK)
model = tf.keras.Sequential([
  tf.keras.layers.Input(shape=(13,)),
  tf.keras.layers.Dense(32, activation="relu"),
  tf.keras.layers.Dense(1, activation="sigmoid"),
])
model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["AUC"])
model.fit(X_train, y_train, validation_data=(X_val, y_val), epochs=8, batch_size=512)

converter = tf.lite.TFLiteConverter.from_keras_model(model)
converter.optimizations = [tf.lite.Optimize.DEFAULT]  # int8 quant
open("domain_classifier.tflite","wb").write(converter.convert())
```

Target: **~200 KB** quantized, **AUC 0.92** on test, inference **< 1 ms** on mid-range Android via NNAPI.

## Export

* Place `domain_classifier.tflite` at `app/src/main/assets/ml/domain_classifier.tflite`.
* Add to `libs.versions.toml`: `tensorflow-lite = "2.16.1"` + `implementation(libs.tensorflow.lite)` in `app/build.gradle.kts`.
* Uncomment the Interpreter block in `TfliteDomainClassifier.classifyWithTflite()`.

Until the asset ships, the heuristic fallback (logistic regression distilled from the same training run) is used automatically — zero behavior change.
