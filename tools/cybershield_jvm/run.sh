#!/usr/bin/env bash
# CyberShield AI Kotlin JVM checks — compile & run without an Android SDK.
#
# Uses the real Kotlin 2.0.21 compiler (matching the app) and a JDK 17. The
# CyberShield engines are pure Kotlin, so no Android stubs are needed — only
# tiny org.junit stubs. This is NOT an Android build: the APK, lint and device
# tests run on CI (see .github/workflows/build-apk.yml).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
WORK="${TMPDIR:-/tmp}/aether-kotlin-jvm"
mkdir -p "$WORK"

# --- JDK 17 (jdk4py wheel ships a real Temurin runtime) -------------------
if ! command -v java >/dev/null 2>&1; then
  VENV="$REPO/.venv"
  if [ ! -x "$VENV/bin/python" ]; then python3 -m venv "$VENV"; fi
  "$VENV/bin/pip" install --quiet "jdk4py==17.0.9.2"
  export JAVA_HOME="$("$VENV/bin/python" -c 'import jdk4py; print(jdk4py.JAVA_HOME)')"
  export PATH="$JAVA_HOME/bin:$PATH"
fi
java -version 2>&1 | head -1

# --- Kotlin compiler 2.0.21 (npm package, same version as the app) --------
if [ ! -x "$WORK/kotlinc/bin/kotlinc" ]; then
  command -v npm >/dev/null 2>&1 || { echo "npm is required to fetch the Kotlin compiler" >&2; exit 1; }
  (cd "$WORK" && npm pack kotlin-compiler@2.0.21 --pack-destination "$WORK" >/dev/null)
  mkdir -p "$WORK/kotlinc"
  tar xzf "$WORK/kotlin-compiler-2.0.21.tgz" -C "$WORK/kotlinc" --strip-components=1
fi
KOTLINC="$WORK/kotlinc/bin/kotlinc"
STDLIB="$WORK/kotlinc/lib/kotlin-stdlib.jar"
"$KOTLINC" -version 2>&1 | head -1

# --- Compile pure engines + suite + stubs + runner -------------------------
CLASSES="$WORK/cs-classes"
rm -rf "$CLASSES"; mkdir -p "$CLASSES"
CS="$REPO/app/src/main/java/com/adshield/pro/cybershield"
"$KOTLINC" \
  "$CS/CyberShieldModels.kt" \
  "$CS/JsonLite.kt" \
  "$CS/ThreatEventMapper.kt" \
  "$CS/BehavioralAnomalyDetector.kt" \
  "$CS/ShieldStateEvaluator.kt" \
  "$CS/ComplianceEvaluator.kt" \
  "$CS/ThreatIntelParsers.kt" \
  "$CS/GeoIndex.kt" \
  "$CS/DemoIntel.kt" \
  "$REPO/app/src/test/java/com/adshield/pro/CyberShieldEngineTestSuite.kt" \
  "$REPO/tools/cybershield_jvm/stubs/org/junit/Assert.kt" \
  "$REPO/tools/cybershield_jvm/CyberShieldJvmTests.kt" \
  -d "$CLASSES"
echo "[kotlin] compiled CyberShield engines + 29 unit tests + smoke check"

echo "[kotlin] running CyberShield JVM unit tests (working dir = app/ for asset access)"
(cd "$REPO/app" && java -cp "$CLASSES:$STDLIB" CyberShieldJvmTestsKt)
