#!/usr/bin/env bash
# Called only after the Android CI build, signature check and emulator smoke pass.
# This release is opt-in and public. It cannot replace the production Latest release.
set -euo pipefail

fail() { echo "::error::$*" >&2; exit 1; }
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch && "${PUBLIC_PREVIEW:-}" == true && "${GITHUB_REF_TYPE:-}" == branch ]] ||
    fail 'Public preview publication requires an explicit manual workflow request on a branch.'

repo=${GITHUB_REPOSITORY:?}
run_ident=${GITHUB_RUN_ID:?}.${GITHUB_RUN_ATTEMPT:?}
sha=${GITHUB_SHA:?}
[[ "$run_ident" =~ ^[0-9]+\.[0-9]+$ && "$sha" =~ ^[0-9a-f]{40}$ ]] || fail 'Missing or invalid workflow provenance.'
[[ "$(git rev-parse HEAD)" == "$sha" ]] || fail 'The checkout does not match the tested commit.'

apk=app/build/outputs/apk/debug/app-debug.apk
sha256sum --check "${RUNNER_TEMP:?}/adshield-verified-debug.sha256" ||
    fail 'The APK changed after verification; the emulator-tested build is required.'
python3 tools/check_universal_release.py --variant debug "$apk"
"${ANDROID_HOME:?}/build-tools/36.0.0/apksigner" verify "$apk"
version=$(sed -nE 's/^[[:space:]]*versionName[[:space:]]*=[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+)"[[:space:]]*$/\1/p' app/build.gradle.kts)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Could not determine the debug version.'
tag="preview-v$version-run.$run_ident"
base="https://github.com/$repo/releases/download/$tag"
name="AdShieldPro-$version-preview-$run_ident.apk"
provenance="https://github.com/$repo/actions/runs/$GITHUB_RUN_ID"
latest=$(gh api "repos/$repo/releases/latest" --jq .tag_name)
[[ -n "$latest" && "$latest" != "$tag" ]] || fail 'Production Latest could not be confirmed.'

work=$(mktemp -d "${RUNNER_TEMP:?}/adshield-preview.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cp -- "$apk" "$work/$name"
digest=$(sha256sum "$work/$name" | cut -d ' ' -f1)
printf '%s\n' "$digest" > "$work/$name.sha256"
cat > "$work/notes.md" <<EOF
**Public test APK — not a production update.** No GitHub sign-in or ZIP extraction is needed.

1. Download [\`$name\`]($base/$name) on an Android 10+ device.
2. Open the APK from Downloads, then tap **Install** in Android. Allow installation from that source if Android prompts.
3. Open **AdShield Pro (Debug)**. It is separate from production and has no production in-app updates.

If Android reports a signing conflict with an older **debug** build, uninstall only the old debug build first; this erases that debug build's local data. Do not uninstall production to install this preview.

This build uses a CI debug signer. It passed the checks in the [Android workflow]($provenance), including fresh install, launch, and Agent instrumentation on the Android 10 x86_64 emulator. It is not a production-signed release or a full device test.

- Source commit: \`$sha\`
- APK SHA-256: \`$digest\`
EOF

# --target is ignored if a tag already exists. Reserve a new ref atomically so even a
# colliding tag cannot attach these tested bytes to the wrong source commit.
gh api --method POST "repos/$repo/git/refs" -f ref="refs/tags/$tag" -f sha="$sha" --silent ||
    fail 'Could not reserve a new preview tag for the verified commit.'
gh release create "$tag" "$work/$name" "$work/$name.sha256" \
    --repo "$repo" --verify-tag --prerelease --latest=false \
    --title "AdShield Pro $version — public debug preview ($run_ident)" --notes-file "$work/notes.md"

is_preview=$(gh release view "$tag" --repo "$repo" --json isPrerelease --jq .isPrerelease)
tagged_sha=$(gh api "repos/$repo/git/ref/tags/$tag" --jq .object.sha)
latest_after=$(gh api "repos/$repo/releases/latest" --jq .tag_name)
[[ "$is_preview" == true && "$tagged_sha" == "$sha" && "$latest_after" == "$latest" ]] ||
    fail 'Could not verify preview provenance or that production Latest stayed unchanged.'
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '## Public debug preview\n\n[Download the signed debug APK](%s/%s) · [SHA-256](%s/%s.sha256)\n\nProduction Latest: `%s`\n' \
        "$base" "$name" "$base" "$name" "$latest_after" >> "$GITHUB_STEP_SUMMARY"
fi
